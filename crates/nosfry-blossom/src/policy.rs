//! Upload policy: the live snapshot pushed by config reload, plus
//! the upload-slot semaphores that outlive any one snapshot.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use nosfry_core::event::PublicKey;
use nosfry_core::moderation::Moderation;

/// Per-pubkey in-flight upload cap.
pub const UPLOADS_PER_PUBKEY: usize = 4;

/// Restart-only service settings — fixed at startup.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `blossom.public_url` trimmed of any trailing `/` — the
    /// descriptor `url` prefix.
    pub public_url: String,
    /// The lowercase host of `public_url` (no port) — matched
    /// against the BUD-11 `server` tag.
    pub public_host: String,
    /// `blossom.max_concurrent_uploads` — the global slot count.
    pub max_concurrent_uploads: usize,
}

/// The live policy snapshot — config reload pushes a whole new
/// `Arc<Policy>` through a `watch` channel rather than mutating, so
/// every request sees one consistent set.
#[derive(Debug)]
pub struct Policy {
    /// `blossom.upload == "everyone"` — otherwise only admins and
    /// NIP-86 allowed pubkeys may upload.
    pub upload_everyone: bool,
    /// Relay admin pubkeys — admitted under `"allowed"`.
    pub admins: Arc<[PublicKey]>,
    /// `blossom.max_blob_size`.
    pub max_blob_size: u64,
    /// `blossom.max_total_bytes`.
    pub max_total_bytes: u64,
    /// `blossom.quota_bytes`.
    pub quota_bytes: u64,
    /// `blossom.quota_blobs`.
    pub quota_blobs: u64,
    /// `blossom.mime_types` — empty means all types allowed.
    pub mime_types: Vec<String>,
}

impl Policy {
    /// Whether `pubkey` may upload under the current mode: everyone,
    /// a relay admin, or a NIP-86 allowed pubkey.
    #[must_use]
    pub fn admits(&self, pubkey: &PublicKey, moderation: &Moderation) -> bool {
        self.upload_everyone
            || self.admins.contains(pubkey)
            || moderation.allowed_pubkeys.contains_key(pubkey)
    }
}

/// The upload-slot guard: a global semaphore permit plus a
/// per-pubkey counter entry, released together on drop. Kept
/// outside the swapped [`Policy`] so in-flight permits are never
/// orphaned by a reload.
#[derive(Debug)]
pub struct Slots {
    global: Arc<tokio::sync::Semaphore>,
    per_key: Arc<Mutex<HashMap<PublicKey, usize>>>,
}

/// One in-flight per-pubkey upload slot; [`Drop`] decrements the
/// counter and removes the entry at zero.
#[derive(Debug)]
pub struct KeyPermit {
    per_key: Arc<Mutex<HashMap<PublicKey, usize>>>,
    pubkey: PublicKey,
}

impl Drop for KeyPermit {
    fn drop(&mut self) {
        let mut map = self.per_key.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(held) = map.get_mut(&self.pubkey) else {
            return;
        };
        *held -= 1;
        if *held == 0 {
            map.remove(&self.pubkey);
        }
    }
}

impl Slots {
    /// Slots sized for `max_concurrent_uploads` global streams.
    #[must_use]
    pub fn new(max_concurrent_uploads: usize) -> Self {
        Self {
            global: Arc::new(tokio::sync::Semaphore::new(max_concurrent_uploads)),
            per_key: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to take one global upload slot plus this pubkey's
    /// per-key slot — global first (its exhaustion is 503), then
    /// per-key (429). The counter map can never exceed
    /// `max_concurrent_uploads` entries. On failure the global
    /// permit drops with the error return.
    ///
    /// # Errors
    ///
    /// [`Slot::Global`] when the global cap is reached,
    /// [`Slot::PerKey`] when this pubkey is already at
    /// `UPLOADS_PER_PUBKEY`.
    pub fn try_upload(
        &self,
        pubkey: &PublicKey,
    ) -> Result<(tokio::sync::OwnedSemaphorePermit, KeyPermit), Slot> {
        let global = Arc::clone(&self.global)
            .try_acquire_owned()
            .map_err(|_| Slot::Global)?;
        let mut map = self.per_key.lock().unwrap_or_else(PoisonError::into_inner);
        let held = map.entry(*pubkey).or_insert(0);
        if *held >= UPLOADS_PER_PUBKEY {
            return Err(Slot::PerKey);
        }
        *held += 1;
        drop(map);
        Ok((
            global,
            KeyPermit {
                per_key: Arc::clone(&self.per_key),
                pubkey: *pubkey,
            },
        ))
    }

    /// Whether the global upload semaphore currently has zero
    /// permits — `HEAD /upload`'s capacity check.
    #[must_use]
    pub fn global_dry(&self) -> bool {
        self.global.available_permits() == 0
    }
}

/// Which upload slot acquisition failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// The global `max_concurrent_uploads` cap is reached (503).
    Global,
    /// This pubkey already holds `UPLOADS_PER_PUBKEY` slots (429).
    PerKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> PublicKey {
        PublicKey([n; 32])
    }

    /// `everyone` admits all; otherwise admins and NIP-86 allowed
    /// pubkeys.
    #[test]
    fn admission_modes() {
        let mut moderation = Moderation::default();
        moderation.allowed_pubkeys.insert(key(1), Some("ok".into()));
        let policy = Policy {
            upload_everyone: false,
            admins: Arc::from([key(2)]),
            max_blob_size: 1,
            max_total_bytes: 1,
            quota_bytes: 1,
            quota_blobs: 1,
            mime_types: Vec::new(),
        };
        assert!(policy.admits(&key(1), &moderation));
        assert!(policy.admits(&key(2), &moderation));
        assert!(!policy.admits(&key(3), &moderation));
        let open = Policy {
            upload_everyone: true,
            admins: Arc::from([]),
            max_blob_size: 1,
            max_total_bytes: 1,
            quota_bytes: 1,
            quota_blobs: 1,
            mime_types: Vec::new(),
        };
        assert!(open.admits(&key(3), &moderation));
    }

    /// Upload slots: global and per-key caps both enforced; permits
    /// release on drop.
    #[test]
    fn upload_slots() {
        let slots = Slots::new(2);
        // Global cap is 2.
        let a = slots.try_upload(&key(1)).unwrap();
        let b = slots.try_upload(&key(2)).unwrap();
        assert!(matches!(slots.try_upload(&key(3)), Err(Slot::Global)));
        assert!(slots.global_dry());
        drop(a);
        assert!(!slots.global_dry());
        let c = slots.try_upload(&key(3)).unwrap();
        drop(b);
        drop(c);
        // Per-key cap is UPLOADS_PER_PUBKEY (needs global headroom).
        let roomy = Slots::new(8);
        let mut held = Vec::new();
        for _ in 0..UPLOADS_PER_PUBKEY {
            held.push(roomy.try_upload(&key(9)).unwrap());
        }
        assert!(matches!(roomy.try_upload(&key(9)), Err(Slot::PerKey)));
        drop(held);
        assert!(roomy.try_upload(&key(9)).is_ok());
        // Dropped permits drain the counter map back to empty.
        let drained = Slots::new(4);
        let mut permits = Vec::new();
        for n in 1..=3_u8 {
            permits.push(drained.try_upload(&key(n)).unwrap());
        }
        assert_eq!(
            drained
                .per_key
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
            3
        );
        drop(permits);
        assert!(
            drained
                .per_key
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
        );
    }
}
