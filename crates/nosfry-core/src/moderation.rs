//! NIP-86 moderation state shared by every store.
//!
//! The [`ModOp`] vocabulary, the NIP-11 [`InfoField`]s, and the
//! in-memory [`Moderation`] snapshot hot paths check. Stores persist
//! the `mod_*` tables and rebuild the snapshot; lookups never touch
//! storage.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use crate::event::{Event, EventId, PublicKey};
use crate::packed::PackedRef;

/// A NIP-86 management operation applied by a store's `moderate`.
#[derive(Debug)]
pub enum ModOp {
    /// Ban `pubkey` (also drops its allow entry).
    BanPubkey {
        /// The author to ban.
        pubkey: PublicKey,
        /// Optional operator note, returned by `listbannedpubkeys`.
        reason: Option<String>,
    },
    /// Remove `pubkey`'s ban (does not touch an allow entry).
    UnbanPubkey {
        /// The author to unban.
        pubkey: PublicKey,
    },
    /// Allow-list `pubkey` (also drops its ban).
    AllowPubkey {
        /// The author to allow.
        pubkey: PublicKey,
        /// Optional operator note.
        reason: Option<String>,
    },
    /// Remove `pubkey` from the allow list (does not touch a ban).
    UnallowPubkey {
        /// The author to remove.
        pubkey: PublicKey,
    },
    /// Ban `id` and delete the stored event in the same transaction.
    BanEvent {
        /// The event id to ban.
        id: EventId,
        /// Optional operator note.
        reason: Option<String>,
    },
    /// Remove `id` from the ban list.
    UnbanEvent {
        /// The event id to unban.
        id: EventId,
    },
    /// Allow `kind` (also drops a disallow entry).
    AllowKind {
        /// The kind number.
        kind: u16,
    },
    /// Disallow `kind` (also drops an allow entry).
    DisallowKind {
        /// The kind number.
        kind: u16,
    },
    /// Block `ip` from connecting; stored in canonical form.
    BlockIp {
        /// The address to block.
        ip: IpAddr,
        /// Optional operator note.
        reason: Option<String>,
    },
    /// Remove `ip` from the block list.
    UnblockIp {
        /// The address to unblock.
        ip: IpAddr,
    },
    /// Override a NIP-11 info field (takes precedence over config).
    SetInfo {
        /// Which field.
        field: InfoField,
        /// The new value; an empty string overrides with empty.
        value: String,
    },
}

/// A NIP-11 info field writable through [`ModOp::SetInfo`].
#[derive(Debug, Clone, Copy)]
pub enum InfoField {
    /// `changerelayname`.
    Name,
    /// `changerelaydescription`.
    Description,
    /// `changerelayicon`.
    Icon,
}

impl InfoField {
    /// The `mod_info` storage key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Description => "description",
            Self::Icon => "icon",
        }
    }
}

/// The full NIP-86 state, loaded at startup and rebuilt after every
/// applied [`ModOp`]. Hot paths read a snapshot — lookups never touch
/// storage.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Moderation {
    /// `mod_pubkeys` rows with the banned state, pubkey → reason.
    pub banned_pubkeys: HashMap<PublicKey, Option<Box<str>>>,
    /// `mod_pubkeys` rows with the allowed state. Non-empty switches
    /// the relay to allow-list mode.
    pub allowed_pubkeys: HashMap<PublicKey, Option<Box<str>>>,
    /// `mod_events` rows, event id → reason.
    pub banned_events: HashMap<EventId, Option<Box<str>>>,
    /// `mod_kinds` rows with the allowed state. Non-empty switches the
    /// relay to allow-list mode for kinds.
    pub allowed_kinds: BTreeSet<u16>,
    /// `mod_kinds` rows with the disallowed state.
    pub disallowed_kinds: BTreeSet<u16>,
    /// `mod_ips` rows, canonical address → reason.
    pub blocked_ips: HashMap<IpAddr, Option<Box<str>>>,
    /// `mod_info["name"]` NIP-11 override.
    pub name: Option<Box<str>>,
    /// `mod_info["description"]` NIP-11 override.
    pub description: Option<Box<str>>,
    /// `mod_info["icon"]` NIP-11 override.
    pub icon: Option<Box<str>>,
}

impl Moderation {
    /// The `blocked:` reason when `event` is not publishable, `None`
    /// when it is. The caller exempts AUTH events and relay-scoped
    /// NIP-62 requests first.
    #[must_use]
    pub fn blocked_reason(&self, event: &Event) -> Option<&'static str> {
        if self.pubkey_blocked(&event.pubkey()) {
            return Some("blocked: pubkey not allowed");
        }
        if self.banned_events.contains_key(&event.id()) {
            return Some("blocked: event banned");
        }
        if self.kind_blocked(u16::from(event.kind())) {
            return Some("blocked: kind not allowed");
        }
        None
    }

    /// Whether a stored `ev` is hidden from readers — the same rules
    /// [`Self::blocked_reason`] applies to writes, so banning an
    /// author or disallowing a kind stops serving the already-stored
    /// matching events until the entry is lifted (`banevent` is the
    /// delete; bans hide). Unmoderated relays take the fast path.
    #[must_use]
    pub fn hides(&self, ev: PackedRef<'_>) -> bool {
        if self.banned_pubkeys.is_empty()
            && self.allowed_pubkeys.is_empty()
            && self.banned_events.is_empty()
            && self.disallowed_kinds.is_empty()
            && self.allowed_kinds.is_empty()
        {
            return false;
        }
        self.pubkey_blocked(&ev.pubkey())
            || self.banned_events.contains_key(&ev.id())
            || self.kind_blocked(ev.kind().0)
    }

    /// `pubkey` is banned or outside a non-empty allow list.
    fn pubkey_blocked(&self, pubkey: &PublicKey) -> bool {
        self.banned_pubkeys.contains_key(pubkey)
            || (!self.allowed_pubkeys.is_empty() && !self.allowed_pubkeys.contains_key(pubkey))
    }

    /// `kind` is disallowed or outside a non-empty allow list.
    fn kind_blocked(&self, kind: u16) -> bool {
        self.disallowed_kinds.contains(&kind)
            || (!self.allowed_kinds.is_empty() && !self.allowed_kinds.contains(&kind))
    }

    /// Whether the allow-lists refuse unlisted writes — a non-empty
    /// `allowed_pubkeys` or `allowed_kinds`. This is the NIP-11
    /// `limitation.restricted_writes` flag.
    #[must_use]
    pub fn restricts_writes(&self) -> bool {
        !self.allowed_pubkeys.is_empty() || !self.allowed_kinds.is_empty()
    }

    /// Whether `ip` is on the block list.
    #[must_use]
    pub fn ip_blocked(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.contains_key(ip)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;
    use crate::kind::Kind;
    use crate::packed::PackedEvent;

    fn ev(id: u8, pubkey: u8, kind: u16) -> PackedEvent {
        PackedEvent::build(
            &EventId([id; 32]),
            &PublicKey([pubkey; 32]),
            0,
            Kind(kind),
            0,
            Vec::<Vec<String>>::new(),
        )
    }

    #[test]
    fn hides_every_moderated_shape() {
        let mut m = Moderation::default();
        // Fast path: a wholly unmoderated snapshot hides nothing.
        assert!(!m.hides(ev(1, 1, 1).packed()));

        m.banned_pubkeys.insert(PublicKey([1; 32]), None);
        assert!(m.hides(ev(2, 1, 1).packed()));
        assert!(!m.hides(ev(2, 2, 1).packed()));

        m.banned_pubkeys.clear();
        m.allowed_pubkeys.insert(PublicKey([1; 32]), None);
        assert!(!m.hides(ev(2, 1, 1).packed()));
        assert!(m.hides(ev(2, 2, 1).packed()));

        m.allowed_pubkeys.clear();
        m.banned_events.insert(EventId([3; 32]), None);
        assert!(m.hides(ev(3, 2, 1).packed()));
        assert!(!m.hides(ev(4, 2, 1).packed()));

        m.banned_events.clear();
        m.disallowed_kinds.insert(4);
        assert!(m.hides(ev(5, 2, 4).packed()));
        assert!(!m.hides(ev(5, 2, 1).packed()));

        m.disallowed_kinds.clear();
        m.allowed_kinds.insert(1);
        assert!(!m.hides(ev(6, 2, 1).packed()));
        assert!(m.hides(ev(6, 2, 4).packed()));
    }

    #[test]
    fn hides_and_blocked_reason_share_the_rules() {
        // The write gate (Event) and the read gate (PackedRef) must
        // agree on every rule over the same identity.
        let pubkey = PublicKey([0xcd; 32]);
        let tags: Vec<Vec<String>> = Vec::new();
        let id = crate::event::event_id(
            crate::event::serialize_for_id(&pubkey, 1, Kind(4), &tags, "").as_bytes(),
        );
        let json = format!(
            r#"{{"id":"{id}","pubkey":"{pubkey}","created_at":1,"kind":4,"tags":[],"content":"","sig":"{}"}}"#,
            "ef".repeat(64)
        );
        let event = crate::event::UnverifiedEvent::parse_structural(&json)
            .unwrap()
            .verify_unsigned(&crate::event::EventLimits::default())
            .unwrap();
        let packed = PackedEvent::build(&id, &pubkey, 1, Kind(4), 0, &tags);
        let agree = |m: &Moderation| m.hides(packed.packed()) == m.blocked_reason(&event).is_some();
        let mut m = Moderation::default();
        assert!(agree(&m));
        m.banned_pubkeys.insert(PublicKey([0xcd; 32]), None);
        assert!(agree(&m));
        m.banned_pubkeys.clear();
        m.allowed_pubkeys.insert(PublicKey([7; 32]), None);
        assert!(agree(&m));
        m.allowed_pubkeys.clear();
        m.banned_events.insert(id, None);
        assert!(agree(&m));
        m.banned_events.clear();
        m.disallowed_kinds.insert(4);
        assert!(agree(&m));
        m.disallowed_kinds.clear();
        m.allowed_kinds.insert(1);
        assert!(agree(&m));
    }
}
