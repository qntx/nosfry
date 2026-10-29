//! `nosfry-lmdb` — synchronous LMDB event store for the `nosfry` protocol core.
//!
//! One writer at a time (the server owns the writer thread); readers take
//! TLS-less read transactions. Layout (all integers big-endian, `Bytes`
//! codec):
//!
//! | db | key | value |
//! |---|---|---|
//! | `meta` | `b"format"` / `b"next_seq"` | u32 / u64 |
//! | `events` | `seq` | packed record |
//! | `payloads` | `seq` | canonical JSON |
//! | `ix_id` | `id` | `seq` |
//! | `ix_time` | `created_at` ‖ `seq` | `id` |
//! | `ix_pubkey` | `pubkey` ‖ `created_at` ‖ `seq` | — |
//! | `ix_kind` | `kind` ‖ `created_at` ‖ `seq` | — |
//! | `ix_pubkey_kind` | `pubkey` ‖ `kind` ‖ `created_at` ‖ `seq` | — |
//! | `ix_tag` | `name` ‖ `len` ‖ packed value ‖ `created_at` ‖ `seq` | — |
//! | `ix_replace` | `Event::address` | `seq` |
//! | `ix_expiration` | `expiration` ‖ `seq` | — |
//! | `ix_deletion` | event `id` ‖ `author` ‖ kind-5 `seq` | — |
//! | `ix_replace_deletion` | `address` ‖ kind-5 `created_at` ‖ kind-5 `seq` | — |
//! | `ix_vanish` | `pubkey` | vanish point `T` (u64, max of requests) |
//! | `vanish_pending` | `pubkey` | resume cursor for NIP-62 cleanup |
//! | `mod_pubkeys` | `pubkey` | state byte ‖ reason |
//! | `mod_events` | event `id` | reason |
//! | `mod_kinds` | `kind` | state byte |
//! | `mod_ips` | canonical `IpAddr` string | reason |
//! | `mod_info` | `name`/`description`/`icon` | UTF-8 value |
//!
//! The last three index the event carrying the metadata: an expiring
//! event owns its `ix_expiration` row, a kind-5 event owns its
//! `ix_deletion`/`ix_replace_deletion` rows, so deleting the carrier
//! removes the metadata (and lifts a deletion block) with it. The
//! `mod_*` tables are the NIP-86 management state.
#![cfg_attr(
    test,
    allow(
        unused_crate_dependencies,
        reason = "dev-deps are exercised by integration tests and benches"
    )
)]

use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use heed::CompactionOption;
use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions, RoTxn, RwTxn, WithoutTls};
use nosfry_core::deletion::DeletionTarget;
use nosfry_core::event::{Event, EventId, PublicKey, UnverifiedEvent, supersedes};
use nosfry_core::moderation::{ModOp, Moderation};
use nosfry_core::packed::PackedRef;
use nosfry_core::store::WriteOutcome;
use nosfry_core::url::RelayUrl;

mod count;
mod scan;

pub use count::{CountResult, CountScan};
pub use scan::{Progress, Scan};

/// On-disk format version, stored under the `format` meta key.
pub const FORMAT_VERSION: u32 = 4;

type BytesDb = Database<Bytes, Bytes>;
type Reader<'a> = RoTxn<'a, WithoutTls>;

/// LMDB environment options.
#[derive(Debug, Clone, Copy)]
pub struct StoreOptions {
    /// Memory map size in bytes.
    pub map_size: usize,
    /// Maximum reader slots.
    pub max_readers: u32,
    /// Disable OS read-ahead on the map (`MDB_NORDAHEAD`). Leave
    /// off: it cuts query throughput by about 10x. If the database
    /// outgrows RAM on a filesystem with large read-ahead (btrfs uses
    /// at least 4 MiB), lower the filesystem's `read_ahead_kb` (e.g.
    /// to 128) instead.
    pub no_read_ahead: bool,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            map_size: 10 << 40, // 10 TiB
            max_readers: 256,
            no_read_ahead: false,
        }
    }
}

/// The result of one [`Store::write`] transaction.
#[derive(Debug, Default)]
pub struct Written {
    /// One outcome per input event, in arrival order.
    pub outcomes: Vec<WriteOutcome>,
    /// Seqs removed inside the transaction: replaced predecessors and
    /// NIP-09 targets (possibly stored and removed in this same batch).
    pub deleted: Vec<u64>,
    /// A stored (or duplicate) NIP-62 request queued deletion work:
    /// the writer should keep draining [`Store::vanish_step`].
    pub vanish_pending: bool,
}

/// Outcome of one [`Store::vanish_step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VanishStep {
    /// Events deleted in this step.
    pub deleted: usize,
    /// `vanish_pending` still holds work — call again.
    pub more: bool,
}

/// `mod_pubkeys`/`mod_kinds` state bytes: a single row per key carries
/// the current state, so ban↔allow and allow↔disallow exclusivity is
/// automatic on `put`.
const ST_BANNED: u8 = 0;
const ST_ALLOWED: u8 = 1;
const ST_DISALLOWED: u8 = 2;

/// Collected seqs and the resume position of one bounded vanish
/// range walk.
struct RangeWalk {
    /// Seqs whose record kind passed the phase's predicate.
    seqs: Vec<u64>,
    /// Index entries examined before the range ended or the budget
    /// ran out — skipped kinds count too, so a step's work is bounded.
    examined: usize,
    /// Key of the last examined row; resuming starts strictly after
    /// it, so skipped rows are never examined twice.
    last: Option<Vec<u8>>,
    /// The range reached its end without spending the budget.
    drained: bool,
}

/// Store failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// LMDB error.
    #[error("lmdb: {0}")]
    Heed(#[from] heed::Error),
    /// Filesystem error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The on-disk format differs from [`FORMAT_VERSION`].
    #[error("format version mismatch: found {found}, expected {expected}")]
    FormatMismatch {
        /// The stored format version.
        found: u32,
        /// The version this build understands.
        expected: u32,
    },
    /// An internal invariant is broken.
    #[error("corrupt store: {0}")]
    Corrupt(&'static str),
}

/// Which index database an [`IndexEntry`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Index {
    /// `ix_id`: `id` → `seq`.
    Id,
    /// `ix_time`: `created_at` ‖ `seq` → `id`.
    Time,
    /// `ix_pubkey`: `pubkey` ‖ `created_at` ‖ `seq`.
    Pubkey,
    /// `ix_kind`: `kind` ‖ `created_at` ‖ `seq`.
    Kind,
    /// `ix_pubkey_kind`: `pubkey` ‖ `kind` ‖ `created_at` ‖ `seq`.
    PubkeyKind,
    /// `ix_tag`: `name` ‖ `len` ‖ `value` ‖ `created_at` ‖ `seq`.
    Tag,
    /// `ix_replace`: `address` → `seq`.
    Replace,
    /// `ix_expiration`: `expiration` ‖ `seq`.
    Expiration,
    /// `ix_deletion`: `id` ‖ `author` ‖ `seq` (`e` targets only; the
    /// row belongs to the kind-5 event carrying it).
    Deletion,
    /// `ix_replace_deletion`: `address` ‖ `created_at` ‖ `seq` of the
    /// kind-5 event carrying it.
    ReplaceDeletion,
}

/// How many index entries the store produces for `event`.
///
/// Five base trees plus one per indexed packed tag, one for `address`,
/// one for `expiration`, and one per deletion target. The writer
/// charges batches by this so a few tag-heavy events cannot overrun a
/// commit.
#[must_use]
pub fn index_entry_count(event: &Event) -> usize {
    5 + event.packed().tags().count()
        + usize::from(event.address().is_some())
        + usize::from(event.expiration().unwrap_or(0) != 0)
        + event.deletion_targets().len()
}

/// Derive every index entry of an event from its packed record, the
/// metadata that cannot be recovered from it (`address`, `expiration`,
/// `deletion_targets`), and its sequence number. Insert and delete
/// share this so they cannot diverge.
fn index_entries(
    packed: PackedRef<'_>,
    address: Option<[u8; 32]>,
    expiration: u64,
    deletion_targets: &[DeletionTarget],
    seq: u64,
    out: &mut Vec<(Index, Vec<u8>, Vec<u8>)>,
) {
    let ca = packed.created_at().to_be_bytes();
    let seqb = seq.to_be_bytes();
    let pk = packed.pubkey().0;
    let kind = packed.kind().0.to_be_bytes();

    out.push((Index::Id, packed.id().0.to_vec(), seqb.to_vec()));

    let mut time_key = Vec::with_capacity(16);
    time_key.extend_from_slice(&ca);
    time_key.extend_from_slice(&seqb);
    out.push((Index::Time, time_key, packed.id().0.to_vec()));

    let mut pubkey_key = Vec::with_capacity(48);
    pubkey_key.extend_from_slice(&pk);
    pubkey_key.extend_from_slice(&ca);
    pubkey_key.extend_from_slice(&seqb);
    out.push((Index::Pubkey, pubkey_key, Vec::new()));

    let mut kind_key = Vec::with_capacity(18);
    kind_key.extend_from_slice(&kind);
    kind_key.extend_from_slice(&ca);
    kind_key.extend_from_slice(&seqb);
    out.push((Index::Kind, kind_key, Vec::new()));

    let mut pk_kind_key = Vec::with_capacity(50);
    pk_kind_key.extend_from_slice(&pk);
    pk_kind_key.extend_from_slice(&kind);
    pk_kind_key.extend_from_slice(&ca);
    pk_kind_key.extend_from_slice(&seqb);
    out.push((Index::PubkeyKind, pk_kind_key, Vec::new()));

    for (name, value) in packed.tags() {
        let mut tag_key = Vec::with_capacity(18 + value.len());
        tag_key.push(name);
        tag_key.push(u8::try_from(value.len()).unwrap_or(u8::MAX));
        tag_key.extend_from_slice(value);
        tag_key.extend_from_slice(&ca);
        tag_key.extend_from_slice(&seqb);
        out.push((Index::Tag, tag_key, Vec::new()));
    }

    if let Some(address) = address {
        out.push((Index::Replace, address.to_vec(), seqb.to_vec()));
    }

    if expiration != 0 {
        let mut expiration_key = Vec::with_capacity(16);
        expiration_key.extend_from_slice(&expiration.to_be_bytes());
        expiration_key.extend_from_slice(&seqb);
        out.push((Index::Expiration, expiration_key, Vec::new()));
    }

    for target in deletion_targets {
        match target {
            DeletionTarget::Event(id) => {
                let mut deletion_key = Vec::with_capacity(72);
                deletion_key.extend_from_slice(&id.0);
                deletion_key.extend_from_slice(&pk);
                deletion_key.extend_from_slice(&seqb);
                out.push((Index::Deletion, deletion_key, Vec::new()));
            }
            DeletionTarget::Address(addr) => {
                let mut replace_key = Vec::with_capacity(48);
                replace_key.extend_from_slice(addr);
                replace_key.extend_from_slice(&ca);
                replace_key.extend_from_slice(&seqb);
                out.push((Index::ReplaceDeletion, replace_key, Vec::new()));
            }
        }
    }
}

/// The LMDB store.
#[derive(Debug)]
pub struct Store {
    env: Env<WithoutTls>,
    meta: BytesDb,
    pub(crate) events: BytesDb,
    pub(crate) payloads: BytesDb,
    ix_id: BytesDb,
    ix_time: BytesDb,
    ix_pubkey: BytesDb,
    ix_kind: BytesDb,
    ix_pubkey_kind: BytesDb,
    ix_tag: BytesDb,
    ix_replace: BytesDb,
    ix_expiration: BytesDb,
    ix_deletion: BytesDb,
    ix_replace_deletion: BytesDb,
    /// `ix_vanish`: `pubkey` → vanish point `T` (u64 BE, max of its
    /// NIP-62 requests' `created_at`).
    ix_vanish: BytesDb,
    /// `vanish_pending`: pubkeys whose vanish ranges are not drained —
    /// a persistent work queue, so a restart resumes mid-vanish.
    vanish_pending: BytesDb,
    /// `mod_pubkeys`: `pubkey` → state byte ‖ reason (NIP-86).
    mod_pubkeys: BytesDb,
    /// `mod_events`: event `id` → reason (NIP-86 bans).
    mod_events: BytesDb,
    /// `mod_kinds`: `kind` (u16 BE) → allowed/disallowed state byte.
    mod_kinds: BytesDb,
    /// `mod_ips`: canonical `IpAddr` string → reason.
    mod_ips: BytesDb,
    /// `mod_info`: `name`/`description`/`icon` → NIP-11 override.
    mod_info: BytesDb,
}

impl Store {
    /// Open (or create) a store at `path`, checking the format version.
    ///
    /// # Errors
    ///
    /// [`StoreError::FormatMismatch`] when the on-disk format differs,
    /// [`StoreError::Io`] when the directory cannot be created, and
    /// [`StoreError::Heed`] for LMDB failures.
    #[expect(
        unsafe_code,
        reason = "heed maps the database file: the caller must not open the same env twice in one process nor let other code modify the files incompatibly"
    )]
    pub fn open(path: &Path, opts: &StoreOptions) -> Result<Self, StoreError> {
        std::fs::create_dir_all(path)?;
        let mut options = EnvOpenOptions::new().read_txn_without_tls();
        options
            .map_size(opts.map_size)
            .max_readers(opts.max_readers)
            .max_dbs(23);
        if opts.no_read_ahead {
            // SAFETY: heed requires env flags to be set before opening.
            unsafe { options.flags(EnvFlags::NO_READ_AHEAD) };
        }
        // SAFETY: the same env is not opened twice in one process, and the
        // map file is not modified incompatibly by other code.
        let env = unsafe { options.open(path)? };
        env.clear_stale_readers()?;

        let mut wtxn = env.write_txn()?;
        let mut open_or_create = |name: &'static str| -> Result<BytesDb, StoreError> {
            match env.open_database::<Bytes, Bytes>(&wtxn, Some(name))? {
                Some(db) => Ok(db),
                None => Ok(env.create_database::<Bytes, Bytes>(&mut wtxn, Some(name))?),
            }
        };
        let meta = open_or_create("meta")?;
        let events = open_or_create("events")?;
        let payloads = open_or_create("payloads")?;
        let ix_id = open_or_create("ix_id")?;
        let ix_time = open_or_create("ix_time")?;
        let ix_pubkey = open_or_create("ix_pubkey")?;
        let ix_kind = open_or_create("ix_kind")?;
        let ix_pubkey_kind = open_or_create("ix_pubkey_kind")?;
        let ix_tag = open_or_create("ix_tag")?;
        let ix_replace = open_or_create("ix_replace")?;
        let ix_expiration = open_or_create("ix_expiration")?;
        let ix_deletion = open_or_create("ix_deletion")?;
        let ix_replace_deletion = open_or_create("ix_replace_deletion")?;
        let ix_vanish = open_or_create("ix_vanish")?;
        let vanish_pending = open_or_create("vanish_pending")?;
        let mod_pubkeys = open_or_create("mod_pubkeys")?;
        let mod_events = open_or_create("mod_events")?;
        let mod_kinds = open_or_create("mod_kinds")?;
        let mod_ips = open_or_create("mod_ips")?;
        let mod_info = open_or_create("mod_info")?;
        if let Some(bytes) = meta.get(&wtxn, b"format")? {
            let found = u32::from_be_bytes(
                bytes
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("bad format value"))?,
            );
            if found != FORMAT_VERSION {
                return Err(StoreError::FormatMismatch {
                    found,
                    expected: FORMAT_VERSION,
                });
            }
        } else {
            meta.put(&mut wtxn, b"format", &FORMAT_VERSION.to_be_bytes())?;
            meta.put(&mut wtxn, b"next_seq", &1u64.to_be_bytes())?;
        }
        wtxn.commit()?;
        Ok(Self {
            env,
            meta,
            events,
            payloads,
            ix_id,
            ix_time,
            ix_pubkey,
            ix_kind,
            ix_pubkey_kind,
            ix_tag,
            ix_replace,
            ix_expiration,
            ix_deletion,
            ix_replace_deletion,
            ix_vanish,
            vanish_pending,
            mod_pubkeys,
            mod_events,
            mod_kinds,
            mod_ips,
            mod_info,
        })
    }

    /// Apply `events` in arrival order inside a single write
    /// transaction. `service_url` is the relay's own URL for NIP-62
    /// (`None` honors only `ALL_RELAYS` requests).
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure, [`StoreError::Corrupt`] on a
    /// broken index invariant.
    pub fn write(
        &self,
        events: &[Arc<Event>],
        service_url: Option<&RelayUrl>,
    ) -> Result<Written, StoreError> {
        let mut txn = self.env.write_txn()?;
        let mut next_seq = self.next_seq(&txn)?;
        let mut written = Written {
            outcomes: Vec::with_capacity(events.len()),
            deleted: Vec::new(),
            vanish_pending: false,
        };
        for event in events {
            let outcome = self.apply(&mut txn, event, &mut next_seq, &mut written.deleted)?;
            // A request to vanish that was stored (or already stored)
            // extends the author's vanish point and queues the sweep.
            // A kind 62 has no address, so `Superseded` here means the
            // newest-only bookkeeping rule — honoring the request is
            // independent of keeping it (NIP-62 MUST).
            if event.requests_vanish(service_url)
                && matches!(
                    outcome,
                    WriteOutcome::Stored { .. }
                        | WriteOutcome::Duplicate
                        | WriteOutcome::Superseded
                )
            {
                written.vanish_pending |= self.record_vanish(&mut txn, event)?;
            }
            written.outcomes.push(outcome);
        }
        self.meta
            .put(&mut txn, b"next_seq", &next_seq.to_be_bytes())?;
        txn.commit()?;
        Ok(written)
    }

    /// Apply one event inside the write transaction: ephemeral and
    /// duplicate ids are skipped, a NIP-09-blocked event is `Deleted`, a
    /// losing replace is `Superseded`, a winner deletes its predecessor
    /// before the insert, and a stored kind 5 deletes its targets.
    fn apply(
        &self,
        txn: &mut RwTxn<'_>,
        event: &Arc<Event>,
        next_seq: &mut u64,
        deleted: &mut Vec<u64>,
    ) -> Result<WriteOutcome, StoreError> {
        // NIP-62: a stored request to vanish blocks the author's
        // equal-or-older events (never a kind 62 itself) and gift
        // wraps `p`-tagged to a vanished pubkey.
        if event.kind().0 != 62 && self.vanish_blocked(txn, event)? {
            return Ok(WriteOutcome::Vanished);
        }
        if event.kind().is_ephemeral() {
            return Ok(WriteOutcome::Ephemeral);
        }
        if self.ix_id.get(txn, &event.id().0)?.is_some() {
            return Ok(WriteOutcome::Duplicate);
        }
        // NIP-62: relays may keep the signed request to vanish for
        // bookkeeping — store only the author's newest.
        if event.kind().0 == 62 && self.vanish_request_superseded(txn, event, deleted)? {
            return Ok(WriteOutcome::Superseded);
        }
        // NIP-09: an id covered by a stored same-author kind 5 stays
        // deleted; a kind 5 itself is never blocked, and a kind 62
        // request to vanish is never blocked either (NIP-62).
        if event.kind().0 != 5
            && event.kind().0 != 62
            && self.has_prefix(txn, Index::Deletion, &deletion_prefix(event))?
        {
            return Ok(WriteOutcome::Deleted);
        }
        // NIP-09: an `a` deletion blocks equal-or-older versions.
        if let Some(address) = event.address()
            && self.replace_deleted(txn, &address, event.created_at())?
        {
            return Ok(WriteOutcome::Deleted);
        }
        if let Some(address) = event.address()
            && let Some((old_seq, old_bytes)) = self.stored_version(txn, &address)?
        {
            let old = PackedRef::new(&old_bytes).ok_or(StoreError::Corrupt("bad packed record"))?;
            if !supersedes(
                (event.created_at(), &event.id()),
                (old.created_at(), &old.id()),
            ) {
                return Ok(WriteOutcome::Superseded);
            }
            if self.delete_seq(txn, old_seq)? {
                deleted.push(old_seq);
            }
        }
        let seq = *next_seq;
        *next_seq = next_seq
            .checked_add(1)
            .ok_or(StoreError::Corrupt("seq overflow"))?;
        self.insert(txn, event, seq)?;
        if event.kind().0 == 5 {
            self.apply_deletions(txn, event, deleted)?;
        }
        Ok(WriteOutcome::Stored { seq })
    }

    /// Whether a stored kind-62 of `event`'s author supersedes the
    /// incoming request — `true` means the caller answers `Superseded`.
    /// Otherwise every stored one is deleted (seqs into `deleted`) and
    /// `event` may insert, so a legacy db holding several requests
    /// collapses to the newest.
    fn vanish_request_superseded(
        &self,
        txn: &mut RwTxn<'_>,
        event: &Event,
        deleted: &mut Vec<u64>,
    ) -> Result<bool, StoreError> {
        // `ix_pubkey_kind` prefix `pubkey ‖ 62u16 BE` spans all of the
        // author's stored requests; the suffix bounds are
        // `created_at ‖ seq` maxima.
        let mut from = Vec::with_capacity(50);
        from.extend_from_slice(&event.pubkey().0);
        from.extend_from_slice(&62u16.to_be_bytes());
        let mut to = from.clone();
        to.extend_from_slice(&u64::MAX.to_be_bytes());
        to.extend_from_slice(&u64::MAX.to_be_bytes());
        let bounds = (Bound::Included(&*from), Bound::Included(&*to));
        // Collect before deleting — never mutate while iterating.
        let mut stored = Vec::new();
        for entry in self.ix_pubkey_kind.range(txn, &bounds)? {
            let (key, _) = entry?;
            let seq = decode_seq(
                key.last_chunk::<8>()
                    .ok_or(StoreError::Corrupt("bad ix_pubkey_kind key"))?,
            )?;
            let packed = self
                .events
                .get(txn, &seq.to_be_bytes())?
                .ok_or(StoreError::Corrupt(
                    "ix_pubkey_kind points at a missing event",
                ))?
                .to_vec();
            stored.push((seq, packed));
        }
        for (_, bytes) in &stored {
            let old = PackedRef::new(bytes).ok_or(StoreError::Corrupt("bad packed record"))?;
            if supersedes(
                (old.created_at(), &old.id()),
                (event.created_at(), &event.id()),
            ) {
                return Ok(true);
            }
        }
        for (seq, _) in stored {
            if self.delete_seq(txn, seq)? {
                deleted.push(seq);
            }
        }
        Ok(false)
    }

    /// Apply every target of a stored kind-5 `event` (NIP-09). Targets
    /// are processed after the kind 5 itself is inserted.
    fn apply_deletions(
        &self,
        txn: &mut RwTxn<'_>,
        event: &Event,
        deleted: &mut Vec<u64>,
    ) -> Result<(), StoreError> {
        for target in event.deletion_targets() {
            match target {
                DeletionTarget::Event(id) => {
                    self.delete_event_target(txn, id, &event.pubkey(), deleted)?;
                }
                DeletionTarget::Address(address) => {
                    self.delete_address_target(
                        txn,
                        address,
                        event.created_at(),
                        &event.pubkey(),
                        deleted,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Delete the `e`-tagged event `id` when it is `author`'s own and
    /// neither a kind 5 (NIP-09: a deletion request cannot delete a
    /// deletion request) nor a kind 62 (NIP-62: a request to vanish
    /// cannot be deleted).
    fn delete_event_target(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EventId,
        author: &PublicKey,
        deleted: &mut Vec<u64>,
    ) -> Result<(), StoreError> {
        let Some(seqb) = self.ix_id.get(txn, &id.0)? else {
            return Ok(());
        };
        let seq = decode_seq(seqb)?;
        let deletable = {
            let Some(bytes) = self.events.get(txn, &seq.to_be_bytes())? else {
                return Ok(());
            };
            let packed = PackedRef::new(bytes).ok_or(StoreError::Corrupt("bad packed record"))?;
            packed.pubkey() == *author && packed.kind().0 != 5 && packed.kind().0 != 62
        };
        if deletable && self.delete_seq(txn, seq)? {
            deleted.push(seq);
        }
        Ok(())
    }

    /// Delete the stored version at `address` when it is `author`'s own
    /// and `created_at <= deleted_at` (the kind-5 timestamp).
    fn delete_address_target(
        &self,
        txn: &mut RwTxn<'_>,
        address: &[u8; 32],
        deleted_at: u64,
        author: &PublicKey,
        deleted: &mut Vec<u64>,
    ) -> Result<(), StoreError> {
        let Some(seqb) = self.ix_replace.get(txn, address)? else {
            return Ok(());
        };
        let seq = decode_seq(seqb)?;
        let deletable = {
            let Some(bytes) = self.events.get(txn, &seq.to_be_bytes())? else {
                return Ok(());
            };
            let packed = PackedRef::new(bytes).ok_or(StoreError::Corrupt("bad packed record"))?;
            packed.pubkey() == *author && packed.created_at() <= deleted_at
        };
        if deletable && self.delete_seq(txn, seq)? {
            deleted.push(seq);
        }
        Ok(())
    }

    /// Whether `index` has any key starting with `prefix`.
    fn has_prefix(&self, txn: &RwTxn<'_>, index: Index, prefix: &[u8]) -> Result<bool, StoreError> {
        Ok(self
            .db(index)
            .get_greater_than_or_equal_to(txn, prefix)?
            .is_some_and(|(key, _)| key.starts_with(prefix)))
    }

    /// Whether a kind-5 `a` deletion at `created_at` or later covers
    /// `address` — blocking equal-or-older versions of it.
    fn replace_deleted(
        &self,
        txn: &RwTxn<'_>,
        address: &[u8; 32],
        created_at: u64,
    ) -> Result<bool, StoreError> {
        let mut from = Vec::with_capacity(48);
        from.extend_from_slice(address);
        from.extend_from_slice(&created_at.to_be_bytes());
        from.extend_from_slice(&0u64.to_be_bytes());
        Ok(self
            .ix_replace_deletion
            .get_greater_than_or_equal_to(txn, &from)?
            .is_some_and(|(key, _)| key.starts_with(address)))
    }

    /// The `(seq, packed bytes)` of the stored event `ix_replace` points
    /// at for `address`; the record load doubles as an index-consistency
    /// check.
    fn stored_version(
        &self,
        txn: &RwTxn<'_>,
        address: &[u8; 32],
    ) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        let Some(old_seq) = self.ix_replace.get(txn, address)? else {
            return Ok(None);
        };
        let old_seq = decode_seq(old_seq)?;
        let bytes = self
            .events
            .get(txn, &old_seq.to_be_bytes())?
            .ok_or(StoreError::Corrupt("ix_replace points at a missing event"))?
            .to_vec();
        Ok(Some((old_seq, bytes)))
    }

    /// The stored vanish point `T` of `pubkey` — the maximum
    /// `created_at` of its honored NIP-62 requests.
    fn vanished_at(&self, txn: &RwTxn<'_>, pubkey: &[u8; 32]) -> Result<Option<u64>, StoreError> {
        self.ix_vanish
            .get(txn, pubkey)?
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| StoreError::Corrupt("bad ix_vanish value"))
            })
            .transpose()
    }

    /// Whether a NIP-62 vanish point covers `event`: the author's `T`
    /// blocks its events with `created_at <= T`, and a kind-1059 gift
    /// wrap is blocked by the `p`-tagged recipient's `T`.
    fn vanish_blocked(&self, txn: &RwTxn<'_>, event: &Event) -> Result<bool, StoreError> {
        if self
            .vanished_at(txn, &event.pubkey().0)?
            .is_some_and(|t| event.created_at() <= t)
        {
            return Ok(true);
        }
        if event.kind().0 != 1059 {
            return Ok(false);
        }
        for (name, value) in event.packed().tags() {
            let Ok(value) = <&[u8; 32]>::try_from(value) else {
                continue;
            };
            if name == b'p'
                && self
                    .vanished_at(txn, value)?
                    .is_some_and(|t| event.created_at() <= t)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Register `event`'s NIP-62 request: raise the author's vanish
    /// point to its `created_at` and queue the pubkey for
    /// [`Store::vanish_step`]. A raised point restarts the walk from
    /// the beginning so rows between the old and new `T` are covered;
    /// an equal-or-older request keeps the in-flight resume position.
    /// Returns whether undrained work is queued.
    fn record_vanish(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<bool, StoreError> {
        let pubkey = event.pubkey().0;
        let t = event.created_at();
        match self.vanished_at(txn, &pubkey)? {
            Some(old) if old >= t => {}
            _ => {
                self.ix_vanish.put(txn, &pubkey, &t.to_be_bytes())?;
                // Phase 0, no resume key: walk from the start.
                self.vanish_pending.put(txn, &pubkey, &[0])?;
                return Ok(true);
            }
        }
        Ok(self.vanish_pending.get(txn, &pubkey)?.is_some())
    }

    /// The highest assigned sequence number (`0` when empty); the upper
    /// bound scans observe.
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure.
    pub fn snapshot(&self) -> Result<u64, StoreError> {
        let txn = self.env.read_txn()?;
        Ok(self.next_seq(&txn)?.saturating_sub(1))
    }

    /// A TLS-less read transaction; callers drop it before returning.
    pub(crate) fn read_txn(&self) -> Result<Reader<'_>, StoreError> {
        Ok(self.env.read_txn()?)
    }

    /// Stream every stored event's canonical JSON to `emit`, ordered by
    /// `created_at` then seq (descending when `reverse`), inclusively
    /// bounded by `since`/`until`. One read transaction, so the stream
    /// is a consistent snapshot. Returns the emitted count.
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure, [`StoreError::Corrupt`] on a
    /// broken index invariant, [`StoreError::Io`] when `emit` fails.
    pub fn export(
        &self,
        since: u64,
        until: u64,
        reverse: bool,
        emit: &mut dyn FnMut(&str) -> std::io::Result<()>,
    ) -> Result<u64, StoreError> {
        let txn = self.read_txn()?;
        let mut lo = Vec::with_capacity(16);
        lo.extend_from_slice(&since.to_be_bytes());
        lo.extend_from_slice(&u64::MIN.to_be_bytes());
        let mut hi = Vec::with_capacity(16);
        hi.extend_from_slice(&until.to_be_bytes());
        hi.extend_from_slice(&u64::MAX.to_be_bytes());
        let bounds = (
            Bound::Included(lo.as_slice()),
            Bound::Included(hi.as_slice()),
        );
        let mut count = 0u64;
        let mut emit_row = |key: &[u8]| -> Result<(), StoreError> {
            let seq: &[u8; 8] = key
                .get(8..)
                .and_then(|s| s.try_into().ok())
                .ok_or(StoreError::Corrupt("bad ix_time key"))?;
            let Some(bytes) = self.payloads.get(&txn, seq)? else {
                return Err(StoreError::Corrupt("ix_time points at a missing payload"));
            };
            let json = std::str::from_utf8(bytes)
                .map_err(|_| StoreError::Corrupt("payload is not UTF-8"))?;
            emit(json)?;
            count += 1;
            Ok(())
        };
        if reverse {
            for entry in self.ix_time.rev_range(&txn, &bounds)? {
                emit_row(entry?.0)?;
            }
        } else {
            for entry in self.ix_time.range(&txn, &bounds)? {
                emit_row(entry?.0)?;
            }
        }
        Ok(count)
    }

    /// Check for stale entries in the reader lock table and clear them
    /// (`mdb_reader_check`): readers whose process died without closing
    /// their transaction would otherwise pin old pages forever, so
    /// `data.mdb` grows without bound. Returns the cleared count.
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure.
    pub fn clear_stale_readers(&self) -> Result<usize, StoreError> {
        Ok(self.env.clear_stale_readers()?)
    }

    /// Copy the environment to `dest` with LMDB compaction, producing a
    /// single `data.mdb`-style file. `dest` must not already exist.
    ///
    /// The copy is written to `<dest>.tmp`, fsynced, then published by a
    /// hard link that fails when `dest` exists — a crash mid-copy never
    /// leaves a plausible-looking partial file under the final name.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when `dest` exists, `<dest>.tmp` exists or
    /// cannot be created, or the publish fails, [`StoreError::Heed`] on
    /// LMDB failure.
    pub fn compact_to(&self, dest: &Path) -> Result<(), StoreError> {
        if dest.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("output file '{}' exists, not overwriting", dest.display()),
            )
            .into());
        }
        let mut tmp_name = dest.as_os_str().to_os_string();
        tmp_name.push(".tmp");
        let tmp = PathBuf::from(tmp_name);
        let mut file = std::fs::File::create_new(&tmp)?;
        let copied = self
            .env
            .copy_to_file(&mut file, CompactionOption::Enabled)
            .map_err(StoreError::from)
            .and_then(|()| {
                file.sync_all()?;
                std::fs::hard_link(&tmp, dest)?;
                std::fs::remove_file(&tmp)?;
                #[cfg(unix)]
                {
                    let dir = dest
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."));
                    std::fs::File::open(dir)?.sync_all()?;
                }
                Ok(())
            });
        match copied {
            Ok(()) => Ok(()),
            Err(err) => {
                drop(file);
                drop(std::fs::remove_file(&tmp));
                Err(err)
            }
        }
    }

    fn next_seq(&self, txn: &Reader<'_>) -> Result<u64, StoreError> {
        let bytes = self
            .meta
            .get(txn, b"next_seq")?
            .ok_or(StoreError::Corrupt("missing next_seq"))?;
        decode_seq(bytes)
    }

    pub(crate) const fn db(&self, index: Index) -> &BytesDb {
        match index {
            Index::Id => &self.ix_id,
            Index::Time => &self.ix_time,
            Index::Pubkey => &self.ix_pubkey,
            Index::Kind => &self.ix_kind,
            Index::PubkeyKind => &self.ix_pubkey_kind,
            Index::Tag => &self.ix_tag,
            Index::Replace => &self.ix_replace,
            Index::Expiration => &self.ix_expiration,
            Index::Deletion => &self.ix_deletion,
            Index::ReplaceDeletion => &self.ix_replace_deletion,
        }
    }

    /// Delete `seqs` still present, in one write transaction; returns
    /// the deleted count (admin path).
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure, [`StoreError::Corrupt`] on a
    /// broken index invariant.
    pub fn delete(&self, seqs: &[u64]) -> Result<u64, StoreError> {
        let mut txn = self.env.write_txn()?;
        let mut count = 0;
        for &seq in seqs {
            if self.delete_seq(&mut txn, seq)? {
                count += 1;
            }
        }
        txn.commit()?;
        Ok(count)
    }

    /// Delete every event whose NIP-40 `expiration` is `<= now`, at
    /// most `limit` of them, in one write transaction; returns the
    /// deleted count.
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure, [`StoreError::Corrupt`] on a
    /// broken index invariant.
    pub fn expire(&self, now: u64, limit: usize) -> Result<usize, StoreError> {
        let mut txn = self.env.write_txn()?;
        let mut seqs = Vec::with_capacity(limit.min(4096));
        let iter = self.ix_expiration.iter(&txn)?;
        for entry in iter.take(limit) {
            let (key, _) = entry?;
            let expiration: &[u8; 8] = key
                .first_chunk::<8>()
                .ok_or(StoreError::Corrupt("bad ix_expiration key"))?;
            if u64::from_be_bytes(*expiration) > now {
                break;
            }
            let seq: &[u8; 8] = key
                .get(8..)
                .and_then(|s| s.try_into().ok())
                .ok_or(StoreError::Corrupt("bad ix_expiration key"))?;
            seqs.push(u64::from_be_bytes(*seq));
        }
        let mut count = 0;
        for seq in seqs {
            if self.delete_seq(&mut txn, seq)? {
                count += 1;
            }
        }
        txn.commit()?;
        Ok(count)
    }

    /// Apply one NIP-86 `op` in a single write transaction and return
    /// the rebuilt [`Moderation`] snapshot. [`ModOp::BanEvent`] also
    /// deletes the stored event, when present, in the same
    /// transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure, [`StoreError::Corrupt`] on
    /// a broken index invariant.
    pub fn moderate(&self, op: ModOp) -> Result<Moderation, StoreError> {
        let mut txn = self.env.write_txn()?;
        match op {
            ModOp::BanPubkey { pubkey, reason } => {
                self.mod_pubkeys.put(
                    &mut txn,
                    &pubkey.0,
                    &state_reason(ST_BANNED, reason.as_deref()),
                )?;
            }
            ModOp::UnbanPubkey { pubkey } => {
                clear_mod_state(&mut txn, self.mod_pubkeys, &pubkey.0, ST_BANNED)?;
            }
            ModOp::AllowPubkey { pubkey, reason } => {
                self.mod_pubkeys.put(
                    &mut txn,
                    &pubkey.0,
                    &state_reason(ST_ALLOWED, reason.as_deref()),
                )?;
            }
            ModOp::UnallowPubkey { pubkey } => {
                clear_mod_state(&mut txn, self.mod_pubkeys, &pubkey.0, ST_ALLOWED)?;
            }
            ModOp::BanEvent { id, reason } => {
                self.mod_events.put(
                    &mut txn,
                    &id.0,
                    reason.as_deref().unwrap_or_default().as_bytes(),
                )?;
                if let Some(seq) = self.ix_id.get(&txn, &id.0)?.map(decode_seq) {
                    self.delete_seq(&mut txn, seq?)?;
                }
            }
            ModOp::UnbanEvent { id } => {
                self.mod_events.delete(&mut txn, &id.0)?;
            }
            ModOp::AllowKind { kind } => {
                self.mod_kinds
                    .put(&mut txn, &kind.to_be_bytes(), &[ST_ALLOWED])?;
            }
            ModOp::DisallowKind { kind } => {
                self.mod_kinds
                    .put(&mut txn, &kind.to_be_bytes(), &[ST_DISALLOWED])?;
            }
            ModOp::BlockIp { ip, reason } => {
                self.mod_ips.put(
                    &mut txn,
                    ip.to_string().as_bytes(),
                    reason.as_deref().unwrap_or_default().as_bytes(),
                )?;
            }
            ModOp::UnblockIp { ip } => {
                self.mod_ips.delete(&mut txn, ip.to_string().as_bytes())?;
            }
            ModOp::SetInfo { field, value } => {
                self.mod_info
                    .put(&mut txn, field.as_str().as_bytes(), value.as_bytes())?;
            }
        }
        let moderation = self.load_moderation(&txn)?;
        txn.commit()?;
        Ok(moderation)
    }

    /// Load the full [`Moderation`] snapshot — used at startup so a
    /// restart keeps every ban, and after each applied op.
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure, [`StoreError::Corrupt`] on
    /// a row that cannot decode.
    pub fn moderation(&self) -> Result<Moderation, StoreError> {
        let txn = self.env.read_txn()?;
        self.load_moderation(&txn)
    }

    /// Rebuild the in-memory snapshot from the five `mod_*` tables.
    fn load_moderation(&self, txn: &RoTxn<'_>) -> Result<Moderation, StoreError> {
        let mut m = Moderation::default();
        for entry in self.mod_pubkeys.iter(txn)? {
            let (key, value) = entry?;
            let pubkey = PublicKey(
                *key.first_chunk::<32>()
                    .ok_or(StoreError::Corrupt("bad mod_pubkeys key"))?,
            );
            let (state, reason) = split_state_reason(value)?;
            match state {
                ST_BANNED => {
                    m.banned_pubkeys.insert(pubkey, reason);
                }
                ST_ALLOWED => {
                    m.allowed_pubkeys.insert(pubkey, reason);
                }
                _ => return Err(StoreError::Corrupt("bad mod_pubkeys state")),
            }
        }
        for entry in self.mod_events.iter(txn)? {
            let (key, value) = entry?;
            let id = EventId(
                *key.first_chunk::<32>()
                    .ok_or(StoreError::Corrupt("bad mod_events key"))?,
            );
            m.banned_events.insert(id, mod_reason(value)?);
        }
        for entry in self.mod_kinds.iter(txn)? {
            let (key, value) = entry?;
            let kind = u16::from_be_bytes(
                *key.first_chunk::<2>()
                    .ok_or(StoreError::Corrupt("bad mod_kinds key"))?,
            );
            match *value {
                [ST_ALLOWED] => {
                    m.allowed_kinds.insert(kind);
                }
                [ST_DISALLOWED] => {
                    m.disallowed_kinds.insert(kind);
                }
                _ => return Err(StoreError::Corrupt("bad mod_kinds value")),
            }
        }
        for entry in self.mod_ips.iter(txn)? {
            let (key, value) = entry?;
            let ip = std::str::from_utf8(key)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or(StoreError::Corrupt("bad mod_ips key"))?;
            m.blocked_ips.insert(ip, mod_reason(value)?);
        }
        for entry in self.mod_info.iter(txn)? {
            let (key, value) = entry?;
            let value = Box::<str>::from(
                std::str::from_utf8(value)
                    .map_err(|_| StoreError::Corrupt("bad mod_info value"))?,
            );
            match key {
                b"name" => m.name = Some(value),
                b"description" => m.description = Some(value),
                b"icon" => m.icon = Some(value),
                _ => return Err(StoreError::Corrupt("bad mod_info key")),
            }
        }
        Ok(m)
    }

    /// Whether any pubkey has undrained vanish work (startup check so
    /// a vanish queued before a crash resumes).
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure.
    pub fn vanish_pending(&self) -> Result<bool, StoreError> {
        let txn = self.env.read_txn()?;
        Ok(self.vanish_pending.iter(&txn)?.next().is_some())
    }

    /// Drain pending vanish work examining at most `limit` index
    /// entries, in one write transaction. Per pubkey the walk visits
    /// the author's events with `created_at <= T` via `ix_pubkey`
    /// (kind 62 skipped — a request to vanish is never deleted), then
    /// kind-1059 gift wraps `p`-tagged to it via `ix_tag`, removing
    /// collected seqs through the full `Store::delete_seq` routine.
    /// The `vanish_pending` value is a resume cursor — a phase byte
    /// plus the last examined index key — so skipped rows (kind 62
    /// itself, non-wrap mentions of the author) are examined once
    /// across steps, and an exhausted wraps range removes the pubkey.
    /// The returned [`VanishStep::more`] is the writer's keep-going
    /// signal; `deleted` counts rows actually removed.
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure, [`StoreError::Corrupt`] on
    /// a broken index invariant.
    pub fn vanish_step(&self, limit: usize) -> Result<VanishStep, StoreError> {
        let mut txn = self.env.write_txn()?;
        let mut queue = Vec::new();
        for entry in self.vanish_pending.iter(&txn)? {
            let (key, value) = entry?;
            let pubkey: &[u8; 32] = key
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad vanish_pending key"))?;
            queue.push((*pubkey, value.to_vec()));
        }
        let mut budget = limit;
        let mut deleted = 0usize;
        let mut more = false;
        for (pubkey, resume) in queue {
            if budget == 0 {
                more = true;
                break;
            }
            let (removed, done) = self.drain_vanished(&mut txn, &pubkey, &resume, &mut budget)?;
            deleted += removed;
            more |= !done;
        }
        txn.commit()?;
        Ok(VanishStep { deleted, more })
    }

    /// Drain one pending pubkey's vanish ranges under the shared
    /// `budget` (decremented per examined entry): the author's events
    /// up to `T` via `ix_pubkey` (kind 62 excepted), then kind-1059
    /// gift wraps `p`-tagged to it via `ix_tag`. Collected seqs go
    /// through [`Store::delete_seq`]; the `vanish_pending` cursor is
    /// removed when both ranges drained and advanced otherwise.
    /// Returns the deleted count and whether the pubkey is done.
    fn drain_vanished(
        &self,
        txn: &mut RwTxn<'_>,
        pubkey: &[u8; 32],
        resume: &[u8],
        budget: &mut usize,
    ) -> Result<(usize, bool), StoreError> {
        let Some(t) = self.vanished_at(txn, pubkey)? else {
            self.vanish_pending.delete(txn, pubkey)?;
            return Ok((0, true));
        };
        let (mut phase, mut last) = decode_resume(resume)?;
        let mut seqs = Vec::new();
        let mut done = false;
        loop {
            let (index, prefix, keep): (&BytesDb, Vec<u8>, fn(u16) -> bool) = if phase == 0 {
                (&self.ix_pubkey, pubkey.to_vec(), |kind| kind != 62)
            } else {
                (&self.ix_tag, wraps_prefix(pubkey), |kind| kind == 1059)
            };
            let walk =
                self.collect_vanished(txn, (index, &prefix), t, last.as_deref(), keep, *budget)?;
            *budget -= walk.examined;
            seqs.extend(walk.seqs);
            last = walk.last;
            if !walk.drained {
                break;
            }
            if phase == 1 {
                done = true;
                break;
            }
            phase = 1;
            last = None;
        }
        let mut deleted = 0usize;
        for seq in seqs {
            deleted += usize::from(self.delete_seq(txn, seq)?);
        }
        if done {
            self.vanish_pending.delete(txn, pubkey)?;
        } else {
            let mut value = Vec::with_capacity(1 + last.as_ref().map_or(0, Vec::len));
            value.push(phase);
            if let Some(key) = &last {
                value.extend_from_slice(key);
            }
            self.vanish_pending.put(txn, pubkey, &value)?;
        }
        Ok((deleted, done))
    }

    /// Walk one vanish index range — `(last, range.1 ‖ T ‖ u64::MAX]`,
    /// or from the range start when `last` is `None` — examining at
    /// most `budget` entries and collecting seqs whose record kind
    /// `keep` accepts.
    fn collect_vanished(
        &self,
        txn: &RwTxn<'_>,
        range: (&BytesDb, &[u8]),
        t: u64,
        last: Option<&[u8]>,
        keep: fn(u16) -> bool,
        budget: usize,
    ) -> Result<RangeWalk, StoreError> {
        let (index, prefix) = range;
        let mut start = Vec::with_capacity(prefix.len() + 16);
        if let Some(key) = last {
            start.extend_from_slice(key);
        } else {
            start.extend_from_slice(prefix);
            start.extend_from_slice(&[0; 16]);
        }
        let lo = if last.is_some() {
            Bound::Excluded(&*start)
        } else {
            Bound::Included(&*start)
        };
        let mut end = Vec::with_capacity(prefix.len() + 16);
        end.extend_from_slice(prefix);
        end.extend_from_slice(&t.to_be_bytes());
        end.extend_from_slice(&u64::MAX.to_be_bytes());
        let bounds = (lo, Bound::Included(&*end));
        let mut walk = RangeWalk {
            seqs: Vec::new(),
            examined: 0,
            last: last.map(<[u8]>::to_vec),
            drained: false,
        };
        let mut iter = index.range(txn, &bounds)?;
        loop {
            if walk.examined >= budget {
                return Ok(walk);
            }
            let Some(entry) = iter.next() else {
                walk.drained = true;
                return Ok(walk);
            };
            walk.examined += 1;
            let (key, _) = entry?;
            walk.last = Some(key.to_vec());
            let seq = decode_seq(
                key.last_chunk::<8>()
                    .ok_or(StoreError::Corrupt("bad vanish index key"))?,
            )?;
            let packed = PackedRef::new(self.events.get(txn, &seq.to_be_bytes())?.ok_or(
                StoreError::Corrupt("vanish index points at a missing event"),
            )?)
            .ok_or(StoreError::Corrupt("bad packed record"))?;
            if keep(packed.kind().0) {
                walk.seqs.push(seq);
            }
        }
    }

    fn insert(&self, txn: &mut RwTxn<'_>, event: &Event, seq: u64) -> Result<(), StoreError> {
        self.events
            .put(txn, &seq.to_be_bytes(), event.packed().as_bytes())?;
        self.payloads
            .put(txn, &seq.to_be_bytes(), event.json().as_bytes())?;
        let mut entries = Vec::new();
        index_entries(
            event.packed(),
            event.address(),
            event.expiration().unwrap_or(0),
            event.deletion_targets(),
            seq,
            &mut entries,
        );
        for (index, key, value) in entries {
            self.db(index).put(txn, &key, &value)?;
        }
        Ok(())
    }

    /// Remove every record and index key of `seq`; `false` when it is
    /// already gone. Index keys are derived from the stored canonical
    /// JSON — the packed record alone cannot reproduce an `address`,
    /// `e`, or `a` value longer than 255 bytes.
    fn delete_seq(&self, txn: &mut RwTxn<'_>, seq: u64) -> Result<bool, StoreError> {
        let seqb = seq.to_be_bytes();
        let mut entries = Vec::new();
        {
            let Some(json) = self.payloads.get(txn, &seqb)? else {
                return Ok(false);
            };
            let json = std::str::from_utf8(json)
                .map_err(|_| StoreError::Corrupt("payload is not UTF-8"))?;
            let unverified = UnverifiedEvent::parse_structural(json)
                .map_err(|_| StoreError::Corrupt("stored payload fails structural parse"))?;
            let packed_bytes = self
                .events
                .get(txn, &seqb)?
                .ok_or(StoreError::Corrupt("payload without packed record"))?;
            let packed =
                PackedRef::new(packed_bytes).ok_or(StoreError::Corrupt("bad packed record"))?;
            index_entries(
                packed,
                unverified.address(),
                unverified.expiration().unwrap_or(0),
                &unverified.deletion_targets(),
                seq,
                &mut entries,
            );
        }
        for (index, key, _) in &entries {
            self.db(*index).delete(txn, key)?;
        }
        self.events.delete(txn, &seqb)?;
        self.payloads.delete(txn, &seqb)?;
        Ok(true)
    }
}

/// The `ix_deletion` lookup prefix `id ‖ pubkey` for an incoming event.
fn deletion_prefix(event: &Event) -> [u8; 64] {
    let mut prefix = [0u8; 64];
    let (id, pubkey) = prefix.split_at_mut(32);
    id.copy_from_slice(&event.id().0);
    pubkey.copy_from_slice(&event.pubkey().0);
    prefix
}

/// The `('p' ‖ 32 ‖ pubkey)` `ix_tag` range prefix for gift wraps
/// `p`-tagged to a vanishing author.
fn wraps_prefix(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(34);
    prefix.extend_from_slice(&[b'p', 32]);
    prefix.extend_from_slice(pubkey);
    prefix
}

/// A `vanish_pending` value: phase byte (`0` author range, `1` wraps
/// range) plus the last examined index key (`None` = walk not
/// started).
fn decode_resume(value: &[u8]) -> Result<(u8, Option<Vec<u8>>), StoreError> {
    let (phase, rest) = value
        .split_first()
        .ok_or(StoreError::Corrupt("bad vanish_pending value"))?;
    match *phase {
        0 | 1 => Ok((*phase, (!rest.is_empty()).then(|| rest.to_vec()))),
        _ => Err(StoreError::Corrupt("bad vanish_pending phase")),
    }
}

fn decode_seq(bytes: &[u8]) -> Result<u64, StoreError> {
    let arr: &[u8; 8] = bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("bad seq value"))?;
    Ok(u64::from_be_bytes(*arr))
}

/// A `mod_pubkeys` value: state byte ‖ reason.
fn state_reason(state: u8, reason: Option<&str>) -> Vec<u8> {
    let reason = reason.unwrap_or_default();
    let mut value = Vec::with_capacity(reason.len() + 1);
    value.push(state);
    value.extend_from_slice(reason.as_bytes());
    value
}

/// Split a `mod_pubkeys` value into `(state, reason)`.
fn split_state_reason(value: &[u8]) -> Result<(u8, Option<Box<str>>), StoreError> {
    let (state, reason) = value
        .split_first()
        .ok_or(StoreError::Corrupt("bad mod_pubkeys value"))?;
    Ok((*state, mod_reason(reason)?))
}

/// A `mod_*` reason: `None` when empty, a decode error when not UTF-8.
fn mod_reason(value: &[u8]) -> Result<Option<Box<str>>, StoreError> {
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(Box::from(std::str::from_utf8(value).map_err(
        |_| StoreError::Corrupt("bad moderation reason"),
    )?)))
}

/// Delete a `mod_pubkeys` row only when it currently holds `state` —
/// `unbanpubkey` must not drop an allow entry (and vice versa).
fn clear_mod_state(
    txn: &mut RwTxn<'_>,
    db: BytesDb,
    key: &[u8],
    state: u8,
) -> Result<(), StoreError> {
    if db.get(txn, key)?.is_some_and(|v| v.first() == Some(&state)) {
        db.delete(txn, key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "unit tests may panic on failure"
    )]

    use std::sync::Arc;

    use nosfry_core::sign::{event, key};
    use serde_json::json;

    use super::*;

    /// `index_entry_count` must equal the number of entries
    /// `index_entries` produces, over events exercising every index.
    #[test]
    fn index_entry_count_matches_index_entries() {
        let signer = key(1);
        let kind5 = event(
            &signer,
            5,
            100,
            &json!([
                ["e", "aa".repeat(32)],
                ["a", format!("1:{}:d", "bb".repeat(32))]
            ]),
            "del",
        );
        let addressable = event(
            &signer,
            30000,
            100,
            &json!([
                ["d", "art"],
                ["expiration", "999999999"],
                ["t", "x"],
                ["e", "cc".repeat(32)]
            ]),
            "addr",
        );
        let plain = event(&signer, 1, 100, &json!([]), "plain");
        let tag_heavy = event(
            &signer,
            1,
            100,
            &json!([["t", "a"], ["t", "b"], ["t", "c"], ["e", "dd".repeat(32)]]),
            "tags",
        );
        for e in [&kind5, &addressable, &plain, &tag_heavy] {
            let mut entries = Vec::new();
            index_entries(
                e.packed(),
                e.address(),
                e.expiration().unwrap_or(0),
                e.deletion_targets(),
                7,
                &mut entries,
            );
            assert_eq!(index_entry_count(e), entries.len(), "kind {}", e.kind().0);
        }
    }

    /// Deleting a superseded event must leave no index entry pointing at
    /// its sequence number.
    #[test]
    fn delete_removes_all_index_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let signer = key(1);
        let old = event(&signer, 0, 100, &json!([["t", "x"]]), "old");
        let new = event(&signer, 0, 200, &json!([["t", "x"]]), "new");
        let outcomes = store.write(&[Arc::clone(&old), new], None).unwrap();
        assert_eq!(
            outcomes.outcomes,
            vec![
                WriteOutcome::Stored { seq: 1 },
                WriteOutcome::Stored { seq: 2 }
            ]
        );
        let old_seq = 1u64.to_be_bytes();
        let txn = store.read_txn().unwrap();
        assert!(store.events.get(&txn, &old_seq).unwrap().is_none());
        assert!(store.payloads.get(&txn, &old_seq).unwrap().is_none());
        assert!(store.ix_id.get(&txn, &old.id().0).unwrap().is_none());
        assert!(
            store
                .ix_replace
                .get(&txn, &old.address().unwrap())
                .unwrap()
                .is_some_and(|v| v != old_seq)
        );
        for db in [
            store.ix_time,
            store.ix_pubkey,
            store.ix_kind,
            store.ix_pubkey_kind,
            store.ix_tag,
            store.ix_expiration,
            store.ix_deletion,
            store.ix_replace_deletion,
        ] {
            for entry in db.iter(&txn).unwrap() {
                let (key, _) = entry.unwrap();
                assert_ne!(key[key.len() - 8..], old_seq, "stale index key {key:?}");
            }
        }
    }

    /// Every seq-suffixed index must be empty of `seq`; `ix_id` and
    /// `ix_replace` are point lookups checked separately by the caller.
    fn assert_seq_gone(store: &Store, seq: u64) {
        let seqb = seq.to_be_bytes();
        let txn = store.read_txn().unwrap();
        assert!(store.events.get(&txn, &seqb).unwrap().is_none());
        assert!(store.payloads.get(&txn, &seqb).unwrap().is_none());
        for db in [
            store.ix_time,
            store.ix_pubkey,
            store.ix_kind,
            store.ix_pubkey_kind,
            store.ix_tag,
            store.ix_expiration,
            store.ix_deletion,
            store.ix_replace_deletion,
        ] {
            for entry in db.iter(&txn).unwrap() {
                let (key, _) = entry.unwrap();
                assert_ne!(key[key.len() - 8..], seqb, "stale index key {key:?}");
            }
        }
    }

    /// An NIP-09 delete removes every index key of an expiring
    /// addressable target, including the lifecycle databases.
    #[test]
    fn deletion_removes_all_index_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let signer = key(1);
        let pk = format!("{}", signer.x_only_public_key().0);
        let target = event(
            &signer,
            30_023,
            100,
            &json!([["d", "art"], ["expiration", "999999999"], ["t", "x"]]),
            "v",
        );
        let kind5 = event(
            &signer,
            5,
            200,
            &json!([
                ["e", format!("{}", target.id())],
                ["a", format!("30023:{pk}:art")]
            ]),
            "",
        );
        let written = store
            .write(&[Arc::clone(&target), Arc::clone(&kind5)], None)
            .unwrap();
        assert_eq!(written.deleted, vec![1]);
        assert_seq_gone(&store, 1);
        let txn = store.read_txn().unwrap();
        assert!(store.ix_id.get(&txn, &target.id().0).unwrap().is_none());
        assert!(
            store
                .ix_replace
                .get(&txn, &target.address().unwrap())
                .unwrap()
                .is_none()
        );
        drop(txn);
        // Deleting the kind 5 removes its own lifecycle index rows.
        assert_eq!(store.delete(&[2]).unwrap(), 1);
        assert_seq_gone(&store, 2);
    }

    /// `expire` removes every index key of the swept events, and the
    /// `ix_replace` entry of a long `d` survives nowhere.
    #[test]
    fn expire_removes_all_index_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let signer = key(1);
        let long_d = "d".repeat(300);
        let target = event(
            &signer,
            30_002,
            100,
            &json!([["d", long_d], ["expiration", "150"], ["t", "x"]]),
            "v",
        );
        store.write(&[Arc::clone(&target)], None).unwrap();
        assert_eq!(store.expire(200, 10).unwrap(), 1);
        assert_seq_gone(&store, 1);
        let txn = store.read_txn().unwrap();
        assert!(store.ix_id.get(&txn, &target.id().0).unwrap().is_none());
        assert!(
            store
                .ix_replace
                .get(&txn, &target.address().unwrap())
                .unwrap()
                .is_none()
        );
    }
}
