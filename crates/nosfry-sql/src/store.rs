//! Schema, writes, expiry and the shared row helpers.

use std::ops::ControlFlow;
use std::sync::Arc;

use nosfry_core::auth::ReadGate;
use nosfry_core::deletion::DeletionTarget;
use nosfry_core::event::{Event, EventId, PublicKey, UnverifiedEvent, supersedes};
use nosfry_core::filter::Filter;
use nosfry_core::hll::Hll;
use nosfry_core::moderation::{ModOp, Moderation};
use nosfry_core::packed::PackedRef;
use nosfry_core::store::WriteOutcome;
use nosfry_core::url::RelayUrl;

use crate::exec::{Executor, Param, Value};
use crate::{Count, Hit, Records, Scan, StoreError};

/// The on-disk schema version `meta.format` must hold.
pub const FORMAT_VERSION: i64 = 3;

/// The largest integer JavaScript exchanges losslessly (`2^53 - 1`).
/// Every integer bound into SQL is clamped to it; a `created_at`
/// above it cannot be stored at all.
pub(crate) const JS_MAX: u64 = (1 << 53) - 1;

/// `v` as a SQL integer parameter, clamped to the JavaScript-safe
/// range: workerd refuses integers it cannot exchange losslessly.
pub(crate) fn int(v: u64) -> Param<'static> {
    Param::Int(i64::try_from(v.min(JS_MAX)).unwrap_or(i64::MAX))
}

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value INTEGER NOT NULL
    ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id BLOB NOT NULL UNIQUE,
        pubkey BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        kind INTEGER NOT NULL,
        address BLOB UNIQUE,
        expiration INTEGER,
        packed BLOB NOT NULL,
        json TEXT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS ix_time ON events (created_at)",
    "CREATE INDEX IF NOT EXISTS ix_pubkey ON events (pubkey, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_kind ON events (kind, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_pubkey_kind ON events (pubkey, kind, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_expiration ON events (expiration) WHERE expiration IS NOT NULL",
    "CREATE TABLE IF NOT EXISTS tags (
        name INTEGER NOT NULL,
        value BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        PRIMARY KEY (name, value, created_at, seq)
    ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS deletions (
        target BLOB NOT NULL,
        author BLOB NOT NULL,
        carrier INTEGER NOT NULL,
        PRIMARY KEY (target, author, carrier)
    ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS replace_deletions (
        address BLOB NOT NULL,
        deleted_at INTEGER NOT NULL,
        carrier INTEGER NOT NULL,
        PRIMARY KEY (address, deleted_at, carrier)
    ) WITHOUT ROWID",
    // NIP-62: `pubkey` → vanish point `T`, the maximum `created_at`
    // of its honored requests to vanish.
    "CREATE TABLE IF NOT EXISTS vanish (
        pubkey BLOB PRIMARY KEY,
        until INTEGER NOT NULL
    ) WITHOUT ROWID",
    // NIP-62: pubkeys whose vanish ranges are not drained — a
    // persistent work queue so a restart resumes mid-vanish. `phase`
    // is 0 for the author's own events (`ix_pubkey`) and 1 for
    // kind-1059 wraps `p`-tagged to it (`tags`); `(created_at, seq)`
    // is the exclusive keyset resume point, NULL for "from the top".
    "CREATE TABLE IF NOT EXISTS vanish_pending (
        pubkey BLOB PRIMARY KEY,
        phase INTEGER NOT NULL,
        created_at INTEGER,
        seq INTEGER
    ) WITHOUT ROWID",
    // NIP-86: one `mod_pubkeys` row carries the pubkey's current
    // state, so ban↔allow exclusivity is automatic on REPLACE.
    // `reason` is NULL for absent-or-empty.
    "CREATE TABLE IF NOT EXISTS mod_pubkeys (
        pubkey BLOB PRIMARY KEY,
        state INTEGER NOT NULL,
        reason TEXT
    ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS mod_events (
        id BLOB PRIMARY KEY,
        reason TEXT
    ) WITHOUT ROWID",
    // NIP-86: one `mod_kinds` row carries the kind's current state —
    // allow↔disallow exclusivity is automatic on REPLACE.
    "CREATE TABLE IF NOT EXISTS mod_kinds (
        kind INTEGER PRIMARY KEY,
        state INTEGER NOT NULL
    ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS mod_ips (
        ip TEXT PRIMARY KEY,
        reason TEXT
    ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS mod_info (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    ) WITHOUT ROWID",
];

/// `mod_pubkeys`/`mod_kinds` state codes (the LMDB layout's state
/// bytes): a single row per key carries the current state, so
/// ban↔allow and allow↔disallow exclusivity is automatic on REPLACE.
const ST_BANNED: i64 = 0;
const ST_ALLOWED: i64 = 1;
const ST_DISALLOWED: i64 = 2;

/// The result of one [`SqlStore::write`] transaction.
#[derive(Debug, Default)]
pub struct Written {
    /// One outcome per input event, in arrival order.
    pub outcomes: Vec<WriteOutcome>,
    /// A stored (or duplicate) NIP-62 request queued deletion work:
    /// the caller should keep draining [`SqlStore::vanish_step`].
    pub vanish_pending: bool,
}

/// Outcome of one [`SqlStore::vanish_step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VanishStep {
    /// Events deleted in this step.
    pub deleted: usize,
    /// `vanish_pending` still holds work — call again.
    pub more: bool,
}

/// The event store: writes, scans and expiry over an [`Executor`].
#[derive(Debug)]
pub struct SqlStore<E> {
    exec: E,
}

impl<E: Executor> SqlStore<E> {
    /// Open the store on `exec`, creating the schema when absent. An
    /// existing `meta.format` other than [`FORMAT_VERSION`] is
    /// refused; until the first release, schema changes replace the
    /// schema — there are no migrations.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::Corrupt`] on an unknown format version.
    pub fn open(exec: E) -> Result<Self, StoreError> {
        let store = Self { exec };
        store.exec.transaction(|| {
            for statement in SCHEMA {
                store.exec_sql(statement, &[])?;
            }
            let mut versions = Vec::new();
            store.query_rows("SELECT value FROM meta WHERE key = 'format'", &[], |row| {
                versions.extend_from_slice(row);
                Ok(())
            })?;
            match versions.first() {
                None => store.exec_sql(
                    "INSERT INTO meta (key, value) VALUES ('format', ?1)",
                    &[Param::Int(FORMAT_VERSION)],
                ),
                Some(Value::Int(v)) if *v == FORMAT_VERSION => Ok(()),
                Some(_) => Err(StoreError::Corrupt("unknown store format version")),
            }
        })?;
        Ok(store)
    }

    /// Apply `events` in arrival order inside a single transaction,
    /// one [`WriteOutcome`] per input. `service_url` is the relay's
    /// own URL for NIP-62: a stored (or duplicate) request to vanish
    /// naming it or `ALL_RELAYS` raises the author's vanish point and
    /// queues the sweep [`SqlStore::vanish_step`] drains.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::OutOfRange`] on a `created_at` above the
    /// JavaScript-safe integer range, [`StoreError::Corrupt`] on a
    /// broken index invariant.
    pub fn write(
        &self,
        events: &[Arc<Event>],
        service_url: Option<&RelayUrl>,
    ) -> Result<Written, StoreError> {
        self.exec.transaction(|| {
            let mut written = Written {
                outcomes: Vec::with_capacity(events.len()),
                vanish_pending: false,
            };
            for event in events {
                written.vanish_pending |=
                    self.apply_event(event, service_url, &mut written.outcomes)?;
            }
            Ok(written)
        })
    }

    /// Delete every event whose NIP-40 `expiration` is `<= now`, at
    /// most `limit` of them, in one transaction; returns the deleted
    /// count.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::Corrupt`] on a broken index invariant.
    pub fn expire(&self, now: u64, limit: usize) -> Result<usize, StoreError> {
        self.exec.transaction(|| {
            let mut seqs = Vec::new();
            self.query_rows(
                "SELECT seq FROM events INDEXED BY ix_expiration
                 WHERE expiration <= ?1 ORDER BY expiration LIMIT ?2",
                &[int(now), int(limit as u64)],
                |row| {
                    seqs.push(uint(row, 0)?);
                    Ok(())
                },
            )?;
            for seq in &seqs {
                self.delete_seq(*seq)?;
            }
            Ok(seqs.len())
        })
    }

    /// The earliest stored NIP-40 `expiration`, or `None` when
    /// nothing expires — the next alarm time after
    /// [`SqlStore::expire`]. `ix_expiration` serves the `MIN`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::Corrupt`] on a broken row shape.
    pub fn next_expiration(&self) -> Result<Option<u64>, StoreError> {
        let row = self.row(
            "SELECT MIN(expiration) FROM events WHERE expiration IS NOT NULL",
            &[],
        )?;
        match row.as_deref() {
            // MIN over an empty set is NULL.
            Some([Value::Null] | []) | None => Ok(None),
            Some(row) => Ok(Some(uint(row, 0)?)),
        }
    }

    /// The underlying executor, for plan inspection and raw
    /// statements the store does not cover.
    pub const fn exec(&self) -> &E {
        &self.exec
    }

    /// Consume the store and return its executor.
    pub fn into_exec(self) -> E {
        self.exec
    }

    /// The stored events matching `filters`, per filter newest-first
    /// and deduplicated by seq across filters, streamed to `sink` in
    /// order; payloads are fetched in chunks so at most one chunk is
    /// resident at a time. `max_rows` bounds index rows examined; see
    /// [`crate::Scan`] for the budget semantics.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::Corrupt`] on a broken index invariant.
    pub fn query(
        &self,
        filters: &[Filter],
        gate: &ReadGate,
        now: u64,
        max_limit: u64,
        max_rows: usize,
        sink: &mut dyn FnMut(Hit),
    ) -> Result<Scan, StoreError> {
        crate::scan::scan(&self.exec, filters, gate, now, max_limit, max_rows, sink)
    }

    /// The `(created_at, id)` records `filters` match under `gate`,
    /// at NIP-40 cutoff `now` (`0` disables it) — the same engine
    /// `query` uses, without the payload fetch. `max_limit` is the
    /// caller's cap plus one so "at the cap" and "over" differ;
    /// `max_rows` bounds index rows examined, reported through
    /// `budget_exhausted`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::Corrupt`] on a broken index invariant.
    pub fn records(
        &self,
        filters: &[Filter],
        gate: &ReadGate,
        now: u64,
        max_limit: u64,
        max_rows: usize,
    ) -> Result<Records, StoreError> {
        crate::scan::records(&self.exec, filters, gate, now, max_limit, max_rows)
    }

    /// The number of stored events `filters` match under `gate` —
    /// the union a `query` without limits would return, counted, at
    /// NIP-40 cutoff `now` (`0` disables it). Rows read count toward
    /// `max_rows`; reaching it answers `approximate` with a partial
    /// count, never an over-count. `hll` is the sketch to feed with
    /// counted authors (from `Hll::for_filters`); see [`Count`].
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::Corrupt`] on a broken index invariant.
    pub fn count(
        &self,
        filters: &[Filter],
        gate: &ReadGate,
        now: u64,
        max_rows: usize,
        hll: Option<Hll>,
    ) -> Result<Count, StoreError> {
        crate::scan::count(&self.exec, filters, gate, now, max_rows, hll)
    }

    /// Apply one event inside the write transaction: ephemeral and
    /// duplicate ids are skipped, a NIP-09-blocked event is `Deleted`,
    /// a losing replace is `Superseded`, a winner deletes its
    /// predecessor before the insert, and a stored kind 5 deletes its
    /// targets. Identical to the LMDB store minus the writer-side
    /// plumbing (`deleted` seqs go to no listener here).
    fn apply(&self, event: &Event) -> Result<WriteOutcome, StoreError> {
        // NIP-62: a stored request to vanish blocks the author's
        // equal-or-older events (never a kind 62 itself) and gift
        // wraps `p`-tagged to a vanished pubkey.
        if event.kind().0 != 62 && self.vanish_blocked(event)? {
            return Ok(WriteOutcome::Vanished);
        }
        if event.kind().is_ephemeral() {
            return Ok(WriteOutcome::Ephemeral);
        }
        if event.created_at() > JS_MAX {
            return Err(StoreError::OutOfRange(
                "created_at exceeds the JavaScript-safe integer range",
            ));
        }
        let id = event.id().0;
        if self.exists("SELECT 1 FROM events WHERE id = ?1", &[Param::Blob(&id)])? {
            return Ok(WriteOutcome::Duplicate);
        }
        // NIP-62: relays may keep the signed request to vanish for
        // bookkeeping — store only the author's newest.
        if event.kind().0 == 62 && self.vanish_request_superseded(event)? {
            return Ok(WriteOutcome::Superseded);
        }
        // NIP-09: an id covered by a stored same-author kind 5 stays
        // deleted; a kind 5 itself is never blocked, and a kind 62
        // request to vanish is never blocked either (NIP-62).
        let pubkey = event.pubkey().0;
        if event.kind().0 != 5
            && event.kind().0 != 62
            && self.exists(
                "SELECT 1 FROM deletions WHERE target = ?1 AND author = ?2 LIMIT 1",
                &[Param::Blob(&id), Param::Blob(&pubkey)],
            )?
        {
            return Ok(WriteOutcome::Deleted);
        }
        // NIP-09: an `a` deletion blocks equal-or-older versions.
        let created = int(event.created_at());
        if let Some(address) = event.address()
            && self.exists(
                "SELECT 1 FROM replace_deletions
                 WHERE address = ?1 AND deleted_at >= ?2 LIMIT 1",
                &[Param::Blob(&address), created],
            )?
        {
            return Ok(WriteOutcome::Deleted);
        }
        if let Some(address) = event.address()
            && let Some(old) = self.row(
                "SELECT seq, packed FROM events WHERE address = ?1",
                &[Param::Blob(&address)],
            )?
        {
            let old_seq = uint(&old, 0)?;
            let packed = record(&old, 1)?;
            if !supersedes(
                (event.created_at(), &event.id()),
                (packed.created_at(), &packed.id()),
            ) {
                return Ok(WriteOutcome::Superseded);
            }
            self.delete_seq(old_seq)?;
        }
        let address = event.address();
        self.exec_sql(
            "INSERT INTO events (id, pubkey, created_at, kind, address, expiration, packed, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            &[
                Param::Blob(&id),
                Param::Blob(&pubkey),
                created,
                Param::Int(i64::from(event.kind().0)),
                address
                    .as_ref()
                    .map_or(Param::Null, |a| Param::Blob(a.as_slice())),
                event.expiration().map_or(Param::Null, int),
                Param::Blob(event.packed().as_bytes()),
                Param::Text(event.json()),
            ],
        )?;
        let seq = self.last_rowid()?;
        for (name, value) in event.packed().tags() {
            self.exec_sql(
                "INSERT OR IGNORE INTO tags (name, value, created_at, seq)
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    Param::Int(i64::from(name)),
                    Param::Blob(value),
                    created,
                    int(seq),
                ],
            )?;
        }
        for target in event.deletion_targets() {
            match target {
                DeletionTarget::Event(target) => self.exec_sql(
                    "INSERT OR IGNORE INTO deletions (target, author, carrier)
                     VALUES (?1, ?2, ?3)",
                    &[Param::Blob(&target.0), Param::Blob(&pubkey), int(seq)],
                )?,
                DeletionTarget::Address(addr) => self.exec_sql(
                    "INSERT OR IGNORE INTO replace_deletions (address, deleted_at, carrier)
                     VALUES (?1, ?2, ?3)",
                    &[Param::Blob(addr), created, int(seq)],
                )?,
            }
        }
        if event.kind().0 == 5 {
            self.apply_deletions(event)?;
        }
        Ok(WriteOutcome::Stored { seq })
    }

    /// Whether a stored kind-62 of `event`'s author supersedes the
    /// incoming request — `true` means the caller answers `Superseded`.
    /// Otherwise every stored one is deleted and `event` may insert, so
    /// a db holding several requests collapses to the newest. Seqs are
    /// collected before deleting — never mutate while iterating.
    fn vanish_request_superseded(&self, event: &Event) -> Result<bool, StoreError> {
        let mut stored_newer = false;
        let mut seqs = Vec::new();
        self.query_rows(
            "SELECT seq, packed FROM events WHERE pubkey = ?1 AND kind = 62",
            &[Param::Blob(&event.pubkey().0)],
            |row| {
                let old = record(row, 1)?;
                if supersedes(
                    (old.created_at(), &old.id()),
                    (event.created_at(), &event.id()),
                ) {
                    stored_newer = true;
                    return Ok(());
                }
                seqs.push(uint(row, 0)?);
                Ok(())
            },
        )?;
        if stored_newer {
            return Ok(true);
        }
        for seq in seqs {
            self.delete_seq(seq)?;
        }
        Ok(false)
    }

    /// Apply one event and, when it is a stored (or duplicate)
    /// NIP-62 request this relay honors, raise the author's vanish
    /// point and queue the sweep. Returns whether undrained work is
    /// queued.
    fn apply_event(
        &self,
        event: &Arc<Event>,
        service_url: Option<&RelayUrl>,
        outcomes: &mut Vec<WriteOutcome>,
    ) -> Result<bool, StoreError> {
        let outcome = self.apply(event)?;
        outcomes.push(outcome);
        if event.requests_vanish(service_url)
            && matches!(
                outcome,
                WriteOutcome::Stored { .. } | WriteOutcome::Duplicate
            )
        {
            return self.record_vanish(event);
        }
        Ok(false)
    }

    /// The stored vanish point `T` of `pubkey` — the maximum
    /// `created_at` of its honored NIP-62 requests.
    fn vanished_at(&self, pubkey: &[u8; 32]) -> Result<Option<u64>, StoreError> {
        match self.row(
            "SELECT until FROM vanish WHERE pubkey = ?1",
            &[Param::Blob(pubkey)],
        )? {
            Some(row) => Ok(Some(uint(&row, 0)?)),
            None => Ok(None),
        }
    }

    /// Whether a NIP-62 vanish point covers `event`: the author's `T`
    /// blocks its events with `created_at <= T`, and a kind-1059 gift
    /// wrap is blocked by the `p`-tagged recipient's `T`.
    fn vanish_blocked(&self, event: &Event) -> Result<bool, StoreError> {
        if self
            .vanished_at(&event.pubkey().0)?
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
                    .vanished_at(value)?
                    .is_some_and(|t| event.created_at() <= t)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Register `event`'s NIP-62 request: raise the author's vanish
    /// point to its `created_at` and queue the pubkey for
    /// [`SqlStore::vanish_step`]. A raised point restarts the walk
    /// from the beginning so rows between the old and new `T` are
    /// covered; an equal-or-older request keeps the in-flight resume
    /// position. Returns whether undrained work is queued.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure.
    fn record_vanish(&self, event: &Event) -> Result<bool, StoreError> {
        let pubkey = event.pubkey().0;
        match self.vanished_at(&pubkey)? {
            Some(old) if old >= event.created_at() => {}
            _ => {
                self.exec_sql(
                    "INSERT OR REPLACE INTO vanish (pubkey, until) VALUES (?1, ?2)",
                    &[Param::Blob(&pubkey), int(event.created_at())],
                )?;
                // Phase 0, no resume key: walk from the start.
                self.exec_sql(
                    "INSERT OR REPLACE INTO vanish_pending
                     (pubkey, phase, created_at, seq) VALUES (?1, 0, NULL, NULL)",
                    &[Param::Blob(&pubkey)],
                )?;
                return Ok(true);
            }
        }
        self.exists(
            "SELECT 1 FROM vanish_pending WHERE pubkey = ?1",
            &[Param::Blob(&pubkey)],
        )
    }

    /// Whether any pubkey has undrained vanish work (startup check so
    /// a vanish queued before a crash resumes).
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure.
    pub fn vanish_pending(&self) -> Result<bool, StoreError> {
        self.exists("SELECT 1 FROM vanish_pending LIMIT 1", &[])
    }

    /// Drain pending vanish work examining at most `limit` index
    /// rows, in one transaction and shared across queued pubkeys.
    /// Per pubkey the walk visits the author's events with
    /// `created_at <= T` via `ix_pubkey` (kind 62 skipped — a request
    /// to vanish is never deleted), then kind-1059 gift wraps
    /// `p`-tagged to it via `tags`, removing collected seqs through
    /// the full `delete_seq` routine. The `vanish_pending`
    /// row is a resume cursor — the phase plus the last examined
    /// `(created_at, seq)` — so skipped rows (kind 62 itself,
    /// non-wrap mentions of the author) are examined once across
    /// steps, and an exhausted wraps range removes the pubkey.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::Corrupt`] on a broken index invariant.
    pub fn vanish_step(&self, limit: usize) -> Result<VanishStep, StoreError> {
        self.exec.transaction(|| {
            let mut queue = Vec::new();
            self.query_rows(
                "SELECT pubkey, phase, created_at, seq FROM vanish_pending ORDER BY pubkey",
                &[],
                |row| {
                    queue.push(PendingVanish {
                        pubkey: blob(row, 0)?,
                        phase: uint(row, 1)?,
                        created_at: opt_uint(row, 2)?,
                        seq: opt_uint(row, 3)?,
                    });
                    Ok(())
                },
            )?;
            self.drain_queue(&queue, limit)
        })
    }

    /// Drain queued pubkeys in order under one shared `budget`.
    fn drain_queue(&self, queue: &[PendingVanish], limit: usize) -> Result<VanishStep, StoreError> {
        let mut budget = limit;
        let mut deleted = 0usize;
        let mut more = false;
        for pending in queue {
            if budget == 0 {
                more = true;
                break;
            }
            let (removed, done) = self.drain_vanished(
                &pending.pubkey,
                pending.phase,
                pending.created_at,
                pending.seq,
                &mut budget,
            )?;
            deleted += removed;
            more |= !done;
        }
        Ok(VanishStep { deleted, more })
    }

    /// Drain one pending pubkey's vanish ranges under the shared
    /// `budget` (decremented per examined row), then `delete_seq` the
    /// collected seqs and advance or remove the `vanish_pending`
    /// cursor. Returns the deleted count and whether the pubkey is
    /// done.
    fn drain_vanished(
        &self,
        pubkey: &[u8; 32],
        phase: u64,
        created_at: Option<u64>,
        seq: Option<u64>,
        budget: &mut usize,
    ) -> Result<(usize, bool), StoreError> {
        let Some(t) = self.vanished_at(pubkey)? else {
            self.exec_sql(
                "DELETE FROM vanish_pending WHERE pubkey = ?1",
                &[Param::Blob(pubkey)],
            )?;
            return Ok((0, true));
        };
        let mut phase = match phase {
            0 | 1 => phase,
            _ => return Err(StoreError::Corrupt("bad vanish_pending phase")),
        };
        let mut last = created_at.zip(seq);
        let mut seqs = Vec::new();
        let mut done = false;
        loop {
            let walk = self.collect_vanished(pubkey, phase, t, last, *budget)?;
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
        for victim in seqs {
            deleted += usize::from(self.delete_seq(victim)?);
        }
        if done {
            self.exec_sql(
                "DELETE FROM vanish_pending WHERE pubkey = ?1",
                &[Param::Blob(pubkey)],
            )?;
        } else {
            self.exec_sql(
                "INSERT OR REPLACE INTO vanish_pending (pubkey, phase, created_at, seq)
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    Param::Blob(pubkey),
                    int(phase),
                    last.map_or(Param::Null, |(created, _)| int(created)),
                    last.map_or(Param::Null, |(_, s)| int(s)),
                ],
            )?;
        }
        Ok((deleted, done))
    }

    /// Walk one vanish range — `(last, T]` on `(created_at, seq)` or
    /// from the top when `last` is `None` — examining at most
    /// `budget` rows and collecting seqs whose record kind `phase`
    /// accepts (phase 0 keeps everything but kind 62, phase 1 keeps
    /// kind 1059 only).
    fn collect_vanished(
        &self,
        pubkey: &[u8; 32],
        phase: u64,
        t: u64,
        last: Option<(u64, u64)>,
        budget: usize,
    ) -> Result<VanishWalk, StoreError> {
        // A NULL resume point binds `(-1, -1)`, admitting every row.
        let (bound_created, bound_seq) = match last {
            Some((created, seq)) => (
                i64::try_from(created).map_err(|_| StoreError::OutOfRange("vanish cursor"))?,
                i64::try_from(seq).map_err(|_| StoreError::OutOfRange("vanish cursor"))?,
            ),
            None => (-1, -1),
        };
        let limit = i64::try_from(budget).map_err(|_| StoreError::OutOfRange("vanish budget"))?;
        let params: Vec<Param<'_>> = if phase == 0 {
            vec![
                Param::Blob(pubkey),
                int(t),
                Param::Int(bound_created),
                Param::Int(bound_seq),
                Param::Int(limit),
            ]
        } else {
            vec![
                Param::Int(i64::from(b'p')),
                Param::Blob(pubkey),
                int(t),
                Param::Int(bound_created),
                Param::Int(bound_seq),
                Param::Int(limit),
            ]
        };
        let mut walk = VanishWalk {
            seqs: Vec::new(),
            examined: 0,
            last,
            drained: false,
        };
        let mut failure = None;
        let result = self.exec.query(
            if phase == 0 {
                SQL_VANISH_PUBKEY
            } else {
                SQL_VANISH_WRAPS
            },
            &params,
            &mut |row| match collect_row(&mut walk, phase, &row) {
                Ok(()) => ControlFlow::Continue(()),
                Err(err) => {
                    failure = Some(err);
                    ControlFlow::Break(())
                }
            },
        );
        if let Err(err) = result {
            return Err(StoreError::sql(err));
        }
        if let Some(err) = failure {
            return Err(err);
        }
        walk.drained = walk.examined < budget;
        Ok(walk)
    }

    /// Apply one NIP-86 `op` in a single transaction and return the
    /// rebuilt [`Moderation`] snapshot. [`ModOp::BanEvent`] also
    /// deletes the stored event, when present, through the full
    /// `delete_seq` routine in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::Corrupt`] on a row that cannot decode.
    pub fn moderate(&self, op: ModOp) -> Result<Moderation, StoreError> {
        self.exec.transaction(|| {
            match op {
                ModOp::BanPubkey { pubkey, reason } => self.exec_sql(
                    "INSERT OR REPLACE INTO mod_pubkeys (pubkey, state, reason)
                     VALUES (?1, ?2, ?3)",
                    &[
                        Param::Blob(&pubkey.0),
                        Param::Int(ST_BANNED),
                        reason_param(reason.as_deref()),
                    ],
                )?,
                ModOp::UnbanPubkey { pubkey } => self.exec_sql(
                    "DELETE FROM mod_pubkeys WHERE pubkey = ?1 AND state = ?2",
                    &[Param::Blob(&pubkey.0), Param::Int(ST_BANNED)],
                )?,
                ModOp::AllowPubkey { pubkey, reason } => self.exec_sql(
                    "INSERT OR REPLACE INTO mod_pubkeys (pubkey, state, reason)
                     VALUES (?1, ?2, ?3)",
                    &[
                        Param::Blob(&pubkey.0),
                        Param::Int(ST_ALLOWED),
                        reason_param(reason.as_deref()),
                    ],
                )?,
                ModOp::UnallowPubkey { pubkey } => self.exec_sql(
                    "DELETE FROM mod_pubkeys WHERE pubkey = ?1 AND state = ?2",
                    &[Param::Blob(&pubkey.0), Param::Int(ST_ALLOWED)],
                )?,
                ModOp::BanEvent { id, reason } => self.ban_event(&id, reason.as_deref())?,
                ModOp::UnbanEvent { id } => self.exec_sql(
                    "DELETE FROM mod_events WHERE id = ?1",
                    &[Param::Blob(&id.0)],
                )?,
                ModOp::AllowKind { kind } => self.exec_sql(
                    "INSERT OR REPLACE INTO mod_kinds (kind, state) VALUES (?1, ?2)",
                    &[Param::Int(i64::from(kind)), Param::Int(ST_ALLOWED)],
                )?,
                ModOp::DisallowKind { kind } => self.exec_sql(
                    "INSERT OR REPLACE INTO mod_kinds (kind, state) VALUES (?1, ?2)",
                    &[Param::Int(i64::from(kind)), Param::Int(ST_DISALLOWED)],
                )?,
                ModOp::BlockIp { ip, reason } => self.exec_sql(
                    "INSERT OR REPLACE INTO mod_ips (ip, reason) VALUES (?1, ?2)",
                    &[
                        Param::Text(&ip.to_string()),
                        reason_param(reason.as_deref()),
                    ],
                )?,
                ModOp::UnblockIp { ip } => self.exec_sql(
                    "DELETE FROM mod_ips WHERE ip = ?1",
                    &[Param::Text(&ip.to_string())],
                )?,
                ModOp::SetInfo { field, value } => self.exec_sql(
                    "INSERT OR REPLACE INTO mod_info (key, value) VALUES (?1, ?2)",
                    &[Param::Text(field.as_str()), Param::Text(&value)],
                )?,
            }
            self.moderation()
        })
    }

    /// Load the full [`Moderation`] snapshot — used at startup so a
    /// restart keeps every ban, and after each applied op.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure,
    /// [`StoreError::Corrupt`] on a row that cannot decode.
    pub fn moderation(&self) -> Result<Moderation, StoreError> {
        let mut m = Moderation::default();
        self.query_rows(
            "SELECT pubkey, state, reason FROM mod_pubkeys",
            &[],
            |row| {
                let pubkey = PublicKey(blob(row, 0)?);
                match uint(row, 1)? {
                    0 => {
                        m.banned_pubkeys.insert(pubkey, mod_reason(row, 2)?);
                    }
                    1 => {
                        m.allowed_pubkeys.insert(pubkey, mod_reason(row, 2)?);
                    }
                    _ => return Err(StoreError::Corrupt("bad mod_pubkeys state")),
                }
                Ok(())
            },
        )?;
        self.query_rows("SELECT id, reason FROM mod_events", &[], |row| {
            m.banned_events
                .insert(EventId(blob(row, 0)?), mod_reason(row, 1)?);
            Ok(())
        })?;
        self.query_rows("SELECT kind, state FROM mod_kinds", &[], |row| {
            let kind = u16::try_from(uint(row, 0)?)
                .map_err(|_| StoreError::Corrupt("bad mod_kinds key"))?;
            match uint(row, 1)? {
                1 => {
                    m.allowed_kinds.insert(kind);
                }
                2 => {
                    m.disallowed_kinds.insert(kind);
                }
                _ => return Err(StoreError::Corrupt("bad mod_kinds state")),
            }
            Ok(())
        })?;
        self.query_rows("SELECT ip, reason FROM mod_ips", &[], |row| {
            let ip = text(row, 0)?
                .parse()
                .map_err(|_| StoreError::Corrupt("bad mod_ips key"))?;
            m.blocked_ips.insert(ip, mod_reason(row, 1)?);
            Ok(())
        })?;
        self.query_rows("SELECT key, value FROM mod_info", &[], |row| {
            let value = Box::<str>::from(text(row, 1)?);
            match text(row, 0)? {
                "name" => m.name = Some(value),
                "description" => m.description = Some(value),
                "icon" => m.icon = Some(value),
                _ => return Err(StoreError::Corrupt("bad mod_info key")),
            }
            Ok(())
        })?;
        Ok(m)
    }

    /// Apply every target of a stored kind-5 `event` (NIP-09). Targets
    /// are processed after the kind 5 itself is inserted.
    fn apply_deletions(&self, event: &Event) -> Result<(), StoreError> {
        for target in event.deletion_targets() {
            match target {
                DeletionTarget::Event(id) => self.delete_event_target(id, &event.pubkey())?,
                DeletionTarget::Address(address) => {
                    self.delete_address_target(address, event.created_at(), &event.pubkey())?;
                }
            }
        }
        Ok(())
    }

    /// Delete the `e`-tagged event `id` when it is `author`'s own and
    /// neither a kind 5 (NIP-09: a deletion request cannot delete a
    /// deletion request) nor a kind 62 (NIP-62: a request to vanish
    /// cannot be deleted).
    fn delete_event_target(&self, id: &EventId, author: &PublicKey) -> Result<(), StoreError> {
        let Some(row) = self.row(
            "SELECT seq, packed FROM events WHERE id = ?1",
            &[Param::Blob(&id.0)],
        )?
        else {
            return Ok(());
        };
        let seq = uint(&row, 0)?;
        let deletable = {
            let packed = record(&row, 1)?;
            packed.pubkey() == *author && packed.kind().0 != 5 && packed.kind().0 != 62
        };
        if deletable {
            self.delete_seq(seq)?;
        }
        Ok(())
    }

    /// Delete the stored version at `address` when it is `author`'s
    /// own and `created_at <= deleted_at` (the kind-5 timestamp).
    fn delete_address_target(
        &self,
        address: &[u8; 32],
        deleted_at: u64,
        author: &PublicKey,
    ) -> Result<(), StoreError> {
        let Some(row) = self.row(
            "SELECT seq, packed FROM events WHERE address = ?1",
            &[Param::Blob(address)],
        )?
        else {
            return Ok(());
        };
        let seq = uint(&row, 0)?;
        let deletable = {
            let packed = record(&row, 1)?;
            packed.pubkey() == *author && packed.created_at() <= deleted_at
        };
        if deletable {
            self.delete_seq(seq)?;
        }
        Ok(())
    }

    /// Remove every row `seq` carries; `false` when it is already
    /// gone. Tag keys are derived from the stored packed record; only
    /// a kind 5 carries deletion blocks, and only its payload needs
    /// the structural JSON parse (the packed record alone cannot
    /// reproduce an `e` or `a` value longer than 255 bytes).
    fn delete_seq(&self, seq: u64) -> Result<bool, StoreError> {
        let Some(row) = self.row(
            "SELECT packed, json FROM events WHERE seq = ?1",
            &[int(seq)],
        )?
        else {
            return Ok(false);
        };
        let packed = record(&row, 0)?;
        let created = int(packed.created_at());
        let author = packed.pubkey().0;
        let seqp = int(seq);
        for (name, value) in packed.tags() {
            self.exec_sql(
                "DELETE FROM tags
                 WHERE name = ?1 AND value = ?2 AND created_at = ?3 AND seq = ?4",
                &[
                    Param::Int(i64::from(name)),
                    Param::Blob(value),
                    created,
                    seqp,
                ],
            )?;
        }
        if packed.kind().0 == 5 {
            let unverified = UnverifiedEvent::parse_structural(text(&row, 1)?)
                .map_err(|_| StoreError::Corrupt("stored payload fails structural parse"))?;
            for target in unverified.deletion_targets() {
                match target {
                    DeletionTarget::Event(id) => self.exec_sql(
                        "DELETE FROM deletions
                         WHERE target = ?1 AND author = ?2 AND carrier = ?3",
                        &[Param::Blob(&id.0), Param::Blob(&author), seqp],
                    )?,
                    DeletionTarget::Address(addr) => self.exec_sql(
                        "DELETE FROM replace_deletions
                         WHERE address = ?1 AND deleted_at = ?2 AND carrier = ?3",
                        &[Param::Blob(&addr), created, seqp],
                    )?,
                }
            }
        }
        self.exec_sql("DELETE FROM events WHERE seq = ?1", &[seqp])?;
        Ok(true)
    }

    /// The seq `AUTOINCREMENT` assigned to the just-inserted event.
    fn last_rowid(&self) -> Result<u64, StoreError> {
        let row = self
            .row("SELECT last_insert_rowid()", &[])?
            .ok_or(StoreError::Corrupt("last_insert_rowid returned no row"))?;
        uint(&row, 0)
    }

    /// Execute one statement, boxing the executor error.
    /// `banevent`: record the ban and delete a stored event through
    /// the full `delete_seq` routine (same transaction, caller's).
    fn ban_event(&self, id: &EventId, reason: Option<&str>) -> Result<(), StoreError> {
        self.exec_sql(
            "INSERT OR REPLACE INTO mod_events (id, reason) VALUES (?1, ?2)",
            &[Param::Blob(&id.0), reason_param(reason)],
        )?;
        if let Some(row) = self.row(
            "SELECT seq FROM events WHERE id = ?1",
            &[Param::Blob(&id.0)],
        )? {
            self.delete_seq(uint(&row, 0)?)?;
        }
        Ok(())
    }

    fn exec_sql(&self, sql: &str, params: &[Param<'_>]) -> Result<(), StoreError> {
        self.exec.execute(sql, params).map_err(StoreError::sql)
    }

    /// Whether `sql` produces at least one row.
    fn exists(&self, sql: &str, params: &[Param<'_>]) -> Result<bool, StoreError> {
        let mut found = false;
        self.exec
            .query(sql, params, &mut |_| {
                found = true;
                ControlFlow::Break(())
            })
            .map_err(StoreError::sql)?;
        Ok(found)
    }

    /// The first row `sql` produces, if any.
    fn row(&self, sql: &str, params: &[Param<'_>]) -> Result<Option<Vec<Value>>, StoreError> {
        let mut first = None;
        self.exec
            .query(sql, params, &mut |row| {
                first = Some(row);
                ControlFlow::Break(())
            })
            .map_err(StoreError::sql)?;
        Ok(first)
    }

    /// Stream every row of `sql` through a fallible visitor.
    fn query_rows(
        &self,
        sql: &str,
        params: &[Param<'_>],
        mut visit: impl FnMut(&[Value]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let mut failure = None;
        let result = self.exec.query(sql, params, &mut |row| match visit(&row) {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => {
                failure = Some(err);
                ControlFlow::Break(())
            }
        });
        match (result, failure) {
            (Err(err), _) => Err(StoreError::sql(err)),
            (Ok(()), Some(err)) => Err(err),
            (Ok(()), None) => Ok(()),
        }
    }
}

/// One queued vanish pubkey and its resume position.
struct PendingVanish {
    /// The author whose vanish range is being drained.
    pubkey: [u8; 32],
    /// 0 = the author's events via `ix_pubkey`, 1 = kind-1059 wraps
    /// `p`-tagged to it via `tags`.
    phase: u64,
    /// Exclusive keyset resume point — `created_at` …
    created_at: Option<u64>,
    /// … and `seq`; `None` when the phase starts from the top.
    seq: Option<u64>,
}

/// Collected seqs and the resume position of one bounded vanish
/// range walk.
struct VanishWalk {
    /// Seqs to delete through the full delete routine.
    seqs: Vec<u64>,
    /// Index rows examined this walk (charged to the step budget).
    examined: usize,
    /// The last examined `(created_at, seq)` — the exclusive resume
    /// bound of the next step.
    last: Option<(u64, u64)>,
    /// The range yielded fewer than the budget allowed.
    drained: bool,
}

// Vanish range statements: the author's own events via `ix_pubkey`
// and kind-1059 wraps `p`-tagged to it via the `tags` primary key —
// both `created_at <= T` with an exclusive `(created_at, seq)`
// keyset lower bound. The `query_plan` tests pin the plans.
pub(crate) const SQL_VANISH_PUBKEY: &str =
    "SELECT seq, created_at, packed FROM events INDEXED BY ix_pubkey
WHERE pubkey = ?1 AND created_at <= ?2
  AND (created_at > ?3 OR (created_at = ?3 AND seq > ?4))
ORDER BY created_at, seq
LIMIT ?5";

pub(crate) const SQL_VANISH_WRAPS: &str = "SELECT t.seq, t.created_at, e.packed
FROM tags AS t
JOIN events AS e ON e.seq = t.seq
WHERE t.name = ?1 AND t.value = ?2 AND t.created_at <= ?3
  AND (t.created_at > ?4 OR (t.created_at = ?4 AND t.seq > ?5))
ORDER BY t.created_at, t.seq
LIMIT ?6";

/// Fold one vanish index row into `walk`: count it, remember the
/// `(created_at, seq)` resume point, and collect the seq when the
/// record's kind survives this phase (phase 0 keeps everything but
/// kind 62, phase 1 keeps kind 1059 only).
fn collect_row(walk: &mut VanishWalk, phase: u64, row: &[Value]) -> Result<(), StoreError> {
    let seq = uint(row, 0)?;
    let created = uint(row, 1)?;
    let packed = record(row, 2)?;
    walk.examined += 1;
    walk.last = Some((created, seq));
    let keep = if phase == 0 {
        packed.kind().0 != 62
    } else {
        packed.kind().0 == 1059
    };
    if keep {
        walk.seqs.push(seq);
    }
    Ok(())
}

/// Column `i` of `row` as a 32-byte blob.
fn blob(row: &[Value], i: usize) -> Result<[u8; 32], StoreError> {
    match row.get(i) {
        Some(Value::Blob(bytes)) => <&[u8; 32]>::try_from(bytes.as_slice())
            .map(<[u8; 32]>::to_owned)
            .map_err(|_| StoreError::Corrupt("row column is not a 32-byte blob")),
        _ => Err(StoreError::Corrupt("row column is not a blob")),
    }
}

/// Column `i` of `row` as an optional unsigned integer (`NULL` =
/// `None`).
fn opt_uint(row: &[Value], i: usize) -> Result<Option<u64>, StoreError> {
    match row.get(i) {
        Some(Value::Null) => Ok(None),
        Some(Value::Int(v)) if *v >= 0 => Ok(Some(u64::try_from(*v).unwrap_or_default())),
        _ => Err(StoreError::Corrupt("row column is not an integer")),
    }
}

/// Column `i` of `row` as an unsigned integer.
pub(crate) fn uint(row: &[Value], i: usize) -> Result<u64, StoreError> {
    match row.get(i) {
        Some(Value::Int(v)) if *v >= 0 => Ok(u64::try_from(*v).unwrap_or_default()),
        _ => Err(StoreError::Corrupt("row column is not an integer")),
    }
}

/// Column `i` of `row` as a validated packed record.
pub(crate) fn record(row: &[Value], i: usize) -> Result<PackedRef<'_>, StoreError> {
    match row.get(i) {
        Some(Value::Blob(bytes)) => {
            PackedRef::new(bytes).ok_or(StoreError::Corrupt("bad packed record"))
        }
        _ => Err(StoreError::Corrupt("row column is not a blob")),
    }
}

/// A `reason` for a `mod_*` row: `None` and empty both bind NULL —
/// the loaded snapshot maps them back to `None`, as the LMDB
/// encoding does.
fn reason_param(reason: Option<&str>) -> Param<'_> {
    reason
        .filter(|reason| !reason.is_empty())
        .map_or(Param::Null, Param::Text)
}

/// Column `i` of `row` as an optional reason (`NULL` or empty =
/// `None` — the LMDB encoding collapses both).
fn mod_reason(row: &[Value], i: usize) -> Result<Option<Box<str>>, StoreError> {
    match row.get(i) {
        Some(Value::Null) => Ok(None),
        Some(Value::Text(s)) if s.is_empty() => Ok(None),
        Some(Value::Text(s)) => Ok(Some(Box::from(s.as_str()))),
        _ => Err(StoreError::Corrupt("row column is not text")),
    }
}

/// Column `i` of `row` as text.
pub(crate) fn text(row: &[Value], i: usize) -> Result<&str, StoreError> {
    match row.get(i) {
        Some(Value::Text(s)) => Ok(s.as_str()),
        _ => Err(StoreError::Corrupt("row column is not text")),
    }
}
