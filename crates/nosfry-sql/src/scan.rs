//! The query engine: one paged index cursor per key, a k-way merge
//! over the newest heads, and an index-row budget.
//!
//! SQL carries only column predicates — the cursor key plus the
//! `since`/`until` window. The authoritative check runs in Rust on the
//! packed record: [`Filter::matches`], the [`ReadGate`], and the
//! NIP-40 expiration rule, identical to the LMDB scan. Ordering and
//! dedup match it too: per filter, `created_at` descending and id
//! ascending inside one timestamp, `limit` applied before the
//! cross-filter seq dedup.

use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::ops::ControlFlow;

use nosfry_core::auth::ReadGate;
use nosfry_core::event::{EventId, cmp_newest_first};
use nosfry_core::filter::Filter;
use nosfry_core::hll::Hll;
use nosfry_core::packed::PackedRef;

use crate::StoreError;
use crate::exec::{Executor, Param, Value};
use crate::store::{JS_MAX, int, record, text, uint};

/// The most a cursor's first page fetches: `ceil(limit / cursors)`
/// clamped to `1..=FIRST_PAGE`, so a wide fan-out reads about
/// `limit` rows rather than `16 · keys`. Pages double up to
/// [`MAX_PAGE`].
const FIRST_PAGE: usize = 16;
/// A page never grows past this.
const MAX_PAGE: usize = 512;

/// A `(created_at, id, seq)` match waiting for its `created_at` group
/// to complete.
type Match = (u64, EventId, u64);

/// What one `query` reports: the matching events themselves are
/// streamed to the caller's sink, so `Scan` only carries the
/// budget flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scan {
    /// The `max_rows` budget stopped the scan early; the emitted
    /// hits are what complete `created_at` groups yielded before
    /// exhaustion.
    pub budget_exhausted: bool,
}

/// One payload statement binds at most this many winning seqs; the
/// sink drains each chunk before the next fetch, so a `query` never
/// holds more than one chunk of event JSON.
const PAYLOAD_CHUNK: usize = 64;

/// One matching stored event.
#[derive(Debug)]
pub struct Hit {
    /// The row's sequence number.
    pub seq: u64,
    /// The canonical event JSON.
    pub json: Box<str>,
}

/// The `(created_at, id)` records one `records` call found.
#[derive(Debug)]
pub struct Records {
    /// Matching `(created_at, id)` rows, per filter newest-first.
    pub records: Vec<(u64, EventId)>,
    /// The `max_rows` budget stopped the scan early; `records` is
    /// what complete `created_at` groups yielded before exhaustion.
    pub budget_exhausted: bool,
}

/// What [`SqlStore::count`] reports, mirroring the LMDB
/// `CountResult`.
///
/// [`SqlStore::count`]: crate::SqlStore::count
#[derive(Debug)]
pub struct Count {
    /// Events counted (the exact union size, or a partial count when
    /// `approximate`).
    pub count: u64,
    /// `true` when the `max_rows` budget stopped the scan early; the
    /// partial `count` is never more than the true count.
    pub approximate: bool,
    /// The HLL registers of counted authors, when the query was
    /// eligible for a sketch.
    pub hll: Option<[u8; 256]>,
}

/// The column predicate one cursor key pins.
#[derive(Clone, Debug)]
enum Key {
    /// `pubkey = ?` on `ix_pubkey`.
    Pubkey([u8; 32]),
    /// `pubkey = ? AND kind = ?` on `ix_pubkey_kind`.
    PubkeyKind([u8; 32], u16),
    /// `kind = ?` on `ix_kind`.
    Kind(u16),
    /// `name = ? AND value = ?` on the `tags` primary key.
    Tag(u8, Vec<u8>),
    /// No key predicate: the whole `ix_time` index.
    Time,
}

impl Key {
    /// The key's bound parameters (`?1`, `?2` of the statement); the
    /// time window, keyset bound and page size follow as `?3..`.
    fn params<'a>(&'a self, out: &mut Vec<Param<'a>>) {
        match self {
            Self::Pubkey(pubkey) => out.push(Param::Blob(pubkey)),
            Self::PubkeyKind(pubkey, kind) => {
                out.push(Param::Blob(pubkey));
                out.push(Param::Int(i64::from(*kind)));
            }
            Self::Kind(kind) => out.push(Param::Int(i64::from(*kind))),
            Self::Tag(name, value) => {
                out.push(Param::Int(i64::from(*name)));
                out.push(Param::Blob(value));
            }
            Self::Time => {}
        }
    }
}

// Cursor statement templates: key parameters first, then `since`,
// `until`, the `(created_at, seq)` keyset bound and `LIMIT`. Every
// paged statement is `INDEXED BY`-pinned; the plans are asserted by
// the `query_plan` tests.

const SQL_PUBKEY_KIND: &str = "SELECT seq, created_at, packed FROM events INDEXED BY ix_pubkey_kind
WHERE pubkey = ?1 AND kind = ?2
  AND created_at >= ?3 AND created_at <= ?4
  AND (created_at < ?5 OR (created_at = ?5 AND seq < ?6))
ORDER BY created_at DESC, seq DESC
LIMIT ?7";

const SQL_PUBKEY: &str = "SELECT seq, created_at, packed FROM events INDEXED BY ix_pubkey
WHERE pubkey = ?1
  AND created_at >= ?2 AND created_at <= ?3
  AND (created_at < ?4 OR (created_at = ?4 AND seq < ?5))
ORDER BY created_at DESC, seq DESC
LIMIT ?6";

const SQL_KIND: &str = "SELECT seq, created_at, packed FROM events INDEXED BY ix_kind
WHERE kind = ?1
  AND created_at >= ?2 AND created_at <= ?3
  AND (created_at < ?4 OR (created_at = ?4 AND seq < ?5))
ORDER BY created_at DESC, seq DESC
LIMIT ?6";

const SQL_TAG: &str = "SELECT t.seq, t.created_at, e.packed
FROM tags AS t
JOIN events AS e ON e.seq = t.seq
WHERE t.name = ?1 AND t.value = ?2
  AND t.created_at >= ?3 AND t.created_at <= ?4
  AND (t.created_at < ?5 OR (t.created_at = ?5 AND t.seq < ?6))
ORDER BY t.created_at DESC, t.seq DESC
LIMIT ?7";

const SQL_TIME: &str = "SELECT seq, created_at, packed FROM events INDEXED BY ix_time
WHERE created_at >= ?1 AND created_at <= ?2
  AND (created_at < ?3 OR (created_at = ?3 AND seq < ?4))
ORDER BY created_at DESC, seq DESC
LIMIT ?5";

const SQL_IDS: &str = "SELECT seq, packed FROM events
WHERE id IN (SELECT unhex(value) FROM json_each(?1))";

const SQL_WINNERS: &str = "SELECT seq, json FROM events
WHERE seq IN (SELECT value FROM json_each(?1))";

/// One index row staged for the merge.
#[derive(Debug)]
struct Row {
    seq: u64,
    created_at: u64,
    packed: Vec<u8>,
}

/// A paged descending cursor over one index key: keyset-bound pages
/// that double in size until the key drains.
#[derive(Debug)]
struct Cursor {
    /// Statement template for this index.
    sql: &'static str,
    /// The key, `None` once it drains.
    key: Option<Key>,
    /// Exclusive `(created_at, seq)` upper bound of the next page.
    bound: (u64, u64),
    /// Rows the next page may fetch.
    page: usize,
    /// Buffered rows of the last fetched page.
    buf: VecDeque<Row>,
}

impl Cursor {
    /// Start a cursor over `key` of one index, `first` rows on the
    /// first page.
    const fn new(sql: &'static str, key: Key, first: usize) -> Self {
        Self {
            sql,
            key: Some(key),
            bound: (JS_MAX, JS_MAX),
            page: first,
            buf: VecDeque::new(),
        }
    }

    /// The next row of the merge — newest first within the key — or
    /// `None` once the key drained. No page is fetched once `seen`
    /// reaches `max_rows`; `exhausted` is set instead.
    fn next<E: Executor>(
        &mut self,
        exec: &E,
        since: u64,
        until: u64,
        seen: &mut usize,
        max_rows: usize,
        exhausted: &mut bool,
    ) -> Result<Option<Row>, StoreError> {
        loop {
            if let Some(row) = self.buf.pop_front() {
                return Ok(Some(row));
            }
            if self.key.is_none() {
                return Ok(None);
            }
            if *seen >= max_rows {
                *exhausted = true;
                return Ok(None);
            }
            let Some(key) = self.key.clone() else {
                return Ok(None);
            };
            let fetched = self.fetch(exec, &key, since, until, seen)?;
            if fetched < self.page {
                self.key = None;
                continue;
            }
            if let Some(last) = self.buf.back() {
                self.bound = (last.created_at, last.seq);
            }
            self.page = self.page.saturating_mul(2).min(MAX_PAGE);
        }
    }

    /// Fetch one keyset-bound page of `key` into `buf`, charging its
    /// rows to `seen`; returns the row count (a short page means the
    /// key drained).
    fn fetch<E: Executor>(
        &mut self,
        exec: &E,
        key: &Key,
        since: u64,
        until: u64,
        seen: &mut usize,
    ) -> Result<usize, StoreError> {
        let mut params = Vec::with_capacity(7);
        key.params(&mut params);
        params.extend([
            int(since),
            int(until),
            int(self.bound.0),
            int(self.bound.1),
            int(self.page as u64),
        ]);
        let buf = &mut self.buf;
        let mut failure = None;
        let mut fetched = 0usize;
        let result = exec.query(self.sql, &params, &mut |row| {
            fetched += 1;
            *seen += 1;
            match parse_row(&row) {
                Ok(parsed) => buf.push_back(parsed),
                Err(err) => {
                    failure = Some(err);
                    return ControlFlow::Break(());
                }
            }
            ControlFlow::Continue(())
        });
        if let Err(err) = result {
            return Err(StoreError::sql(err));
        }
        if let Some(err) = failure {
            return Err(err);
        }
        Ok(fetched)
    }
}

/// `(seq, created_at, packed)` of one index row.
fn parse_row(row: &[Value]) -> Result<Row, StoreError> {
    let seq = uint(row, 0)?;
    let created_at = uint(row, 1)?;
    let packed = record(row, 2)?;
    Ok(Row {
        seq,
        created_at,
        packed: packed.as_bytes().to_vec(),
    })
}

/// A merge head: the newest `(created_at, seq)` pops first.
#[derive(Debug)]
struct Head {
    row: Row,
    cursor: usize,
}

impl PartialEq for Head {
    fn eq(&self, other: &Self) -> bool {
        (self.row.created_at, self.row.seq) == (other.row.created_at, other.row.seq)
    }
}

impl Eq for Head {}

impl Ord for Head {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.row.created_at, self.row.seq).cmp(&(other.row.created_at, other.row.seq))
    }
}

impl PartialOrd for Head {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Which index a filter scans, one per filter, in strfry order: `ids`,
/// `authors`+`kinds`, `authors`, smallest tag set, `kinds`, `created_at`.
enum Mode {
    /// Direct `id` lookups, sorted afterwards.
    Ids(Vec<[u8; 32]>),
    /// A k-way merge over the index's cursors.
    Ranges(Vec<Cursor>),
}

/// The cursor keys [`plan`] and [`count`] derive from a filter: the
/// same pick without the paging policy.
enum Shape {
    /// `id` point lookups.
    Ids(Vec<[u8; 32]>),
    /// `(statement, keys, tag condition position)`: one cursor per
    /// key on one index. The position marks the `Filter::tags()`
    /// entry whose values seeded `keys` — COUNT's cover dedup needs
    /// it; only the `SQL_TAG` branch sets it.
    Ranges(&'static str, Vec<Key>, Option<usize>),
}

/// One cursor per key, `first` rows on the first page.
fn cursors(sql: &'static str, keys: Vec<Key>, first: usize) -> Vec<Cursor> {
    keys.into_iter()
        .map(|key| Cursor::new(sql, key, first))
        .collect()
}

/// The statement and keys a filter's index cursors cover.
fn shape(filter: &Filter) -> Shape {
    if let Some(ids) = filter.ids() {
        return Shape::Ids(ids.to_vec());
    }
    let tag = filter
        .tags()
        .iter()
        .enumerate()
        .min_by_key(|(_, (_, values))| values.len());
    match (filter.authors(), filter.kinds(), tag) {
        (Some(authors), Some(kinds), _)
            if (authors.len() as u64).saturating_mul(kinds.len() as u64) <= 256 =>
        {
            Shape::Ranges(
                SQL_PUBKEY_KIND,
                authors
                    .iter()
                    .flat_map(|pk| kinds.iter().map(|kind| Key::PubkeyKind(*pk, *kind)))
                    .collect(),
                None,
            )
        }
        (Some(authors), _, _) => Shape::Ranges(
            SQL_PUBKEY,
            authors.iter().map(|pk| Key::Pubkey(*pk)).collect(),
            None,
        ),
        (None, _, Some((pos, (name, values)))) => Shape::Ranges(
            SQL_TAG,
            values
                .iter()
                .map(|value| Key::Tag(*name, value.as_bytes().to_vec()))
                .collect(),
            Some(pos),
        ),
        (None, Some(kinds), _) => Shape::Ranges(
            SQL_KIND,
            kinds.iter().map(|kind| Key::Kind(*kind)).collect(),
            None,
        ),
        (None, None, _) => Shape::Ranges(SQL_TIME, vec![Key::Time], None),
    }
}

fn plan(filter: &Filter, limit: u64) -> Mode {
    match shape(filter) {
        Shape::Ids(ids) => Mode::Ids(ids),
        Shape::Ranges(sql, keys, _) => {
            // The first page is `limit / keys` clamped to
            // `1..=FIRST_PAGE` so a wide fan-out reads about `limit`
            // rows; pages then double up to MAX_PAGE.
            let first = usize::try_from(limit.div_ceil(keys.len() as u64))
                .unwrap_or(usize::MAX)
                .clamp(1, FIRST_PAGE);
            Mode::Ranges(cursors(sql, keys, first))
        }
    }
}

/// Per-candidate checks shared by both modes, mirroring the LMDB
/// scan's `try_candidate`: `last_seq` dup-skip, NIP-40 expiration
/// (`now = 0` disables it — expiration values are always `>= 100`),
/// the read gate, then the compiled matcher.
fn try_candidate(
    filter: &Filter,
    gate: &ReadGate,
    now: u64,
    seq: u64,
    packed: PackedRef<'_>,
    last_seq: &mut Option<u64>,
) -> Option<Match> {
    if *last_seq == Some(seq) {
        return None;
    }
    *last_seq = Some(seq);
    let expiration = packed.expiration();
    if expiration != 0 && expiration <= now {
        return None;
    }
    if !gate.allows(packed) {
        return None;
    }
    filter
        .matches(packed)
        .then(|| (packed.created_at(), packed.id(), seq))
}

/// Emit one complete `created_at` group: the bounded heap holds the
/// smallest `limit - taken` entries and `into_sorted_vec` emits them
/// id-ascending, each counted toward `taken` whether or not it is
/// re-sent (limit-then-dedup across filters).
fn flush_group(
    group: &mut BinaryHeap<Match>,
    taken: &mut u64,
    emitted: &mut HashSet<u64>,
    out: &mut Vec<Match>,
) {
    for m in std::mem::take(group).into_sorted_vec() {
        *taken += 1;
        if emitted.insert(m.2) {
            out.push(m);
        }
    }
}

/// `id` lookups through one `json_each` parameter, then the
/// sort/truncate/emit finalize pass.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the LMDB scan's shared step state"
)]
fn scan_ids<E: Executor>(
    exec: &E,
    filter: &Filter,
    gate: &ReadGate,
    now: u64,
    limit: u64,
    ids: &[[u8; 32]],
    emitted: &mut HashSet<u64>,
    seen: &mut usize,
    max_rows: usize,
    budget: &mut bool,
) -> Result<Vec<Match>, StoreError> {
    let list = format!(
        "[{}]",
        ids.iter()
            .map(|id| format!("\"{}\"", faster_hex::hex_string(id)))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut collected = Vec::new();
    let mut last_seq = None;
    let mut failure = None;
    let result = exec.query(SQL_IDS, &[Param::Text(&list)], &mut |row| {
        if *seen >= max_rows {
            *budget = true;
            return ControlFlow::Break(());
        }
        *seen += 1;
        match (uint(&row, 0), record(&row, 1)) {
            (Ok(seq), Ok(packed)) => {
                if let Some(m) = try_candidate(filter, gate, now, seq, packed, &mut last_seq) {
                    collected.push(m);
                }
            }
            (Err(err), _) | (_, Err(err)) => {
                failure = Some(err);
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    });
    if let Err(err) = result {
        return Err(StoreError::sql(err));
    }
    if let Some(err) = failure {
        return Err(err);
    }
    collected.sort_by(|a, b| cmp_newest_first((a.0, &a.1), (b.0, &b.1)));
    collected.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    Ok(collected
        .into_iter()
        .filter(|m| emitted.insert(m.2))
        .collect())
}

/// The k-way merge over a `Ranges` mode's cursors: heap-pop the
/// newest head, refill its cursor, flush completed `created_at`
/// groups. `seen` counts index rows read, not heads popped — a page
/// fetch may push `seen` past `max_rows`, and already-read rows still
/// merge so only complete groups ship.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the LMDB scan's shared step state"
)]
fn scan_ranges<E: Executor>(
    exec: &E,
    filter: &Filter,
    gate: &ReadGate,
    now: u64,
    limit: u64,
    cursors: &mut [Cursor],
    since: u64,
    until: u64,
    emitted: &mut HashSet<u64>,
    seen: &mut usize,
    max_rows: usize,
    budget: &mut bool,
) -> Result<Vec<Match>, StoreError> {
    let mut heap = BinaryHeap::new();
    for (i, cursor) in cursors.iter_mut().enumerate() {
        if let Some(row) = cursor.next(exec, since, until, seen, max_rows, budget)? {
            heap.push(Head { row, cursor: i });
        }
    }
    let mut group: BinaryHeap<Match> = BinaryHeap::new();
    let mut taken = 0u64;
    let mut last_seq = None;
    let mut out = Vec::new();
    while let Some(head) = heap.pop() {
        let Some(cursor) = cursors.get_mut(head.cursor) else {
            return Err(StoreError::Corrupt("merge head without a cursor"));
        };
        if let Some(row) = cursor.next(exec, since, until, seen, max_rows, budget)? {
            heap.push(Head {
                row,
                cursor: head.cursor,
            });
        }
        // A lower created_at completes the current group; heads pop
        // in non-increasing order.
        if group.peek().is_some_and(|m| head.row.created_at < m.0) {
            flush_group(&mut group, &mut taken, emitted, &mut out);
            if taken >= limit {
                return Ok(out);
            }
        }
        let packed =
            PackedRef::new(&head.row.packed).ok_or(StoreError::Corrupt("bad packed record"))?;
        if let Some(m) = try_candidate(filter, gate, now, head.row.seq, packed, &mut last_seq) {
            // `taken` only grows on a flush, so `remaining` is constant
            // while one group fills; drop the largest id beyond it.
            let remaining = usize::try_from(limit.saturating_sub(taken)).unwrap_or(usize::MAX);
            group.push(m);
            if group.len() > remaining {
                group.pop();
            }
        }
    }
    if !*budget {
        flush_group(&mut group, &mut taken, emitted, &mut out);
    }
    Ok(out)
}

/// The canonical JSON of the winning seqs, streamed to `sink` in
/// `seqs` order [`PAYLOAD_CHUNK`] winners per statement.
fn fetch_jsons<E: Executor>(
    exec: &E,
    seqs: &[u64],
    sink: &mut dyn FnMut(Hit),
) -> Result<(), StoreError> {
    for chunk in seqs.chunks(PAYLOAD_CHUNK) {
        let list = format!(
            "[{}]",
            chunk
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut jsons = HashMap::new();
        let mut failure = None;
        let result = exec.query(SQL_WINNERS, &[Param::Text(&list)], &mut |row| {
            if let (Ok(seq), Ok(json)) = (uint(&row, 0), text(&row, 1)) {
                jsons.insert(seq, Box::from(json));
            } else {
                failure = Some(StoreError::Corrupt("bad payload row"));
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        });
        if let Err(err) = result {
            return Err(StoreError::sql(err));
        }
        if let Some(err) = failure {
            return Err(err);
        }
        for &seq in chunk {
            if let Some(json) = jsons.remove(&seq) {
                sink(Hit { seq, json });
            }
        }
    }
    Ok(())
}

/// Run the whole filter set once: per-filter modes, shared dedup.
/// The matches carry their records so callers either fetch payloads
/// ([`scan`]) or return the `(created_at, id)` rows ([`records`]).
fn scan_matches<E: Executor>(
    exec: &E,
    filters: &[Filter],
    gate: &ReadGate,
    now: u64,
    max_limit: u64,
    max_rows: usize,
) -> Result<(Vec<Match>, bool), StoreError> {
    let mut matches = Vec::new();
    let mut emitted = HashSet::new();
    let mut seen = 0usize;
    let mut budget_exhausted = false;
    for filter in filters {
        let limit = filter.effective_limit(max_limit);
        if filter.is_impossible() || limit == 0 {
            continue;
        }
        let since = filter.since().unwrap_or(0);
        let until = filter.until().unwrap_or(u64::MAX);
        let found = match plan(filter, limit) {
            Mode::Ids(ids) => scan_ids(
                exec,
                filter,
                gate,
                now,
                limit,
                &ids,
                &mut emitted,
                &mut seen,
                max_rows,
                &mut budget_exhausted,
            )?,
            Mode::Ranges(mut cursors) => scan_ranges(
                exec,
                filter,
                gate,
                now,
                limit,
                &mut cursors,
                since,
                until,
                &mut emitted,
                &mut seen,
                max_rows,
                &mut budget_exhausted,
            )?,
        };
        matches.extend(found);
        if budget_exhausted {
            break;
        }
    }
    Ok((matches, budget_exhausted))
}

/// [`scan_matches`] plus the chunked payload fetch, streamed.
pub(crate) fn scan<E: Executor>(
    exec: &E,
    filters: &[Filter],
    gate: &ReadGate,
    now: u64,
    max_limit: u64,
    max_rows: usize,
    sink: &mut dyn FnMut(Hit),
) -> Result<Scan, StoreError> {
    let (matches, budget_exhausted) = scan_matches(exec, filters, gate, now, max_limit, max_rows)?;
    let seqs: Vec<u64> = matches.iter().map(|m| m.2).collect();
    fetch_jsons(exec, &seqs, sink)?;
    Ok(Scan { budget_exhausted })
}

/// [`scan_matches`] alone: the records a `NEG-OPEN` syncs, without
/// touching the payloads.
pub(crate) fn records<E: Executor>(
    exec: &E,
    filters: &[Filter],
    gate: &ReadGate,
    now: u64,
    max_limit: u64,
    max_rows: usize,
) -> Result<Records, StoreError> {
    let (matches, budget_exhausted) = scan_matches(exec, filters, gate, now, max_limit, max_rows)?;
    Ok(Records {
        records: matches.into_iter().map(|m| (m.0, m.1)).collect(),
        budget_exhausted,
    })
}

/// COUNT's per-candidate checks — the LMDB `CountScan::examine`:
/// NIP-40 expiration (`now = 0` disables it), the read gate, the
/// tag-cover dedup (an event an *earlier* value of the seeding tag
/// condition also reaches is counted under that cursor), the
/// compiled matcher, then union dedup: an event an earlier filter
/// matches is counted once, there.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the LMDB count's shared step state"
)]
fn count_candidate(
    filters: &[Filter],
    filter_i: usize,
    gate: &ReadGate,
    now: u64,
    cover: Option<(usize, usize)>,
    packed: PackedRef<'_>,
    counted: &mut u64,
    hll: &mut Option<Hll>,
) {
    let expiration = packed.expiration();
    if expiration != 0 && expiration <= now {
        return;
    }
    if !gate.allows(packed) {
        return;
    }
    let Some(filter) = filters.get(filter_i) else {
        return;
    };
    if let Some((tag_pos, cursor)) = cover
        && let Some((name, values)) = filter.tags().get(tag_pos)
        && values
            .get(..cursor)
            .unwrap_or_default()
            .iter()
            .any(|value| {
                packed
                    .tags()
                    .any(|(n, t)| n == *name && t == value.as_bytes())
            })
    {
        return;
    }
    if !filter.matches(packed) {
        return;
    }
    if filters
        .get(..filter_i)
        .unwrap_or_default()
        .iter()
        .any(|f| f.matches(packed))
    {
        return;
    }
    *counted += 1;
    if let Some(hll) = hll.as_mut() {
        hll.add(&packed.pubkey());
    }
}

/// `id` lookups through one `json_each` parameter; every fetched row
/// counts toward the budget (`id IN` already deduplicates).
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the scan's shared step state"
)]
fn count_ids<E: Executor>(
    exec: &E,
    filters: &[Filter],
    filter_i: usize,
    gate: &ReadGate,
    now: u64,
    ids: &[[u8; 32]],
    counted: &mut u64,
    hll: &mut Option<Hll>,
    seen: &mut usize,
    max_rows: usize,
    approximate: &mut bool,
) -> Result<(), StoreError> {
    let list = format!(
        "[{}]",
        ids.iter()
            .map(|id| format!("\"{}\"", faster_hex::hex_string(id)))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut failure = None;
    let result = exec.query(SQL_IDS, &[Param::Text(&list)], &mut |row| {
        if *seen >= max_rows {
            *approximate = true;
            return ControlFlow::Break(());
        }
        *seen += 1;
        match record(&row, 1) {
            Ok(packed) => count_candidate(filters, filter_i, gate, now, None, packed, counted, hll),
            Err(err) => {
                failure = Some(err);
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    });
    if let Err(err) = result {
        return Err(StoreError::sql(err));
    }
    if let Some(err) = failure {
        return Err(err);
    }
    Ok(())
}

/// Walk each `Ranges` cursor to exhaustion in order; `cursor`'s
/// index feeds the tag-cover dedup. `approximate` stops the walk
/// once the row budget refuses a fetch.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the scan's shared step state"
)]
fn count_ranges<E: Executor>(
    exec: &E,
    filters: &[Filter],
    filter_i: usize,
    gate: &ReadGate,
    now: u64,
    sql: &'static str,
    keys: Vec<Key>,
    tag: Option<usize>,
    counted: &mut u64,
    hll: &mut Option<Hll>,
    seen: &mut usize,
    max_rows: usize,
    approximate: &mut bool,
) -> Result<(), StoreError> {
    let Some(filter) = filters.get(filter_i) else {
        return Ok(());
    };
    let since = filter.since().unwrap_or(0);
    let until = filter.until().unwrap_or(u64::MAX);
    for (c, cursor) in cursors(sql, keys, MAX_PAGE).iter_mut().enumerate() {
        while let Some(row) = cursor.next(exec, since, until, seen, max_rows, approximate)? {
            let packed =
                PackedRef::new(&row.packed).ok_or(StoreError::Corrupt("bad packed record"))?;
            count_candidate(
                filters,
                filter_i,
                gate,
                now,
                tag.map(|pos| (pos, c)),
                packed,
                counted,
                hll,
            );
        }
        if *approximate {
            return Ok(());
        }
    }
    Ok(())
}

/// Count the union `filters` match: the same index cursors as
/// [`scan`], walked to exhaustion in order with no merge and no
/// `limit` (COUNT ignores it), deduplicated exactly like the LMDB
/// `CountScan` — an event counts under the first filter matching it
/// and, on the tag index, under the first covering cursor. Every row
/// fetched counts toward `max_rows`; reaching it stops early with
/// `approximate` and a partial count, never an over-count. Pages
/// start at `MAX_PAGE` since every row is needed.
pub(crate) fn count<E: Executor>(
    exec: &E,
    filters: &[Filter],
    gate: &ReadGate,
    now: u64,
    max_rows: usize,
    mut hll: Option<Hll>,
) -> Result<Count, StoreError> {
    let mut counted = 0u64;
    let mut approximate = false;
    let mut seen = 0usize;
    for (filter_i, filter) in filters.iter().enumerate() {
        if filter.is_impossible() {
            continue;
        }
        match shape(filter) {
            Shape::Ids(ids) => count_ids(
                exec,
                filters,
                filter_i,
                gate,
                now,
                &ids,
                &mut counted,
                &mut hll,
                &mut seen,
                max_rows,
                &mut approximate,
            )?,
            Shape::Ranges(sql, keys, tag) => count_ranges(
                exec,
                filters,
                filter_i,
                gate,
                now,
                sql,
                keys,
                tag,
                &mut counted,
                &mut hll,
                &mut seen,
                max_rows,
                &mut approximate,
            )?,
        }
        if approximate {
            break;
        }
    }
    Ok(Count {
        count: counted,
        approximate,
        hll: hll.map(|h| *h.registers()),
    })
}

#[cfg(all(test, feature = "rusqlite"))]
#[allow(
    clippy::tests_outside_test_module,
    reason = "the module is also gated on the `rusqlite` feature"
)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may panic on failure"
)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::SqlStore;
    use crate::rusqlite::Connection;

    const AUTHOR: &str = "\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"";
    const EVENT_ID: &str = "\"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\"";
    const EVENT_ID_2: &str = "\"bbccddeeff00112233445566778899aabbccddeeff00112233445566778899aa\"";

    fn store() -> SqlStore<Connection> {
        SqlStore::open(Connection::open_in_memory().unwrap()).unwrap()
    }

    fn filter(json: &str) -> Filter {
        Filter::parse(json).unwrap()
    }

    /// `plan` for `json` with a large `limit`.
    fn plan_test(json: &str) -> Mode {
        plan(&filter(json), 500)
    }

    /// `EXPLAIN QUERY PLAN` detail lines for one statement.
    fn explain(exec: &Connection, sql: &str, params: &[Param<'_>]) -> String {
        let mut lines = Vec::new();
        exec.query(&format!("EXPLAIN QUERY PLAN {sql}"), params, &mut |row| {
            if let Some(Value::Text(detail)) = row.get(3) {
                lines.push(detail.clone());
            }
            ControlFlow::Continue(())
        })
        .unwrap();
        lines.join(" | ")
    }

    /// Assert the plan searches `index` and neither table-scans events
    /// nor falls back to a sorter.
    fn assert_plan(exec: &Connection, sql: &str, params: &[Param<'_>], index: &str) {
        let plan = explain(exec, sql, params);
        assert!(plan.contains(index), "expected {index}, got: {plan}");
        assert!(!plan.contains("SCAN events"), "scanned events: {plan}");
        assert!(!plan.contains("TEMP B-TREE"), "sort used: {plan}");
    }

    /// One first page's parameters for `key`: a boundless window
    /// and an unstarted `(created_at, seq)` bound.
    fn params(key: &Key, page: u64) -> Vec<Param<'_>> {
        let mut params = Vec::new();
        key.params(&mut params);
        params.extend([int(0), int(u64::MAX), int(JS_MAX), int(JS_MAX), int(page)]);
        params
    }

    #[test]
    fn plan_picks_one_cursor_per_list_value() {
        match plan_test(&format!("{{\"ids\":[{EVENT_ID},{EVENT_ID_2}]}}")) {
            Mode::Ids(ids) => assert_eq!(ids.len(), 2),
            Mode::Ranges(_) => panic!("expected id lookups"),
        }
        let cursors = |json: &str| match plan_test(json) {
            Mode::Ranges(cursors) => cursors,
            Mode::Ids(_) => panic!("expected range cursors"),
        };
        let one = |json: &str| {
            let mut cursors = cursors(json);
            assert_eq!(cursors.len(), 1);
            cursors.remove(0)
        };
        // `authors` with `kinds` gives one `ix_pubkey_kind` cursor per
        // pair; the merge orders their results globally.
        let pairs = cursors(&format!("{{\"authors\":[{AUTHOR}],\"kinds\":[1,3]}}"));
        assert_eq!(pairs.len(), 2);
        assert!(pairs.iter().all(|cursor| cursor.sql == SQL_PUBKEY_KIND));
        assert_eq!(one(&format!("{{\"authors\":[{AUTHOR}]}}")).sql, SQL_PUBKEY);
        // `authors` wins over tag conditions; `kinds` alone uses
        // `ix_kind`, and a bare filter falls back to `ix_time`.
        let tags = cursors(&format!("{{\"#e\":[{EVENT_ID},{EVENT_ID_2}]}}"));
        assert_eq!(tags.len(), 2);
        assert!(tags.iter().all(|cursor| cursor.sql == SQL_TAG));
        let mixed = one(&format!("{{\"authors\":[{AUTHOR}],\"#e\":[{EVENT_ID}]}}"));
        assert_eq!(mixed.sql, SQL_PUBKEY);
        let kinds = cursors("{\"kinds\":[1,3]}");
        assert_eq!(kinds.len(), 2);
        assert!(kinds.iter().all(|cursor| cursor.sql == SQL_KIND));
        assert_eq!(one("{}").sql, SQL_TIME);
    }

    #[test]
    fn ids_plan_uses_the_unique_id_index() {
        let store = store();
        assert_plan(
            store.exec(),
            SQL_IDS,
            &[Param::Text(&format!("[{EVENT_ID}]"))],
            "SEARCH events USING INDEX sqlite_autoindex_events_1",
        );
    }

    #[test]
    fn pubkey_kind_plan_uses_ix_pubkey_kind() {
        let store = store();
        let key = Key::PubkeyKind([0x11; 32], 1);
        let params = params(&key, 8);
        assert_plan(store.exec(), SQL_PUBKEY_KIND, &params, "ix_pubkey_kind");
    }

    #[test]
    fn pubkey_plan_uses_ix_pubkey() {
        let store = store();
        let key = Key::Pubkey([0x11; 32]);
        let params = params(&key, 8);
        assert_plan(store.exec(), SQL_PUBKEY, &params, "ix_pubkey");
    }

    #[test]
    fn tag_plan_uses_the_tags_primary_key() {
        let store = store();
        let key = Key::Tag(b't', b"word".to_vec());
        let params = params(&key, 8);
        assert_plan(
            store.exec(),
            SQL_TAG,
            &params,
            "SEARCH t USING PRIMARY KEY (name=? AND value=? AND created_at>? AND created_at<?)",
        );
    }

    #[test]
    fn kind_plan_uses_ix_kind() {
        let store = store();
        let params = params(&Key::Kind(1), 8);
        assert_plan(store.exec(), SQL_KIND, &params, "ix_kind");
    }

    #[test]
    fn time_plan_uses_ix_time() {
        let store = store();
        let params = params(&Key::Time, 8);
        assert_plan(store.exec(), SQL_TIME, &params, "ix_time");
    }

    #[test]
    fn winners_plan_uses_the_rowid_lookup() {
        let store = store();
        assert_plan(
            store.exec(),
            SQL_WINNERS,
            &[Param::Text(&json!([1, 2]).to_string())],
            "SEARCH events USING INTEGER PRIMARY KEY",
        );
    }

    #[test]
    fn vanish_plans_use_their_indexes() {
        use crate::store::{SQL_VANISH_PUBKEY, SQL_VANISH_WRAPS};
        let store = store();
        assert_plan(
            store.exec(),
            SQL_VANISH_PUBKEY,
            &[Param::Blob(&[0; 32]), int(0), int(0), int(0), int(0)],
            "SEARCH events USING INDEX ix_pubkey",
        );
        assert_plan(
            store.exec(),
            SQL_VANISH_WRAPS,
            &[
                Param::Int(i64::from(b'p')),
                Param::Blob(&[0; 32]),
                int(0),
                int(0),
                int(0),
                int(0),
            ],
            "SEARCH t USING PRIMARY KEY",
        );
    }
}
