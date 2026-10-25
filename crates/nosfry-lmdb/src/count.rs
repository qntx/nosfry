//! NIP-45 `COUNT` scans: the union a [`Scan`] would emit, counted.
//!
//! A [`CountScan`] walks the same index cursors as [`Scan`] — one read
//! transaction per `step`, same wall-clock budget — but never fetches
//! payloads, applies no filter `limit`, and deduplicates without a
//! hash set: an event is counted for the *first* filter (in REQ order)
//! it matches, and, within one filter, only under the *first* tag
//! cursor covering it. A `seq` is a fixed point in the store, so
//! "earlier filter wins" and "earlier cursor wins" are pure predicate
//! checks with zero per-event memory.
//!
//! Every examined index entry counts toward `budget_entries`; reaching
//! it stops the scan with `approximate: true`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nosfry_core::auth::ReadGate;
use nosfry_core::filter::Filter;
use nosfry_core::hll::Hll;
use nosfry_core::packed::PackedRef;

use crate::scan::{self, BUDGET_CHECK_EVERY, Cursor, Mode, Progress, RevIter};
use crate::{Index, Reader, Store, StoreError};

/// What a finished [`CountScan`] reports.
#[derive(Debug, Clone)]
pub struct CountResult {
    /// Events counted (the exact union size, or a partial count when
    /// `approximate`).
    pub count: u64,
    /// `true` when the entry budget stopped the scan early.
    pub approximate: bool,
    /// Index entries examined (matched or not, duplicates included).
    pub examined: u64,
    /// The HLL registers of counted authors, when the query was
    /// eligible for a sketch.
    pub hll: Option<[u8; 256]>,
}

/// A snapshot-bounded, budgeted count of the stored events a filter
/// group would return.
#[derive(Debug)]
pub struct CountScan {
    filters: Arc<[Filter]>,
    /// Read visibility snapshotted at COUNT time.
    gate: ReadGate,
    snapshot: u64,
    /// NIP-40 cutoff: events with `expiration <= now` are hidden.
    now: u64,
    /// Index entries this scan may examine before going approximate
    /// (`0` = no cap).
    budget_entries: u64,
    hll: Option<Hll>,
    plans: Vec<Option<CountPlan>>,
    /// First unfinished plan.
    next_plan: usize,
    /// Index entries examined so far (matched or not, duplicates
    /// included).
    examined: u64,
    count: u64,
    approximate: bool,
    done: bool,
}

/// Per-filter walk state: like [`scan::plan`]'s modes but cursor order
/// instead of a merge, since counting needs no ordering.
#[derive(Debug)]
enum CountPlan {
    /// `ix_id` point lookups.
    Ids { pending: VecDeque<[u8; 32]> },
    /// Descending range cursors on one index, walked in order.
    Ranges {
        db: Index,
        cursors: Vec<Cursor>,
        /// First unexhausted cursor.
        next: usize,
        /// For `Index::Tag`: position in `Filter::tags()` of the
        /// condition whose values seeded `cursors` — earlier values of
        /// that condition are the covering check for dedup.
        tag: Option<usize>,
    },
}

impl CountScan {
    /// New count over `filters` under `gate`, bounded to `seq <=
    /// snapshot`. `budget_entries` caps the index entries examined
    /// (`0` = no cap); `now` is the NIP-40 cutoff and `hll` the sketch
    /// to feed with counted authors (from [`Hll::for_filters`]).
    #[must_use]
    pub fn new(
        filters: Arc<[Filter]>,
        gate: ReadGate,
        snapshot: u64,
        budget_entries: u64,
        now: u64,
        hll: Option<Hll>,
    ) -> Self {
        let plans = filters
            .iter()
            .map(|filter| {
                if filter.is_impossible() {
                    return None;
                }
                Some(match scan::plan(filter) {
                    Mode::Ids { pending } => CountPlan::Ids { pending },
                    Mode::Ranges { db, cursors } => CountPlan::Ranges {
                        db,
                        cursors,
                        next: 0,
                        tag: (db == Index::Tag).then(|| {
                            // Same pick as `scan::plan`: fewest values.
                            filter
                                .tags()
                                .iter()
                                .enumerate()
                                .min_by_key(|(_, (_, values))| values.len())
                                .map_or(0, |(i, _)| i)
                        }),
                    },
                })
            })
            .collect();
        Self {
            filters,
            gate,
            snapshot,
            now,
            budget_entries,
            hll,
            plans,
            next_plan: 0,
            examined: 0,
            count: 0,
            approximate: false,
            done: false,
        }
    }

    /// Examine candidates for up to `budget` wall time; the entry
    /// budget is checked after every candidate, the wall clock every
    /// 64.
    ///
    /// # Errors
    ///
    /// [`StoreError::Heed`] on LMDB failure, [`StoreError::Corrupt`] on a
    /// broken index invariant.
    pub fn step(&mut self, store: &Store, budget: Duration) -> Result<Progress, StoreError> {
        if self.done {
            return Ok(Progress::Done);
        }
        let txn = store.read_txn()?;
        let Self {
            filters,
            gate,
            snapshot,
            now,
            budget_entries,
            hll,
            plans,
            next_plan,
            examined,
            count,
            ..
        } = self;
        let mut step = CountStep {
            store,
            txn: &txn,
            filters,
            gate,
            snapshot: *snapshot,
            now: *now,
            budget_entries: *budget_entries,
            hll,
            count,
            examined,
            processed: 0,
            start: Instant::now(),
            budget,
        };
        let pending = run_plans(&mut step, plans, next_plan)?;
        drop(txn);
        if !pending {
            self.done = true;
            return Ok(Progress::Done);
        }
        if self.budget_entries != 0 && self.examined >= self.budget_entries {
            self.approximate = true;
            self.done = true;
            return Ok(Progress::Done);
        }
        Ok(Progress::Pending)
    }

    /// The result so far; meaningful once [`Progress::Done`] is seen.
    #[must_use]
    pub fn result(&self) -> CountResult {
        CountResult {
            count: self.count,
            approximate: self.approximate,
            examined: self.examined,
            hll: self.hll.as_ref().map(|hll| *hll.registers()),
        }
    }
}

/// Drive plans in order; `true` when a budget stopped mid-plan.
fn run_plans(
    step: &mut CountStep<'_>,
    plans: &mut [Option<CountPlan>],
    next_plan: &mut usize,
) -> Result<bool, StoreError> {
    for (i, slot) in plans.iter_mut().enumerate().skip(*next_plan) {
        let Some(plan) = slot.as_mut() else {
            continue;
        };
        let stopped = match plan {
            CountPlan::Ids { pending } => walk_ids(step, i, pending)?,
            CountPlan::Ranges {
                db,
                cursors,
                next,
                tag,
            } => walk_ranges(step, i, *db, cursors, next, *tag)?,
        };
        if stopped {
            *next_plan = i;
            return Ok(true);
        }
        *slot = None;
    }
    *next_plan = plans.len();
    Ok(false)
}

/// `ix_id` point lookups until the queue drains or a budget fires.
fn walk_ids(
    step: &mut CountStep<'_>,
    filter_i: usize,
    pending: &mut VecDeque<[u8; 32]>,
) -> Result<bool, StoreError> {
    while let Some(id) = pending.pop_front() {
        *step.examined += 1;
        if let Some(bytes) = step.store.db(Index::Id).get(step.txn, &id)? {
            examine(step, filter_i, None, scan::decode_seq(bytes)?)?;
        }
        if step_stopped(step) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Walk each cursor in order until they all exhaust or a budget fires.
fn walk_ranges(
    step: &mut CountStep<'_>,
    filter_i: usize,
    index: Index,
    cursors: &mut [Cursor],
    next: &mut usize,
    tag: Option<usize>,
) -> Result<bool, StoreError> {
    let db = step.store.db(index);
    for (c, cursor) in cursors.iter_mut().enumerate().skip(*next) {
        let mut iter: Option<RevIter<'_>> =
            Some(Box::new(db.rev_range(step.txn, &cursor.bounds())?));
        while let Some(key) = scan::pull(&mut iter, cursor)? {
            *step.examined += 1;
            examine(step, filter_i, tag.map(|pos| (pos, c)), scan::key_seq(&key))?;
            if step_stopped(step) {
                *next = c;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Whether the step must yield: the entry budget after every
/// candidate, the wall clock every `BUDGET_CHECK_EVERY`.
fn step_stopped(step: &mut CountStep<'_>) -> bool {
    step.processed += 1;
    if step.budget_entries != 0 && *step.examined >= step.budget_entries {
        return true;
    }
    step.processed.is_multiple_of(BUDGET_CHECK_EVERY) && step.start.elapsed() >= step.budget
}

/// Per-step state, mirroring `Scan`'s: the read txn, the snapshot, the
/// mutable counters, and the budget cadence.
struct CountStep<'a> {
    store: &'a Store,
    txn: &'a Reader<'a>,
    filters: &'a [Filter],
    gate: &'a ReadGate,
    snapshot: u64,
    now: u64,
    budget_entries: u64,
    hll: &'a mut Option<Hll>,
    count: &'a mut u64,
    examined: &'a mut u64,
    /// Candidates examined this step (wall-clock check cadence).
    processed: usize,
    start: Instant,
    budget: Duration,
}

/// seq/snapshot checks, packed load, dedup, `Filter::matches`, count.
///
/// `cover` is `Some((tag_pos, cursor))` for tag-index candidates: the
/// event counts only if no *earlier* value of that tag condition
/// reaches it — the same `(name, value)` pair indexes an event under
/// the same `(created_at, seq)` suffix, so the earliest covering
/// cursor is a deterministic, memory-free canonical pick.
fn examine(
    step: &mut CountStep<'_>,
    filter_i: usize,
    cover: Option<(usize, usize)>,
    seq: u64,
) -> Result<(), StoreError> {
    if seq > step.snapshot {
        return Ok(());
    }
    let Some(bytes) = step.store.events.get(step.txn, &seq.to_be_bytes())? else {
        return Ok(()); // deleted between slices
    };
    let packed = PackedRef::new(bytes).ok_or(StoreError::Corrupt("bad packed record"))?;
    // NIP-40: an expired event is never counted, even before the sweep.
    let expiration = packed.expiration();
    if expiration != 0 && expiration <= step.now {
        return Ok(());
    }
    // The read gate hides restricted kinds.
    if !step.gate.allows(packed) {
        return Ok(());
    }
    let Some(filter) = step.filters.get(filter_i) else {
        return Ok(());
    };
    if let Some((tag_pos, cursor)) = cover
        && let Some((name, values)) = filter.tags().get(tag_pos)
        && {
            // `values` is sorted by bytes; search instead of scanning
            // every value against every tag — O(tags × log values).
            let earlier = values.get(..cursor).unwrap_or_default();
            packed.tags().any(|(n, t)| {
                n == *name && earlier.binary_search_by(|v| v.as_bytes().cmp(t)).is_ok()
            })
        }
    {
        return Ok(());
    }
    if !filter.matches(packed) {
        return Ok(());
    }
    // An event matched by an earlier filter is counted once, there.
    if step
        .filters
        .get(..filter_i)
        .unwrap_or_default()
        .iter()
        .any(|f| f.matches(packed))
    {
        return Ok(());
    }
    *step.count += 1;
    if let Some(hll) = step.hll.as_mut() {
        hll.add(&packed.pubkey());
    }
    Ok(())
}
