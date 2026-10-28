//! Reader thread: time-sliced stored-event scans.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nosfry_core::event::EventId;
use nosfry_core::hll::Hll;
use nosfry_core::message::{
    RelayVerb, SubId, count_frame, eose_frame, event_frame, neg_err_frame,
    neg_err_frame_with_limit, neg_msg_frame,
};
use nosfry_core::session::SubKey;
use nosfry_core::sync::{self, NegentropyStorageVector};
use nosfry_lmdb::{CountResult, CountScan, Progress, Scan, Store, StoreError};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::sync::watch;

use crate::channels::{ConnId, Out, Outbound, ReaderMsg, ScanKind, ShardMsg, route};
use crate::metrics::{Metrics, StoreOp};

/// How long an idle reader waits for new work.
const IDLE_WAIT: Duration = Duration::from_millis(5);

/// Frames per `Out::Frames` chunk pushed by a scan step.
const CHUNK_FRAMES: usize = 64;

/// Accounted bytes per `Out::Frames` chunk.
const CHUNK_BYTES: usize = 256 * 1024;

/// A sync session without a `NEG-MSG` for this long is dropped with
/// `closed: idle timeout`.
const NEG_IDLE: Duration = Duration::from_secs(60);

/// foldhash for the sync map (client-controlled sub ids), like the
/// shard's maps.
type Negs = HashMap<(ConnId, SubId), NegSession, foldhash::fast::RandomState>;

// Loop iterations, test-only spin detector. Thread-local so readers
// run by concurrent tests count independently.
#[cfg(test)]
thread_local! {
    static LOOP_TICKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The stored-event work one subscription asked for.
#[derive(Debug)]
enum Job {
    /// A REQ's snapshot-bounded scan.
    Scan(Scan),
    /// A NIP-45 `COUNT`.
    Count(Box<CountScan>),
    /// A NIP-77 `NEG-OPEN` record scan (boxed: it carries the record
    /// buffer and the initial message).
    Neg(Box<NegScan>),
}

/// Bytes reserved on `Tuning::sync_memory` for one sync: grown in
/// steps while a `NEG-OPEN` scan collects, moved into the sealed
/// `NegSession`, and released on drop whichever stage it dies at.
#[derive(Debug)]
struct SyncReservation {
    /// Bytes currently charged.
    bytes: usize,
    /// The shared counter behind `nosfry_sync_memory_bytes`.
    counter: Arc<AtomicUsize>,
}

impl SyncReservation {
    /// An empty reservation over `counter`.
    const fn new(counter: Arc<AtomicUsize>) -> Self {
        Self { bytes: 0, counter }
    }

    /// Charge `add` more bytes; `false` (nothing charged) when the
    /// total would exceed `budget` (`0` = unlimited). CAS loop like
    /// `shard::try_charge`: refuse, never overshoot.
    fn grow(&mut self, add: usize, budget: usize) -> bool {
        loop {
            let current = self.counter.load(Ordering::Relaxed);
            if budget != 0 && current.saturating_add(add) > budget {
                return false;
            }
            if self
                .counter
                .compare_exchange_weak(
                    current,
                    current.saturating_add(add),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.bytes += add;
                return true;
            }
        }
    }
}

impl Drop for SyncReservation {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// Records one charge step covers; the CAS stays off the per-record
/// path and the reservation sits at most one step over the exact
/// `records.len() * SYNC_RECORD_BYTES` size.
const SYNC_CHARGE_STEP: usize = 1024;

/// A `NEG-OPEN` scan plus the records it collects.
#[derive(Debug)]
struct NegScan {
    /// Record-mode scan: same matching/dedup/limits as a REQ, no
    /// payload fetches.
    scan: Scan,
    /// `(created_at, id)` in emit order.
    records: Vec<(u64, EventId)>,
    /// The client's initial reconcile message.
    msg: Box<[u8]>,
    /// Records already charged to `reservation` (a `SYNC_CHARGE_STEP`
    /// multiple).
    charged: usize,
    /// Memory reserved for `records`, released on drop.
    reservation: SyncReservation,
}

/// A sealed sync kept for later `NEG-MSG`s: the storage, its memory
/// reservation, and the idle clock.
#[derive(Debug)]
struct NegSession {
    /// Session generation (stale `NEG-MSG`s never match it).
    generation: u64,
    /// Sealed record storage.
    storage: NegentropyStorageVector,
    /// Bytes reserved on `Tuning::sync_memory`, released on drop.
    _reserved: SyncReservation,
    /// Last `NEG-OPEN`/`NEG-MSG` time; [`NEG_IDLE`] reaps idle ones.
    last_active: Instant,
    /// Where the idle-timeout `NEG-ERR` goes.
    out: Outbound,
}

/// The reader's pending scan queues plus open sync sessions.
#[derive(Debug)]
struct Work {
    /// Scans not yet started.
    new_scans: VecDeque<ScanEntry>,
    /// Time-sliced scans awaiting their next slice.
    resumed: VecDeque<ScanEntry>,
    /// Sealed syncs kept for `NEG-MSG`s.
    negs: Negs,
}

/// `nosfry::scan` completion line for a stored REQ scan: one row per
/// EOSE, spanning every time-slice pause (strfry's `dbScanPerf`).
fn log_scan_done(conn: ConnId, sub: &SubKey, filters: usize, events: u64, started: Instant) {
    tracing::debug!(
        target: "nosfry::scan",
        conn,
        sub = sub.id.as_str(),
        filters,
        events,
        elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "stored scan done"
    );
}

/// `nosfry::scan` completion line for a COUNT, with the index-entry
/// count the scan already tracks.
fn log_count_done(
    conn: ConnId,
    sub: &SubKey,
    filters: usize,
    started: Instant,
    result: &CountResult,
) {
    tracing::debug!(
        target: "nosfry::scan",
        conn,
        sub = sub.id.as_str(),
        filters,
        count = result.count,
        approximate = result.approximate,
        examined = result.examined,
        elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "count scan done"
    );
}

/// One running scan.
#[derive(Debug)]
struct ScanEntry {
    conn: ConnId,
    sub: SubKey,
    job: Job,
    out: Outbound,
    /// The scan's first emitted frame already went out as its own
    /// chunk so the first event never waits for a full chunk.
    first_pushed: bool,
    /// Filters the scan was opened with (log field only).
    filters: usize,
    /// Stored events emitted so far (log field only).
    events: u64,
    /// Scan start; `elapsed_us` at completion spans every
    /// time-slice pause.
    started: Instant,
}

/// Tunables a reader thread holds for its lifetime (restart-only).
pub(crate) struct Tuning {
    /// Per-slice stored-scan time budget.
    pub(crate) budget: Duration,
    /// Per-connection pending bytes above which its scans pause.
    pub(crate) high_water: usize,
    /// Process-wide pending budget: over it, scans pause whose
    /// connection already holds more than `CHUNK_BYTES` pending —
    /// under memory pressure only connections already behind stop
    /// receiving scan output; clients that keep up are not stalled,
    /// so an attacker holding the budget cannot stall everyone's
    /// queries (0 = unlimited).
    pub(crate) total_budget: usize,
    /// Per-filter cap on stored scan results.
    pub(crate) max_filter_limit: u64,
    /// Index entries a `COUNT` scan may examine before answering
    /// `"approximate": true`.
    pub(crate) max_filter_limit_count: u64,
    /// Records a sync scan may hold before answering
    /// `blocked: too many query results`.
    pub(crate) max_sync_events: u64,
    /// Process-wide budget for sealed sync storages, accounted at
    /// `SYNC_RECORD_BYTES` per record (0 = unlimited).
    pub(crate) max_sync_memory_bytes: usize,
    /// Shared counter for [`Tuning::max_sync_memory_bytes`].
    pub(crate) sync_memory: Arc<AtomicUsize>,
}

/// Reader thread main loop. `tuning.high_water` pauses scans for
/// connections whose outbound queue is backing up; `total_budget`
/// adds the process-wide rule documented on [`Tuning`]. New and
/// resumed scans alternate slices. `shutdown` ends the idle wait
/// even while shard senders still point at this reader (shards forward
/// into it).
pub(crate) fn run(
    store: &Store,
    rx: &Receiver<ReaderMsg>,
    shards: &[tokio_mpsc::Sender<ShardMsg>],
    tuning: &Tuning,
    metrics: &Metrics,
    shutdown: &watch::Receiver<bool>,
) {
    let mut work = Work {
        new_scans: VecDeque::new(),
        resumed: VecDeque::new(),
        negs: Negs::with_hasher(foldhash::fast::RandomState::default()),
    };
    let mut skipped = 0usize;
    // Alternate between the queues: new scans get their first slice
    // quickly, but a steady stream of them may not starve resumed ones
    // (resumed gets at least every other slice while both are queued).
    let mut prefer_new = true;
    loop {
        #[cfg(test)]
        LOOP_TICKS.with(|t| t.set(t.get() + 1));
        match rx.try_recv() {
            Ok(msg) => {
                apply(msg, &mut work, tuning);
                skipped = 0;
                continue;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        reap_negs(&mut work.negs);
        let entry = if prefer_new {
            work.new_scans
                .pop_front()
                .or_else(|| work.resumed.pop_front())
        } else {
            work.resumed
                .pop_front()
                .or_else(|| work.new_scans.pop_front())
        };
        prefer_new = !prefer_new;
        let Some(entry) = entry else {
            if !idle(rx, &mut work, tuning, shutdown) {
                return;
            }
            continue;
        };
        // Pause scans for connections above the outbound high-water
        // mark, or — while the process-wide total is over budget — for
        // connections already more than one chunk behind.
        let pending = entry.out.pending();
        let behind = tuning.total_budget != 0
            && entry.out.total() > tuning.total_budget
            && pending > CHUNK_BYTES;
        if pending <= tuning.high_water && !behind {
            skipped = 0;
            step(entry, store, tuning, shards, metrics, &mut work);
            continue;
        }
        work.resumed.push_back(entry);
        skipped += 1;
        if skipped < work.new_scans.len() + work.resumed.len() {
            continue;
        }
        // A full pass with nothing runnable: block for new work
        // instead of spinning.
        if !idle(rx, &mut work, tuning, shutdown) {
            return;
        }
        skipped = 0;
    }
}

/// Block up to `IDLE_WAIT` for one control message; `false` means the
/// reader exits (senders gone or shutdown raised).
fn idle(
    rx: &Receiver<ReaderMsg>,
    work: &mut Work,
    tuning: &Tuning,
    shutdown: &watch::Receiver<bool>,
) -> bool {
    match rx.recv_timeout(IDLE_WAIT) {
        Ok(msg) => {
            apply(msg, work, tuning);
            true
        }
        Err(RecvTimeoutError::Disconnected) => false,
        Err(RecvTimeoutError::Timeout) => !*shutdown.borrow(),
    }
}

/// Run one time-slice of `entry` — chunked `Frames` pushes, EOSE plus
/// `Activate` on completion of a REQ, a single `COUNT` frame on
/// completion of a count, `Closed` on error — and requeue it into
/// `resumed` when it stays pending.
fn step(
    entry: ScanEntry,
    store: &Store,
    tuning: &Tuning,
    shards: &[tokio_mpsc::Sender<ShardMsg>],
    metrics: &Metrics,
    work: &mut Work,
) {
    let budget = tuning.budget;
    let ScanEntry {
        conn,
        sub,
        job,
        out,
        first_pushed,
        filters,
        mut events,
        started,
    } = entry;
    match job {
        Job::Neg(mut neg) => {
            let result = neg.scan.step_records(store, budget, &mut |created_at, id| {
                neg.records.push((created_at, id));
            });
            if !charge_neg_scan(&mut neg, tuning) {
                out.push(Out::Neg {
                    sub: sub.clone(),
                    text: neg_err_frame(&sub.id, "blocked: sync capacity exhausted"),
                    closes: true,
                });
                return;
            }
            match result {
                Ok(Progress::Pending) => work.resumed.push_back(ScanEntry {
                    conn,
                    sub,
                    job: Job::Neg(neg),
                    out,
                    first_pushed,
                    filters,
                    events,
                    started,
                }),
                Ok(Progress::Done) => finish_neg(conn, &sub, &out, *neg, &mut work.negs, tuning),
                Err(err) => neg_failed(conn, &sub, &out, &err, metrics),
            }
        }
        Job::Count(mut scan) => match scan.step(store, budget) {
            Ok(Progress::Pending) => work.resumed.push_back(ScanEntry {
                conn,
                sub,
                job: Job::Count(scan),
                out,
                first_pushed,
                filters,
                events,
                started,
            }),
            Ok(Progress::Done) => {
                let result = scan.result();
                log_count_done(conn, &sub, filters, started, &result);
                let text = count_frame(
                    &sub.id,
                    result.count,
                    result.approximate,
                    result.hll.as_ref(),
                );
                out.push(Out::Count { sub, text });
            }
            Err(err) => scan_failed(conn, &sub, &out, &err, metrics),
        },
        Job::Scan(mut scan) => {
            let mut first = !first_pushed;
            let mut texts = Vec::new();
            let mut bytes = 0usize;
            let result = scan.step(store, budget, &mut |_seq, json| {
                events += 1;
                let text = event_frame(&sub.id, json);
                if first {
                    first = false;
                    out.push(Out::Frames {
                        sub: sub.clone(),
                        texts: vec![text],
                    });
                    return;
                }
                bytes += text.len();
                texts.push(text);
                if texts.len() >= CHUNK_FRAMES || bytes >= CHUNK_BYTES {
                    out.push(Out::Frames {
                        sub: sub.clone(),
                        texts: std::mem::take(&mut texts),
                    });
                    bytes = 0;
                }
            });
            let first_pushed = first_pushed || !first;
            if !texts.is_empty() {
                out.push(Out::Frames {
                    sub: sub.clone(),
                    texts,
                });
            }
            match result {
                Ok(Progress::Pending) => work.resumed.push_back(ScanEntry {
                    conn,
                    sub,
                    job: Job::Scan(scan),
                    out,
                    first_pushed,
                    filters,
                    events,
                    started,
                }),
                Ok(Progress::Done) => {
                    log_scan_done(conn, &sub, filters, events, started);
                    out.push(Out::Frame {
                        sub: Some(sub.clone()),
                        verb: RelayVerb::Eose,
                        text: eose_frame(&sub.id),
                    });
                    drop(route(shards, conn).blocking_send(ShardMsg::Activate { conn, sub }));
                }
                Err(err) => scan_failed(conn, &sub, &out, &err, metrics),
            }
        }
    }
}

/// A store error on any scan kind: count it, log it, close the sub.
fn scan_failed(conn: ConnId, sub: &SubKey, out: &Outbound, err: &StoreError, metrics: &Metrics) {
    metrics.store_error(StoreOp::Scan);
    tracing::error!(%err, conn, "scan failed");
    out.push(Out::Closed {
        sub: sub.clone(),
        reason: "error: internal error".to_owned(),
    });
}

/// A store error on a sync scan: `NEG-ERR`, not `CLOSED` (the id
/// lives in the `neg` namespace).
fn neg_failed(conn: ConnId, sub: &SubKey, out: &Outbound, err: &StoreError, metrics: &Metrics) {
    metrics.store_error(StoreOp::Scan);
    tracing::error!(%err, conn, "sync scan failed");
    out.push(Out::Neg {
        sub: sub.clone(),
        text: neg_err_frame(&sub.id, "error: internal error"),
        closes: true,
    });
}

/// Why a sync round produced no reply to send.
#[derive(Clone, Copy)]
enum NegError {
    /// The wire message failed the negentropy protocol.
    Invalid,
    /// `insert`/`seal` failed on a fresh storage — internal.
    Internal,
    /// No session (or a stale generation) answered the message.
    Unknown,
}

/// Charge a `NEG-OPEN` scan's new records one `SYNC_CHARGE_STEP` at a
/// time so the CAS stays off the per-record path; `false` refuses —
/// the caller stops the sync and the dropped scan releases its
/// reservation.
fn charge_neg_scan(neg: &mut NegScan, tuning: &Tuning) -> bool {
    let target = neg.records.len().next_multiple_of(SYNC_CHARGE_STEP);
    if target <= neg.charged {
        return true;
    }
    if !neg.reservation.grow(
        (target - neg.charged) * sync::SYNC_RECORD_BYTES,
        tuning.max_sync_memory_bytes,
    ) {
        return false;
    }
    neg.charged = target;
    true
}

/// A finished `NEG-OPEN` scan: over-limit and over-budget answers
/// never build a storage; otherwise seal the records, reconcile the
/// initial message, and keep the session for `NEG-MSG`s.
fn finish_neg(
    conn: ConnId,
    sub: &SubKey,
    out: &Outbound,
    neg: NegScan,
    negs: &mut Negs,
    tuning: &Tuning,
) {
    let NegScan {
        records,
        msg,
        reservation,
        ..
    } = neg;
    if u64::try_from(records.len()).unwrap_or(u64::MAX) > tuning.max_sync_events {
        out.push(Out::Neg {
            sub: sub.clone(),
            text: neg_err_frame_with_limit(
                &sub.id,
                "blocked: too many query results",
                tuning.max_sync_events,
            ),
            closes: true,
        });
        return;
    }
    let opened = sync::build_storage(&records)
        .map_err(|err| {
            tracing::error!(%err, "sync vector build failed");
            NegError::Internal
        })
        .and_then(|storage| {
            sync::reconcile(&storage, &msg)
                .map(|reply| (storage, reply))
                .map_err(|err| {
                    tracing::debug!(%err, "negentropy reconcile failed");
                    NegError::Invalid
                })
        });
    match opened {
        // NIP-77 answers every client message: `reconcile` always
        // yields at least the protocol-version byte.
        Ok((storage, reply)) => {
            out.push(Out::Neg {
                sub: sub.clone(),
                text: neg_msg_frame(&sub.id, &faster_hex::hex_string(&reply)),
                closes: false,
            });
            negs.insert(
                (conn, sub.id.clone()),
                NegSession {
                    generation: sub.generation,
                    storage,
                    _reserved: reservation,
                    last_active: Instant::now(),
                    out: out.clone(),
                },
            );
        }
        // A failed seal drops `reservation` with the error reply.
        Err(err) => push_neg_err(conn, sub, out, err),
    }
}

/// Answer `sub` with the `NEG-ERR` a failed round maps to; wire
/// details stay in the logs.
fn push_neg_err(conn: ConnId, sub: &SubKey, out: &Outbound, err: NegError) {
    let text = match err {
        NegError::Invalid => neg_err_frame(&sub.id, "invalid: malformed negentropy message"),
        NegError::Unknown => neg_err_frame(&sub.id, "closed: unknown subscription"),
        NegError::Internal => {
            tracing::error!(conn, "sync storage build failed");
            neg_err_frame(&sub.id, "error: internal error")
        }
    };
    out.push(Out::Neg {
        sub: sub.clone(),
        text,
        closes: true,
    });
}

/// A `NEG-MSG` round: reconcile against the stored session, or
/// `closed: unknown subscription` when none matches (including a
/// session still scanning, which is cancelled).
fn neg_msg(conn: ConnId, sub: &SubKey, msg: &[u8], out: &Outbound, work: &mut Work) {
    let key = (conn, sub.id.clone());
    let reply = match work.negs.get_mut(&key) {
        Some(session) if session.generation == sub.generation => {
            sync::reconcile(&session.storage, msg)
                .inspect(|_| session.last_active = Instant::now())
                .map_err(|err| {
                    tracing::debug!(%err, "negentropy reconcile failed");
                    NegError::Invalid
                })
        }
        _ => Err(NegError::Unknown),
    };
    match reply {
        // As on open, every client message is answered.
        Ok(reply) => out.push(Out::Neg {
            sub: sub.clone(),
            text: neg_msg_frame(&sub.id, &faster_hex::hex_string(&reply)),
            closes: false,
        }),
        Err(NegError::Unknown) => {
            // A `NEG-MSG` for a still-scanning sync is unanswerable
            // (no storage yet): drop the scan and answer closed.
            let keep = |e: &ScanEntry| {
                e.conn != conn || e.sub.id != sub.id || !matches!(e.job, Job::Neg(_))
            };
            work.new_scans.retain(keep);
            work.resumed.retain(keep);
            push_neg_err(conn, sub, out, NegError::Unknown);
        }
        Err(err) => {
            // The removed session's reservation releases on drop.
            work.negs.remove(&key);
            push_neg_err(conn, sub, out, err);
        }
    }
}

/// Idle-sync reaper: sessions without a `NEG-MSG` for `NEG_IDLE` are
/// dropped and their reservation released; the connection answers
/// `closed: idle timeout`.
fn reap_negs(negs: &mut Negs) {
    if negs.is_empty() {
        return;
    }
    let now = Instant::now();
    let mut dead = Vec::new();
    negs.retain(|(conn, id), session| {
        if now.duration_since(session.last_active) < NEG_IDLE {
            return true;
        }
        dead.push((
            SubKey {
                id: id.clone(),
                generation: session.generation,
            },
            session.out.clone(),
        ));
        let _ = conn;
        false
    });
    for (sub, out) in dead {
        out.push(Out::Neg {
            sub: sub.clone(),
            text: neg_err_frame(&sub.id, "closed: idle timeout"),
            closes: true,
        });
    }
}

/// Apply an inbox message.
fn apply(msg: ReaderMsg, work: &mut Work, tuning: &Tuning) {
    match msg {
        ReaderMsg::Start(start) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let filters = start.filters.len();
            let job = match start.kind {
                ScanKind::Req => Job::Scan(Scan::new(
                    start.filters,
                    start.gate,
                    start.snapshot,
                    tuning.max_filter_limit,
                    now,
                )),
                ScanKind::Count => {
                    let hll = Hll::for_filters(&start.filters);
                    Job::Count(Box::new(CountScan::new(
                        start.filters,
                        start.gate,
                        start.snapshot,
                        tuning.max_filter_limit_count,
                        now,
                        hll,
                    )))
                }
                // One record over the cap so completion can tell
                // "at the limit" from "over the limit"; a filter's
                // own `limit` still applies first.
                ScanKind::Neg { msg: open } => Job::Neg(Box::new(NegScan {
                    scan: Scan::new(
                        start.filters,
                        start.gate,
                        start.snapshot,
                        tuning.max_sync_events.saturating_add(1),
                        now,
                    ),
                    records: Vec::new(),
                    msg: open,
                    charged: 0,
                    reservation: SyncReservation::new(Arc::clone(&tuning.sync_memory)),
                })),
            };
            work.new_scans.push_back(ScanEntry {
                conn: start.conn,
                sub: start.sub,
                job,
                out: start.out,
                first_pushed: false,
                filters,
                events: 0,
                started: Instant::now(),
            });
        }
        ReaderMsg::Cancel { conn, sub_id } => {
            // REQ/CLOSE lives in the `subs` namespace; a sync under
            // the same id in `neg` is not cancelled.
            let keep = |e: &ScanEntry| {
                e.conn != conn || e.sub.id != sub_id || matches!(e.job, Job::Neg(_))
            };
            work.new_scans.retain(keep);
            work.resumed.retain(keep);
        }
        ReaderMsg::CancelConn { conn } => {
            work.new_scans.retain(|e| e.conn != conn);
            work.resumed.retain(|e| e.conn != conn);
            drop_conn_negs(&mut work.negs, conn);
        }
        ReaderMsg::NegMsg(neg) => {
            let crate::channels::NegMsg {
                conn,
                sub,
                msg: payload,
                out,
            } = *neg;
            neg_msg(conn, &sub, &payload, &out, work);
        }
        ReaderMsg::NegClose { conn, sub_id } => {
            // Drop the session (any generation) and any queued sync
            // scan for the id; `subs` under the same id are not
            // touched.
            let keep = |e: &ScanEntry| {
                e.conn != conn || e.sub.id != sub_id || !matches!(e.job, Job::Neg(_))
            };
            work.new_scans.retain(keep);
            work.resumed.retain(keep);
            // The removed session's reservation releases on drop.
            work.negs.remove(&(conn, sub_id));
        }
    }
}

/// Drop every sync session belonging to `conn`; their reservations
/// release on drop.
fn drop_conn_negs(negs: &mut Negs, conn: ConnId) {
    negs.retain(|(owner, _), _| *owner != conn);
}

#[allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_methods,
    reason = "unit tests may panic on failure; the spin detector sleeps               between loop-tick samples"
)]
#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use nosfry_core::auth::ReadGate;
    use nosfry_core::filter::Filter;
    use nosfry_core::message::SubId;
    use nosfry_lmdb::StoreOptions;
    use tokio::sync::mpsc;

    use super::*;
    use crate::channels::{ScanKind, ScanStart};

    /// A signed kind-1 event at a distinct `created_at`.
    fn event(i: u64) -> Arc<nosfry_core::event::Event> {
        use nosfry_core::event::{EventLimits, UnverifiedEvent};
        use sha2::Digest;
        let mut secret = [0u8; 32];
        secret[..8].copy_from_slice(&(i + 1).to_be_bytes());
        secret[31] = 0x5a;
        let keypair = secp256k1::Keypair::from_secret_bytes(secret).unwrap();
        let pubkey = faster_hex::hex_string(&keypair.x_only_public_key().0.to_byte_array());
        let created_at = 1_700_000_000 + i;
        let preimage = serde_json::json!([0, pubkey, created_at, 1, [], "x"]);
        let id: [u8; 32] = sha2::Sha256::digest(preimage.to_string().as_bytes()).into();
        let sig = secp256k1::schnorr::sign_no_aux_rand(&id, &keypair);
        let json = serde_json::json!({
            "id": faster_hex::hex_string(&id),
            "pubkey": pubkey,
            "created_at": created_at,
            "kind": 1,
            "tags": [],
            "content": "x",
            "sig": faster_hex::hex_string(&sig.to_byte_array()),
        })
        .to_string();
        Arc::new(
            UnverifiedEvent::parse(&json, &EventLimits::default())
                .unwrap()
                .verify(&EventLimits::default())
                .unwrap(),
        )
    }

    /// The first `Out` a scan produces is a single-frame chunk so the
    /// first event never waits for 64 frames; the rest chunk normally.
    #[test]
    fn first_emit_is_a_single_frame_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let events: Vec<Arc<nosfry_core::event::Event>> = (0..10).map(event).collect();
        store.write(&events, None).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let (shard_tx, _shard_rx) = mpsc::channel(8);
        let (out, out_rx) = Outbound::new(1 << 30, Arc::new(AtomicUsize::new(0)));
        let filters: Arc<[Filter]> = Arc::from(vec![Filter::parse("{\"kinds\":[1]}").unwrap()]);
        tx.send(ReaderMsg::Start(Box::new(ScanStart {
            conn: 1,
            sub: SubKey {
                id: SubId::parse("s").unwrap(),
                generation: 1,
            },
            kind: ScanKind::Req,
            filters,
            gate: ReadGate::default(),
            snapshot: u64::MAX,
            out,
        })))
        .unwrap();
        let reader = std::thread::spawn(move || {
            run(
                &store,
                &rx,
                &[shard_tx],
                &Tuning {
                    budget: Duration::from_secs(10),
                    high_water: usize::MAX,
                    total_budget: 0,
                    max_filter_limit: 500,
                    max_filter_limit_count: 1_000_000,
                    max_sync_events: 1_000_000,
                    max_sync_memory_bytes: 0,
                    sync_memory: Arc::new(AtomicUsize::new(0)),
                },
                &Metrics::new(),
                &watch::channel(false).1,
            );
        });
        let first = out_rx.blocking_recv().unwrap();
        let second = out_rx.blocking_recv().unwrap();
        let third = out_rx.blocking_recv().unwrap();
        let Out::Frames { texts: first, .. } = first else {
            panic!("first Out was not Frames: {first:?}")
        };
        let Out::Frames { texts: rest, .. } = second else {
            panic!("second Out was not Frames: {second:?}")
        };
        let Out::Frame { text: eose, .. } = third else {
            panic!("third Out was not the EOSE frame: {third:?}")
        };
        assert_eq!(first.len(), 1, "first chunk must carry one frame");
        assert_eq!(rest.len(), 9);
        assert!(eose.contains("EOSE"), "{eose}");
        drop(tx);
        reader.join().unwrap();
    }

    /// Every queued scan sits above the outbound high-water mark: the
    /// reader must block on `recv_timeout` instead of spinning.
    #[test]
    fn paused_scans_do_not_busy_spin() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let (shard_tx, _shard_rx) = mpsc::channel(8);
        let (out, _out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));
        // The queued scan's connection is over the high-water mark from
        // the start, so its step can never run.
        out.push(Out::Frame {
            sub: None,
            verb: RelayVerb::Notice,
            text: "x".repeat(1024),
        });
        let filters: Arc<[Filter]> = Arc::from(vec![Filter::parse("{\"kinds\":[1]}").unwrap()]);
        tx.send(ReaderMsg::Start(Box::new(ScanStart {
            conn: 1,
            sub: SubKey {
                id: SubId::parse("s").unwrap(),
                generation: 1,
            },
            kind: ScanKind::Req,
            filters,
            gate: ReadGate::default(),
            snapshot: 0,
            out,
        })))
        .unwrap();

        // The reader runs on its own thread and returns its private
        // `LOOP_TICKS` count on join.
        let reader = std::thread::spawn(move || {
            run(
                &store,
                &rx,
                &[shard_tx],
                &Tuning {
                    budget: Duration::ZERO,
                    high_water: 0,
                    total_budget: 0,
                    max_filter_limit: 500,
                    max_filter_limit_count: 1_000_000,
                    max_sync_events: 1_000_000,
                    max_sync_memory_bytes: 0,
                    sync_memory: Arc::new(AtomicUsize::new(0)),
                },
                &Metrics::new(),
                &watch::channel(false).1,
            );
            LOOP_TICKS.with(std::cell::Cell::get)
        });
        std::thread::sleep(Duration::from_millis(300));
        drop(tx);
        let ticks = reader.join().unwrap();
        // IDLE_WAIT is 5ms: roughly 60 passes in 300ms. An unpaused
        // spin would tick millions of times in the same window.
        assert!(ticks < 1000, "reader spun {ticks} times in 300ms");
    }

    /// With the process-wide pending total over a tiny budget, a scan
    /// whose connection is already more than one chunk behind stays
    /// paused while a caught-up connection's scan completes.
    #[test]
    fn total_budget_pauses_only_behind_scans() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let events: Vec<Arc<nosfry_core::event::Event>> = (0..3).map(event).collect();
        store.write(&events, None).unwrap();
        // Pre-inflated shared total: over any tiny budget.
        let total = Arc::new(AtomicUsize::new(2));
        let (tx, rx) = std::sync::mpsc::channel();
        let (shard_tx, mut shard_rx) = mpsc::channel(8);
        // Conn 1 is already more than one chunk behind; conn 2 has
        // nothing pending. Both share the same total.
        let (behind_out, behind_rx) = Outbound::new(usize::MAX, Arc::clone(&total));
        behind_out.push(Out::Frame {
            sub: None,
            verb: RelayVerb::Notice,
            text: "x".repeat(CHUNK_BYTES + 1),
        });
        let (caught_out, caught_rx) = Outbound::new(1 << 30, Arc::clone(&total));
        let filters: Arc<[Filter]> = Arc::from(vec![Filter::parse("{\"kinds\":[1]}").unwrap()]);
        for (conn, out) in [(1, behind_out), (2, caught_out)] {
            tx.send(ReaderMsg::Start(Box::new(ScanStart {
                conn,
                sub: SubKey {
                    id: SubId::parse(&format!("s{conn}")).unwrap(),
                    generation: 1,
                },
                kind: ScanKind::Req,
                filters: Arc::clone(&filters),
                gate: ReadGate::default(),
                snapshot: u64::MAX,
                out,
            })))
            .unwrap();
        }
        let reader = std::thread::spawn(move || {
            run(
                &store,
                &rx,
                &[shard_tx],
                &Tuning {
                    budget: Duration::from_secs(10),
                    high_water: usize::MAX,
                    total_budget: 1,
                    max_filter_limit: 500,
                    max_filter_limit_count: 1_000_000,
                    max_sync_events: 1_000_000,
                    max_sync_memory_bytes: 0,
                    sync_memory: Arc::new(AtomicUsize::new(0)),
                },
                &Metrics::new(),
                &watch::channel(false).1,
            );
        });
        // Conn 2's scan completes (frames + EOSE + Activate); conn 1's
        // scan stays paused and pushes nothing beyond the notice frame
        // already queued above.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut eose = false;
        while !eose && Instant::now() < deadline {
            match caught_rx.try_recv() {
                Some(Out::Frame { ref text, .. }) if text.contains("EOSE") => eose = true,
                Some(_) | None => {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        assert!(eose, "caught-up scan did not complete under total budget");
        assert_eq!(
            shard_rx.blocking_recv().map(|_| ()),
            Some(()),
            "caught-up scan never activated"
        );
        std::thread::sleep(Duration::from_millis(100));
        let mut behind_frames = 0usize;
        while let Some(out) = behind_rx.try_recv() {
            behind_frames += usize::from(matches!(out, Out::Frames { .. }));
            assert!(
                matches!(out, Out::Frame { ref text, .. } if !text.contains("EOSE")),
                "behind scan pushed while paused: {out:?}"
            );
        }
        assert_eq!(behind_frames, 0, "behind scan emitted frames while paused");
        drop(tx);
        reader.join().unwrap();
    }

    /// A resumed scan must keep receiving slices while a steady stream
    /// of new scans arrives: the scheduler alternates the queues, so a
    /// flood of REQs cannot starve long-running scans.
    #[test]
    fn resumed_scan_progresses_during_new_scan_flood() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let events: Vec<Arc<nosfry_core::event::Event>> = (0..4_000).map(event).collect();
        store.write(&events, None).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        // Every finishing scan `blocking_send`s an `Activate`; keep the
        // inbox bigger than the flood.
        let (shard_tx, mut shard_rx) = mpsc::channel(8_192);
        let (long_out, long_rx) = Outbound::new(1 << 30, Arc::new(AtomicUsize::new(0)));
        let all: Arc<[Filter]> = Arc::from(vec![Filter::parse("{\"kinds\":[1]}").unwrap()]);
        let one: Arc<[Filter]> =
            Arc::from(vec![Filter::parse("{\"kinds\":[1],\"limit\":1}").unwrap()]);
        tx.send(ReaderMsg::Start(Box::new(ScanStart {
            conn: 1,
            sub: SubKey {
                id: SubId::parse("long").unwrap(),
                generation: 1,
            },
            kind: ScanKind::Req,
            filters: Arc::clone(&all),
            gate: ReadGate::default(),
            snapshot: u64::MAX,
            out: long_out,
        })))
        .unwrap();
        // Queue the flood before the reader starts so every scan is
        // applied before the first step: `new_scans` is [long, n0..n499]
        // and a scheduler that always prefers new scans cannot reach
        // the resumed queue until the whole flood is done.
        for i in 0..500u64 {
            let (out, _rx) = Outbound::new(0, Arc::new(AtomicUsize::new(0)));
            tx.send(ReaderMsg::Start(Box::new(ScanStart {
                conn: 2 + i,
                sub: SubKey {
                    id: SubId::parse(&format!("n{i}")).unwrap(),
                    generation: 1,
                },
                kind: ScanKind::Req,
                filters: Arc::clone(&one),
                gate: ReadGate::default(),
                snapshot: u64::MAX,
                out,
            })))
            .unwrap();
        }
        let reader = std::thread::spawn(move || {
            run(
                &store,
                &rx,
                &[shard_tx],
                &Tuning {
                    budget: Duration::from_micros(50),
                    high_water: usize::MAX,
                    total_budget: 0,
                    max_filter_limit: 5_000,
                    max_filter_limit_count: 1_000_000,
                    max_sync_events: 1_000_000,
                    max_sync_memory_bytes: 0,
                    sync_memory: Arc::new(AtomicUsize::new(0)),
                },
                &Metrics::new(),
                &watch::channel(false).1,
            );
        });
        // Every finished scan reports one `Activate` on `shard_rx`.
        // With alternating slices the long scan finishes long before
        // the flood drains; a new-scans-first scheduler would not emit
        // its EOSE until all 500 flood scans are done.
        let (mut activates, mut eose) = (0usize, false);
        let deadline = Instant::now() + Duration::from_secs(30);
        while !eose && activates < 500 && Instant::now() < deadline {
            while let Some(out) = long_rx.try_recv() {
                eose |= matches!(out, Out::Frame { ref text, .. } if text.contains("EOSE"));
            }
            match shard_rx.try_recv() {
                Ok(_) => activates += 1,
                Err(_) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        assert!(eose, "resumed scan starved during the flood");
        drop(tx);
        reader.join().unwrap();
    }

    /// A sync session idle past `NEG_IDLE` is reaped: `closed: idle
    /// timeout` on its `Outbound`, reservation released, fresher
    /// sessions untouched.
    #[test]
    fn idle_sync_is_reaped() {
        let tuning = Tuning {
            budget: Duration::from_secs(10),
            high_water: usize::MAX,
            total_budget: 0,
            max_filter_limit: 500,
            max_filter_limit_count: 1_000_000,
            max_sync_events: 1_000_000,
            max_sync_memory_bytes: 0,
            sync_memory: Arc::new(AtomicUsize::new(80)),
        };
        let (out, out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));
        let mut negs = Negs::with_hasher(foldhash::fast::RandomState::default());
        let session = |id: &str, generation: u64, last_active: Instant, conn_out: &Outbound| {
            let mut storage = NegentropyStorageVector::new();
            storage.seal().unwrap();
            (
                (1, SubId::parse(id).unwrap()),
                NegSession {
                    generation,
                    storage,
                    _reserved: SyncReservation {
                        bytes: 40,
                        counter: Arc::clone(&tuning.sync_memory),
                    },
                    last_active,
                    out: conn_out.clone(),
                },
            )
        };
        for (id, generation, last_active) in [
            (
                "s",
                7,
                Instant::now()
                    .checked_sub(NEG_IDLE + Duration::from_secs(1))
                    .unwrap(),
            ),
            ("t", 8, Instant::now()),
        ] {
            let (key, session) = session(id, generation, last_active, &out);
            negs.insert(key, session);
        }

        reap_negs(&mut negs);

        assert_eq!(negs.len(), 1, "{negs:?}");
        assert!(negs.contains_key(&(1, SubId::parse("t").unwrap())));
        assert_eq!(tuning.sync_memory.load(Ordering::Relaxed), 40);
        let Out::Neg { sub, text, closes } = out_rx.try_recv().unwrap() else {
            panic!("expected the idle-timeout NEG-ERR")
        };
        assert_eq!(sub.id.as_str(), "s");
        assert_eq!(sub.generation, 7);
        assert_eq!(text, "[\"NEG-ERR\",\"s\",\"closed: idle timeout\"]");
        assert!(closes);
    }

    /// Run a reader against `store` on a thread; returns the sender
    /// half and the join handle (`drop` the sender to stop it).
    fn spawn_reader(
        store: Store,
        budget: Duration,
        max_sync_memory_bytes: usize,
    ) -> (
        std::sync::mpsc::Sender<ReaderMsg>,
        Arc<AtomicUsize>,
        std::thread::JoinHandle<()>,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let (shard_tx, _shard_rx) = mpsc::channel(8);
        let sync_memory = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&sync_memory);
        let reader = std::thread::spawn(move || {
            run(
                &store,
                &rx,
                &[shard_tx],
                &Tuning {
                    budget,
                    high_water: usize::MAX,
                    total_budget: 0,
                    max_filter_limit: 500,
                    max_filter_limit_count: 1_000_000,
                    max_sync_events: 1_000_000,
                    max_sync_memory_bytes,
                    sync_memory: counter,
                },
                &Metrics::new(),
                &watch::channel(false).1,
            );
        });
        (tx, sync_memory, reader)
    }

    /// A `NEG-OPEN` start message for `conn`/`id` over `filters`.
    fn neg_start(conn: u64, id: &str, filters: Arc<[Filter]>, out: Outbound) -> ReaderMsg {
        ReaderMsg::Start(Box::new(ScanStart {
            conn,
            sub: SubKey {
                id: SubId::parse(id).unwrap(),
                generation: 1,
            },
            kind: ScanKind::Neg {
                msg: vec![0x61].into(),
            },
            filters,
            gate: ReadGate::default(),
            snapshot: u64::MAX,
            out,
        }))
    }

    /// Wait until `pred` holds for the counter or panic after 5 s.
    fn until(counter: &AtomicUsize, pred: impl Fn(usize) -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pred(counter.load(Ordering::Relaxed)) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A sync whose records exceed `max_sync_memory_bytes` is refused
    /// mid-scan with `blocked: sync capacity exhausted`; the gauge
    /// returns to 0.
    #[test]
    fn sync_scan_over_budget_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let events: Vec<Arc<nosfry_core::event::Event>> = (0..100).map(event).collect();
        store.write(&events, None).unwrap();
        // One charge step (1024 records x 40 B) already exceeds it.
        let (tx, counter, reader) = spawn_reader(store, Duration::from_secs(10), 1_000);
        let (out, out_rx) = Outbound::new(1 << 30, Arc::new(AtomicUsize::new(0)));
        let filters: Arc<[Filter]> = Arc::from(vec![Filter::parse("{}").unwrap()]);
        tx.send(neg_start(1, "n", filters, out)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let frame = out_rx.blocking_recv().unwrap();
            if let Out::Neg { text, .. } = frame {
                assert!(text.contains("blocked: sync capacity exhausted"), "{text}");
                break;
            }
            assert!(Instant::now() < deadline, "no NEG-ERR within 5 s");
        }
        until(&counter, |n| n == 0, "sync memory released");
        drop(tx);
        reader.join().unwrap();
    }

    /// Cancelling a connection mid-scan drops the in-progress sync
    /// and releases its stepped reservation.
    #[test]
    fn sync_scan_cancel_releases() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        // A zero-time step budget yields ~1 record per step, so the
        // scan is still in flight when the cancel lands.
        let events: Vec<Arc<nosfry_core::event::Event>> = (0..5_000).map(event).collect();
        store.write(&events, None).unwrap();
        let (tx, counter, reader) = spawn_reader(store, Duration::ZERO, 0);
        let (out, _out_rx) = Outbound::new(1 << 30, Arc::new(AtomicUsize::new(0)));
        let filters: Arc<[Filter]> = Arc::from(vec![Filter::parse("{}").unwrap()]);
        tx.send(neg_start(1, "n", filters, out)).unwrap();
        until(&counter, |n| n > 0, "the first charge");
        tx.send(ReaderMsg::CancelConn { conn: 1 }).unwrap();
        until(&counter, |n| n == 0, "reservation released on cancel");
        drop(tx);
        reader.join().unwrap();
    }

    /// A finished sync holds its reservation in the sealed session;
    /// `NEG-CLOSE` releases it.
    #[test]
    fn sync_close_releases() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let events: Vec<Arc<nosfry_core::event::Event>> = (0..100).map(event).collect();
        store.write(&events, None).unwrap();
        let (tx, counter, reader) = spawn_reader(store, Duration::from_secs(10), 0);
        let (outbound, out_rx) = Outbound::new(1 << 30, Arc::new(AtomicUsize::new(0)));
        let filters: Arc<[Filter]> = Arc::from(vec![Filter::parse("{}").unwrap()]);
        tx.send(neg_start(1, "n", filters, outbound)).unwrap();
        // The session seals once the NEG-MSG reply arrives; its
        // reservation covers one 1024-record step.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let frame = out_rx.blocking_recv().unwrap();
            if let Out::Neg { text, .. } = frame {
                assert!(text.contains("\"NEG-MSG\""), "{text}");
                break;
            }
            assert!(Instant::now() < deadline, "no NEG-MSG within 5 s");
        }
        until(&counter, |n| n == 40 * 1_024, "the session reservation");
        tx.send(ReaderMsg::NegClose {
            conn: 1,
            sub_id: SubId::parse("n").unwrap(),
        })
        .unwrap();
        until(&counter, |n| n == 0, "reservation released on close");
        drop(tx);
        reader.join().unwrap();
    }
}
