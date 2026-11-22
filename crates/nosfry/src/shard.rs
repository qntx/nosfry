//! Monitor shard thread: the live-subscription inverted index plus the
//! snapshot/pending machinery that makes delivery exactly-once.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::TrySendError;

use nosfry_core::event::Event;
use nosfry_core::filter::Filter;
use nosfry_core::message::{SubId, neg_err_frame};
use nosfry_core::monitor::Monitors;
use nosfry_core::session::SubKey;
use nosfry_lmdb::Store;
use tokio::sync::mpsc;

use crate::channels::{
    ConnId, JobSlot, Out, Outbound, ReaderInbox, ReaderMsg, ScanKind, ScanLease, ScanStart,
    ShardMsg, route,
};
use crate::metrics::{Metrics, ReaderBusy};

/// Buffered matches per pending subscription before `CLOSED`.
const PENDING_CAP: usize = 4096;

/// foldhash for the hot-path maps (server-assigned conn ids and client
/// sub ids); randomized seeding keeps `HashDoS` resistance.
type Map<K, V> = HashMap<K, V, foldhash::fast::RandomState>;

fn map<K, V>() -> Map<K, V> {
    Map::with_hasher(foldhash::fast::RandomState::default())
}

/// A subscription registered but not yet activated: its live matches
/// buffer until the stored scan finishes. Every buffered match holds
/// an [`Outbound::reserve`] against the connection's byte budget —
/// counted in `reserved` and the process total, never in `pending`:
/// the reader's high-water pause must not stall the very scan whose
/// `Activate` flush returns the reservation. A sub whose reservations
/// alone fill the budget ends at the per-connection cap with "fell
/// behind" for that sub only — never a connection kill, never a
/// deadlock.
#[derive(Debug)]
struct PendingSub {
    /// Generation the pending state belongs to; `Activate` must match.
    generation: u64,
    /// Buffered live matches in arrival order. Entries share the
    /// pending's `SubKey` — id from the map key, generation from
    /// `generation` — rebuilt at flush.
    buffer: VecDeque<Arc<Event>>,
    /// Bytes `buffer` holds reserved on the connection's `Outbound`;
    /// every teardown path releases them before the `PendingSub` dies.
    reserved: usize,
}

/// Per-connection state inside one shard; created on `Register`, which
/// always carries the connection's outbound queue.
#[derive(Debug)]
struct ConnState {
    /// Where frames go.
    out: Outbound,
    /// Pending subscriptions: sub id -> generation + buffered matches.
    pending: Map<SubId, PendingSub>,
    /// `Filter::approx_bytes` charged per live subscription; removal
    /// releases the charge, so a `Remove` for a refused or gone sub
    /// is a no-op.
    sub_bytes: Map<SubId, usize>,
    /// Each REQ's scan snapshot: the live stream delivers only seqs
    /// above it, so an event can never arrive both stored and live.
    snapshots: Map<SubId, u64>,
}

/// One monitor shard's state: the monitor index, connection outbound
/// queues, the reader routing table it forwards scan control to, and
/// the authoritative `last_seq` snapshot source.
#[derive(Debug)]
struct Shard {
    monitors: Monitors<ConnId>,
    conns: Map<ConnId, ConnState>,
    /// Reader inboxes, routed `conn % len`; forwarding Start/Cancel from
    /// here keeps a subscription's reader messages in shard order.
    /// Sends are always `try_send`: the shard is the hub every other
    /// thread waits on, so it can never block on a reader.
    readers: Arc<[ReaderInbox]>,
    /// Process-wide counters (reader shedding).
    metrics: Arc<Metrics>,
    /// Process-wide live-subscription byte charge, shared by every
    /// shard (the `nosfry_subscription_bytes` gauge).
    sub_charge: Arc<AtomicUsize>,
    /// `[relay] max_subscription_bytes_total` (`0` = unlimited).
    sub_budget: usize,
    /// Re-read at `Register` so foreign writers on the same LMDB env
    /// (a `nosfry sync`/`import` process) become visible to new scans.
    store: Arc<Store>,
    last_seq: u64,
    hits: Vec<(ConnId, SubKey)>,
}

/// Charge `bytes` against the shared budget (`0` = unlimited) with a
/// CAS loop: several shard threads share the counter, so a
/// `fetch_add`-then-undo could transiently push a peer shard over.
/// The charge is always counted — the budget only decides whether a
/// REQ is refused — so the gauge reflects real usage when unlimited.
fn try_charge(total: &AtomicUsize, budget: usize, bytes: usize) -> bool {
    let mut current = total.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(bytes) else {
            return false;
        };
        if budget != 0 && next > budget {
            return false;
        }
        match total.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(now) => current = now,
        }
    }
}

/// Return `bytes` to the shared charge.
fn release(total: &AtomicUsize, bytes: usize) {
    total.fetch_sub(bytes, Ordering::Relaxed);
}

/// Release `sub_id`'s charge from `state`, if any — idempotent: a
/// `Remove` for a refused or already-closed sub is a no-op.
fn release_sub(state: &mut ConnState, sub_id: &SubId, charge: &AtomicUsize) {
    if let Some(bytes) = state.sub_bytes.remove(sub_id) {
        release(charge, bytes);
    }
}

impl Shard {
    fn new(
        store: &Arc<Store>,
        readers: Arc<[ReaderInbox]>,
        sub_charge: Arc<AtomicUsize>,
        sub_budget: usize,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            monitors: Monitors::new(),
            conns: map(),
            readers,
            metrics,
            sub_charge,
            sub_budget,
            last_seq: store.snapshot().unwrap_or(0),
            store: Arc::clone(store),
            hits: Vec::new(),
        }
    }

    /// Apply one inbox message.
    fn handle(&mut self, msg: ShardMsg) {
        match msg {
            ShardMsg::Register(mut start) => {
                // The snapshot is assigned before the Start is queued
                // on the reader, so a `Cancel` forwarded later can
                // never overtake it. Seqs committed by another process
                // on the same env never arrive via `Batch`, so re-read
                // the store here.
                self.last_seq = self.last_seq.max(self.store.snapshot().unwrap_or(0));
                start.snapshot = self.last_seq;
                self.register(start);
            }
            ShardMsg::Activate { conn, sub } => {
                let Some(state) = self.conns.get_mut(&conn) else {
                    return;
                };
                // A stale Activate (an old generation's scan finishing
                // after a re-REQ) must not flush or activate the new
                // subscription before its own scan completes.
                if state
                    .pending
                    .get(&sub.id)
                    .is_some_and(|pending| pending.generation != sub.generation)
                {
                    return;
                }
                if let Some(pending) = state.pending.remove(&sub.id) {
                    flush(&state.out, &sub.id, pending);
                }
            }
            ShardMsg::Remove { conn, sub_id } => {
                self.unregister_req(conn, &sub_id);
                self.forward(conn, ReaderMsg::Cancel { conn, sub_id });
            }
            ShardMsg::RemoveConn { conn } => {
                self.monitors.remove_connection(conn);
                if let Some(state) = self.conns.remove(&conn) {
                    self.release_conn(state);
                }
                self.forward(conn, ReaderMsg::CancelConn { conn });
            }
            // Sync control shares the reader with its scan so a
            // `NEG-MSG`/`NEG-CLOSE` cannot overtake the `Start`
            // that created the session.
            ShardMsg::NegMsg(neg) => {
                let result = route(&self.readers, neg.conn)
                    .tx
                    .try_send(ReaderMsg::NegMsg(neg));
                // `Full` hands back the `NegMsg` just sent; the
                // session closes the sync on the `NEG-ERR`, and a
                // reader-side session it left behind is reaped by
                // `NEG_IDLE`.
                if let Err(TrySendError::Full(ReaderMsg::NegMsg(failed))) = result {
                    self.metrics.reader_busy(ReaderBusy::NegMsg);
                    failed.out.push(Out::Neg {
                        sub: failed.sub.clone(),
                        text: neg_err_frame(&failed.sub.id, "rate-limited: relay busy"),
                        closes: true,
                    });
                }
            }
            ShardMsg::NegClose { conn, sub_id } => {
                self.forward(conn, ReaderMsg::NegClose { conn, sub_id });
            }
            ShardMsg::Batch(batch) => {
                for (seq, event) in batch.iter() {
                    self.last_seq = self.last_seq.max(*seq);
                    self.deliver(event, Some(*seq));
                }
            }
            ShardMsg::Ephemeral(event) => {
                self.deliver(&event, None);
            }
        }
    }

    /// Admit one scan: take a slot on the connection's own
    /// pending-query budget first, then one on the reader's job
    /// budget (the job cap, not the inbox, is the binding shared
    /// limit), then — for a REQ — charge the subscription budget and
    /// register the live machinery, and only then hand the `Start` to
    /// the reader. A connection opening queries faster than its
    /// reader drains them hits its own cap and is shed alone, before
    /// it may spend the shared cap on other connections' work. A
    /// full inbox undoes the registration exactly like the `Remove`
    /// path before shedding; a disconnected one means shutdown and
    /// drops silently.
    fn register(&mut self, start: Box<ScanStart>) {
        let Some(conn_slot) = JobSlot::try_acquire(&start.conn_jobs) else {
            self.shed_start(
                &start,
                "rate-limited: too many pending queries",
                ReaderBusy::ConnScan,
            );
            return;
        };
        let Some(reader_slot) = JobSlot::try_acquire(&route(&self.readers, start.conn).jobs) else {
            self.shed_start(&start, "rate-limited: relay busy", ReaderBusy::Scan);
            return;
        };
        // A COUNT or sync needs the snapshot but no live
        // machinery: no monitor index, no pending buffer, no
        // budget charge.
        if matches!(start.kind, ScanKind::Req) && !self.register_req(&start) {
            return;
        }
        let conn = start.conn;
        let msg = ReaderMsg::Start {
            start,
            lease: ScanLease {
                _conn: conn_slot,
                _reader: reader_slot,
            },
        };
        // `Full` hands back the message just sent — always the `Start`
        // here; any other variant is impossible and its lease simply
        // drops with the message. A disconnect means shutdown.
        if let Err(TrySendError::Full(ReaderMsg::Start { start: failed, .. })) =
            route(&self.readers, conn).tx.try_send(msg)
        {
            if matches!(failed.kind, ScanKind::Req) {
                self.unregister_req(failed.conn, &failed.sub.id);
            }
            self.shed_start(&failed, "rate-limited: relay busy", ReaderBusy::Scan);
        }
    }

    /// The shed answer for an un-admitted scan: `CLOSED <reason>` for
    /// REQ/COUNT, `NEG-ERR` for a sync open — the same frame family a
    /// client-side rate limit produces, so SDKs back off and the
    /// freed session/neg slot tears the sub down itself. `busy` is
    /// the `nosfry_reader_busy_total` class it counts under.
    fn shed_start(&self, start: &ScanStart, reason: &'static str, busy: ReaderBusy) {
        self.metrics.reader_busy(busy);
        match start.kind {
            ScanKind::Req | ScanKind::Count => start.out.push(Out::Closed {
                sub: start.sub.clone(),
                reason: reason.to_owned(),
            }),
            ScanKind::Neg { .. } => start.out.push(Out::Neg {
                sub: start.sub.clone(),
                text: neg_err_frame(&start.sub.id, reason),
                closes: true,
            }),
        }
    }

    /// Forward a control message to `conn`'s reader, never blocking:
    /// a full inbox drops it (counted as `control`), because every
    /// message it carries is safe to lose —
    /// * a dropped `Cancel` only lets an already-admitted scan run to
    ///   completion (bounded by `max_filter_limit`); its frames fail
    ///   the connection's `is_current` gate and its `Activate` is
    ///   ignored by the shard's generation check;
    /// * a dropped `CancelConn`/`NegClose` leaves sync sessions that
    ///   the `NEG_IDLE` reaper collects within 60 s while their memory
    ///   stays charged to `max_sync_memory_bytes`, and scans of a
    ///   closed connection still run to completion — bounded by
    ///   `max_filter_limit` per filter, `max_filter_limit_count` for a
    ///   COUNT — but their pushes charge nothing once the
    ///   `OutboundRx` is dropped.
    fn forward(&self, conn: ConnId, msg: ReaderMsg) {
        match route(&self.readers, conn).tx.try_send(msg) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => self.metrics.reader_busy(ReaderBusy::Control),
        }
    }

    /// The `RemoveConn` teardown of one connection's state: release
    /// every live sub's byte charge and every pending buffer's
    /// reservations.
    fn release_conn(&self, state: ConnState) {
        release(&self.sub_charge, state.sub_bytes.values().sum());
        for pending in state.pending.into_values() {
            state.out.unreserve(pending.reserved);
        }
    }

    /// The `Remove`-path state teardown: monitor index, pending
    /// buffer, and the subscription byte charge. Idempotent — also
    /// the undo for a `Start` that never reached the reader.
    fn unregister_req(&mut self, conn: ConnId, sub_id: &SubId) {
        self.monitors.remove(conn, sub_id);
        if let Some(state) = self.conns.get_mut(&conn) {
            if let Some(pending) = state.pending.remove(sub_id) {
                state.out.unreserve(pending.reserved);
            }
            state.snapshots.remove(sub_id);
            release_sub(state, sub_id, &self.sub_charge);
        }
    }

    /// Charge and register one REQ subscription. `false` when the
    /// budget refused it: nothing is touched — no monitor, no pending
    /// buffer, no `Start` — and the refusal `CLOSED` queued on `out`
    /// frees the session slot itself, so its `Remove` is an
    /// accounting no-op.
    fn register_req(&mut self, start: &ScanStart) -> bool {
        let bytes: usize = start.filters.iter().map(Filter::approx_bytes).sum();
        if !try_charge(&self.sub_charge, self.sub_budget, bytes) {
            start.out.push(Out::Closed {
                sub: start.sub.clone(),
                reason: "blocked: subscription capacity exhausted".to_owned(),
            });
            return false;
        }
        let state = self
            .conns
            .entry(start.conn)
            .and_modify(|state| state.out = start.out.clone())
            .or_insert_with(|| ConnState {
                out: start.out.clone(),
                pending: map(),
                sub_bytes: map(),
                snapshots: map(),
            });
        // A re-REQ arrives as Remove + Register, but releasing an
        // old charge on insert keeps the accounting right for a
        // bare re-Register too — and its buffer's reservations go
        // with it.
        if let Some(old) = state.sub_bytes.insert(start.sub.id.clone(), bytes) {
            release(&self.sub_charge, old);
        }
        if let Some(old) = state.pending.insert(
            start.sub.id.clone(),
            PendingSub {
                generation: start.sub.generation,
                buffer: VecDeque::new(),
                reserved: 0,
            },
        ) {
            state.out.unreserve(old.reserved);
        }
        state.snapshots.insert(start.sub.id.clone(), start.snapshot);
        self.monitors.insert(
            start.conn,
            start.sub.clone(),
            Arc::clone(&start.filters),
            start.gate.clone(),
        );
        true
    }

    /// Match the event against the monitor index and route each hit;
    /// `seq` is `Some` for stored [`Batch`] events and `None` for
    /// ephemeral ones, which always deliver.
    fn deliver(&mut self, event: &Arc<Event>, seq: Option<u64>) {
        self.monitors.matches(event.packed(), &mut self.hits);
        let Self {
            monitors,
            conns,
            hits,
            sub_charge,
            ..
        } = self;
        for (conn, sub) in hits.drain(..) {
            let Some(state) = conns.get_mut(&conn) else {
                continue;
            };
            route_hit(monitors, state, conn, sub, event, seq, sub_charge);
        }
    }
}

/// Route one monitor hit: buffered while the subscription's stored scan
/// runs (closed and dropped when the buffer overflows), one shared
/// `Arc` pushed to the connection once active.
fn route_hit(
    monitors: &mut Monitors<ConnId>,
    state: &mut ConnState,
    conn: ConnId,
    sub: SubKey,
    event: &Arc<Event>,
    seq: Option<u64>,
    sub_charge: &AtomicUsize,
) {
    // Exactly-once: a seq at or under the sub's REQ snapshot was (or
    // will be) returned by its stored scan — live delivery skips it.
    if seq.is_some_and(|s| s <= state.snapshots.get(&sub.id).copied().unwrap_or(0)) {
        return;
    }
    let Some(pending) = state.pending.get_mut(&sub.id) else {
        state.out.push(Out::Event {
            sub,
            event: Arc::clone(event),
        });
        return;
    };
    let frame_bytes = Out::event_bytes(&sub, event);
    if pending.buffer.len() < PENDING_CAP && state.out.reserve(frame_bytes) {
        pending.buffer.push_back(Arc::clone(event));
        pending.reserved += frame_bytes;
        return;
    }
    // Over the entry cap or the byte budget: the reservations go
    // back first so the `CLOSED` itself still fits.
    if let Some(dropped) = state.pending.remove(&sub.id) {
        state.out.unreserve(dropped.reserved);
    }
    state.out.push(Out::Closed {
        sub: sub.clone(),
        reason: "error: subscription fell behind".to_owned(),
    });
    // Release the charge now: the `Remove` the connection sends for
    // this `Out::Closed` may be dropped as stale, and a second
    // release is a no-op on the map anyway.
    if let Some(bytes) = state.sub_bytes.remove(&sub.id) {
        release(sub_charge, bytes);
    }
    state.snapshots.remove(&sub.id);
    monitors.remove(conn, &sub.id);
}

/// Flush an activated pending sub: release its reservations — each
/// push below charges the same bytes again — then send every buffered
/// live match under the `SubKey` rebuilt from the map key and the
/// pending generation.
fn flush(out: &Outbound, sub_id: &SubId, pending: PendingSub) {
    out.unreserve(pending.reserved);
    let sub = SubKey {
        id: sub_id.clone(),
        generation: pending.generation,
    };
    for event in pending.buffer {
        out.push(Out::Event {
            sub: sub.clone(),
            event,
        });
    }
}

/// Shard thread main loop. `last_seq` starts at the store snapshot,
/// is re-read on every `Register` so foreign writers become visible,
/// and otherwise advances via [`ShardMsg::Batch`]. `readers` is the
/// routing table the shard forwards scan control into;
/// `sub_charge`/`sub_budget` are the process-wide live-subscription
/// byte accounting the shards share.
pub(crate) fn run(
    store: &Arc<Store>,
    mut rx: mpsc::Receiver<ShardMsg>,
    readers: Arc<[ReaderInbox]>,
    sub_charge: Arc<AtomicUsize>,
    sub_budget: usize,
    metrics: Arc<Metrics>,
) {
    let mut shard = Shard::new(store, readers, sub_charge, sub_budget, metrics);
    while let Some(msg) = rx.blocking_recv() {
        shard.handle(msg);
    }
}

#[allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "unit tests may panic on failure"
)]
#[cfg(test)]
mod tests {
    use nosfry_core::auth::ReadGate;
    use nosfry_core::event::{EventLimits, UnverifiedEvent};
    use nosfry_core::filter::Filter;
    use nosfry_lmdb::StoreOptions;
    use secp256k1::{Keypair, SecretKey, schnorr};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::channels::{JobBudget, ScanKind, ScanStart};

    fn event(kind: u16, content: &str) -> Arc<Event> {
        let keypair = Keypair::from_secret_key(&SecretKey::from_secret_bytes([7u8; 32]).unwrap());
        let pk_hex = faster_hex::hex_string(&keypair.x_only_public_key().0.to_byte_array());
        let created_at = 1_700_000_000u64;
        let preimage =
            serde_json::to_string(&json!([0, pk_hex, created_at, kind, [], content])).unwrap();
        let id = Sha256::digest(preimage.as_bytes());
        let sig = schnorr::sign_no_aux_rand(&id, &keypair);
        let json = serde_json::to_string(&json!({
            "id": faster_hex::hex_string(&id),
            "pubkey": pk_hex,
            "created_at": created_at,
            "kind": kind,
            "tags": [],
            "content": content,
            "sig": faster_hex::hex_string(&sig.to_byte_array()),
        }))
        .unwrap();
        Arc::new(
            UnverifiedEvent::parse(&json, &EventLimits::default())
                .unwrap()
                .verify(&EventLimits::default())
                .unwrap(),
        )
    }

    fn sub_key(id: &str, generation: u64) -> SubKey {
        SubKey {
            id: SubId::parse(id).unwrap(),
            generation,
        }
    }

    fn filters() -> Arc<[Filter]> {
        Arc::from(vec![Filter::parse("{\"kinds\":[1]}").unwrap()])
    }

    /// A one-inbox reader routing table at `cap` slots; returns the
    /// shard-side table, the reader receiver, and the job counter.
    fn readers(
        cap: usize,
    ) -> (
        Arc<[ReaderInbox]>,
        std::sync::mpsc::Receiver<ReaderMsg>,
        Arc<JobBudget>,
    ) {
        let (tx, rx) = std::sync::mpsc::sync_channel(cap);
        let jobs = Arc::new(JobBudget::new(crate::READER_JOBS));
        (
            Arc::from([ReaderInbox {
                tx,
                jobs: Arc::clone(&jobs),
            }]),
            rx,
            jobs,
        )
    }

    /// A `Shard` on a tempdir store with one reader inbox of `cap`
    /// slots; the returned receiver is the reader side.
    fn shard_with_reader_cap(
        cap: usize,
    ) -> (
        Shard,
        std::sync::mpsc::Receiver<ReaderMsg>,
        Arc<JobBudget>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path(), &StoreOptions::default()).unwrap());
        let (readers, rx, jobs) = readers(cap);
        (
            Shard::new(
                &store,
                readers,
                Arc::new(AtomicUsize::new(0)),
                0,
                Arc::new(Metrics::new()),
            ),
            rx,
            jobs,
            dir,
        )
    }

    /// Remove(gen1) + Register(gen2) + Activate(gen1) must not flush or
    /// activate the new subscription before its own scan completes.
    #[test]
    fn stale_activate_does_not_flush_new_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path(), &StoreOptions::default()).unwrap());
        let (readers, _reader_rx, _jobs) = readers(8);
        let mut shard = Shard::new(
            &store,
            readers,
            Arc::new(AtomicUsize::new(0)),
            0,
            Arc::new(Metrics::new()),
        );
        let (out, out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        shard.handle(ShardMsg::Register(Box::new(ScanStart {
            conn: 1,
            sub: sub_key("s", 1),
            kind: ScanKind::Req,
            filters: filters(),
            out: out.clone(),
            gate: ReadGate::default(),
            snapshot: 0,
            conn_jobs: Arc::new(JobBudget::new(usize::MAX)),
        })));
        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });
        shard.handle(ShardMsg::Register(Box::new(ScanStart {
            conn: 1,
            sub: sub_key("s", 2),
            kind: ScanKind::Req,
            filters: filters(),
            out,
            gate: ReadGate::default(),
            snapshot: 0,
            conn_jobs: Arc::new(JobBudget::new(usize::MAX)),
        })));
        // The stale generation's scan finished late; Activate is ignored.
        shard.handle(ShardMsg::Activate {
            conn: 1,
            sub: sub_key("s", 1),
        });

        // A live batch must still buffer for gen2, not deliver.
        let batch: crate::channels::Batch = vec![(1u64, event(1, "hi"))];
        shard.handle(ShardMsg::Batch(Arc::new(batch)));
        assert!(
            out_rx.try_recv().is_none(),
            "stale Activate delivered frames to gen2"
        );

        // The real Activate flushes the buffered event.
        shard.handle(ShardMsg::Activate {
            conn: 1,
            sub: sub_key("s", 2),
        });
        match out_rx.try_recv() {
            Some(Out::Event { sub, .. }) => assert_eq!(sub.generation, 2),
            other => panic!("expected buffered Event, got {other:?}"),
        }
    }

    /// `Register` after a `Batch` must send the reader a `Start`
    /// carrying the shard's post-batch `last_seq` as the snapshot.
    #[test]
    fn register_starts_scan_at_current_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path(), &StoreOptions::default()).unwrap());
        let (readers, reader_rx, _jobs) = readers(8);
        let mut shard = Shard::new(
            &store,
            readers,
            Arc::new(AtomicUsize::new(0)),
            0,
            Arc::new(Metrics::new()),
        );
        let (out, _out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        let batch: crate::channels::Batch = vec![(42u64, event(1, "hi"))];
        shard.handle(ShardMsg::Batch(Arc::new(batch)));
        shard.handle(ShardMsg::Register(Box::new(ScanStart {
            conn: 1,
            sub: sub_key("s", 1),
            kind: ScanKind::Req,
            filters: filters(),
            out,
            gate: ReadGate::default(),
            snapshot: 0,
            conn_jobs: Arc::new(JobBudget::new(usize::MAX)),
        })));

        match reader_rx.try_recv() {
            Ok(ReaderMsg::Start { start, .. }) => assert_eq!(start.snapshot, 42),
            other => panic!("expected Start with snapshot 42, got {other:?}"),
        }
    }

    /// A writer on the same env but outside this process — `nosfry
    /// sync` or `import` — commits seqs the shard never sees in a
    /// `Batch`: the snapshot re-read at `Register` makes them
    /// visible to the new REQ's stored scan, and the per-sub
    /// snapshot check keeps the late `Batch` from delivering them
    /// a second time.
    #[test]
    fn foreign_writes_visible_once() {
        use nosfry_core::url::RelayNames;

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path(), &StoreOptions::default()).unwrap());
        let (readers, _reader_rx, _jobs) = readers(8);
        let mut shard = Shard::new(
            &store,
            readers,
            Arc::new(AtomicUsize::new(0)),
            0,
            Arc::new(Metrics::new()),
        );
        // `old` registers before the foreign write: snapshot 0.
        let (out_old, out_old_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));
        shard.handle(req(1, "old", 1, &out_old));
        // A foreign writer commits seq 1 without a `Batch`.
        let foreign = event(1, "foreign");
        store
            .write(&[Arc::clone(&foreign)], &RelayNames::default())
            .unwrap();
        // `new` registers after: its snapshot covers seq 1.
        let (out_new, out_new_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));
        shard.handle(req(2, "new", 1, &out_new));
        // Both subscriptions go live.
        shard.handle(ShardMsg::Activate {
            conn: 1,
            sub: sub_key("old", 1),
        });
        shard.handle(ShardMsg::Activate {
            conn: 2,
            sub: sub_key("new", 1),
        });
        // The foreign seq's `Batch` arrives late, plus a newer one.
        let newer = event(1, "newer");
        let batch: crate::channels::Batch =
            vec![(1, Arc::clone(&foreign)), (2, Arc::clone(&newer))];
        shard.handle(ShardMsg::Batch(Arc::new(batch)));
        // The ephemeral has no seq: both subs take it.
        let eph = event(1, "ephemeral");
        shard.handle(ShardMsg::Ephemeral(Arc::clone(&eph)));
        let mut old_ids = Vec::new();
        while let Some(Out::Event { event, .. }) = out_old_rx.try_recv() {
            old_ids.push(event.id());
        }
        assert_eq!(old_ids, vec![foreign.id(), newer.id(), eph.id()]);
        let mut new_ids = Vec::new();
        while let Some(Out::Event { event, .. }) = out_new_rx.try_recv() {
            new_ids.push(event.id());
        }
        assert_eq!(new_ids, vec![newer.id(), eph.id()]);
    }

    /// `Register` then `Remove` must reach the reader as `Start` then
    /// `Cancel` in that order — the FIFO channel keeps a fast REQ+CLOSE
    /// from spawning a scan after its cancel.
    #[test]
    fn register_then_remove_orders_start_before_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path(), &StoreOptions::default()).unwrap());
        let (readers, reader_rx, _jobs) = readers(8);
        let mut shard = Shard::new(
            &store,
            readers,
            Arc::new(AtomicUsize::new(0)),
            0,
            Arc::new(Metrics::new()),
        );
        let (out, _out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        shard.handle(ShardMsg::Register(Box::new(ScanStart {
            conn: 1,
            sub: sub_key("s", 1),
            kind: ScanKind::Req,
            filters: filters(),
            out,
            gate: ReadGate::default(),
            snapshot: 0,
            conn_jobs: Arc::new(JobBudget::new(usize::MAX)),
        })));
        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });

        match reader_rx.try_recv() {
            Ok(ReaderMsg::Start { start, .. }) if start.conn == 1 => {}
            other => panic!("expected Start first, got {other:?}"),
        }
        match reader_rx.try_recv() {
            Ok(ReaderMsg::Cancel { conn: 1, .. }) => {}
            other => panic!("expected Cancel second, got {other:?}"),
        }
    }

    fn req(conn: u64, sub: &str, generation: u64, out: &Outbound) -> ShardMsg {
        ShardMsg::Register(Box::new(ScanStart {
            conn,
            sub: sub_key(sub, generation),
            kind: ScanKind::Req,
            filters: filters(),
            out: out.clone(),
            gate: ReadGate::default(),
            snapshot: 0,
            conn_jobs: Arc::new(JobBudget::new(usize::MAX)),
        }))
    }

    /// A REQ on an explicit connection budget (the fairness cap).
    fn req_budget(
        conn: u64,
        sub: &str,
        generation: u64,
        out: &Outbound,
        conn_jobs: &Arc<JobBudget>,
    ) -> ShardMsg {
        ShardMsg::Register(Box::new(ScanStart {
            conn,
            sub: sub_key(sub, generation),
            kind: ScanKind::Req,
            filters: filters(),
            out: out.clone(),
            gate: ReadGate::default(),
            snapshot: 0,
            conn_jobs: Arc::clone(conn_jobs),
        }))
    }

    fn shard_with_budget(
        budget: usize,
    ) -> (
        Shard,
        Arc<AtomicUsize>,
        std::sync::mpsc::Receiver<ReaderMsg>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path(), &StoreOptions::default()).unwrap());
        let (readers, reader_rx, _jobs) = readers(8);
        let charge = Arc::new(AtomicUsize::new(0));
        (
            Shard::new(
                &store,
                readers,
                Arc::clone(&charge),
                budget,
                Arc::new(Metrics::new()),
            ),
            charge,
            reader_rx,
            dir,
        )
    }

    /// An over-budget REQ is refused `blocked:` before any state is
    /// built — no monitor, no reader `Start`, no charge — and the
    /// `Remove` its `Out::Closed` triggers is an accounting no-op.
    #[test]
    fn over_budget_register_is_refused() {
        let bytes = Filter::parse("{\"kinds\":[1]}").unwrap().approx_bytes();
        let (mut shard, charge, reader_rx, _dir) = shard_with_budget(bytes - 1);
        let (out, out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        shard.handle(req(1, "s", 1, &out));
        match out_rx.try_recv() {
            Some(Out::Closed { sub, reason }) => {
                assert_eq!(sub.id.as_str(), "s");
                assert_eq!(reason, "blocked: subscription capacity exhausted");
            }
            other => panic!("expected refusal Closed, got {other:?}"),
        }
        assert!(reader_rx.try_recv().is_err(), "no Start for a refused sub");
        assert_eq!(charge.load(Ordering::Relaxed), 0);

        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });
        assert_eq!(charge.load(Ordering::Relaxed), 0);
    }

    /// `Remove`, `RemoveConn`, and a bare re-`Register` each release
    /// the charge exactly once.
    #[test]
    fn subscription_charge_is_released() {
        let bytes = Filter::parse("{\"kinds\":[1]}").unwrap().approx_bytes();
        let (mut shard, charge, _reader_rx, _dir) = shard_with_budget(0);
        let (out, _out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        shard.handle(req(1, "s", 1, &out));
        shard.handle(req(1, "t", 1, &out));
        assert_eq!(charge.load(Ordering::Relaxed), 2 * bytes);

        // A re-REQ of a live id replaces its charge, not doubles it.
        shard.handle(req(1, "s", 2, &out));
        assert_eq!(charge.load(Ordering::Relaxed), 2 * bytes);

        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });
        assert_eq!(charge.load(Ordering::Relaxed), bytes);
        // A second Remove for a gone sub releases nothing.
        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });
        assert_eq!(charge.load(Ordering::Relaxed), bytes);

        shard.handle(ShardMsg::RemoveConn { conn: 1 });
        assert_eq!(charge.load(Ordering::Relaxed), 0);
    }

    /// The pending-buffer overflow close drops the monitor and
    /// releases the charge even if the connection's `Remove` is lost.
    #[test]
    fn overflow_close_releases_the_charge() {
        let (mut shard, charge, _reader_rx, _dir) = shard_with_budget(0);
        let (out, out_rx) = Outbound::new(usize::MAX, Arc::new(AtomicUsize::new(0)));

        shard.handle(req(1, "s", 1, &out));
        // Fill the pending buffer to PENDING_CAP through live batches —
        // an unbounded budget so only the entry cap can trip.
        let ev = event(1, "x");
        for _ in 0..PENDING_CAP {
            shard.handle(ShardMsg::Batch(Arc::new(vec![(1u64, Arc::clone(&ev))])));
        }
        let reserved = out.reserved();
        assert!(reserved > 0, "buffered matches went uncharged");

        let batch: crate::channels::Batch = vec![(1u64, event(1, "hi"))];
        shard.handle(ShardMsg::Batch(Arc::new(batch)));
        match out_rx.try_recv() {
            Some(Out::Closed { reason, .. }) => {
                assert_eq!(reason, "error: subscription fell behind");
            }
            other => panic!("expected overflow Closed, got {other:?}"),
        }
        // The reservations went back; the queue holds only the CLOSED.
        assert_eq!(out.reserved(), 0, "reservations were not returned");
        assert_eq!(charge.load(Ordering::Relaxed), 0);
        // The following Remove stays a no-op.
        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });
        assert_eq!(charge.load(Ordering::Relaxed), 0);
    }

    /// The bytes an `Out::Event` for `ev` under `id` charges —
    /// `accounted_bytes` stated independently so drift between the
    /// reservation and the push shows up here.
    fn event_frame_bytes(id: &str, ev: &Event) -> usize {
        ev.json().len() + SubId::parse(id).unwrap().json().len() + 12
    }

    /// A pending REQ's buffered live matches reserve their
    /// `Out::Event` bytes on the connection's `Outbound` — inside the
    /// per-connection budget and the process total — and the
    /// `Activate` flush leaves exactly the queued frames' charge.
    #[test]
    fn pending_buffer_reserves_outbound_bytes() {
        let (mut shard, _charge, _reader_rx, _dir) = shard_with_budget(0);
        let total = Arc::new(AtomicUsize::new(0));
        let (out, out_rx) = Outbound::new(usize::MAX, Arc::clone(&total));

        shard.handle(req(1, "s", 1, &out));
        let ev = event(1, "hi");
        let bytes = event_frame_bytes("s", &ev);
        shard.handle(ShardMsg::Batch(Arc::new(vec![(1u64, ev)])));
        assert_eq!(out.reserved(), bytes, "buffered match went uncharged");
        assert_eq!(out.pending(), 0, "a reservation is not queued bytes");
        assert_eq!(total.load(Ordering::Relaxed), bytes);

        shard.handle(ShardMsg::Activate {
            conn: 1,
            sub: sub_key("s", 1),
        });
        // Unreserved then re-charged by the push: the same bytes, now
        // a queued frame — after it, no reservation may linger.
        assert_eq!(out.reserved(), 0);
        assert_eq!(out.pending(), bytes);
        assert!(matches!(out_rx.try_recv(), Some(Out::Event { .. })));
        out_rx.written(bytes);
        drop(out_rx);
        assert_eq!(out.pending(), 0);
        assert_eq!(total.load(Ordering::Relaxed), 0);
    }

    /// `Remove` on a pending sub returns its reservations.
    #[test]
    fn remove_unreserves_the_buffer() {
        let (mut shard, _charge, _reader_rx, _dir) = shard_with_budget(0);
        let total = Arc::new(AtomicUsize::new(0));
        let (out, _out_rx) = Outbound::new(usize::MAX, Arc::clone(&total));

        shard.handle(req(1, "s", 1, &out));
        let ev = event(1, "hi");
        shard.handle(ShardMsg::Batch(Arc::new(vec![(1u64, Arc::clone(&ev))])));
        assert_eq!(
            out.reserved(),
            event_frame_bytes("s", &ev),
            "buffered match went uncharged"
        );

        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });
        assert_eq!(out.reserved(), 0, "Remove kept the reservation");
        assert_eq!(total.load(Ordering::Relaxed), 0);
    }

    /// `RemoveConn` returns every pending sub's reservations.
    #[test]
    fn remove_conn_unreserves_the_buffer() {
        let (mut shard, _charge, _reader_rx, _dir) = shard_with_budget(0);
        let total = Arc::new(AtomicUsize::new(0));
        let (out, _out_rx) = Outbound::new(usize::MAX, Arc::clone(&total));

        shard.handle(req(1, "s", 1, &out));
        shard.handle(req(1, "t", 1, &out));
        let ev = event(1, "hi");
        shard.handle(ShardMsg::Batch(Arc::new(vec![(1u64, Arc::clone(&ev))])));
        assert_eq!(
            out.reserved(),
            2 * event_frame_bytes("s", &ev),
            "buffered matches went uncharged"
        );

        shard.handle(ShardMsg::RemoveConn { conn: 1 });
        assert_eq!(out.reserved(), 0, "RemoveConn kept the reservations");
        assert_eq!(total.load(Ordering::Relaxed), 0);
    }

    /// A bare re-`Register` of a pending id releases the old buffer's
    /// reservations; the new generation starts empty.
    #[test]
    fn re_register_unreserves_the_buffer() {
        let (mut shard, _charge, _reader_rx, _dir) = shard_with_budget(0);
        let total = Arc::new(AtomicUsize::new(0));
        let (out, out_rx) = Outbound::new(usize::MAX, Arc::clone(&total));

        shard.handle(req(1, "s", 1, &out));
        let ev = event(1, "hi");
        shard.handle(ShardMsg::Batch(Arc::new(vec![(1u64, Arc::clone(&ev))])));
        let bytes = event_frame_bytes("s", &ev);
        assert_eq!(out.reserved(), bytes);

        shard.handle(req(1, "s", 2, &out));
        assert_eq!(out.reserved(), 0, "re-Register kept the old reservations");
        assert_eq!(total.load(Ordering::Relaxed), 0);

        // Generation 2 buffers and flushes under its own reservation.
        shard.handle(ShardMsg::Batch(Arc::new(vec![(2u64, Arc::clone(&ev))])));
        assert_eq!(out.reserved(), bytes);
        shard.handle(ShardMsg::Activate {
            conn: 1,
            sub: sub_key("s", 2),
        });
        assert!(matches!(
            out_rx.try_recv(),
            Some(Out::Event {
                sub: SubKey { generation: 2, .. },
                ..
            })
        ));
        out_rx.written(bytes);
        drop(out_rx);
        assert_eq!(out.pending(), 0);
    }

    /// Reservations share the connection's byte budget: a burst that
    /// overruns it closes only that sub — `error: subscription fell
    /// behind`, never `is_dead` — and returns every reserved byte.
    #[test]
    fn fell_behind_unreserves_and_keeps_the_connection() {
        let (mut shard, charge, _reader_rx, _dir) = shard_with_budget(0);
        let total = Arc::new(AtomicUsize::new(0));
        let (out, out_rx) = Outbound::new(4096, Arc::clone(&total));

        shard.handle(req(1, "s", 1, &out));
        for _ in 0..30 {
            shard.handle(ShardMsg::Batch(Arc::new(vec![(1u64, event(1, "hi"))])));
        }
        match out_rx.try_recv() {
            Some(Out::Closed { sub, reason }) => {
                assert_eq!(sub.id.as_str(), "s");
                assert_eq!(reason, "error: subscription fell behind");
            }
            other => panic!("expected fell-behind Closed, got {other:?}"),
        }
        assert!(
            !out.is_dead(),
            "a refused reserve must not kill the connection"
        );
        // Every reserved byte came back: only the CLOSED is charged.
        assert_eq!(out.reserved(), 0);
        assert_eq!(out.pending(), total.load(Ordering::Relaxed));
        out_rx.written(out.pending());
        drop(out_rx);
        assert_eq!(out.pending(), 0);
        assert_eq!(total.load(Ordering::Relaxed), 0);
        assert_eq!(charge.load(Ordering::Relaxed), 0);
    }

    /// COUNTs and syncs register scans without touching the
    /// subscription budget.
    #[test]
    fn count_and_neg_are_not_charged() {
        let (mut shard, charge, _reader_rx, _dir) = shard_with_budget(1);
        let (out, _out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        for kind in [ScanKind::Count, ScanKind::Neg { msg: Box::new([1]) }] {
            shard.handle(ShardMsg::Register(Box::new(ScanStart {
                conn: 1,
                sub: sub_key("s", 1),
                kind,
                filters: filters(),
                out: out.clone(),
                gate: ReadGate::default(),
                snapshot: 0,
                conn_jobs: Arc::new(JobBudget::new(usize::MAX)),
            })));
        }
        assert_eq!(charge.load(Ordering::Relaxed), 0);
    }

    /// A `Shard` with one reader inbox pre-filled at `cap` slots plus
    /// its metrics, for the shed-path tests.
    fn busy_shard() -> (
        Shard,
        std::sync::mpsc::Receiver<ReaderMsg>,
        Arc<JobBudget>,
        Arc<Metrics>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path(), &StoreOptions::default()).unwrap());
        // Capacity 1, already occupied by an unrelated message.
        let (readers, rx, jobs) = readers(1);
        readers[0]
            .tx
            .try_send(ReaderMsg::CancelConn { conn: 999 })
            .unwrap();
        let metrics = Arc::new(Metrics::new());
        (
            Shard::new(
                &store,
                readers,
                Arc::new(AtomicUsize::new(0)),
                0,
                Arc::clone(&metrics),
            ),
            rx,
            jobs,
            metrics,
            dir,
        )
    }

    /// A full reader inbox sheds a REQ: `CLOSED rate-limited: relay
    /// busy` on the connection, the monitor/pending/charge undo leaves
    /// nothing registered, and the job slot is returned.
    #[test]
    fn full_reader_inbox_sheds_req() {
        let (mut shard, reader_rx, jobs, _metrics, _dir) = busy_shard();
        let (out, out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        shard.handle(req(1, "s", 1, &out));

        match out_rx.try_recv() {
            Some(Out::Closed { sub, reason }) => {
                assert_eq!(sub.id.as_str(), "s");
                assert_eq!(reason, "rate-limited: relay busy");
            }
            other => panic!("expected shed Closed, got {other:?}"),
        }
        assert_eq!(jobs.jobs.load(Ordering::Relaxed), 0, "the slot is returned");
        let state = &shard.conns[&1];
        assert!(state.pending.is_empty(), "no pending buffer survives");
        assert!(state.sub_bytes.is_empty(), "no charge survives");
        assert_eq!(shard.sub_charge.load(Ordering::Relaxed), 0);
        // The pre-filled message is still the only one in the inbox.
        assert!(matches!(
            reader_rx.try_recv(),
            Ok(ReaderMsg::CancelConn { conn: 999 })
        ));
        assert!(reader_rx.try_recv().is_err());
    }

    /// A full reader inbox sheds COUNT and NEG-OPEN scans too: COUNT
    /// gets the same `CLOSED`, the sync gets a `NEG-ERR`.
    #[test]
    fn full_reader_inbox_sheds_count_and_neg() {
        let (mut shard, _reader_rx, _jobs, _metrics, _dir) = busy_shard();
        let (out, out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        for kind in [ScanKind::Count, ScanKind::Neg { msg: Box::new([1]) }] {
            shard.handle(ShardMsg::Register(Box::new(ScanStart {
                conn: 1,
                sub: sub_key("s", 1),
                kind,
                filters: filters(),
                out: out.clone(),
                gate: ReadGate::default(),
                snapshot: 0,
                conn_jobs: Arc::new(JobBudget::new(usize::MAX)),
            })));
        }

        match out_rx.try_recv() {
            Some(Out::Closed { reason, .. }) => {
                assert_eq!(reason, "rate-limited: relay busy");
            }
            other => panic!("expected shed Closed for COUNT, got {other:?}"),
        }
        match out_rx.try_recv() {
            Some(Out::Neg { text, closes, .. }) => {
                assert_eq!(text, "[\"NEG-ERR\",\"s\",\"rate-limited: relay busy\"]");
                assert!(closes);
            }
            other => panic!("expected shed NEG-ERR, got {other:?}"),
        }
    }

    /// A reader at the job cap sheds a REQ without touching anything:
    /// no `ConnState`, no charge — even on an empty inbox.
    #[test]
    fn reader_job_cap_sheds_before_registering() {
        let (mut shard, _reader_rx, jobs, _dir) = shard_with_reader_cap(8);
        jobs.jobs.store(crate::READER_JOBS, Ordering::Relaxed);
        let (out, out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        shard.handle(req(1, "s", 1, &out));

        match out_rx.try_recv() {
            Some(Out::Closed { reason, .. }) => {
                assert_eq!(reason, "rate-limited: relay busy");
            }
            other => panic!("expected shed Closed, got {other:?}"),
        }
        assert!(shard.conns.is_empty(), "a shed REQ registers nothing");
        assert_eq!(shard.sub_charge.load(Ordering::Relaxed), 0);
    }

    /// A `NEG-MSG` that cannot reach its reader is answered on its own
    /// `out`: a closing `NEG-ERR rate-limited: relay busy`.
    #[test]
    fn full_reader_inbox_sheds_neg_msg() {
        let (mut shard, _reader_rx, _jobs, _metrics, _dir) = busy_shard();
        let (out, out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        shard.handle(ShardMsg::NegMsg(Box::new(crate::channels::NegMsg {
            conn: 1,
            sub: sub_key("n", 1),
            msg: Box::new([0x61]),
            out,
        })));

        match out_rx.try_recv() {
            Some(Out::Neg { text, closes, .. }) => {
                assert_eq!(text, "[\"NEG-ERR\",\"n\",\"rate-limited: relay busy\"]");
                assert!(closes);
            }
            other => panic!("expected shed NEG-ERR, got {other:?}"),
        }
    }

    /// Remove/RemoveConn/NegClose on a full reader inbox are dropped,
    /// not queued — the calls return at once and each drop is counted
    /// under `msg="control"`.
    #[test]
    fn full_reader_inbox_drops_control_messages() {
        let (mut shard, _reader_rx, _jobs, metrics, _dir) = busy_shard();
        let (out, _out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));
        shard.handle(req(1, "s", 1, &out)); // shed; state untouched

        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });
        shard.handle(ShardMsg::RemoveConn { conn: 1 });
        shard.handle(ShardMsg::NegClose {
            conn: 1,
            sub_id: SubId::parse("n").unwrap(),
        });

        assert!(
            metrics
                .render(0, 0, 0, 0, 0)
                .contains("nosfry_reader_busy_total{msg=\"control\"} 3"),
            "{}",
            metrics.render(0, 0, 0, 0, 0)
        );
    }
    /// The per-connection pending-query budget sheds only the
    /// flooding connection: another connection on the same reader is
    /// still admitted, and the conn slot returns when the queued
    /// `Start` drops.
    #[test]
    fn conn_job_cap_sheds_only_that_connection() {
        let (mut shard, reader_rx, _jobs, _dir) = shard_with_reader_cap(8);
        let conn_jobs = Arc::new(JobBudget::new(1));
        let (out1, out_rx1) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        shard.handle(req_budget(1, "s1", 1, &out1, &conn_jobs));
        assert_eq!(conn_jobs.jobs.load(Ordering::Relaxed), 1);

        shard.handle(req_budget(1, "s2", 1, &out1, &conn_jobs));
        match out_rx1.try_recv() {
            Some(Out::Closed { sub, reason }) => {
                assert_eq!(sub.id.as_str(), "s2");
                assert_eq!(reason, "rate-limited: too many pending queries");
            }
            other => panic!("expected shed Closed, got {other:?}"),
        }
        assert_eq!(conn_jobs.jobs.load(Ordering::Relaxed), 1);

        // Another connection on the same reader is still admitted.
        let (out2, _out_rx2) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));
        shard.handle(req(2, "s3", 1, &out2));

        // Dropping conn 1's queued `Start` returns its conn slot.
        match reader_rx.try_recv() {
            Ok(ReaderMsg::Start { start, .. }) => assert_eq!(start.conn, 1),
            other => panic!("expected conn 1's Start, got {other:?}"),
        }
        assert_eq!(conn_jobs.jobs.load(Ordering::Relaxed), 0);
        assert!(matches!(reader_rx.try_recv(), Ok(ReaderMsg::Start { .. })));
    }
}
