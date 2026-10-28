//! Monitor shard thread: the live-subscription inverted index plus the
//! snapshot/pending machinery that makes delivery exactly-once.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nosfry_core::event::Event;
use nosfry_core::filter::Filter;
use nosfry_core::message::SubId;
use nosfry_core::monitor::Monitors;
use nosfry_core::session::SubKey;
use nosfry_lmdb::Store;
use tokio::sync::mpsc;

use crate::channels::{ConnId, Out, Outbound, ReaderMsg, ScanKind, ScanStart, ShardMsg, route};

/// Buffered matches per pending subscription before `CLOSED`.
const PENDING_CAP: usize = 4096;

/// foldhash for the hot-path maps (server-assigned conn ids and client
/// sub ids); randomized seeding keeps `HashDoS` resistance.
type Map<K, V> = HashMap<K, V, foldhash::fast::RandomState>;

fn map<K, V>() -> Map<K, V> {
    Map::with_hasher(foldhash::fast::RandomState::default())
}

/// A subscription registered but not yet activated: its live matches
/// buffer until the stored scan finishes.
#[derive(Debug)]
struct PendingSub {
    /// Generation the pending state belongs to; `Activate` must match.
    generation: u64,
    /// Buffered live matches in arrival order.
    buffer: VecDeque<(SubKey, Arc<Event>)>,
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
    readers: Arc<[std::sync::mpsc::Sender<ReaderMsg>]>,
    /// Process-wide live-subscription byte charge, shared by every
    /// shard (the `nosfry_subscription_bytes` gauge).
    sub_charge: Arc<AtomicUsize>,
    /// `[relay] max_subscription_bytes_total` (`0` = unlimited).
    sub_budget: usize,
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
        store: &Store,
        readers: Arc<[std::sync::mpsc::Sender<ReaderMsg>]>,
        sub_charge: Arc<AtomicUsize>,
        sub_budget: usize,
    ) -> Self {
        Self {
            monitors: Monitors::new(),
            conns: map(),
            readers,
            sub_charge,
            sub_budget,
            last_seq: store.snapshot().unwrap_or(0),
            hits: Vec::new(),
        }
    }

    /// Apply one inbox message.
    fn handle(&mut self, msg: ShardMsg) {
        match msg {
            ShardMsg::Register(mut start) => {
                // The snapshot is assigned before the Start is queued
                // on the reader, so a `Cancel` forwarded later can
                // never overtake it.
                start.snapshot = self.last_seq;
                // A COUNT or sync needs the snapshot but no live
                // machinery: no monitor index, no pending buffer, no
                // budget charge.
                if matches!(start.kind, ScanKind::Req) && !self.register_req(&start) {
                    return;
                }
                drop(route(&self.readers, start.conn).send(ReaderMsg::Start(start)));
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
                    flush(&state.out, pending.buffer);
                }
            }
            ShardMsg::Remove { conn, sub_id } => {
                self.monitors.remove(conn, &sub_id);
                if let Some(state) = self.conns.get_mut(&conn) {
                    state.pending.remove(&sub_id);
                    release_sub(state, &sub_id, &self.sub_charge);
                }
                drop(route(&self.readers, conn).send(ReaderMsg::Cancel { conn, sub_id }));
            }
            ShardMsg::RemoveConn { conn } => {
                self.monitors.remove_connection(conn);
                if let Some(state) = self.conns.remove(&conn) {
                    release(&self.sub_charge, state.sub_bytes.values().sum());
                }
                drop(route(&self.readers, conn).send(ReaderMsg::CancelConn { conn }));
            }
            // Sync control shares the reader with its scan so a
            // `NEG-MSG`/`NEG-CLOSE` cannot overtake the `Start`
            // that created the session.
            ShardMsg::NegMsg(neg) => {
                drop(route(&self.readers, neg.conn).send(ReaderMsg::NegMsg(neg)));
            }
            ShardMsg::NegClose { conn, sub_id } => {
                drop(route(&self.readers, conn).send(ReaderMsg::NegClose { conn, sub_id }));
            }
            ShardMsg::Batch(batch) => {
                for (seq, event) in batch.iter() {
                    self.last_seq = self.last_seq.max(*seq);
                    self.deliver(event);
                }
            }
            ShardMsg::Ephemeral(event) => {
                self.deliver(&event);
            }
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
            });
        // A re-REQ arrives as Remove + Register, but releasing an
        // old charge on insert keeps the accounting right for a
        // bare re-Register too.
        if let Some(old) = state.sub_bytes.insert(start.sub.id.clone(), bytes) {
            release(&self.sub_charge, old);
        }
        state.pending.insert(
            start.sub.id.clone(),
            PendingSub {
                generation: start.sub.generation,
                buffer: VecDeque::new(),
            },
        );
        self.monitors.insert(
            start.conn,
            start.sub.clone(),
            Arc::clone(&start.filters),
            start.gate.clone(),
        );
        true
    }

    /// Match the event against the monitor index and route each hit.
    fn deliver(&mut self, event: &Arc<Event>) {
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
            route_hit(monitors, state, conn, sub, event, sub_charge);
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
    sub_charge: &AtomicUsize,
) {
    let Some(pending) = state.pending.get_mut(&sub.id) else {
        state.out.push(Out::Event {
            sub,
            event: Arc::clone(event),
        });
        return;
    };
    if pending.buffer.len() < PENDING_CAP {
        pending.buffer.push_back((sub, Arc::clone(event)));
        return;
    }
    state.out.push(Out::Closed {
        sub: sub.clone(),
        reason: "error: subscription fell behind".to_owned(),
    });
    state.pending.remove(&sub.id);
    // Release the charge now: the `Remove` the connection sends for
    // this `Out::Closed` may be dropped as stale, and a second
    // release is a no-op on the map anyway.
    if let Some(bytes) = state.sub_bytes.remove(&sub.id) {
        release(sub_charge, bytes);
    }
    monitors.remove(conn, &sub.id);
}

/// Push every buffered live match to the connection.
fn flush(out: &Outbound, buffer: VecDeque<(SubKey, Arc<Event>)>) {
    for (sub, event) in buffer {
        out.push(Out::Event { sub, event });
    }
}

/// Shard thread main loop. `last_seq` starts at the store snapshot —
/// every later seq arrives only via [`ShardMsg::Batch`]. `readers` is
/// the routing table the shard forwards scan control into;
/// `sub_charge`/`sub_budget` are the process-wide live-subscription
/// byte accounting the shards share.
pub(crate) fn run(
    store: &Store,
    mut rx: mpsc::Receiver<ShardMsg>,
    readers: Arc<[std::sync::mpsc::Sender<ReaderMsg>]>,
    sub_charge: Arc<AtomicUsize>,
    sub_budget: usize,
) {
    let mut shard = Shard::new(store, readers, sub_charge, sub_budget);
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
    use crate::channels::{ScanKind, ScanStart};

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

    /// Remove(gen1) + Register(gen2) + Activate(gen1) must not flush or
    /// activate the new subscription before its own scan completes.
    #[test]
    fn stale_activate_does_not_flush_new_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let (reader_tx, _reader_rx) = std::sync::mpsc::channel();
        let mut shard = Shard::new(
            &store,
            Arc::from([reader_tx]),
            Arc::new(AtomicUsize::new(0)),
            0,
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
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let (reader_tx, reader_rx) = std::sync::mpsc::channel();
        let mut shard = Shard::new(
            &store,
            Arc::from([reader_tx]),
            Arc::new(AtomicUsize::new(0)),
            0,
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
        })));

        match reader_rx.try_recv() {
            Ok(ReaderMsg::Start(start)) => assert_eq!(start.snapshot, 42),
            other => panic!("expected Start with snapshot 42, got {other:?}"),
        }
    }

    /// `Register` then `Remove` must reach the reader as `Start` then
    /// `Cancel` in that order — the FIFO channel keeps a fast REQ+CLOSE
    /// from spawning a scan after its cancel.
    #[test]
    fn register_then_remove_orders_start_before_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let (reader_tx, reader_rx) = std::sync::mpsc::channel();
        let mut shard = Shard::new(
            &store,
            Arc::from([reader_tx]),
            Arc::new(AtomicUsize::new(0)),
            0,
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
        })));
        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });

        match reader_rx.try_recv() {
            Ok(ReaderMsg::Start(start)) if start.conn == 1 => {}
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
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        let (reader_tx, reader_rx) = std::sync::mpsc::channel();
        let charge = Arc::new(AtomicUsize::new(0));
        (
            Shard::new(&store, Arc::from([reader_tx]), Arc::clone(&charge), budget),
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
        let (out, out_rx) = Outbound::new(1 << 20, Arc::new(AtomicUsize::new(0)));

        shard.handle(req(1, "s", 1, &out));
        let state = shard.conns.get_mut(&1).unwrap();
        let pending = state.pending.get_mut(&SubId::parse("s").unwrap()).unwrap();
        for _ in 0..PENDING_CAP {
            pending.buffer.push_back((sub_key("s", 1), event(1, "x")));
        }

        let batch: crate::channels::Batch = vec![(1u64, event(1, "hi"))];
        shard.handle(ShardMsg::Batch(Arc::new(batch)));
        match out_rx.try_recv() {
            Some(Out::Closed { reason, .. }) => {
                assert_eq!(reason, "error: subscription fell behind");
            }
            other => panic!("expected overflow Closed, got {other:?}"),
        }
        assert_eq!(charge.load(Ordering::Relaxed), 0);
        // The following Remove stays a no-op.
        shard.handle(ShardMsg::Remove {
            conn: 1,
            sub_id: SubId::parse("s").unwrap(),
        });
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
            })));
        }
        assert_eq!(charge.load(Ordering::Relaxed), 0);
    }
}
