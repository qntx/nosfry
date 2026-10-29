//! The single writer thread: group commits, expiry sweeps, batch broadcast.

use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nosfry_core::message::{RelayVerb, ok_frame};
use nosfry_core::moderation::Moderation;
use nosfry_core::store::WriteOutcome;
use nosfry_lmdb::Store;
use tokio::sync::mpsc;
use tokio::sync::watch;

use crate::Live;
use crate::channels::{Batch, Out, Outbound, ShardMsg, WriteRequest, WriterMsg};
use crate::metrics::{Metrics, StoreOp};

/// Events deleted per expiry sweep; a sweep hitting the cap keeps
/// looping (without blocking on the inbox) until it clears.
const EXPIRE_CAP: usize = 10_000;

/// Expiry timer cadence (strfry's cron interval is ~9 s).
const EXPIRE_INTERVAL: Duration = Duration::from_secs(10);

/// Events deleted per vanish sweep; same backlog semantics as
/// [`EXPIRE_CAP`].
const VANISH_CAP: usize = 10_000;

/// A store commit, shard enqueue, or expiry/vanish sweep slower than this is
/// logged — it stalls every publisher's `OK` while reads keep flowing.
const SLOW_WRITE: Duration = Duration::from_secs(1);

/// Current unix time; `0` before the epoch (never in practice).
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Writer thread main loop: block for the first message, drain every
/// queued publish into one transaction (an `Expire` seen while
/// draining is deferred, not batched), commit once, queue the batch —
/// minus the seqs the same transaction deleted — on every shard, then
/// push each request's `OK` straight onto its connection's outbound
/// queue.
/// After the batch, one expiry sweep runs when pending; a sweep that
/// hits [`EXPIRE_CAP`] keeps the loop in non-blocking mode so large
/// backlogs interleave with publishes instead of starving them.
/// Exits when every sender is dropped.
///
/// Ordering invariant: every shard has the batch queued before any
/// `OK` is sent, so a `REQ` issued after `OK` always snapshots the
/// event (read-your-writes before `EOSE`).
pub(crate) fn run(
    store: &Store,
    mut rx: mpsc::Receiver<WriterMsg>,
    shards: &[mpsc::Sender<ShardMsg>],
    metrics: &Metrics,
    live: &watch::Receiver<Arc<Live>>,
    mod_tx: &watch::Sender<Arc<Moderation>>,
) {
    let mut expire_pending = false;
    let mut expire_backlog = false;
    // Vanish work persisted across a restart resumes on the first
    // loop turn; `backlog` keeps the inbox non-blocking while a step
    // still reports more work.
    let mut vanish_pending = store.vanish_pending().unwrap_or_else(|err| {
        tracing::error!(%err, "vanish queue check failed");
        false
    });
    let mut vanish_backlog = vanish_pending;
    loop {
        let first = if expire_backlog || vanish_backlog {
            match rx.try_recv() {
                Ok(msg) => Some(msg),
                Err(mpsc::error::TryRecvError::Empty) => None,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        } else {
            match rx.blocking_recv() {
                Some(msg) => Some(msg),
                None => break,
            }
        };
        match first {
            Some(WriterMsg::Publish(req)) => {
                let (reqs, moderations) = drain(req, &mut rx, &mut expire_pending);
                vanish_pending |= write_batch(store, reqs, shards, metrics, live);
                for (op, reply) in moderations {
                    moderate(store, op, reply, metrics, mod_tx);
                }
            }
            Some(WriterMsg::Expire) | None => expire_pending = true,
            Some(WriterMsg::Moderate { op, reply }) => {
                moderate(store, op, reply, metrics, mod_tx);
            }
        }
        if expire_pending {
            expire_backlog = expire_sweep(store, metrics);
            expire_pending = expire_backlog;
        }
        if vanish_pending {
            vanish_backlog = vanish_sweep(store, metrics);
            vanish_pending = vanish_backlog;
        }
    }
}

/// One NIP-86 management op. The rebuilt snapshot is published on
/// `mod_tx` *before* the reply goes out — the writer thread is the
/// only publisher, so subscribers always observe snapshots in commit
/// order; the reply only confirms the commit (or the store error)
/// for the waiting HTTP handler.
fn moderate(
    store: &Store,
    op: nosfry_core::moderation::ModOp,
    reply: tokio::sync::oneshot::Sender<Result<(), nosfry_lmdb::StoreError>>,
    metrics: &Metrics,
    mod_tx: &watch::Sender<Arc<Moderation>>,
) {
    match store.moderate(op) {
        Ok(snapshot) => {
            mod_tx.send_replace(Arc::new(snapshot));
            if reply.send(Ok(())).is_err() {
                tracing::debug!("management reply receiver dropped");
            }
        }
        Err(err) => {
            metrics.store_error(StoreOp::Moderate);
            if reply.send(Err(err)).is_err() {
                tracing::debug!("management reply receiver dropped");
            }
        }
    }
}

/// One expiry sweep plus the stale-reader check. `true` means the
/// sweep hit its cap, so the loop keeps polling the inbox
/// non-blockingly and sweeps again.
fn expire_sweep(store: &Store, metrics: &Metrics) -> bool {
    let started = Instant::now();
    let backlog = match store.expire(now(), EXPIRE_CAP) {
        Ok(deleted) => {
            let elapsed = started.elapsed();
            if elapsed > SLOW_WRITE {
                tracing::warn!(
                    elapsed_ms = elapsed.as_millis(),
                    deleted,
                    "slow expiry sweep"
                );
            }
            deleted >= EXPIRE_CAP
        }
        Err(err) => {
            metrics.store_error(StoreOp::Expire);
            tracing::error!(%err, "expiry sweep failed");
            false
        }
    };
    clear_stale_readers(store);
    backlog
}

/// One NIP-62 vanish sweep; `true` means work remains, same contract
/// as [`expire_sweep`].
fn vanish_sweep(store: &Store, metrics: &Metrics) -> bool {
    let started = Instant::now();
    match store.vanish_step(VANISH_CAP) {
        Ok(step) => {
            let elapsed = started.elapsed();
            if elapsed > SLOW_WRITE {
                tracing::warn!(
                    elapsed_ms = elapsed.as_millis(),
                    deleted = step.deleted,
                    "slow vanish sweep"
                );
            }
            step.more
        }
        Err(err) => {
            metrics.store_error(StoreOp::Vanish);
            tracing::error!(%err, "vanish sweep failed");
            false
        }
    }
}

/// `mdb_reader_check`: clear lock-table slots left by readers whose
/// process died mid-transaction (kill -9, `export | head`), which would
/// otherwise pin old pages and grow `data.mdb` without bound.
fn clear_stale_readers(store: &Store) {
    match store.clear_stale_readers() {
        Ok(0) => {}
        Ok(cleared) => tracing::warn!(cleared, "cleared stale LMDB readers"),
        Err(err) => tracing::error!(%err, "stale-reader check failed"),
    }
}

/// Commit one publish batch, queue `Stored` events on every shard,
/// then push each request's `OK`. Events stored and removed inside
/// the same transaction (`Written::deleted`) are never broadcast.
/// Returns `true` when any stored event was a request to vanish, so
/// the run loop schedules a sweep.
fn write_batch(
    store: &Store,
    reqs: Vec<WriteRequest>,
    shards: &[mpsc::Sender<ShardMsg>],
    metrics: &Metrics,
    live: &watch::Receiver<Arc<Live>>,
) -> bool {
    let events: Vec<Arc<nosfry_core::event::Event>> =
        reqs.iter().map(|r| Arc::clone(&r.event)).collect();
    // The service URL re-reads the live config so a reload applies to
    // the next batch (like the write-policy plugin).
    let service_url = live.borrow().limits.auth.relay().cloned();
    let started = Instant::now();
    let written = match store.write(&events, service_url.as_ref()) {
        Ok(written) => written,
        Err(err) => {
            write_failed(reqs, metrics, &err);
            return false;
        }
    };
    let commit_elapsed = started.elapsed();
    if commit_elapsed > SLOW_WRITE {
        tracing::warn!(
            elapsed_ms = commit_elapsed.as_millis(),
            events = events.len(),
            "slow store commit"
        );
    }
    let vanish = written.vanish_pending;
    let (batch, replies) = collect_batch(reqs, written, events);
    enqueue_batch(batch, shards);
    for (out, text) in replies {
        out.push(Out::Frame {
            sub: None,
            verb: RelayVerb::Ok,
            text,
        });
    }
    vanish
}

/// A failed commit: count the error and answer every request
/// `OK false "error: internal error"`.
fn write_failed(reqs: Vec<WriteRequest>, metrics: &Metrics, err: &nosfry_lmdb::StoreError) {
    metrics.store_error(StoreOp::Write);
    tracing::error!(%err, "store write failed");
    for req in reqs {
        req.out.push(Out::Frame {
            sub: None,
            verb: RelayVerb::Ok,
            text: ok_frame(&req.event.id(), false, "error: internal error"),
        });
    }
}

/// Queue the stored batch on every monitor shard (`blocking_send`:
/// the writer applies backpressure instead of dropping events).
fn enqueue_batch(batch: Batch, shards: &[mpsc::Sender<ShardMsg>]) {
    if batch.is_empty() {
        return;
    }
    let batch = Arc::new(batch);
    let started = Instant::now();
    for shard in shards {
        drop(shard.blocking_send(ShardMsg::Batch(Arc::clone(&batch))));
    }
    let elapsed = started.elapsed();
    if elapsed > SLOW_WRITE {
        tracing::warn!(elapsed_ms = elapsed.as_millis(), "slow shard enqueue");
    }
}

/// Split a commit's outcomes into the shard batch (`Stored` events
/// minus the ones the same transaction deleted) and each request's
/// serialized `OK` reply.
fn collect_batch(
    reqs: Vec<WriteRequest>,
    written: nosfry_lmdb::Written,
    events: Vec<Arc<nosfry_core::event::Event>>,
) -> (Batch, Vec<(Outbound, String)>) {
    let mut batch = Vec::new();
    let mut replies = Vec::with_capacity(reqs.len());
    for (req, (outcome, event)) in reqs
        .into_iter()
        .zip(written.outcomes.into_iter().zip(events))
    {
        let (accepted, message) = outcome.ok_reply();
        replies.push((req.out, ok_frame(&event.id(), accepted, message)));
        if let WriteOutcome::Stored { seq } = outcome
            && !written.deleted.contains(&seq)
        {
            batch.push((seq, event));
        }
    }
    (batch, replies)
}

/// The expiry timer: nudge the writer every [`EXPIRE_INTERVAL`]. The
/// blocking `recv_timeout` ends the thread the moment `Server::stop`
/// drops the stop sender; a full writer inbox just skips the tick, a
/// closed one exits. `tx`/`stop_rx` are borrowed: the spawn closure
/// owns them, so the writer's channel closes when this thread exits.
pub(crate) fn expire_timer(tx: &mpsc::Sender<WriterMsg>, stop_rx: &std::sync::mpsc::Receiver<()>) {
    while stop_rx.recv_timeout(EXPIRE_INTERVAL) == Err(RecvTimeoutError::Timeout) {
        match tx.try_send(WriterMsg::Expire) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => break,
        }
    }
}

/// Drain the inbox into one publish batch: `first` plus every publish
/// already queued. The batch has no cap of its own; the inbox bound
/// ([`crate::WRITER_QUEUE`] requests, [`crate::WRITER_QUEUE_BYTES`]
/// of event bytes held until each `OK`) bounds the transaction. On a
/// database larger than RAM a commit costs roughly one write per
/// distinct dirty B-tree page, which grows sublinearly with the batch,
/// so committing the whole backlog at once amortizes it (strfry's
/// writer drains its queue the same way).
///
/// An `Expire` seen while draining is deferred (flagged for the next
/// sweep), `Moderate` requests collect for after the commit, and an
/// empty or closed inbox ends the drain.
fn drain(
    first: WriteRequest,
    rx: &mut mpsc::Receiver<WriterMsg>,
    expire_pending: &mut bool,
) -> (Vec<WriteRequest>, Vec<QueuedModeration>) {
    let mut reqs = vec![first];
    let mut moderations = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        match msg {
            WriterMsg::Publish(next) => reqs.push(next),
            WriterMsg::Expire => *expire_pending = true,
            WriterMsg::Moderate { op, reply } => moderations.push((op, reply)),
        }
    }
    (reqs, moderations)
}

/// One queued management op deferred past the publish commit.
type QueuedModeration = (
    nosfry_core::moderation::ModOp,
    tokio::sync::oneshot::Sender<Result<(), nosfry_lmdb::StoreError>>,
);

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use serde_json::json;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::channels::QueueCharge;

    fn request(keypair: &secp256k1::Keypair, tags: &serde_json::Value) -> WriteRequest {
        let event = nosfry_core::sign::event(keypair, 1, 1_700_000_000, tags, "x");
        let (out, _rx) = Outbound::new(usize::MAX, Arc::new(AtomicUsize::new(0)));
        let charge = QueueCharge {
            budget: Arc::new(Semaphore::new(0)),
            bytes: 0,
        };
        WriteRequest {
            event,
            out,
            _charge: charge,
        }
    }

    /// Twenty thousand queued publishes — past the old 16,384 cap —
    /// drain into one batch; the inbox is the only bound.
    #[test]
    fn drain_takes_past_old_cap() {
        let kp = nosfry_core::sign::key(1);
        let (tx, mut rx) = mpsc::channel(32_768);
        for _ in 0..20_000 {
            tx.try_send(WriterMsg::Publish(request(&kp, &json!([]))))
                .unwrap();
        }
        let mut expire = false;
        let (reqs, mods) = drain(request(&kp, &json!([])), &mut rx, &mut expire);
        assert_eq!(reqs.len(), 20_001);
        assert!(mods.is_empty());
    }

    /// `Expire` and `Moderate` queued between publishes are deferred
    /// and collected while every publish lands in the batch.
    #[test]
    fn drain_defers_expire_and_collects_moderate() {
        let kp = nosfry_core::sign::key(1);
        let (tx, mut rx) = mpsc::channel(64);
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        tx.try_send(WriterMsg::Publish(request(&kp, &json!([]))))
            .unwrap();
        tx.try_send(WriterMsg::Expire).unwrap();
        tx.try_send(WriterMsg::Moderate {
            op: nosfry_core::moderation::ModOp::BanPubkey {
                pubkey: nosfry_core::event::PublicKey(kp.x_only_public_key().0.to_byte_array()),
                reason: None,
            },
            reply: reply_tx,
        })
        .unwrap();
        tx.try_send(WriterMsg::Publish(request(&kp, &json!([]))))
            .unwrap();
        let mut expire = false;
        let (reqs, mods) = drain(request(&kp, &json!([])), &mut rx, &mut expire);
        assert_eq!(reqs.len(), 3);
        assert_eq!(mods.len(), 1);
        assert!(expire);
        assert_eq!(rx.len(), 0);
    }

    /// Dropping a charge returns its bytes to the queue budget.
    #[test]
    fn charge_releases_budget() {
        let budget = Arc::new(Semaphore::new(64 << 20));
        let n = 4_096;
        budget.try_acquire_many(n).unwrap().forget();
        let charge = QueueCharge {
            budget: Arc::clone(&budget),
            bytes: n,
        };
        assert_eq!(budget.available_permits(), (64 << 20) - n as usize);
        drop(charge);
        assert_eq!(budget.available_permits(), 64 << 20);
    }
}
