//! Message types exchanged between the connection tasks and the
//! writer, monitor shard, and reader threads.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use nosfry_core::auth::ReadGate;
use nosfry_core::event::Event;
use nosfry_core::filter::Filter;
use nosfry_core::message::{RelayVerb, SubId};
use nosfry_core::moderation::ModOp;
use nosfry_core::session::SubKey;
use nosfry_lmdb::StoreError;
use tokio::sync::{Semaphore, mpsc, oneshot};

/// Connection identifier; also the shard/reader routing key.
pub(crate) type ConnId = u64;

/// Route `conn` to `conn % slots.len()`.
///
/// Every routing table is built from a `.max(1)` thread count at
/// server startup, so `slots` is never empty and `index` is in bounds.
pub(crate) fn route<T>(slots: &[T], conn: ConnId) -> &T {
    let index = usize::try_from(conn).unwrap_or(usize::MAX) % slots.len().max(1);
    let Some(slot) = slots.get(index) else {
        unreachable!("routing tables are never empty")
    };
    slot
}

/// One committed write batch: `(seq, event)` for `Stored` events only.
pub(crate) type Batch = Vec<(u64, Arc<Event>)>;

/// Inbox item for the writer thread.
#[derive(Debug)]
pub(crate) enum WriterMsg {
    /// A verified event to store.
    Publish(WriteRequest),
    /// Sweep expired events (NIP-40).
    Expire,
    /// Apply a NIP-86 management op (all `mod_*` writes go through
    /// the single writer thread). The writer publishes the rebuilt
    /// snapshot on `mod_tx` *before* replying, so snapshots reach
    /// subscribers in commit order and the reply only confirms the
    /// commit.
    Moderate {
        /// The operation.
        op: ModOp,
        /// Result delivered to the HTTP handler.
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
}

/// A publish's share of the writer queue byte budget, returned to the
/// semaphore when the request is dropped (after its `OK`).
#[derive(Debug)]
pub(crate) struct QueueCharge {
    /// The semaphore the bytes are returned to on drop.
    pub(crate) budget: Arc<Semaphore>,
    /// Permits held.
    pub(crate) bytes: u32,
}

impl QueueCharge {
    /// Wait for `bytes` of `budget`; `None` once the semaphore is closed.
    pub(crate) async fn acquire(budget: &Arc<Semaphore>, bytes: u32) -> Option<Self> {
        budget.acquire_many(bytes).await.ok()?.forget();
        Some(Self {
            budget: Arc::clone(budget),
            bytes,
        })
    }
}

impl Drop for QueueCharge {
    fn drop(&mut self) {
        self.budget
            .add_permits(usize::try_from(self.bytes).unwrap_or(usize::MAX));
    }
}

/// A publish request queued for the single writer thread.
#[derive(Debug)]
pub(crate) struct WriteRequest {
    /// The verified event.
    pub(crate) event: Arc<Event>,
    /// The connection's outbound queue; the writer pushes the `OK`
    /// frame onto it directly (one fewer task wake-up than a reply
    /// channel bouncing through the connection's `select!`). The `OK`
    /// is pushed only after the batch is queued on every shard, so a
    /// `REQ` issued after `OK` always snapshots the event.
    pub(crate) out: Outbound,
    /// The event's share of `WRITER_QUEUE_BYTES`; dropping the request
    /// returns it to the budget, so a publish holds writer-queue bytes
    /// only while it waits in the inbox or rides a commit.
    pub(crate) _charge: QueueCharge,
}

/// Inbox item for a monitor shard thread.
#[derive(Debug)]
pub(crate) enum ShardMsg {
    /// Register a subscription as pending (boxed: it dwarfs the other
    /// variants); the shard fills `snapshot` with the current last seq
    /// — the highest it has already received — and forwards it as
    /// [`ReaderMsg::Start`], so a `Cancel` it forwards later can never
    /// be overtaken by the `Start`.
    Register(Box<ScanStart>),
    /// The historical scan finished: flush the pending buffer and mark
    /// the subscription active.
    Activate {
        /// Owning connection.
        conn: ConnId,
        /// Subscription key.
        sub: SubKey,
    },
    /// Close one subscription.
    Remove {
        /// Owning connection.
        conn: ConnId,
        /// Subscription id.
        sub_id: SubId,
    },
    /// Drop everything belonging to a connection.
    RemoveConn {
        /// The connection.
        conn: ConnId,
    },
    /// A committed write batch to match against live subscriptions.
    /// The writer queues it on every shard before sending any `OK`,
    /// so a `REQ` issued after `OK` always snapshots the event.
    Batch(Arc<Batch>),
    /// An ephemeral event to broadcast (never stored).
    Ephemeral(Arc<Event>),
    /// `NEG-MSG` for an open sync; routed to the same reader as the
    /// `Register` so it cannot overtake the `Start` (boxed: it
    /// dwarfs the other variants).
    NegMsg(Box<NegMsg>),
    /// `NEG-CLOSE` or a session-side sync drop: releases the
    /// reader-side storage.
    NegClose {
        /// Owning connection.
        conn: ConnId,
        /// Sync subscription id.
        sub_id: SubId,
    },
}

/// Inbox item for a reader thread.
#[derive(Debug)]
pub(crate) enum ReaderMsg {
    /// Start a snapshot-bounded scan (boxed: it dwarfs the other variants).
    Start(Box<ScanStart>),
    /// Cancel one scan.
    Cancel {
        /// Owning connection.
        conn: ConnId,
        /// Subscription id.
        sub_id: SubId,
    },
    /// Drop everything belonging to a connection.
    CancelConn {
        /// The connection.
        conn: ConnId,
    },
    /// `NEG-MSG` for an open sync session.
    NegMsg(Box<NegMsg>),
    /// Release one sync session (`NEG-CLOSE`, replace, or relay drop).
    NegClose {
        /// Owning connection.
        conn: ConnId,
        /// Sync subscription id.
        sub_id: SubId,
    },
}

/// What a `Register`/`Start` asks the shard and reader to do.
#[derive(Debug)]
pub(crate) enum ScanKind {
    /// Stored-event scan plus a live monitor (REQ).
    Req,
    /// Stored-event count only (NIP-45 `COUNT`): no monitor, no
    /// pending buffer, no EOSE — one `["COUNT",…]` frame.
    Count,
    /// A record-mode scan then a sealed storage the reader keeps for
    /// `NEG-MSG` reconciliation (NIP-77).
    Neg {
        /// The client's initial `NEG-OPEN` reconcile message.
        msg: Box<[u8]>,
    },
}

/// Arguments for [`ReaderMsg::Start`].
#[derive(Debug)]
pub(crate) struct ScanStart {
    /// Owning connection.
    pub(crate) conn: ConnId,
    /// Subscription key (with generation).
    pub(crate) sub: SubKey,
    /// Which scan the reader runs.
    pub(crate) kind: ScanKind,
    /// Compiled filters.
    pub(crate) filters: Arc<[Filter]>,
    /// Read visibility snapshotted at REQ time.
    pub(crate) gate: ReadGate,
    /// Snapshot seq S assigned by the shard.
    pub(crate) snapshot: u64,
    /// Where results go.
    pub(crate) out: Outbound,
}

/// A `NEG-MSG` forwarded to the reader owning the sync (boxed: it
/// dwarfs the other variants).
#[derive(Debug)]
pub(crate) struct NegMsg {
    /// Owning connection (also selects the reader).
    pub(crate) conn: ConnId,
    /// Sync subscription key (generation included: the reader rejects
    /// messages for a stale session).
    pub(crate) sub: SubKey,
    /// Raw negentropy wire bytes.
    pub(crate) msg: Box<[u8]>,
    /// Where the reply goes (and `NEG-ERR`s on a missing session).
    pub(crate) out: Outbound,
}

/// One outbound item for a connection's write loop.
#[derive(Debug)]
pub(crate) enum Out {
    /// A pre-serialized frame; `sub` carries the generation the
    /// connection checks before writing (`None` always goes out).
    Frame {
        /// Subscription tag for the `is_current` gate.
        sub: Option<SubKey>,
        /// The frame type (for relay-side metrics).
        verb: RelayVerb,
        /// The serialized frame.
        text: String,
    },
    /// A chunk of pre-serialized scan frames for one subscription:
    /// the reader packs a step's emits so the connection wakes once
    /// per chunk instead of once per event.
    Frames {
        /// Subscription key.
        sub: SubKey,
        /// Serialized frames in emit order.
        texts: Vec<String>,
    },
    /// A live match: one shared `Arc` per event, framed into
    /// `["EVENT",sub,json]` by the connection at write time.
    Event {
        /// Subscription key.
        sub: SubKey,
        /// The matched event.
        event: Arc<Event>,
    },
    /// The relay is closing the subscription: the connection closes it
    /// in its session and tears down the scan/monitor when current.
    Closed {
        /// Subscription key.
        sub: SubKey,
        /// The CLOSED reason.
        reason: String,
    },
    /// A finished NIP-45 `COUNT` answer; the connection writes it only
    /// while `is_current` holds, then frees the sub slot.
    Count {
        /// Subscription key.
        sub: SubKey,
        /// The serialized `["COUNT",…]` frame.
        text: String,
    },
    /// A `NEG-MSG`/`NEG-ERR` answer for a sync; `closes` is set on
    /// every `NEG-ERR` because the session drops the sync on error.
    Neg {
        /// Sync subscription key.
        sub: SubKey,
        /// The serialized frame.
        text: String,
        /// The frame closes the sync (`NEG-ERR`).
        closes: bool,
    },
}

impl Out {
    /// Accounted size in bytes for the outbound budget: exact for
    /// `Frame`, the serialized frame's size for `Event` (payload plus
    /// `["EVENT",<sub>,` overhead) and `Closed`.
    #[must_use]
    pub(crate) fn accounted_bytes(&self) -> usize {
        match self {
            Self::Frame { text, .. } | Self::Count { text, .. } | Self::Neg { text, .. } => {
                text.len()
            }
            Self::Frames { texts, .. } => texts.iter().map(String::len).sum(),
            Self::Event { sub, event } => event.json().len() + sub.id.json().len() + 12,
            Self::Closed { sub, reason } => sub.id.json().len() + reason.len() + 14,
        }
    }
}

/// Per-connection outbound queue: unbounded frames plus a bounded byte
/// budget tracked atomically. `total` is the process-wide sum of every
/// connection's `pending`, shared by all `Outbound`s.
#[derive(Debug)]
pub(crate) struct Outbound {
    tx: mpsc::UnboundedSender<Out>,
    pending: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
    dead: Arc<AtomicBool>,
    max_pending: usize,
}

impl Outbound {
    /// New queue; `max_pending` is the byte budget and `total` the
    /// process-wide pending-byte counter shared by every connection.
    #[must_use]
    pub(crate) fn new(max_pending: usize, total: Arc<AtomicUsize>) -> (Self, OutboundRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let pending = Arc::new(AtomicUsize::new(0));
        (
            Self {
                tx,
                pending: Arc::clone(&pending),
                total: Arc::clone(&total),
                dead: Arc::new(AtomicBool::new(false)),
                max_pending,
            },
            OutboundRx { rx, pending, total },
        )
    }

    /// Queue a frame. Pushing pending bytes above `max_pending` marks
    /// the connection dead and drops the frame instead.
    pub(crate) fn push(&self, out: Out) {
        let len = out.accounted_bytes();
        let prev = self.pending.fetch_add(len, Ordering::Relaxed);
        self.total.fetch_add(len, Ordering::Relaxed);
        if prev + len > self.max_pending {
            self.pending.fetch_sub(len, Ordering::Relaxed);
            self.total.fetch_sub(len, Ordering::Relaxed);
            self.dead.store(true, Ordering::Relaxed);
            return;
        }
        if self.tx.send(out).is_err() {
            self.pending.fetch_sub(len, Ordering::Relaxed);
            self.total.fetch_sub(len, Ordering::Relaxed);
        }
    }

    /// Pending outbound bytes.
    #[must_use]
    pub(crate) fn pending(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    /// Process-wide pending outbound bytes (every connection's
    /// `pending` summed).
    #[must_use]
    pub(crate) fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    /// The byte budget was exceeded; the connection should close.
    #[must_use]
    pub(crate) fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }
}

impl Clone for Outbound {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            pending: Arc::clone(&self.pending),
            total: Arc::clone(&self.total),
            dead: Arc::clone(&self.dead),
            max_pending: self.max_pending,
        }
    }
}

/// Receiving end of an [`Outbound`] queue; owns the consumer-side byte
/// accounting. `written` releases the bytes of frames popped for the
/// socket, and dropping releases every byte still queued so a closed
/// connection never leaves its `pending` charged into `total`.
#[derive(Debug)]
pub(crate) struct OutboundRx {
    rx: mpsc::UnboundedReceiver<Out>,
    pending: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
}

impl OutboundRx {
    /// Next queued frame; `None` once every `Outbound` sender dropped.
    pub(crate) async fn recv(&mut self) -> Option<Out> {
        self.rx.recv().await
    }

    /// Next queued frame without waiting.
    pub(crate) fn try_recv(&mut self) -> Result<Out, mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }

    /// Next queued frame, blocking the calling thread (tests only).
    #[cfg(test)]
    pub(crate) fn blocking_recv(&mut self) -> Option<Out> {
        self.rx.blocking_recv()
    }

    /// Release the bytes of frames removed from the queue (written to
    /// the socket or dropped mid-batch).
    pub(crate) fn written(&self, bytes: usize) {
        self.pending.fetch_sub(bytes, Ordering::Relaxed);
        self.total.fetch_sub(bytes, Ordering::Relaxed);
    }
}

impl Drop for OutboundRx {
    fn drop(&mut self) {
        // Close first: a `push` racing the drop fails its `send` and
        // subtracts the bytes it charged. Every frame that made it in
        // before the close is still queued, so draining afterwards
        // releases exactly the remaining charge — nothing can arrive
        // after `close` that the drain would miss.
        self.rx.close();
        while let Ok(out) = self.rx.try_recv() {
            let len = out.accounted_bytes();
            self.pending.fetch_sub(len, Ordering::Relaxed);
            self.total.fetch_sub(len, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(bytes: usize) -> Out {
        Out::Frame {
            sub: None,
            verb: RelayVerb::Notice,
            text: "x".repeat(bytes),
        }
    }

    /// Frames still queued when the consumer drops release both the
    /// per-connection `pending` and the process-wide `total`.
    #[test]
    fn dropping_the_receiver_releases_queued_bytes() {
        let total = Arc::new(AtomicUsize::new(0));
        let (out, rx) = Outbound::new(usize::MAX, Arc::clone(&total));
        out.push(frame(100));
        out.push(frame(200));
        assert_eq!(out.pending(), 300);
        assert_eq!(out.total(), 300);
        drop(rx);
        assert_eq!(out.pending(), 0);
        assert_eq!(out.total(), 0);
    }

    /// A `push` racing a dropped receiver fails its `send` and
    /// subtracts the bytes it charged.
    #[test]
    fn push_after_receiver_drop_charges_nothing() {
        let total = Arc::new(AtomicUsize::new(0));
        let (out, rx) = Outbound::new(usize::MAX, Arc::clone(&total));
        drop(rx);
        out.push(frame(100));
        assert_eq!(out.pending(), 0);
        assert_eq!(out.total(), 0);
    }

    /// `written` releases exactly the received frame's bytes.
    #[test]
    fn written_releases_only_the_received_frame() {
        let total = Arc::new(AtomicUsize::new(0));
        let (out, mut rx) = Outbound::new(usize::MAX, Arc::clone(&total));
        out.push(frame(100));
        out.push(frame(200));
        let first = rx.blocking_recv().unwrap();
        rx.written(first.accounted_bytes());
        assert_eq!(out.pending(), 200);
        assert_eq!(out.total(), 200);
    }
}
