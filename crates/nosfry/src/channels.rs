//! Message types exchanged between the connection tasks and the
//! writer, monitor shard, and reader threads.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;

use futures_util::task::AtomicWaker;
use nosfry_core::auth::ReadGate;
use nosfry_core::event::Event;
use nosfry_core::filter::Filter;
use nosfry_core::message::{RelayVerb, SubId};
use nosfry_core::moderation::ModOp;
use nosfry_core::session::SubKey;
use nosfry_lmdb::StoreError;
use tokio::sync::{Semaphore, oneshot};

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

/// The [`Outbound`] queue's mutex payload: the frames themselves and
/// whether the receiver is gone. The lock orders `closed` inside
/// `push` against `Drop for OutboundRx` so a racing push either lands
/// before close and is drained, or sees `closed` and releases itself.
#[derive(Debug)]
struct Queue {
    /// Queued frames, oldest first.
    items: VecDeque<Out>,
    /// `OutboundRx` dropped; pushes release their charge immediately.
    closed: bool,
}

impl Queue {
    /// A burst grew this deque far past idle size; once drained, swap
    /// in a fresh one so the buffer goes back to the allocator.
    fn shrink(&mut self) {
        if self.items.is_empty() && self.items.capacity() > 64 {
            self.items = VecDeque::new();
        }
    }
}

/// Shared state of one connection's [`Outbound`]/[`OutboundRx`] pair.
/// A few words per idle connection where the previous channel kept an
/// eager buffer block plus channel state (~2.4 KiB).
#[derive(Debug)]
struct Shared {
    /// Queued frames and the closed flag.
    queue: Mutex<Queue>,
    /// A `recv` parked on an empty queue; `push` and the last sender
    /// `Drop` wake it.
    waker: AtomicWaker,
    /// Bytes queued on this connection.
    pending: AtomicUsize,
    /// Byte budget exceeded; the connection should close.
    dead: AtomicBool,
    /// Live `Outbound` clones; `recv` returns `None` once it hits 0.
    senders: AtomicUsize,
    /// The byte budget.
    max_pending: usize,
}

/// Per-connection outbound queue: unbounded frames plus a bounded byte
/// budget tracked atomically. `total` is the process-wide sum of every
/// connection's `pending`, shared by all `Outbound`s.
#[derive(Debug)]
pub(crate) struct Outbound {
    shared: Arc<Shared>,
    total: Arc<AtomicUsize>,
}

impl Outbound {
    /// New queue; `max_pending` is the byte budget and `total` the
    /// process-wide pending-byte counter shared by every connection.
    #[must_use]
    pub(crate) fn new(max_pending: usize, total: Arc<AtomicUsize>) -> (Self, OutboundRx) {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                items: VecDeque::new(),
                closed: false,
            }),
            waker: AtomicWaker::new(),
            pending: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
            senders: AtomicUsize::new(1),
            max_pending,
        });
        (
            Self {
                shared: Arc::clone(&shared),
                total: Arc::clone(&total),
            },
            OutboundRx { shared, total },
        )
    }

    /// Queue a frame. Pushing pending bytes above `max_pending` marks
    /// the connection dead and drops the frame instead.
    pub(crate) fn push(&self, out: Out) {
        let len = out.accounted_bytes();
        let prev = self.shared.pending.fetch_add(len, Ordering::Relaxed);
        self.total.fetch_add(len, Ordering::Relaxed);
        if prev + len > self.shared.max_pending {
            self.release(len);
            self.shared.dead.store(true, Ordering::Relaxed);
            return;
        }
        {
            let mut queue = self.lock_queue();
            if queue.closed {
                self.release(len);
                return;
            }
            queue.items.push_back(out);
        }
        self.shared.waker.wake();
    }

    /// Undo a charge that never made it into the queue.
    fn release(&self, len: usize) {
        self.shared.pending.fetch_sub(len, Ordering::Relaxed);
        self.total.fetch_sub(len, Ordering::Relaxed);
    }

    /// Lock the shared queue, ignoring poisoning (a panicked holder
    /// left at most a dropped frame behind).
    fn lock_queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.shared
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Pending outbound bytes.
    #[must_use]
    pub(crate) fn pending(&self) -> usize {
        self.shared.pending.load(Ordering::Relaxed)
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
        self.shared.dead.load(Ordering::Relaxed)
    }
}

impl Clone for Outbound {
    fn clone(&self) -> Self {
        self.shared.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
            total: Arc::clone(&self.total),
        }
    }
}

impl Drop for Outbound {
    fn drop(&mut self) {
        // The last sender wakes a parked `recv` so it observes the
        // empty `senders` count and returns `None`.
        if self.shared.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.waker.wake();
        }
    }
}

/// Receiving end of an [`Outbound`] queue; owns the consumer-side byte
/// accounting. `written` releases the bytes of frames popped for the
/// socket, and dropping releases every byte still queued so a closed
/// connection never leaves its `pending` charged into `total`.
#[derive(Debug)]
pub(crate) struct OutboundRx {
    shared: Arc<Shared>,
    total: Arc<AtomicUsize>,
}

impl OutboundRx {
    /// Next queued frame; `None` once every `Outbound` sender dropped.
    /// Cancel-safe: the waker registers before the queue is checked,
    /// so a push between check and park still wakes the next poll.
    pub(crate) async fn recv(&self) -> Option<Out> {
        std::future::poll_fn(|cx| {
            self.shared.waker.register(cx.waker());
            if let Some(out) = self.pop() {
                return Poll::Ready(Some(out));
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                // A push before the AcqRel decrement is visible here;
                // without this re-pop a last-sender push-then-drop
                // would lose the frame.
                return Poll::Ready(self.pop());
            }
            Poll::Pending
        })
        .await
    }

    /// Next queued frame without waiting (tests only; production
    /// drains through [`OutboundRx::take_into`]).
    #[cfg(test)]
    pub(crate) fn try_recv(&self) -> Option<Out> {
        self.pop()
    }

    /// Move frames into `batch` under one lock: at most until `batch`
    /// holds `max_frames` or accumulates `max_bytes` accounted bytes.
    /// `bytes` sums the moved charge, released later via `written`.
    pub(crate) fn take_into(
        &self,
        batch: &mut VecDeque<Out>,
        max_frames: usize,
        max_bytes: usize,
        bytes: &mut usize,
    ) {
        let mut queue = self.lock_queue();
        while batch.len() < max_frames && *bytes < max_bytes {
            let Some(out) = queue.items.pop_front() else {
                break;
            };
            *bytes += out.accounted_bytes();
            batch.push_back(out);
        }
        queue.shrink();
    }

    /// Pop one frame and shrink a burst-grown empty queue.
    fn pop(&self) -> Option<Out> {
        let mut queue = self.lock_queue();
        let out = queue.items.pop_front();
        queue.shrink();
        out
    }

    /// Lock the shared queue; see [`Outbound::lock_queue`].
    fn lock_queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.shared
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Next queued frame, blocking the calling thread (tests only).
    #[cfg(test)]
    pub(crate) fn blocking_recv(&self) -> Option<Out> {
        loop {
            if let out @ Some(_) = self.try_recv() {
                return out;
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                // Same re-pop as `recv`: a push before the decrement
                // is still in the queue.
                return self.try_recv();
            }
            std::thread::yield_now();
        }
    }

    /// Release the bytes of frames removed from the queue (written to
    /// the socket or dropped mid-batch).
    pub(crate) fn written(&self, bytes: usize) {
        self.shared.pending.fetch_sub(bytes, Ordering::Relaxed);
        self.total.fetch_sub(bytes, Ordering::Relaxed);
    }
}

impl Drop for OutboundRx {
    fn drop(&mut self) {
        // Close first: a `push` racing the drop sees `closed` under
        // the same lock and releases the bytes it charged. Every
        // frame that made it in before the close is still queued, so
        // draining afterwards releases exactly the remaining charge —
        // nothing can arrive after `closed` that the drain would miss.
        let mut queue = self.lock_queue();
        queue.closed = true;
        for out in queue.items.drain(..) {
            let len = out.accounted_bytes();
            self.shared.pending.fetch_sub(len, Ordering::Relaxed);
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

    /// `recv` returns `None` once the last `Outbound` clone drops.
    #[test]
    fn recv_ends_after_last_sender_drops() {
        use std::task::{Context, Waker};

        let (out, rx) = Outbound::new(usize::MAX, Arc::new(AtomicUsize::new(0)));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = Box::pin(rx.recv());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        drop(out);
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Ready(None)));
    }

    /// A push that lands before the last sender drops is delivered
    /// even when `recv` first polls after the drop: the senders-0
    /// path re-pops instead of losing the frame.
    #[test]
    fn recv_delivers_final_push_after_sender_drops() {
        use std::task::{Context, Waker};

        let (out, rx) = Outbound::new(usize::MAX, Arc::new(AtomicUsize::new(0)));
        out.push(frame(9));
        drop(out);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = Box::pin(rx.recv());
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Ready(Some(_))));
        let mut next = Box::pin(rx.recv());
        assert!(matches!(next.as_mut().poll(&mut cx), Poll::Ready(None)));
    }

    /// A `push` from another thread wakes a `recv` parked on an empty
    /// queue.
    #[test]
    fn push_wakes_pending_recv() {
        use std::task::{Context, Wake, Waker};

        struct Flag(AtomicBool);
        impl Wake for Flag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let (out, rx) = Outbound::new(usize::MAX, Arc::new(AtomicUsize::new(0)));
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        std::thread::spawn(move || out.push(frame(7)))
            .join()
            .unwrap();
        assert!(flag.0.load(Ordering::SeqCst), "push did not wake recv");
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Ready(Some(_))));
    }

    /// Draining a large burst returns the grown `VecDeque` capacity.
    #[test]
    fn drained_burst_releases_queue_capacity() {
        let (out, rx) = Outbound::new(usize::MAX, Arc::new(AtomicUsize::new(0)));
        for _ in 0..1_000 {
            out.push(frame(100));
        }
        while rx.try_recv().is_some() {}
        let cap = rx.lock_queue().items.capacity();
        assert_eq!(cap, 0, "burst capacity not returned: {cap}");
    }

    /// `take_into` stops at the frame count and at the byte cap.
    #[test]
    fn take_into_respects_both_limits() {
        let (out, rx) = Outbound::new(usize::MAX, Arc::new(AtomicUsize::new(0)));
        for _ in 0..10 {
            out.push(frame(100));
        }
        let mut batch = VecDeque::new();
        let mut bytes = 0usize;
        rx.take_into(&mut batch, 3, usize::MAX, &mut bytes);
        assert_eq!(batch.len(), 3, "frame limit");
        rx.take_into(&mut batch, usize::MAX, bytes, &mut bytes);
        assert_eq!(batch.len(), 3, "byte limit");
        rx.take_into(&mut batch, usize::MAX, usize::MAX, &mut bytes);
        assert_eq!(batch.len(), 10, "remainder");
    }

    /// `written` releases exactly the received frame's bytes.
    #[test]
    fn written_releases_only_the_received_frame() {
        let total = Arc::new(AtomicUsize::new(0));
        let (out, rx) = Outbound::new(usize::MAX, Arc::clone(&total));
        out.push(frame(100));
        out.push(frame(200));
        let first = rx.blocking_recv().unwrap();
        rx.written(first.accounted_bytes());
        assert_eq!(out.pending(), 200);
        assert_eq!(out.total(), 200);
    }
}
