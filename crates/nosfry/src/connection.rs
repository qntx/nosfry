//! One connection task per WebSocket: owns the `nosfry_core::session::Session`
//! and bridges it to the writer and its monitor shard (which forwards
//! scan control to the reader).

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::SinkExt;
use futures_util::stream::StreamExt;
use nosfry_core::auth::{AUTH_KIND, ReadGate};
use nosfry_core::event::PublicKey;
use nosfry_core::filter::Filter;
use nosfry_core::limits::AddressBuckets;
use nosfry_core::message::{RelayVerb, SubId, closed_frame, event_frame, notice_frame, ok_frame};
use nosfry_core::moderation::Moderation;
use nosfry_core::policy::Decision;
use nosfry_core::session::{Command, Session, SubKey};
use tokio::sync::{mpsc, watch};
use yawc::close::CloseCode;
use yawc::{Frame, HttpWebSocket, OpCode};

use crate::channels::{
    ConnId, Out, Outbound, OutboundRx, QueueCharge, ScanKind, ScanStart, ShardMsg, WriteRequest,
    WriterMsg, route,
};
use crate::metrics::{EventOutcome, Metrics};

/// Per-connection state handed down from the server.
#[derive(Debug, Clone)]
pub(crate) struct Handle {
    /// Writer inbox.
    pub(crate) writer: mpsc::Sender<WriterMsg>,
    /// Shared writer-inbox byte budget (`WRITER_QUEUE_BYTES`); a
    /// publish acquires its event's JSON size before queueing.
    pub(crate) writer_budget: Arc<tokio::sync::Semaphore>,
    /// Monitor shard inboxes, indexed by `conn % shards.len()`; the
    /// shard owns the reader routing for scans.
    pub(crate) shards: Arc<[mpsc::Sender<ShardMsg>]>,
    /// Live-reloadable state: limits/outbound budget are read once
    /// per connection, the write policy at every publish.
    pub(crate) live: watch::Receiver<Arc<crate::Live>>,
    /// Latest NIP-86 snapshot; cloned per publish, never borrowed
    /// across an `.await`.
    pub(crate) moderation: watch::Receiver<Arc<Moderation>>,
    /// Process-wide counters.
    pub(crate) metrics: Arc<Metrics>,
    /// Process-wide pending outbound bytes shared by every `Outbound`.
    pub(crate) outbound_total: Arc<AtomicUsize>,
    /// Broadcast shutdown signal.
    pub(crate) shutdown: watch::Receiver<bool>,
    /// Tracks every live connection task for the shutdown deadline.
    pub(crate) tracker: tokio_util::task::TaskTracker,
}

/// Global connection counter.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// Allocate the connection id. Called where the `conn` span is
/// created (http.rs `websocket`) so span, shard routing, and reader
/// logs share the id.
pub(crate) fn next_conn_id() -> ConnId {
    NEXT_CONN.fetch_add(1, Ordering::Relaxed)
}

/// Frames batched into one socket flush after the first `Out` arrives.
const BATCH_MAX_FRAMES: usize = 64;
/// Byte cap for one batched flush.
const BATCH_MAX_BYTES: usize = 256 * 1024;
/// How long a best-effort close frame may block the shutdown path.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

/// A batched socket write that failed.
#[derive(Debug)]
enum WriteError {
    /// `feed`/`flush` returned a socket error.
    Socket(yawc::WebSocketError),
    /// The batch exceeded its deadline.
    Stalled,
}

/// One connection's runtime state.
struct Connection<'a> {
    /// Connection id; the shard routing key.
    conn: ConnId,
    /// The client's IP address (for the write-policy plugin).
    peer: IpAddr,
    /// Server-wide state.
    handle: &'a Handle,
    /// This connection's monitor shard (register/remove plus the scan
    /// control the shard forwards to the reader).
    shard: mpsc::Sender<ShardMsg>,
    /// Protocol state machine.
    session: Session,
    /// This connection's outbound queue.
    out: Outbound,
    /// Ping interval, fixed at connect time.
    ping_interval: Duration,
    /// Reusable drained-batch buffer (`VecDeque` keeps FIFO order and
    /// its capacity across batches without a `drain` loop).
    batch: VecDeque<Out>,
}

impl<'a> Connection<'a> {
    /// `None` when the per-connection NIP-42 challenge cannot be
    /// generated — the connection ends without a close frame.
    /// `address` carries the rate-limit buckets shared with every
    /// other connection of this client address.
    fn new(
        handle: &'a Handle,
        conn: ConnId,
        peer: IpAddr,
        address: Arc<AddressBuckets>,
    ) -> Option<(Self, OutboundRx)> {
        // Limits and the outbound budget are fixed at connect time;
        // reloads apply to the next connection.
        let live = handle.live.borrow().clone();
        let mut challenge = [0u8; 16];
        if let Err(err) = getrandom::fill(&mut challenge) {
            tracing::error!(%err, "cannot generate an AUTH challenge");
            tracing::debug!(
                target: "nosfry::conn",
                reason = "auth challenge unavailable",
                "connection closed"
            );
            return None;
        }
        let (out, out_rx) = Outbound::new(
            live.config.relay.max_pending_outbound_bytes,
            Arc::clone(&handle.outbound_total),
        );
        Some((
            Self {
                conn,
                peer,
                handle,
                shard: route(&handle.shards, conn).clone(),
                session: Session::new(
                    Arc::clone(&live.limits),
                    faster_hex::hex_string(&challenge),
                    address,
                ),
                out,
                ping_interval: Duration::from_secs(live.config.relay.auto_ping_seconds),
                batch: VecDeque::new(),
            },
            out_rx,
        ))
    }

    /// Handle one inbound frame; `false` means the connection ends.
    async fn inbound(
        &mut self,
        ws: &mut HttpWebSocket,
        frame: Option<Frame>,
        last_inbound: &mut Instant,
    ) -> bool {
        let Some(frame) = frame else {
            return false;
        };
        *last_inbound = Instant::now();
        match frame.opcode() {
            OpCode::Ping => return self.pong(ws).await,
            OpCode::Text => {
                let Ok(text) = std::str::from_utf8(frame.payload()) else {
                    self.out.push(Out::Frame {
                        sub: None,
                        verb: RelayVerb::Notice,
                        text: notice_frame("invalid: malformed utf-8"),
                    });
                    return true;
                };
                tracing::trace!(
                    target: "nosfry::inbound",
                    msg = text,
                    "inbound message"
                );
                let mut commands = Vec::new();
                let received = self.session.on_text(now_ms(), text, &mut commands);
                if let Some(verb) = received.verb {
                    self.handle.metrics.client_message(verb);
                }
                if received.rate_limited
                    && let Some(verb) = received.verb
                {
                    self.handle.metrics.rate_limited(verb);
                }
                for cmd in commands {
                    self.command(cmd).await;
                }
            }
            OpCode::Binary => self.out.push(Out::Frame {
                sub: None,
                verb: RelayVerb::Notice,
                text: notice_frame("invalid: binary frames are not supported"),
            }),
            OpCode::Close => return false,
            _ => {}
        }
        true
    }

    /// Flush yawc's queued pong for an inbound ping under the batch
    /// write deadline. `Sink::poll_ready` drains `obligated_sends`
    /// (`poll_flush` does not), so the queue never holds more than one
    /// flush; `false` means the connection ends.
    async fn pong(&self, ws: &mut HttpWebSocket) -> bool {
        let flushed = tokio::time::timeout(
            self.ping_interval,
            futures_util::future::poll_fn(|cx| {
                futures_util::Sink::poll_ready(std::pin::Pin::new(&mut *ws), cx)
            }),
        )
        .await;
        match flushed {
            Ok(Ok(())) => true,
            Ok(Err(err)) => {
                tracing::debug!(%err, "pong write failed");
                false
            }
            Err(_) => {
                tracing::debug!("pong write stalled");
                false
            }
        }
    }

    /// Execute one session command.
    async fn command(&self, cmd: Command) {
        match cmd {
            Command::Publish { event, authed } => self.publish(event, authed).await,
            Command::Subscribe { sub, filters, gate } => {
                self.subscribe(sub, filters, gate, ScanKind::Req).await;
            }
            Command::Count { sub, filters, gate } => {
                self.subscribe(sub, filters, gate, ScanKind::Count).await;
            }
            Command::NegOpen {
                sub,
                filters,
                gate,
                msg,
            } => {
                self.subscribe(sub, filters, gate, ScanKind::Neg { msg })
                    .await;
            }
            Command::NegMsg { sub, msg } => {
                // The shard routes it to the same reader as the
                // sync's `Start`, so it cannot overtake it.
                drop(
                    self.shard
                        .send(ShardMsg::NegMsg(Box::new(crate::channels::NegMsg {
                            conn: self.conn,
                            sub,
                            msg,
                            out: self.out.clone(),
                        })))
                        .await,
                );
            }
            Command::NegClose { sub_id } => {
                drop(
                    self.shard
                        .send(ShardMsg::NegClose {
                            conn: self.conn,
                            sub_id,
                        })
                        .await,
                );
            }
            Command::Unsubscribe { sub_id } => self.unsubscribe(sub_id).await,
            Command::Send { verb, text } => {
                self.out.push(Out::Frame {
                    sub: None,
                    verb,
                    text,
                });
            }
        }
    }

    /// NIP-86 publish gate, checked before the write-policy plugin
    /// and covering ephemeral events: banned authors/ids/kinds get a
    /// `blocked:` `OK`. AUTH events and requests to vanish naming this
    /// relay are exempt — a banned author may still vanish.
    fn moderation_allows(&self, event: &nosfry_core::event::Event) -> bool {
        if event.kind() == AUTH_KIND
            || event.requests_vanish(self.handle.live.borrow().limits.auth.relay())
        {
            return true;
        }
        let Some(reason) = self.handle.moderation.borrow().blocked_reason(event) else {
            return true;
        };
        self.handle.metrics.event_outcome(EventOutcome::Moderated);
        self.out.push(Out::Frame {
            sub: None,
            verb: RelayVerb::Ok,
            text: ok_frame(&event.id(), false, reason),
        });
        false
    }

    /// Ask the write-policy plugin and answer the client when it
    /// vetoes. `false` means the event stops here: `reject` answers
    /// `OK false` (`blocked: rejected by write policy` when the plugin
    /// leaves `msg` empty; strfry would send a bare empty message),
    /// `shadowReject` answers `OK true` without storing or
    /// broadcasting.
    async fn policy_accepts(
        &self,
        event: &nosfry_core::event::Event,
        authed: Option<PublicKey>,
    ) -> bool {
        // The policy is re-read per event so a config reload takes
        // effect on the next publish on every connection.
        let live = self.handle.live.borrow().clone();
        // NIP-62: a request to vanish naming this relay must not be
        // filtered by the write policy (restricted relays MUST comply).
        if event.requests_vanish(live.limits.auth.relay()) {
            return true;
        }
        let Some(policy) = &live.policy else {
            return true;
        };
        let (ok, message) = match policy.check(event, self.peer, authed).await {
            Decision::Accept => return true,
            Decision::Reject(m) if m.is_empty() => {
                (false, "blocked: rejected by write policy".to_owned())
            }
            Decision::Reject(m) => (false, m),
            Decision::ShadowReject(m) => (true, m),
        };
        self.handle.metrics.event_outcome(EventOutcome::Policy);
        self.out.push(Out::Frame {
            sub: None,
            verb: RelayVerb::Ok,
            text: ok_frame(&event.id(), ok, &message),
        });
        false
    }

    /// Run the NIP-86 moderation snapshot and the write-policy plugin
    /// (when configured), then broadcast an ephemeral event or queue a
    /// stored write; the writer pushes the `OK` onto this connection's
    /// `Outbound` itself.
    async fn publish(&self, event: Arc<nosfry_core::event::Event>, authed: Option<PublicKey>) {
        if !self.moderation_allows(&event) {
            return;
        }
        if !self.policy_accepts(&event, authed).await {
            return;
        }
        if event.kind().is_ephemeral() {
            self.broadcast(&event).await;
            self.handle.metrics.event_outcome(EventOutcome::Ephemeral);
            self.out.push(Out::Frame {
                sub: None,
                verb: RelayVerb::Ok,
                text: ok_frame(&event.id(), true, ""),
            });
            return;
        }
        let id = event.id();
        let bytes = u32::try_from(event.json().len().clamp(1, crate::WRITER_QUEUE_BYTES))
            .unwrap_or(u32::MAX);
        let Some(charge) = QueueCharge::acquire(&self.handle.writer_budget, bytes).await else {
            self.handle.metrics.event_outcome(EventOutcome::Error);
            self.out.push(Out::Frame {
                sub: None,
                verb: RelayVerb::Ok,
                text: ok_frame(&id, false, "error: internal error"),
            });
            return;
        };
        if self
            .handle
            .writer
            .send(WriterMsg::Publish(WriteRequest {
                event,
                out: self.out.clone(),
                _charge: charge,
            }))
            .await
            .is_err()
        {
            self.handle.metrics.event_outcome(EventOutcome::Error);
            self.out.push(Out::Frame {
                sub: None,
                verb: RelayVerb::Ok,
                text: ok_frame(&id, false, "error: internal error"),
            });
        }
    }

    /// Fan an ephemeral event out to every monitor shard.
    async fn broadcast(&self, event: &Arc<nosfry_core::event::Event>) {
        for shard in self.handle.shards.iter() {
            if shard
                .send(ShardMsg::Ephemeral(Arc::clone(event)))
                .await
                .is_err()
            {
                break;
            }
        }
    }

    /// Register a subscription with this connection's shard; the shard
    /// assigns the scan snapshot and starts it on the reader itself.
    /// The NIP-86 snapshot is attached here so REQ, COUNT and NEG all
    /// hide moderated events.
    async fn subscribe(&self, sub: SubKey, filters: Arc<[Filter]>, gate: ReadGate, kind: ScanKind) {
        let gate = gate.with_moderation(self.handle.moderation.borrow().clone());
        drop(
            self.shard
                .send(ShardMsg::Register(Box::new(ScanStart {
                    conn: self.conn,
                    sub,
                    kind,
                    filters,
                    gate,
                    snapshot: 0,
                    out: self.out.clone(),
                })))
                .await,
        );
    }

    /// Remove one subscription at the shard (which forwards the reader
    /// cancel itself).
    async fn unsubscribe(&self, sub_id: SubId) {
        drop(
            self.shard
                .send(ShardMsg::Remove {
                    conn: self.conn,
                    sub_id,
                })
                .await,
        );
    }

    /// Drain `out_rx` (bounded by `BATCH_MAX_*`), feed every surviving
    /// frame, then flush — one socket flush per batch.
    async fn write_batch(
        &mut self,
        ws: &mut HttpWebSocket,
        first: Out,
        out_rx: &OutboundRx,
    ) -> Result<(), WriteError> {
        let mut batch = std::mem::take(&mut self.batch);
        let mut bytes = first.accounted_bytes();
        batch.push_back(first);
        out_rx.take_into(&mut batch, BATCH_MAX_FRAMES, BATCH_MAX_BYTES, &mut bytes);
        // Account every drained frame up front: a timeout mid-batch
        // drops the rest, and their bytes must not stay charged to the
        // outbound queue.
        for msg in &batch {
            out_rx.written(msg.accounted_bytes());
        }
        // One deadline covers every surviving feed plus the flush.
        let result = tokio::time::timeout(self.ping_interval, async {
            while let Some(msg) = batch.pop_front() {
                self.feed(ws, msg).await.map_err(WriteError::Socket)?;
            }
            ws.flush().await.map_err(WriteError::Socket)
        })
        .await;
        self.batch = batch;
        result.map_err(|_| WriteError::Stalled)?
    }

    /// One drained batch: feed + flush; `false` means the connection
    /// ends (socket error or stalled write).
    async fn write_out(
        &mut self,
        ws: &mut HttpWebSocket,
        first: Option<Out>,
        out_rx: &OutboundRx,
    ) -> bool {
        let Some(first) = first else {
            return false;
        };
        match self.write_batch(ws, first, out_rx).await {
            Ok(()) => true,
            Err(WriteError::Socket(err)) => {
                tracing::debug!(%err, "websocket write failed");
                false
            }
            Err(WriteError::Stalled) => {
                tracing::debug!("websocket write stalled");
                false
            }
        }
    }

    /// Shutdown watch tick: `true` (close sent) when the flag is raised.
    async fn shutdown_close(
        &self,
        ws: &mut HttpWebSocket,
        shutdown: &watch::Receiver<bool>,
    ) -> bool {
        if !*shutdown.borrow() {
            return false;
        }
        self.closing(ws, CloseCode::Away, &[]).await;
        true
    }

    /// Send one text frame and count it; `OK` and relay-sent `CLOSED`
    /// frames also log on `nosfry::ingest` (strfry's `invalidEvents`
    /// counterpart — accept *and* reject `OK`s, refused REQs/COUNTs).
    /// The log copy is only built when the target is enabled, so a
    /// disabled level costs nothing measurable.
    async fn feed_frame(
        &self,
        ws: &mut HttpWebSocket,
        verb: RelayVerb,
        text: String,
    ) -> Result<(), yawc::WebSocketError> {
        let log = matches!(verb, RelayVerb::Ok | RelayVerb::Closed)
            && tracing::enabled!(target: "nosfry::ingest", tracing::Level::DEBUG);
        let frame = log.then(|| text.clone());
        ws.feed(Frame::text(text.into_bytes())).await?;
        self.handle.metrics.relay_message(verb);
        if let Some(frame) = frame {
            tracing::debug!(target: "nosfry::ingest", frame = %frame, "sent");
        }
        Ok(())
    }

    /// Feed one outbound message; skipped subscriptions consume nothing.
    async fn feed(&mut self, ws: &mut HttpWebSocket, msg: Out) -> Result<(), yawc::WebSocketError> {
        match msg {
            Out::Frame { sub, verb, text } => {
                if sub.as_ref().is_some_and(|s| !self.session.is_current(s)) {
                    return Ok(());
                }
                self.feed_frame(ws, verb, text).await?;
            }
            Out::Frames { sub, texts } => {
                if !self.session.is_current(&sub) {
                    return Ok(());
                }
                for text in texts {
                    ws.feed(Frame::text(text.into_bytes())).await?;
                    self.handle.metrics.relay_message(RelayVerb::Event);
                }
            }
            Out::Event { sub, event } => {
                if !self.session.is_current(&sub) {
                    return Ok(());
                }
                let text = event_frame(&sub.id, event.json());
                ws.feed(Frame::text(text.into_bytes())).await?;
                self.handle.metrics.relay_message(RelayVerb::Event);
            }
            Out::Closed { sub, reason } => {
                if !self.session.close_by_relay(&sub) {
                    return Ok(());
                }
                // The shard removes the monitor and forwards the reader
                // cancel itself.
                drop(
                    self.shard
                        .send(ShardMsg::Remove {
                            conn: self.conn,
                            sub_id: sub.id.clone(),
                        })
                        .await,
                );
                let text = closed_frame(&sub.id, &reason);
                self.feed_frame(ws, RelayVerb::Closed, text).await?;
            }
            Out::Count { sub, text } => {
                if !self.session.is_current(&sub) {
                    return Ok(());
                }
                ws.feed(Frame::text(text.into_bytes())).await?;
                self.handle.metrics.relay_message(RelayVerb::Count);
                // The count is answered: free the sub slot. The scan
                // already finished, so there is nothing to cancel.
                self.session.close_by_relay(&sub);
            }
            Out::Neg { sub, text, closes } => {
                if !self.session.is_current_neg(&sub) {
                    return Ok(());
                }
                ws.feed(Frame::text(text.into_bytes())).await?;
                // Every closing sync frame is a NEG-ERR.
                self.handle.metrics.relay_message(if closes {
                    RelayVerb::NegErr
                } else {
                    RelayVerb::NegMsg
                });
                if closes {
                    // The sync errored: free the neg slot. The reader
                    // already released its side.
                    self.session.close_neg_by_relay(&sub);
                }
            }
        }
        Ok(())
    }

    /// Ping tick: close an idle connection (1001), else send a ping.
    /// `false` means the connection ends.
    async fn keepalive(&self, ws: &mut HttpWebSocket, last_inbound: Instant) -> bool {
        if last_inbound.elapsed() > self.ping_interval.saturating_mul(2) {
            self.closing(ws, CloseCode::Away, &[]).await;
            return false;
        }
        match tokio::time::timeout(self.ping_interval, ws.send(Frame::ping(&[][..]))).await {
            Ok(Ok(())) => true,
            Ok(Err(err)) => {
                tracing::debug!(%err, "ping failed");
                false
            }
            Err(_) => {
                tracing::debug!("ping write stalled");
                false
            }
        }
    }

    /// One select-loop tick: `Some(reason)` ends the connection.
    async fn step(
        &mut self,
        ws: &mut HttpWebSocket,
        out_rx: &OutboundRx,
        ping: &mut tokio::time::Interval,
        last_inbound: &mut Instant,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Option<&'static str> {
        tokio::select! {
            frame = ws.next() => (!self.inbound(ws, frame, last_inbound).await)
                .then_some("client closed or read failed"),
            first = out_rx.recv() => (!self.write_out(ws, first, out_rx).await)
                .then_some("write failed or stalled"),
            _ = ping.tick() => {
                (!self.keepalive(ws, *last_inbound).await).then_some("ping timeout")
            }
            _ = shutdown.changed() => self.shutdown_close(ws, shutdown).await.then_some("shutdown"),
        }
    }

    /// Best-effort close frame bounded by `CLOSE_TIMEOUT`.
    async fn closing(&self, ws: &mut HttpWebSocket, code: CloseCode, reason: &[u8]) {
        drop(tokio::time::timeout(CLOSE_TIMEOUT, ws.send(Frame::close(code, reason))).await);
    }

    /// Best-effort flush of yawc's queued control frames — the close
    /// a read error (oversized payload, protocol violation) or a
    /// peer close leaves in `obligated_sends` — under the close
    /// deadline so the peer sees the code instead of a bare EOF.
    /// `Sink::poll_ready` is what drains the queue (`poll_flush`
    /// does not).
    async fn drain_obligated(&self, ws: &mut HttpWebSocket) {
        drop(
            tokio::time::timeout(CLOSE_TIMEOUT, async {
                drop(
                    futures_util::future::poll_fn(|cx| {
                        futures_util::Sink::poll_ready(std::pin::Pin::new(&mut *ws), cx)
                    })
                    .await,
                );
                drop(ws.flush().await);
            })
            .await,
        );
    }

    /// Drop everything this connection registered at the shard.
    async fn teardown(&self) {
        drop(
            self.shard
                .send(ShardMsg::RemoveConn { conn: self.conn })
                .await,
        );
    }
}

/// Run one WebSocket connection until close, error, or shutdown.
/// `address` shares the client address's rate-limit buckets into the
/// session.
pub(crate) async fn run(
    ws: &mut HttpWebSocket,
    handle: &Handle,
    conn_id: ConnId,
    peer: IpAddr,
    address: Arc<AddressBuckets>,
) {
    let Some((mut conn, out_rx)) = Connection::new(handle, conn_id, peer, address) else {
        return;
    };
    let mut ping = tokio::time::interval(conn.ping_interval);
    let mut last_inbound = Instant::now();
    let mut shutdown = handle.shutdown.clone();

    let reason: &'static str = loop {
        if let Some(reason) = conn
            .step(ws, &out_rx, &mut ping, &mut last_inbound, &mut shutdown)
            .await
        {
            break reason;
        }
        if conn.out.is_dead() {
            conn.closing(ws, CloseCode::Policy, b"slow consumer").await;
            break "slow consumer";
        }
    };

    conn.drain_obligated(ws).await;
    conn.teardown().await;
    tracing::debug!(target: "nosfry::conn", reason, "connection closed");
}
