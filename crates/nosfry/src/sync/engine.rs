//! The windowed NIP-77 reconciliation engine. Work is a stack of
//! `[lo, hi]` timestamp windows, processed newest first; each window
//! opens a `NEG-OPEN` session that compares the local store against
//! the peer, `NEG-CLOSE`s, then transfers the differing ids it kept.
//! Oversized windows — too many local records, too many kept ids, or
//! a peer `blocked: too many query results` — split at the time
//! midpoint and requeue. Transfers stay bounded: download `REQ`s of
//! `ids_per_req` ids each through `EOSE`, uploads at 500-event chunks
//! with at most 32 unanswered `OK`s.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::Negentropy;
use nosfry_core::auth::ReadGate;
use nosfry_core::client::{PeerLimits, ids_per_req, reason_prefix};
use nosfry_core::event::{EventId, UnverifiedEvent};
use nosfry_core::filter::Filter;
use nosfry_core::limits::Limits;
use nosfry_core::sync::build_storage;
use nosfry_lmdb::{Progress, Scan, Store};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};

use super::conn::{Msg, RelayConn, trunc};
use super::ingest::{Ctx, batch};
use super::{Plan, SyncError, SyncOptions, SyncStats, now_secs};
use crate::policy::WritePolicy;

/// Per-side cap on kept have/need ids when the caller passes 0
/// (100k × 40 B ⇒ 4 MB, ADR §3).
const DEFAULT_PENDING_IDS: usize = 100_000;

/// One local-scan slice: the read txn is released between steps.
const STEP_BUDGET: Duration = Duration::from_millis(50);

/// The NIP-01 `limit` ceiling for collection scans.
const MAX_IDS_PER_REQ: usize = 500;

/// At most this many `EVENT`s await an `OK` at once (ADR §6).
const MAX_PENDING_OKS: usize = 32;

/// Upload chunk when loading events out of the local store.
const UPLOAD_CHUNK: usize = 500;

/// Reconcile / download / upload retries before a window or event
/// counts failed.
const MAX_ATTEMPTS: u8 = 8;

/// Peer retry hints above this are clamped.
const MAX_RATE_WAIT: Duration = Duration::from_secs(60);

/// Progress logging cadence.
const LOG_CADENCE: Duration = Duration::from_secs(5);

/// One timestamp window, inclusive both ends; `once` marks a window
/// already requeued after an auth advance.
#[derive(Debug, Clone, Copy)]
struct Window {
    lo: u64,
    hi: u64,
    reauthed: bool,
}

impl Window {
    const fn is_point(self) -> bool {
        self.lo >= self.hi
    }

    /// The (older, newer) halves around the time midpoint.
    const fn halves(self) -> (Self, Self) {
        let mid = self.lo + (self.hi - self.lo) / 2;
        (
            Self {
                lo: self.lo,
                hi: mid,
                reauthed: self.reauthed,
            },
            Self {
                lo: mid + 1,
                hi: self.hi,
                reauthed: self.reauthed,
            },
        )
    }
}

/// How one reconcile pass ends.
enum Step {
    /// The peer sent `None` from `reconcile_with_ids`: `NEG-CLOSE`
    /// was sent; transfer the kept ids.
    Done,
    /// Kept have+need crossed `pending_ids`: `NEG-CLOSE` was sent;
    /// transfer what was gathered, then requeue.
    Capped,
}

/// Peer-advertised constraints resolved once per run.
pub(crate) struct Peer<'a> {
    /// NIP-11 limits.
    pub(crate) limits: &'a PeerLimits,
    /// `NEG-OPEN`/`NEG-MSG` frame byte cap.
    pub(crate) frame_limit: u64,
}

/// How a window's reconcile retries ended.
enum Resolved {
    /// A pass closed: transfer the kept ids.
    Done(Step, Vec<EventId>, Vec<EventId>),
    /// The window must split (or fail at a point window).
    Split,
    /// Retries exhausted: count `failed_windows`.
    Fail,
}

/// Non-fatal reconcile outcomes.
enum Retry {
    /// `blocked` with a limit or "too many": split the window.
    Split,
    /// Capacity, rate-limit, or transient error: back off, reopen.
    Backoff,
    /// `auth-required`: authenticate, then reopen.
    AuthNeeded,
    /// Stop the run.
    Fatal(SyncError),
}

/// The engine state threaded through the run.
pub(crate) struct Engine<'a, S> {
    conn: &'a mut RelayConn<S>,
    store: &'a Store,
    opts: &'a SyncOptions,
    plan: &'a Plan,
    peer: &'a PeerLimits,
    /// `NEG-OPEN`/`NEG-MSG` frame byte cap.
    frame_limit: u64,
    /// Session limits from the local config.
    limits: &'a Limits,
    /// Kept-id cap in effect.
    pending_ids: usize,
    /// Download batch size from peer limits.
    ids_per_req: usize,
    /// Stack of pending windows (pop = next), newest first.
    stack: Vec<Window>,
    /// Windows requeued after an auth advance.
    requeued: VecDeque<Window>,
    /// The first `NEG-MSG` of the run proves the peer speaks NIP-77;
    /// before it, a NOTICE/CLOSED/stall is fatal `NoNip77`.
    first_neg_msg: bool,
    /// Fresh subscription ids.
    sub_seq: u64,
    stats: SyncStats,
    last_log: Instant,
}

impl<'a, S> Engine<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Run the whole range to completion.
    ///
    /// # Errors
    ///
    /// [`SyncError`] on a fatal peer, transport, or store failure.
    pub(crate) async fn run(
        conn: &'a mut RelayConn<S>,
        store: &'a Store,
        opts: &'a SyncOptions,
        plan: &'a Plan,
        peer: Peer<'a>,
        limits: &'a Limits,
        policy: Option<WritePolicy>,
    ) -> Result<SyncStats, SyncError> {
        let mut engine = Self {
            conn,
            store,
            opts,
            plan,
            peer: peer.limits,
            frame_limit: peer.frame_limit,
            limits,
            pending_ids: if opts.pending_ids == 0 {
                DEFAULT_PENDING_IDS
            } else {
                opts.pending_ids
            },
            ids_per_req: ids_per_req(peer.limits).clamp(1, MAX_IDS_PER_REQ),
            stack: vec![Window {
                lo: plan.lo,
                hi: plan.hi,
                reauthed: false,
            }],
            requeued: VecDeque::new(),
            first_neg_msg: false,
            sub_seq: 0,
            stats: SyncStats::default(),
            last_log: Instant::now(),
        };
        let ctx = Ctx {
            store,
            limits,
            url: &opts.url,
            policy: policy.as_ref(),
        };
        while let Some(window) = engine.next_window() {
            engine.stats.windows += 1;
            engine.sync_window(window, &ctx).await?;
            engine.log_progress();
        }
        Ok(engine.stats)
    }

    /// The next window: the stack top, then auth requeues.
    fn next_window(&mut self) -> Option<Window> {
        self.stack.pop().or_else(|| self.requeued.pop_front())
    }

    /// `n<seq>` — a fresh NEG-OPEN subscription id.
    fn next_sub(&mut self) -> String {
        self.sub_seq += 1;
        format!("n{}", self.sub_seq)
    }

    /// Requeue both halves of `window` so the newer runs first.
    fn split(&mut self, window: Window) {
        let (older, newer) = window.halves();
        self.stack.push(older);
        self.stack.push(newer);
    }

    /// Collect `(created_at, id)` records for `window` in short
    /// read-txn steps; the caller splits when the cap is crossed.
    fn local_records(&self, window: Window) -> Result<Vec<(u64, EventId)>, SyncError> {
        let filter = self.scan_filter(window, self.opts.window_records as u64 + 1)?;
        let gate = self.gate()?;
        let snapshot = self.store.snapshot().map_err(SyncError::Store)?;
        let mut scan = Scan::new(Arc::from([filter]), gate, snapshot, u64::MAX, now_secs());
        let mut records = Vec::new();
        loop {
            match scan.step_records(self.store, STEP_BUDGET, &mut |created_at, id| {
                records.push((created_at, id));
            }) {
                Ok(Progress::Pending) => {}
                Ok(Progress::Done) => break,
                Err(err) => return Err(SyncError::Store(err)),
            }
        }
        Ok(records)
    }

    /// A parsed `Filter` for local scans over `window` (`limit` is the
    /// overshoot sentinel for collection, 0 = none).
    fn scan_filter(&self, window: Window, limit: u64) -> Result<Filter, SyncError> {
        let mut map = self.plan.base.clone();
        map.insert("since".to_owned(), json!(window.lo));
        map.insert("until".to_owned(), json!(window.hi));
        if limit > 0 {
            map.insert("limit".to_owned(), json!(limit));
        }
        let text = serde_json::Value::Object(map).to_string();
        Filter::parse(&text).map_err(|err| SyncError::Usage(format!("window filter failed: {err}")))
    }

    /// The download/upload read gate: moderation bans apply.
    fn gate(&self) -> Result<ReadGate, SyncError> {
        let moderation = self.store.moderation().map_err(SyncError::Store)?;
        Ok(ReadGate::default().with_moderation(Arc::new(moderation)))
    }

    /// Reconcile and transfer one window: retryable failures wait and
    /// reopen, capped passes transfer then split, and everything else
    /// either splits the window or counts `failed_windows`.
    async fn sync_window(&mut self, window: Window, ctx: &Ctx<'_>) -> Result<(), SyncError> {
        let records = self.local_records(window)?;
        if records.len() > self.opts.window_records {
            if window.is_point() {
                tracing::warn!(
                    records = records.len(),
                    "window exceeds the record cap at a single second"
                );
            } else {
                self.split(window);
                return Ok(());
            }
        }
        let epoch = self.conn.auth_epoch();
        let (step, have, need) = match self.reconcile_retries(window, &records).await? {
            Resolved::Done(step, have, need) => (step, have, need),
            Resolved::Split => {
                if window.is_point() {
                    self.stats.failed_windows += 1;
                } else {
                    self.split(window);
                }
                return Ok(());
            }
            Resolved::Fail => {
                self.stats.failed_windows += 1;
                return Ok(());
            }
        };
        if matches!(step, Step::Capped) {
            let before = self.stats.downloaded + self.stats.uploaded;
            self.transfer(&have, &need, window, ctx).await?;
            if window.is_point() && self.stats.downloaded + self.stats.uploaded == before {
                self.stats.failed_windows += 1;
            } else if window.is_point() {
                self.stack.push(window);
            } else {
                self.split(window);
            }
            return Ok(());
        }
        self.transfer(&have, &need, window, ctx).await?;
        // A challenge answered mid-window whose `OK` is still in
        // flight: consume it before deciding whether the epoch moved.
        if self.conn.auth_pending() {
            self.authenticate().await?;
        }
        if !window.reauthed && self.conn.auth_epoch() != epoch {
            self.requeued.push_back(Window {
                reauthed: true,
                ..window
            });
        }
        Ok(())
    }

    /// `reconcile` with backoff pacing and auth retries. `Split`
    /// asks the caller to halve the window, `Fail` counts it.
    async fn reconcile_retries(
        &mut self,
        window: Window,
        records: &[(u64, EventId)],
    ) -> Result<Resolved, SyncError> {
        let mut have: Vec<EventId> = Vec::new();
        let mut need: Vec<EventId> = Vec::new();
        let mut attempts = 0u8;
        loop {
            match self.reconcile(window, records, &mut have, &mut need).await {
                Ok(step) => return Ok(Resolved::Done(step, have, need)),
                Err(Retry::Split) => return Ok(Resolved::Split),
                Err(Retry::Backoff) if attempts + 1 >= MAX_ATTEMPTS => {
                    return Ok(Resolved::Fail);
                }
                Err(Retry::Backoff) => {
                    attempts += 1;
                    self.wait(backoff(attempts)).await?;
                    have.clear();
                    need.clear();
                }
                Err(Retry::AuthNeeded) => {
                    self.authenticate().await?;
                }
                Err(Retry::Fatal(err)) => return Err(err),
            }
        }
    }

    /// `NEG-OPEN` for `window`, then `NEG-MSG` rounds until the peer
    /// closes the diff; the kept ids land in `have`/`need` per the
    /// direction.
    async fn reconcile(
        &mut self,
        window: Window,
        records: &[(u64, EventId)],
        have: &mut Vec<EventId>,
        need: &mut Vec<EventId>,
    ) -> Result<Step, Retry> {
        let storage = build_storage(records).map_err(|err| {
            Retry::Fatal(SyncError::Negentropy(format!("local storage build: {err}")))
        })?;
        let mut neg = Negentropy::borrowed(&storage, self.frame_limit)
            .map_err(|err| Retry::Fatal(SyncError::Negentropy(format!("init: {err}"))))?;
        let initial = neg
            .initiate()
            .map_err(|err| Retry::Fatal(SyncError::Negentropy(format!("initiate: {err}"))))?;
        let sub = self.next_sub();
        let filter = serde_json::Value::Object({
            let mut map = self.plan.base.clone();
            map.insert("since".to_owned(), json!(window.lo));
            map.insert("until".to_owned(), json!(window.hi));
            map
        });
        let open = json!(["NEG-OPEN", sub, filter, faster_hex::hex_string(&initial)]);
        self.conn
            .send(&open.to_string())
            .await
            .map_err(Retry::Fatal)?;
        loop {
            let msg = match self.conn.recv(self.opts.timeout).await {
                Ok(Msg::Neg { sub: s, msg }) if s == sub => msg,
                Ok(Msg::NegErr {
                    sub: s,
                    message,
                    limit,
                }) if s == sub => return Err(neg_err(&message, limit)),
                // NIP-77 is a run-level property: before the first
                // NEG-MSG a NOTICE or a CLOSED on the neg sub is a
                // peer that does not speak it; afterwards a NOTICE is
                // just noise (conn already warned) and a CLOSED is a
                // transient retry.
                Ok(Msg::Notice { message }) if !self.first_neg_msg => {
                    return Err(Retry::Fatal(SyncError::NoNip77(format!(
                        "NOTICE {:?}",
                        trunc(&message)
                    ))));
                }
                Ok(Msg::Closed {
                    sub: s, message, ..
                }) if s == sub && !self.first_neg_msg => {
                    return Err(Retry::Fatal(SyncError::NoNip77(format!(
                        "CLOSED {:?}",
                        trunc(&message)
                    ))));
                }
                Ok(Msg::Closed { sub: s, .. }) if s == sub => {
                    return Err(Retry::Backoff);
                }
                Ok(_) => continue,
                Err(SyncError::Stalled(_)) if !self.first_neg_msg => {
                    return Err(Retry::Fatal(SyncError::NoNip77(format!(
                        "no reply to NEG-OPEN within {} s",
                        self.opts.timeout.as_secs()
                    ))));
                }
                Err(err) => return Err(Retry::Fatal(err)),
            };
            self.first_neg_msg = true;
            let mut have_ids = Vec::new();
            let mut need_ids = Vec::new();
            let reply = neg
                .reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)
                .map_err(|err| {
                    Retry::Fatal(SyncError::Negentropy(format!("peer message: {err}")))
                })?;
            self.stats.have += have_ids.len() as u64;
            self.stats.need += need_ids.len() as u64;
            if self.opts.direction.up() {
                have.extend(have_ids.iter().map(|id| EventId(**id)));
            }
            if self.opts.direction.down() {
                need.extend(need_ids.iter().map(|id| EventId(**id)));
            }
            match reply {
                Some(next) if have.len() + need.len() <= self.pending_ids => {
                    let text = format!(
                        "[\"NEG-MSG\",\"{sub}\",\"{}\"]",
                        faster_hex::hex_string(&next)
                    );
                    self.conn.send(&text).await.map_err(Retry::Fatal)?;
                }
                Some(_) => {
                    self.neg_close(&sub).await.map_err(Retry::Fatal)?;
                    return Ok(Step::Capped);
                }
                None => {
                    self.neg_close(&sub).await.map_err(Retry::Fatal)?;
                    return Ok(Step::Done);
                }
            }
        }
    }

    /// `NEG-CLOSE` — best effort, a dead socket already surfaced.
    async fn neg_close(&mut self, sub: &str) -> Result<(), SyncError> {
        self.conn.send(&format!("[\"NEG-CLOSE\",\"{sub}\"]")).await
    }

    /// Wait out an answered challenge: the `OK` may trail other
    /// frames, so receive until the epoch reports authenticated.
    async fn authenticate(&mut self) -> Result<(), SyncError> {
        if !self.conn.has_key() {
            return Err(SyncError::AuthRequired);
        }
        while !self.conn.authed() {
            if let Msg::Notice { message } = self.conn.recv(self.opts.timeout).await? {
                tracing::warn!("peer NOTICE during AUTH: {}", trunc(&message));
            }
        }
        Ok(())
    }

    /// Sleep `duration` while answering pings/AUTH inside `recv`;
    /// NOTICEs are logged by the connection layer.
    async fn wait(&mut self, duration: Duration) -> Result<(), SyncError> {
        let deadline = Instant::now() + duration;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match self.conn.recv(remaining.min(self.opts.timeout)).await {
                Ok(_) | Err(SyncError::Stalled(_)) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// After a pass closes: download `need`, upload `have`.
    async fn transfer(
        &mut self,
        have: &[EventId],
        need: &[EventId],
        window: Window,
        ctx: &Ctx<'_>,
    ) -> Result<(), SyncError> {
        if self.opts.direction.down() {
            self.download(need, window, ctx).await?;
        }
        if self.opts.direction.up() {
            self.upload(have).await?;
        }
        Ok(())
    }

    /// `["REQ","d<seq>",{"ids":[...]}]` per batch through `EOSE`, then
    /// `CLOSE`; missing ids and exhausted retries count `failed`.
    async fn download(
        &mut self,
        need: &[EventId],
        window: Window,
        ctx: &Ctx<'_>,
    ) -> Result<(), SyncError> {
        let filter = self.scan_filter(window, 0)?;
        let mut idx = 0usize;
        let mut attempts = 0u8;
        let mut auth_tried = false;
        while idx < need.len() {
            let end = (idx + self.ids_per_req).min(need.len());
            let ids = need.get(idx..end).unwrap_or(&[]);
            let list: Vec<String> = ids.iter().map(ToString::to_string).collect();
            self.sub_seq += 1;
            let sub = format!("d{}", self.sub_seq);
            self.conn
                .send(&json!(["REQ", sub, {"ids": list}]).to_string())
                .await?;
            let (got, closed) = self.collect(&sub).await?;
            self.conn.send(&format!("[\"CLOSE\",\"{sub}\"]")).await?;
            let Some((message, hint)) = closed else {
                let requested: HashSet<EventId> = ids.iter().copied().collect();
                let delivered =
                    batch(ctx, &got, &requested, &filter, now_secs(), &mut self.stats).await?;
                self.stats.failed += (ids.len() as u64).saturating_sub(delivered);
                idx = end;
                attempts = 0;
                auth_tried = false;
                continue;
            };
            match reason_prefix(&message) {
                "rate-limited" if attempts + 1 < MAX_ATTEMPTS => {
                    attempts += 1;
                    self.wait(
                        hint.map_or_else(|| backoff(attempts), Duration::from_millis)
                            .min(MAX_RATE_WAIT),
                    )
                    .await?;
                    continue;
                }
                "auth-required" if !auth_tried => {
                    auth_tried = true;
                    self.authenticate().await?;
                    continue;
                }
                _ => self.stats.failed += (end - idx) as u64,
            }
            idx = end;
            attempts = 0;
            auth_tried = false;
        }
        Ok(())
    }

    /// Gather `EVENT`s for `sub` until `EOSE` or `CLOSED`; the
    /// `CLOSED` payload comes back for the caller to classify.
    async fn collect(
        &mut self,
        sub: &str,
    ) -> Result<(Vec<String>, Option<(String, Option<u64>)>), SyncError> {
        let mut got: Vec<String> = Vec::new();
        loop {
            match self.conn.recv(self.opts.timeout).await? {
                Msg::Event { sub: s, json } if s == sub => got.push(json),
                Msg::Eose { sub: s } if s == sub => return Ok((got, None)),
                Msg::Closed {
                    sub: s,
                    message,
                    retry_after_ms,
                } if s == sub => return Ok((got, Some((message, retry_after_ms)))),
                _ => {}
            }
        }
    }

    /// Load `have` chunks out of the store and send `EVENT` frames,
    /// at most [`MAX_PENDING_OKS`] awaiting an `OK`; `rate-limited`
    /// pauses sends, `auth-required` authenticates then resends once.
    async fn upload(&mut self, have: &[EventId]) -> Result<(), SyncError> {
        let mut up = Upload {
            queue: VecDeque::new(),
            pending: HashMap::new(),
            hold_until: None,
            hint: Duration::ZERO,
        };
        for chunk in have.chunks(UPLOAD_CHUNK) {
            up.queue.extend(
                self.load_events(chunk)?
                    .into_iter()
                    .map(|(id, json)| (id, json, 0)),
            );
            self.drain_uploads(&mut up).await?;
        }
        Ok(())
    }

    /// Pump one chunk to completion: sends, then `OK`s, until both
    /// the queue and pending set are empty.
    async fn drain_uploads(&mut self, up: &mut Upload) -> Result<(), SyncError> {
        while !(up.queue.is_empty() && up.pending.is_empty()) {
            self.send_events(up).await?;
            if up.pending.is_empty() && up.queue.is_empty() {
                break;
            }
            if up.pending.is_empty() {
                Self::hold_sends(up).await;
                continue;
            }
            self.recv_ok(up).await?;
        }
        Ok(())
    }

    /// All sends held by a rate-limit pause: sleep it out.
    async fn hold_sends(up: &mut Upload) {
        let now = Instant::now();
        if let Some(t) = up.hold_until.filter(|t| *t > now) {
            tokio::time::sleep(t - now).await;
        }
        up.hold_until = None;
    }

    /// Wait for the next frame; `OK`s settle pending events.
    async fn recv_ok(&mut self, up: &mut Upload) -> Result<(), SyncError> {
        if let Msg::Ok {
            id,
            accepted,
            message,
            retry_after_ms,
        } = self.conn.recv(self.opts.timeout).await?
        {
            self.handle_ok(up, id, accepted, &message, retry_after_ms)
                .await?;
        }
        Ok(())
    }

    /// Send queued `EVENT`s until the queue, the `OK` cap, or a
    /// rate-limit hold says stop.
    async fn send_events(&mut self, up: &mut Upload) -> Result<(), SyncError> {
        loop {
            if up.queue.is_empty()
                || up.pending.len() >= MAX_PENDING_OKS
                || up.hold_until.is_some_and(|t| t > Instant::now())
            {
                return Ok(());
            }
            let Some((id, json, attempts)) = up.queue.pop_front() else {
                return Ok(());
            };
            let frame = format!("[\"EVENT\",{json}]");
            if self
                .peer
                .max_message_length
                .is_some_and(|max| frame.len() as u64 > max)
            {
                self.stats.skipped += 1;
                continue;
            }
            self.conn.send(&frame).await?;
            up.pending.insert(id, (json, attempts));
            // Once rate-limited, sends trickle at the hint's pace:
            // the peer's bucket refills one token per hint, so
            // bursting the queue only burns attempts.
            if !up.queue.is_empty() && up.hint > Duration::ZERO {
                up.hold_until = Some(Instant::now() + up.hint);
                return Ok(());
            }
        }
    }

    /// One `OK` for a pending `EVENT`: acceptances tally, refusals
    /// classify — rate limits pace a requeue, auth retries once.
    async fn handle_ok(
        &mut self,
        up: &mut Upload,
        id: EventId,
        accepted: bool,
        message: &str,
        retry_after_ms: Option<u64>,
    ) -> Result<(), SyncError> {
        let Some((json, attempts)) = up.pending.remove(&id) else {
            return Ok(());
        };
        if accepted {
            if reason_prefix(message) == "duplicate" {
                self.stats.duplicates += 1;
            } else {
                self.stats.uploaded += 1;
            }
            return Ok(());
        }
        match reason_prefix(message) {
            "rate-limited" => {
                let attempts = attempts + 1;
                if attempts >= MAX_ATTEMPTS {
                    self.stats.failed += 1;
                    return Ok(());
                }
                up.queue.push_back((id, json, attempts));
                up.hint = retry_after_ms
                    .map_or_else(|| backoff(attempts), Duration::from_millis)
                    .min(MAX_RATE_WAIT);
                up.hold_until = Some(Instant::now() + up.hint);
            }
            "auth-required" => {
                if !self.conn.has_key() {
                    return Err(SyncError::AuthRequired);
                }
                if attempts > 0 {
                    self.stats.failed += 1;
                    return Ok(());
                }
                self.authenticate().await?;
                up.queue.push_back((id, json, 1));
            }
            "error" => self.stats.failed += 1,
            _ => self.stats.refused_remote += 1,
        }
        Ok(())
    }

    /// Scan the store for `ids` and return each event's `(id, json)`
    /// that may leave the relay: NIP-70 protected events and
    /// restricted kinds (when local AUTH is off) are skipped. Ids
    /// that produce no event count `skipped`.
    fn load_events(&mut self, ids: &[EventId]) -> Result<Vec<(EventId, String)>, SyncError> {
        let list: Vec<String> = ids.iter().map(ToString::to_string).collect();
        let filter = Filter::parse(&json!({"ids": list}).to_string())
            .map_err(|err| SyncError::Usage(format!("ids filter failed: {err}")))?;
        let gate = self.gate()?;
        let snapshot = self.store.snapshot().map_err(SyncError::Store)?;
        let mut scan = Scan::new(Arc::from([filter]), gate, snapshot, u64::MAX, now_secs());
        let mut out: Vec<(EventId, String)> = Vec::new();
        loop {
            match scan.step(self.store, STEP_BUDGET, &mut |_seq, json| {
                push_uploadable(&mut out, json, self.limits);
            }) {
                Ok(Progress::Pending) => {}
                Ok(Progress::Done) => break,
                Err(err) => return Err(SyncError::Store(err)),
            }
        }
        self.stats.skipped += ids.len().saturating_sub(out.len()) as u64;
        Ok(out)
    }

    /// Progress line at most every [`LOG_CADENCE`].
    fn log_progress(&mut self) {
        if self.last_log.elapsed() < LOG_CADENCE {
            return;
        }
        self.last_log = Instant::now();
        tracing::info!(
            windows = self.stats.windows,
            have = self.stats.have,
            need = self.stats.need,
            downloaded = self.stats.downloaded,
            uploaded = self.stats.uploaded,
            failed = self.stats.failed,
            "sync progress"
        );
    }
}

/// Upload state: the send queue, `EVENT`s awaiting `OK`, and the
/// rate-limit pacing the peer's hints impose.
struct Upload {
    /// `(id, json, attempts)` events not yet sent.
    queue: VecDeque<(EventId, String, u8)>,
    /// `id -> (json, attempts)` sent and awaiting `OK`.
    pending: HashMap<EventId, (String, u8)>,
    /// Sends held until this instant.
    hold_until: Option<Instant>,
    /// The peer's last retry hint (send cadence).
    hint: Duration,
}

/// Exponential backoff: 1 s, 2 s, 4 s, … capped at 30 s.
fn backoff(attempt: u8) -> Duration {
    let secs = 1u64.checked_shl(u32::from(attempt)).unwrap_or(60);
    Duration::from_secs(secs.min(30))
}

/// Whether a stored event may be uploaded: never NIP-70 protected
/// (the event itself or one it embeds), never a restricted kind —
/// the local relay serves those only to authenticated authors and
/// recipients, and the peer is neither.
fn uploadable(unverified: &UnverifiedEvent<'_>, limits: &Limits) -> bool {
    !unverified.is_protected()
        && !unverified.embeds_protected()
        && !limits.auth.is_restricted(unverified.kind().0)
}

/// Map a `NEG-ERR` to the retry decision: `blocked` with a limit
/// element or "too many" splits the window, "capacity" is transient
/// and backs off, every other `blocked` refuses the sync outright.
fn neg_err(message: &str, limit: Option<u64>) -> Retry {
    let prefix = reason_prefix(message);
    if prefix == "blocked" && (limit.is_some() || message.contains("too many")) {
        return Retry::Split;
    }
    match prefix {
        "blocked" if message.contains("capacity") => Retry::Backoff,
        "rate-limited" | "closed" | "error" => Retry::Backoff,
        "auth-required" => Retry::AuthNeeded,
        _ => Retry::Fatal(SyncError::Refused(trunc(message).to_owned())),
    }
}

/// The `Scan` step sink for uploads: parse each record and keep it
/// only when the event may leave the relay. Stored JSON may predate
/// a tightened `max_num_tags`/`max_tag_val_size`, so parse
/// structurally — a stored event must never be dropped for a newer
/// bound.
fn push_uploadable(out: &mut Vec<(EventId, String)>, json: &str, limits: &Limits) {
    if let Ok(unverified) = UnverifiedEvent::parse_structural(json)
        && uploadable(&unverified, limits)
    {
        out.push((unverified.id(), json.to_owned()));
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;

    /// `blocked:` splits or backs off only on the two transient
    /// reasons; everything else refuses.
    #[test]
    fn neg_err_maps_reasons() {
        assert!(matches!(
            neg_err("blocked: sync capacity exhausted", None),
            Retry::Backoff
        ));
        assert!(matches!(
            neg_err("blocked: too many query results", None),
            Retry::Split
        ));
        assert!(matches!(neg_err("blocked: limit", Some(10)), Retry::Split));
        // A limit element only splits on `blocked:`.
        assert!(matches!(
            neg_err("rate-limited: slow down", Some(10)),
            Retry::Backoff
        ));
        assert!(matches!(
            neg_err("blocked: you are banned", None),
            Retry::Fatal(_)
        ));
        for msg in [
            "rate-limited: slow down",
            "closed: closing",
            "error: something",
        ] {
            assert!(matches!(neg_err(msg, None), Retry::Backoff), "{msg}");
        }
        assert!(matches!(
            neg_err("auth-required: who are you", None),
            Retry::AuthNeeded
        ));
        for msg in ["restricted: nope", "invalid: bad frame", "unknown: huh"] {
            assert!(matches!(neg_err(msg, None), Retry::Fatal(_)), "{msg}");
        }
    }
}
