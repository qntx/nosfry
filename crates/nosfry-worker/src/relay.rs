//! The relay object: connections, sessions, the live-subscription
//! index, and hibernation state over a [`SqlStore`].

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::ControlFlow;
use std::sync::Arc;

use nosfry_core::auth::{AUTH_KIND, ReadGate};
use nosfry_core::event::{Event, PublicKey};
use nosfry_core::filter::Filter;
use nosfry_core::hll::Hll;
use nosfry_core::limits::{AddressBuckets, Limits};
use nosfry_core::management::{self, Action, Request};
use nosfry_core::message::{
    SubId, closed_frame, count_frame, eose_frame, event_frame, neg_err_frame,
    neg_err_frame_with_limit, neg_msg_frame, ok_frame,
};
use nosfry_core::moderation::Moderation;
use nosfry_core::monitor::Monitors;
use nosfry_core::policy::{self, Decision};
use nosfry_core::session::{Command, Session, SubKey};
use nosfry_core::store::WriteOutcome;
use nosfry_core::sync::{self, NegentropyStorageVector};
use nosfry_sql::{Executor, Param, SqlStore, StoreError, Value};
use serde::{Deserialize, Serialize};

use crate::config::{Config, ConfigError};

/// Connection ids must stay below 2^53: they are bound into SQL,
/// where integers are JavaScript doubles. The glue assigns them
/// (e.g. random 53-bit) and `accept`/`open` refuse larger ones.
const JS_MAX: u64 = (1 << 53) - 1;

/// A negentropy session idle this long is reaped with
/// `closed: idle timeout` — the native 60 seconds.
const NEG_IDLE_MS: u64 = 60_000;

/// A `u64` bound into SQL: ids stay under 2^53 already, so the
/// clamp is unreachable except for corrupt `subs` rows.
fn int(v: u64) -> Param<'static> {
    Param::Int(i64::try_from(v.min(JS_MAX)).unwrap_or(i64::MAX))
}

/// The `subs` schema the relay owns; created in [`Relay::open`].
const SUBS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS subs (
    conn INTEGER NOT NULL,
    sub_id TEXT NOT NULL,
    filters TEXT NOT NULL,
    authed INTEGER NOT NULL,
    PRIMARY KEY (conn, sub_id)
) WITHOUT ROWID";

/// What the platform does with a text frame and a close.
pub trait Socket {
    /// Send one text frame.
    fn send(&self, text: &str);
    /// Close the socket with a WebSocket code and reason.
    fn close(&self, code: u16, reason: &str);
}

/// Per-socket hibernation state, serialized into the platform's
/// WebSocket attachment (under 16 KiB at [`MAX_AUTHED_PUBKEYS`]).
///
/// [`MAX_AUTHED_PUBKEYS`]: nosfry_core::auth::MAX_AUTHED_PUBKEYS
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// Caller-chosen connection id (< 2^53, unique among live sockets).
    pub conn: u64,
    /// The client address the per-IP rate buckets key on.
    pub ip: Option<IpAddr>,
    /// The NIP-42 challenge issued to this connection.
    pub challenge: String,
    /// Whether the challenge was already sent.
    pub challenge_sent: bool,
    /// Authenticated pubkeys, lowercase hex.
    pub authed: Vec<String>,
}

/// Side effects one [`Relay::message`] call produced, beyond the
/// frames already written to sockets.
#[derive(Debug, Default)]
pub struct Effects {
    /// The connection's attachment changed (the challenge was sent or
    /// the authenticated set grew); the glue rewrites it on the socket.
    pub attachment: Option<Attachment>,
    /// The earliest expiration among events stored by this call; the
    /// glue moves the alarm forward when it precedes the scheduled one.
    pub expiration: Option<u64>,
    /// A stored (or duplicate) NIP-62 request to vanish queued
    /// deletion work; the glue schedules the alarm for now.
    pub vanish: bool,
    /// A publish paused at the write-policy point; the glue answers
    /// it and calls [`Relay::decided`]. A message carries at most one
    /// EVENT, so at most one check is pending per call.
    pub policy: Option<PolicyCheck>,
}

/// A publish waiting on the write-policy verdict: the connection,
/// the event, and the strfry request line to send the policy.
#[derive(Debug)]
pub struct PolicyCheck {
    /// The publishing connection.
    pub conn: u64,
    /// The verified event under review.
    pub event: Arc<Event>,
    /// The `{"type":"new",…}` line to POST to the policy.
    pub line: String,
}

/// The management RPC answer the glue turns into an HTTP response.
#[derive(Debug)]
pub struct Managed {
    /// The HTTP status.
    pub status: u16,
    /// The response body — a JSON object for 200/401 answers, plain
    /// text for 400/413 like the native axum handler.
    pub body: String,
}

/// [`Relay`] construction failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayError {
    /// The configuration is invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A connection id exceeds the JavaScript-safe integer range.
    #[error("connection id exceeds the JavaScript-safe integer range")]
    ConnId,
}

/// One live connection.
#[derive(Debug)]
struct Conn<S> {
    /// The platform socket.
    socket: S,
    /// The sans-IO protocol state.
    session: Session,
    /// The client address the shared buckets key on.
    ip: Option<IpAddr>,
    /// The connection's NIP-42 challenge (the session also holds it).
    challenge: String,
}

/// One open negentropy sync: the sealed storage `NEG-MSG`s reconcile
/// against. Sessions live only in the object's memory — a Durable
/// Object wake drops them all and the next `NEG-MSG` answers
/// `closed: unknown subscription` (ADR 0007: sync state does not
/// hibernate).
#[derive(Debug)]
struct NegSession {
    /// The session generation the slot opened under.
    generation: u64,
    /// The sealed `(created_at, id)` records.
    storage: NegentropyStorageVector,
    /// The sync-memory reservation this session holds.
    reserved: usize,
    /// Last `NEG-OPEN`/`NEG-MSG` time; [`NEG_IDLE_MS`] reaps idle ones.
    last_active_ms: u64,
}

/// The relay object: the SQL store, the session per connection, and
/// the monitor index — everything but the platform's socket, timer,
/// and persistence calls.
#[derive(Debug)]
pub struct Relay<E: Executor, S: Socket> {
    store: SqlStore<E>,
    config: Config,
    limits: Arc<Limits>,
    /// Parsed `[relay.management] admins` — hex strings are validated
    /// in [`Config::parse`]; `open` parses them once.
    admins: Vec<PublicKey>,
    /// The NIP-86 snapshot hot paths read; `manage` replaces it with
    /// a fresh `Arc` after every applied op.
    moderation: Arc<Moderation>,
    conns: HashMap<u64, Conn<S>>,
    /// `AddressBuckets` shared by every connection of one client
    /// address; the entry dies with the last.
    buckets: HashMap<IpAddr, Arc<AddressBuckets>>,
    monitors: Monitors<u64>,
    /// Whether a write policy runs (the `POLICY` binding exists).
    policy: bool,
    /// Open negentropy sessions by `(conn, subscription id)`.
    negs: HashMap<(u64, SubId), NegSession>,
    /// Total bytes the open negentropy sessions have reserved against
    /// `[relay] max_sync_memory_bytes` (`0` = unlimited).
    sync_reserved: usize,
    /// The filters-JSON bytes each live subscription charges against
    /// `[worker] max_subscription_bytes` (`0` = unlimited).
    sub_bytes: HashMap<u64, HashMap<SubId, usize>>,
    /// The total `sub_bytes` charges.
    subs_bytes: usize,
    /// Subscriptions `restore_subs` re-registered at open and the
    /// `subs` rows it dropped as stale, corrupt, or over budget —
    /// the wake's one-line restore log.
    restored_subs: usize,
    dropped_subs: usize,
}

/// The fields `restore_subs` streams each `subs` row through while
/// the executor holds `self.store`.
struct Restore<'a, S: Socket> {
    conns: &'a mut HashMap<u64, Conn<S>>,
    limits: &'a Arc<Limits>,
    moderation: &'a Arc<Moderation>,
    monitors: &'a mut Monitors<u64>,
    sub_bytes: &'a mut HashMap<u64, HashMap<SubId, usize>>,
    subs_bytes: &'a mut usize,
}

impl<E: Executor, S: Socket> Relay<E, S> {
    /// Open the object: create the `subs` table, resume one session
    /// per `(socket, attachment)` pair, reload their subscriptions
    /// into the monitor index, and drop `subs` rows whose connection
    /// is not live (a crash or deploy strands them).
    ///
    /// # Errors
    ///
    /// [`RelayError::Config`] on an invalid config,
    /// [`RelayError::ConnId`] on an attachment conn id above 2^53 − 1,
    /// [`RelayError::Store`] on SQL failures or corrupt `subs` rows.
    /// `policy` tells the relay a write-policy endpoint exists — the
    /// glue passes the `POLICY` binding's presence.
    pub fn open(
        store: SqlStore<E>,
        config: Config,
        sockets: Vec<(S, Attachment)>,
        policy: bool,
    ) -> Result<Self, RelayError> {
        let limits = Arc::new(config.limits()?);
        store
            .exec()
            .execute(SUBS_SCHEMA, &[])
            .map_err(|err| StoreError::Sql(Box::new(err)))?;
        let moderation = Arc::new(store.moderation()?);
        let admins = config
            .relay
            .management
            .admin_keys()
            .map_err(ConfigError::Admins)?;
        let mut relay = Self {
            store,
            config,
            limits,
            admins,
            moderation,
            conns: HashMap::new(),
            buckets: HashMap::new(),
            monitors: Monitors::new(),
            policy,
            negs: HashMap::new(),
            sync_reserved: 0,
            sub_bytes: HashMap::new(),
            subs_bytes: 0,
            restored_subs: 0,
            dropped_subs: 0,
        };
        for (socket, attachment) in sockets {
            if attachment.conn > JS_MAX {
                return Err(RelayError::ConnId);
            }
            let buckets = relay.buckets_for(attachment.ip);
            let authed: Arc<[PublicKey]> = attachment
                .authed
                .iter()
                .filter_map(|hex| PublicKey::from_hex(hex))
                .collect::<Vec<_>>()
                .into();
            let session = Session::resume(
                Arc::clone(&relay.limits),
                attachment.challenge.clone(),
                buckets,
                attachment.challenge_sent,
                authed,
            );
            relay.conns.insert(
                attachment.conn,
                Conn {
                    socket,
                    session,
                    ip: attachment.ip,
                    challenge: attachment.challenge,
                },
            );
        }
        relay.restore_subs()?;
        Ok(relay)
    }

    /// Wake-restore counts for the one-line construction log: live
    /// connections, re-registered subscriptions, and `subs` rows
    /// dropped as stale, corrupt, or over budget.
    #[must_use]
    pub fn restored(&self) -> (usize, usize, usize) {
        (self.conns.len(), self.restored_subs, self.dropped_subs)
    }

    /// Whether `ip` is on the NIP-86 block list; the glue answers 403
    /// before upgrades, NIP-11, and the management RPC — the native
    /// order.
    #[must_use]
    pub fn ip_blocked(&self, ip: Option<IpAddr>) -> bool {
        ip.is_some_and(|ip| self.moderation.ip_blocked(&ip))
    }

    /// Whether `ip` may open another connection under the global and
    /// per-address caps; the glue answers 503 before upgrading.
    /// Address-less connections count toward the global cap only.
    #[must_use]
    pub fn admits(&self, ip: Option<IpAddr>) -> bool {
        let global = self.config.relay.max_connections;
        if global != 0 && self.conns.len() >= global {
            return false;
        }
        let per_ip = self.config.relay.max_connections_per_ip;
        ip.is_none_or(|ip| {
            per_ip == 0 || self.conns.values().filter(|c| c.ip == Some(ip)).count() < per_ip
        })
    }

    /// Whether `conn` is a live connection — the glue regenerates
    /// its random id until this answers false.
    #[must_use]
    pub fn is_live(&self, conn: u64) -> bool {
        self.conns.contains_key(&conn)
    }

    /// Register a new socket. `conn` is caller-chosen and must be
    /// unique among live connections and below 2^53 (it is bound into
    /// `subs` rows). Returns the initial attachment to persist on the
    /// socket.
    ///
    /// # Errors
    ///
    /// [`RelayError::ConnId`] when `conn` exceeds 2^53 − 1.
    pub fn accept(
        &mut self,
        socket: S,
        conn: u64,
        ip: Option<IpAddr>,
        challenge: String,
    ) -> Result<Attachment, RelayError> {
        if conn > JS_MAX {
            return Err(RelayError::ConnId);
        }
        let buckets = self.buckets_for(ip);
        let session = Session::new(Arc::clone(&self.limits), challenge.clone(), buckets);
        self.conns.insert(
            conn,
            Conn {
                socket,
                session,
                ip,
                challenge: challenge.clone(),
            },
        );
        Ok(Attachment {
            conn,
            ip,
            challenge,
            challenge_sent: false,
            authed: Vec::new(),
        })
    }

    /// Feed one inbound text frame, run the resulting commands in
    /// order, and report side effects. A text longer than
    /// `max_websocket_payload_size` closes the socket with 1009 and
    /// drops the connection exactly like [`Relay::close`].
    #[must_use]
    pub fn message(&mut self, conn: u64, now_ms: u64, text: &str) -> Effects {
        let mut effects = Effects::default();
        self.reap_negs(now_ms);
        if text.len() > self.config.relay.max_websocket_payload_size {
            if let Some(c) = self.conns.get(&conn) {
                c.socket.close(1009, "message too big");
            }
            self.close(conn);
            return effects;
        }
        let Some(c) = self.conns.get_mut(&conn) else {
            return effects;
        };
        let challenge_sent = c.session.challenge_sent();
        let authed = c.session.authenticated().len();
        let mut commands = Vec::new();
        // `Received` only carries metrics (verb, rate_limited); the
        // worker has no metrics.
        let _received = c.session.on_text(now_ms, text, &mut commands);
        for command in commands {
            self.command(conn, command, now_ms, &mut effects);
        }
        if let Some(live) = self.conns.get(&conn)
            && (live.session.challenge_sent() != challenge_sent
                || live.session.authenticated().len() != authed)
        {
            effects.attachment = Some(Attachment {
                conn,
                ip: live.ip,
                challenge: live.challenge.clone(),
                challenge_sent: live.session.challenge_sent(),
                authed: live
                    .session
                    .authenticated()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            });
        }
        effects
    }

    /// Drop a connection: remove its subscriptions from the monitor
    /// index, delete its `subs` rows, release its subscription byte
    /// charges and negentropy reservations, and release its share of
    /// the address buckets.
    pub fn close(&mut self, conn: u64) {
        self.drop_conn_negs(conn);
        self.monitors.remove_connection(conn);
        if let Some(subs) = self.sub_bytes.remove(&conn) {
            self.subs_bytes -= subs.values().sum::<usize>();
        }
        self.exec("DELETE FROM subs WHERE conn = ?1", &[int(conn)]);
        let Some(c) = self.conns.remove(&conn) else {
            return;
        };
        // `c` still holds its session's bucket share: two references
        // left (the map's and the session's) means this was the last.
        if let Some(ip) = c.ip
            && self
                .buckets
                .get(&ip)
                .is_some_and(|b| Arc::strong_count(b) == 2)
        {
            self.buckets.remove(&ip);
        }
    }

    /// Run the NIP-40 and NIP-62 sweeps: delete up to 10,000 expired
    /// events, then drain one vanish step of up to 10,000 examined
    /// index rows. Answers the next alarm time — `Some(now)` while
    /// either backlog remains (run again immediately), else the next
    /// expiration or `None`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure.
    pub fn alarm(&self, now: u64) -> Result<Option<u64>, StoreError> {
        let expiring = self.store.expire(now, 10_000)? == 10_000;
        let step = self.store.vanish_step(10_000)?;
        if expiring || step.more {
            return Ok(Some(now));
        }
        self.store.next_expiration()
    }

    /// The alarm the object should wake at: `Some(now)` while vanish
    /// work is pending, else the next expiration — the value the
    /// glue reconciles against the stored alarm on wake so work
    /// committed just before a crash still runs.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sql`] on executor failure.
    pub fn next_alarm(&self, now: u64) -> Result<Option<u64>, StoreError> {
        if self.store.vanish_pending()? {
            return Ok(Some(now));
        }
        self.store.next_expiration()
    }

    /// The NIP-86 management endpoint: `POST` with the
    /// `application/nostr+json+rpc` content type, NIP-98 authorized
    /// against `[relay.management] admins` — the native status
    /// table: 405 without either, 413 over [`management::BODY_LIMIT`]
    /// (the glue refuses earlier without buffering), 401 on
    /// authorization failure, 400 on invalid UTF-8/JSON, and method
    /// errors as `{"error": …}` at 200.
    #[must_use]
    pub fn manage(
        &mut self,
        content_type: Option<&str>,
        authorization: Option<&str>,
        body: &[u8],
        now: u64,
    ) -> Managed {
        let managed = |status, value: serde_json::Value| Managed {
            status,
            body: value.to_string(),
        };
        let rpc = content_type
            .and_then(|v| v.split(';').next())
            .is_some_and(|t| t.trim().eq_ignore_ascii_case(management::CONTENT_TYPE));
        if !rpc || self.admins.is_empty() {
            return Managed {
                status: 405,
                body: String::new(),
            };
        }
        if body.len() > management::BODY_LIMIT {
            return Managed {
                status: 413,
                body: "Failed to buffer the request body: length limit exceeded".to_owned(),
            };
        }
        if let Err(error) = management::authorize(
            authorization,
            body,
            now,
            &self.config.events,
            self.limits.auth.relay(),
            &self.admins,
        ) {
            return managed(
                401,
                serde_json::json!({"error": format!("unauthorized: {error}")}),
            );
        }
        let Ok(text) = std::str::from_utf8(body) else {
            return Managed {
                status: 400,
                body: "invalid utf-8".to_owned(),
            };
        };
        let Ok(request) = serde_json::from_str::<Request<'_>>(text) else {
            return Managed {
                status: 400,
                body: "invalid request json".to_owned(),
            };
        };
        match management::action(&request, &self.moderation) {
            Ok(Action::Respond(result)) => managed(200, serde_json::json!({"result": result})),
            Ok(Action::Apply(op)) => match self.store.moderate(op) {
                Ok(moderation) => {
                    self.moderation = Arc::new(moderation);
                    managed(200, serde_json::json!({"result": true}))
                }
                Err(err) => managed(200, serde_json::json!({"error": format!("error: {err}")})),
            },
            Err(error) => managed(200, serde_json::json!({"error": error})),
        }
    }

    /// The optional capabilities the configuration advertises in the
    /// NIP-11 document and on the landing page.
    fn features(&self) -> nosfry_core::info::Features {
        nosfry_core::info::Features {
            count: self.limits.req.max_filter_limit_count > 0,
            sync: self.sync_cap() > 0,
            auth: !self.config.relay.service_url.is_empty(),
            management: !self.config.relay.management.admins.is_empty(),
        }
    }

    /// The NIP-11 relay information document; the NIP-86
    /// moderation snapshot overrides `name`/`description`/`icon`
    /// like native.
    #[must_use]
    pub fn nip11(&self) -> String {
        nosfry_core::info::document(
            &self.config.relay.info,
            &self.moderation,
            self.features(),
            &self.limits,
            self.config.relay.max_websocket_payload_size,
        )
    }

    /// The HTML landing page, mirroring [`Self::nip11`]'s effective
    /// info.
    #[must_use]
    pub fn landing(&self) -> String {
        nosfry_core::site::landing_page(
            &self.config.relay.info,
            &self.moderation,
            self.features(),
            &self.config.relay.service_url,
        )
    }

    /// Consume the relay and return the store (tests reopen it with
    /// `into_exec`).
    pub fn into_store(self) -> SqlStore<E> {
        self.store
    }

    /// The shared `AddressBuckets` for `ip` (address-less connections
    /// get a disabled pair they never share).
    fn buckets_for(&mut self, ip: Option<IpAddr>) -> Arc<AddressBuckets> {
        match ip {
            Some(ip) => Arc::clone(
                self.buckets
                    .entry(ip)
                    .or_insert_with(|| Arc::new(AddressBuckets::new(&self.limits.rate))),
            ),
            None => Arc::new(AddressBuckets::default()),
        }
    }

    /// Run `sql` best-effort. These calls are cleanup deletes whose
    /// failure is unrecoverable anyway (the executor is broken), so
    /// the outcome is intentionally dropped rather than propagated.
    fn exec(&self, sql: &str, params: &[Param<'_>]) {
        drop(self.store.exec().execute(sql, params));
    }

    /// Send `text` on `conn`'s socket if it is still live.
    fn send(&self, conn: u64, text: &str) {
        if let Some(c) = self.conns.get(&conn) {
            c.socket.send(text);
        }
    }

    /// Execute one session command in order. `now_ms` is unix time in
    /// milliseconds; store queries take its seconds.
    fn command(&mut self, conn: u64, command: Command, now_ms: u64, effects: &mut Effects) {
        match command {
            Command::Send { text, .. } => self.send(conn, &text),
            Command::Publish { event, authed } => {
                self.publish(conn, &event, authed, now_ms, effects);
            }
            Command::Subscribe { sub, filters, gate } => {
                self.subscribe(
                    conn,
                    sub,
                    filters,
                    gate.with_moderation(Arc::clone(&self.moderation)),
                    now_ms / 1000,
                );
            }
            Command::Unsubscribe { sub_id } => self.unsubscribe(conn, &sub_id),
            Command::Count { sub, filters, gate } => {
                let gate = gate.with_moderation(Arc::clone(&self.moderation));
                self.count(conn, &sub, &filters, &gate, now_ms / 1000);
            }
            Command::NegOpen {
                sub,
                filters,
                gate,
                msg,
            } => {
                let gate = gate.with_moderation(Arc::clone(&self.moderation));
                self.neg_open(conn, &sub, &filters, &gate, &msg, now_ms);
            }
            Command::NegMsg { sub, msg } => self.neg_msg(conn, &sub, &msg, now_ms),
            Command::NegClose { sub_id } => self.neg_close(conn, &sub_id),
        }
    }

    /// `min([relay.limits] max_sync_events, [worker] max_scan_rows)` —
    /// the record cap a `NEG-OPEN` answer obeys and NIP-11 advertises.
    fn sync_cap(&self) -> u64 {
        self.limits
            .req
            .max_sync_events
            .min(self.config.worker.max_scan_rows as u64)
    }

    /// Send `text` as the negentropy frame native sends, closing the
    /// session slot after it when `closes`. A stale generation drops
    /// the frame without sending, like native.
    fn neg_frame(&mut self, conn: u64, sub: &SubKey, text: &str, closes: bool) {
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        if !c.session.is_current_neg(sub) {
            return;
        }
        c.socket.send(text);
        if closes {
            c.session.close_neg_by_relay(sub);
        }
    }

    /// A `NEG-OPEN`: the records scan admits the session, over-cap or
    /// exhausted-budget scans are refused `blocked:` with the
    /// effective limit, and the memory budget refuses
    /// `blocked: sync capacity exhausted` — the native wording.
    /// Success always answers `NEG-MSG`, even an empty protocol round.
    fn neg_open(
        &mut self,
        conn: u64,
        sub: &SubKey,
        filters: &[Filter],
        gate: &ReadGate,
        msg: &[u8],
        now_ms: u64,
    ) {
        self.reap_negs(now_ms);
        let cap = self.sync_cap();
        let found = self.store.records(
            filters,
            gate,
            now_ms / 1000,
            cap.saturating_add(1),
            self.config.worker.max_scan_rows,
        );
        let records = match found {
            Err(_) => {
                self.neg_frame(
                    conn,
                    sub,
                    &neg_err_frame(&sub.id, "error: internal error"),
                    true,
                );
                return;
            }
            Ok(found) if found.budget_exhausted || found.records.len() as u64 > cap => {
                self.neg_frame(
                    conn,
                    sub,
                    &neg_err_frame_with_limit(&sub.id, "blocked: too many query results", cap),
                    true,
                );
                return;
            }
            Ok(found) => found.records,
        };
        let reserved = records.len() * sync::SYNC_RECORD_BYTES;
        let budget = self.config.relay.max_sync_memory_bytes;
        if budget != 0 && self.sync_reserved.saturating_add(reserved) > budget {
            self.neg_frame(
                conn,
                sub,
                &neg_err_frame(&sub.id, "blocked: sync capacity exhausted"),
                true,
            );
            return;
        }
        let opened = sync::build_storage(&records)
            .map_err(|_| ())
            .and_then(|storage| {
                sync::reconcile(&storage, msg)
                    .map(|reply| (storage, reply))
                    .map_err(|_| ())
            });
        match opened {
            Ok((storage, reply)) => {
                self.neg_frame(
                    conn,
                    sub,
                    &neg_msg_frame(&sub.id, &faster_hex::hex_string(&reply)),
                    false,
                );
                let live = self
                    .conns
                    .get(&conn)
                    .is_some_and(|c| c.session.is_current_neg(sub));
                if live {
                    self.sync_reserved += reserved;
                    self.negs.insert(
                        (conn, sub.id.clone()),
                        NegSession {
                            generation: sub.generation,
                            storage,
                            reserved,
                            last_active_ms: now_ms,
                        },
                    );
                }
            }
            Err(()) => {
                self.neg_frame(
                    conn,
                    sub,
                    &neg_err_frame(&sub.id, "invalid: malformed negentropy message"),
                    true,
                );
            }
        }
    }

    /// A `NEG-MSG`: reconcile against the stored records and answer
    /// `NEG-MSG` (even an empty round), or close with the native
    /// wording — `closed: unknown subscription` when no session
    /// answers, `invalid: malformed negentropy message` on a wire
    /// error. Both failures release the reservation.
    fn neg_msg(&mut self, conn: u64, sub: &SubKey, msg: &[u8], now_ms: u64) {
        let key = (conn, sub.id.clone());
        match self.negs.get_mut(&key) {
            Some(session) if session.generation == sub.generation => {
                if let Ok(reply) = sync::reconcile(&session.storage, msg) {
                    session.last_active_ms = now_ms;
                    self.neg_frame(
                        conn,
                        sub,
                        &neg_msg_frame(&sub.id, &faster_hex::hex_string(&reply)),
                        false,
                    );
                } else {
                    self.drop_neg(&key);
                    self.neg_frame(
                        conn,
                        sub,
                        &neg_err_frame(&sub.id, "invalid: malformed negentropy message"),
                        true,
                    );
                }
            }
            _ => self.neg_frame(
                conn,
                sub,
                &neg_err_frame(&sub.id, "closed: unknown subscription"),
                true,
            ),
        }
    }

    /// A `NEG-CLOSE`: drop the session and release its reservation
    /// (the session slot is already gone — `drop_neg` ran first).
    fn neg_close(&mut self, conn: u64, sub_id: &SubId) {
        self.drop_neg(&(conn, sub_id.clone()));
    }

    /// Release `key`'s session reservation and drop it.
    fn drop_neg(&mut self, key: &(u64, SubId)) {
        if let Some(session) = self.negs.remove(key) {
            self.sync_reserved -= session.reserved;
        }
    }

    /// Drop every negentropy session `conn` owns — socket close or
    /// message-too-big teardown.
    fn drop_conn_negs(&mut self, conn: u64) {
        let keys: Vec<(u64, SubId)> = self
            .negs
            .keys()
            .filter(|(c, _)| *c == conn)
            .cloned()
            .collect();
        for key in keys {
            self.drop_neg(&key);
        }
    }

    /// Reap sessions idle [`NEG_IDLE_MS`] or longer with
    /// `closed: idle timeout` — the lazy native reaper, run at the
    /// head of every `message()` and before admitting a session.
    fn reap_negs(&mut self, now_ms: u64) {
        if self.negs.is_empty() {
            return;
        }
        let dead: Vec<(u64, SubKey)> = self
            .negs
            .iter()
            .filter(|(_, s)| now_ms.saturating_sub(s.last_active_ms) >= NEG_IDLE_MS)
            .map(|((conn, id), s)| {
                (
                    *conn,
                    SubKey {
                        id: id.clone(),
                        generation: s.generation,
                    },
                )
            })
            .collect();
        for (conn, sub) in dead {
            self.drop_neg(&(conn, sub.id.clone()));
            self.neg_frame(
                conn,
                &sub,
                &neg_err_frame(&sub.id, "closed: idle timeout"),
                true,
            );
        }
    }

    /// A verified event: the moderation gate, then the write-policy
    /// point (the glue answers it and calls [`Relay::decided`]), then
    /// the store. NIP-86 runs first, exactly where the native
    /// connection checks it; AUTH events and a relay-scoped request
    /// to vanish are exempt (a banned author may still authenticate
    /// or vanish), and a vanish request also bypasses the policy —
    /// restricted relays MUST comply with NIP-62.
    fn publish(
        &mut self,
        conn: u64,
        event: &Arc<Event>,
        authed: Option<PublicKey>,
        now_ms: u64,
        effects: &mut Effects,
    ) {
        if event.kind() != AUTH_KIND
            && !event.requests_vanish(self.limits.auth.relay())
            && let Some(reason) = self.moderation.blocked_reason(event)
        {
            self.send(conn, &ok_frame(&event.id(), false, reason));
            return;
        }
        if self.policy && !event.requests_vanish(self.limits.auth.relay()) {
            let ip = self
                .conns
                .get(&conn)
                .and_then(|c| c.ip)
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            effects.policy = Some(PolicyCheck {
                conn,
                event: Arc::clone(event),
                line: policy::request_line(event.json(), now_ms / 1000, ip, authed),
            });
            return;
        }
        self.store_publish(conn, event, effects);
    }

    /// Finish a publish paused for the write policy — the native
    /// `policy_accepts` outcome: `reject` answers `OK false`
    /// (`blocked: rejected by write policy` on an empty `msg`),
    /// `shadowReject` answers `OK true` without storing or
    /// broadcasting, `accept` continues to the store. The connection
    /// may be gone by the time the verdict arrives (another message
    /// ran while the glue awaited): an `Accept` still writes and
    /// delivers — only its `OK` is skipped (`send` is a no-op).
    pub fn decided(
        &mut self,
        conn: u64,
        event: &Arc<Event>,
        decision: Decision,
        _now_ms: u64,
    ) -> Effects {
        let mut effects = Effects::default();
        match decision {
            Decision::Accept => self.store_publish(conn, event, &mut effects),
            Decision::Reject(m) if m.is_empty() => self.send(
                conn,
                &ok_frame(&event.id(), false, "blocked: rejected by write policy"),
            ),
            Decision::Reject(m) => {
                self.send(conn, &ok_frame(&event.id(), false, &m));
            }
            Decision::ShadowReject(m) => {
                self.send(conn, &ok_frame(&event.id(), true, &m));
            }
        }
        effects
    }

    /// The publish tail shared by the synchronous path and a policy
    /// `accept`: persist non-ephemeral kinds and deliver a `Stored`
    /// or ephemeral event to every current subscription, the
    /// publisher's own included.
    fn store_publish(&mut self, conn: u64, event: &Arc<Event>, effects: &mut Effects) {
        if event.kind().is_ephemeral() {
            self.send(conn, &ok_frame(&event.id(), true, ""));
            self.deliver(event);
            return;
        }
        match self
            .store
            .write(std::slice::from_ref(event), self.limits.auth.relay())
        {
            Ok(written) => {
                let Some(&outcome) = written.outcomes.first() else {
                    return;
                };
                effects.vanish |= written.vanish_pending;
                let (accepted, message) = outcome.ok_reply();
                self.send(conn, &ok_frame(&event.id(), accepted, message));
                if matches!(outcome, WriteOutcome::Stored { .. }) {
                    self.deliver(event);
                    effects.expiration = event.expiration();
                }
            }
            Err(_) => self.send(conn, &ok_frame(&event.id(), false, "error: internal error")),
        }
    }

    /// Fan `event` out to every matching current subscription.
    fn deliver(&mut self, event: &Event) {
        let mut hits = Vec::new();
        self.monitors.matches(event.packed(), &mut hits);
        for (conn, sub) in hits {
            if let Some(c) = self.conns.get(&conn)
                && c.session.is_current(&sub)
            {
                c.socket.send(&event_frame(&sub.id, event.json()));
            }
        }
    }

    /// A `REQ`: refuse subscriptions that would cross the
    /// `[worker] max_subscription_bytes` budget, stream the stored
    /// hits then `EOSE`, register the monitor, and persist the
    /// subscription — only a subscription that survived its `EOSE`
    /// reaches the `subs` table.
    fn subscribe(
        &mut self,
        conn: u64,
        sub: SubKey,
        filters: Arc<[Filter]>,
        gate: ReadGate,
        now: u64,
    ) {
        let filters_json = format!(
            "[{}]",
            filters
                .iter()
                .map(Filter::to_json)
                .collect::<Vec<_>>()
                .join(",")
        );
        let bytes: usize = filters.iter().map(Filter::approx_bytes).sum();
        if !self.sub_fits(conn, &sub.id, bytes) {
            self.send(
                conn,
                &closed_frame(&sub.id, "blocked: subscription capacity exhausted"),
            );
            if let Some(c) = self.conns.get_mut(&conn) {
                c.session.close_by_relay(&sub);
            }
            return;
        }
        // EVENTs go out from the scan's sink, so a REQ never holds
        // more than one chunk of payloads.
        let conns = &self.conns;
        let scanned = self.store.query(
            &filters,
            &gate,
            now,
            self.limits.req.max_filter_limit,
            self.config.worker.max_scan_rows,
            &mut |hit| {
                if let Some(c) = conns.get(&conn) {
                    c.socket.send(&event_frame(&sub.id, &hit.json));
                }
            },
        );
        if scanned.is_err() {
            self.send(conn, &closed_frame(&sub.id, "error: internal error"));
            if let Some(c) = self.conns.get_mut(&conn) {
                c.session.close_by_relay(&sub);
            }
            return;
        }
        self.send(conn, &eose_frame(&sub.id));
        let authed = self
            .conns
            .get(&conn)
            .map_or(0, |c| c.session.authenticated().len());
        let authed = u64::try_from(authed).unwrap_or(u64::MAX);
        let persisted = self
            .store
            .exec()
            .execute(
                "INSERT INTO subs (conn, sub_id, filters, authed) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (conn, sub_id) DO UPDATE SET filters = excluded.filters,
                     authed = excluded.authed",
                &[
                    int(conn),
                    Param::Text(sub.id.as_str()),
                    Param::Text(&filters_json),
                    int(authed),
                ],
            )
            .is_ok();
        if persisted {
            self.charge_sub(conn, &sub.id, bytes);
            self.monitors.insert(conn, sub, filters, gate);
        } else {
            self.send(conn, &closed_frame(&sub.id, "error: internal error"));
            if let Some(c) = self.conns.get_mut(&conn) {
                c.session.close_by_relay(&sub);
            }
        }
    }

    /// A `COUNT`: one frame over the stored union, then the relay
    /// closes the sub — a COUNT is a one-shot subscription and
    /// persists nothing to `subs`. The row budget is the smaller of
    /// the COUNT entry budget and the platform's scan-row cap;
    /// hitting it marks the answer `approximate`.
    fn count(&mut self, conn: u64, sub: &SubKey, filters: &[Filter], gate: &ReadGate, now: u64) {
        let budget = usize::try_from(
            self.limits
                .req
                .max_filter_limit_count
                .min(self.config.worker.max_scan_rows as u64),
        )
        .unwrap_or(usize::MAX);
        match self
            .store
            .count(filters, gate, now, budget, Hll::for_filters(filters))
        {
            Ok(result) => self.send(
                conn,
                &count_frame(
                    &sub.id,
                    result.count,
                    result.approximate,
                    result.hll.as_ref(),
                ),
            ),
            Err(_) => self.send(conn, &closed_frame(&sub.id, "error: internal error")),
        }
        if let Some(c) = self.conns.get_mut(&conn) {
            c.session.close_by_relay(sub);
        }
    }

    /// A `CLOSE` (or a relay-side unsubscribe): drop the monitor,
    /// the persisted row, and the byte charge.
    fn unsubscribe(&mut self, conn: u64, sub_id: &SubId) {
        self.monitors.remove(conn, sub_id);
        self.release_sub(conn, sub_id);
        self.exec(
            "DELETE FROM subs WHERE conn = ?1 AND sub_id = ?2",
            &[int(conn), Param::Text(sub_id.as_str())],
        );
    }

    /// Whether charging `bytes` to `(conn, id)` stays within
    /// `[worker] max_subscription_bytes` (`0` = unlimited);
    /// re-subscribing an id replaces its earlier charge.
    fn sub_fits(&self, conn: u64, id: &SubId, bytes: usize) -> bool {
        let budget = self.config.worker.max_subscription_bytes;
        if budget == 0 {
            return true;
        }
        let current = self
            .sub_bytes
            .get(&conn)
            .and_then(|subs| subs.get(id))
            .copied()
            .unwrap_or(0);
        self.subs_bytes - current + bytes <= budget
    }

    /// Charge `bytes` to `(conn, id)` — run [`Relay::sub_fits`]
    /// first.
    fn charge_sub(&mut self, conn: u64, id: &SubId, bytes: usize) {
        if let Some(old) = self
            .sub_bytes
            .entry(conn)
            .or_default()
            .insert(id.clone(), bytes)
        {
            self.subs_bytes -= old;
        }
        self.subs_bytes += bytes;
    }

    /// Release `(conn, id)`'s charge, if any.
    fn release_sub(&mut self, conn: u64, id: &SubId) {
        let Some(subs) = self.sub_bytes.get_mut(&conn) else {
            return;
        };
        if let Some(bytes) = subs.remove(id) {
            self.subs_bytes -= bytes;
        }
        if subs.is_empty() {
            self.sub_bytes.remove(&conn);
        }
    }

    /// Decode a live connection's `subs` row and re-register it in
    /// the session: the subscription comes back under a fresh
    /// generation and a REQ-time read gate (`authed` counts the
    /// pubkeys that had authenticated when the REQ arrived; pubkeys
    /// only append, so the prefix is exact). `None` on a corrupt row.
    /// A free-standing function so `restore_subs` can call it inside
    /// the row callback while the executor holds `self.store`.
    fn decode_sub(
        conns: &mut HashMap<u64, Conn<S>>,
        limits: &Arc<Limits>,
        moderation: &Arc<Moderation>,
        row: &[Value],
    ) -> Option<(SubKey, Arc<[Filter]>, ReadGate)> {
        let uint = |i: usize| match row.get(i) {
            Some(Value::Int(v)) if *v >= 0 => u64::try_from(*v).ok(),
            _ => None,
        };
        let text = |i: usize| match row.get(i) {
            Some(Value::Text(s)) => Some(s.as_str()),
            _ => None,
        };
        let conn = uint(0)?;
        let sub_id = SubId::parse(text(1)?).ok()?;
        let mut parsed = Vec::new();
        for raw in serde_json::from_str::<Vec<&serde_json::value::RawValue>>(text(2)?).ok()? {
            parsed.push(Filter::from_raw(raw).ok()?);
        }
        let authed = uint(3)?;
        let c = conns.get_mut(&conn)?;
        let key = c.session.resume_sub(sub_id);
        let keys = c.session.authenticated();
        let n = usize::try_from(authed)
            .unwrap_or(usize::MAX)
            .min(keys.len());
        let gate = ReadGate::new(
            Arc::clone(&limits.auth),
            keys.get(..n).unwrap_or(&[]).into(),
        )
        .with_moderation(Arc::clone(moderation));
        Some((key, parsed.into(), gate))
    }

    /// One streamed `subs` row: resume the subscription and charge
    /// its filters' `approx_bytes` against the budget — the same
    /// estimate a REQ is charged — or answer the row's primary key
    /// when it should be deleted: over-budget or corrupt state is
    /// dropped, never a reason to brick the open.
    fn restore_row(
        row: &[Value],
        state: &mut Restore<'_, S>,
        budget: usize,
    ) -> Option<(u64, String)> {
        let (conn, sub_id) = sub_pk(row)?;
        let Some((key, filters, gate)) =
            Self::decode_sub(state.conns, state.limits, state.moderation, row)
        else {
            return Some((conn, sub_id));
        };
        let bytes: usize = filters.iter().map(Filter::approx_bytes).sum();
        if budget != 0 && bytes > budget.saturating_sub(*state.subs_bytes) {
            return Some((conn, sub_id));
        }
        *state.subs_bytes += bytes;
        state
            .sub_bytes
            .entry(conn)
            .or_default()
            .insert(key.id.clone(), bytes);
        state.monitors.insert(conn, key, filters, gate);
        None
    }

    /// `SELECT COUNT(*) FROM subs` for the wake restore summary.
    fn sub_row_count(&self) -> Result<usize, RelayError> {
        let mut count = 0usize;
        self.store
            .exec()
            .query("SELECT COUNT(*) FROM subs", &[], &mut |row| {
                if let Some(Value::Int(v)) = row.first()
                    && let Ok(v) = usize::try_from(*v)
                {
                    count = v;
                }
                ControlFlow::Continue(())
            })
            .map_err(|err| StoreError::Sql(Box::new(err)))?;
        Ok(count)
    }

    /// Reload the live connections' `subs` rows. One statement
    /// deletes the rows of connections that are not live (a crash or
    /// deploy strands them) before any row is read, then each
    /// remaining row streams through decode into the monitor index —
    /// the set never materializes, so a huge table cannot OOM the
    /// wake into a crash loop. Rows charge
    /// `[worker] max_subscription_bytes` the same as a REQ; rows
    /// over the budget and corrupt rows are deleted. Only executor
    /// failures abort the open.
    fn restore_subs(&mut self) -> Result<(), RelayError> {
        let live = format!(
            "[{}]",
            self.conns
                .keys()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let rows_before = self.sub_row_count()?;
        self.store
            .exec()
            .execute(
                "DELETE FROM subs WHERE conn NOT IN (SELECT value FROM json_each(?1))",
                &[Param::Text(&live)],
            )
            .map_err(|err| StoreError::Sql(Box::new(err)))?;
        let stale = rows_before - self.sub_row_count()?;
        let budget = self.config.worker.max_subscription_bytes;
        let mut doomed = Vec::new();
        {
            // Row-at-a-time decode: the callback borrows the fields it
            // touches so `self.store` can stay borrowed by the query.
            let mut state = Restore {
                conns: &mut self.conns,
                limits: &self.limits,
                moderation: &self.moderation,
                monitors: &mut self.monitors,
                sub_bytes: &mut self.sub_bytes,
                subs_bytes: &mut self.subs_bytes,
            };
            self.store
                .exec()
                .query(
                    "SELECT conn, sub_id, filters, authed FROM subs",
                    &[],
                    &mut |row| {
                        doomed.extend(Self::restore_row(&row, &mut state, budget));
                        ControlFlow::Continue(())
                    },
                )
                .map_err(|err| StoreError::Sql(Box::new(err)))?;
        }
        self.restored_subs = self.monitors.len();
        // Stale-connection rows swept above plus the corrupt or
        // over-budget rows doomed while streaming.
        self.dropped_subs = stale + doomed.len();
        for (conn, sub_id) in doomed {
            self.exec(
                "DELETE FROM subs WHERE conn = ?1 AND sub_id = ?2",
                &[int(conn), Param::Text(&sub_id)],
            );
        }
        Ok(())
    }
}

/// Decode a `subs` row's primary key — the `(conn, sub_id)` pair
/// needed to delete the row. `None` when the columns are not their
/// declared types; such a row cannot even be addressed, so it is
/// left for the next wake's sweep.
fn sub_pk(row: &[Value]) -> Option<(u64, String)> {
    let conn = match row.first() {
        Some(Value::Int(v)) if *v >= 0 => u64::try_from(*v).ok()?,
        _ => return None,
    };
    let sub_id = match row.get(1) {
        Some(Value::Text(s)) => s.clone(),
        _ => return None,
    };
    Some((conn, sub_id))
}
