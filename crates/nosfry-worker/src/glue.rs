//! The Cloudflare Workers shell: the entry `fetch` routes every
//! request to the single `relay` Durable Object, which wraps the
//! host-testable [`Relay`] behind the hibernation WebSocket API and
//! `transactionSync`.
//!
//! [`worker::Storage::transaction`] runs the KV transaction path, so
//! [`DoSql::transaction`] calls `transactionSync` on the raw
//! `DurableObjectStorage` through `js-sys` instead.
//!
//! The write policy is an optional `POLICY` service binding: each
//! event reaching the policy point is `POST`ed to it as the strfry
//! request line and its `{"id","action","msg"}` answer finishes the
//! publish. Unlike the native plugin's serial stdio pipe, checks on
//! different connections interleave inside the object while a fetch
//! is in flight — a service-bound policy must not rely on ordering.

#![allow(
    tail_expr_drop_order,
    clippy::future_not_send,
    clippy::unused_async_trait_impl,
    reason = "workerd is single-threaded so futures and RefCell state never cross threads; the workers-rs and wasm-bindgen macros generate temporaries whose drop order changes under Rust 2024; the DurableObject trait mandates async signatures even for handlers without awaits"
)]

use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::OnceLock;
use std::time::Duration;

use js_sys::{Date, Function, Reflect};
use nosfry_core::message::notice_frame;
use nosfry_core::policy::{self, Decision};
use nosfry_sql::{Executor, Param, SqlStore, StoreError, Value};
use wasm_bindgen::closure::ScopedClosure;
use wasm_bindgen::{JsCast, JsValue};
use worker::{
    Context, DurableObject, Env, Error, Fetcher, Method, Request, RequestInit, Response, Result,
    ScheduledTime, State, WebSocket, WebSocketIncomingMessage, WebSocketPair, console_error,
    console_log, durable_object, event,
};

use crate::config::Config;
use crate::relay::{Attachment, PolicyCheck, Relay, Socket};

/// The `NOSFRY_CONFIG` variable's TOML, parsed once per isolate —
/// the variable cannot change between requests, and the entry
/// `fetch` needs only `location_hint` out of it. A parse error still
/// answers 500 and is logged every request.
fn config(env: &Env) -> Result<Config> {
    static PARSED: OnceLock<Result<Config, String>> = OnceLock::new();
    match PARSED.get_or_init(|| {
        let toml = env
            .var("NOSFRY_CONFIG")
            .map(|v| v.to_string())
            .unwrap_or_default();
        Config::parse(&toml).map_err(|err| err.to_string())
    }) {
        Ok(config) => Ok(config.clone()),
        Err(err) => {
            console_error!("invalid NOSFRY_CONFIG: {err}");
            Err(Error::from(err.clone()))
        }
    }
}

/// Install the panic hook once per isolate: a Rust panic aborts the
/// isolate — the runtime reports it as `Network connection lost` —
/// so the message must reach the workerd log to be diagnosable.
#[event(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// Route by path: `/` reaches the `relay` object (honouring
/// `[worker] location_hint`), the `NodeInfo` paths are answered
/// here from config, and anything else is a 404 that never wakes
/// the object — like native, the relay answers only its own
/// endpoints.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let config = config(&env)?;
    let path = req.path();
    match path.as_str() {
        "/" => {}
        "/.well-known/nodeinfo" | "/nodeinfo/2.1" => {
            return nodeinfo_response(&config, &path, &req.method());
        }
        _ => return Response::error("not found", 404),
    }
    let namespace = env.durable_object("RELAY")?;
    let hint = &config.worker.location_hint;
    let stub = if hint.is_empty() {
        namespace.get_by_name("relay")?
    } else {
        namespace.get_by_name_with_location_hint("relay", hint)?
    };
    stub.fetch_with_request(req).await
}

/// The same CORS headers the native `with_cors` emits
/// ([`nosfry_core::site::CORS_HEADERS`]).
fn with_cors(response: Response) -> Result<Response> {
    for (name, value) in nosfry_core::site::CORS_HEADERS {
        response.headers().set(name, value)?;
    }
    Ok(response)
}

/// The entry Worker's static `NodeInfo` answers: the discovery
/// document 404s without a `service_url`, the 2.1 document always
/// answers, and only `GET` is accepted — like the native routes.
fn nodeinfo_response(config: &Config, path: &str, method: &Method) -> Result<Response> {
    if *method != Method::Get {
        return Response::error("method not allowed", 405);
    }
    let (body, content_type) = if path == "/nodeinfo/2.1" {
        (
            nosfry_core::site::nodeinfo(),
            "application/json; profile=\"http://nodeinfo.diaspora.software/ns/schema/2.1#\"",
        )
    } else {
        let Some(body) = nosfry_core::site::nodeinfo_links(&config.relay.service_url) else {
            return Response::error("not found", 404);
        };
        (body, "application/json")
    };
    let response = Response::ok(body)?;
    response.headers().set("Content-Type", content_type)?;
    with_cors(response)
}

/// Connection ids are bound into `subs` rows, so they must stay
/// inside the JavaScript safe-integer range.
const JS_MAX: u64 = (1 << 53) - 1;

/// `ctx.storage.sql` as a [`nosfry_sql::Executor`].
struct DoSql {
    /// `ctx.storage`: `sql()` hands out `SqlStorage` handles, and
    /// `as_raw()` reaches the unbound `transactionSync`.
    storage: worker::Storage,
}

/// A statement-level failure from workerd's SQL surface.
#[derive(Debug)]
struct DoSqlError(String);

impl std::fmt::Display for DoSqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DoSqlError {}

impl DoSqlError {
    fn sql(self) -> StoreError {
        StoreError::Sql(Box::new(self))
    }
}

fn js_error(err: &Error) -> DoSqlError {
    DoSqlError(err.to_string())
}

fn js_value_error(value: JsValue) -> DoSqlError {
    js_error(&Error::from(value))
}

fn storage_param(param: &Param<'_>) -> Result<worker::SqlStorageValue, DoSqlError> {
    Ok(match param {
        Param::Null => worker::SqlStorageValue::Null,
        &Param::Int(v) => worker::SqlStorageValue::try_from_i64(v).map_err(|e| js_error(&e))?,
        Param::Text(s) => worker::SqlStorageValue::from(*s),
        Param::Blob(b) => worker::SqlStorageValue::from(b.to_vec()),
    })
}

fn storage_value(value: worker::SqlStorageValue) -> Value {
    match value {
        worker::SqlStorageValue::Null => Value::Null,
        worker::SqlStorageValue::Boolean(b) => Value::Int(i64::from(b)),
        worker::SqlStorageValue::Integer(i) => Value::Int(i),
        worker::SqlStorageValue::Float(f) => Value::Real(f),
        worker::SqlStorageValue::String(s) => Value::Text(s),
        worker::SqlStorageValue::Blob(b) => Value::Blob(b),
    }
}

impl Executor for DoSql {
    type Error = DoSqlError;

    fn query(
        &self,
        sql: &str,
        params: &[Param<'_>],
        row: &mut dyn FnMut(Vec<Value>) -> ControlFlow<()>,
    ) -> Result<(), Self::Error> {
        let bindings = params
            .iter()
            .map(storage_param)
            .collect::<Result<Vec<_>, _>>()?;
        let cursor = self
            .storage
            .sql()
            .exec(sql, Some(bindings))
            .map_err(|e| js_error(&e))?;
        for result in cursor.raw() {
            let values = result
                .map_err(|e| js_error(&e))?
                .into_iter()
                .map(storage_value)
                .collect();
            if row(values).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn execute(&self, sql: &str, params: &[Param<'_>]) -> Result<(), Self::Error> {
        let bindings = params
            .iter()
            .map(storage_param)
            .collect::<Result<Vec<_>, _>>()?;
        // `exec` runs eagerly in workerd; dropping the cursor leaves
        // its rows unread, which an execute never inspects anyway.
        drop(
            self.storage
                .sql()
                .exec(sql, Some(bindings))
                .map_err(|e| js_error(&e))?,
        );
        Ok(())
    }

    fn transaction<T>(&self, f: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
        // workers-rs binds the KV `transaction`, not the SQL
        // `transactionSync`: call it on the raw `DurableObjectStorage`.
        let raw: JsValue = AsRef::<JsValue>::as_ref(self.storage.as_raw()).clone();
        let txn = Reflect::get(&raw, &JsValue::from_str("transactionSync"))
            .and_then(JsCast::dyn_into::<Function>)
            .map_err(|e| js_value_error(e).sql())?;
        let mut outcome = None;
        let mut body = Some(f);
        let called = {
            let outcome = &mut outcome;
            let mut run =
                move || -> Result<JsValue, JsValue> { invoke_body(&mut body, &mut *outcome) };
            let closure =
                ScopedClosure::<dyn FnMut() -> Result<JsValue, JsValue>>::borrow_mut(&mut run);
            txn.call1(&raw, closure.as_js_value())
        };
        match (called, outcome) {
            (_, Some(result)) => result,
            // Our callback always records an outcome, even when it
            // throws; a bare `call1` failure is a workerd error.
            (Ok(_), None) => Err(DoSqlError(
                "transactionSync returned without invoking its callback".into(),
            )
            .sql()),
            (Err(js), None) => Err(js_value_error(js).sql()),
        }
    }
}

/// The `transactionSync` callback body: run `f`, record the outcome,
/// and throw on error so workerd rolls the transaction back.
fn invoke_body<T, F>(
    body: &mut Option<F>,
    outcome: &mut Option<Result<T, StoreError>>,
) -> Result<JsValue, JsValue>
where
    F: FnOnce() -> Result<T, StoreError>,
{
    let Some(body) = body.take() else {
        return Err(JsValue::from_str("transaction body ran twice"));
    };
    match body() {
        Ok(value) => {
            *outcome = Some(Ok(value));
            Ok(JsValue::UNDEFINED)
        }
        Err(err) => {
            // Throwing rolls the transaction back; the real
            // `StoreError` comes out through `outcome`.
            let message = err.to_string();
            *outcome = Some(Err(err));
            Err(js_sys::Error::new(&message).into())
        }
    }
}

/// A hibernatable `WebSocket` as a [`Socket`].
struct DoSocket(WebSocket);

impl Socket for DoSocket {
    fn send(&self, text: &str) {
        // A failure means the socket is already gone; the relay's own
        // bookkeeping is unaffected either way.
        drop(self.0.send_with_str(text));
    }

    fn close(&self, code: u16, reason: &str) {
        drop(self.0.close(Some(code), Some(reason)));
    }
}

/// One hibernated socket's decoded attachment. A missing or
/// undecodable attachment strands only that socket — it is closed
/// 1011 `internal error` while the rest restore normally, instead of
/// failing the whole object.
fn socket_attachment(ws: &WebSocket) -> Option<Attachment> {
    if let Ok(Some(attachment)) = ws.deserialize_attachment() {
        Some(attachment)
    } else {
        drop(ws.close(Some(1011), Some("internal error")));
        None
    }
}

/// A fresh connection id in the JavaScript-safe range, regenerated
/// until unused — a random id could collide with a live connection
/// and overwrite it in `conns`.
fn fresh_conn_id<E: Executor, S: Socket>(relay: &Relay<E, S>) -> Result<u64> {
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).map_err(|e| Error::from(e.to_string()))?;
        let conn = u64::from_ne_bytes(bytes) & JS_MAX;
        if !relay.is_live(conn) {
            return Ok(conn);
        }
    }
}

/// The hibernatable relay: one Durable Object named `relay` holding
/// all live connections.
#[durable_object]
pub struct RelayObject {
    state: State,
    /// `Err` when `new` failed to build the relay: the object keeps
    /// the message and answers every later request with a 500.
    relay: RefCell<Result<Relay<DoSql, DoSocket>, String>>,
    /// The scheduled alarm in unix milliseconds; `None` also means
    /// "not yet loaded from storage" — `schedule_alarm` reads it once
    /// when the cache is empty.
    alarm: Cell<Option<u64>>,
    /// The `POLICY` service binding; `None` means no write policy.
    policy: Option<Fetcher>,
    /// `[relay.write_policy] timeout_seconds` — the check deadline.
    policy_timeout: Duration,
}

impl std::fmt::Debug for RelayObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayObject").finish_non_exhaustive()
    }
}

impl RelayObject {
    /// The 500 every request gets once `new` failed.
    fn down_response(err: &str) -> Result<Response> {
        console_error!("relay object failed to initialize: {err}");
        Response::error("internal error", 500)
    }

    /// Handle a WebSocket upgrade request: cap check, `accept` on the
    /// runtime and the relay, attachment, then the 101.
    fn upgrade(&self, ip: Option<IpAddr>) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        let attachment = {
            let mut borrowed = self.relay.borrow_mut();
            let Ok(relay) = borrowed.as_mut() else {
                return Self::down_response("unreachable: checked in fetch");
            };
            if !relay.admits(ip) {
                return Response::error("too many connections", 503);
            }
            let conn = fresh_conn_id(relay)?;
            let mut challenge_bytes = [0u8; 32];
            getrandom::fill(&mut challenge_bytes).map_err(|e| Error::from(e.to_string()))?;
            let challenge = faster_hex::hex_string(&challenge_bytes);
            self.state.accept_web_socket(&pair.server);
            relay
                .accept(DoSocket(pair.server.clone()), conn, ip, challenge)
                .map_err(|e| Error::from(e.to_string()))?
        };
        pair.server.serialize_attachment(&attachment)?;
        Response::from_websocket(pair.client)
    }

    /// The NIP-86 management `POST`: read at most
    /// [`management::BODY_LIMIT`] bytes off the stream (an honest
    /// `Content-Length` is refused before any read), then let the
    /// relay authorize and dispatch — its `Managed` carries status
    /// and body verbatim.
    async fn manage(&self, mut req: Request) -> Result<Response> {
        let headers = req.headers();
        let content_type = headers.get("Content-Type")?;
        let authorization = headers.get("Authorization")?;
        if headers
            .get("Content-Length")?
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|len| len > nosfry_core::management::BODY_LIMIT as u64)
        {
            return with_cors(Response::error(
                "Failed to buffer the request body: length limit exceeded",
                413,
            )?);
        }
        let Some(body) = Self::buffered_body(&mut req).await? else {
            return with_cors(Response::error(
                "Failed to buffer the request body: length limit exceeded",
                413,
            )?);
        };
        let managed = {
            let mut borrowed = self.relay.borrow_mut();
            let Ok(relay) = borrowed.as_mut() else {
                return Self::down_response("unreachable: checked in fetch");
            };
            relay.manage(
                content_type.as_deref(),
                authorization.as_deref(),
                &body,
                worker::Date::now().as_millis() / 1000,
            )
        };
        let json = managed.body.starts_with('{');
        let response = Response::ok(managed.body)?.with_status(managed.status);
        if json {
            response.headers().set("Content-Type", "application/json")?;
        }
        // Every NIP-86 answer carries CORS — a browser admin tool
        // must be able to read the 401/200 replies.
        with_cors(response)
    }

    /// Buffer the request body: `None` when it exceeds
    /// [`management::BODY_LIMIT`] — the stream stops without reading
    /// further. A POST without a body streams nothing.
    async fn buffered_body(req: &mut Request) -> Result<Option<Vec<u8>>> {
        use futures_util::StreamExt;
        // A POST without a body has no stream — an empty body.
        let Ok(mut stream) = req.stream() else {
            return Ok(Some(Vec::new()));
        };
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk?);
            if body.len() > nosfry_core::management::BODY_LIMIT {
                return Ok(None);
            }
        }
        Ok(Some(body))
    }

    /// Schedule the alarm at `ms` (unix milliseconds) when it is
    /// earlier than the scheduled one. An empty cache triggers the
    /// one `get_alarm` read; a stored alarm keeps it.
    async fn schedule_alarm(&self, ms: u64) -> Result<()> {
        let current = match self.alarm.get() {
            Some(current) => Some(current),
            None => self
                .state
                .storage()
                .get_alarm()
                .await?
                .and_then(|t| u64::try_from(t).ok()),
        };
        if current.is_some_and(|current| current <= ms) {
            return Ok(());
        }
        self.state
            .storage()
            .set_alarm(ScheduledTime::new(Date::new(&(ms as f64).into())))
            .await?;
        self.alarm.set(Some(ms));
        Ok(())
    }

    /// Apply the alarm effects of a `message`/`decided` call: move
    /// the alarm forward for the earliest expiration, and run it now
    /// when vanish work queued.
    async fn apply_effects(&self, effects: &crate::relay::Effects) -> Result<()> {
        if let Some(expiration) = effects.expiration {
            self.schedule_alarm(expiration.saturating_mul(1000)).await?;
        }
        if effects.vanish {
            self.schedule_alarm(worker::Date::now().as_millis()).await?;
        }
        Ok(())
    }

    /// Ask the `POLICY` service binding about `check` and finish the
    /// publish: POST the strfry request line, race
    /// `[relay.write_policy] timeout_seconds`, and parse the verdict.
    /// Every failure — fetch error, non-2xx, timeout, an over-long or
    /// unparseable body, an id mismatch — maps to the native
    /// `error: internal error` reject, logged at error.
    async fn run_policy(&self, check: &PolicyCheck) -> Result<()> {
        use futures_util::future::{self, Either};
        let id = check.event.id().to_string();
        let decision = match &self.policy {
            None => {
                console_error!("write policy enabled without a POLICY binding");
                Decision::Reject("error: internal error".to_owned())
            }
            Some(fetcher) => {
                let mut init = RequestInit::new();
                init.with_method(Method::Post)
                    .with_body(Some(JsValue::from_str(&check.line)));
                let fetch = fetcher.fetch("https://policy.invalid/", Some(init));
                let delay = worker::Delay::from(self.policy_timeout);
                futures_util::pin_mut!(fetch, delay);
                let answered = match future::select(fetch, delay).await {
                    Either::Left((answered, _)) => answered,
                    Either::Right(_) => {
                        console_error!("write policy timed out");
                        return self
                            .decide(check, Decision::Reject("error: internal error".to_owned()))
                            .await;
                    }
                };
                match answered {
                    Err(error) => {
                        console_error!("write policy fetch failed: {error}");
                        Decision::Reject("error: internal error".to_owned())
                    }
                    Ok(mut response) => match self.policy_response(&mut response, &id).await {
                        Ok(decision) => decision,
                        Err(error) => {
                            console_error!("write policy check failed: {error}");
                            Decision::Reject("error: internal error".to_owned())
                        }
                    },
                }
            }
        };
        self.decide(check, decision).await
    }

    /// Read a policy response body into a [`Decision`]; every failure
    /// mode is an error the caller logs and maps to
    /// `error: internal error`.
    async fn policy_response(&self, response: &mut Response, id: &str) -> Result<Decision, String> {
        if !(200..300).contains(&response.status_code()) {
            return Err(format!("policy answered HTTP {}", response.status_code()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("policy body unreadable: {e}"))?;
        // strfry's maximum record size, applied to the whole body.
        if body.len() > 8192 {
            return Err("policy response exceeds 8192 bytes".to_owned());
        }
        policy::parse_response(&body, id).map_err(|err| format!("bad policy response: {err:?}"))
    }

    /// Hand the policy's verdict to the relay and apply the effects
    /// its answer produced.
    async fn decide(&self, check: &PolicyCheck, decision: Decision) -> Result<()> {
        let effects = {
            let mut borrowed = self.relay.borrow_mut();
            match borrowed.as_mut() {
                Ok(relay) => relay.decided(
                    check.conn,
                    &check.event,
                    decision,
                    worker::Date::now().as_millis(),
                ),
                Err(err) => {
                    console_error!("relay object failed to initialize: {err}");
                    return Ok(());
                }
            }
        };
        self.apply_effects(&effects).await
    }

    /// Reconcile the stored alarm with the wanted time `ms` once on
    /// wake: a crash between a store commit and `set_alarm` would
    /// otherwise strand queued vanish or expiry work forever. The
    /// runtime blocks event delivery on the `block_concurrency_while`
    /// gate — `new` must not await the returned future.
    fn reconcile_alarm(state: &State, ms: u64) {
        let storage = state.storage();
        let _init = state.block_concurrency_while(async move {
            let stored = storage
                .get_alarm()
                .await?
                .and_then(|t| u64::try_from(t).ok());
            if stored.is_none_or(|stored| ms < stored) {
                storage
                    .set_alarm(ScheduledTime::new(Date::new(&(ms as f64).into())))
                    .await?;
            }
            Ok(())
        });
    }

    /// `relay.close` for the socket's attached connection; a missing
    /// or malformed attachment strands its `subs` rows, which the
    /// next `open` purges.
    fn close_connection(&self, ws: &WebSocket) {
        if let Ok(Some(attachment)) = ws.deserialize_attachment::<Attachment>()
            && let Ok(relay) = self.relay.borrow_mut().as_mut()
        {
            relay.close(attachment.conn);
        }
    }
}

impl DurableObject for RelayObject {
    fn new(state: State, env: Env) -> Self {
        // A present `POLICY` binding enables the write policy; its
        // absence is not an error.
        let policy = env.service("POLICY").ok();
        let config = config(&env);
        let policy_timeout = config.as_ref().map_or_else(
            |_| Duration::from_secs(10),
            |c| Duration::from_secs(c.relay.write_policy.timeout_seconds),
        );
        let relay = (|| -> Result<Relay<DoSql, DoSocket>, String> {
            let config = config.map_err(|e| e.to_string())?;
            let storage = state.storage();
            let store = SqlStore::open(DoSql { storage }).map_err(|e| e.to_string())?;
            let mut sockets = Vec::new();
            for ws in state.get_websockets() {
                sockets.extend(socket_attachment(&ws).map(|a| (DoSocket(ws), a)));
            }
            Relay::open(store, config, sockets, policy.is_some()).map_err(|e| e.to_string())
        })();
        // One line per construction — a hibernation wake re-runs
        // this and the restore counts prove the object restarted.
        if let Ok(relay) = relay.as_ref() {
            let (conns, subs, dropped) = relay.restored();
            console_log!(
                "restored {conns} connections, {subs} subscriptions ({dropped} rows dropped)"
            );
        }
        // Reconcile the alarm once on wake: `next_alarm` is
        // synchronous, so the wanted time is computed before any
        // future — the `RefCell` borrow never crosses an await.
        let wanted = relay.as_ref().ok().and_then(|relay| {
            relay
                .next_alarm(worker::Date::now().as_millis() / 1000)
                .ok()
                .flatten()
        });
        if let Some(secs) = wanted {
            Self::reconcile_alarm(&state, secs.saturating_mul(1000));
        }
        Self {
            state,
            relay: RefCell::new(relay),
            alarm: Cell::new(None),
            policy,
            policy_timeout,
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if let Err(err) = self.relay.borrow().as_ref() {
            return Self::down_response(err);
        }
        if req.method() == Method::Options {
            return with_cors(Response::empty()?.with_status(204));
        }
        let headers = req.headers();
        // NIP-86: a blocked client address is refused before upgrades,
        // NIP-11, and the management RPC — the native order.
        let ip = headers
            .get("CF-Connecting-IP")?
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        if self
            .relay
            .borrow()
            .as_ref()
            .is_ok_and(|relay| relay.ip_blocked(ip))
        {
            return with_cors(Response::empty()?.with_status(403));
        }
        if headers
            .get("Upgrade")?
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        {
            return self.upgrade(ip);
        }
        if req.method() == Method::Post {
            return self.manage(req).await;
        }
        if req.method() == Method::Get
            && headers
                .get("Accept")?
                .is_some_and(|v| v.contains("application/nostr+json"))
        {
            let mut borrowed = self.relay.borrow_mut();
            return match borrowed.as_mut() {
                Ok(relay) => {
                    let response = Response::ok(relay.nip11())?;
                    response
                        .headers()
                        .set("Content-Type", "application/nostr+json")?;
                    with_cors(response)
                }
                Err(err) => Self::down_response(err),
            };
        }
        let mut borrowed = self.relay.borrow_mut();
        match borrowed.as_mut() {
            Ok(relay) => {
                let response = Response::ok(relay.landing())?;
                response
                    .headers()
                    .set("Content-Type", "text/html; charset=utf-8")?;
                for (name, value) in nosfry_core::site::LANDING_HEADERS {
                    response.headers().set(name, value)?;
                }
                Ok(response)
            }
            Err(err) => Self::down_response(err),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let WebSocketIncomingMessage::String(text) = message else {
            ws.send_with_str(notice_frame("invalid: binary frames are not supported"))?;
            return Ok(());
        };
        let Some(attachment) = ws.deserialize_attachment::<Attachment>()? else {
            // The socket was accepted but never attached; there is no
            // connection state to drive.
            return ws.close(Some(1011), Some("internal error"));
        };
        let mut effects = {
            let mut borrowed = self.relay.borrow_mut();
            match borrowed.as_mut() {
                Ok(relay) => relay.message(attachment.conn, worker::Date::now().as_millis(), &text),
                Err(err) => {
                    console_error!("relay object failed to initialize: {err}");
                    return ws.close(Some(1011), Some("internal error"));
                }
            }
        };
        if let Some(updated) = effects.attachment.take() {
            ws.serialize_attachment(&updated)?;
        }
        // The `RefCell` borrow ended with `effects`; the policy fetch
        // awaits freely and `decided` borrows again.
        if let Some(check) = effects.policy.take() {
            self.run_policy(&check).await?;
        }
        self.apply_effects(&effects).await?;
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        self.close_connection(&ws);
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, error: Error) -> Result<()> {
        console_error!("websocket error: {error}");
        self.close_connection(&ws);
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        // The fired alarm is consumed: clear the cache so an early
        // error below cannot leave the stale (past) time suppressing
        // every later `schedule_alarm` — the next schedule reconciles
        // with `get_alarm`.
        self.alarm.set(None);
        let now = worker::Date::now().as_millis() / 1000;
        let next = {
            let borrowed = self.relay.borrow();
            match borrowed.as_ref() {
                Ok(relay) => relay.alarm(now).map_err(|e| Error::from(e.to_string()))?,
                Err(err) => return Self::down_response(err),
            }
        };
        if let Some(secs) = next {
            let ms = secs.saturating_mul(1000);
            self.state
                .storage()
                .set_alarm(ScheduledTime::new(Date::new(&(ms as f64).into())))
                .await?;
            self.alarm.set(Some(ms));
        } else {
            self.state.storage().delete_alarm().await?;
            self.alarm.set(None);
        }
        Response::empty()
    }
}
