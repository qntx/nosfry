//! NIP-86 relay management API: `POST /` with
//! `Content-Type: application/nostr+json+rpc`, authorized by a NIP-98
//! event (`Authorization: Nostr <base64(event)>`) from a configured
//! admin pubkey. Writes go through the single writer thread; reads
//! answer from the in-memory [`nosfry_core::moderation::Moderation`]
//! snapshot. The protocol itself — content type, limits, NIP-98 gate,
//! request dispatch — lives in [`nosfry_core::management`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
pub(crate) use nosfry_core::management::BODY_LIMIT;
use nosfry_core::management::{Action, AuthError, Request};
use nosfry_core::moderation::ModOp;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use crate::channels::WriterMsg;
use crate::http::{AppState, ip_blocked};

/// Warn-once flag for a management endpoint without `service_url`
/// (every request then fails the `u`-tag check).
static NO_SERVICE_URL_WARNED: AtomicBool = AtomicBool::new(false);

/// `POST /` — the NIP-86 endpoint exists only with a
/// `application/nostr+json+rpc` content type and a non-empty
/// `[relay.management] admins`; anything else falls through to the
/// pre-NIP-86 behavior (405).
pub(crate) async fn handle(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Every NIP-86 answer carries CORS: a browser admin tool's
    // preflight must see POST + Authorization, and it must be able
    // to read the 401/200 replies.
    crate::http::with_cors(answer(&state, peer, headers, body).await)
}

/// The NIP-86 answer for one POST; `handle` adds CORS.
async fn answer(state: &AppState, peer: SocketAddr, headers: HeaderMap, body: Bytes) -> Response {
    if ip_blocked(state, &headers, peer.ip()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let live = state.live.borrow().clone();
    let rpc = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| {
            t.trim()
                .eq_ignore_ascii_case(nosfry_core::management::CONTENT_TYPE)
        });
    if !rpc || live.admins.is_empty() {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let service_url = live.limits.auth.relay();
    let auth = nosfry_core::management::authorize(
        authorization,
        &body,
        now,
        &live.config.events,
        service_url,
        &live.admins,
    );
    if matches!(auth, Err(AuthError::NoServiceUrl))
        && !NO_SERVICE_URL_WARNED.swap(true, Ordering::Relaxed)
    {
        tracing::warn!(
            "relay.management configured without relay.service_url; \
                        NIP-98 `u` checks cannot pass"
        );
    }
    if let Err(error) = auth {
        return unauthorized(error);
    }
    let Ok(text) = std::str::from_utf8(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid utf-8").into_response();
    };
    match serde_json::from_str::<Request<'_>>(text) {
        Err(_) => (StatusCode::BAD_REQUEST, "invalid request json").into_response(),
        Ok(request) => match dispatch(state, &request).await {
            Ok(result) => Json(json!({ "result": result })).into_response(),
            Err(error) => Json(json!({ "error": error })).into_response(),
        },
    }
}

/// `401 {"error": "unauthorized: <reason>"}`.
fn unauthorized(error: AuthError) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": format!("unauthorized: {error}") })),
    )
        .into_response()
}

/// Dispatch one request. `Err` becomes the `{"error": …}` response
/// body at HTTP 200 (method-level errors are not HTTP errors).
async fn dispatch(state: &AppState, request: &Request<'_>) -> Result<Value, String> {
    let m = state.moderation.borrow().clone();
    match nosfry_core::management::action(request, &m) {
        Ok(Action::Respond(result)) => Ok(result),
        Ok(Action::Apply(op)) => apply(state, op).await,
        Err(error) => Err(error),
    }
}

/// Send `op` to the writer thread, then rebuild the cached NIP-11
/// document and landing page from the latest moderation snapshot.
/// The writer already published the snapshot in commit order before
/// replying, and `send_modify` serializes the rebuild against other
/// publishers — ops are rare admin calls, so every one rebuilds
/// unconditionally.
async fn apply(state: &AppState, op: ModOp) -> Result<Value, String> {
    let (reply, rx) = oneshot::channel();
    state
        .conn
        .writer
        .send(WriterMsg::Moderate { op, reply })
        .await
        .map_err(|_| "error: internal error".to_owned())?;
    rx.await
        .map_err(|_| "error: internal error".to_owned())?
        .map_err(|err| format!("error: {err}"))?;
    state.live_tx.send_modify(|live| {
        let moderation = state.moderation.borrow().clone();
        let mut next = (**live).clone();
        next.nip11 = crate::http::nip11(&next.config, &next.limits, &moderation).into();
        next.landing = crate::http::landing(&next.config, &next.limits, &moderation).into();
        *live = Arc::new(next);
    });
    Ok(Value::Bool(true))
}
