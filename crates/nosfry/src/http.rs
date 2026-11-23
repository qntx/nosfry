//! axum HTTP surface: WebSocket upgrade, NIP-11 document, landing page.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, get};
use nosfry_core::moderation::Moderation;
use tokio::sync::watch;
use tracing::Instrument as _;
use yawc::{IncomingUpgrade, Options};

use crate::Live;
use crate::config::Config;
use crate::connection;
use crate::limiter::ConnectionLimiter;
use crate::management;
use crate::metrics::Metrics;
use crate::peer::{self, Origin, Peer};

/// Everything a connection handler needs.
#[derive(Clone)]
pub(crate) struct AppState {
    /// Live-reloadable state (config, limits, NIP-11, policy).
    pub(crate) live: watch::Receiver<Arc<Live>>,
    /// Connection dispatch.
    pub(crate) conn: connection::Handle,
    /// Process-wide counters.
    pub(crate) metrics: Arc<Metrics>,
    /// Simultaneous-connection caps.
    pub(crate) limiter: Arc<ConnectionLimiter>,
    /// Server-wide deflate state for connections that negotiate no
    /// context takeover; sized for the messages compressed at the same
    /// moment, not for connections.
    pub(crate) deflate_pool: yawc::DeflatePool,
    /// Process-wide reserved sync-storage bytes (the
    /// `nosfry_sync_memory_bytes` gauge).
    pub(crate) sync_memory: Arc<std::sync::atomic::AtomicUsize>,
    /// Process-wide charged live-subscription bytes (the
    /// `nosfry_subscription_bytes` gauge).
    pub(crate) subscription_bytes: Arc<std::sync::atomic::AtomicUsize>,
    /// Per-reader scan-job budgets, summed into the
    /// `nosfry_reader_jobs` gauge. The inboxes' senders stay with
    /// `Server` — holding them here would keep the reader channels
    /// connected past `stop`'s `drop` while router clones live.
    pub(crate) reader_jobs: Arc<[Arc<crate::channels::JobBudget>]>,
    /// Latest NIP-86 snapshot; read-only copies for the handlers.
    /// The writer thread publishes in commit order on this channel —
    /// nothing else may send.
    pub(crate) moderation: watch::Receiver<Arc<Moderation>>,
    /// [`Live`] sender — `changerelay*` ops rebuild `nip11`.
    pub(crate) live_tx: watch::Sender<Arc<Live>>,
    /// The running blob service (the `blossom` cargo feature),
    /// `Some` only when `[blossom] enabled` — set by `serve()`.
    #[cfg(feature = "blossom")]
    pub(crate) blossom: Option<crate::blossom::Blossom>,
}

/// `DeflatePool` has no `Debug`; every other field does.
impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("live", &self.live)
            .field("conn", &self.conn)
            .field("metrics", &self.metrics)
            .field("limiter", &self.limiter)
            .field("sync_memory", &self.sync_memory)
            .field("subscription_bytes", &self.subscription_bytes)
            .field("moderation", &self.moderation)
            .field("live_tx", &self.live_tx)
            .finish_non_exhaustive()
    }
}

/// Build the application router. `/metrics` exists only when
/// `[relay] metrics` is enabled — otherwise it falls through to the
/// default 404 like any unknown path.
pub(crate) fn router(state: AppState) -> Router {
    let router = Router::new()
        .route(
            "/",
            get(root)
                .post(management::handle)
                .on(MethodFilter::OPTIONS, preflight)
                .route_layer(DefaultBodyLimit::max(management::BODY_LIMIT)),
        )
        .route("/.well-known/nodeinfo", get(nodeinfo_links))
        .route("/nodeinfo/2.1", get(nodeinfo));
    let router = if state.live.borrow().config.relay.metrics {
        router.route("/metrics", get(metrics))
    } else {
        router
    };
    router.with_state(state)
}

/// Prometheus text exposition format (0.0.4), no CORS.
async fn metrics(State(state): State<AppState>) -> Response {
    #[cfg_attr(
        not(feature = "blossom"),
        expect(unused_mut, reason = "only blossom appends to the body")
    )]
    let mut body = state.metrics.render(
        state.limiter.total(),
        state
            .conn
            .outbound_total
            .load(std::sync::atomic::Ordering::Relaxed),
        state.sync_memory.load(std::sync::atomic::Ordering::Relaxed),
        state
            .subscription_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        state
            .reader_jobs
            .iter()
            .map(|budget| budget.jobs.load(std::sync::atomic::Ordering::Relaxed))
            .sum(),
    );
    #[cfg(feature = "blossom")]
    if let Some(blossom) = &state.blossom {
        body.push_str(&blossom.render_metrics());
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

/// Apply [`nosfry_core::site::CORS_HEADERS`] — shared by the
/// preflight, NIP-11, `NodeInfo`, and every NIP-86 response (the
/// management handler wraps its answer in this).
pub(crate) fn with_cors(mut response: Response) -> Response {
    for (name, value) in nosfry_core::site::CORS_HEADERS {
        response.headers_mut().insert(
            header::HeaderName::from_static(name),
            header::HeaderValue::from_static(value),
        );
    }
    response
}

async fn preflight() -> Response {
    with_cors(StatusCode::NO_CONTENT.into_response())
}

/// `/.well-known/nodeinfo`: discovery pointing at `/nodeinfo/2.1` on
/// the canonical URL's host — 404 when the relay has no name.
async fn nodeinfo_links(State(state): State<AppState>) -> Response {
    let service_url = state.live.borrow().config.relay.service_url().to_owned();
    let Some(body) = nosfry_core::site::nodeinfo_links(&service_url) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    with_cors(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

/// `/nodeinfo/2.1`: the `NodeInfo` 2.1 document.
async fn nodeinfo() -> Response {
    with_cors(
        (
            [(
                header::CONTENT_TYPE,
                "application/json; profile=\"http://nodeinfo.diaspora.software/ns/schema/2.1#\"",
            )],
            nosfry_core::site::nodeinfo(),
        )
            .into_response(),
    )
}

/// `Onion-Location` header name (`http://<addr>.onion/` value,
/// computed per [`Live`] snapshot).
const ONION_LOCATION: header::HeaderName = header::HeaderName::from_static("onion-location");

/// The `Onion-Location` advertisement value: `http://<first onion
/// host>/` when `relay.onion.onion_location` is set and the relay has
/// a derived onion URL; `None` otherwise.
pub(crate) fn onion_location(relay: &crate::config::Relay) -> Option<header::HeaderValue> {
    if !relay.onion.onion_location {
        return None;
    }
    let host = relay.onion_urls.first()?.strip_prefix("ws://")?;
    header::HeaderValue::from_str(&format!("http://{host}/")).ok()
}

/// Insert `Onion-Location` into a response unless the request already
/// arrived over the onion — advertising it there would send clients
/// in circles.
fn with_onion_location(response: Response, live: &Live, origin: &Origin) -> Response {
    if origin.is_onion() {
        return response;
    }
    let mut response = response;
    if let Some(value) = &live.onion_location {
        response.headers_mut().insert(ONION_LOCATION, value.clone());
    }
    response
}

async fn root(State(state): State<AppState>, request: Request) -> Response {
    let (mut parts, _body) = request.into_parts();
    // The accept path always inserts `Origin`; missing means a
    // broken wiring path, not a client error.
    let Some(origin) = parts.extensions.get::<Origin>().cloned() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let (peer, fell_back) = peer::resolve(&origin, &parts.headers);
    if fell_back {
        peer::warn_fallback(&origin.listener);
    }
    if ip_blocked(&state, &peer) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let wants_upgrade = parts
        .headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if wants_upgrade && let Some(response) = websocket(&state, &mut parts, &origin, &peer).await {
        return response;
    }
    let accepts_nostr = parts
        .headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/nostr+json"));
    if accepts_nostr {
        return with_onion_location(
            with_cors(
                (
                    [(header::CONTENT_TYPE, "application/nostr+json")],
                    state.live.borrow().nip11.clone(),
                )
                    .into_response(),
            ),
            &state.live.borrow(),
            &origin,
        );
    }
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8");
    for (name, value) in nosfry_core::site::LANDING_HEADERS {
        builder = builder.header(name, value);
    }
    let response = builder
        .body(Body::from(state.live.borrow().landing.clone()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    with_onion_location(response, &state.live.borrow(), &origin)
}

/// Whether the request's peer — resolved `real_ip_header`-aware, the
/// same identity the per-peer limiter charges — is an IP on the
/// NIP-86 block list. A listener peer has no address and is never
/// IP-blocked. Checked before upgrades, NIP-11, and the management
/// RPC — existing WebSocket connections are not cut off (block
/// applies to new requests only).
pub(crate) fn ip_blocked(state: &AppState, peer: &Peer) -> bool {
    let Peer::Ip(ip) = peer else { return false };
    state.moderation.borrow().ip_blocked(ip)
}

/// Initial capacity of each socket's read buffer. 71% of corpus
/// events serialize under 1 KiB and 99.5% under 4 KiB, and yawc
/// returns a grown buffer to this size after a large frame — a bigger
/// start would be per-connection memory spent on nothing.
const READ_BUFFER_CAPACITY: usize = 2 * 1024;

/// Initial capacity of each socket's write buffer. Zero: yawc reserves
/// room per frame and `release_write_buffer` gives the memory back
/// after each flush, so an idle connection holds no write buffer.
const WRITE_BUFFER_CAPACITY: usize = 0;

/// Outbound payloads shorter than this are sent uncompressed: every
/// reply type (OK, EOSE, CLOSED, NOTICE, AUTH, COUNT) is shorter and
/// gains nothing, while every event message is longer.
const COMPRESSION_THRESHOLD: usize = 128;

/// WebSocket options for one upgrade, from the live config snapshot.
/// The deflate level is fixed at `fast()` (level 1, strfry's
/// `deflateInit2` level) — query responses dominate and level 6 costs
/// CPU without buying meaningful bytes at these message sizes. Without
/// context takeover the deflate state comes from `pool`, so an idle
/// connection costs only its socket buffers; with `sliding_window`
/// each connection keeps its own (~370 KiB once used).
fn upgrade_options(relay: &crate::config::Relay, pool: &yawc::DeflatePool) -> Options {
    // yawc refuses a frame of `>= max_payload_read` bytes, so pass
    // one past the limit: `max_websocket_payload_size` stays the
    // inclusive bound, same as the worker's `len > max` check.
    let options = Options::default()
        .with_max_payload_read(relay.max_websocket_payload_size.saturating_add(1))
        .with_read_buffer_capacity(READ_BUFFER_CAPACITY)
        .with_write_buffer_capacity(WRITE_BUFFER_CAPACITY);
    if !relay.compression.enabled {
        return options;
    }
    Options {
        compression: Some(yawc::DeflateOptions {
            level: yawc::CompressionLevel::fast(),
            server_no_context_takeover: !relay.compression.sliding_window,
            client_no_context_takeover: !relay.compression.sliding_window,
            compression_threshold: COMPRESSION_THRESHOLD,
            // Context takeover pins per-connection state and must not
            // borrow from the pool.
            pool: (!relay.compression.sliding_window).then(|| pool.clone()),
        }),
        ..options
    }
}

/// WebSocket upgrade branch of `root`; `None` when the upgrade headers
/// were malformed and the request falls through to NIP-11/plain text.
/// Options come from [`upgrade_options`] on a per-upgrade config
/// snapshot, so a reload only affects connections opened afterwards.
async fn websocket(
    state: &AppState,
    parts: &mut Parts,
    origin: &Origin,
    peer: &Peer,
) -> Option<Response> {
    let Ok(upgrade) = IncomingUpgrade::from_request_parts(parts, &()).await else {
        return None;
    };
    // One snapshot per upgrade: existing connections keep the
    // options they started with.
    let live = state.live.borrow().clone();
    let options = upgrade_options(&live.config.relay, &state.deflate_pool);
    // The cap is charged before the upgrade. Rejections log at
    // debug: a hostile peer may hammer the cap and must not flood
    // the log.
    let Some(permit) = state.limiter.try_acquire(&origin.listener.profile, peer) else {
        tracing::debug!(target: "nosfry::conn", peer = %peer, "connection cap reached");
        state.metrics.connection_rejected();
        return Some((StatusCode::TOO_MANY_REQUESTS, "too many connections").into_response());
    };
    let Ok((response, fut)) = upgrade.upgrade(options) else {
        return Some(StatusCode::BAD_REQUEST.into_response());
    };
    let response = with_onion_location(response.into_response(), &live, origin);
    let buckets = permit.buckets();
    // The listener profile's session limits. Running listeners are
    // validated against `profiles` at load and on every reload, so the
    // entry always exists; a missing one means broken wiring, not a
    // client error.
    let Some(limits) = live.profile_limits.get(origin.listener.profile.as_ref()) else {
        tracing::error!(
            profile = %origin.listener.profile,
            "validated listener profile missing"
        );
        return Some(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };
    let limits = Arc::clone(limits);
    let conn = connection::next_conn_id();
    // INFO level so the span exists under the default `info` filter:
    // nothing logs at info inside it, but every warn/error/debug line
    // of this connection then carries id and peer.
    let span = tracing::info_span!(target: "nosfry::conn", "conn", id = conn, peer = %peer);
    let handle = state.conn.clone();
    let tracker = handle.tracker.clone();
    let peer = peer.clone();
    tracker.spawn(
        async move {
            let _permit = permit;
            match fut.await {
                Ok(mut ws) => {
                    tracing::debug!(target: "nosfry::conn", "connection open");
                    connection::run(&mut ws, &handle, conn, peer, limits, buckets).await;
                }
                Err(err) => tracing::debug!(target: "nosfry::conn", %err, "upgrade failed"),
            }
        }
        .instrument(span),
    );
    Some(response)
}

/// The optional capabilities the `[relay]` configuration advertises
/// in the NIP-11 document and on the landing page.
fn features(
    relay: &crate::config::Relay,
    auth: &nosfry_core::auth::AuthRules,
) -> nosfry_core::info::Features {
    nosfry_core::info::Features {
        count: relay.limits.max_filter_limit_count > 0,
        sync: relay.limits.max_sync_events > 0,
        auth: !relay.service_url().is_empty(),
        gift_wrap: auth.guards_gift_wraps(),
        management: !relay.management.admins.is_empty(),
    }
}

/// The NIP-11 relay information document, rebuilt with the live
/// config whenever the config or moderation snapshot changes.
pub(crate) fn nip11(
    config: &Config,
    limits: &nosfry_core::limits::Limits,
    moderation: &Moderation,
) -> String {
    let relay = &config.relay;
    let document = nosfry_core::info::document(
        &relay.info,
        moderation,
        features(relay, &limits.auth),
        limits,
        relay.max_websocket_payload_size,
    );
    iroh_extension(document, relay)
}

/// When iroh listeners are bound, the NIP-11 document gains
/// `"iroh": {"alpn": "nosfry/http/1", "endpoints": ["<z32>", …]}` —
/// served on a clearnet name, that is the proof the endpoint ids
/// belong to this relay. The core document is re-serialized through
/// `serde_json::Value` (no preserve-order feature, key order
/// unchanged).
#[cfg(feature = "iroh")]
fn iroh_extension(document: String, relay: &crate::config::Relay) -> String {
    if relay.iroh_urls.is_empty() {
        return document;
    }
    let endpoints: Vec<&str> = relay
        .iroh_urls
        .iter()
        .filter_map(|url| {
            url.strip_prefix("ws://")
                .and_then(|rest| rest.strip_suffix(".iroh"))
        })
        .collect();
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&document) else {
        return document;
    };
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "iroh".to_owned(),
            serde_json::json!({
                "alpn": String::from_utf8_lossy(crate::iroh::ALPN),
                "endpoints": endpoints,
            }),
        );
    }
    serde_json::to_string(&value).unwrap_or(document)
}

/// No iroh listeners can exist without the feature.
#[cfg(not(feature = "iroh"))]
const fn iroh_extension(document: String, _relay: &crate::config::Relay) -> String {
    document
}

/// The HTML landing page, rendered alongside [`nip11`] (same
/// effective info, same rebuild points).
pub(crate) fn landing(
    config: &Config,
    limits: &nosfry_core::limits::Limits,
    moderation: &Moderation,
) -> String {
    let relay = &config.relay;
    nosfry_core::site::landing_page(
        &relay.info,
        moderation,
        features(relay, &limits.auth),
        relay.service_url(),
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "unit tests panic on failure"
)]
mod tests {
    use super::*;

    /// The `iroh` NIP-11 extension: endpoints are the listeners'
    /// z32 ids in `[[relay.listen]]` order, the alpn the wire
    /// protocol.
    #[cfg(feature = "iroh")]
    #[test]
    fn nip11_lists_iroh_endpoints() {
        let mut config = Config::default();
        let (a, b) = ("a".repeat(52), "b".repeat(52));
        config.relay.iroh_urls = vec![format!("ws://{a}.iroh"), format!("ws://{b}.iroh")];
        let limits = config.limits().unwrap();
        let document = nip11(&config, &limits, &Moderation::default());
        let value: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert_eq!(
            value["iroh"],
            serde_json::json!({
                "alpn": "nosfry/http/1",
                "endpoints": [a, b],
            }),
            "{document}"
        );
        // And the field is absent without iroh listeners.
        let without = Config::default();
        let bare_limits = without.limits().unwrap();
        let bare = nip11(&without, &bare_limits, &Moderation::default());
        assert!(!bare.contains("\"iroh\""), "{bare}");
    }

    /// Compression off: no `DeflateOptions`, but the payload limit and
    /// the socket buffer capacities still apply.
    #[test]
    fn upgrade_options_without_compression() {
        let config = Config {
            relay: crate::config::Relay {
                compression: crate::config::Compression {
                    enabled: false,
                    sliding_window: false,
                },
                ..Config::default().relay
            },
            ..Config::default()
        };
        let pool = yawc::DeflatePool::new(1);
        let options = upgrade_options(&config.relay, &pool);
        assert!(options.compression.is_none());
        // yawc's cap is exclusive: one past the configured limit.
        assert_eq!(
            options.max_payload_read,
            Some(config.relay.max_websocket_payload_size + 1)
        );
        assert_eq!(options.read_buffer_capacity, Some(READ_BUFFER_CAPACITY));
        assert_eq!(options.write_buffer_capacity, Some(WRITE_BUFFER_CAPACITY));
    }

    /// Default (no context takeover): both directions reset per
    /// message, the pool carries deflate state, small replies go out
    /// uncompressed.
    #[test]
    fn upgrade_options_pooled() {
        let config = Config::default();
        let pool = yawc::DeflatePool::new(1);
        let options = upgrade_options(&config.relay, &pool);
        let deflate = options.compression.expect("deflate negotiated");
        assert!(deflate.server_no_context_takeover);
        assert!(deflate.client_no_context_takeover);
        assert_eq!(deflate.compression_threshold, COMPRESSION_THRESHOLD);
        assert!(deflate.pool.is_some());
    }

    /// `sliding_window` keeps context both ways and must not touch the
    /// pool — its state would pin the shared objects.
    #[test]
    fn upgrade_options_sliding_window() {
        let config = Config {
            relay: crate::config::Relay {
                compression: crate::config::Compression {
                    enabled: true,
                    sliding_window: true,
                },
                ..Config::default().relay
            },
            ..Config::default()
        };
        let pool = yawc::DeflatePool::new(1);
        let options = upgrade_options(&config.relay, &pool);
        let deflate = options.compression.expect("deflate negotiated");
        assert!(!deflate.server_no_context_takeover);
        assert!(!deflate.client_no_context_takeover);
        assert_eq!(deflate.compression_threshold, COMPRESSION_THRESHOLD);
        assert!(deflate.pool.is_none());
    }
}
