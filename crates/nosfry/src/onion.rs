//! Embedded onion-service listeners (cargo feature `onion`).
//!
//! Arti publishes the service, every rendezvous circuit is a
//! connection source, and each accepted stream enters the same
//! HTTP/WebSocket path a TCP listener uses.
//!
//! The Arti client is shared by every `onion:` listener and
//! bootstraps under a supervisor task: clearnet listeners never wait
//! on Tor, and an unreachable Tor network retries on a capped
//! exponential backoff instead of failing the relay. The accept path
//! is split so `serve_circuit` is testable without Tor: the
//! supervisor's adapter turns `RendRequest`s into a stream of
//! `DataStream`s, and `serve_circuit` only sees byte streams.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::status::BootstrapStatus;
use arti_client::{BootstrapBehavior, TorClient};
use futures_util::{Stream, StreamExt as _};
use safelog::DisplayRedacted as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, watch};
use tokio_util::task::TaskTracker;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::config::TokenBucketConfig;
use tor_hsservice::status::State;
use tor_hsservice::{HsNickname, OnionServiceConfig, RendRequest, RunningOnionService};
use tor_keymgr::KeystoreSelector;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, error, info, warn};

use crate::config::{Config, Onion};
use crate::metrics::{self, ONION_STATES};
use crate::peer::{ListenerInfo, Origin, Transport};
use crate::{ServerError, serve_stream};

/// The virtual port onion clients connect to (`BEGIN` requests on
/// any other port are rejected).
const VIRT_PORT: u16 = 80;

/// Bootstrap/launch retry delay: doubles from 1 s up to this cap.
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// Bootstrap/launch retry delay: first retry.
const BACKOFF_MIN: Duration = Duration::from_secs(1);

/// The shared Arti client's concrete type.
pub(crate) type Client = TorClient<PreferredRuntime>;

/// An onion listener's bound state: the shared Arti client, the
/// service's configuration and its derived `ws://` URL.
pub(crate) struct Bound {
    /// The client shared by every onion listener.
    pub(crate) client: Arc<Client>,
    /// What `launch_onion_service` is called with.
    pub(crate) svc_config: OnionServiceConfig,
    /// `ws://<addr>.onion` — canonical or alias depending on
    /// `relay.service_url`.
    pub(crate) url: String,
}

impl fmt::Debug for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bound")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// The Arti client configuration: a `state/` and `cache/` pair under
/// the configured `state_dir`.
pub(crate) fn tor_config(onion: &Onion) -> Result<arti_client::TorClientConfig, ServerError> {
    TorClientConfigBuilder::from_directories(
        onion.state_dir.join("state"),
        onion.state_dir.join("cache"),
    )
    .build()
    .map_err(|err| ServerError::Onion(err.to_string()))
}

/// The `OnionServiceConfig` for one listener: nickname (already
/// slug-validated at config load), the per-circuit stream cap, and
/// the introduction-point token bucket when `intro_rate` is set.
fn svc_config(onion: &Onion, nickname: &str) -> Result<OnionServiceConfig, ServerError> {
    let nickname = nickname
        .parse::<HsNickname>()
        .map_err(|err| ServerError::Onion(err.to_string()))?;
    let mut builder = OnionServiceConfig::builder();
    builder
        .nickname(nickname)
        .max_concurrent_streams_per_circuit(onion.max_streams_per_circuit);
    if onion.intro_rate > 0 {
        builder.rate_limit_at_intro(Some(TokenBucketConfig::new(
            onion.intro_rate,
            onion.intro_burst,
        )));
    }
    builder
        .build()
        .map_err(|err| ServerError::Onion(err.to_string()))
}

/// Generate (or load) the nickname's identity key in the keystore
/// and return its service configuration and `ws://<addr>.onion`
/// URL. Offline: an `OnionService` created this way has no runtime
/// and never touches the network.
fn identity(onion: &Onion, nickname: &str) -> Result<(OnionServiceConfig, String), ServerError> {
    let tor_cfg = tor_config(onion)?;
    let svc_config = svc_config(onion, nickname)?;
    let service = TorClient::<PreferredRuntime>::create_onion_service(&tor_cfg, svc_config.clone())
        .map_err(|err| ServerError::Onion(err.to_string()))?;
    let hsid = service
        .generate_identity_key(KeystoreSelector::Primary)
        .map_err(|err| ServerError::Onion(err.to_string()))?;
    Ok((svc_config, format!("ws://{}", hsid.display_unredacted())))
}

/// The `ws://<addr>.onion` URL of every `onion:` listener, in
/// `[[relay.listen]]` order.
///
/// Generates any missing identity key but never touches the network
/// or opens the database.
///
/// # Errors
///
/// Any keystore/state-dir failure, or no onion listener in the config.
pub fn addresses(config: &Config) -> Result<Vec<String>, ServerError> {
    crate::state_dir::prepare(&config.relay.onion.state_dir, "onion")
        .map_err(ServerError::Onion)?;
    let mut urls = Vec::new();
    for listen in &config.relay.listen {
        if let crate::config::ListenAddress::Onion(nickname) = &listen.address {
            urls.push(identity(&config.relay.onion, nickname)?.1);
        }
    }
    if urls.is_empty() {
        return Err(ServerError::Onion(
            "relay.listen has no onion listener".to_owned(),
        ));
    }
    Ok(urls)
}

/// Prepare one onion listener at `bind` time: secure the state dir,
/// derive its identity (failing startup on keystore or filesystem
/// mistrust errors before anything serves), and create the shared
/// Arti client on first use — manually bootstrapped so `bind` never
/// blocks on the Tor network.
pub(crate) fn bind_service(
    onion: &Onion,
    nickname: &str,
    client: &mut Option<Arc<Client>>,
) -> Result<Bound, ServerError> {
    crate::state_dir::prepare(&onion.state_dir, "onion").map_err(ServerError::Onion)?;
    let tor_cfg = tor_config(onion)?;
    let (svc_config, url) = identity(onion, nickname)?;
    let client = if let Some(client) = client.as_ref() {
        Arc::clone(client)
    } else {
        let created = TorClient::builder()
            .config(tor_cfg)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .map_err(|err| ServerError::Onion(err.to_string()))?;
        *client = Some(Arc::clone(&created));
        created
    };
    Ok(Bound {
        client,
        svc_config,
        url,
    })
}

/// One onion listener's circuit budget and metrics slot.
pub(crate) struct Circuits {
    /// `max_circuits` permits: one per rendezvous circuit being
    /// established or open.
    budget: Arc<Semaphore>,
    /// Circuit number sequence, for debug logs only.
    next: AtomicU64,
    /// This listener's fixed metadata.
    info: Arc<ListenerInfo>,
    /// The listener's `nosfry_onion_*` series.
    metrics: Arc<metrics::OnionListener>,
}

/// An admitted rendezvous circuit: holds its budget permit and the
/// listener identity for as long as it is open.
pub(crate) struct Circuit {
    /// The `max_circuits` slot, released on drop.
    _permit: tokio::sync::OwnedSemaphorePermit,
    /// This circuit's number (debug logs only).
    n: u64,
    /// The listener's fixed metadata.
    info: Arc<ListenerInfo>,
    /// The listener's `nosfry_onion_*` series.
    metrics: Arc<metrics::OnionListener>,
}

impl Drop for Circuit {
    fn drop(&mut self) {
        self.metrics.circuit_close();
    }
}

impl Circuits {
    /// A budget of `max_circuits` circuits for `info`'s listener.
    pub(crate) fn new(
        max_circuits: usize,
        info: Arc<ListenerInfo>,
        metrics: Arc<metrics::OnionListener>,
    ) -> Self {
        Self {
            budget: Arc::new(Semaphore::new(max_circuits)),
            next: AtomicU64::new(1),
            info,
            metrics,
        }
    }

    /// Take a circuit slot; `None` (and `circuits_rejected_total` +1)
    /// when `max_circuits` are already open or being established.
    pub(crate) fn admit(&self) -> Option<Circuit> {
        let Ok(permit) = Arc::clone(&self.budget).try_acquire_owned() else {
            self.metrics.circuit_rejected();
            return None;
        };
        self.metrics.circuit_open();
        Some(Circuit {
            _permit: permit,
            n: self.next.fetch_add(1, Ordering::Relaxed),
            info: Arc::clone(&self.info),
            metrics: Arc::clone(&self.metrics),
        })
    }
}

/// Serve every stream of one rendezvous circuit through the relay's
/// HTTP/WebSocket path. Each stream is its own connection in the
/// tracker, the peer is the listener-wide `Peer::Circuit`, and the
/// circuit ends when its stream of requests does or shutdown fires.
pub(crate) async fn serve_circuit<S, St>(
    circuit: Circuit,
    mut streams: St,
    router: axum::Router,
    http_stop_rx: watch::Receiver<()>,
    http_tracker: TaskTracker,
) where
    St: Stream<Item = S> + Unpin + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let n = circuit.n;
    debug!(listener = %circuit.info.id, circuit = n, "onion circuit open");
    let origin = Origin {
        listener: Arc::clone(&circuit.info),
        transport: Transport::Circuit(n),
    };
    let mut stop = http_stop_rx.clone();
    loop {
        let next = tokio::select! {
            stream = streams.next() => stream,
            _ = stop.changed() => break,
        };
        let Some(io) = next else { break };
        circuit.metrics.stream();
        serve_stream(
            io,
            origin.clone(),
            &router,
            &http_stop_rx,
            &http_tracker,
            None,
        );
    }
    debug!(listener = %circuit.info.id, circuit = n, "onion circuit closed");
    drop(circuit);
}

/// One listener's supervisor input.
struct Parts {
    /// The listener's fixed metadata.
    info: Arc<ListenerInfo>,
    /// Its service configuration.
    svc_config: OnionServiceConfig,
    /// Its `nosfry_onion_*` metric slot (same order as the config).
    metrics: Arc<metrics::OnionListener>,
    /// Its `max_circuits` budget.
    circuits: Circuits,
}

/// Map Arti's `State` to a `nosfry_onion_state` label index.
fn state_index(state: State) -> usize {
    let name = match state {
        State::Shutdown => "shutdown",
        State::Bootstrapping => "bootstrapping",
        State::DegradedReachable => "degraded_reachable",
        State::DegradedUnreachable => "degraded_unreachable",
        State::Running => "running",
        State::Recovering => "recovering",
        _ => "broken",
    };
    ONION_STATES
        .iter()
        .position(|candidate| *candidate == name)
        .unwrap_or(0)
}

/// Next bootstrap event, `None` on stream end or shutdown.
async fn next_boot(
    events: &mut (impl Stream<Item = BootstrapStatus> + Unpin),
    stop: &mut watch::Receiver<()>,
) -> Option<BootstrapStatus> {
    tokio::select! {
        event = events.next() => event,
        _ = stop.changed() => None,
    }
}

/// Log Arti bootstrap progress: once per 10 % step and once when
/// ready for traffic. `stop` ends it early; the sync dialer keeps a
/// channel open for the bootstrap's span.
pub(crate) async fn log_bootstrap(client: Arc<Client>, mut stop: watch::Receiver<()>) {
    let mut events = std::pin::pin!(client.bootstrap_events());
    let mut next_step = 0.1_f32;
    while let Some(status) = next_boot(&mut events, &mut stop).await {
        if status.ready_for_traffic() {
            info!("tor bootstrap ready for traffic");
            return;
        }
        let frac = status.as_frac();
        if frac >= next_step {
            info!(progress = %format_args!("{:.0}%", frac * 100.0), "tor bootstrap progress");
            next_step = (frac * 10.0).floor() / 10.0 + 0.1;
        }
    }
}

/// Log every Arti service-state change and mirror it into the
/// listener's `nosfry_onion_state` series.
async fn log_status(
    service: Arc<RunningOnionService>,
    slot: Arc<metrics::OnionListener>,
    mut stop: watch::Receiver<()>,
) {
    let mut events = std::pin::pin!(service.status_events());
    let mut last = usize::MAX;
    loop {
        let next = tokio::select! {
            event = events.next() => event,
            _ = stop.changed() => break,
        };
        let Some(status) = next else { break };
        let state = status.state();
        let index = state_index(state);
        if index == last {
            continue;
        }
        last = index;
        slot.set_state(index);
        info!(?state, "onion service state");
    }
}

/// Whether a stream request is a `BEGIN` for the relay's virtual
/// port; anything else is `END`ed `DONE`.
fn is_begin(request: &tor_hsservice::StreamRequest) -> bool {
    matches!(
        request.request(),
        IncomingStreamRequest::Begin(begin) if begin.port() == VIRT_PORT
    )
}

/// One `StreamRequest`: a `BEGIN` for the relay's virtual port
/// becomes its byte stream; anything else is rejected `DONE`.
async fn take_stream(
    request: tor_hsservice::StreamRequest,
) -> Option<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    if !is_begin(&request) {
        request
            .reject(End::new_with_reason(EndReason::DONE))
            .await
            .ok();
        return None;
    }
    request
        .accept(Connected::new_empty())
        .await
        .inspect_err(|err| debug!(%err, "onion stream accept failed"))
        .ok()
}

/// Accept rendezvous requests for one running service: admit within
/// the `max_circuits` budget (reject otherwise), hand each accepted
/// circuit's `BEGIN :80` streams to `serve_circuit`, and `END`/`DONE`
/// every other request.
async fn accept_rend(
    service: Arc<RunningOnionService>,
    mut rends: impl Stream<Item = RendRequest> + Unpin + Send + 'static,
    parts: Parts,
    router: axum::Router,
    mut stop: watch::Receiver<()>,
    tracker: TaskTracker,
) {
    // Keep the service alive for this task's life; dropping it stops
    // introductions and closes its circuits.
    let _service = service;
    loop {
        let next = tokio::select! {
            rend = rends.next() => rend,
            _ = stop.changed() => break,
        };
        let Some(rend) = next else { break };
        let Some(circuit) = parts.circuits.admit() else {
            if let Err(err) = rend.reject().await {
                debug!(%err, "failed to reject rendezvous request");
            }
            continue;
        };
        let router = router.clone();
        let tracker2 = tracker.clone();
        let mut stop_accept = stop.clone();
        let info = Arc::clone(&parts.info);
        tracker.spawn(async move {
            let accepted = tokio::select! {
                result = rend.accept() => result,
                _ = stop_accept.changed() => return,
            };
            let requests = match accepted {
                Ok(requests) => requests,
                Err(err) => {
                    debug!(%err, listener = %info.id, "rendezvous accept failed");
                    return;
                }
            };
            let streams = requests.filter_map(take_stream);
            serve_circuit(circuit, streams.boxed(), router, stop_accept, tracker2).await;
        });
    }
}

/// Sleep `delay` or return early on shutdown; reports whether the
/// caller should retry.
async fn backoff(delay: Duration, stop: &mut watch::Receiver<()>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => true,
        _ = stop.changed() => false,
    }
}

/// Bootstrap the shared client, retrying with the shared `delay`
/// backoff; `false` when shutdown fires first. Shutdown during
/// bootstrap returns at once instead of waiting out the tracker
/// deadline.
async fn bootstrap_client(
    client: &Arc<Client>,
    delay: &mut Duration,
    stop: &mut watch::Receiver<()>,
) -> bool {
    loop {
        let result = tokio::select! {
            result = client.bootstrap() => result,
            _ = stop.changed() => return false,
        };
        match result {
            Ok(()) => return true,
            Err(err) => {
                warn!(%err, retry_in = ?delay, "tor bootstrap failed; retrying");
                if !backoff(*delay, stop).await {
                    return false;
                }
                *delay = (*delay * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// Launch one onion service, retrying with the shared `delay` backoff;
/// `None` when shutdown fires first.
async fn launch_service(
    client: &Arc<Client>,
    parts: &Parts,
    delay: &mut Duration,
    stop: &mut watch::Receiver<()>,
) -> Option<(
    Arc<RunningOnionService>,
    std::pin::Pin<Box<dyn Stream<Item = RendRequest> + Send>>,
)> {
    loop {
        match client.launch_onion_service(parts.svc_config.clone()) {
            Ok(Some((service, rends))) => return Some((service, Box::pin(rends))),
            Ok(None) => error!(
                listener = %parts.info.id,
                "onion service is disabled in the Arti config; retrying"
            ),
            Err(err) => warn!(
                %err,
                listener = %parts.info.id,
                retry_in = ?delay,
                "onion service launch failed; retrying"
            ),
        }
        if !backoff(*delay, stop).await {
            return None;
        }
        *delay = (*delay * 2).min(BACKOFF_MAX);
    }
}

/// The onion listeners' supervisor: bootstrap the shared client with
/// capped exponential backoff (Tor may be unreachable for minutes —
/// never crash, never spin), then launch each service and run its
/// status and rendezvous loops. Ends when `stop` fires; open streams
/// drain through the shared tracker.
pub(crate) async fn supervise(
    listeners: Vec<(Arc<ListenerInfo>, Bound)>,
    max_circuits: usize,
    metrics: Vec<Arc<metrics::OnionListener>>,
    router: axum::Router,
    mut stop: watch::Receiver<()>,
    tracker: TaskTracker,
) {
    let Some(client) = listeners
        .first()
        .map(|(_, bound)| Arc::clone(&bound.client))
    else {
        return;
    };
    let parts: Vec<Parts> = listeners
        .into_iter()
        .zip(metrics)
        .map(|((info, bound), slot)| Parts {
            circuits: Circuits::new(max_circuits, Arc::clone(&info), Arc::clone(&slot)),
            info,
            svc_config: bound.svc_config,
            metrics: slot,
        })
        .collect();

    tracker.spawn(log_bootstrap(Arc::clone(&client), stop.clone()));
    let mut delay = BACKOFF_MIN;
    if !bootstrap_client(&client, &mut delay, &mut stop).await {
        return;
    }
    delay = BACKOFF_MIN;

    for part in parts {
        let Some((service, rends)) = launch_service(&client, &part, &mut delay, &mut stop).await
        else {
            return;
        };
        delay = BACKOFF_MIN;
        info!(listener = %part.info.id, "onion service launched");
        tracker.spawn(log_status(
            Arc::clone(&service),
            Arc::clone(&part.metrics),
            stop.clone(),
        ));
        tracker.spawn(accept_rend(
            service,
            rends,
            part,
            router.clone(),
            stop.clone(),
            tracker.clone(),
        ));
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::case_sensitive_file_extension_comparisons,
    reason = "unit tests panic on failure and check URL shapes"
)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use futures_util::{SinkExt as _, stream};
    use nosfry_core::sign;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::config::{Config, Listen, ListenAddress};

    fn info(nickname: &str) -> Arc<ListenerInfo> {
        Arc::new(ListenerInfo {
            id: Arc::from(format!("onion:{nickname}").as_str()),
            profile: Arc::from("onion"),
            real_ip_header: String::new(),
            last_warn_secs: AtomicU64::new(0),
        })
    }

    fn slot(nickname: &str) -> Arc<metrics::OnionListener> {
        Arc::new(metrics::OnionListener::new(Arc::from(nickname)))
    }

    fn onion_config(state_dir: &std::path::Path) -> Config {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.db.path = dir.keep();
        config.relay.listen = vec![Listen {
            address: ListenAddress::Onion("test".to_owned()),
            profile: "onion".to_owned(),
            real_ip_header: String::new(),
        }];
        config.relay.profiles.insert(
            "onion".to_owned(),
            crate::config::Profile {
                max_connections_per_peer: 2,
                ..crate::config::Profile::default()
            },
        );
        config.relay.onion.state_dir = state_dir.to_path_buf();
        config.relay.onion.onion_location = true;
        config.relay.onion_urls = vec!["ws://abcdefghij.onion".to_owned()];
        config
    }

    /// A tempdir ready to be a `state_dir` (tempfile honours the
    /// umask; the onion rule wants 0700).
    #[cfg(unix)]
    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(not(unix))]
    fn private_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test]
    async fn addresses_are_stable_and_per_nickname() {
        let dir = private_dir();
        let mut config = onion_config(dir.path());
        let first = addresses(&config).unwrap();
        assert_eq!(first.len(), 1);
        assert!(first[0].starts_with("ws://") && first[0].ends_with(".onion"));
        // Same state dir → same address (the key persists).
        assert_eq!(addresses(&config).unwrap(), first);
        // A second nickname derives its own address.
        config.relay.listen.push(Listen {
            address: ListenAddress::Onion("other".to_owned()),
            profile: "onion".to_owned(),
            real_ip_header: String::new(),
        });
        let both = addresses(&config).unwrap();
        assert_eq!(both[0], first[0]);
        assert_ne!(both[1], first[0]);
        assert!(both[1].ends_with(".onion"));
    }

    #[tokio::test]
    async fn circuit_admission_caps_and_rejects() {
        let circuits = Circuits::new(1, info("test"), slot("test"));
        let first = circuits.admit().unwrap();
        assert!(circuits.admit().is_none());
        assert_eq!(circuits.metrics.counters().1, 1);
        drop(first);
        assert!(circuits.admit().is_some());
    }

    /// One duplex pair per circuit stream; `body` is written on the
    /// client half and the response head is read back.
    async fn http_exchange(io: &mut tokio::io::DuplexStream, request: &str) -> String {
        io.write_all(request.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 8192];
        let mut head = String::new();
        while !head.contains("\r\n\r\n") {
            let n = io.read(&mut buf).await.unwrap();
            head.push_str(std::str::from_utf8(&buf[..n]).unwrap());
        }
        head
    }

    async fn ws_result(
        io: tokio::io::DuplexStream,
    ) -> yawc::Result<yawc::WebSocket<tokio::io::DuplexStream>> {
        yawc::WebSocket::handshake(
            "ws://localhost/".parse().unwrap(),
            io,
            yawc::Options::default(),
        )
        .await
    }

    async fn ws(io: tokio::io::DuplexStream) -> yawc::WebSocket<tokio::io::DuplexStream> {
        ws_result(io).await.unwrap()
    }

    /// Next text frame, skipping pings, or panic on a 10 s stall.
    async fn next_text(ws: &mut yawc::WebSocket<tokio::io::DuplexStream>) -> String {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let frame = tokio::time::timeout_at(deadline, ws.next())
                .await
                .expect("frame timeout")
                .expect("stream ended");
            if frame.opcode() == yawc::OpCode::Text {
                return std::str::from_utf8(frame.payload()).unwrap().to_owned();
            }
        }
    }

    /// Text frames until the publish `OK`; asserts it succeeded.
    async fn await_ok(ws: &mut yawc::WebSocket<tokio::io::DuplexStream>) {
        loop {
            let text = next_text(ws).await;
            if text.starts_with("[\"OK\"") {
                assert!(text.contains("true"), "{text}");
                return;
            }
        }
    }

    /// Text frames up to and including the `EOSE`.
    async fn until_eose(ws: &mut yawc::WebSocket<tokio::io::DuplexStream>) -> Vec<String> {
        let mut frames = Vec::new();
        loop {
            let text = next_text(ws).await;
            let eose = text.starts_with("[\"EOSE\"");
            frames.push(text);
            if eose {
                return frames;
            }
        }
    }

    /// The accept path without Tor: duplex streams stand in for
    /// rendezvous-circuit streams, the circuit cap and the
    /// listener-wide peer cap apply, and every stream reaches the
    /// usual HTTP/WebSocket handlers.
    #[tokio::test]
    async fn serve_circuit_accept_path() {
        let state_dir = tempfile::tempdir().unwrap();
        let config = onion_config(state_dir.path());
        let server = crate::Server::new(config).unwrap();
        let router = server.router();
        let tracker = TaskTracker::new();
        let (stop_tx, stop_rx) = watch::channel(());
        let slot = slot("test");
        let circuits = Circuits::new(2, info("test"), Arc::clone(&slot));

        // (a) NIP-11 over a circuit stream.
        let (server_io, mut client_io) = tokio::io::duplex(8192);
        tracker.spawn(serve_circuit(
            circuits.admit().unwrap(),
            stream::iter(vec![server_io]),
            router.clone(),
            stop_rx.clone(),
            tracker.clone(),
        ));
        let head = http_exchange(
            &mut client_io,
            "GET / HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\n\r\n",
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("application/nostr+json"), "{head}");
        // `Onion-Location` is configured but never sent back to a
        // client that already arrived over the onion.
        assert!(!head.contains("onion-location"), "{head}");

        // (b) a WebSocket EVENT/REQ round-trip on one stream.
        let (s1, c1) = tokio::io::duplex(8192);
        let (s2, c2) = tokio::io::duplex(8192);
        let (s3, c3) = tokio::io::duplex(8192);
        tracker.spawn(serve_circuit(
            circuits.admit().unwrap(),
            stream::iter(vec![s1, s2]),
            router.clone(),
            stop_rx.clone(),
            tracker.clone(),
        ));
        tracker.spawn(serve_circuit(
            circuits.admit().unwrap(),
            stream::iter(vec![s3]),
            router.clone(),
            stop_rx.clone(),
            tracker.clone(),
        ));
        let mut ws1 = ws(c1).await;
        let ws2 = ws(c2).await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let event = sign::event(&sign::key(1), 1, now, &serde_json::json!([]), "hi");
        ws1.send(yawc::Frame::text(format!("[\"EVENT\",{}]", event.json())))
            .await
            .unwrap();

        // Wait for the commit's OK before scanning, or the REQ can
        // beat the writer.
        await_ok(&mut ws1).await;
        ws1.send(yawc::Frame::text("[\"REQ\",\"s\",{}]"))
            .await
            .unwrap();
        let frames = until_eose(&mut ws1).await;
        assert!(
            frames.iter().any(|f| f.starts_with("[\"EVENT\"")),
            "{frames:?}"
        );

        // (c) the listener-wide peer cap: a third WebSocket — even on
        // a different circuit — is refused.
        assert!(ws_result(c3).await.is_err());
        drop(ws2);

        // (d) every stream counted.
        assert_eq!(slot.counters().2, 4);
        // Drop the client halves first: an upgraded connection's task
        // lives until its WebSocket closes, so it would wait forever.
        drop(ws1);
        drop(client_io);
        stop_tx.send(()).ok();
        tracker.close();
        tracker.wait().await;
        // `stop` joins the worker threads, which exit only once every
        // shard sender drops — `router` still holds one via `State`.
        drop(router);
        server.stop();
    }
}
