//! The `iroh:` listener's bound state, accept loop and supervisor.
//!
//! [`bind`] runs at startup: it secures the state dir, loads or
//! creates the listener's key and binds the endpoint — a local
//! operation that never waits on the network. [`accept`] runs one
//! task per listener: every `Incoming` beyond `max_connections` is
//! refused *before* the handshake (the relay spends no cryptography
//! on it), each admitted connection hands its bidirectional streams
//! to [`serve_stream`] as independent HTTP/1.1 connections.
//! [`supervise`] only reports: the home-relay connectivity and the
//! listener's dial address, live as iroh learns it.

use std::fmt;
use std::sync::Arc;

use futures_util::StreamExt as _;
use iroh::Watcher as _;
use iroh::endpoint::{Connection, Incoming, PathEventStream, RecvStream, SendStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use super::{ALPN, BiStream, DialAddr, alias, builder, secret_key};
use crate::config::Iroh;
use crate::metrics;
use crate::peer::{ListenerInfo, Origin, Transport};
use crate::{ServerError, serve_stream};

/// An iroh listener's bound state: the endpoint and its derived
/// `ws://` name. The endpoint id is `bound.endpoint.id()`.
pub(crate) struct Bound {
    /// The bound endpoint; `serve` clones it into the accept task,
    /// the supervisor and its shutdown list.
    pub(crate) endpoint: iroh::Endpoint,
    /// `ws://<z32>.iroh` — canonical or alias depending on
    /// `relay.service_url` and any onion URL.
    pub(crate) url: String,
}

impl fmt::Debug for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bound")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// Prepare one iroh listener at `bind` time: secure the state dir,
/// load or create its key, and bind the endpoint with the shared
/// [`builder`]. Binding is local — UDP sockets and the endpoint's
/// internal actors, no network round trip — so it fails startup on
/// real errors and never blocks on reachability.
pub(crate) async fn bind(cfg: &Iroh, nickname: &str) -> Result<Bound, ServerError> {
    crate::state_dir::prepare(&cfg.state_dir, "iroh").map_err(ServerError::Iroh)?;
    let key = secret_key(cfg, nickname)?;
    let endpoint = builder(cfg)
        .secret_key(key)
        .bind()
        .await
        .map_err(|err| ServerError::Iroh(err.to_string()))?;
    let id = *endpoint.id().as_bytes();
    Ok(Bound {
        endpoint,
        url: alias(&id),
    })
}

/// Accept iroh connections until `stop` fires. `Incoming`s beyond
/// `max_connections` are refused before the QUIC handshake — a
/// refusal costs the relay no cryptography and the peer one packet.
/// Each admitted connection's handshake and stream loop runs as one
/// task of the HTTP tracker, so shutdown waits out nothing but the
/// deadline.
pub(crate) async fn accept(
    endpoint: iroh::Endpoint,
    max_connections: usize,
    info: Arc<ListenerInfo>,
    metrics: Arc<metrics::IrohListener>,
    router: axum::Router,
    mut stop: watch::Receiver<()>,
    tracker: TaskTracker,
) {
    let slots = Arc::new(Semaphore::new(max_connections));
    loop {
        let incoming = tokio::select! {
            next = endpoint.accept() => next,
            _ = stop.changed() => break,
        };
        let Some(incoming) = incoming else { break };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            metrics.rejected();
            debug!(listener = %info.id, "iroh connection refused: max_connections reached");
            incoming.refuse();
            continue;
        };
        tracker.spawn(serve_connection(
            incoming,
            permit,
            Arc::clone(&info),
            Arc::clone(&metrics),
            router.clone(),
            stop.clone(),
            tracker.clone(),
        ));
    }
}

/// One admitted iroh connection: complete the handshake (or leave on
/// shutdown), then serve every bidirectional stream as an
/// independent HTTP/1.1 connection. The remote endpoint id — already
/// authenticated by QUIC's TLS — is the peer. Ends when the
/// connection closes or `stop` fires; the permit returns to the
/// semaphore on drop.
async fn serve_connection(
    incoming: Incoming,
    permit: OwnedSemaphorePermit,
    info: Arc<ListenerInfo>,
    metrics: Arc<metrics::IrohListener>,
    router: axum::Router,
    mut stop: watch::Receiver<()>,
    tracker: TaskTracker,
) {
    let Some(conn) = handshake(incoming, &info, &mut stop).await else {
        return;
    };
    // The server offers only ALPN, so anything else cannot complete —
    // the check is a guard against a future second ALPN slipping in.
    if conn.alpn() != ALPN {
        debug!(listener = %info.id, "iroh connection with unexpected ALPN; closing");
        conn.close(0_u32.into(), b"unsupported alpn");
        return;
    }
    // Held until the task ends: the slot covers handshake and the
    // whole connection.
    let _permit = permit;
    let remote = *conn.remote_id().as_bytes();
    let peer = format!("iroh:{}", super::z32(&remote));
    debug!(listener = %info.id, %peer, "iroh connection open");
    let origin = Origin {
        listener: Arc::clone(&info),
        transport: Transport::Iroh(remote),
    };
    let mut path = ConnectionPath::new(&conn, &metrics, &info, peer);
    let mut events = conn.path_events();
    let mut events_open = true;
    while let Some((send, recv)) = next_stream(
        &conn,
        &mut events,
        &mut events_open,
        &mut path,
        &info,
        &mut stop,
    )
    .await
    {
        metrics.stream();
        serve_stream(
            BiStream { recv, send },
            origin.clone(),
            &router,
            &stop,
            &tracker,
            None,
        );
    }
}

/// The QUIC handshake behind the same `stop` the accept loop races:
/// `None` on shutdown or a failed handshake (debug-logged; the peer
/// sees a refused or closed attempt).
async fn handshake(
    incoming: Incoming,
    info: &ListenerInfo,
    stop: &mut watch::Receiver<()>,
) -> Option<Connection> {
    let attempt = async move {
        match incoming.accept() {
            Ok(accepting) => accepting.await.map_err(|err| err.to_string()),
            Err(err) => Err(err.to_string()),
        }
    };
    tokio::select! {
        result = attempt => match result {
            Ok(conn) => Some(conn),
            Err(err) => {
                debug!(%err, listener = %info.id, "iroh handshake failed");
                None
            }
        },
        _ = stop.changed() => None,
    }
}

/// Wait for the next bidirectional stream, path event or close:
/// `Some` a stream to serve, `None` on shutdown or connection end.
/// Path events only re-pin the connection's `path` metric label.
async fn next_stream(
    conn: &Connection,
    events: &mut PathEventStream,
    events_open: &mut bool,
    path: &mut ConnectionPath,
    info: &ListenerInfo,
    stop: &mut watch::Receiver<()>,
) -> Option<(SendStream, RecvStream)> {
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => return None,
            stream = conn.accept_bi() => return match stream {
                Ok(pair) => Some(pair),
                Err(err) => {
                    debug!(%err, listener = %info.id, "iroh connection closed");
                    None
                }
            },
            event = events.next(), if *events_open => {
                if event.is_some() {
                    path.update(conn);
                } else {
                    *events_open = false;
                }
            }
        }
    }
}

/// Keeps one connection's `nosfry_iroh_connections{listener,path}`
/// series pinned to its selected path (`direct` or `relay`),
/// re-evaluated on every `path_events` event and decremented on
/// drop. Path changes log at debug with the peer.
struct ConnectionPath {
    /// The listener's `nosfry_iroh_*` series.
    metrics: Arc<metrics::IrohListener>,
    /// `iroh:<z32>` of the remote endpoint (log field only).
    peer: String,
    /// The listener's fixed metadata.
    info: Arc<ListenerInfo>,
    /// The currently counted `path` label, if any.
    kind: Option<&'static str>,
}

impl ConnectionPath {
    /// Count the connection under its current selected path, if it
    /// has one yet.
    fn new(
        conn: &Connection,
        metrics: &Arc<metrics::IrohListener>,
        info: &Arc<ListenerInfo>,
        peer: String,
    ) -> Self {
        let mut guard = Self {
            metrics: Arc::clone(metrics),
            peer,
            info: Arc::clone(info),
            kind: None,
        };
        guard.update(conn);
        guard
    }

    /// Re-read the selected path after a `path_events` event and move
    /// the counted label if it changed.
    fn update(&mut self, conn: &Connection) {
        let kind = super::selected_path(conn);
        if kind == self.kind {
            return;
        }
        debug!(
            listener = %self.info.id,
            peer = %self.peer,
            from = self.kind.unwrap_or("none"),
            to = kind.unwrap_or("none"),
            "iroh selected path changed"
        );
        if let Some(old) = self.kind.take() {
            self.metrics.connection_close(old);
        }
        if let Some(new) = kind {
            self.metrics.connection_open(new);
        }
        self.kind = kind;
    }
}

impl Drop for ConnectionPath {
    fn drop(&mut self) {
        if let Some(kind) = self.kind.take() {
            self.metrics.connection_close(kind);
        }
    }
}

/// One iroh listener's supervisor: report the home-relay
/// connectivity (`nosfry_iroh_relay_connected` 0/1, an info log on
/// every change, the auth-denied reason at warn) and log the
/// listener's dial address at info whenever `watch_addr` learns a
/// new relay or direct address. iroh itself retries the relay
/// connection on its internal backoff — there is nothing to launch
/// or restart here.
pub(crate) async fn supervise(
    endpoint: iroh::Endpoint,
    info: Arc<ListenerInfo>,
    metrics: Arc<metrics::IrohListener>,
    mut stop: watch::Receiver<()>,
) {
    let mut relays = std::pin::pin!(endpoint.home_relay_status().stream());
    let mut addrs = std::pin::pin!(endpoint.watch_addr().stream());
    let mut connected = false;
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            statuses = relays.next() => {
                let Some(statuses) = statuses else { break };
                relay_status(&statuses, &info, &metrics, &mut connected);
            }
            addr = addrs.next() => {
                let Some(addr) = addr else { break };
                info!(
                    listener = %info.id,
                    dial = %DialAddr::from(&addr),
                    "iroh dial address"
                );
            }
        }
    }
}

/// One `home_relay_status` snapshot: warn on each auth-denied
/// relay, and flip `nosfry_iroh_relay_connected` (and log) when the
/// any-relay-connected bit changes.
fn relay_status(
    statuses: &[iroh::endpoint::RelayStatus],
    info: &ListenerInfo,
    metrics: &metrics::IrohListener,
    connected: &mut bool,
) {
    for status in statuses {
        if let Some(reason) = status.auth_denied_reason() {
            warn!(
                listener = %info.id,
                relay = %status.url(),
                %reason,
                "iroh relay authentication denied"
            );
        }
    }
    let up = statuses
        .iter()
        .any(iroh::endpoint::RelayStatus::is_connected);
    if up != *connected {
        *connected = up;
        metrics.set_relay_connected(up);
        info!(listener = %info.id, connected = up, "iroh home relay connectivity");
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "unit tests panic on failure"
)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicU64;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use futures_util::SinkExt as _;
    use nosfry_core::sign;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::config::{Config, Listen, ListenAddress, Profile};
    use crate::iroh::{DialAddr, z32};

    fn info(nickname: &str) -> Arc<ListenerInfo> {
        Arc::new(ListenerInfo {
            id: Arc::from(format!("iroh:{nickname}").as_str()),
            profile: Arc::from("iroh"),
            real_ip_header: String::new(),
            last_warn_secs: AtomicU64::new(0),
        })
    }

    fn slot(nickname: &str) -> Arc<metrics::IrohListener> {
        Arc::new(metrics::IrohListener::new(Arc::from(nickname)))
    }

    /// The test config: one `iroh:` listener on the `iroh` profile
    /// (one WebSocket per peer), offline iroh settings.
    fn test_config(state_dir: &std::path::Path, per_peer: usize) -> Config {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.db.path = dir.keep();
        config.relay.listen = vec![Listen {
            address: ListenAddress::Iroh("test".to_owned()),
            profile: "iroh".to_owned(),
            real_ip_header: String::new(),
        }];
        config.relay.profiles.insert(
            "iroh".to_owned(),
            Profile {
                max_connections_per_peer: per_peer,
                ..Profile::default()
            },
        );
        config.relay.iroh.state_dir = state_dir.to_path_buf();
        config.relay.iroh.relay_mode = crate::config::IrohRelayMode::Disabled;
        config.relay.iroh.address_lookup = crate::config::IrohAddressLookup::Disabled;
        config
    }

    #[cfg(unix)]
    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(not(unix))]
    fn private_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A fresh client endpoint: same builder as the listener, a
    /// generated key, offline settings.
    async fn client(cfg: &Iroh) -> iroh::Endpoint {
        builder(cfg)
            .secret_key(iroh::SecretKey::generate())
            .bind()
            .await
            .unwrap()
    }

    /// The `<id>@127.0.0.1:<port>` dial address of a bound endpoint,
    /// through the same parse/convert path a dialer takes.
    fn dial_of(endpoint: &iroh::Endpoint, cfg: &Iroh) -> iroh::EndpointAddr {
        let socket = endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .unwrap();
        let text = format!(
            "{}@127.0.0.1:{}",
            z32(endpoint.id().as_bytes()),
            socket.port()
        );
        text.parse::<DialAddr>().unwrap().to_endpoint_addr(cfg)
    }

    /// `buf` holds a complete HTTP/1.1 response once its head ends
    /// and the `Content-Length` body arrived (header names compared
    /// lowercased).
    fn response_complete(buf: &[u8]) -> bool {
        let Some(head_end) = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
        else {
            return false;
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
        head.lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .is_some_and(|len| buf.len() >= head_end + len)
    }

    /// One bidirectional stream = one HTTP/1.1 connection; `body`
    /// writes the request and reads the response head and body.
    async fn http_exchange(conn: &Connection, request: &str) -> String {
        let (send, recv) = conn.open_bi().await.unwrap();
        let mut io = BiStream { recv, send };
        io.write_all(request.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 65536];
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !response_complete(&out) {
            let n = tokio::time::timeout_at(deadline, io.read(&mut buf))
                .await
                .expect("HTTP response timeout")
                .expect("stream read");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    async fn ws_result(conn: &Connection) -> yawc::Result<yawc::WebSocket<BiStream>> {
        let (send, recv) = conn.open_bi().await.unwrap();
        yawc::WebSocket::handshake(
            "ws://localhost/".parse().unwrap(),
            BiStream { recv, send },
            yawc::Options::default(),
        )
        .await
    }

    async fn ws(conn: &Connection) -> yawc::WebSocket<BiStream> {
        ws_result(conn).await.unwrap()
    }

    /// Next text frame, skipping pings, or panic on a 10 s stall.
    async fn next_text(ws: &mut yawc::WebSocket<BiStream>) -> String {
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
    async fn await_ok(ws: &mut yawc::WebSocket<BiStream>) {
        loop {
            let text = next_text(ws).await;
            if text.starts_with("[\"OK\"") {
                assert!(text.contains("true"), "{text}");
                return;
            }
        }
    }

    /// Text frames up to and including the `EOSE`.
    async fn until_eose(ws: &mut yawc::WebSocket<BiStream>) -> Vec<String> {
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

    /// One running listener (endpoint + accept task + supervisor)
    /// and its shutdown channel.
    struct Running {
        /// The listener's endpoint.
        endpoint: iroh::Endpoint,
        /// The accept task's stop channel.
        stop_tx: watch::Sender<()>,
        /// The listener's `nosfry_iroh_*` series.
        metrics: Arc<metrics::IrohListener>,
    }

    async fn run_listener(
        cfg: &Iroh,
        max_connections: usize,
        router: axum::Router,
        tracker: TaskTracker,
    ) -> Running {
        let bound = bind(cfg, "test").await.unwrap();
        let endpoint = bound.endpoint;
        let (stop_tx, stop_rx) = watch::channel(());
        let slot = slot("test");
        tracker.spawn(accept(
            endpoint.clone(),
            max_connections,
            info("test"),
            Arc::clone(&slot),
            router,
            stop_rx.clone(),
            tracker.clone(),
        ));
        tracker.spawn(supervise(
            endpoint.clone(),
            info("test"),
            Arc::clone(&slot),
            stop_rx,
        ));
        Running {
            endpoint,
            stop_tx,
            metrics: slot,
        }
    }

    /// The full accept path over real loopback endpoints: NIP-11 and
    /// a WebSocket publish/query, the global `max_connections` cap,
    /// the per-endpoint peer cap, and clean shutdown.
    #[tokio::test]
    async fn accept_path() {
        let state_dir = private_dir();
        let mut config = test_config(state_dir.path(), 1);
        let cfg = config.relay.iroh.clone();

        // Bind first: the NIP-11 document names the derived id.
        let bound = bind(&cfg, "test").await.unwrap();
        config.relay.iroh_urls = vec![bound.url.clone()];
        let z = z32(bound.endpoint.id().as_bytes());
        drop(bound);

        let server = crate::Server::new(config).unwrap();
        let router = server.router();
        let tracker = TaskTracker::new();
        let running = run_listener(&cfg, 8, router.clone(), tracker.clone()).await;

        // (a) NIP-11 over one bidirectional stream: HTTP 200 and the
        // `iroh` extension naming this endpoint.
        let client_a = client(&cfg).await;
        let conn = client_a
            .connect(dial_of(&running.endpoint, &cfg), ALPN)
            .await
            .unwrap();
        let response = http_exchange(
            &conn,
            "GET / HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains(&z), "{response}");
        assert!(
            response.contains("\"alpn\":\"nosfry/http/1\""),
            "{response}"
        );

        // (b) a WebSocket on another stream of the same connection:
        // publish an event (OK true) and REQ returns it.
        let mut ws1 = ws(&conn).await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let event = sign::event(&sign::key(1), 1, now, &serde_json::json!([]), "hi");
        ws1.send(yawc::Frame::text(format!("[\"EVENT\",{}]", event.json())))
            .await
            .unwrap();
        await_ok(&mut ws1).await;
        ws1.send(yawc::Frame::text("[\"REQ\",\"s\",{}]"))
            .await
            .unwrap();
        let frames = until_eose(&mut ws1).await;
        assert!(
            frames.iter().any(|f| f.starts_with("[\"EVENT\"")),
            "{frames:?}"
        );

        // (c) the per-peer cap: a second WebSocket on the same
        // endpoint id is refused; another endpoint connects fine.
        assert!(ws_result(&conn).await.is_err());
        let client_b = client(&cfg).await;
        let conn_b = client_b
            .connect(dial_of(&running.endpoint, &cfg), ALPN)
            .await
            .unwrap();
        let ws_b = ws(&conn_b).await;

        // Every stream so far counted (NIP-11, ws1, the refused
        // handshake stream, ws_b).
        assert_eq!(running.metrics.counters().1, 4);
        drop(ws1);
        drop(ws_b);
        conn.close(0_u32.into(), b"done");
        conn_b.close(0_u32.into(), b"done");

        // (d) `max_connections = 1`: while one client holds a
        // connection, a second endpoint's connect is refused before
        // the handshake.
        running.stop_tx.send_replace(());
        tracker.close();
        tracker.wait().await;
        let capped_tracker = TaskTracker::new();
        let capped = run_listener(&cfg, 1, router.clone(), capped_tracker.clone()).await;
        let conn1 = client_a
            .connect(dial_of(&capped.endpoint, &cfg), ALPN)
            .await
            .unwrap();
        let refused = client_b
            .connect(dial_of(&capped.endpoint, &cfg), ALPN)
            .await;
        assert!(refused.is_err());
        // The first connection still works.
        let (send, recv) = conn1.open_bi().await.unwrap();
        let mut io = BiStream { recv, send };
        io.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        assert!(io.read(&mut [0u8; 64]).await.unwrap() > 0);

        // (e) clean shutdown: stop fires, the tracker drains, the
        // endpoint closes.
        capped.stop_tx.send_replace(());
        capped_tracker.close();
        capped_tracker.wait().await;
        tokio::time::timeout(Duration::from_secs(10), capped.endpoint.close())
            .await
            .unwrap();
        client_a.close().await;
        client_b.close().await;
        drop(router);
        tokio::task::spawn_blocking(move || server.stop())
            .await
            .unwrap();
    }
}
