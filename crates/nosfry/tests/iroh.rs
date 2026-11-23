//! iroh transport end-to-end against the in-process relay: the
//! `nosfry connect` TCP gateway, `nosfry sync iroh:<dial>`, the
//! `ws://<z32>.iroh` AUTH tag, connection caps and metrics.
//!
//! Every case stays on loopback: endpoints run with
//! `relay_mode = "disabled"` and `address_lookup = "disabled"` and
//! the dial addresses carry `127.0.0.1:<port>` hints. The one
//! network test is `network_relay_path` (ignored by default).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::shadow_unrelated,
    clippy::too_many_lines,
    clippy::print_stderr,
    unused_crate_dependencies,
    reason = "tests may panic on failure paths; deps cover every test binary"
)]

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use futures_util::{SinkExt as _, StreamExt as _};
use nosfry::config::{Config, Iroh, IrohAddressLookup, IrohRelayMode, Listen, ListenAddress};
use nosfry::iroh::connect::{self, ConnectOptions};
use nosfry::sync::{Direction, Outcome, SyncOptions};
use nosfry_core::event::Event;
use nosfry_lmdb::Store;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};
use yawc::{Frame, WebSocket};

const T: Duration = Duration::from_secs(30);
/// Small LMDB map so a test process can hold many envs at once.
const MAP_SIZE: usize = 1 << 30;

/// Unix seconds now; test events must stay inside the relay's
/// `reject_events_older/newer` window.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `[relay.iroh]` that never leaves the host: no relays, no address
/// lookup — a `127.0.0.1` hint is the whole dial address.
fn offline_iroh() -> Iroh {
    Iroh {
        relay_mode: IrohRelayMode::Disabled,
        address_lookup: IrohAddressLookup::Disabled,
        ..Iroh::default()
    }
}

/// A running iroh-only relay plus its dialing coordinates.
struct IrohRelay {
    /// The endpoint id's z32 text.
    id: String,
    /// The endpoint's IPv4 UDP port.
    port: u16,
    /// `ws://<z32>.iroh` — the relay's canonical name.
    alias: String,
    stop: oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
    /// Keeps the store and state directories alive.
    _dir: tempfile::TempDir,
}

impl IrohRelay {
    /// `<z32>@127.0.0.1:<port>` — what `nosfry connect` takes.
    fn dial_addr(&self) -> String {
        format!("{}@127.0.0.1:{}", self.id, self.port)
    }

    /// `iroh:<z32>@127.0.0.1:<port>` — what `nosfry sync` takes.
    fn sync_url(&self) -> String {
        format!("iroh:{}", self.dial_addr())
    }

    async fn stop(self) {
        self.stop.send(()).ok();
        self.handle.await.ok();
    }
}

/// Start `config` with its listeners replaced by one `iroh:main`
/// listener; returns once `serve` is spawned. `nosfry::bind` gives
/// the endpoint's id and UDP port before `serve` takes the
/// listeners — QUIC buffers a client's first packets until the
/// accept loop runs, so a gateway `bind` doubles as the readiness
/// wait.
async fn iroh_relay(mut config: Config) -> IrohRelay {
    let dir = tempfile::tempdir().unwrap();
    config.db.path = dir.path().join("db");
    config.db.map_size = MAP_SIZE;
    config.relay.iroh.state_dir = dir.path().join("iroh");
    config.relay.listen = vec![Listen {
        address: ListenAddress::Iroh("main".to_owned()),
        profile: "default".to_owned(),
        real_ip_header: String::new(),
    }];
    let (stop, rx) = oneshot::channel();
    let (_reload_tx, reload_rx) = watch::channel(config.clone());
    let listeners = nosfry::bind(&config).await.unwrap();
    let endpoint = listeners
        .iter()
        .find_map(nosfry::Listener::iroh_endpoint)
        .cloned()
        .expect("one iroh listener");
    let id = endpoint.id().to_z32();
    let port = endpoint
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .unwrap()
        .port();
    let handle = tokio::spawn(async move {
        nosfry::serve(
            config,
            listeners,
            async {
                rx.await.ok();
            },
            reload_rx,
        )
        .await
        .unwrap();
    });
    IrohRelay {
        alias: format!("ws://{id}.iroh"),
        id,
        port,
        stop,
        handle,
        _dir: dir,
    }
}

/// The relay's `common::config()` with offline iroh settings.
fn relay_config() -> Config {
    let mut config = config();
    config.relay.iroh = offline_iroh();
    config
}

/// A running `nosfry connect` gateway bound to an ephemeral port.
struct Gateway {
    /// The TCP `127.0.0.1:<port>` clients dial.
    addr: SocketAddr,
    stop: oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<Result<(), nosfry::ServerError>>,
}

impl Gateway {
    async fn stop(self) {
        self.stop.send(()).ok();
        match tokio::time::timeout(T, self.handle).await {
            Ok(Ok(Ok(()))) => {}
            other => panic!("gateway did not stop cleanly: {other:?}"),
        }
    }
}

/// [`connect::bind`] + `serve` on a task, ready to accept.
async fn gateway(relay: &IrohRelay) -> Gateway {
    gateway_result(relay)
        .await
        .unwrap_or_else(|err| panic!("gateway bind failed: {err}"))
}

/// `bind` only — tests that assert a refused connect need the error.
async fn gateway_result(relay: &IrohRelay) -> Result<Gateway, nosfry::ServerError> {
    let bound = connect::bind(
        &offline_iroh(),
        ConnectOptions {
            dial: relay.dial_addr().parse().unwrap(),
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            max_connections: 64,
            allow_remote: false,
            timeout: T,
        },
    )
    .await?;
    let addr = bound.local_addr()?;
    let (stop, rx) = oneshot::channel();
    let handle = tokio::spawn(bound.serve(async move {
        rx.await.ok();
    }));
    Ok(Gateway { addr, stop, handle })
}

/// A yawc WebSocket client to `ws://addr/` (a gateway address).
async fn ws_connect(addr: SocketAddr) -> yawc::TcpWebSocket {
    WebSocket::connect(format!("ws://{addr}/").parse().unwrap())
        .await
        .unwrap()
}

/// One HTTP GET over TCP through the gateway, `Connection: close`,
/// returning the whole response.
async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

/// A raw WebSocket upgrade request's response head (for the 429 the
/// peer cap answers with — yawc hides the status).
async fn upgrade_head(addr: SocketAddr) -> String {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(T, tcp.read(&mut buf))
            .await
            .expect("upgrade head timeout")
            .expect("upgrade head read");
        assert!(n > 0, "connection closed before the head ended");
        head.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// `COUNT` of all events the relay serves, through a gateway.
async fn remote_count(addr: SocketAddr) -> u64 {
    let mut ws = ws_connect(addr).await;
    send_text(&mut ws, &count_wire("c", "{}")).await;
    loop {
        let frame: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
        if frame[0] == "COUNT" {
            return frame[2]["count"].as_u64().unwrap();
        }
    }
}

/// Publish `events` over one gateway WebSocket, asserting `OK true`.
async fn publish(addr: SocketAddr, evs: &[Arc<Event>]) {
    let mut ws = ws_connect(addr).await;
    for ev in evs {
        send_text(&mut ws, &event_wire(ev)).await;
        let ok: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
        assert_eq!(ok[0], "OK", "{ok}");
        assert_eq!(ok[2], true, "{ok}");
    }
}

/// `n` kind-1 events from rotating keys at spread timestamps.
fn events(n: usize, base_ts: u64, step: u64) -> Vec<Arc<Event>> {
    (0..n)
        .map(|i| {
            event(
                &key(u8::try_from(i % 8).unwrap() + 1),
                1,
                base_ts + i as u64 * step,
                &json!([]),
                &format!("iroh event {i}"),
            )
        })
        .collect()
}

/// A local store for `sync::run`, with offline iroh settings.
fn local(dir: &Path) -> (Config, Store) {
    let mut config = relay_config();
    config.db.path = dir.to_path_buf();
    config.db.map_size = MAP_SIZE;
    let store = Store::open(&config.db.path, &config.store_options()).unwrap();
    (config, store)
}

/// Write `events` into `store` like the network write path does.
fn seed(store: &Store, config: &Config, events: &[Arc<Event>]) {
    let limits = config.limits().unwrap();
    store.write(events, limits.auth.names()).unwrap();
}

fn local_count(store: &Store) -> u64 {
    store.export(0, u64::MAX, false, &mut |_| Ok(())).unwrap()
}

/// `["AUTH", <signed 22242>]` answering `challenge` for `relay_url`.
fn auth_wire(keypair: &secp256k1::Keypair, challenge: &str, relay_url: &str) -> String {
    let ev = event(
        keypair,
        22_242,
        now(),
        &json!([["challenge", challenge], ["relay", relay_url]]),
        "",
    );
    format!("[\"AUTH\",{}]", ev.json())
}

/// (a)+(b) Through the gateway: NIP-11 carries the `iroh` extension
/// and a WebSocket publishes and queries.
#[tokio::test]
async fn gateway_nip11_and_websocket() {
    let relay = iroh_relay(relay_config()).await;
    let gw = gateway(&relay).await;

    // (a) NIP-11 GET through the gateway.
    let response = http_get(gw.addr, "/").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains("\"alpn\":\"nosfry/http/1\""),
        "{response}"
    );
    assert!(response.contains(&relay.id), "{response}");

    // (b) a WebSocket through the gateway: publish then query.
    let mut ws = ws_connect(gw.addr).await;
    let ev = event(&key(1), 1, now(), &json!([]), "hi over iroh");
    send_text(&mut ws, &event_wire(&ev)).await;
    let ok: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
    assert_eq!(ok[0], "OK", "{ok}");
    assert_eq!(ok[2], true, "{ok}");
    send_text(&mut ws, &req_wire("s", "{}")).await;
    let mut saw_event = false;
    loop {
        let frame: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
        match frame[0].as_str().unwrap() {
            "EVENT" => {
                assert_eq!(frame[2]["id"], ev.id().to_string(), "{frame}");
                saw_event = true;
            }
            // A catch-all REQ may match restricted kinds, so the
            // relay's AUTH challenge precedes the results.
            "AUTH" => {}
            "EOSE" => break,
            other => panic!("unexpected frame: {other}"),
        }
    }
    assert!(saw_event, "the published event never arrived");

    gw.stop().await;
    relay.stop().await;
}

/// (c) An iroh-only relay's canonical name is `ws://<z32>.iroh`; the
/// NIP-42 relay tag must name it — another URL is refused.
#[tokio::test]
async fn auth_tag_is_the_iroh_alias() {
    let relay = iroh_relay(relay_config()).await;
    let gw = gateway(&relay).await;

    // Unauthenticated REQ for a restricted kind: challenge + CLOSED.
    let mut ws = ws_connect(gw.addr).await;
    send_text(&mut ws, &req_wire("sub", "{\"kinds\":[4]}")).await;
    let auth: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
    assert_eq!(auth[0], "AUTH", "{auth}");
    let challenge = auth[1].as_str().unwrap().to_owned();
    let closed: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
    assert_eq!(closed[0], "CLOSED", "{closed}");
    assert!(
        closed[2].as_str().unwrap().starts_with("auth-required"),
        "{closed}"
    );

    // The ws://<z32>.iroh alias authenticates; the REQ then answers.
    send_text(&mut ws, &auth_wire(&key(1), &challenge, &relay.alias)).await;
    let ok: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
    assert_eq!(ok[0], "OK", "{ok}");
    assert_eq!(ok[2], true, "{ok}");
    send_text(&mut ws, &req_wire("sub2", "{\"kinds\":[4]}")).await;
    let eose: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
    assert_eq!(eose[0], "EOSE", "{eose}");
    drop(ws);

    // Another relay URL is refused.
    let mut ws2 = ws_connect(gw.addr).await;
    send_text(&mut ws2, &req_wire("sub", "{\"kinds\":[4]}")).await;
    let auth2: Value = serde_json::from_str(&recv_text(&mut ws2, T).await).unwrap();
    assert_eq!(auth2[0], "AUTH", "{auth2}");
    let challenge2 = auth2[1].as_str().unwrap().to_owned();
    let closed2: Value = serde_json::from_str(&recv_text(&mut ws2, T).await).unwrap();
    assert_eq!(closed2[0], "CLOSED", "{closed2}");
    send_text(
        &mut ws2,
        &auth_wire(&key(1), &challenge2, "wss://relay.example.com"),
    )
    .await;
    let ok2: Value = serde_json::from_str(&recv_text(&mut ws2, T).await).unwrap();
    assert_eq!(ok2[0], "OK", "{ok2}");
    assert_eq!(ok2[2], false, "{ok2}");

    gw.stop().await;
    relay.stop().await;
}

/// (d) `sync::run` with `iroh:<dial>` in all three directions.
#[tokio::test]
async fn sync_iroh_down_up_both() {
    // Down: the peer's events arrive in the local store.
    let relay = iroh_relay(relay_config()).await;
    let gw = gateway(&relay).await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let evs = events(30, now() - 3_600, 10);
    publish(gw.addr, &evs).await;
    let mut o = SyncOptions::new(relay.sync_url());
    o.direction = Direction::Down;
    o.timeout = T;
    let report = nosfry::sync::run(&store, &config, o).await.unwrap();
    assert_eq!(report.outcome, Outcome::Complete, "{:?}", report.stats);
    assert_eq!(report.stats.downloaded, 30, "{:?}", report.stats);
    assert_eq!(local_count(&store), 30);
    relay.stop().await;
    drop(store);
    gw.stop().await;

    // Up: local events land in the peer's store.
    let relay = iroh_relay(relay_config()).await;
    let gw = gateway(&relay).await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let evs = events(25, now() - 7_200, 10);
    seed(&store, &config, &evs);
    let mut o = SyncOptions::new(relay.sync_url());
    o.direction = Direction::Up;
    o.timeout = T;
    let report = nosfry::sync::run(&store, &config, o).await.unwrap();
    assert_eq!(report.outcome, Outcome::Complete, "{:?}", report.stats);
    assert_eq!(report.stats.uploaded, 25, "{:?}", report.stats);
    assert_eq!(remote_count(gw.addr).await, 25);
    relay.stop().await;
    gw.stop().await;

    // Both: disjoint sets converge on either side.
    let relay = iroh_relay(relay_config()).await;
    let gw = gateway(&relay).await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let mine = events(20, now() - 3_600, 10);
    let theirs = events(15, now() - 7_200, 10);
    seed(&store, &config, &mine);
    publish(gw.addr, &theirs).await;
    let mut o = SyncOptions::new(relay.sync_url());
    o.direction = Direction::Both;
    o.timeout = T;
    let report = nosfry::sync::run(&store, &config, o).await.unwrap();
    assert_eq!(report.outcome, Outcome::Complete, "{:?}", report.stats);
    assert_eq!(report.stats.downloaded, 15, "{:?}", report.stats);
    assert_eq!(report.stats.uploaded, 20, "{:?}", report.stats);
    assert_eq!(local_count(&store), 35);
    assert_eq!(remote_count(gw.addr).await, 35);
    gw.stop().await;
    relay.stop().await;
}

/// (e) `max_connections_per_peer` keys on the endpoint id: through
/// one gateway (one iroh connection, one endpoint id) the third
/// concurrent WebSocket is refused with 429, while a second
/// gateway's different endpoint id still upgrades.
#[tokio::test]
async fn per_peer_cap_keys_on_endpoint_id() {
    let mut config = relay_config();
    default_profile(&mut config).max_connections_per_peer = 2;
    let relay = iroh_relay(config).await;
    let gw_a = gateway(&relay).await;

    let _ws1 = ws_connect(gw_a.addr).await;
    let _ws2 = ws_connect(gw_a.addr).await;
    let head = upgrade_head(gw_a.addr).await;
    assert!(head.starts_with("HTTP/1.1 429"), "{head}");

    // Another gateway means another endpoint id — another peer.
    let gw_b = gateway(&relay).await;
    let _ws3 = ws_connect(gw_b.addr).await;

    gw_a.stop().await;
    gw_b.stop().await;
    relay.stop().await;
}

/// (f)+(g) `[relay.iroh] max_connections = 1` lets the first gateway
/// connect, refuses the second's initial connect pre-handshake, and
/// the metrics served through the surviving gateway show both the
/// rejection counter and the loopback connection under
/// `path="direct"`.
#[tokio::test]
async fn listener_cap_refuses_second_connection() {
    let mut config = relay_config();
    config.relay.iroh.max_connections = 1;
    config.relay.metrics = true;
    let relay = iroh_relay(config).await;
    let gw_a = gateway(&relay).await;

    // Gateway B's first connect is refused before the handshake.
    let err = gateway_result(&relay).await.err().unwrap().to_string();
    assert!(err.contains("iroh"), "{err}");

    // Let the refusal counter land, then read /metrics through
    // gateway A.
    let body = wait_for_metrics(gw_a.addr).await;
    assert!(
        body.contains("nosfry_iroh_connections{listener=\"main\",path=\"direct\"} 1"),
        "{body}"
    );
    let rejected = body
        .lines()
        .find(|line| line.starts_with("nosfry_iroh_connections_rejected_total"))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    assert!(rejected >= 1, "{body}");

    gw_a.stop().await;
    relay.stop().await;
}

/// `/metrics` through the gateway, retried until the connection
/// gauge reports the live connection.
async fn wait_for_metrics(addr: SocketAddr) -> String {
    let deadline = Instant::now() + T;
    loop {
        let body = http_get(addr, "/metrics").await;
        if body.contains("nosfry_iroh_connections{listener=\"main\",path=\"direct\"} 1") {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "metrics never showed the connection:\n{body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// One bidirectional stream pair as a `BiStream`-shaped byte stream
/// for the ignored network test (`nosfry::iroh::BiStream` is
/// crate-private).
struct TestStream {
    recv: iroh::endpoint::RecvStream,
    send: iroh::endpoint::SendStream,
}

impl tokio::io::AsyncRead for TestStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

impl tokio::io::AsyncWrite for TestStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

/// The path kind of `conn`'s selected path, like
/// `nosfry::iroh::selected_path`.
fn selected_path(conn: &iroh::endpoint::Connection) -> &'static str {
    conn.paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map_or(
            "none",
            |path| {
                if path.is_relay() { "relay" } else { "direct" }
            },
        )
}

/// Ignored network test — needs the n0 relay network (internet).
/// Run it against a local iroh relay that publishes to n0:
///
/// ```sh
/// cargo test -p nosfry --features iroh --test iroh network_relay_path -- --ignored --nocapture
/// ```
///
/// or dial a relay on another machine:
///
/// ```sh
/// NOSFRY_IROH_PEER=<dial-address> cargo test -p nosfry --features iroh --test iroh network_relay_path -- --ignored --nocapture
/// ```
///
/// The dialing endpoint has its IP transports cleared, so the whole
/// connection must run through the iroh relay — the test asserts
/// the `relay` path, prints time to first byte and publish→OK
/// latency.
#[tokio::test]
#[ignore = "needs the n0 relay network and DNS lookup"]
async fn network_relay_path() {
    // The peer: a local iroh relay on the n0 infrastructure, or the
    // dial address NOSFRY_IROH_PEER names (cross-machine runs).
    let external = std::env::var("NOSFRY_IROH_PEER").ok();
    let relay = if external.is_none() {
        let mut config = relay_config();
        config.relay.iroh.relay_mode = IrohRelayMode::N0;
        config.relay.iroh.address_lookup = IrohAddressLookup::N0;
        Some(iroh_relay(config).await)
    } else {
        None
    };
    let dial_text = external.unwrap_or_else(|| {
        // Endpoint id only — the n0 lookup resolves it.
        relay.as_ref().unwrap().id.clone()
    });
    let dial: nosfry::iroh::DialAddr = dial_text.parse().unwrap();

    // The dialing side: no direct paths, so the only reachable
    // transport is the shared iroh relay.
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .clear_ip_transports()
        .bind()
        .await
        .unwrap();
    let iroh_cfg = Iroh {
        relay_mode: IrohRelayMode::N0,
        address_lookup: IrohAddressLookup::N0,
        ..Iroh::default()
    };
    let t0 = Instant::now();
    let conn = tokio::time::timeout(
        Duration::from_secs(60),
        endpoint.connect(dial.to_endpoint_addr(&iroh_cfg), nosfry::iroh::ALPN),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");
    eprintln!("connected in {:?}", t0.elapsed());
    assert_eq!(selected_path(&conn), "relay", "expected a relayed path");

    // Time to first byte: an HTTP GET on a fresh stream.
    let (send, recv) = conn.open_bi().await.unwrap();
    let mut io = TestStream { recv, send };
    let ttfb_start = Instant::now();
    io.write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let n = io.read(&mut [0u8; 4096]).await.unwrap();
    assert!(n > 0);
    eprintln!("time to first byte: {:?}", ttfb_start.elapsed());

    // End to end: a WebSocket on another stream, publish → OK.
    let (send, recv) = conn.open_bi().await.unwrap();
    let mut ws = WebSocket::handshake(
        format!("ws://{}.iroh/", dial.id.to_z32()).parse().unwrap(),
        TestStream { recv, send },
        yawc::Options::default(),
    )
    .await
    .unwrap();
    let ev = event(&key(1), 1, now(), &json!([]), "over the relay");
    let publish_start = Instant::now();
    ws.send(Frame::text(format!("[\"EVENT\",{}]", ev.json())))
        .await
        .unwrap();
    loop {
        let frame = tokio::time::timeout(T, ws.next())
            .await
            .expect("OK frame timeout")
            .expect("stream ended");
        if frame.opcode() == yawc::OpCode::Text {
            let msg: Value = serde_json::from_slice(frame.payload()).unwrap();
            assert_eq!(msg[0], "OK", "{msg}");
            assert_eq!(msg[2], true, "{msg}");
            break;
        }
    }
    eprintln!("publish->OK latency: {:?}", publish_start.elapsed());

    conn.close(0_u32.into(), b"done");
    endpoint.close().await;
    if let Some(relay) = relay {
        relay.stop().await;
    }
}
