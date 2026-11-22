//! Shared test helpers: deterministic signing, client framing, server
//! bootstrap.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs,
    unreachable_pub,
    reason = "test helpers may panic and are only partially used per binary"
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nosfry::config::{Config, Listen, ListenAddress, Profile};
use nosfry_core::event::{Event, EventLimits, UnverifiedEvent};
use secp256k1::{Keypair, SecretKey, schnorr};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{oneshot, watch};

/// Fixed `n`-th test keypair.
pub fn key(n: u8) -> Keypair {
    let mut bytes = [0u8; 32];
    bytes[31] = n.max(1);
    Keypair::from_secret_key(&SecretKey::from_secret_bytes(bytes).unwrap())
}

/// Build a signed, verified event.
pub fn event(
    keypair: &Keypair,
    kind: u16,
    created_at: u64,
    tags: &Value,
    content: &str,
) -> Arc<Event> {
    let pubkey = faster_hex::hex_string(&keypair.x_only_public_key().0.to_byte_array());
    let preimage =
        serde_json::to_string(&json!([0, pubkey, created_at, kind, tags, content])).unwrap();
    let id = Sha256::digest(preimage.as_bytes());
    let sig = schnorr::sign_no_aux_rand(&id, keypair);
    let event_json = serde_json::to_string(&json!({
        "id": faster_hex::hex_string(&id),
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": faster_hex::hex_string(&sig.to_byte_array()),
    }))
    .unwrap();
    Arc::new(
        UnverifiedEvent::parse(&event_json, &EventLimits::default())
            .unwrap()
            .verify(&EventLimits::default())
            .unwrap(),
    )
}

/// The client EVENT wire message for an event.
pub fn event_wire(event: &Event) -> String {
    format!("[\"EVENT\",{}]", event.json())
}

/// A REQ wire message.
pub fn req_wire(sub_id: &str, filters: &str) -> String {
    format!("[\"REQ\",\"{sub_id}\",{filters}]")
}

/// A `COUNT` wire message.
pub fn count_wire(sub_id: &str, filters: &str) -> String {
    format!("[\"COUNT\",\"{sub_id}\",{filters}]")
}

/// A CLOSE wire message.
pub fn close_wire(sub_id: &str) -> String {
    format!("[\"CLOSE\",\"{sub_id}\"]")
}

/// Shared test config: rate limits and the per-peer connection cap
/// are disabled so traffic-heavy tests are not throttled; tests that
/// need them set the fields back on [`default_profile`].
pub fn config() -> Config {
    let mut config = Config::default();
    let profile = default_profile(&mut config);
    profile.rate_limits = nosfry_core::limits::RateLimits {
        events_per_second: 0,
        events_burst: 0,
        reqs_per_second: 0,
        reqs_burst: 0,
        ip_events_per_second: 0,
        ip_events_burst: 0,
        ip_reqs_per_second: 0,
        ip_reqs_burst: 0,
    };
    profile.max_connections_per_peer = 0;
    config
}

/// The `default` profile entry for test mutation.
pub fn default_profile(config: &mut Config) -> &mut Profile {
    config
        .relay
        .profiles
        .entry("default".to_owned())
        .or_default()
}

/// A `[[relay.listen]]` entry on an ephemeral TCP port.
pub fn tcp_listen() -> Listen {
    Listen {
        address: ListenAddress::Tcp("127.0.0.1:0".parse().unwrap()),
        profile: "default".to_owned(),
        real_ip_header: String::new(),
    }
}

/// A `[[relay.listen]]` entry on a unix socket path.
pub fn unix_listen(path: &Path) -> Listen {
    Listen {
        address: ListenAddress::Unix(path.to_path_buf()),
        profile: "default".to_owned(),
        real_ip_header: String::new(),
    }
}

/// Running test relay.
pub struct Relay {
    /// Bound TCP address (`127.0.0.1:0` when the config has no TCP
    /// listener — a unix-only relay).
    pub addr: SocketAddr,
    /// The first unix listener's socket path, if any.
    pub unix_path: Option<PathBuf>,
    /// Push a config reload (the SIGHUP path's channel end).
    reload_tx: watch::Sender<Config>,
    stop: oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
    /// Keep the store directory alive.
    _dir: tempfile::TempDir,
}

impl Relay {
    /// Start a relay with the default config on a tempdir store.
    pub async fn start() -> Self {
        Self::start_with(config()).await
    }

    /// Start with a caller-adjusted config; the `db.path` inside it is
    /// overridden by the tempdir unless `db_path` is set. The shipped
    /// `127.0.0.1:7777` listener is replaced by an ephemeral port;
    /// tests that set `relay.listen` explicitly keep their own.
    pub async fn start_with(mut config: Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        if config.db.path.as_os_str() == "./nosfry-db" {
            config.db.path = dir.path().to_path_buf();
        }
        if config.relay.listen == Config::default().relay.listen {
            config.relay.listen = vec![tcp_listen()];
        }
        let unix_path = config
            .relay
            .listen
            .iter()
            .find_map(|listen| match &listen.address {
                ListenAddress::Unix(path) => Some(path.clone()),
                ListenAddress::Tcp(_) => None,
            });
        let (tx, rx) = oneshot::channel();
        let (reload_tx, reload_rx) = watch::channel(config.clone());
        let listeners = nosfry::bind(&config).await.unwrap();
        let addr = listeners
            .iter()
            .find_map(nosfry::Listener::local_addr)
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
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
        // Wait until a listener answers.
        for _ in 0..100 {
            let ready = match (&unix_path, addr.port()) {
                (Some(path), 0) => tokio::net::UnixStream::connect(path).await.is_ok(),
                _ => tokio::net::TcpStream::connect(addr).await.is_ok(),
            };
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Self {
            addr,
            unix_path,
            reload_tx,
            stop: tx,
            handle,
            _dir: dir,
        }
    }

    /// Send a config through the reload channel (what SIGHUP does in
    /// the binary).
    pub fn reload(&self, config: Config) {
        self.reload_tx.send(config).unwrap();
    }

    /// A websocket client connection.
    pub async fn connect(&self) -> yawc::TcpWebSocket {
        let url = format!("ws://{}/", self.addr);
        yawc::WebSocket::connect(url.parse().unwrap())
            .await
            .unwrap()
    }

    /// A websocket client connection over the first unix listener.
    pub async fn connect_unix(&self) -> yawc::WebSocket<tokio::net::UnixStream> {
        let path = self.unix_path.as_ref().expect("relay has no unix listener");
        let io = tokio::net::UnixStream::connect(path).await.unwrap();
        yawc::WebSocket::handshake(
            "ws://localhost/".parse().unwrap(),
            io,
            yawc::Options::default(),
        )
        .await
        .unwrap()
    }

    /// Graceful stop: drop the senders, drain, join.
    pub async fn stop(self) {
        self.stop.send(()).ok();
        self.handle.await.ok();
    }
}

/// Receive one text frame within `timeout`; panics on close/timeout.
pub async fn recv_text<S>(ws: &mut yawc::WebSocket<S>, timeout: Duration) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;
    loop {
        let frame = tokio::time::timeout(timeout, ws.next())
            .await
            .expect("frame timeout")
            .expect("stream ended");
        if frame.opcode() == yawc::OpCode::Text {
            return std::str::from_utf8(frame.payload()).unwrap().to_owned();
        }
    }
}

/// Send one text frame.
pub async fn send_text<S>(ws: &mut yawc::WebSocket<S>, text: &str)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::SinkExt;
    ws.send(yawc::Frame::text(text.to_owned())).await.unwrap();
}
