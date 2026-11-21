//! Shared code for the iroh-relay spike: nosfry's exact hyper serving
//! path made generic over the accepted byte stream, plus the adapter
//! that joins a QUIC bidirectional stream pair into one
//! AsyncRead+AsyncWrite.

use std::net::SocketAddr;
#[cfg(feature = "iroh")]
use std::pin::Pin;
#[cfg(feature = "iroh")]
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "iroh")]
use tokio::io::ReadBuf;
use tokio::net::TcpListener;
use tower::ServiceExt as _;

/// Same as `nosfry`'s `HEADER_READ_TIMEOUT`.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Socket tuning copied from `nosfry::tune` (`TCP_NODELAY`, optional
/// `SO_KEEPALIVE`).
fn tune<S: std::os::fd::AsFd>(tcp: &S, keepalive: bool) {
    let socket = socket2::SockRef::from(tcp);
    if let Err(err) = socket.set_tcp_nodelay(true) {
        tracing::warn!(%err, "failed to set TCP_NODELAY");
    }
    if keepalive && let Err(err) = socket.set_keepalive(true) {
        tracing::warn!(%err, "failed to set SO_KEEPALIVE");
    }
}

/// Serve one byte stream as one HTTP/1.1 connection, wiring identical
/// to `nosfry::spawn_connection` minus the graceful-stop machinery:
/// hyper `http1::Builder` + `TowerToHyperService` + `.with_upgrades()`,
/// inserting `ConnectInfo(peer)` into every request's extensions
/// (the relay's root handler fails with 500 without it).
pub fn serve_stream<S>(stream: S, router: axum::Router, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(router.into_service().map_request(
        move |mut req: hyper::Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            req.map(Body::new)
        },
    ));
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::debug!(%err, "connection error");
        }
    });
}

/// The same loop as `nosfry::accept_loop` for plain TCP clients.
pub async fn tcp_accept_loop(listener: TcpListener, router: axum::Router, keepalive: bool) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::error!(%err, "TCP accept error");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        tune(&tcp, keepalive);
        serve_stream(tcp, router.clone(), peer);
    }
}

/// Build the shared relay server and its router.
pub fn relay_server(
    config: nosfry::config::Config,
) -> Result<(nosfry::Server, axum::Router), nosfry::ServerError> {
    let server = nosfry::Server::new(config)?;
    let router = server.router();
    Ok((server, router))
}

/// A QUIC bidirectional stream pair (send + recv) viewed as a single
/// byte stream. `poll_read` delegates to the receive half, the write
/// side to the send half, so QUIC stream FIN (send-side shutdown)
/// propagates exactly like TCP half-close.
#[cfg(feature = "iroh")]
pub struct BiStream {
    /// Receive half.
    pub recv: iroh::endpoint::RecvStream,
    /// Send half.
    pub send: iroh::endpoint::SendStream,
}

#[cfg(feature = "iroh")]
impl AsyncRead for BiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

#[cfg(feature = "iroh")]
impl AsyncWrite for BiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

#[cfg(feature = "iroh")]
pub use iroh_support::*;

#[cfg(feature = "iroh")]
mod iroh_support {
    use std::path::Path;

    use anyhow::{Context as _, Result};
    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

    /// The spike's ALPN: each bidirectional QUIC stream carries one
    /// plain HTTP/1.1 connection.
    pub const ALPN: &[u8] = b"nosfry/http1";

    /// Load the persistent secret key from `path`, creating it 0600 on
    /// first run.
    pub fn secret_key(path: &Path) -> Result<SecretKey> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let bytes: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .context("key file is not 32 bytes")?;
                Ok(SecretKey::from_bytes(&bytes))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let key = SecretKey::generate();
                write_key(path, &key)?;
                Ok(key)
            }
            Err(err) => Err(err).context("read key file"),
        }
    }

    fn write_key(path: &Path, key: &SecretKey) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(path).context("create key file")?;
        use std::io::Write as _;
        file.write_all(&key.to_bytes()).context("write key file")
    }

    /// Build and bind an endpoint on the n0 presets, with optional
    /// custom relay map, relay-only (no IP transports) mode, and a
    /// no-relay mode (relay servers disabled completely) for the
    /// forced-direct-path experiment.
    pub async fn endpoint(
        key: &SecretKey,
        relay_only: bool,
        relay_url: Option<&str>,
        no_relay: bool,
    ) -> Result<Endpoint> {
        let mut builder = Endpoint::builder(presets::N0)
            .secret_key(key.clone())
            .alpns(vec![ALPN.to_vec()]);
        if let Some(url) = relay_url {
            builder = builder.relay_mode(RelayMode::custom([url.parse()
                .context("relay url")?]));
        } else if no_relay {
            builder = builder.relay_mode(RelayMode::Disabled);
        }
        if relay_only {
            builder = builder.clear_ip_transports();
        }
        builder.bind().await.context("endpoint bind")
    }

    /// Hex-serialized `EndpointAddr` ticket for CLI exchange (the
    /// addr's serde JSON form, hex-encoded).
    pub fn ticket(addr: &EndpointAddr) -> String {
        match serde_json::to_vec(addr) {
            Ok(json) => faster_hex::hex_string(&json),
            Err(_) => String::new(),
        }
    }

    /// Parse the `<endpoint-id-or-ticket>` CLI argument: `ticket:<hex>`
    /// decodes an [`EndpointAddr`]; anything else parses as an
    /// `EndpointId` (z32) with no direct addrs (resolved via
    /// pkarr/relay).
    pub fn parse_peer(arg: &str) -> Result<EndpointAddr> {
        if let Some(hex) = arg.strip_prefix("ticket:") {
            let bytes = faster_hex::hex_decode_vec(hex.as_bytes())
                .context("ticket hex")?;
            serde_json::from_slice(&bytes).context("ticket json")
        } else {
            Ok(EndpointAddr::new(arg.parse().context("endpoint id")?))
        }
    }

    /// The `EndpointAddr` hint a dialer needs for the direct-path test
    /// on loopback: the endpoint id plus every bound socket as an IP
    /// transport address.
    pub fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
        let mut addr = EndpointAddr::new(endpoint.id());
        for socket in endpoint.bound_sockets() {
            addr = addr.with_ip_addr(socket);
        }
        addr
    }
}
