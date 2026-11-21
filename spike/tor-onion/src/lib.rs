//! Shared serving path for the tor-onion spike: exactly the hyper
//! wiring `nosfry`'s `spawn_connection`/`accept_loop` use, generic over
//! the accepted byte stream.

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
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

/// Build the shared relay server, its router, and a TCP listener on the
/// configured bind/port. Both spike binaries use this as the base.
pub fn relay_server(
    config: nosfry::config::Config,
) -> Result<(nosfry::Server, axum::Router), nosfry::ServerError> {
    let server = nosfry::Server::new(config)?;
    let router = server.router();
    Ok((server, router))
}
