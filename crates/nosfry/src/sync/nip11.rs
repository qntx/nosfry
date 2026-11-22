//! Fetch the peer's NIP-11 document over an already-dialed stream:
//! one `GET` with `Accept: application/nostr+json`, status 200 only,
//! no redirects, body capped at 64 KiB, the whole exchange under the
//! caller's timeout. Every failure is `None` — the caller warns and
//! assumes default limits.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use nosfry_core::client::PeerLimits;
use tokio::io::{AsyncRead, AsyncWrite};

use super::dial::Target;

/// NIP-11 body cap: real documents are a few KiB.
const MAX_BODY: usize = 64 << 10;

/// Fetch and parse the peer's NIP-11 document; `None` on any
/// transport, status, or shape failure.
pub(crate) async fn fetch<S>(io: S, target: &Target, timeout: Duration) -> Option<PeerLimits>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(timeout, fetch_inner(io, target))
        .await
        .ok()
        .flatten()
}

async fn fetch_inner<S>(io: S, target: &Target) -> Option<PeerLimits>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .ok()?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::debug!(%err, "NIP-11 connection failed");
        }
    });
    let path = target.url.query().map_or_else(
        || target.url.path().to_owned(),
        |query| format!("{}?{query}", target.url.path()),
    );
    let host = target.url.port().map_or_else(
        || target.host.clone(),
        |port| format!("{}:{port}", target.host),
    );
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(hyper::header::HOST, host)
        .header(hyper::header::ACCEPT, "application/nostr+json")
        .body(Empty::<Bytes>::new())
        .ok()?;
    let response = sender.send_request(request).await.ok()?;
    if response.status() != hyper::StatusCode::OK {
        return None;
    }
    let mut body: Incoming = response.into_body();
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > MAX_BODY {
                return None;
            }
            buf.extend_from_slice(&data);
        }
    }
    PeerLimits::parse(&buf)
}
