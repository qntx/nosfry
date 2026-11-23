//! Dial `iroh:` peer URLs through an ephemeral iroh endpoint (the
//! `iroh` cargo feature).
//!
//! Unlike the onion route's shared Arti state, a sync dials with a
//! throwaway endpoint: a generated secret key under `[relay.iroh]`'s
//! relay and address-lookup settings, no identity file and no state
//! dir. The endpoint and its one connection outlive the resolve:
//! [`dial::Dialer`](super::dial::Dialer) holds them for the run so
//! the NIP-11 fetch and the WebSocket ride the same QUIC connection,
//! and [`close`] shuts the endpoint down when the run ends.

use std::time::Duration;

use ::iroh::endpoint::Connection;
use ::iroh::{Endpoint, SecretKey};

use super::SyncError;
use crate::iroh::{ALPN, BiStream, DialAddr, builder};

/// How long a graceful endpoint close may take before the command
/// stops waiting — the sockets and relay connections drop either
/// way.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bind an ephemeral endpoint under `cfg` and connect it to `dial`
/// within `timeout`. The endpoint comes back with the connection so
/// the dialer can hold both for the run; on failure it is closed
/// gracefully before the error returns — a dropped endpoint logs an
/// abort error over the real one.
///
/// # Errors
///
/// [`SyncError::Connect`] on bind or connect failure or timeout.
pub(crate) async fn connect(
    cfg: &crate::config::Iroh,
    dial: &DialAddr,
    timeout: Duration,
) -> Result<(Endpoint, Connection), SyncError> {
    let endpoint = builder(cfg)
        .secret_key(SecretKey::generate())
        .bind()
        .await
        .map_err(|err| SyncError::Connect(format!("iroh endpoint bind failed: {err}")))?;
    let result =
        tokio::time::timeout(timeout, endpoint.connect(dial.to_endpoint_addr(cfg), ALPN)).await;
    match result {
        Ok(Ok(connection)) => Ok((endpoint, connection)),
        result => {
            drop(tokio::time::timeout(CLOSE_TIMEOUT, endpoint.close()).await);
            Err(match result {
                Ok(Err(err)) => SyncError::Connect(format!("iroh connect failed: {err}")),
                _ => SyncError::Connect("iroh connect timed out".to_owned()),
            })
        }
    }
}

/// Open a new bidirectional stream on `conn`, bounded by `timeout`.
/// Every stream is an ordinary HTTP/1.1 connection (ALPN
/// `nosfry/http/1`).
///
/// # Errors
///
/// [`SyncError::Connect`] on timeout or a stream-open failure.
pub(crate) async fn open(conn: &Connection, timeout: Duration) -> Result<BiStream, SyncError> {
    let (send, recv) = tokio::time::timeout(timeout, conn.open_bi())
        .await
        .map_err(|_| {
            SyncError::Connect(format!(
                "iroh stream open timed out after {} s",
                timeout.as_secs()
            ))
        })?
        .map_err(|err| SyncError::Connect(format!("iroh stream open failed: {err}")))?;
    Ok(BiStream { recv, send })
}

/// Gracefully close `endpoint`, bounded so a stalled close cannot
/// hang the command.
pub(crate) async fn close(endpoint: Endpoint) {
    if tokio::time::timeout(CLOSE_TIMEOUT, endpoint.close())
        .await
        .is_err()
    {
        tracing::warn!("iroh endpoint close stalled");
    }
}
