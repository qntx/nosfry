//! Dial `.onion` peer URLs through an embedded Arti client (the
//! `onion` cargo feature).
//!
//! The client shares `[relay.onion] state_dir`'s `state/` and
//! `cache/` pair with the onion listeners' Arti, deliberately: one
//! guard set per installation instead of a second set of entry
//! guards, and a directory cache that a running relay keeps warm so
//! a `nosfry sync` next to it bootstraps in seconds. Arti's own lock
//! files arbitrate the two processes — the state manager's lock and
//! tor-dirmgr's `dir.lock`: a client that loses them proceeds with
//! the state and cache read-only (arti-client `client.rs`, "We'll
//! proceed in read-only mode"), so a `sync` next to a live relay
//! cannot corrupt them. The
//! command already runs as the relay's user (it opens the same LMDB
//! store), so the 0700 directory is readable.

use std::sync::Arc;
use std::time::Duration;

use arti_client::config::BoolOrAuto;
use arti_client::{BootstrapBehavior, DataStream, StreamPrefs, TorClient};
use tokio::sync::watch;

use super::SyncError;
use crate::config::Onion;
use crate::onion::{self, Client};

/// Cold bootstrap downloads the consensus; a warm cache (a running
/// relay's, or a recent run's) takes seconds.
const TOR_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);

/// The run's shared Arti client: state under `onion.state_dir`,
/// manually bootstrapped within [`TOR_BOOTSTRAP_TIMEOUT`] with
/// progress logged at 10 % steps, and default stream prefs that
/// allow onion services explicitly (not just
/// `address_filter.allow_onion_addrs`'s `Auto` default).
///
/// # Errors
///
/// [`SyncError::Connect`] on a state-dir refusal, client-build or
/// bootstrap failure; Arti's own text stays safelog-redacted.
pub(crate) async fn client(onion: &Onion) -> Result<Arc<Client>, SyncError> {
    crate::state_dir::prepare(&onion.state_dir, "onion").map_err(SyncError::Connect)?;
    let tor_cfg = onion::tor_config(onion).map_err(|err| SyncError::Connect(err.to_string()))?;
    let client = TorClient::builder()
        .config(tor_cfg)
        .bootstrap_behavior(BootstrapBehavior::Manual)
        .create_unbootstrapped()
        .map_err(|err| SyncError::Connect(format!("tor client build failed: {err}")))?;
    // Reuse the listener's progress logger: the open watch channel
    // never fires; closing it ends the task once bootstrap resolves.
    let (stop_tx, stop_rx) = watch::channel(());
    let progress = tokio::spawn(onion::log_bootstrap(Arc::clone(&client), stop_rx));
    let result = tokio::time::timeout(TOR_BOOTSTRAP_TIMEOUT, client.bootstrap()).await;
    drop(stop_tx);
    progress.await.ok();
    let mut prefs = StreamPrefs::new();
    prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
    match result {
        Err(_) => Err(SyncError::Connect(format!(
            "tor bootstrap timed out after {} s",
            TOR_BOOTSTRAP_TIMEOUT.as_secs()
        ))),
        Ok(Err(err)) => Err(SyncError::Connect(format!("tor bootstrap failed: {err}"))),
        Ok(Ok(())) => Ok(client.with_prefs(prefs)),
    }
}

/// Open `host:port` over the shared `client`, bounded by `timeout`.
/// `host` keeps any labels before the v3 address (Tor's vhosting).
///
/// # Errors
///
/// [`SyncError::Connect`] on timeout or an Arti failure — safelog
/// redacts its internals; the onion host is the operator's argument.
pub(crate) async fn connect(
    client: &Arc<Client>,
    host: String,
    port: u16,
    timeout: Duration,
) -> Result<DataStream, SyncError> {
    match tokio::time::timeout(timeout, client.connect((host, port))).await {
        Err(_) => Err(SyncError::Connect(format!(
            "onion connect timed out after {} s",
            timeout.as_secs()
        ))),
        Ok(Err(err)) => Err(SyncError::Connect(format!("onion connect failed: {err}"))),
        Ok(Ok(stream)) => Ok(stream),
    }
}
