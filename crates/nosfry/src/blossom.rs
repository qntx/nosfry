//! Blossom blob-server wiring (the `blossom` cargo feature): the
//! `FsStore` open, the router state, the live-policy channel, and
//! the pieces `/metrics` and the accept loops share.
//!
//! The blob service serves only on `[[blossom.listen]]` addresses;
//! the relay router never mounts there and vice versa.

use std::sync::Arc;
use std::time::Duration;

use nosfry_blossom::{BlobStore as _, FsStore, Metrics, Mode, Policy, Shared, Slots};
use nosfry_core::event::PublicKey;
use nosfry_core::moderation::Moderation;
use tokio::sync::watch;

use crate::ServerError;
use crate::config::Config;

/// Per-chunk idle timeout while streaming an upload (408 past it).
const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The running blob service: what `serve()` hands to the accept
/// loops, `reload_loop`, and `/metrics`.
#[derive(Clone)]
pub(crate) struct Blossom {
    /// The Blossom router — mounted only on blossom listeners.
    pub(crate) router: axum::Router,
    /// The `watch` channel `reload_loop` pushes live
    /// [`nosfry_blossom::Policy`] snapshots through.
    pub(crate) policy_tx: watch::Sender<Arc<Policy>>,
    /// `nosfry_blossom_*` counters/gauges appended to `/metrics`.
    pub(crate) metrics: Arc<Metrics>,
    /// The store — `totals()` feeds the `stored_*` gauges.
    pub(crate) store: FsStore,
    /// `blossom.max_connections` — acquired per accepted blossom
    /// connection and held for its lifetime.
    pub(crate) connections: Arc<tokio::sync::Semaphore>,
}

impl Blossom {
    /// The `nosfry_blossom_*` block of the `/metrics` render —
    /// empty when the totals read fails (a scrape must not fail
    /// because LMDB was briefly contended).
    pub(crate) fn render_metrics(&self) -> String {
        self.store
            .totals()
            .map_or_else(|_| String::new(), |usage| self.metrics.render(&usage))
    }
}

/// Open the blob service — `None` when `[blossom] enabled` is off.
///
/// # Errors
///
/// [`ServerError::Blossom`] when the store cannot open,
/// [`ServerError::RelayValue`] when `public_url` is unusable
/// (unreachable after a validated load).
pub(crate) fn open(
    config: &Config,
    admins: &Arc<[PublicKey]>,
    moderation: watch::Receiver<Arc<Moderation>>,
) -> Result<Option<Blossom>, ServerError> {
    if !config.blossom.enabled {
        return Ok(None);
    }
    let store = FsStore::open(&config.blossom.dir, Mode::Serve)
        .map_err(|err| ServerError::Blossom(err.to_string()))?;
    let (policy_tx, policy_rx) = watch::channel(Arc::new(config.blossom.policy(admins)));
    let metrics = Arc::new(Metrics::default());
    let shared = Arc::new(Shared {
        store: store.clone(),
        settings: config.blossom.settings()?,
        policy: policy_rx,
        moderation,
        slots: Slots::new(config.blossom.max_concurrent_uploads),
        metrics: Arc::clone(&metrics),
        now: nosfry_blossom::http::unix_now,
        idle_timeout: UPLOAD_IDLE_TIMEOUT,
    });
    tracing::info!(
        target: "nosfry::blossom",
        dir = %config.blossom.dir.display(),
        max_connections = config.blossom.max_connections,
        "blossom blob server enabled"
    );
    Ok(Some(Blossom {
        router: nosfry_blossom::router(shared),
        policy_tx,
        metrics,
        store,
        connections: Arc::new(tokio::sync::Semaphore::new(config.blossom.max_connections)),
    }))
}
