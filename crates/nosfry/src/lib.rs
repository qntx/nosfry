//! nosfry: the native Nostr relay.
//!
//! Thread topology: one tokio multi-thread runtime for connection
//! tasks, one OS writer thread, M monitor shard threads, and N reader
//! threads. LMDB is only touched by the writer and reader threads;
//! everything else communicates over bounded channels.
#![cfg_attr(
    test,
    allow(
        unused_crate_dependencies,
        reason = "dev-deps are exercised by integration tests"
    )
)]

pub mod admin;
mod channels;
pub mod config;
mod connection;
mod http;
mod limiter;
mod management;
mod metrics;
mod policy;
mod reader;
mod shard;
mod writer;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::thread::JoinHandle;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use clap as _;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use nosfry_core::event::PublicKey;
use nosfry_core::moderation::Moderation;
use nosfry_lmdb::Store;
use rlimit as _;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tower::ServiceExt as _;
use tracing_subscriber as _;

use crate::channels::{ReaderMsg, ShardMsg, WriterMsg};
use crate::config::Config;

/// How many publish requests the writer queues before backpressuring
/// connections; the byte budget in [`WRITER_QUEUE_BYTES`] binds first
/// under sustained load. One write transaction drains the whole
/// inbox, so this also bounds the events in a commit.
const WRITER_QUEUE: usize = 65_536;

/// Bytes of verified event JSON queued on the writer across all
/// connections; a publish acquires its `json().len()` before it may
/// occupy an inbox slot, so a flood of large events backpressures at
/// 64 MiB instead of an event count. With [`WRITER_QUEUE`] it also
/// bounds one write transaction.
const WRITER_QUEUE_BYTES: usize = 64 << 20;

/// How many messages one monitor shard queues.
const SHARD_QUEUE: usize = 4096;

/// Fatal server errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
    /// Filesystem/config IO failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// LMDB failure.
    #[error("store: {0}")]
    Store(#[from] nosfry_lmdb::StoreError),
    /// TOML parse failure.
    #[error("config: {0}")]
    Config(#[from] toml::de::Error),
    /// Invalid `[relay] service_url`.
    #[error("config: relay.service_url: {0}")]
    ServiceUrl(#[from] nosfry_core::url::RelayUrlError),
    /// Invalid `[relay.management] admins` entry.
    #[error("config: relay.management.admins: {0}: not a 64-hex pubkey")]
    Admins(String),
    /// Invalid `[relay.info]` value.
    #[error("config: {0}")]
    Info(#[from] nosfry_core::info::InfoError),
    /// Invalid `[relay.filter_validation]` value.
    #[error("config: {0}")]
    FilterValidation(#[from] nosfry_core::limits::FilterValidationError),
    /// An invalid `[relay]` value with no dedicated error type; the
    /// message names the key.
    #[error("config: {0}")]
    RelayValue(String),
    /// The worker shutdown task failed.
    #[error("worker shutdown: {0}")]
    Shutdown(#[source] tokio::task::JoinError),
    /// A worker thread failed to start.
    #[error("thread spawn failed: {0}")]
    Spawn(#[source] std::io::Error),
}

/// The live-reloadable slice of server state. Every reader clones the
/// `Arc` out of a `watch` borrow — never holding the borrow across an
/// `.await` — so a reload never blocks a request. Restart-only fields
/// (see [`Config::reloadable_from`]) stay frozen at startup values.
#[derive(Debug, Clone)]
pub(crate) struct Live {
    /// Effective configuration.
    pub(crate) config: Arc<Config>,
    /// Session limits assembled by [`Config::limits`]; new connections
    /// only — existing sessions keep the limits they started with.
    pub(crate) limits: Arc<nosfry_core::limits::Limits>,
    /// Pre-serialized NIP-11 document, rebuilt on each reload.
    pub(crate) nip11: axum::body::Bytes,
    /// Pre-rendered landing page, rebuilt with `nip11`.
    pub(crate) landing: axum::body::Bytes,
    /// Active write-policy plugin; read at each publish so a reload
    /// applies to the next event on every connection.
    pub(crate) policy: Option<policy::WritePolicy>,
    /// Parsed `[relay.management] admins` — hex strings are validated
    /// at load; this set is parsed once per snapshot.
    pub(crate) admins: Arc<[PublicKey]>,
}

/// The `monitors` shard channel pairs.
fn shard_channels(monitors: usize) -> (Vec<mpsc::Sender<ShardMsg>>, Vec<mpsc::Receiver<ShardMsg>>) {
    (0..monitors)
        .map(|_| mpsc::channel::<ShardMsg>(SHARD_QUEUE))
        .unzip()
}

/// The `readers` reader channel pairs; senders are shared by every
/// shard for scan routing.
fn reader_channels(
    readers: usize,
) -> (
    Arc<[std::sync::mpsc::Sender<ReaderMsg>]>,
    Vec<std::sync::mpsc::Receiver<ReaderMsg>>,
) {
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..readers)
        .map(|_| std::sync::mpsc::channel::<ReaderMsg>())
        .unzip();
    (txs.into(), rxs)
}

/// Start the write-policy task unless the plugin command is empty.
fn start_policy(cfg: &config::WritePolicy) -> Option<policy::WritePolicy> {
    (!cfg.plugin.is_empty())
        .then(|| policy::WritePolicy::new(&cfg.plugin, Duration::from_secs(cfg.timeout_seconds)))
}

/// Apply reloaded configs until the `reload` channel closes, publishing
/// a fresh [`Live`] for every valid one (see [`reload_once`]).
async fn reload_loop(
    mut reload: watch::Receiver<Config>,
    live_tx: watch::Sender<Arc<Live>>,
    limiter: Arc<limiter::ConnectionLimiter>,
    moderation: watch::Receiver<Arc<Moderation>>,
    mut live: Arc<Live>,
) {
    while reload.changed().await.is_ok() {
        let incoming = reload.borrow_and_update().clone();
        if let Some(next) = reload_once(incoming, &live, &limiter) {
            live = next;
            live_tx.send_modify(|current| {
                let snapshot = moderation.borrow().clone();
                let mut updated = (*live).clone();
                updated.nip11 = http::nip11(&updated.config, &updated.limits, &snapshot).into();
                updated.landing = http::landing(&updated.config, &snapshot).into();
                *current = Arc::new(updated);
            });
        }
    }
}

/// Spawn one monitor-shard thread per inbox, all sharing the
/// process-wide live-subscription charge.
fn spawn_shards(
    store: &Arc<Store>,
    shard_rxs: Vec<mpsc::Receiver<ShardMsg>>,
    readers: &Arc<[std::sync::mpsc::Sender<ReaderMsg>]>,
    charge: &Arc<AtomicUsize>,
    budget: usize,
    threads: &mut Vec<JoinHandle<()>>,
) -> Result<(), ServerError> {
    for rx in shard_rxs {
        let shard_store = Arc::clone(store);
        let shard_readers = Arc::clone(readers);
        let shard_charge = Arc::clone(charge);
        threads.push(
            std::thread::Builder::new()
                .name("nosfry-monitor".into())
                .spawn(move || {
                    shard::run(&shard_store, rx, shard_readers, shard_charge, budget);
                })
                .map_err(ServerError::Spawn)?,
        );
    }
    Ok(())
}

/// Reader tunables derived from the startup config (restart-only:
/// readers hold them for their lifetime).
fn reader_tuning(config: &Config, sync_memory: &Arc<AtomicUsize>) -> reader::Tuning {
    reader::Tuning {
        budget: Duration::from_micros(config.relay.query_timeslice_budget_microseconds),
        high_water: config.relay.max_pending_outbound_bytes / 4,
        total_budget: config.relay.max_pending_outbound_bytes_total,
        max_filter_limit: config.relay.limits.max_filter_limit,
        max_filter_limit_count: config.relay.limits.max_filter_limit_count,
        max_sync_events: config.relay.limits.max_sync_events,
        max_sync_memory_bytes: config.relay.max_sync_memory_bytes,
        sync_memory: Arc::clone(sync_memory),
    }
}

/// One reload: merge, validate, then apply. Validation runs before any
/// side effect, so a rejected reload leaves the connection caps, the
/// write-policy task, and the limits exactly as they were (`None`).
/// The cached NIP-11 document is seeded from the running [`Live`];
/// `reload_loop` re-derives it from the latest moderation snapshot
/// inside the publish's `send_modify`.
fn reload_once(
    incoming: Config,
    live: &Live,
    limiter: &limiter::ConnectionLimiter,
) -> Option<Arc<Live>> {
    let (merged, ignored) = live.config.reloadable_from(incoming);
    if !ignored.is_empty() {
        tracing::warn!(?ignored, "restart-only keys ignored on config reload");
    }
    let limits = merged.limits().inspect_err(log_invalid_reload).ok()?;
    let admins = merged.admins().inspect_err(log_invalid_reload).ok()?;
    Some(Arc::new(apply_reload(
        merged, limits, admins, live, limiter,
    )))
}

fn log_invalid_reload(err: &ServerError) {
    tracing::error!(%err, "invalid reloaded config; keeping the running one");
}

/// Apply a validated reload: update the connection caps, replace the
/// write-policy task only when its command or timeout changed, and
/// build the next [`Live`]. The cached NIP-11 document and landing
/// page carry over; `reload_loop` re-derives both from the latest
/// moderation snapshot at publish time.
fn apply_reload(
    merged: Config,
    limits: nosfry_core::limits::Limits,
    admins: Arc<[PublicKey]>,
    live: &Live,
    limiter: &limiter::ConnectionLimiter,
) -> Live {
    limiter.update_caps(
        merged.relay.max_connections,
        merged.relay.max_connections_per_ip,
        limits.rate,
    );
    let policy = if merged.relay.write_policy == live.config.relay.write_policy {
        live.policy.clone()
    } else {
        start_policy(&merged.relay.write_policy)
    };
    tracing::info!("configuration reloaded");
    Live {
        nip11: live.nip11.clone(),
        landing: live.landing.clone(),
        config: Arc::new(merged),
        limits: Arc::new(limits),
        policy,
        admins,
    }
}

/// The shared deflate state pool, sized for the messages compressed
/// at the same moment — the runtime's worker count, not the
/// connection count. Must run inside the runtime.
fn deflate_pool() -> yawc::DeflatePool {
    yawc::DeflatePool::new(tokio::runtime::Handle::current().metrics().num_workers())
}

/// A running server: router state plus the worker threads.
#[derive(Debug)]
pub struct Server {
    state: http::AppState,
    live_tx: watch::Sender<Arc<Live>>,
    stop_tx: watch::Sender<bool>,
    writer_tx: mpsc::Sender<WriterMsg>,
    /// Dropping this unblocks the expiry timer's `recv_timeout` at once.
    expire_stop: std::sync::mpsc::Sender<()>,
    shard_txs: Vec<mpsc::Sender<ShardMsg>>,
    reader_txs: Arc<[std::sync::mpsc::Sender<ReaderMsg>]>,
    threads: Vec<JoinHandle<()>>,
}

impl Server {
    /// Start every worker thread and build the router state.
    ///
    /// # Errors
    ///
    /// [`ServerError::Store`] when the store fails to open,
    /// [`ServerError::Spawn`] when a worker thread cannot start.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime: the deflate pool is sized from the
    /// current runtime's worker count.
    pub fn new(config: Config) -> Result<Self, ServerError> {
        let config = Arc::new(config);
        let store = Arc::new(Store::open(&config.db.path, &config.store_options())?);
        let monitors = config.relay.threads.monitors.max(1);
        let readers = config.relay.threads.readers.max(1);
        let metrics = Arc::new(metrics::Metrics::new());
        // Process-wide pending outbound bytes, shared by every
        // connection's `Outbound`; process-wide sealed-sync-storage
        // bytes, shared by every reader; process-wide live-subscription
        // bytes, shared by every monitor shard.
        let outbound_total = Arc::new(AtomicUsize::new(0));
        let sync_memory = Arc::new(AtomicUsize::new(0));
        let subscription_bytes = Arc::new(AtomicUsize::new(0));
        let tuning = reader_tuning(&config, &sync_memory);
        let mut threads = Vec::with_capacity(monitors + readers + 1);
        let (stop_tx, stop_rx) = watch::channel(false);

        // All channels first: shards forward scan control into reader
        // inboxes, readers reply through shard inboxes.
        let (shard_txs, shard_rxs) = shard_channels(monitors);
        let (reader_txs, reader_rxs) = reader_channels(readers);

        // Monitor shards.
        spawn_shards(
            &store,
            shard_rxs,
            &reader_txs,
            &subscription_bytes,
            config.relay.max_subscription_bytes_total,
            &mut threads,
        )?;

        // Readers.
        let tuning = Arc::new(tuning);
        for rx in reader_rxs {
            let reader_store = Arc::clone(&store);
            let reader_shards = shard_txs.clone();
            let reader_shutdown = stop_rx.clone();
            let reader_metrics = Arc::clone(&metrics);
            let reader_tuning = Arc::clone(&tuning);
            threads.push(
                std::thread::Builder::new()
                    .name("nosfry-reader".into())
                    .spawn(move || {
                        reader::run(
                            &reader_store,
                            &rx,
                            &reader_shards,
                            &reader_tuning,
                            &reader_metrics,
                            &reader_shutdown,
                        );
                    })
                    .map_err(ServerError::Spawn)?,
            );
        }

        // NIP-86 state persisted in the store becomes the first
        // snapshot; the management handler publishes the snapshot the
        // writer returns after each applied op.
        let moderation = Arc::new(store.moderation()?);
        let (mod_tx, mod_rx) = watch::channel(Arc::clone(&moderation));

        // The live-config channel exists before the writer spawn so
        // the vanish path re-reads `service_url` on every batch.
        let limits = config.limits()?;
        let admins = config.admins()?;
        let (live_tx, live_rx) = watch::channel(Arc::new(Live {
            config: Arc::clone(&config),
            nip11: http::nip11(&config, &limits, &moderation).into(),
            landing: http::landing(&config, &moderation).into(),
            limits: Arc::new(limits),
            policy: start_policy(&config.relay.write_policy),
            admins,
        }));

        // Writer.
        let (writer_tx, writer_rx) = mpsc::channel::<WriterMsg>(WRITER_QUEUE);
        let writer_shards = shard_txs.clone();
        let writer_metrics = Arc::clone(&metrics);
        let writer_live = live_rx.clone();
        threads.push(
            std::thread::Builder::new()
                .name("nosfry-writer".into())
                .spawn(move || {
                    writer::run(
                        &store,
                        writer_rx,
                        &writer_shards,
                        &writer_metrics,
                        &writer_live,
                        &mod_tx,
                    );
                })
                .map_err(ServerError::Spawn)?,
        );

        // Expiry timer: owns a writer sender and the stop receiver so
        // the writer channel closes when the thread exits.
        let (expire_stop, expire_stop_rx) = std::sync::mpsc::channel::<()>();
        {
            let expire_writer = writer_tx.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("nosfry-expiry".into())
                    .spawn(move || writer::expire_timer(&expire_writer, &expire_stop_rx))
                    .map_err(ServerError::Spawn)?,
            );
        }
        let conn = connection::Handle {
            writer: writer_tx.clone(),
            writer_budget: Arc::new(tokio::sync::Semaphore::new(WRITER_QUEUE_BYTES)),
            shards: Arc::from(shard_txs.as_slice()),
            live: live_rx.clone(),
            moderation: mod_rx.clone(),
            metrics: Arc::clone(&metrics),
            outbound_total,
            shutdown: stop_rx,
            tracker: tokio_util::task::TaskTracker::new(),
        };
        Ok(Self {
            state: http::AppState {
                live: live_rx,
                conn,
                sync_memory,
                subscription_bytes,
                metrics,
                deflate_pool: deflate_pool(),
                moderation: mod_rx,
                live_tx: live_tx.clone(),
                limiter: Arc::new(limiter::ConnectionLimiter::new(
                    config.relay.max_connections,
                    config.relay.max_connections_per_ip,
                    config.relay.rate_limits,
                )),
            },
            live_tx,
            stop_tx,
            writer_tx,
            expire_stop,
            shard_txs,
            reader_txs,
            threads,
        })
    }

    /// The axum router, ready for `axum::serve`.
    pub fn router(&self) -> axum::Router {
        http::router(self.state.clone())
    }

    /// Tell every connection to close (1001 Going Away).
    pub fn signal_shutdown(&self) {
        self.stop_tx.send_replace(true);
    }

    /// Signal shutdown, drop every worker inbox, and join the threads.
    /// The writer drains and commits its remaining batch on the way out.
    pub fn stop(self) {
        self.signal_shutdown();
        drop(self.state);
        drop(self.writer_tx);
        drop(self.expire_stop);
        drop(self.shard_txs);
        drop(self.reader_txs);
        for thread in self.threads {
            drop(thread.join());
        }
    }
}

/// Read deadline for a complete HTTP request head: a client holding a
/// connection without finishing its headers is dropped (slowloris).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether an `accept` error belongs to one dying connection and can be
/// skipped. Anything else (e.g. `EMFILE`) is logged and the accept loop
/// backs off for a second, as `axum::serve` does.
fn is_connection_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

/// Socket tuning for one accepted connection: `TCP_NODELAY` always,
/// `SO_KEEPALIVE` (OS default timings, like strfry's plain
/// setsockopt) when `[relay] tcp_keepalive` is on. Failures warn and
/// the connection proceeds, as strfry does.
fn tune<S: std::os::fd::AsFd>(tcp: &S, keepalive: bool) {
    let socket = socket2::SockRef::from(tcp);
    if let Err(err) = socket.set_tcp_nodelay(true) {
        tracing::warn!(%err, "failed to set TCP_NODELAY");
    }
    if keepalive && let Err(err) = socket.set_keepalive(true) {
        tracing::warn!(%err, "failed to set SO_KEEPALIVE");
    }
}

/// Accept HTTP/1 connections until `shutdown` resolves, serving each
/// with a header-read deadline `axum::serve` cannot set. In-flight
/// connections get `graceful_shutdown` once `http_stop` fires.
async fn accept_loop(
    listener: &TcpListener,
    router: &axum::Router,
    live: &watch::Receiver<Arc<Live>>,
    shutdown: impl Future<Output = ()>,
    http_stop_rx: &watch::Receiver<()>,
    http_tracker: &tokio_util::task::TaskTracker,
) {
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (tcp, peer) = tokio::select! {
            res = listener.accept() => match res {
                Ok(accepted) => accepted,
                Err(err) => {
                    if !is_connection_error(&err) {
                        tracing::error!(%err, "accept error");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        // Read the flag per accept so a reload reaches new sockets.
        let keepalive = live.borrow().config.relay.tcp_keepalive;
        spawn_connection(tcp, peer, router, keepalive, http_stop_rx, http_tracker);
    }
}

/// Serve one accepted socket with the header-read deadline, tracked by
/// `http_tracker` and gracefully shut down when `http_stop` fires.
fn spawn_connection(
    tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    router: &axum::Router,
    keepalive: bool,
    http_stop_rx: &watch::Receiver<()>,
    http_tracker: &tokio_util::task::TaskTracker,
) {
    tune(&tcp, keepalive);
    let service = TowerToHyperService::new(router.clone().into_service().map_request(
        move |mut req: hyper::Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            req.map(Body::new)
        },
    ));
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(tcp), service)
        .with_upgrades();
    let mut conn = Box::pin(conn);
    let mut conn_stop = http_stop_rx.clone();
    http_tracker.spawn(async move {
        tokio::select! {
            res = conn.as_mut() => {
                if let Err(err) = res {
                    tracing::debug!(%err, "connection error");
                }
                return;
            }
            _ = conn_stop.changed() => {}
        }
        conn.as_mut().graceful_shutdown();
        if let Err(err) = conn.as_mut().await {
            tracing::debug!(%err, "connection error");
        }
    });
}

/// Close a task tracker and await it with the shutdown deadline.
async fn wait_for(tracker: &tokio_util::task::TaskTracker, what: &str) {
    tracker.close();
    if tokio::time::timeout(Duration::from_secs(10), tracker.wait())
        .await
        .is_err()
    {
        tracing::warn!(
            remaining = tracker.len(),
            "shutdown deadline hit with {what}"
        );
    }
}

/// Run the relay until `shutdown` resolves. `reload` yields new
/// configurations (the binary sends on SIGHUP); each one is merged
/// through [`Config::reloadable_from`] and applied without
/// interrupting service.
///
/// # Errors
///
/// [`ServerError::Store`] or [`ServerError::Spawn`] on startup, or
/// [`ServerError::Shutdown`] when the worker-join task fails.
pub async fn serve(
    config: Config,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
    reload: watch::Receiver<Config>,
) -> Result<(), ServerError> {
    let server = Server::new(config)?;
    // The reload task ends when the sender side drops; it shares
    // neither the connection tracker nor the shutdown signal.
    tokio::spawn(reload_loop(
        reload,
        server.live_tx.clone(),
        Arc::clone(&server.state.limiter),
        server.state.moderation.clone(),
        server.live_tx.borrow().clone(),
    ));
    let stop = server.stop_tx.clone();
    let tracker = server.state.conn.tracker.clone();
    // HTTP/1 only, with a header-read deadline `axum::serve` cannot set.
    // `http_stop` asks every in-flight connection to shut down
    // gracefully; `http_tracker` awaits them.
    let (http_stop, http_stop_rx) = watch::channel(());
    let http_tracker = tokio_util::task::TaskTracker::new();
    let router = server.router();
    accept_loop(
        &listener,
        &router,
        &server.state.live,
        async move {
            shutdown.await;
            stop.send_replace(true);
        },
        &http_stop_rx,
        &http_tracker,
    )
    .await;
    // The router holds an AppState (writer/shard senders): drop it so
    // `server.stop()`'s channel teardown can complete.
    drop(router);
    // Gracefully close in-flight HTTP connections (idle keep-alive and
    // mid-read conns end promptly), bounded by the shutdown deadline.
    drop(http_stop_rx);
    http_stop.send_replace(());
    wait_for(&http_tracker, "open HTTP connections").await;
    // Stop accepting new connection tasks, then give live ones a
    // deadline to close (the watch signal already went out).
    wait_for(&tracker, "open connections").await;
    // Joining worker threads blocks; keep it off the runtime.
    tokio::task::spawn_blocking(move || server.stop())
        .await
        .map_err(ServerError::Shutdown)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use super::*;

    /// `tune` sets `SO_KEEPALIVE` only when asked; `TCP_NODELAY`
    /// always (asserted on a real loopback pair).
    #[test]
    fn tune_socket_flags() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        tune(&server, true);
        let socket = socket2::SockRef::from(&server);
        assert!(socket.keepalive().unwrap());
        assert!(socket.tcp_nodelay().unwrap());

        let keepalive_off = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let _off = std::net::TcpStream::connect(keepalive_off.local_addr().unwrap()).unwrap();
        let (plain, _) = keepalive_off.accept().unwrap();
        tune(&plain, false);
        let plain = socket2::SockRef::from(&plain);
        assert!(!plain.keepalive().unwrap());
        assert!(plain.tcp_nodelay().unwrap());
    }
}
