//! nosfry: the native Nostr relay.
//!
//! Thread topology: one tokio multi-thread runtime for connection
//! tasks, one OS writer thread, M monitor shard threads, and N reader
//! threads. LMDB is only touched by the writer and reader threads;
//! everything else communicates over bounded channels.
//!
//! Send order (the deadlock-freedom argument): connection tasks send
//! to the writer and their shard over async channels that
//! backpressure the task itself; the writer `blocking_send`s
//! committed batches to shards; readers `blocking_send` scan
//! completions (`Activate`) to shards; shards only ever `try_send` to
//! readers, shedding work on a full inbox; and every thread pushes
//! replies to the byte-capped per-connection `Outbound` queues, which
//! never block. The shard waits on nothing, so the wait-for graph is
//! acyclic.
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
mod peer;
mod policy;
mod reader;
mod shard;
pub mod sync;
mod writer;

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::thread::JoinHandle;
use std::time::Duration;

use axum::body::Body;
use clap as _;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use nosfry_core::event::PublicKey;
use nosfry_core::moderation::Moderation;
use nosfry_lmdb::Store;
#[cfg(not(unix))]
use rlimit as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{mpsc, watch};
use tower::ServiceExt as _;
use tracing_subscriber as _;

use crate::channels::{ReaderInbox, ReaderMsg, ShardMsg, WriterMsg};
use crate::config::{Config, ListenAddress};
use crate::peer::{ListenerInfo, Origin};

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

/// Scan jobs (REQ, COUNT, and NEG-OPEN `Start`s) admitted to one
/// reader and not yet finished. This — not the inbox size — is the
/// binding shared admission limit: one reader's live scan count can
/// never exceed it, so time-sliced work stays bounded no matter how
/// many subscriptions clients open. Fairness across connections
/// comes first: a connection's own pending-query budget
/// (`2 * max_subs_per_connection`, built in `Connection::new`)
/// sheds it alone with `rate-limited: too many pending queries`
/// before it can spend this shared cap, which sheds with
/// `rate-limited: relay busy` instead of queueing unboundedly.
const READER_JOBS: usize = 4_096;

/// One reader inbox's capacity: `READER_JOBS` scan slots plus
/// `SHARD_QUEUE` of headroom for the control messages (`Cancel`,
/// `CancelConn`, `NegClose`, `NegMsg`) that share it, so the job cap — not
/// the channel — is what sheds new `Start`s.
const READER_QUEUE: usize = READER_JOBS + SHARD_QUEUE;

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
    /// Invalid `[relay] service_url` or `service_url_aliases` entry.
    #[error("config: relay.service_url: {0}")]
    ServiceUrl(#[from] nosfry_core::url::RelayNamesError),
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
    /// Each `[relay.profiles.<name>]`'s session limits — `limits`
    /// with the profile's `rate_limits` swapped in. A connection
    /// takes its listener profile's entry at upgrade time.
    pub(crate) profile_limits:
        Arc<std::collections::HashMap<String, Arc<nosfry_core::limits::Limits>>>,
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

/// The `readers` reader channel pairs; the shared routing table lets
/// every shard forward scan work — and charge the job slot it
/// admits — without ever blocking on a reader.
fn reader_channels(
    readers: usize,
) -> (
    Arc<[ReaderInbox]>,
    Vec<std::sync::mpsc::Receiver<ReaderMsg>>,
) {
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..readers)
        .map(|_| std::sync::mpsc::sync_channel::<ReaderMsg>(READER_QUEUE))
        .unzip();
    let inboxes: Arc<[ReaderInbox]> = txs
        .into_iter()
        .map(|tx| ReaderInbox {
            tx,
            jobs: Arc::new(channels::JobBudget::new(READER_JOBS)),
        })
        .collect();
    (inboxes, rxs)
}

/// Start the write-policy task unless the plugin command is empty.
pub(crate) fn start_policy(cfg: &config::WritePolicy) -> Option<policy::WritePolicy> {
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
                updated.landing = http::landing(&updated.config, &updated.limits, &snapshot).into();
                *current = Arc::new(updated);
            });
        }
    }
}

/// Spawn one monitor-shard thread per inbox, all sharing the
/// process-wide live-subscription charge and the metrics sink.
fn spawn_shards(
    store: &Arc<Store>,
    shard_rxs: Vec<mpsc::Receiver<ShardMsg>>,
    readers: &Arc<[ReaderInbox]>,
    charge: &Arc<AtomicUsize>,
    budget: usize,
    metrics: &Arc<metrics::Metrics>,
    threads: &mut Vec<JoinHandle<()>>,
) -> Result<(), ServerError> {
    for rx in shard_rxs {
        let shard_store = Arc::clone(store);
        let shard_readers = Arc::clone(readers);
        let shard_charge = Arc::clone(charge);
        let shard_metrics = Arc::clone(metrics);
        threads.push(
            std::thread::Builder::new()
                .name("nosfry-monitor".into())
                .spawn(move || {
                    shard::run(
                        &shard_store,
                        rx,
                        shard_readers,
                        shard_charge,
                        budget,
                        shard_metrics,
                    );
                })
                .map_err(ServerError::Spawn)?,
        );
    }
    Ok(())
}

/// Spawn one reader thread per inbox, all sharing the shard routing
/// table, `tuning`, `metrics`, and the shutdown watch.
fn spawn_readers(
    store: &Arc<Store>,
    reader_rxs: Vec<std::sync::mpsc::Receiver<ReaderMsg>>,
    shard_txs: &[mpsc::Sender<ShardMsg>],
    tuning: &Arc<reader::Tuning>,
    metrics: &Arc<metrics::Metrics>,
    stop_rx: &watch::Receiver<bool>,
    threads: &mut Vec<JoinHandle<()>>,
) -> Result<(), ServerError> {
    for rx in reader_rxs {
        let reader_store = Arc::clone(store);
        let reader_shards = shard_txs.to_vec();
        let reader_shutdown = stop_rx.clone();
        let reader_metrics = Arc::clone(metrics);
        let reader_tuning = Arc::clone(tuning);
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

/// The process's soft open-file limit (unix only).
#[cfg(unix)]
fn soft_nofile() -> Result<u64, ServerError> {
    rlimit::getrlimit(rlimit::Resource::NOFILE)
        .map(|(soft, _)| soft)
        .map_err(|err| {
            ServerError::RelayValue(format!("could not read the open-file limit: {err}"))
        })
}

/// No fd limit exists off unix; report one so the ceiling is the
/// whole `usize` range.
#[cfg(not(unix))]
fn soft_nofile() -> Result<u64, ServerError> {
    Ok(u64::MAX)
}

/// Resolve `relay.max_connections` against the open-file ceiling:
/// `None` takes the ceiling, `Some(0)` and over-ceiling values are
/// refused. `soft` is the process's soft open-file limit — read by
/// the caller (`Server::new` after `main` raised it, `reload_once`
/// on every reload, since `relay.nofiles` is restart-only but the
/// read is cheap).
fn effective_max_connections(relay: &config::Relay, soft: u64) -> Result<usize, ServerError> {
    if relay.max_connections == Some(0) {
        return Err(ServerError::RelayValue(
            "relay.max_connections must be at least 1; omit it for the open-file-limit default"
                .to_owned(),
        ));
    }
    let ceiling = limiter::connection_ceiling(soft);
    match relay.max_connections {
        None if ceiling == 0 => Err(ServerError::RelayValue(format!(
            "the open-file limit {soft} leaves no room for connections"
        ))),
        None => Ok(ceiling),
        Some(max) if max > ceiling => Err(ServerError::RelayValue(format!(
            "relay.max_connections = {max} exceeds what the open-file limit allows: \
             soft limit {soft} leaves room for {ceiling} connections \
             ({soft} - 64 - {soft}/8); raise relay.nofiles or the hard limit, \
             or lower max_connections"
        ))),
        Some(max) => Ok(max),
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
    let max_connections = soft_nofile()
        .and_then(|soft| effective_max_connections(&merged.relay, soft))
        .inspect_err(log_invalid_reload)
        .ok()?;
    Some(Arc::new(apply_reload(
        merged,
        limits,
        admins,
        live,
        limiter,
        max_connections,
    )))
}

fn log_invalid_reload(err: &ServerError) {
    tracing::error!(%err, "invalid reloaded config; keeping the running one");
}

/// One notice when restricted kinds are configured but AUTH is off:
/// such writes are refused because there is no reader to serve.
fn log_restricted_writes(config: &Config) {
    if config.relay.service_url.is_empty() && !config.relay.auth.restricted_read_kinds.is_empty() {
        tracing::info!(
            "AUTH disabled: writes of restricted kinds {:?} are refused",
            config.relay.auth.restricted_read_kinds
        );
    }
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
    max_connections: usize,
) -> Live {
    limiter.update_caps(max_connections, &merged.relay.profiles());
    let profile_limits = merged.profile_limits(&limits);
    let policy = if merged.relay.write_policy == live.config.relay.write_policy {
        live.policy.clone()
    } else {
        start_policy(&merged.relay.write_policy)
    };
    log_restricted_writes(&merged);
    tracing::info!("configuration reloaded");
    Live {
        nip11: live.nip11.clone(),
        landing: live.landing.clone(),
        config: Arc::new(merged),
        limits: Arc::new(limits),
        profile_limits: Arc::new(profile_limits),
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
    reader_txs: Arc<[ReaderInbox]>,
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
        let soft_nofile = soft_nofile()?;
        let max_connections = effective_max_connections(&config.relay, soft_nofile)?;
        tracing::info!(max_connections, soft_nofile, "connection cap");
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
            &metrics,
            &mut threads,
        )?;

        // Readers.
        spawn_readers(
            &store,
            reader_rxs,
            &shard_txs,
            &Arc::new(tuning),
            &metrics,
            &stop_rx,
            &mut threads,
        )?;

        // NIP-86 state persisted in the store becomes the first
        // snapshot; the management handler publishes the snapshot the
        // writer returns after each applied op.
        let moderation = Arc::new(store.moderation()?);
        let (mod_tx, mod_rx) = watch::channel(Arc::clone(&moderation));

        // The live-config channel exists before the writer spawn so
        // the vanish path re-reads `service_url` on every batch.
        let limits = config.limits()?;
        let profile_limits = config.profile_limits(&limits);
        let admins = config.admins()?;
        let (live_tx, live_rx) = watch::channel(Arc::new(Live {
            config: Arc::clone(&config),
            nip11: http::nip11(&config, &limits, &moderation).into(),
            landing: http::landing(&config, &limits, &moderation).into(),
            limits: Arc::new(limits),
            profile_limits: Arc::new(profile_limits),
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
                reader_jobs: reader_txs
                    .iter()
                    .map(|inbox| Arc::clone(&inbox.jobs))
                    .collect(),
                metrics,
                deflate_pool: deflate_pool(),
                moderation: mod_rx,
                live_tx: live_tx.clone(),
                limiter: Arc::new(limiter::ConnectionLimiter::new(
                    max_connections,
                    &config.relay.profiles(),
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

/// One bound `[[relay.listen]]` entry: the socket plus the fixed
/// listener info every connection it accepts carries.
#[derive(Debug)]
pub struct Listener(ListenerKind);

#[derive(Debug)]
enum ListenerKind {
    /// A TCP listener; its connections are `Peer::Ip` peers.
    Tcp {
        /// The bound socket.
        listener: TcpListener,
        /// This listener's fixed metadata.
        info: Arc<ListenerInfo>,
    },
    /// A unix-domain-socket listener (unix only); without a
    /// `real_ip_header` its connections are `Peer::Listener` peers
    /// sharing the socket's identity. The socket file is removed
    /// when the listener is dropped (server shutdown).
    #[cfg(unix)]
    Unix {
        /// The bound socket.
        listener: UnixListener,
        /// This listener's fixed metadata.
        info: Arc<ListenerInfo>,
        /// Unlinks the socket file on drop.
        guard: UnixSocketGuard,
    },
}

/// Unlinks a bound unix socket's path on drop (server shutdown).
/// Kept off `Listener` itself so the enum stays destructurable.
#[cfg(unix)]
#[derive(Debug)]
pub struct UnixSocketGuard(std::path::PathBuf);

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.0)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%err, path = %self.0.display(), "could not remove unix socket");
        }
    }
}

impl Listener {
    /// The bound TCP address — `Some` only for TCP listeners. Tests
    /// bind `127.0.0.1:0` and read the real port here.
    #[must_use]
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        match &self.0 {
            ListenerKind::Tcp { listener, .. } => listener.local_addr().ok(),
            #[cfg(unix)]
            ListenerKind::Unix { .. } => None,
        }
    }
}

/// The address `listening` logs and tests report: the bound TCP
/// address or the `unix:` path.
impl std::fmt::Display for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ListenerKind::Tcp { listener, info } => match listener.local_addr() {
                Ok(addr) => addr.fmt(f),
                Err(_) => info.id.fmt(f),
            },
            #[cfg(unix)]
            ListenerKind::Unix { info, .. } => info.id.fmt(f),
        }
    }
}

/// Bind every `[[relay.listen]]` address.
///
/// A unix path that already exists is probed: a refused connect means
/// a stale socket file, which is removed and re-bound; a successful
/// connect means a live server owns it and the bind fails `address in
/// use`.
///
/// # Errors
///
/// [`ServerError::Io`] on bind failure or when a unix socket path is
/// already in use.
pub async fn bind(config: &Config) -> Result<Vec<Listener>, ServerError> {
    let mut listeners = Vec::with_capacity(config.relay.listen.len());
    for listen in &config.relay.listen {
        let info = Arc::new(ListenerInfo {
            id: Arc::from(listen.address.to_string().as_str()),
            profile: Arc::from(listen.profile.as_str()),
            real_ip_header: listen.real_ip_header.clone(),
            last_warn_secs: std::sync::atomic::AtomicU64::new(0),
        });
        match &listen.address {
            ListenAddress::Tcp(sock) => listeners.push(Listener(ListenerKind::Tcp {
                listener: TcpListener::bind(sock).await?,
                info,
            })),
            #[cfg(unix)]
            ListenAddress::Unix(path) => {
                let (listener, guard) = bind_unix(path).await?;
                listeners.push(Listener(ListenerKind::Unix {
                    listener,
                    info,
                    guard,
                }));
            }
            #[cfg(not(unix))]
            ListenAddress::Unix(path) => {
                return Err(ServerError::RelayValue(format!(
                    "unix listeners are unsupported on this platform: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(listeners)
}

/// Bind one unix socket path, returning the listener and the guard
/// that unlinks it on shutdown. A path that already exists must be a
/// socket — anything else is an error, never removed (Linux answers a
/// connect to a regular file `ECONNREFUSED`, so the probe alone would
/// take it for stale). An existing socket is probed by connecting: a
/// refused connect means a stale socket file, which is removed and
/// re-bound; a successful connect means a live server owns it and the
/// bind fails `address in use`; anything else is an error.
#[cfg(unix)]
async fn bind_unix(path: &std::path::Path) -> Result<(UnixListener, UnixSocketGuard), ServerError> {
    use std::os::unix::fs::FileTypeExt as _;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a unix socket", path.display()),
            )));
        }
        match tokio::net::UnixStream::connect(path).await {
            Ok(_) => {
                return Err(ServerError::Io(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("unix socket {} already in use", path.display()),
                )));
            }
            // A stale socket file from a dead server: remove and
            // re-bind.
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(path)?;
            }
            Err(err) => return Err(ServerError::Io(err)),
        }
    }
    let listener = UnixListener::bind(path)?;
    Ok((listener, UnixSocketGuard(path.to_path_buf())))
}

/// Accept HTTP/1 connections on one TCP listener until `http_stop`
/// fires, serving each through [`serve_stream`]. `tcp_keepalive` is
/// read per accept so a reload reaches new sockets.
async fn accept_tcp(
    listener: TcpListener,
    info: Arc<ListenerInfo>,
    router: axum::Router,
    live: watch::Receiver<Arc<Live>>,
    mut http_stop_rx: watch::Receiver<()>,
    http_tracker: tokio_util::task::TaskTracker,
) {
    loop {
        let accepted = tokio::select! {
            res = listener.accept() => res,
            _ = http_stop_rx.changed() => break,
        };
        let (tcp, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(err) => {
                if !is_connection_error(&err) {
                    tracing::error!(%err, "accept error");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        let keepalive = live.borrow().config.relay.tcp_keepalive;
        tune(&tcp, keepalive);
        let origin = Origin {
            listener: Arc::clone(&info),
            transport: Some(peer),
        };
        serve_stream(tcp, origin, &router, &http_stop_rx, &http_tracker);
    }
}

/// Accept HTTP/1 connections on one unix listener until `http_stop`
/// fires. A unix connection has no client address: its `Origin`
/// transport is `None` and its peer resolves to the listener
/// identity unless the listener's `real_ip_header` supplies one.
#[cfg(unix)]
async fn accept_unix(
    listener: UnixListener,
    info: Arc<ListenerInfo>,
    _guard: UnixSocketGuard,
    router: axum::Router,
    mut http_stop_rx: watch::Receiver<()>,
    http_tracker: tokio_util::task::TaskTracker,
) {
    loop {
        let accepted = tokio::select! {
            res = listener.accept() => res,
            _ = http_stop_rx.changed() => break,
        };
        let (io, _addr) = match accepted {
            Ok(accepted) => accepted,
            Err(err) => {
                if !is_connection_error(&err) {
                    tracing::error!(%err, "accept error");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        let origin = Origin {
            listener: Arc::clone(&info),
            transport: None,
        };
        serve_stream(io, origin, &router, &http_stop_rx, &http_tracker);
    }
}

/// Serve one accepted byte stream — any transport's `AsyncRead +
/// AsyncWrite` — with the header-read deadline `axum::serve` cannot
/// set, the `Origin` extension every handler resolves its peer from,
/// WebSocket upgrades, and a graceful shutdown once `http_stop`
/// fires. Transport-specific tuning happens in the accept loop
/// before this runs.
fn serve_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    io: S,
    origin: Origin,
    router: &axum::Router,
    http_stop_rx: &watch::Receiver<()>,
    http_tracker: &tokio_util::task::TaskTracker,
) {
    let service = TowerToHyperService::new(router.clone().into_service().map_request(
        move |mut req: hyper::Request<Incoming>| {
            req.extensions_mut().insert(origin.clone());
            req.map(Body::new)
        },
    ));
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(io), service)
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
    listeners: Vec<Listener>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    reload: watch::Receiver<Config>,
) -> Result<(), ServerError> {
    log_restricted_writes(&config);
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
    // `http_stop` ends every accept loop and asks every in-flight
    // connection to shut down gracefully; `http_tracker` awaits them.
    let (http_stop, http_stop_rx) = watch::channel(());
    let http_tracker = tokio_util::task::TaskTracker::new();
    let router = server.router();
    // One accept loop per listener, sharing the trackers and shutdown.
    for listener in listeners {
        match listener.0 {
            ListenerKind::Tcp { listener, info } => {
                http_tracker.spawn(accept_tcp(
                    listener,
                    info,
                    router.clone(),
                    server.state.live.clone(),
                    http_stop_rx.clone(),
                    http_tracker.clone(),
                ));
            }
            #[cfg(unix)]
            ListenerKind::Unix {
                listener,
                info,
                guard,
            } => {
                http_tracker.spawn(accept_unix(
                    listener,
                    info,
                    guard,
                    router.clone(),
                    http_stop_rx.clone(),
                    http_tracker.clone(),
                ));
            }
        }
    }
    shutdown.await;
    stop.send_replace(true);
    // The router holds an AppState (writer/shard senders): drop it so
    // `server.stop()`'s channel teardown can complete.
    drop(router);
    // Break the accept loops and gracefully close in-flight HTTP
    // connections (idle keep-alive and mid-read conns end promptly),
    // bounded by the shutdown deadline.
    drop(http_stop_rx);
    http_stop.send_replace(());
    wait_for(&http_tracker, "open HTTP connections").await;
    // Give live connections a deadline to close (the watch signal
    // already went out).
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

    /// `max_connections` resolves against the fd ceiling: `None`
    /// takes the ceiling, `Some(0)` and over-ceiling values are
    /// refused, and a zero ceiling leaves no room at all.
    #[test]
    fn effective_max_connections_resolves_against_the_ceiling() {
        let mut relay = config::Relay::default();
        let soft = 1_024;
        let ceiling = limiter::connection_ceiling(soft); // 832
        assert_eq!(effective_max_connections(&relay, soft).unwrap(), ceiling);

        relay.max_connections = Some(0);
        let zero_err = effective_max_connections(&relay, soft).unwrap_err();
        assert_eq!(
            zero_err.to_string(),
            "config: relay.max_connections must be at least 1; \
             omit it for the open-file-limit default"
        );

        relay.max_connections = Some(ceiling);
        assert_eq!(effective_max_connections(&relay, soft).unwrap(), ceiling);

        relay.max_connections = Some(ceiling + 1);
        let over_err = effective_max_connections(&relay, soft).unwrap_err();
        assert!(
            over_err
                .to_string()
                .contains("relay.max_connections = 833 exceeds"),
            "{over_err}"
        );

        relay.max_connections = None;
        let room_err = effective_max_connections(&relay, 64).unwrap_err();
        assert!(
            room_err
                .to_string()
                .contains("leaves no room for connections"),
            "{room_err}"
        );
    }

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
