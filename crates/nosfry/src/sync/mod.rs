//! `nosfry sync`: a windowed NIP-77 client that reconciles the local
//! store with a remote relay (ADR `0010-sync-client`).
//!
//! [`run`] resolves and vets the URL (`dial`), fetches the peer's
//! NIP-11 limits (`nip11`) over a first connection, opens the
//! WebSocket (`conn`) over a second, then drives the windowed
//! reconciliation engine (`engine`). Downloads pass the full wire
//! validation plus moderation and the write-policy plugin
//! (`ingest`); NIP-42 authentication signs a key file
//! (`auth`).

mod auth;
mod conn;
mod dial;
mod engine;
mod ingest;
mod nip11;

use std::path::PathBuf;
use std::time::Duration;

use nosfry_lmdb::Store;
use serde_json::{Map, Value};
use yawc::WebSocket;

use crate::config::Config;

/// Inbound WebSocket payload cap (8 MiB): relay messages are small;
/// this bounds a peer's worst frame.
const MAX_PAYLOAD_READ: usize = 8 << 20;

/// Which way events move.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Direction {
    /// Download what the peer has and we lack.
    #[default]
    Down,
    /// Upload what we have and the peer lacks.
    Up,
    /// Both directions.
    Both,
}

impl Direction {
    /// Whether downloads run.
    const fn down(self) -> bool {
        matches!(self, Self::Down | Self::Both)
    }

    /// Whether uploads run.
    const fn up(self) -> bool {
        matches!(self, Self::Up | Self::Both)
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Down => "down",
            Self::Up => "up",
            Self::Both => "both",
        })
    }
}

/// Inputs for one [`run`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SyncOptions {
    /// Peer relay URL (`ws://`/`wss://`, as given — also the AUTH
    /// event's `relay` tag).
    pub url: String,
    /// A single NIP-01 filter JSON; `limit`/`search` keys are refused.
    pub filter: Option<String>,
    /// Which way events move.
    pub direction: Direction,
    /// Only events at or after this unix timestamp.
    pub since: Option<u64>,
    /// Only events at or before this unix timestamp.
    pub until: Option<u64>,
    /// File holding a 64-hex secret key, for NIP-42 AUTH.
    pub auth_key_file: Option<PathBuf>,
    /// Admit private/loopback/link-local peer addresses.
    pub allow_private: bool,
    /// Stall timeout: any wait past it aborts the run.
    pub timeout: Duration,
    /// Local records collected per window before splitting (test
    /// knob; the CLI uses the default).
    pub window_records: usize,
    /// Pending have/need ids kept per window before the window is
    /// split mid-flight (test knob; the CLI uses the default).
    pub pending_ids: usize,
}

impl SyncOptions {
    /// Options for `url` with the CLI defaults.
    #[must_use]
    pub const fn new(url: String) -> Self {
        Self {
            url,
            filter: None,
            direction: Direction::Down,
            since: None,
            until: None,
            auth_key_file: None,
            allow_private: false,
            timeout: Duration::from_secs(60),
            window_records: 100_000,
            pending_ids: 100_000,
        }
    }
}

/// Tallies of a finished run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncStats {
    /// Windows fully reconciled (splits and requeues excluded).
    pub windows: u64,
    /// Ids the peer reported we lack (transfer candidates in `down`).
    pub need: u64,
    /// Ids we hold that the peer lacks (transfer candidates in `up`).
    pub have: u64,
    /// Events stored from the peer.
    pub downloaded: u64,
    /// Already-stored events the peer sent or `OK`ed as duplicates.
    pub duplicates: u64,
    /// Events the peer accepted with `OK true`.
    pub uploaded: u64,
    /// Downloaded events refused by local rules (validation, kinds,
    /// moderation, write policy).
    pub refused_local: u64,
    /// Events refused for peer-side reasons (unrequested, malformed,
    /// bad signature, outside the window) or `OK false`ed by the peer.
    pub refused_remote: u64,
    /// Local events skipped for upload (protected, hidden from an
    /// unauthenticated reader, over the peer's message limit, gone
    /// from the store).
    pub skipped: u64,
    /// Downloads whose store outcome was superseded, deleted or
    /// vanished.
    pub superseded_or_deleted: u64,
    /// Transfers that failed transiently (retries exhausted, ids
    /// missing at `EOSE`, peer `error:`).
    pub failed: u64,
    /// Windows abandoned after retries.
    pub failed_windows: u64,
}

/// Whether every difference moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every difference transferred or refused by a deterministic rule.
    Complete,
    /// The run finished with failed transfers; re-running continues.
    Partial,
}

/// [`run`]'s result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    /// Transfer tallies.
    pub stats: SyncStats,
    /// `Partial` iff `failed > 0 || failed_windows > 0`.
    pub outcome: Outcome,
}

/// Fatal sync failures (CLI exit code 1).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// Bad arguments or a refused filter/URL/range.
    #[error("{0}")]
    Usage(String),
    /// Configuration could not produce session limits.
    #[error("config: {0}")]
    Config(#[from] Box<crate::ServerError>),
    /// LMDB failure.
    #[error("store: {0}")]
    Store(#[from] nosfry_lmdb::StoreError),
    /// Filesystem failure (key file).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The URL failed vetting or resolution.
    #[error("{0}")]
    Url(String),
    /// TCP/TLS/WebSocket connect failed.
    #[error("connect failed: {0}")]
    Connect(String),
    /// The connection dropped mid-run or a frame broke the protocol.
    #[error("connection lost: {0}")]
    Lost(String),
    /// The peer closed the WebSocket.
    #[error("connection closed by peer")]
    Closed,
    /// No frame arrived within the stall timeout.
    #[error("peer stalled: no reply within {0} s")]
    Stalled(u64),
    /// The peer does not speak NIP-77.
    #[error("peer does not support NIP-77: {0}")]
    NoNip77(String),
    /// The peer refuses negentropy sync outright.
    #[error("peer refuses NIP-77 sync: {0}")]
    Refused(String),
    /// A negentropy message failed (malformed peer input or a local
    /// storage build).
    #[error("invalid negentropy message: {0}")]
    Negentropy(String),
    /// The peer wants NIP-42 AUTH and no key was given.
    #[error("peer requires NIP-42 AUTH; pass --auth-key-file")]
    AuthRequired,
    /// The peer rejected the AUTH event.
    #[error("peer refused authentication: {0}")]
    AuthRefused(String),
    /// `--auth-key-file` failed to load.
    #[error("invalid --auth-key-file: {0}")]
    KeyFile(String),
    /// The peer's advertised message length cannot fit a negentropy
    /// frame.
    #[error("{0}")]
    FrameTooSmall(#[from] nosfry_core::client::FrameTooSmall),
}

/// The parsed `--filter` plus the reconciled time range.
struct Plan {
    /// Filter object without `since`/`until`/`limit` — per-window
    /// bounds are inserted per window.
    base: Map<String, Value>,
    /// Reconciled range lower bound.
    lo: u64,
    /// Reconciled range upper bound.
    hi: u64,
}

/// Validate `opts`: parse the filter JSON object, refuse
/// `limit`/`search`, compile it, and compute the reconciled range.
fn validate(opts: &SyncOptions, limits: &nosfry_core::limits::Limits) -> Result<Plan, SyncError> {
    let now = now_secs();
    let hi_bound = now.saturating_add(limits.event.reject_events_newer_than_seconds);
    let mut base = match &opts.filter {
        None => Map::new(),
        Some(json) => {
            let value: Value = serde_json::from_str(json)
                .map_err(|err| SyncError::Usage(format!("invalid --filter JSON: {err}")))?;
            value
                .as_object()
                .cloned()
                .ok_or_else(|| SyncError::Usage("--filter must be a JSON object".to_owned()))?
        }
    };
    for banned in ["limit", "search"] {
        if base.remove(banned).is_some() {
            return Err(SyncError::Usage(format!(
                "--filter must not carry `{banned}`: it would make the synced set partial"
            )));
        }
    }
    let base_json = Value::Object(base.clone()).to_string();
    let filter = nosfry_core::filter::Filter::parse(&base_json)
        .map_err(|err| SyncError::Usage(format!("invalid --filter: {}", err.reason())))?;
    let lo = [filter.since(), opts.since]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0);
    let hi = [filter.until(), opts.until, Some(hi_bound)]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(hi_bound);
    if lo > hi {
        return Err(SyncError::Usage(format!(
            "empty range: since {lo} is after until {hi}"
        )));
    }
    Ok(Plan { base, lo, hi })
}

/// Fetch NIP-11 limits on their own connection. Every failure warns
/// and falls back to the protocol defaults.
async fn peer_limits(target: &dial::Target, timeout: Duration) -> nosfry_core::client::PeerLimits {
    let peer = try_fetch(target, timeout).await.unwrap_or_default();
    if peer
        .supported_nips
        .as_ref()
        .is_some_and(|nips| !nips.contains(&77))
    {
        tracing::warn!("peer does not advertise NIP-77; trying anyway");
    }
    peer
}

/// One best-effort NIP-11 fetch; a failure logs why and yields `None`.
async fn try_fetch(
    target: &dial::Target,
    timeout: Duration,
) -> Option<nosfry_core::client::PeerLimits> {
    let io = match dial::dial(target, timeout).await {
        Ok(io) => io,
        Err(err) => {
            tracing::warn!(%err, "NIP-11 dial failed; assuming default peer limits");
            return None;
        }
    };
    let limits = nip11::fetch(io, target, timeout).await;
    if limits.is_none() {
        tracing::warn!("NIP-11 fetch failed; assuming default peer limits");
    }
    limits
}

/// Unix seconds now.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Reconcile `store` with the peer named by `opts.url`.
///
/// Opens the store's LMDB environment directly like `import`: one
/// short write transaction per download batch.
///
/// # Errors
///
/// [`SyncError`] is fatal (CLI exit 1): bad arguments, an unsafe URL,
/// a failed connection or handshake, a stalled peer, a peer without
/// or refusing NIP-77, or a required/refused authentication.
pub async fn run(
    store: &Store,
    config: &Config,
    opts: SyncOptions,
) -> Result<SyncReport, SyncError> {
    let limits = config
        .limits()
        .map_err(|err| SyncError::Config(Box::new(err)))?;
    let plan = validate(&opts, &limits)?;
    // Fail fast on a bad key file, before any network work.
    let key = opts
        .auth_key_file
        .as_deref()
        .map(auth::load_key)
        .transpose()?;
    if let Some(key) = &key {
        tracing::info!(
            pubkey = %nosfry_core::event::PublicKey(key.x_only_public_key().0.to_byte_array()),
            "auth key loaded"
        );
    }
    let target = dial::resolve(&opts.url, opts.allow_private).await?;
    let peer = peer_limits(&target, opts.timeout).await;
    let frame_limit = nosfry_core::client::neg_frame_limit(peer.max_message_length)?;
    let io = dial::dial(&target, opts.timeout)
        .await
        .map_err(|err| SyncError::Connect(err.to_string()))?;
    let options = yawc::Options::default()
        .with_max_payload_read(MAX_PAYLOAD_READ)
        .with_balanced_compression();
    let ws = tokio::time::timeout(
        opts.timeout,
        WebSocket::handshake(target.url.clone(), io, options),
    )
    .await
    .map_err(|_| SyncError::Stalled(opts.timeout.as_secs()))?
    .map_err(|err| SyncError::Connect(err.to_string()))?;
    let mut conn = conn::RelayConn::new(ws, opts.url.clone(), key);
    let policy = crate::start_policy(&config.relay.write_policy);
    let stats = engine::Engine::run(
        &mut conn,
        store,
        &opts,
        &plan,
        engine::Peer {
            limits: &peer,
            frame_limit,
        },
        &limits,
        policy,
    )
    .await?;
    Ok(SyncReport {
        outcome: if stats.failed > 0 || stats.failed_windows > 0 {
            Outcome::Partial
        } else {
            Outcome::Complete
        },
        stats,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;

    fn limits() -> nosfry_core::limits::Limits {
        nosfry_core::limits::Limits::default()
    }

    fn opts() -> SyncOptions {
        SyncOptions::new("ws://relay.example.com".to_owned())
    }

    #[test]
    fn validate_rejects_limit_and_search() {
        for filter in ["{\"limit\":5}", "{\"search\":\"x\"}"] {
            let mut o = opts();
            o.filter = Some(filter.to_owned());
            assert!(matches!(validate(&o, &limits()), Err(SyncError::Usage(_))));
        }
    }

    #[test]
    fn validate_range_intersection() {
        let mut o = opts();
        o.filter = Some("{\"since\":100,\"until\":200}".to_owned());
        o.since = Some(150);
        o.until = Some(180);
        let plan = validate(&o, &limits()).unwrap();
        assert_eq!((plan.lo, plan.hi), (150, 180));
        // Empty range is refused.
        o.until = Some(140);
        assert!(matches!(validate(&o, &limits()), Err(SyncError::Usage(_))));
        // Defaults: since 0, until now + slack.
        let defaults = validate(&opts(), &limits()).unwrap();
        assert_eq!(defaults.lo, 0);
        assert!(defaults.hi >= now_secs());
    }

    #[test]
    fn validate_rejects_bad_filter() {
        let mut o = opts();
        o.filter = Some("not json".to_owned());
        assert!(matches!(validate(&o, &limits()), Err(SyncError::Usage(_))));
        o.filter = Some("[]".to_owned());
        assert!(matches!(validate(&o, &limits()), Err(SyncError::Usage(_))));
        o.filter = Some("{\"kinds\":\"x\"}".to_owned());
        assert!(matches!(validate(&o, &limits()), Err(SyncError::Usage(_))));
    }
}
