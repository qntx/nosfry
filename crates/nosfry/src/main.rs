//! `nosfry` binary: the relay entry point and administration CLI.
#![allow(
    unused_crate_dependencies,
    reason = "the binary uses only the thin-cli subset of the package's dependencies"
)]
// `run` awaits `nosfry::sync::run`; proving its future `Send` walks
// Arti's `TorClient::connect` type graph (see the library root).
#![cfg_attr(feature = "onion", recursion_limit = "256")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use nosfry::config::Config;
use nosfry_lmdb::Store;

#[derive(Parser)]
#[command(name = "nosfry", version, about = "a Nostr relay")]
struct Cli {
    /// Config file path (env `NOSFRY_CONFIG`).
    #[arg(
        long,
        env = "NOSFRY_CONFIG",
        default_value = "nosfry.toml",
        global = true
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the relay.
    Relay,
    /// Export all events as JSON lines, oldest first, then the
    /// persisted management state and vanish points as
    /// `{"nosfry_state":1,…}` lines.
    Export {
        /// Only events at or after this unix timestamp.
        #[arg(long, default_value_t = 0)]
        since: u64,
        /// Only events at or before this unix timestamp.
        #[arg(long, default_value_t = u64::MAX)]
        until: u64,
        /// Newest first instead.
        #[arg(long)]
        reverse: bool,
        /// Omit the `nosfry_state` lines (for piping into other
        /// relays, e.g. `nosfry export --events-only | strfry import`).
        #[arg(long)]
        events_only: bool,
    },
    /// Import event JSON lines from stdin.
    Import {
        /// Log each rejected line with its reason.
        #[arg(long)]
        show_rejected: bool,
        /// Skip only the BIP-340 signature check: the id hash,
        /// canonical size, and every structural/limit check still
        /// run. For trusted input such as a dump from a trusted
        /// relay; never for network input.
        #[arg(long)]
        no_verify: bool,
    },
    /// Emit stored events matching a REQ filter (JSON), newest first.
    Scan {
        /// Print only the match count.
        #[arg(long)]
        count: bool,
        /// Filter JSON, e.g. '{"kinds":[1]}'.
        filter: String,
    },
    /// Delete stored events matching a REQ filter (JSON) and/or
    /// `--age`. At least one of the two is required.
    Delete {
        /// Count matches without deleting.
        #[arg(long)]
        dry_run: bool,
        /// Only events with `created_at` older than `now - SECONDS`;
        /// combined with FILTER the earlier `until` wins.
        #[arg(long, value_name = "SECONDS")]
        age: Option<u64>,
        /// Filter JSON, e.g. '{"kinds":[1]}'.
        #[arg(required_unless_present = "age")]
        filter: Option<String>,
    },
    /// Write a compacted copy of the database to a new file.
    Compact {
        /// Destination file; must not exist.
        dest: PathBuf,
    },
    /// Sync events with a remote relay over NIP-77 negentropy,
    /// newest-first in bounded time windows.
    Sync {
        /// Peer relay URL: `ws://` or `wss://`.
        url: String,
        /// One NIP-01 filter (a JSON object); `limit` and `search`
        /// are refused since they would make the synced set partial.
        #[arg(long)]
        filter: Option<String>,
        /// Transfer direction.
        #[arg(long, value_enum, default_value = "down")]
        dir: nosfry::sync::Direction,
        /// Only events at or after this unix timestamp.
        #[arg(long)]
        since: Option<u64>,
        /// Only events at or before this unix timestamp.
        #[arg(long)]
        until: Option<u64>,
        /// 64-hex secret key file for NIP-42 AUTH.
        #[arg(long, value_name = "PATH")]
        auth_key_file: Option<PathBuf>,
        /// Allow peers on private/loopback/link-local addresses.
        #[arg(long)]
        allow_private: bool,
        /// Stall timeout in seconds.
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
    /// Embedded onion service commands (the `onion` feature).
    #[cfg(feature = "onion")]
    Onion {
        #[command(subcommand)]
        cmd: OnionCmd,
    },
}

/// `nosfry onion …` subcommands.
#[cfg(feature = "onion")]
#[derive(Subcommand)]
enum OnionCmd {
    /// Print the configured onion listeners' `ws://<addr>.onion`
    /// URLs, one per line. Generates any missing identity key under
    /// `[relay.onion] state_dir`; never starts the relay or touches
    /// the network.
    Address,
}

fn init_tracing() {
    use tracing_subscriber::fmt::format::FmtSpan;
    let env = std::env::var("RUST_LOG_JSON").is_ok_and(|v| v == "1" || v == "true");
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if env {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_span_events(FmtSpan::NONE)
            .with_current_span(true)
            .with_span_list(false)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }
}

/// Wait for SIGINT or SIGTERM.
#[cfg(unix)]
async fn shutdown_signal() {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(term) => term,
        Err(err) => {
            tracing::warn!(%err, "SIGTERM handler unavailable");
            tokio::signal::ctrl_c().await.ok();
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// Wait for SIGINT (ctrl-c).
#[cfg(not(unix))]
async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.ok();
}

/// Re-read the config file on every SIGHUP and forward it to the
/// server's reload channel. A parse/validation failure logs the error
/// and keeps the running configuration.
#[cfg(unix)]
async fn reload_on_sighup(path: PathBuf, tx: tokio::sync::watch::Sender<Config>) {
    let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(hup) => hup,
        Err(err) => {
            tracing::warn!(%err, "SIGHUP handler unavailable");
            return;
        }
    };
    while hup.recv().await.is_some() {
        match Config::load(&path) {
            Ok(config) => drop(tx.send(config)),
            Err(err) => tracing::error!(
                %err,
                path = %path.display(),
                "config reload failed, keeping the running configuration"
            ),
        }
    }
}

/// Open an existing database for a read-only command.
fn open_existing(config: &Config) -> Result<Store, Box<dyn std::error::Error>> {
    if !config.db.path.join("data.mdb").exists() {
        return Err(format!("no database at {}", config.db.path.display()).into());
    }
    Ok(Store::open(&config.db.path, &config.store_options())?)
}

/// A locked, buffered stdout for JSON-lines output.
fn stdout() -> std::io::BufWriter<std::io::StdoutLock<'static>> {
    std::io::BufWriter::new(std::io::stdout().lock())
}

/// The io error at the bottom of `err`'s source chain is a broken
/// pipe (the reader went away, e.g. `nosfry export | head`).
fn is_broken_pipe(mut err: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if let Some(io) = err.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::BrokenPipe
        {
            return true;
        }
        match err.source() {
            Some(source) => err = source,
            None => return false,
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = Config::load(&cli.config)?;
    match cli.command {
        Cmd::Relay => relay(config, cli.config).await,
        Cmd::Export {
            since,
            until,
            reverse,
            events_only,
        } => export(&config, since, until, reverse, events_only),
        Cmd::Import {
            show_rejected,
            no_verify,
        } => import(&config, show_rejected, no_verify),
        Cmd::Scan { count, filter } => scan(&config, &filter, count),
        Cmd::Delete {
            dry_run,
            age,
            filter,
        } => delete(&config, filter.as_deref(), age, dry_run),
        Cmd::Compact { dest } => compact(&config, &dest),
        Cmd::Sync {
            url,
            filter,
            dir,
            since,
            until,
            auth_key_file,
            allow_private,
            timeout,
        } => {
            let mut opts = nosfry::sync::SyncOptions::new(url);
            opts.filter = filter;
            opts.direction = dir;
            opts.since = since;
            opts.until = until;
            opts.auth_key_file = auth_key_file;
            opts.allow_private = allow_private;
            opts.timeout = Duration::from_secs(timeout);
            return sync(&config, opts).await;
        }
        #[cfg(feature = "onion")]
        Cmd::Onion {
            cmd: OnionCmd::Address,
        } => {
            let mut out = stdout();
            for url in nosfry::onion::addresses(&config)? {
                writeln!(out, "{url}")?;
            }
            Ok(())
        }
    }
    .map(|()| ExitCode::SUCCESS)
}

/// Run [`nosfry::sync::run`] against the configured store: `0`
/// complete, `3` partial (transient transfers missed), `1` fatal.
async fn sync(
    config: &Config,
    opts: nosfry::sync::SyncOptions,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    // `open` creates the database when absent, like `import`.
    let store = Store::open(&config.db.path, &config.store_options())?;
    let report = nosfry::sync::run(&store, config, opts).await?;
    tracing::info!(stats = ?report.stats, outcome = ?report.outcome, "sync done");
    Ok(match report.outcome {
        nosfry::sync::Outcome::Complete => ExitCode::SUCCESS,
        nosfry::sync::Outcome::Partial => ExitCode::from(3),
    })
}

/// Raise the soft open-file limit toward `target`, capped by the hard
/// limit (`rlimit` never lowers it and is a no-op off unix). systemd and
/// containerd hand processes a soft limit of 1024, which would cap the
/// relay near 1000 connections. The resulting limit is logged next to
/// the target, so a hard-limit cap is visible without warning on every
/// default start. Unlike strfry, a failure only warns: a relay that can
/// still start should start.
fn raise_nofile_limit(target: u64) {
    if target == 0 {
        return;
    }
    match rlimit::increase_nofile_limit(target) {
        Ok(limit) => tracing::info!(limit, requested = target, "open-file limit"),
        Err(err) => tracing::warn!(%err, "could not raise open-file limit"),
    }
}

async fn relay(config: Config, path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    raise_nofile_limit(config.relay.nofiles);
    let listeners = nosfry::bind(&config).await?;
    for listener in &listeners {
        tracing::info!(address = %listener, "listening");
    }
    let (reload_tx, reload_rx) = tokio::sync::watch::channel(config.clone());
    #[cfg(unix)]
    tokio::spawn(reload_on_sighup(path, reload_tx));
    #[cfg(not(unix))]
    drop(reload_tx);
    nosfry::serve(config, listeners, shutdown_signal(), reload_rx).await?;
    Ok(())
}

fn export(
    config: &Config,
    since: u64,
    until: u64,
    reverse: bool,
    events_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_existing(config)?;
    let mut out = stdout();
    let count = nosfry::admin::export(&store, since, until, reverse, events_only, &mut out)?;
    out.flush()?;
    tracing::info!(count, "export done");
    Ok(())
}

fn import(
    config: &Config,
    show_rejected: bool,
    no_verify: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(&config.db.path, &config.store_options())?;
    let limits = config.limits()?;
    let stdin = std::io::stdin();
    nosfry::admin::import(
        &store,
        &config.events,
        limits.auth.names(),
        config.relay.max_websocket_payload_size,
        stdin.lock(),
        show_rejected,
        no_verify,
    )?;
    Ok(())
}

fn scan(config: &Config, filter: &str, count: bool) -> Result<(), Box<dyn std::error::Error>> {
    let filter = nosfry_core::filter::Filter::parse(filter)?;
    let store = open_existing(config)?;
    let mut out = stdout();
    let matched = nosfry::admin::scan(&store, filter, count, &mut out)?;
    if count {
        writeln!(out, "{matched}")?;
    }
    out.flush()?;
    Ok(())
}

fn delete(
    config: &Config,
    filter: Option<&str>,
    age: Option<u64>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // `required_unless_present` guarantees filter or age; an absent
    // filter parses as the empty filter, but `--age` then always
    // bounds it with `until`, so nothing can delete all.
    let mut filter = match filter {
        Some(json) => nosfry_core::filter::Filter::parse(json)?,
        None => nosfry_core::filter::Filter::parse("{}")?,
    };
    if let Some(age) = age {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        filter = filter.with_until(now.saturating_sub(age));
    }
    let store = open_existing(config)?;
    let mut out = stdout();
    let deleted = nosfry::admin::delete(&store, filter, dry_run)?;
    writeln!(out, "{deleted}")?;
    out.flush()?;
    Ok(())
}

fn compact(config: &Config, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_existing(config)?;
    nosfry::admin::compact(&store, dest)?;
    tracing::info!(dest = %dest.display(), "compact done");
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(err) if is_broken_pipe(err.as_ref()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(%err, "fatal");
            ExitCode::FAILURE
        }
    }
}
