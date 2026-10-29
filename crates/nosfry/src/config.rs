//! TOML configuration, strfry-style sections and defaults.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use nosfry_core::auth::AuthConfig;
use nosfry_core::event::{EventLimits, PublicKey};
use nosfry_core::info::Info;
use nosfry_core::limits::{FilterValidationConfig, Limits, RateLimits, ReqLimits};
use nosfry_core::management::ManagementConfig;
use nosfry_lmdb::StoreOptions;
use serde::Deserialize;

use crate::ServerError;

/// The whole `nosfry.toml` document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Database environment section.
    pub db: Db,
    /// Event acceptance limits (`nosfry_core::event::EventLimits` verbatim).
    pub events: EventLimits,
    /// Relay behaviour section.
    pub relay: Relay,
}

/// `[db]` — LMDB environment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Db {
    /// Environment directory.
    pub path: PathBuf,
    /// LMDB map size in bytes.
    pub map_size: usize,
    /// Maximum concurrent read transactions.
    pub max_readers: u32,
    /// Disable OS read-ahead on the LMDB map (`MDB_NORDAHEAD`). Leave
    /// off: it cuts query throughput by about 10x. If the database
    /// outgrows RAM on a filesystem with large read-ahead (btrfs uses
    /// at least 4 MiB), lower the filesystem's `read_ahead_kb` (e.g.
    /// to 128) instead.
    pub no_read_ahead: bool,
}

/// `[relay]` — network and runtime behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Relay {
    /// Bind address.
    pub bind: IpAddr,
    /// Bind port.
    pub port: u16,
    /// The relay's canonical `ws://`/`wss://` URL clients sign into an
    /// AUTH event's `relay` tag and name in a NIP-62 request to
    /// vanish. Empty disables AUTH: restricted kinds are stored but
    /// never served, and protected events are rejected.
    pub service_url: String,
    /// Soft open-file limit to raise to at startup, capped by the hard
    /// limit (0 = leave unchanged).
    pub nofiles: u64,
    /// Header carrying the real client IP; its last comma-separated
    /// value is trusted, so set it only behind a proxy that sets or
    /// appends the header (empty = socket address).
    pub real_ip_header: String,
    /// Maximum inbound WebSocket payload in bytes.
    pub max_websocket_payload_size: usize,
    /// WebSocket ping interval in seconds.
    pub auto_ping_seconds: u64,
    /// Set `SO_KEEPALIVE` on accepted sockets (strfry
    /// `enableTcpKeepalive`): OS default timings, reloadable for new
    /// connections.
    pub tcp_keepalive: bool,
    /// Pending outbound bytes above which the connection is closed.
    pub max_pending_outbound_bytes: usize,
    /// Process-wide pending outbound byte budget: when the sum of
    /// every connection's pending exceeds it, scans pause on
    /// connections already more than one chunk behind (restart-only;
    /// 0 = unlimited).
    pub max_pending_outbound_bytes_total: usize,
    /// Process-wide budget for sealed negentropy sync storages,
    /// accounted at 40 bytes per scanned record (restart-only;
    /// 0 = unlimited).
    pub max_sync_memory_bytes: usize,
    /// Process-wide budget for live subscriptions: every REQ is
    /// charged the `Filter::approx_bytes` sum of its filters
    /// (compiled filters plus monitor index entries) and refused
    /// `blocked: subscription capacity exhausted` over budget
    /// (restart-only; 0 = unlimited).
    pub max_subscription_bytes_total: usize,
    /// Maximum simultaneous WebSocket connections (0 = unlimited).
    pub max_connections: usize,
    /// Maximum simultaneous WebSocket connections per client IP
    /// (0 = unlimited). IPv4 counts per address; IPv6 per /64.
    pub max_connections_per_ip: usize,
    /// Serve `GET /metrics` (Prometheus text exposition format) on the
    /// relay port. Unauthenticated — keep it behind a reverse proxy or
    /// firewall.
    pub metrics: bool,
    /// Per-slice scan budget in microseconds.
    pub query_timeslice_budget_microseconds: u64,
    /// REQ limits (`nosfry_core::limits::ReqLimits` verbatim).
    pub limits: ReqLimits,
    /// REQ/COUNT filter-validation rules
    /// (`nosfry_core::limits::FilterValidationConfig` verbatim).
    pub filter_validation: FilterValidationConfig,
    /// Per-connection EVENT/REQ rate limits
    /// (`nosfry_core::limits::RateLimits` verbatim).
    pub rate_limits: RateLimits,
    /// Thread pool sizes.
    pub threads: Threads,
    /// WebSocket compression.
    pub compression: Compression,
    /// Write-policy plugin.
    pub write_policy: WritePolicy,
    /// NIP-42 authentication and restricted read kinds.
    pub auth: AuthConfig,
    /// NIP-86 management API.
    pub management: ManagementConfig,
    /// NIP-11 relay information.
    pub info: Info,
}

/// `[relay.threads]` — worker thread counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Threads {
    /// Scan reader threads.
    pub readers: usize,
    /// Monitor shard threads.
    pub monitors: usize,
}

/// `[relay.compression]` — permessage-deflate settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Compression {
    /// Negotiate permessage-deflate. On by default: yawc bounds the
    /// inflated size of an inbound message by
    /// `max_websocket_payload_size`.
    pub enabled: bool,
    /// Keep the LZ77 sliding window between messages (context
    /// takeover). Off by default: deflate state then comes from a
    /// server-wide pool and an idle connection costs only its socket
    /// buffers, at 18–52% more bytes and ~25% more CPU per compressed
    /// message than the sliding window. `true` is strfry's default and
    /// keeps ~370 KiB of per-connection state once a message was
    /// compressed.
    pub sliding_window: bool,
}

/// `[relay.write_policy]` — strfry-compatible write-policy plugin.
///
/// Plugins written for strfry run unchanged: each verified event is
/// sent to `/bin/sh -c <plugin>` as one JSON line and the plugin's
/// `accept`/`reject`/`shadowReject` answer decides its fate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WritePolicy {
    /// The plugin command (empty = off). A command without spaces is
    /// a path and reloads when the file's mtime changes.
    pub plugin: String,
    /// Seconds the plugin has to answer each request.
    pub timeout_seconds: u64,
}

impl Default for WritePolicy {
    fn default() -> Self {
        Self {
            plugin: String::new(),
            timeout_seconds: 10,
        }
    }
}

impl Default for Db {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./nosfry-db"),
            map_size: StoreOptions::default().map_size,
            max_readers: StoreOptions::default().max_readers,
            no_read_ahead: false,
        }
    }
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            bind: IpAddr::from([127, 0, 0, 1]),
            port: 7_777,
            service_url: String::new(),
            nofiles: 1_000_000,
            real_ip_header: String::new(),
            max_websocket_payload_size: 131_072,
            auto_ping_seconds: 55,
            tcp_keepalive: false,
            max_pending_outbound_bytes: 33_554_432,
            max_pending_outbound_bytes_total: 1_073_741_824,
            max_sync_memory_bytes: 1_073_741_824,
            max_subscription_bytes_total: 1_073_741_824,
            max_connections: 0,
            max_connections_per_ip: 128,
            metrics: false,
            query_timeslice_budget_microseconds: 10_000,
            limits: ReqLimits::default(),
            filter_validation: FilterValidationConfig::default(),
            rate_limits: RateLimits::default(),
            threads: Threads::default(),
            compression: Compression::default(),
            write_policy: WritePolicy::default(),
            auth: AuthConfig::default(),
            management: ManagementConfig::default(),
            info: Info::default(),
        }
    }
}

impl Default for Threads {
    fn default() -> Self {
        Self {
            readers: 3,
            monitors: 3,
        }
    }
}

impl Default for Compression {
    fn default() -> Self {
        Self {
            enabled: true,
            sliding_window: false,
        }
    }
}

impl Config {
    /// Parse a TOML file. `path == "-"` reads stdin.
    ///
    /// # Errors
    ///
    /// [`ServerError::Io`] on read failure, [`ServerError::Config`] on
    /// TOML syntax errors or unknown keys, [`ServerError::ServiceUrl`]
    /// on an invalid `[relay] service_url`, [`ServerError::Admins`] on
    /// a malformed `[relay.management] admins` entry,
    /// [`ServerError::Info`] on an invalid `[relay.info]` value,
    /// [`ServerError::FilterValidation`] on an invalid
    /// `[relay.filter_validation]` value, [`ServerError::RelayValue`]
    /// on `relay.auto_ping_seconds = 0` or a write-policy plugin on a
    /// system without `/bin/sh`.
    pub fn load(path: &Path) -> Result<Self, ServerError> {
        let text = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&text)?;
        config.limits()?;
        config.relay.info.validate()?;
        Self::plugin_needs_shell(&config.relay.write_policy.plugin, Path::new("/bin/sh"))?;
        Ok(config)
    }

    /// `nosfry_core::limits::Limits` assembled from `[events]`,
    /// `[relay.limits]`, `[relay.filter_validation]`,
    /// `[relay.rate_limits]`, and `[relay.auth]`.
    ///
    /// # Errors
    ///
    /// [`ServerError::ServiceUrl`] on an invalid `[relay] service_url`,
    /// [`ServerError::Admins`] on a malformed
    /// `[relay.management] admins` entry,
    /// [`ServerError::FilterValidation`] on an invalid
    /// `[relay.filter_validation]` value, [`ServerError::RelayValue`]
    /// on `relay.auto_ping_seconds = 0`.
    pub fn limits(&self) -> Result<Limits, ServerError> {
        // `interval(Duration::ZERO)` panics and the interval doubles
        // as the write deadline — unlike strfry, 0 cannot mean
        // "no pings".
        if self.relay.auto_ping_seconds == 0 {
            return Err(ServerError::RelayValue(
                "relay.auto_ping_seconds must be at least 1".into(),
            ));
        }
        let service_url = if self.relay.service_url.is_empty() {
            None
        } else {
            Some(nosfry_core::url::RelayUrl::parse(&self.relay.service_url)?)
        };
        self.relay
            .management
            .admin_keys()
            .map_err(|e| ServerError::Admins(e.0))?;
        Ok(Limits {
            event: self.events,
            req: ReqLimits {
                filter_validation: self.relay.filter_validation.limits()?,
                ..self.relay.limits.clone()
            },
            rate: self.relay.rate_limits,
            auth: std::sync::Arc::new(nosfry_core::auth::AuthRules::new(
                service_url,
                &self.relay.auth.restricted_read_kinds,
                self.relay.auth.restrict_read_to_involved,
            )),
        })
    }

    /// Parsed `[relay.management] admins` for a `Live` snapshot —
    /// `load` already rejected malformed entries, so this cannot
    /// fail on a loaded config.
    ///
    /// # Errors
    ///
    /// [`ServerError::Admins`] on a malformed entry.
    pub(crate) fn admins(&self) -> Result<std::sync::Arc<[PublicKey]>, ServerError> {
        Ok(self
            .relay
            .management
            .admin_keys()
            .map_err(|e| ServerError::Admins(e.0))?
            .into())
    }

    /// `StoreOptions` assembled from `[db]`.
    #[must_use]
    pub const fn store_options(&self) -> StoreOptions {
        StoreOptions {
            map_size: self.db.map_size,
            max_readers: self.db.max_readers,
            no_read_ahead: self.db.no_read_ahead,
        }
    }

    /// A write-policy plugin is spawned under `sh -c` (strfry does the
    /// same): a configured plugin on a system without a shell — the
    /// distroless runtime image has none — would only fail every publish
    /// `error: internal error` at runtime, so refuse it at load.
    fn plugin_needs_shell(plugin: &str, shell: &Path) -> Result<(), ServerError> {
        if !plugin.is_empty() && !shell.exists() {
            return Err(ServerError::RelayValue(format!(
                "relay.write_policy.plugin needs {}, which this system lacks \
             (the distroless container image has no shell)",
                shell.display()
            )));
        }
        Ok(())
    }

    /// Merge a reloaded config into the running one: every restart-only
    /// field keeps the running value, everything else follows `new`.
    /// Returns the effective config plus the names of the restart-only
    /// keys that differed (the server warns about them once per reload).
    ///
    /// Restart-only: `[db]`, `relay.bind`, `relay.port`,
    /// `relay.nofiles`, `relay.metrics` (route registration),
    /// `relay.query_timeslice_budget_microseconds`, `relay.threads`,
    /// `relay.limits.max_filter_limit`,
    /// `relay.limits.max_filter_limit_count`,
    /// `relay.limits.max_sync_events`, and
    /// `relay.max_sync_memory_bytes` (reader threads hold them),
    /// `relay.max_pending_outbound_bytes_total`, and
    /// `relay.max_subscription_bytes_total` (ditto).
    #[must_use]
    pub fn reloadable_from(&self, mut new: Self) -> (Self, Vec<&'static str>) {
        let mut ignored = Vec::new();
        if new.db != self.db {
            ignored.push("db");
            new.db.clone_from(&self.db);
        }
        let running = &self.relay;
        let relay = &mut new.relay;
        if relay.bind != running.bind {
            ignored.push("relay.bind");
            relay.bind = running.bind;
        }
        if relay.port != running.port {
            ignored.push("relay.port");
            relay.port = running.port;
        }
        if relay.nofiles != running.nofiles {
            ignored.push("relay.nofiles");
            relay.nofiles = running.nofiles;
        }
        if relay.metrics != running.metrics {
            ignored.push("relay.metrics");
            relay.metrics = running.metrics;
        }
        if relay.query_timeslice_budget_microseconds != running.query_timeslice_budget_microseconds
        {
            ignored.push("relay.query_timeslice_budget_microseconds");
            relay.query_timeslice_budget_microseconds = running.query_timeslice_budget_microseconds;
        }
        if relay.threads != running.threads {
            ignored.push("relay.threads");
            relay.threads = running.threads;
        }
        if relay.limits.max_filter_limit != running.limits.max_filter_limit {
            ignored.push("relay.limits.max_filter_limit");
            relay.limits.max_filter_limit = running.limits.max_filter_limit;
        }
        if relay.limits.max_filter_limit_count != running.limits.max_filter_limit_count {
            ignored.push("relay.limits.max_filter_limit_count");
            relay.limits.max_filter_limit_count = running.limits.max_filter_limit_count;
        }
        if relay.limits.max_sync_events != running.limits.max_sync_events {
            ignored.push("relay.limits.max_sync_events");
            relay.limits.max_sync_events = running.limits.max_sync_events;
        }
        if relay.max_sync_memory_bytes != running.max_sync_memory_bytes {
            ignored.push("relay.max_sync_memory_bytes");
            relay.max_sync_memory_bytes = running.max_sync_memory_bytes;
        }
        if relay.max_pending_outbound_bytes_total != running.max_pending_outbound_bytes_total {
            ignored.push("relay.max_pending_outbound_bytes_total");
            relay.max_pending_outbound_bytes_total = running.max_pending_outbound_bytes_total;
        }
        if relay.max_subscription_bytes_total != running.max_subscription_bytes_total {
            ignored.push("relay.max_subscription_bytes_total");
            relay.max_subscription_bytes_total = running.max_subscription_bytes_total;
        }
        (new, ignored)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use super::*;

    /// The shipped `nosfry.example.toml` parses to exactly `Config::default()`.
    #[test]
    fn example_toml_matches_defaults() {
        let text = include_str!("../../../nosfry.example.toml");
        let parsed: Config = toml::from_str(text).unwrap();
        assert_eq!(parsed, Config::default());
    }

    /// `relay.nofiles` defaults to strfry's `1_000_000`; `0` disables.
    #[test]
    fn nofiles_default_and_zero() {
        assert_eq!(Config::default().relay.nofiles, 1_000_000);
        let parsed: Config = toml::from_str("[relay]\nnofiles = 0\n").unwrap();
        assert_eq!(parsed.relay.nofiles, 0);
    }

    /// Unknown keys stay rejected.
    #[test]
    fn unknown_key_rejected() {
        assert!(toml::from_str::<Config>("[relay]\nbogus = 1\n").is_err());
    }

    /// `Config::load` validates `[relay] service_url` too, so a file
    /// whose URL is not ws/wss fails with `ServerError::ServiceUrl`
    /// and a broken SIGHUP reload keeps the running configuration.
    #[test]
    fn load_rejects_invalid_service_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nosfry.toml");
        std::fs::write(&path, "[relay]\nservice_url = \"http://bad\"\n").unwrap();
        assert!(matches!(
            Config::load(&path),
            Err(ServerError::ServiceUrl(_))
        ));
    }

    /// `Config::load` validates `[relay.info]` too: a `pubkey` or
    /// `self` that is not 64 lowercase hex fails with
    /// `ServerError::Info` and a broken reload keeps the running
    /// configuration.
    #[test]
    fn load_rejects_invalid_info_pubkey() {
        for key in ["pubkey", "self"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("nosfry.toml");
            std::fs::write(&path, format!("[relay.info]\n{key} = \"npub1bad\"\n")).unwrap();
            assert!(matches!(Config::load(&path), Err(ServerError::Info(_))));
        }
    }

    /// `Config::load` validates `[relay.filter_validation]` when
    /// enabled: `max_filters_per_req = 0` or a `min` over `max`
    /// fails with `ServerError::FilterValidation` naming the key, and
    /// a broken reload keeps the running configuration.
    #[test]
    fn load_rejects_invalid_filter_validation() {
        for section in [
            "enabled = true\nmax_filters_per_req = 0",
            "enabled = true\nmin_filters_per_req = 4",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("nosfry.toml");
            std::fs::write(&path, format!("[relay.filter_validation]\n{section}\n")).unwrap();
            assert!(
                matches!(Config::load(&path), Err(ServerError::FilterValidation(_))),
                "{section}"
            );
        }
        // Disabled sections are never validated.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nosfry.toml");
        std::fs::write(
            &path,
            "[relay.filter_validation]\nenabled = false\nmax_filters_per_req = 0\n",
        )
        .unwrap();
        assert!(Config::load(&path).is_ok());
    }

    /// `relay.auto_ping_seconds = 0` would panic every connection
    /// task (`interval(Duration::ZERO)`); `Config::limits` — run at
    /// load and on every reload — refuses it.
    #[test]
    fn load_rejects_zero_auto_ping() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nosfry.toml");
        std::fs::write(&path, "[relay]\nauto_ping_seconds = 0\n").unwrap();
        let Err(ServerError::RelayValue(msg)) = Config::load(&path) else {
            unreachable!("auto_ping_seconds = 0 must fail")
        };
        assert_eq!(msg, "relay.auto_ping_seconds must be at least 1");
    }

    /// A write-policy plugin runs under `/bin/sh -c`; without a shell
    /// it is refused at load, with one it loads.
    #[test]
    fn plugin_needs_a_shell() {
        let missing = Path::new("/definitely/not/a/shell");
        let err = Config::plugin_needs_shell("/bin/true", missing).unwrap_err();
        assert!(
            matches!(&err, ServerError::RelayValue(_)),
            "expected RelayValue, got {err:?}"
        );
        let ServerError::RelayValue(msg) = err else {
            unreachable!("matched above")
        };
        assert!(
            msg.starts_with("relay.write_policy.plugin needs /definitely/not/a/shell"),
            "{msg}"
        );
        assert!(msg.contains("no shell"), "{msg}");

        let shell = tempfile::NamedTempFile::new().unwrap();
        Config::plugin_needs_shell("/bin/true", shell.path()).unwrap();
        Config::plugin_needs_shell("", missing).unwrap();
    }

    /// Restart-only fields keep the running value and are reported;
    /// reloadable fields pass through.
    #[test]
    fn reloadable_from() {
        let running = Config::default();
        let mut new = Config::default();
        new.db.path = PathBuf::from("/elsewhere");
        new.relay.port = 9_999;
        new.relay.nofiles = 0;
        new.relay.metrics = true;
        new.relay.query_timeslice_budget_microseconds = 1;
        new.relay.threads.readers = 9;
        new.relay.limits.max_filter_limit = 1;
        new.relay.limits.max_filter_limit_count = 1;
        new.relay.limits.max_sync_events = 1;
        new.relay.max_sync_memory_bytes = 1;
        new.relay.max_pending_outbound_bytes_total = 1;
        new.relay.info.name = "reloaded".into();
        new.relay.rate_limits.events_per_second = 5;
        new.relay.write_policy.plugin = "/bin/true".into();
        new.relay.service_url = "wss://relay.example.com".into();
        let (merged, ignored) = running.reloadable_from(new);
        assert_eq!(
            ignored,
            [
                "db",
                "relay.port",
                "relay.nofiles",
                "relay.metrics",
                "relay.query_timeslice_budget_microseconds",
                "relay.threads",
                "relay.limits.max_filter_limit",
                "relay.limits.max_filter_limit_count",
                "relay.limits.max_sync_events",
                "relay.max_sync_memory_bytes",
                "relay.max_pending_outbound_bytes_total",
            ]
        );
        assert_eq!(merged.db.path, running.db.path);
        assert_eq!(merged.relay.port, running.relay.port);
        assert_eq!(merged.relay.info.name, "reloaded");
        assert_eq!(merged.relay.rate_limits.events_per_second, 5);
        assert_eq!(merged.relay.write_policy.plugin, "/bin/true");
        assert_eq!(merged.relay.service_url, "wss://relay.example.com");
    }

    /// An unchanged reload reports nothing.
    #[test]
    fn reloadable_from_noop() {
        let running = Config::default();
        let (merged, ignored) = running.clone().reloadable_from(running);
        let expected: [&str; 0] = [];
        assert_eq!(ignored, expected);
        assert_eq!(merged, Config::default());
    }
}
