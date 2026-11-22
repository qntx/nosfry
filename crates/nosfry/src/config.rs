//! TOML configuration, strfry-style sections and defaults.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
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
    /// `[[relay.listen]]` — the addresses the relay accepts
    /// connections on (restart-only: reloads keep the running set).
    #[serde(default = "default_listen")]
    pub listen: Vec<Listen>,
    /// `[relay.profiles.<name>]` — per-peer connection caps and rate
    /// limits. The `default` profile always exists: it is
    /// `Profile::default()` when the file does not define it.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    /// The relay's canonical `ws://`/`wss://` URL clients sign into an
    /// AUTH event's `relay` tag and name in a NIP-62 request to
    /// vanish. Empty disables AUTH: restricted kinds are refused on
    /// write and never served, and protected events are rejected.
    pub service_url: String,
    /// Other `ws://`/`wss://` URLs the relay answers to — an onion
    /// address torrc forwards, an iroh name, an old domain. An AUTH
    /// `relay` tag, NIP-62 `relay` tag or NIP-98 `u` tag may name any
    /// of them; they require a canonical `service_url`.
    #[serde(default)]
    pub service_url_aliases: Vec<String>,
    /// Soft open-file limit to raise to at startup, capped by the hard
    /// limit (0 = leave unchanged).
    pub nofiles: u64,
    /// Maximum inbound WebSocket payload in bytes.
    pub max_websocket_payload_size: usize,
    /// WebSocket ping interval in seconds.
    pub auto_ping_seconds: u64,
    /// Set `SO_KEEPALIVE` on accepted sockets (strfry
    /// `enableTcpKeepalive`): OS default timings, reloadable for new
    /// connections. Applies to TCP listeners only.
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
    /// Maximum simultaneous WebSocket connections. Omitted, the cap
    /// derives from the soft open-file limit (see
    /// `limiter::connection_ceiling`); an explicit `0` is refused —
    /// there is no "unlimited".
    pub max_connections: Option<usize>,
    /// Serve `GET /metrics` (Prometheus text exposition format) on
    /// every listener. Unauthenticated — keep it behind a reverse
    /// proxy or firewall.
    pub metrics: bool,
    /// Per-slice scan budget in microseconds.
    pub query_timeslice_budget_microseconds: u64,
    /// REQ limits (`nosfry_core::limits::ReqLimits` verbatim).
    pub limits: ReqLimits,
    /// REQ/COUNT filter-validation rules
    /// (`nosfry_core::limits::FilterValidationConfig` verbatim).
    pub filter_validation: FilterValidationConfig,
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

/// One `[[relay.listen]]` entry: an address plus the profile and
/// real-IP trust the connections accepted on it use.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// `"<ip>:<port>"`, `"[v6]:<port>"`, or `"unix:<absolute path>"`.
    pub address: ListenAddress,
    /// The `[relay.profiles.<name>]` this listener's connections use.
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Header carrying the real client IP; its last comma-separated
    /// value is trusted, so set it only on a listener reachable only
    /// through a proxy that sets or appends the header (default "": no
    /// header is trusted).
    #[serde(default)]
    pub real_ip_header: String,
}

/// A `[[relay.listen]]` `address`: a TCP socket address or a
/// unix-domain-socket path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ListenAddress {
    /// `"<ip>:<port>"` or `"[v6]:<port>"`.
    Tcp(SocketAddr),
    /// `"unix:<absolute path>"` — the socket's directory and the umask
    /// decide its permissions; there is no mode key.
    Unix(PathBuf),
}

impl ListenAddress {
    /// Parse the `[[relay.listen]]` address forms; the error names the
    /// offending value.
    fn parse(value: &str) -> Result<Self, String> {
        if let Some(path) = value.strip_prefix("unix:") {
            return if Path::new(path).is_absolute() {
                Ok(Self::Unix(PathBuf::from(path)))
            } else {
                Err(format!(
                    "invalid listener address {value:?}: unix path must be absolute"
                ))
            };
        }
        value.parse().map(Self::Tcp).map_err(|_| {
            format!(
                "invalid listener address {value:?}: expected \
                 \"<ip>:<port>\", \"[v6]:<port>\", or \"unix:<absolute path>\""
            )
        })
    }
}

/// The configured string: `unix:`-prefixed paths round-trip exactly,
/// socket addresses in their canonical form.
impl std::fmt::Display for ListenAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(sock) => sock.fmt(f),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

impl<'de> Deserialize<'de> for ListenAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// `[relay.profiles.<name>]` — the caps and rate limits one listener
/// profile applies to its peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Maximum simultaneous WebSocket connections per peer
    /// (0 = unlimited). IP peers count per address (IPv4 exact, IPv6
    /// per /64); a transport without client addresses (unix socket)
    /// counts all its connections as one peer.
    #[serde(default = "default_max_connections_per_peer")]
    pub max_connections_per_peer: usize,
    /// `[relay.profiles.<name>.rate_limits]` — per-connection and
    /// per-peer EVENT/REQ rate limits (`nosfry_core::limits::RateLimits`
    /// verbatim). The `ip_*` buckets are per-peer: on a unix listener
    /// they bind listener-wide.
    #[serde(default)]
    pub rate_limits: RateLimits,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            max_connections_per_peer: default_max_connections_per_peer(),
            rate_limits: RateLimits::default(),
        }
    }
}

fn default_listen() -> Vec<Listen> {
    vec![Listen {
        address: ListenAddress::Tcp(SocketAddr::from(([127, 0, 0, 1], 7_777))),
        profile: default_profile(),
        real_ip_header: String::new(),
    }]
}

fn default_profile() -> String {
    "default".to_owned()
}

const fn default_max_connections_per_peer() -> usize {
    128
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

impl Relay {
    /// `profiles` with `default` guaranteed present — it is
    /// `Profile::default()` when the file does not define it.
    pub(crate) fn profiles(&self) -> BTreeMap<String, Profile> {
        let mut profiles = self.profiles.clone();
        profiles.entry(default_profile()).or_default();
        profiles
    }

    /// `[[relay.listen]]` invariants, checked at load and at reload
    /// (a reload removing a profile a running listener uses is
    /// refused through this check).
    fn check_listeners(&self) -> Result<(), ServerError> {
        if self.listen.is_empty() {
            return Err(ServerError::RelayValue(
                "relay.listen needs at least one listener".to_owned(),
            ));
        }
        let profiles = self.profiles();
        let mut seen = HashSet::with_capacity(self.listen.len());
        for listen in &self.listen {
            if !seen.insert(&listen.address) {
                return Err(ServerError::RelayValue(format!(
                    "relay.listen: duplicate address \"{}\"",
                    listen.address
                )));
            }
            if !profiles.contains_key(&listen.profile) {
                return Err(ServerError::RelayValue(format!(
                    "relay.listen: listener \"{}\" uses undefined profile {:?}",
                    listen.address, listen.profile
                )));
            }
        }
        Ok(())
    }
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            profiles: BTreeMap::from([("default".to_owned(), Profile::default())]),
            service_url: String::new(),
            service_url_aliases: Vec::new(),
            nofiles: 1_000_000,
            max_websocket_payload_size: 131_072,
            auto_ping_seconds: 55,
            tcp_keepalive: false,
            max_pending_outbound_bytes: 33_554_432,
            max_pending_outbound_bytes_total: 1_073_741_824,
            max_sync_memory_bytes: 1_073_741_824,
            max_subscription_bytes_total: 1_073_741_824,
            max_connections: None,
            metrics: false,
            query_timeslice_budget_microseconds: 10_000,
            limits: ReqLimits::default(),
            filter_validation: FilterValidationConfig::default(),
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
    /// `[relay.limits]`, `[relay.filter_validation]`, the `default`
    /// profile's `rate_limits`, and `[relay.auth]`.
    ///
    /// # Errors
    ///
    /// [`ServerError::ServiceUrl`] on an invalid `[relay] service_url`,
    /// [`ServerError::Admins`] on a malformed
    /// `[relay.management] admins` entry,
    /// [`ServerError::FilterValidation`] on an invalid
    /// `[relay.filter_validation]` value, [`ServerError::RelayValue`]
    /// on `relay.auto_ping_seconds = 0` or an invalid
    /// `[[relay.listen]]` set.
    pub fn limits(&self) -> Result<Limits, ServerError> {
        // `interval(Duration::ZERO)` panics and the interval doubles
        // as the write deadline — unlike strfry, 0 cannot mean
        // "no pings".
        if self.relay.auto_ping_seconds == 0 {
            return Err(ServerError::RelayValue(
                "relay.auto_ping_seconds must be at least 1".into(),
            ));
        }
        self.relay.check_listeners()?;
        nosfry_core::limits::check_payload_size(
            self.relay.max_websocket_payload_size,
            &self.events,
        )
        .map_err(|e| ServerError::RelayValue(e.to_string()))?;
        let names = nosfry_core::url::RelayNames::parse(
            &self.relay.service_url,
            &self.relay.service_url_aliases,
        )?;
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
            rate: self
                .relay
                .profiles()
                .get("default")
                .map_or_else(RateLimits::default, |profile| profile.rate_limits),
            auth: std::sync::Arc::new(nosfry_core::auth::AuthRules::new(
                names,
                &self.relay.auth.restricted_read_kinds,
                self.relay.auth.restrict_read_to_involved,
            )),
        })
    }

    /// Per-profile session `Limits` for [`crate::Live`]: the shared
    /// limits with each profile's `rate_limits` swapped in. `base`
    /// must already be validated (`Config::limits`).
    pub(crate) fn profile_limits(
        &self,
        base: &Limits,
    ) -> std::collections::HashMap<String, std::sync::Arc<Limits>> {
        self.relay
            .profiles()
            .iter()
            .map(|(name, profile)| {
                (
                    name.clone(),
                    std::sync::Arc::new(Limits {
                        rate: profile.rate_limits,
                        ..base.clone()
                    }),
                )
            })
            .collect()
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
    /// Restart-only: `[db]`, `relay.listen`,
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
        if relay.listen != running.listen {
            ignored.push("relay.listen");
            relay.listen.clone_from(&running.listen);
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

    /// `[relay] service_url_aliases` validates like `service_url` —
    /// every entry must be a `ws://`/`wss://` URL, and aliases
    /// require a canonical `service_url`.
    #[test]
    fn service_url_aliases_validate() {
        let mut config = Config::default();
        config.relay.service_url = "wss://relay.example.com".into();
        config.relay.service_url_aliases = vec!["ws://abcdef.onion".into()];
        let limits = config.limits().unwrap();
        assert!(limits.auth.names().matches("wss://relay.example.com"));
        assert!(limits.auth.names().matches("ws://abcdef.onion"));

        config.relay.service_url_aliases = vec!["http://bad".into()];
        assert!(matches!(config.limits(), Err(ServerError::ServiceUrl(_))));

        config.relay.service_url = String::new();
        config.relay.service_url_aliases = vec!["ws://abcdef.onion".into()];
        assert!(matches!(config.limits(), Err(ServerError::ServiceUrl(_))));
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

    /// `relay.max_websocket_payload_size` must carry the largest
    /// allowed EVENT frame (`max_event_size + 10`). `Config::limits`
    /// runs at load and on every reload, so both paths refuse the
    /// pair.
    #[test]
    fn load_rejects_payload_below_event_frame() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nosfry.toml");
        std::fs::write(
            &path,
            "[events]\nmax_event_size = 100\n[relay]\nmax_websocket_payload_size = 109\n",
        )
        .unwrap();
        let Err(ServerError::RelayValue(msg)) = Config::load(&path) else {
            unreachable!("undersized payload must fail")
        };
        assert_eq!(
            msg,
            "relay.max_websocket_payload_size (109) must be at least events.max_event_size + 10 (110) so the largest allowed event fits in one EVENT frame"
        );
        std::fs::write(
            &path,
            "[events]\nmax_event_size = 100\n[relay]\nmax_websocket_payload_size = 110\n",
        )
        .unwrap();
        Config::load(&path).expect("boundary pair loads");
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
        new.relay.listen = vec![Listen {
            address: ListenAddress::Tcp(SocketAddr::from(([127, 0, 0, 1], 9_999))),
            profile: "default".to_owned(),
            real_ip_header: String::new(),
        }];
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
        new.relay
            .profiles
            .entry("default".to_owned())
            .or_default()
            .rate_limits
            .events_per_second = 5;
        new.relay.write_policy.plugin = "/bin/true".into();
        new.relay.service_url = "wss://relay.example.com".into();
        let (merged, ignored) = running.reloadable_from(new);
        assert_eq!(
            ignored,
            [
                "db",
                "relay.listen",
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
        assert_eq!(merged.relay.listen, running.relay.listen);
        assert_eq!(merged.relay.info.name, "reloaded");
        assert_eq!(
            merged
                .relay
                .profiles()
                .get("default")
                .unwrap()
                .rate_limits
                .events_per_second,
            5
        );
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

    /// `[[relay.listen]]` accepts `<ip>:<port>`, `[v6]:<port>`, and
    /// `unix:<absolute path>`; anything else is an error naming the
    /// value.
    #[test]
    fn listen_address_forms() {
        let parse = |toml: &str| -> Option<ListenAddress> {
            toml::from_str::<Config>(&format!("[[relay.listen]]\naddress = \"{toml}\"\n"))
                .ok()
                .and_then(|config| config.relay.listen.into_iter().next())
                .map(|listen| listen.address)
        };
        assert_eq!(
            parse("127.0.0.1:7777"),
            Some(ListenAddress::Tcp("127.0.0.1:7777".parse().unwrap()))
        );
        assert_eq!(
            parse("[::1]:8080"),
            Some(ListenAddress::Tcp("[::1]:8080".parse().unwrap()))
        );
        assert_eq!(
            parse("unix:/run/nosfry/tor.sock"),
            Some(ListenAddress::Unix(PathBuf::from("/run/nosfry/tor.sock")))
        );
        for bad in [
            "unix:relative.sock",
            "example.com:7777",
            "127.0.0.1",
            ":7777",
            "unix:",
        ] {
            let err = toml::from_str::<Config>(&format!("[[relay.listen]]\naddress = \"{bad}\"\n"))
                .unwrap_err();
            assert!(
                err.to_string().contains(bad),
                "the error names the invalid value {bad:?}: {err}"
            );
        }
    }

    /// A listener `address` is required; `profile` and
    /// `real_ip_header` default.
    #[test]
    fn listen_defaults() {
        let listen = toml::from_str::<Config>("[[relay.listen]]\naddress = \"127.0.0.1:7777\"\n")
            .unwrap()
            .relay
            .listen
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(listen.profile, "default");
        assert_eq!(listen.real_ip_header, "");
        // `default` is synthesized when the file defines no profile.
        assert_eq!(
            *toml::from_str::<Config>("")
                .unwrap()
                .relay
                .profiles()
                .get("default")
                .unwrap(),
            Profile::default()
        );
        // The shipped default is one TCP listener on 7777.
        assert_eq!(
            Config::default().relay.listen,
            vec![Listen {
                address: ListenAddress::Tcp("127.0.0.1:7777".parse().unwrap()),
                profile: "default".to_owned(),
                real_ip_header: String::new(),
            }]
        );
    }

    /// `check_listeners` refuses an empty set, duplicate addresses,
    /// and unknown profiles — at load (`limits()`) and for a merged
    /// reload (a reload removing a profile a running listener uses
    /// fails validation there, so it is refused).
    #[test]
    fn listener_validation() {
        let mut empty = Config::default();
        empty.relay.listen = Vec::new();
        let err_empty = empty.limits().unwrap_err();
        assert!(
            err_empty.to_string().contains("at least one listener"),
            "{err_empty}"
        );

        let mut dup = Config::default();
        let extra = dup.relay.listen.first().unwrap().clone();
        dup.relay.listen.push(extra);
        let err_dup = dup.limits().unwrap_err();
        assert!(
            err_dup.to_string().contains("duplicate address"),
            "{err_dup}"
        );

        let mut unknown = Config::default();
        if let Some(listen) = unknown.relay.listen.first_mut() {
            listen.profile = "tor".to_owned();
        }
        let err_unknown = unknown.limits().unwrap_err();
        assert!(
            err_unknown.to_string().contains("undefined profile")
                && err_unknown.to_string().contains("tor"),
            "{err_unknown}"
        );

        // The merged config a reload produces carries the running
        // listeners: a reload removing their profile is refused by the
        // same check (`limits()` runs on the merged config).
        let running = {
            let mut config = Config::default();
            config
                .relay
                .profiles
                .insert("tor".to_owned(), Profile::default());
            if let Some(listen) = config.relay.listen.first_mut() {
                listen.profile = "tor".to_owned();
            }
            config
        };
        // The reload offers only `default`.
        let (merged, _) = running.reloadable_from(Config::default());
        let err_merged = merged.limits().unwrap_err();
        assert!(
            err_merged.to_string().contains("undefined profile")
                && err_merged.to_string().contains("tor"),
            "{err_merged}"
        );
    }
}
