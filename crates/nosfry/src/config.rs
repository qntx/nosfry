//! TOML configuration, strfry-style sections and defaults.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nosfry_core::access::AccessConfig;
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
    /// Blossom blob-server section (the `blossom` cargo feature).
    pub blossom: Blossom,
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
    /// write and never served, and protected events are rejected —
    /// unless an embedded onion listener exists, whose derived URL
    /// then stands in as the canonical name (see [`Relay::service_url`]).
    pub service_url: String,
    /// Other `ws://`/`wss://` URLs the relay answers to — an onion
    /// address torrc forwards, an iroh name, an old domain. An AUTH
    /// `relay` tag, NIP-62 `relay` tag or NIP-98 `u` tag may name any
    /// of them; they require a canonical `service_url`.
    #[serde(default)]
    pub service_url_aliases: Vec<String>,
    /// `[relay.onion]` — embedded onion service settings (the `onion`
    /// cargo feature).
    #[serde(default)]
    pub onion: Onion,
    /// The `ws://<addr>.onion` URLs of the embedded onion listeners,
    /// derived from their keys at startup — never read from the file.
    /// With no `service_url` the first is the canonical name;
    /// otherwise all are aliases.
    #[serde(skip)]
    pub onion_urls: Vec<String>,
    /// `[relay.iroh]` — embedded iroh listener settings (the `iroh`
    /// cargo feature).
    #[serde(default)]
    pub iroh: Iroh,
    /// The `ws://<z32>.iroh` URLs of the embedded iroh listeners,
    /// derived from their keys at startup — never read from the file.
    /// With no `service_url` and no onion URL the first is the
    /// canonical name; otherwise all are aliases.
    #[serde(skip)]
    pub iroh_urls: Vec<String>,
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
    /// `[relay.access]` — per-kind read/write access rules.
    pub access: AccessConfig,
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

/// A `[[relay.listen]]` `address`: a TCP socket address, a
/// unix-domain-socket path, an embedded onion service, or an embedded
/// iroh endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ListenAddress {
    /// `"<ip>:<port>"` or `"[v6]:<port>"`.
    Tcp(SocketAddr),
    /// `"unix:<absolute path>"` — the socket's directory and the umask
    /// decide its permissions; there is no mode key.
    Unix(PathBuf),
    /// `"onion:<nickname>"` — an embedded onion service (the `onion`
    /// cargo feature); the nickname names the service's key directory
    /// under `[relay.onion] state_dir`.
    Onion(String),
    /// `"iroh:<nickname>"` — an embedded iroh endpoint (the `iroh`
    /// cargo feature); the nickname names the key file under
    /// `[relay.iroh] state_dir`.
    Iroh(String),
}

/// The slug rule for an embedded transport's nickname (Arti's rule,
/// reused for iroh): non-empty, not starting with `-`, only lowercase
/// ASCII alphanumerics, `_`, `-`.
fn is_nickname(nickname: &str) -> bool {
    !nickname.is_empty()
        && !nickname.starts_with('-')
        && nickname
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
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
        if let Some(nickname) = value.strip_prefix("onion:") {
            return if is_nickname(nickname) {
                Ok(Self::Onion(nickname.to_owned()))
            } else {
                Err(format!(
                    "invalid listener address {value:?}: onion nickname must be non-empty, \
                     not start with '-', and contain only [a-z0-9_-]"
                ))
            };
        }
        if let Some(nickname) = value.strip_prefix("iroh:") {
            return if is_nickname(nickname) {
                Ok(Self::Iroh(nickname.to_owned()))
            } else {
                Err(format!(
                    "invalid listener address {value:?}: iroh nickname must be non-empty, \
                     not start with '-', and contain only [a-z0-9_-]"
                ))
            };
        }
        value.parse().map(Self::Tcp).map_err(|_| {
            format!(
                "invalid listener address {value:?}: expected \
                 \"<ip>:<port>\", \"[v6]:<port>\", \"unix:<absolute path>\", \
                 \"onion:<nickname>\", or \"iroh:<nickname>\""
            )
        })
    }
}

/// The configured string: `unix:`-, `onion:`- and `iroh:`-prefixed
/// values round-trip exactly, socket addresses in their canonical
/// form.
impl std::fmt::Display for ListenAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(sock) => sock.fmt(f),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
            Self::Onion(nickname) => write!(f, "onion:{nickname}"),
            Self::Iroh(nickname) => write!(f, "iroh:{nickname}"),
        }
    }
}

impl<'de> Deserialize<'de> for ListenAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// `blossom.upload` — who may upload blobs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Upload {
    /// Admins plus NIP-86 allowed pubkeys.
    #[default]
    Allowed,
    /// Any validly authorized pubkey.
    Everyone,
}

/// `[blossom]` — the blob server (the `blossom` cargo feature).
/// `upload`, `max_blob_size`, `max_total_bytes`, `quota_bytes`,
/// `quota_blobs`, and `mime_types` are live-reloadable; everything
/// else is restart-only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Blossom {
    /// Serve Blossom on `[[blossom.listen]]` (restart-only).
    pub enabled: bool,
    /// The blob server's public `http(s)://host[:port]` URL —
    /// required when enabled; must not share a host with
    /// `relay.service_url` or any alias so uploaded HTML/SVG can
    /// never run in the relay's origin (restart-only).
    pub public_url: String,
    /// Blob store directory (restart-only).
    pub dir: PathBuf,
    /// Who may upload.
    pub upload: Upload,
    /// Maximum blob size in bytes (at least 1, at most
    /// `max_total_bytes`).
    pub max_blob_size: u64,
    /// Global cap on stored blob bytes (at least 1).
    pub max_total_bytes: u64,
    /// Per-pubkey stored-byte quota (at least 1).
    pub quota_bytes: u64,
    /// Per-pubkey blob-count quota (at least 1).
    pub quota_blobs: u64,
    /// Allowed `type/subtype` or `type/*` media types, lowercase;
    /// empty allows every type.
    pub mime_types: Vec<String>,
    /// Simultaneous upload streams, 1..=1024 (restart-only).
    pub max_concurrent_uploads: usize,
    /// Simultaneous blossom connections — accept waits for a free
    /// slot (restart-only).
    pub max_connections: usize,
    /// `[[blossom.listen]]` — the blob server's addresses
    /// (restart-only).
    #[serde(default = "default_blossom_listen")]
    pub listen: Vec<BlossomListen>,
}

/// One `[[blossom.listen]]` entry — the same address forms as
/// `[[relay.listen]]` except `onion:` and `iroh:`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlossomListen {
    /// `"<ip>:<port>"`, `"[v6]:<port>"`, or `"unix:<absolute path>"`.
    pub address: ListenAddress,
}

fn default_blossom_listen() -> Vec<BlossomListen> {
    vec![BlossomListen {
        address: ListenAddress::Tcp(SocketAddr::from(([127, 0, 0, 1], 7_778))),
    }]
}

impl Default for Blossom {
    fn default() -> Self {
        Self {
            enabled: false,
            public_url: String::new(),
            dir: PathBuf::from("./nosfry-blobs"),
            upload: Upload::default(),
            max_blob_size: 104_857_600,
            max_total_bytes: 10_737_418_240,
            quota_bytes: 1_073_741_824,
            quota_blobs: 10_000,
            mime_types: Vec::new(),
            max_concurrent_uploads: 16,
            max_connections: 1024,
            listen: default_blossom_listen(),
        }
    }
}

impl Blossom {
    /// The `public_url` host, lowercased — `None` when it does not
    /// parse to an `http(s)` URL with a host.
    #[cfg(feature = "blossom")]
    fn public_host(&self) -> Option<String> {
        url::Url::parse(&self.public_url)
            .ok()?
            .host_str()
            .map(str::to_ascii_lowercase)
    }

    /// The `ws(s)`/`http(s)` host of a relay name URL — `None` when
    /// it has none (empty string included).
    #[cfg(feature = "blossom")]
    fn url_host(name: &str) -> Option<String> {
        if name.is_empty() {
            return None;
        }
        url::Url::parse(name)
            .ok()?
            .host_str()
            .map(str::to_ascii_lowercase)
    }

    /// The restart-only service settings for `nosfry_blossom`.
    ///
    /// # Errors
    ///
    /// [`ServerError::RelayValue`] when `public_url` is unusable —
    /// unreachable after a validated load.
    #[cfg(feature = "blossom")]
    pub fn settings(&self) -> Result<nosfry_blossom::Settings, ServerError> {
        Ok(nosfry_blossom::Settings {
            public_url: self.public_url.trim_end_matches('/').to_owned(),
            public_host: self.public_host().ok_or_else(|| {
                ServerError::RelayValue("blossom.public_url has no host".to_owned())
            })?,
            max_concurrent_uploads: self.max_concurrent_uploads,
        })
    }

    /// The live `nosfry_blossom` policy this config describes.
    #[cfg(feature = "blossom")]
    #[must_use]
    pub fn policy(&self, admins: &Arc<[PublicKey]>) -> nosfry_blossom::Policy {
        nosfry_blossom::Policy {
            upload_everyone: self.upload == Upload::Everyone,
            admins: Arc::clone(admins),
            max_blob_size: self.max_blob_size,
            max_total_bytes: self.max_total_bytes,
            quota_bytes: self.quota_bytes,
            quota_blobs: self.quota_blobs,
            mime_types: self.mime_types.clone(),
        }
    }

    /// Whether two listener addresses collide — the same TCP port
    /// where either IP is unspecified or the IPs match, or the same
    /// unix path. A port-0 (ephemeral) entry can never collide: the
    /// OS assigns a free port.
    #[cfg(feature = "blossom")]
    fn addresses_clash(here: &ListenAddress, other: &ListenAddress) -> bool {
        match (here, other) {
            (ListenAddress::Tcp(here), ListenAddress::Tcp(other)) => {
                here.port() != 0
                    && here.port() == other.port()
                    && (here.ip().is_unspecified()
                        || other.ip().is_unspecified()
                        || here.ip() == other.ip())
            }
            (ListenAddress::Unix(here), ListenAddress::Unix(other)) => here == other,
            _ => false,
        }
    }

    /// Field rules, checked at load and at reload through
    /// [`Config::limits`]. Numeric/shape rules always run; listener
    /// and `public_url` cross-checks run when `enabled`.
    ///
    /// # Errors
    ///
    /// [`ServerError::RelayValue`] describing the first rule broken.
    pub fn check(&self, relay: &Relay) -> Result<(), ServerError> {
        for (key, value) in [
            ("max_blob_size", self.max_blob_size),
            ("max_total_bytes", self.max_total_bytes),
            ("quota_bytes", self.quota_bytes),
            ("quota_blobs", self.quota_blobs),
        ] {
            if value == 0 {
                return Err(ServerError::RelayValue(format!(
                    "blossom.{key} must be at least 1"
                )));
            }
        }
        if self.max_blob_size > self.max_total_bytes {
            return Err(ServerError::RelayValue(
                "blossom.max_blob_size must not exceed blossom.max_total_bytes".to_owned(),
            ));
        }
        if self.max_concurrent_uploads == 0 || self.max_concurrent_uploads > 1024 {
            return Err(ServerError::RelayValue(
                "blossom.max_concurrent_uploads must be in 1..=1024".to_owned(),
            ));
        }
        if self.max_connections == 0 {
            return Err(ServerError::RelayValue(
                "blossom.max_connections must be at least 1".to_owned(),
            ));
        }
        let mut seen = HashSet::with_capacity(self.listen.len());
        for listen in &self.listen {
            if !seen.insert(&listen.address) {
                return Err(ServerError::RelayValue(format!(
                    "blossom.listen: duplicate address \"{}\"",
                    listen.address
                )));
            }
            if let ListenAddress::Onion(nickname) = &listen.address {
                return Err(ServerError::RelayValue(format!(
                    "blossom.listen: \"onion:{nickname}\" — blossom listeners do not \
                     support onion: yet"
                )));
            }
            if let ListenAddress::Iroh(nickname) = &listen.address {
                return Err(ServerError::RelayValue(format!(
                    "blossom.listen: \"iroh:{nickname}\" — blossom listeners do not \
                     support iroh: yet"
                )));
            }
        }
        #[cfg(feature = "blossom")]
        for mime in &self.mime_types {
            if !nosfry_blossom::mime::allow_entry(mime) {
                return Err(ServerError::RelayValue(format!(
                    "blossom.mime_types entry {mime:?} is not a lowercase \
                     \"type/subtype\" or \"type/*\""
                )));
            }
        }
        if !self.enabled {
            return Ok(());
        }
        #[cfg(not(feature = "blossom"))]
        {
            let _ = relay;
            Err(ServerError::RelayValue(
                "blossom.enabled: needs nosfry built with the blossom cargo \
                 feature (cargo install nosfry --features blossom)"
                    .to_owned(),
            ))
        }
        #[cfg(feature = "blossom")]
        {
            if self.listen.is_empty() {
                return Err(ServerError::RelayValue(
                    "blossom.listen needs at least one listener when enabled".to_owned(),
                ));
            }
            self.check_public_url(relay)?;
            let clash = self
                .listen
                .iter()
                .flat_map(|listen| relay.listen.iter().map(move |r| (listen, r)))
                .find(|(listen, r)| Self::addresses_clash(&listen.address, &r.address));
            if let Some((listen, relay_listen)) = clash {
                return Err(ServerError::RelayValue(format!(
                    "blossom.listen \"{}\" shares an address with relay.listen \"{}\"",
                    listen.address, relay_listen.address
                )));
            }
            Ok(())
        }
    }

    /// `public_url` shape plus the must-not-share-a-host check
    /// against `service_url` and `service_url_aliases`.
    #[cfg(feature = "blossom")]
    fn check_public_url(&self, relay: &Relay) -> Result<(), ServerError> {
        let parsed = url::Url::parse(&self.public_url).map_err(|_| {
            ServerError::RelayValue(format!(
                "blossom.public_url {:?} is not a valid http(s) URL",
                self.public_url
            ))
        })?;
        let good_shape = matches!(parsed.scheme(), "http" | "https")
            && parsed.host().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && (parsed.path().is_empty() || parsed.path() == "/")
            && parsed.query().is_none()
            && parsed.fragment().is_none();
        if !good_shape {
            return Err(ServerError::RelayValue(format!(
                "blossom.public_url {:?} must be http(s)://host[:port] with no path, \
                 query, fragment, or userinfo",
                self.public_url
            )));
        }
        let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
            return Err(ServerError::RelayValue(
                "blossom.public_url has no host".to_owned(),
            ));
        };
        let names = std::iter::once(relay.service_url.as_str())
            .chain(relay.service_url_aliases.iter().map(String::as_str));
        if names
            .filter_map(Self::url_host)
            .any(|relay_host| relay_host == host)
        {
            return Err(ServerError::RelayValue(
                "blossom.public_url must be on a different host than the relay \
                 (uploaded HTML/SVG must never run in the relay's origin)"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// `[relay.onion]` — process-wide settings of the embedded onion
/// service (the `onion` cargo feature). Everything but
/// `onion_location` is restart-only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Onion {
    /// Arti state root: `state` (including the onion service
    /// keystores) and `cache` live beneath it. Must be a directory
    /// with mode 0700 owned by the relay user; missing, it is created
    /// with mode 0700.
    pub state_dir: PathBuf,
    /// Concurrent rendezvous circuits per onion listener, including
    /// ones still being established; further introductions are
    /// dropped.
    pub max_circuits: usize,
    /// Arti `max_concurrent_streams_per_circuit`: Arti closes a
    /// circuit whose client opens more streams than this. A client
    /// multiplexes all its streams to the service on one circuit, so
    /// this must cover an ordinary client's connection count.
    pub max_streams_per_circuit: u32,
    /// Introduction rate limit sent to the intro points (Arti
    /// `rate_limit_at_intro`, requests per second). `0` leaves the
    /// network default; then `intro_burst` must be `0` too.
    pub intro_rate: u32,
    /// Introduction burst for `intro_rate`; `0` = unset.
    pub intro_burst: u32,
    /// Advertise the first onion address as `Onion-Location` on
    /// NIP-11, the landing page and upgrade responses of non-onion
    /// listeners (reloadable).
    pub onion_location: bool,
}

impl Onion {
    /// Field rules, checked at load and at reload through
    /// [`Config::limits`].
    fn check(&self) -> Result<(), ServerError> {
        if self.state_dir.as_os_str().is_empty() {
            return Err(ServerError::RelayValue(
                "relay.onion.state_dir must not be empty".to_owned(),
            ));
        }
        if self.max_circuits == 0 {
            return Err(ServerError::RelayValue(
                "relay.onion.max_circuits must be at least 1".to_owned(),
            ));
        }
        if self.max_streams_per_circuit == 0 {
            return Err(ServerError::RelayValue(
                "relay.onion.max_streams_per_circuit must be at least 1".to_owned(),
            ));
        }
        for (key, value) in [
            ("intro_rate", self.intro_rate),
            ("intro_burst", self.intro_burst),
        ] {
            if value > i32::MAX as u32 {
                return Err(ServerError::RelayValue(format!(
                    "relay.onion.{key} must not exceed {}",
                    i32::MAX
                )));
            }
        }
        if (self.intro_rate == 0) != (self.intro_burst == 0) {
            return Err(ServerError::RelayValue(
                "relay.onion.intro_rate and intro_burst must both be 0 (unset) or both at least 1"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// `[relay.iroh]` — process-wide settings of the embedded iroh
/// listeners (the `iroh` cargo feature). Every key is restart-only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Iroh {
    /// Key directory: `<nickname>.key` files, one per `iroh:`
    /// listener, 32 raw bytes each (created mode 0600 on first
    /// start). Must be a directory with mode 0700 owned by the relay
    /// user; missing, it is created with mode 0700.
    pub state_dir: PathBuf,
    /// Which relay servers the endpoints use: `n0` relays, the
    /// operator's own (`relay_urls`), or none (direct paths only).
    pub relay_mode: IrohRelayMode,
    /// `http(s)://` URLs of self-hosted `iroh-relay` servers; required
    /// and only allowed with `relay_mode = "custom"`. With a custom
    /// relay map the dialer adds them to the dial address as hints.
    pub relay_urls: Vec<String>,
    /// How endpoints publish and resolve dialing information: n0's
    /// DNS server, or nothing (`"disabled"`: the dial address then
    /// needs `ip:port` hints).
    pub address_lookup: IrohAddressLookup,
    /// Concurrent QUIC connections per iroh listener, handshakes
    /// included; further `Incoming`s are refused pre-handshake.
    pub max_connections: usize,
    /// The QUIC concurrent bidirectional stream cap offered to peers:
    /// one HTTP/1.1 connection per stream, so a client multiplexes
    /// all its connections on this many streams of one QUIC
    /// connection.
    pub max_streams_per_connection: u32,
}

impl Iroh {
    /// Field rules, checked at load and at reload through
    /// [`Config::limits`].
    fn check(&self) -> Result<(), ServerError> {
        if self.state_dir.as_os_str().is_empty() {
            return Err(ServerError::RelayValue(
                "relay.iroh.state_dir must not be empty".to_owned(),
            ));
        }
        if self.max_connections == 0 {
            return Err(ServerError::RelayValue(
                "relay.iroh.max_connections must be at least 1".to_owned(),
            ));
        }
        if self.max_streams_per_connection == 0 {
            return Err(ServerError::RelayValue(
                "relay.iroh.max_streams_per_connection must be at least 1".to_owned(),
            ));
        }
        let custom = self.relay_mode == IrohRelayMode::Custom;
        if custom == self.relay_urls.is_empty() {
            return Err(ServerError::RelayValue(
                "relay.iroh.relay_urls must be non-empty exactly when \
                 relay_mode = \"custom\""
                    .to_owned(),
            ));
        }
        for url in &self.relay_urls {
            let valid = url::Url::parse(url).is_ok_and(|parsed| {
                matches!(parsed.scheme(), "http" | "https") && parsed.host().is_some()
            });
            if !valid {
                return Err(ServerError::RelayValue(format!(
                    "relay.iroh.relay_urls entry {url:?} must be an http(s):// URL with a host"
                )));
            }
        }
        Ok(())
    }
}

/// `relay.iroh.relay_mode` — which iroh relay servers the endpoints
/// use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IrohRelayMode {
    /// n0's production relay servers.
    #[default]
    N0,
    /// The operator's own `iroh-relay` servers (`relay_urls`).
    Custom,
    /// No relay servers: direct paths only.
    Disabled,
}

/// `relay.iroh.address_lookup` — how the endpoints publish and
/// resolve dialing information.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IrohAddressLookup {
    /// Publish to and resolve from n0's DNS server.
    #[default]
    N0,
    /// No address lookup: dialing needs hints in the dial address.
    Disabled,
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

impl Default for Onion {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("./nosfry-onion"),
            max_circuits: 256,
            max_streams_per_circuit: 128,
            intro_rate: 0,
            intro_burst: 0,
            onion_location: false,
        }
    }
}

impl Default for Iroh {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("./nosfry-iroh"),
            relay_mode: IrohRelayMode::default(),
            relay_urls: Vec::new(),
            address_lookup: IrohAddressLookup::default(),
            max_connections: 256,
            max_streams_per_connection: 128,
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

    /// The relay's canonical name: `service_url`, else the first
    /// derived onion URL, else the first derived iroh URL, or `""`
    /// when the relay has no name at all (AUTH disabled).
    pub fn service_url(&self) -> &str {
        if !self.service_url.is_empty() {
            return &self.service_url;
        }
        if let Some(url) = self.onion_urls.first() {
            return url;
        }
        self.iroh_urls.first().map_or("", String::as_str)
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
            if let ListenAddress::Onion(nickname) = &listen.address
                && !listen.real_ip_header.is_empty()
            {
                return Err(ServerError::RelayValue(format!(
                    "relay.listen: onion listener \"onion:{nickname}\" cannot set \
                     real_ip_header (onion connections carry no client address)"
                )));
            }
            #[cfg(not(feature = "onion"))]
            if let ListenAddress::Onion(nickname) = &listen.address {
                return Err(ServerError::RelayValue(format!(
                    "relay.listen: \"onion:{nickname}\" needs nosfry built with the onion \
                     cargo feature (cargo install nosfry --features onion)"
                )));
            }
            if let ListenAddress::Iroh(nickname) = &listen.address
                && !listen.real_ip_header.is_empty()
            {
                return Err(ServerError::RelayValue(format!(
                    "relay.listen: iroh listener \"iroh:{nickname}\" cannot set \
                     real_ip_header (iroh connections carry no client IP address)"
                )));
            }
            #[cfg(not(feature = "iroh"))]
            if let ListenAddress::Iroh(nickname) = &listen.address {
                return Err(ServerError::RelayValue(format!(
                    "relay.listen: \"iroh:{nickname}\" needs nosfry built with the iroh \
                     cargo feature (cargo install nosfry --features iroh)"
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
            onion: Onion::default(),
            onion_urls: Vec::new(),
            iroh: Iroh::default(),
            iroh_urls: Vec::new(),
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
            access: AccessConfig::default(),
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
    /// profile's `rate_limits`, and `[relay.access]`.
    ///
    /// # Errors
    ///
    /// [`ServerError::ServiceUrl`] on an invalid `[relay] service_url`,
    /// [`ServerError::Admins`] on a malformed
    /// `[relay.management] admins` entry,
    /// [`ServerError::FilterValidation`] on an invalid
    /// `[relay.filter_validation]` value, [`ServerError::RelayValue`]
    /// on `relay.auto_ping_seconds = 0`, an invalid `[[relay.listen]]`
    /// set, or an invalid `[relay.access]` rule.
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
        self.relay.onion.check()?;
        self.blossom.check(&self.relay)?;
        self.relay.iroh.check()?;
        nosfry_core::limits::check_payload_size(
            self.relay.max_websocket_payload_size,
            &self.events,
        )
        .map_err(|e| ServerError::RelayValue(e.to_string()))?;
        // The configured aliases, then the derived onion and iroh
        // URLs — parse dedups, so a canonical derived name is not
        // repeated.
        let aliases: Vec<String> = self
            .relay
            .service_url_aliases
            .iter()
            .chain(&self.relay.onion_urls)
            .chain(&self.relay.iroh_urls)
            .cloned()
            .collect();
        let names = nosfry_core::url::RelayNames::parse(self.relay.service_url(), &aliases)?;
        self.relay
            .management
            .admin_keys()
            .map_err(|e| ServerError::Admins(e.0))?;
        let access = nosfry_core::access::AccessRules::compile(&self.relay.access)
            .map_err(|e| ServerError::RelayValue(format!("relay.access: {e}")))?;
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
            auth: Arc::new(nosfry_core::auth::AuthRules::new(names, access)),
        })
    }

    /// Per-profile session `Limits` for [`crate::Live`]: the shared
    /// limits with each profile's `rate_limits` swapped in. `base`
    /// must already be validated (`Config::limits`).
    pub(crate) fn profile_limits(
        &self,
        base: &Limits,
    ) -> std::collections::HashMap<String, Arc<Limits>> {
        self.relay
            .profiles()
            .iter()
            .map(|(name, profile)| {
                (
                    name.clone(),
                    Arc::new(Limits {
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
    pub(crate) fn admins(&self) -> Result<Arc<[PublicKey]>, ServerError> {
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
    /// `relay.max_pending_outbound_bytes_total`,
    /// `relay.max_subscription_bytes_total` (ditto), every
    /// `[relay.onion]` key but `onion_location`, and all of
    /// `[relay.iroh]`. `relay.onion_urls` and `relay.iroh_urls` are
    /// derived at startup and always carry over.
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
        // `[relay.onion]` is restart-only except `onion_location`;
        // `onion_urls` is derived at startup, never from the file.
        let onion_location = relay.onion.onion_location;
        if (Onion {
            onion_location: running.onion.onion_location,
            ..relay.onion.clone()
        }) != running.onion
        {
            ignored.push("relay.onion");
        }
        relay.onion.clone_from(&running.onion);
        relay.onion.onion_location = onion_location;
        relay.onion_urls.clone_from(&running.onion_urls);
        // `[blossom]` restart-only keys; the live keys follow `new`
        // and reach the blob service through its policy channel.
        #[cfg(feature = "blossom")]
        {
            let blossom = &mut new.blossom;
            let running_blossom = &self.blossom;
            ignored.extend(
                [
                    (
                        "blossom.enabled",
                        blossom.enabled != running_blossom.enabled,
                    ),
                    (
                        "blossom.public_url",
                        blossom.public_url != running_blossom.public_url,
                    ),
                    ("blossom.dir", blossom.dir != running_blossom.dir),
                    (
                        "blossom.max_concurrent_uploads",
                        blossom.max_concurrent_uploads != running_blossom.max_concurrent_uploads,
                    ),
                    (
                        "blossom.max_connections",
                        blossom.max_connections != running_blossom.max_connections,
                    ),
                    ("blossom.listen", blossom.listen != running_blossom.listen),
                ]
                .into_iter()
                .filter_map(|(name, changed)| changed.then_some(name)),
            );
            blossom.enabled = running_blossom.enabled;
            blossom.public_url.clone_from(&running_blossom.public_url);
            blossom.dir.clone_from(&running_blossom.dir);
            blossom.max_concurrent_uploads = running_blossom.max_concurrent_uploads;
            blossom.max_connections = running_blossom.max_connections;
            blossom.listen.clone_from(&running_blossom.listen);
        }
        // `[relay.iroh]` is wholly restart-only; `iroh_urls` is
        // derived at startup and always carries over.
        if relay.iroh != running.iroh {
            ignored.push("relay.iroh");
            relay.iroh.clone_from(&running.iroh);
        }
        relay.iroh_urls.clone_from(&running.iroh_urls);
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

    /// `[blossom]` parses without the feature but `enabled` refuses
    /// (the `relay.listen` `onion:` address gate's precedent).
    #[cfg(not(feature = "blossom"))]
    #[test]
    fn blossom_enabled_needs_feature() {
        let parsed: Config = toml::from_str("[blossom]\nenabled = true\n").unwrap();
        let err = parsed.blossom.check(&parsed.relay).unwrap_err();
        assert!(err.to_string().contains("blossom cargo feature"), "{err}");
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

    /// `onion:<nickname>` address forms: Arti's slug rule, and the
    /// display/parse round-trip.
    #[test]
    fn onion_address_forms() {
        for good in ["a", "nosfry", "relay_1", "a-b_c-9"] {
            let listen = ListenAddress::parse(&format!("onion:{good}")).unwrap();
            assert_eq!(listen.to_string(), format!("onion:{good}"));
        }
        for bad in ["", "-x", "UPPER", "a.b", "a/b", "a+b", "a:b", "x y"] {
            assert!(
                ListenAddress::parse(&format!("onion:{bad}")).is_err(),
                "onion:{bad} must not parse"
            );
        }
        // The generic error text lists every form.
        let err = ListenAddress::parse("nope").unwrap_err();
        assert!(err.contains("onion:<nickname>"), "{err}");
    }

    /// An onion listener cannot set `real_ip_header`: circuits carry
    /// no client address, so the header would be silently ignored.
    #[test]
    fn onion_listener_refuses_real_ip_header() {
        let mut config = Config::default();
        config.relay.listen = vec![Listen {
            address: ListenAddress::Onion("x".to_owned()),
            profile: "default".to_owned(),
            real_ip_header: "X-Forwarded-For".to_owned(),
        }];
        let err = config.limits().unwrap_err().to_string();
        assert!(err.contains("real_ip_header"), "{err}");
    }

    /// Builds without the `onion` feature refuse an onion listener
    /// with a message naming the feature, at load and at reload
    /// (both go through `limits()`).
    #[cfg(not(feature = "onion"))]
    #[test]
    fn onion_listener_needs_the_feature() {
        let mut config = Config::default();
        config.relay.listen = vec![Listen {
            address: ListenAddress::Onion("x".to_owned()),
            profile: "default".to_owned(),
            real_ip_header: String::new(),
        }];
        let err = config.limits().unwrap_err().to_string();
        assert!(err.contains("onion") && err.contains("feature"), "{err}");
    }

    /// Every `[relay.onion]` rule is enforced through `limits()`,
    /// which the load and reload paths share.
    #[test]
    fn onion_settings_validate() {
        let mut config = Config::default();
        config.relay.onion.state_dir = PathBuf::new();
        assert!(config.limits().is_err());

        config.relay.onion = Onion {
            max_circuits: 0,
            ..Onion::default()
        };
        assert!(config.limits().is_err());

        config.relay.onion = Onion {
            max_streams_per_circuit: 0,
            ..Onion::default()
        };
        assert!(config.limits().is_err());

        for (rate, burst) in [(1, 0), (0, 1)] {
            config.relay.onion = Onion {
                intro_rate: rate,
                intro_burst: burst,
                ..Onion::default()
            };
            assert!(config.limits().is_err(), "rate {rate} burst {burst}");
        }

        config.relay.onion = Onion {
            intro_rate: i32::MAX as u32 + 1,
            intro_burst: 1,
            ..Onion::default()
        };
        assert!(config.limits().is_err());
    }

    /// The first derived onion URL is canonical with no
    /// `service_url`; with one it joins the aliases.
    #[test]
    fn onion_urls_name_the_relay() {
        let mut config = Config::default();
        config.relay.onion_urls = vec!["ws://aaa.onion".into(), "ws://bbb.onion".into()];
        assert_eq!(config.relay.service_url(), "ws://aaa.onion");
        let limits = config.limits().unwrap();
        assert!(limits.auth.names().matches("ws://aaa.onion"));
        assert!(limits.auth.names().matches("ws://bbb.onion"));

        config.relay.service_url = "wss://relay.example.com".into();
        let limits_named = config.limits().unwrap();
        assert!(limits_named.auth.names().matches("wss://relay.example.com"));
        assert!(limits_named.auth.names().matches("ws://aaa.onion"));
    }

    /// `onion_location` reloads; every other `[relay.onion]` key is
    /// restart-only, and `onion_urls` always carries over.
    #[test]
    fn reload_keeps_onion_settings() {
        let mut running = Config::default();
        running.relay.onion.max_circuits = 64;
        running.relay.onion_urls = vec!["ws://aaa.onion".into()];
        let mut new = Config::default();
        new.relay.onion.max_circuits = 128;
        new.relay.onion.onion_location = true;
        let (merged, ignored) = running.reloadable_from(new);
        assert!(ignored.contains(&"relay.onion"), "{ignored:?}");
        assert_eq!(merged.relay.onion.max_circuits, 64);
        assert!(merged.relay.onion.onion_location);
        assert_eq!(merged.relay.onion_urls, vec!["ws://aaa.onion"]);

        // Only `onion_location` differing does not report the table.
        let mut changed = running.clone();
        changed.relay.onion.onion_location = true;
        let (merged2, ignored2) = running.reloadable_from(changed);
        assert!(!ignored2.contains(&"relay.onion"), "{ignored2:?}");
        assert!(merged2.relay.onion.onion_location);
    }

    /// `iroh:<nickname>` address forms: the shared slug rule, and
    /// the display/parse round-trip.
    #[test]
    fn iroh_address_forms() {
        for good in ["a", "nosfry", "relay_1", "a-b_c-9"] {
            let listen = ListenAddress::parse(&format!("iroh:{good}")).unwrap();
            assert_eq!(listen.to_string(), format!("iroh:{good}"));
        }
        for bad in ["", "-x", "UPPER", "a.b", "a/b", "a+b", "a:b", "x y"] {
            assert!(
                ListenAddress::parse(&format!("iroh:{bad}")).is_err(),
                "iroh:{bad} must not parse"
            );
        }
        // The generic error text lists every form.
        let err = ListenAddress::parse("nope").unwrap_err();
        assert!(err.contains("iroh:<nickname>"), "{err}");
    }

    /// An iroh listener cannot set `real_ip_header`: QUIC connections
    /// carry no client IP address the limiter could trust, so the
    /// header would be silently ignored.
    #[test]
    fn iroh_listener_refuses_real_ip_header() {
        let mut config = Config::default();
        config.relay.listen = vec![Listen {
            address: ListenAddress::Iroh("x".to_owned()),
            profile: "default".to_owned(),
            real_ip_header: "X-Forwarded-For".to_owned(),
        }];
        let err = config.limits().unwrap_err().to_string();
        assert!(err.contains("real_ip_header"), "{err}");
    }

    /// Builds without the `iroh` feature refuse an iroh listener
    /// with a message naming the feature, at load and at reload
    /// (both go through `limits()`).
    #[cfg(not(feature = "iroh"))]
    #[test]
    fn iroh_listener_needs_the_feature() {
        let mut config = Config::default();
        config.relay.listen = vec![Listen {
            address: ListenAddress::Iroh("x".to_owned()),
            profile: "default".to_owned(),
            real_ip_header: String::new(),
        }];
        let err = config.limits().unwrap_err().to_string();
        assert!(err.contains("iroh") && err.contains("feature"), "{err}");
    }

    /// Every `[relay.iroh]` rule is enforced through `limits()`,
    /// which the load and reload paths share.
    #[test]
    fn iroh_settings_validate() {
        let mut config = Config::default();
        config.relay.iroh.state_dir = PathBuf::new();
        assert!(config.limits().is_err());

        config.relay.iroh = Iroh {
            max_connections: 0,
            ..Iroh::default()
        };
        assert!(config.limits().is_err());

        config.relay.iroh = Iroh {
            max_streams_per_connection: 0,
            ..Iroh::default()
        };
        assert!(config.limits().is_err());

        // `relay_urls` only with `relay_mode = "custom"`.
        config.relay.iroh = Iroh {
            relay_mode: IrohRelayMode::Custom,
            relay_urls: Vec::new(),
            ..Iroh::default()
        };
        assert!(config.limits().is_err());
        config.relay.iroh = Iroh {
            relay_mode: IrohRelayMode::N0,
            relay_urls: vec!["https://relay.example.com".into()],
            ..Iroh::default()
        };
        assert!(config.limits().is_err());
        config.relay.iroh = Iroh {
            relay_mode: IrohRelayMode::Disabled,
            relay_urls: vec!["https://relay.example.com".into()],
            ..Iroh::default()
        };
        assert!(config.limits().is_err());

        // Entries must be http(s) URLs with a host.
        for bad in [
            "not-a-url",
            "ftp://relay.example.com",
            "ws://relay.example.com",
        ] {
            config.relay.iroh = Iroh {
                relay_mode: IrohRelayMode::Custom,
                relay_urls: vec![bad.into()],
                ..Iroh::default()
            };
            assert!(config.limits().is_err(), "{bad}");
        }
        config.relay.iroh = Iroh {
            relay_mode: IrohRelayMode::Custom,
            relay_urls: vec![
                "https://relay.example.com".into(),
                "http://127.0.0.1:3340".into(),
            ],
            ..Iroh::default()
        };
        config.limits().expect("custom relay map validates");
    }

    /// `relay_mode`/`address_lookup` parse as the lowercase strings.
    #[test]
    fn iroh_mode_strings_parse() {
        let config: Config = toml::from_str(
            "[relay.iroh]\nrelay_mode = \"custom\"\nrelay_urls = [\"https://r.example.com\"]\n\
             address_lookup = \"disabled\"\n",
        )
        .unwrap();
        assert_eq!(config.relay.iroh.relay_mode, IrohRelayMode::Custom);
        assert_eq!(
            config.relay.iroh.address_lookup,
            IrohAddressLookup::Disabled
        );
        assert!(toml::from_str::<Config>("[relay.iroh]\nrelay_mode = \"bogus\"\n").is_err());
        assert!(toml::from_str::<Config>("[relay.iroh]\naddress_lookup = \"bogus\"\n").is_err());
    }

    /// With no `service_url` and no onion URL the first iroh URL is
    /// canonical; with a `service_url` it joins the aliases.
    #[test]
    fn iroh_urls_name_the_relay() {
        let mut config = Config::default();
        config.relay.iroh_urls = vec![
            format!("ws://{}.iroh", "a".repeat(52)),
            format!("ws://{}.iroh", "b".repeat(52)),
        ];
        assert_eq!(
            config.relay.service_url(),
            format!("ws://{}.iroh", "a".repeat(52))
        );
        let limits = config.limits().unwrap();
        assert!(
            limits
                .auth
                .names()
                .matches(&format!("ws://{}.iroh", "a".repeat(52)))
        );
        assert!(
            limits
                .auth
                .names()
                .matches(&format!("ws://{}.iroh", "b".repeat(52)))
        );

        config.relay.service_url = "wss://relay.example.com".into();
        let limits_named = config.limits().unwrap();
        assert!(limits_named.auth.names().matches("wss://relay.example.com"));
        assert!(
            limits_named
                .auth
                .names()
                .matches(&format!("ws://{}.iroh", "a".repeat(52)))
        );
    }

    /// An onion URL outranks an iroh URL for the canonical name.
    #[test]
    fn onion_url_outranks_iroh_for_service_url() {
        let mut config = Config::default();
        config.relay.onion_urls = vec!["ws://aaa.onion".into()];
        config.relay.iroh_urls = vec![format!("ws://{}.iroh", "a".repeat(52))];
        assert_eq!(config.relay.service_url(), "ws://aaa.onion");
    }

    /// The whole `[relay.iroh]` table is restart-only and `iroh_urls`
    /// always carries over.
    #[test]
    fn reload_keeps_iroh_settings() {
        let mut running = Config::default();
        running.relay.iroh.max_connections = 64;
        running.relay.iroh_urls = vec![format!("ws://{}.iroh", "a".repeat(52))];
        let mut new = Config::default();
        new.relay.iroh.max_connections = 128;
        new.relay.iroh.relay_mode = IrohRelayMode::Disabled;
        let (merged, ignored) = running.reloadable_from(new);
        assert!(ignored.contains(&"relay.iroh"), "{ignored:?}");
        assert_eq!(merged.relay.iroh.max_connections, 64);
        assert_eq!(merged.relay.iroh.relay_mode, IrohRelayMode::N0);
        assert_eq!(
            merged.relay.iroh_urls,
            vec![format!("ws://{}.iroh", "a".repeat(52))]
        );
    }
}
