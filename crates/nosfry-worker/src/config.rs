//! TOML configuration: the native `[relay]`/`[events]` keys Workers
//! keeps, plus the `[worker]` section.

use nosfry_core::auth::{AuthConfig, AuthRules};
use nosfry_core::event::EventLimits;
use nosfry_core::info::Info;
use nosfry_core::limits::{
    FilterValidationConfig, FilterValidationError, Limits, RateLimits, ReqLimits,
};
use nosfry_core::management::{AdminsError, ManagementConfig};
use nosfry_core::url::RelayUrlError;
use serde::Deserialize;

/// The `NOSFRY_CONFIG` document. Every section rejects unknown keys,
/// so native-only keys (`bind`, `port`, `db`, `threads`, …) fail
/// fast instead of being silently ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Event acceptance limits (`nosfry_core::event::EventLimits` verbatim).
    pub events: EventLimits,
    /// Relay behaviour section.
    pub relay: Relay,
    /// Workers platform section.
    pub worker: Worker,
}

/// `[relay]` — the subset of the native relay section Workers keeps.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Relay {
    /// The relay's canonical `ws://`/`wss://` URL clients sign into an
    /// AUTH event's `relay` tag. Empty disables AUTH: restricted
    /// kinds are refused on write and never served, and protected
    /// events are rejected.
    pub service_url: String,
    /// Maximum inbound WebSocket payload in bytes.
    pub max_websocket_payload_size: usize,
    /// Maximum simultaneous WebSocket connections (0 = unlimited).
    /// Workers keeps a tighter default than native's 0 because a
    /// Durable Object serializes all of them on one thread.
    pub max_connections: usize,
    /// Maximum simultaneous connections from one client address
    /// (0 = unlimited), the native default.
    pub max_connections_per_ip: usize,
    /// REQ limits (`nosfry_core::limits::ReqLimits` verbatim).
    pub limits: ReqLimits,
    /// REQ/COUNT filter-validation rules
    /// (`nosfry_core::limits::FilterValidationConfig` verbatim).
    pub filter_validation: FilterValidationConfig,
    /// Per-connection EVENT/REQ rate limits
    /// (`nosfry_core::limits::RateLimits` verbatim).
    pub rate_limits: RateLimits,
    /// NIP-42 authentication and restricted read kinds.
    pub auth: AuthConfig,
    /// NIP-86 management API.
    pub management: ManagementConfig,
    /// The write-policy service binding's knobs. There is no
    /// `plugin` on Workers — the `POLICY` binding's presence decides
    /// whether a policy runs.
    pub write_policy: WritePolicy,
    /// Process-wide budget for sealed negentropy sync storages,
    /// `0` = unlimited. Workers keeps a tighter default than native
    /// because a Durable Object holds all of them on one isolate.
    pub max_sync_memory_bytes: usize,
    /// NIP-11 relay information.
    pub info: Info,
}

/// `[relay.write_policy]` — strfry write-policy settings Workers
/// keeps; `plugin` stays unknown (no child processes on Workers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WritePolicy {
    /// Seconds the policy has to answer each request.
    pub timeout_seconds: u64,
}

impl Default for WritePolicy {
    fn default() -> Self {
        Self {
            timeout_seconds: 10,
        }
    }
}

/// `[worker]` — Workers platform knobs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Worker {
    /// Durable Object `locationHint`; empty = none.
    pub location_hint: String,
    /// Per-REQ index-row budget, the Workers substitute for native
    /// time slicing (one thread cannot yield inside a message). It
    /// also bounds a `COUNT` scan together with `[relay.limits]
    /// max_filter_limit_count`: the effective COUNT budget is their
    /// minimum, `0` disabling COUNT entirely.
    pub max_scan_rows: usize,
    /// Process-wide budget for live subscriptions, charged as the
    /// `Filter::approx_bytes` sum of each subscription's filters —
    /// the same estimate the native `[relay]
    /// max_subscription_bytes_total` uses (`0` = unlimited).
    /// `max_connections` × `max_subs_per_connection` × payload-sized
    /// filters would far exceed an isolate's memory, so a REQ that
    /// would cross the budget answers `blocked: subscription
    /// capacity exhausted`.
    pub max_subscription_bytes: usize,
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            service_url: String::new(),
            max_websocket_payload_size: 131_072,
            max_connections: 5_000,
            max_connections_per_ip: 128,
            limits: ReqLimits::default(),
            filter_validation: FilterValidationConfig::default(),
            rate_limits: RateLimits::default(),
            auth: AuthConfig::default(),
            management: ManagementConfig::default(),
            write_policy: WritePolicy::default(),
            max_sync_memory_bytes: 33_554_432,
            info: Info::default(),
        }
    }
}

impl Default for Worker {
    fn default() -> Self {
        Self {
            location_hint: String::new(),
            max_scan_rows: 100_000,
            max_subscription_bytes: 33_554_432,
        }
    }
}

/// Configuration failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// TOML syntax error or an unknown key.
    #[error("config: {0}")]
    Toml(#[from] toml::de::Error),
    /// `[relay] service_url` is not a `ws://`/`wss://` URL.
    #[error(transparent)]
    ServiceUrl(#[from] RelayUrlError),
    /// `[worker] max_scan_rows` is 0 — every REQ/COUNT would return
    /// nothing, so the configuration is refused.
    #[error("[worker] max_scan_rows must be at least 1")]
    MaxScanRows,
    /// A malformed `[relay.management] admins` entry.
    #[error(transparent)]
    Admins(#[from] AdminsError),
    /// An invalid `[relay.info]` value.
    #[error(transparent)]
    Info(#[from] nosfry_core::info::InfoError),
    /// An invalid `[relay.filter_validation]` value.
    #[error(transparent)]
    FilterValidation(#[from] FilterValidationError),
    /// `[relay] max_websocket_payload_size` cannot carry the largest
    /// allowed EVENT frame.
    #[error(transparent)]
    PayloadTooSmall(#[from] nosfry_core::limits::PayloadTooSmall),
}

impl Config {
    /// Parse a TOML document.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Toml`] on syntax errors or unknown keys,
    /// [`ConfigError::ServiceUrl`] on an invalid
    /// `[relay] service_url`, [`ConfigError::MaxScanRows`] when
    /// `[worker] max_scan_rows` is 0, [`ConfigError::Admins`] on a
    /// malformed `[relay.management] admins` entry,
    /// [`ConfigError::Info`] on an invalid `[relay.info]` value,
    /// [`ConfigError::FilterValidation`] on an invalid
    /// `[relay.filter_validation]` value.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.limits()?;
        if config.worker.max_scan_rows == 0 {
            return Err(ConfigError::MaxScanRows);
        }
        config.relay.management.admin_keys()?;
        config.relay.info.validate()?;
        Ok(config)
    }

    /// `nosfry_core::limits::Limits` assembled from `[events]`,
    /// `[relay.limits]`, `[relay.filter_validation]`,
    /// `[relay.rate_limits]`, and `[relay.auth]`. `max_sync_events`
    /// reaches the session verbatim; the effective sync event cap is
    /// its minimum with `[worker] max_scan_rows`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ServiceUrl`] on an invalid
    /// `[relay] service_url`, [`ConfigError::FilterValidation`] on an
    /// invalid `[relay.filter_validation]` value.
    pub fn limits(&self) -> Result<Limits, ConfigError> {
        nosfry_core::limits::check_payload_size(
            self.relay.max_websocket_payload_size,
            &self.events,
        )?;
        Ok(Limits {
            event: self.events,
            req: ReqLimits {
                filter_validation: self.relay.filter_validation.limits()?,
                ..self.relay.limits.clone()
            },
            rate: self.relay.rate_limits,
            auth: self.auth_rules()?,
        })
    }

    /// The shared `AuthRules` from `service_url`, the restricted
    /// kinds, and the involved-only setting.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ServiceUrl`] on an invalid
    /// `[relay] service_url`.
    pub fn auth_rules(&self) -> Result<std::sync::Arc<AuthRules>, ConfigError> {
        let service_url = if self.relay.service_url.is_empty() {
            None
        } else {
            Some(nosfry_core::url::RelayUrl::parse(&self.relay.service_url)?)
        };
        Ok(std::sync::Arc::new(AuthRules::new(
            service_url,
            &self.relay.auth.restricted_read_kinds,
            self.relay.auth.restrict_read_to_involved,
        )))
    }
}
