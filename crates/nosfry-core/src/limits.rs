//! Relay resource limits (strfry-compatible defaults).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use serde::Deserialize;

use crate::auth::AuthRules;
use crate::event::EventLimits;
use crate::filter::Filter;

/// REQ-side limits: filter shape and subscription count. All fields
/// carry strfry's defaults and unknown keys are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReqLimits {
    /// Maximum number of filters in a single REQ.
    pub max_req_filter_size: usize,
    /// Maximum concurrently open subscriptions per connection.
    pub max_subs_per_connection: usize,
    /// Cap applied to a filter's `limit` when serving stored events.
    pub max_filter_limit: u64,
    /// Cap on index entries a `COUNT` scan may examine; `0` disables
    /// `COUNT` entirely. The count itself is never capped — hitting
    /// the budget marks the answer `"approximate": true`.
    pub max_filter_limit_count: u64,
    /// Maximum number of stored events a `NEG-OPEN` sync may hold;
    /// `0` disables negentropy sync entirely. The filter's own `limit`
    /// applies inside this cap; over it the sync is refused.
    pub max_sync_events: u64,
    /// Maximum number of `#x` tag conditions allowed per filter.
    pub max_tags_per_filter: usize,
    /// Effective filter-validation rules; `None` when
    /// `[relay.filter_validation] enabled` is false. Configured via
    /// [`FilterValidationConfig`] — it has no `[relay.limits]` key.
    #[serde(skip)]
    pub filter_validation: Option<FilterValidation>,
}

impl Default for ReqLimits {
    fn default() -> Self {
        Self {
            max_req_filter_size: 200,
            max_subs_per_connection: 200,
            max_filter_limit: 500,
            max_filter_limit_count: 1_000_000,
            max_sync_events: 1_000_000,
            max_tags_per_filter: 3,
            filter_validation: None,
        }
    }
}

/// `[relay.filter_validation]` — strfry `relay.filterValidation`
/// parity. `enabled = false` disables every check;
/// [`FilterValidationConfig::limits`] turns the section into the
/// effective [`FilterValidation`] (or `None`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterValidationConfig {
    /// Enforce the rules on REQ and `COUNT` (`NEG-OPEN` is exempt).
    pub enabled: bool,
    /// Filters allowed in one REQ, inclusive.
    pub max_filters_per_req: usize,
    /// Filters required in one REQ, inclusive.
    pub min_filters_per_req: usize,
    /// Kinds allowed per filter.
    pub max_kinds_per_filter: usize,
    /// Kinds a filter may list; empty allows every kind. When
    /// non-empty a filter without a `kinds` key is refused — a
    /// deliberate deviation from strfry, which lets it match every
    /// kind.
    pub allowed_kinds: Vec<u16>,
    /// Require each filter to pin exactly one `authors` entry or
    /// exactly one `#p`/`#e` value.
    pub require_author_or_tag: bool,
}

impl Default for FilterValidationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_filters_per_req: 3,
            min_filters_per_req: 1,
            max_kinds_per_filter: 3,
            allowed_kinds: Vec::new(),
            require_author_or_tag: false,
        }
    }
}

/// The effective filter-validation rules a session enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterValidation {
    /// Filters allowed in one REQ, inclusive.
    pub max_filters_per_req: usize,
    /// Filters required in one REQ, inclusive.
    pub min_filters_per_req: usize,
    /// Kinds allowed per filter.
    pub max_kinds_per_filter: usize,
    /// Kinds a filter may list; empty allows every kind.
    pub allowed_kinds: BTreeSet<u16>,
    /// Require exactly one `authors`/`#p`/`#e` value per filter.
    pub require_author_or_tag: bool,
}

impl FilterValidationConfig {
    /// The effective rules, or `None` when disabled.
    ///
    /// # Errors
    ///
    /// [`FilterValidationError`] naming the offending key when
    /// `enabled` and `max_filters_per_req` is 0 or
    /// `min_filters_per_req` exceeds it.
    pub fn limits(&self) -> Result<Option<FilterValidation>, FilterValidationError> {
        if !self.enabled {
            return Ok(None);
        }
        if self.max_filters_per_req == 0 {
            return Err(FilterValidationError(
                "max_filters_per_req must be at least 1",
            ));
        }
        if self.min_filters_per_req > self.max_filters_per_req {
            return Err(FilterValidationError(
                "min_filters_per_req must not exceed max_filters_per_req",
            ));
        }
        Ok(Some(FilterValidation {
            max_filters_per_req: self.max_filters_per_req,
            min_filters_per_req: self.min_filters_per_req,
            max_kinds_per_filter: self.max_kinds_per_filter,
            allowed_kinds: self.allowed_kinds.iter().copied().collect(),
            require_author_or_tag: self.require_author_or_tag,
        }))
    }
}

impl FilterValidation {
    /// The first violation `filters` commit — the `CLOSED` detail
    /// after the `blocked:` prefix — or `None` when they all pass.
    /// Enforced on REQ and `COUNT`; `NEG-OPEN` is exempt.
    #[must_use]
    pub fn violation(&self, filters: &[Filter]) -> Option<String> {
        if filters.len() < self.min_filters_per_req || filters.len() > self.max_filters_per_req {
            return Some(format!("invalid number of filters: {}", filters.len()));
        }
        filters
            .iter()
            .find_map(|filter| self.filter_violation(filter))
    }

    /// The first violation one filter commits, in strfry's check
    /// order: kinds count, allowed kinds, author/tag requirement.
    fn filter_violation(&self, filter: &Filter) -> Option<String> {
        match filter.kinds() {
            Some(kinds) => {
                if kinds.len() > self.max_kinds_per_filter {
                    return Some(format!("too many kinds in filter: {}", kinds.len()));
                }
                if !self.allowed_kinds.is_empty()
                    && let Some(kind) = kinds.iter().find(|k| !self.allowed_kinds.contains(k))
                {
                    return Some(format!("kind not allowed: {kind}"));
                }
            }
            None if !self.allowed_kinds.is_empty() => {
                return Some("filter must list kinds".to_owned());
            }
            None => {}
        }
        if self.require_author_or_tag {
            let pinned = filter.authors().is_some_and(|a| a.len() == 1)
                || filter.tag_values(b'p').is_some_and(|v| v.len() == 1)
                || filter.tag_values(b'e').is_some_and(|v| v.len() == 1);
            if !pinned {
                return Some("filter must have exactly one author, p tag, or e tag".to_owned());
            }
        }
        None
    }
}

/// `FilterValidationConfig::limits` failure. The payload completes
/// the `relay.filter_validation.` prefix into a sentence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("relay.filter_validation.{0}")]
pub struct FilterValidationError(pub &'static str);

/// Per-connection token-bucket rate limits for EVENT and REQ messages,
/// plus shared per-address buckets the adapter hands to every session
/// of one client address. A `*_per_second` of 0 disables that bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimits {
    /// EVENT messages accepted per second, sustained.
    pub events_per_second: u32,
    /// EVENT burst capacity: the bucket starts full and refills at
    /// `events_per_second`.
    pub events_burst: u32,
    /// REQ messages accepted per second, sustained.
    pub reqs_per_second: u32,
    /// REQ burst capacity.
    pub reqs_burst: u32,
    /// EVENT messages accepted per second across every connection of
    /// one client address.
    pub ip_events_per_second: u32,
    /// Shared EVENT burst capacity per client address.
    pub ip_events_burst: u32,
    /// REQ messages accepted per second across every connection of
    /// one client address.
    pub ip_reqs_per_second: u32,
    /// Shared REQ burst capacity per client address.
    pub ip_reqs_burst: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            events_per_second: 20,
            events_burst: 100,
            reqs_per_second: 20,
            reqs_burst: 100,
            ip_events_per_second: 100,
            ip_events_burst: 500,
            ip_reqs_per_second: 100,
            ip_reqs_burst: 500,
        }
    }
}

/// Per-address grouping key for connection caps and rate buckets.
///
/// IPv4 as-is, IPv4-mapped IPv6 folded to its IPv4, other IPv6
/// grouped by /64 — one subscriber typically owns a whole /64, so
/// per-address caps there are trivially bypassed. The NIP-86 IP
/// block list keeps exact addresses; this key is only for caps and
/// buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressKey {
    /// IPv4 address bits.
    V4(u32),
    /// First 64 bits of the IPv6 address.
    V6(u64),
}

impl From<IpAddr> for AddressKey {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(u32::from(v4)),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
                || Self::V6((u128::from(v6) >> 64) as u64),
                |v4| Self::V4(u32::from(v4)),
            ),
        }
    }
}

/// Token buckets shared by every connection of one client address
/// (built from the `ip_*` rate limits). A `None` bucket is disabled;
/// `Default` gives a fully disabled pair.
#[derive(Debug, Default)]
pub struct AddressBuckets {
    events: Option<Mutex<TokenBucket>>,
    reqs: Option<Mutex<TokenBucket>>,
}

impl AddressBuckets {
    /// Buckets for the shared `ip_*` limits of `rate`.
    #[must_use]
    pub fn new(rate: &RateLimits) -> Self {
        Self {
            events: (rate.ip_events_per_second > 0).then(|| {
                Mutex::new(TokenBucket::new(
                    rate.ip_events_per_second,
                    rate.ip_events_burst,
                ))
            }),
            reqs: (rate.ip_reqs_per_second > 0).then(|| {
                Mutex::new(TokenBucket::new(
                    rate.ip_reqs_per_second,
                    rate.ip_reqs_burst,
                ))
            }),
        }
    }

    /// Spend one shared EVENT token at `now_ms`; `true` when the
    /// bucket is disabled.
    pub fn take_event(&self, now_ms: u64) -> bool {
        self.events.as_ref().is_none_or(|bucket| {
            bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(now_ms)
        })
    }

    /// Spend one shared REQ token at `now_ms`; `true` when the
    /// bucket is disabled.
    pub fn take_req(&self, now_ms: u64) -> bool {
        self.reqs.as_ref().is_none_or(|bucket| {
            bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(now_ms)
        })
    }

    /// Every enabled bucket is back at full capacity (disabled buckets
    /// count as full): an address with no live connections has cooled
    /// off, and dropping its state cannot grant a fresh burst.
    pub fn is_idle(&self, now_ms: u64) -> bool {
        self.events.as_ref().is_none_or(|bucket| {
            bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_full(now_ms)
        }) && self.reqs.as_ref().is_none_or(|bucket| {
            bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_full(now_ms)
        })
    }
}

/// A token bucket in milli-tokens (1 token = 1000 milli-tokens) so a
/// sub-token refill per millisecond needs no floats. Starts full; a
/// clock that goes backwards refills nothing.
#[derive(Debug, Clone)]
pub(crate) struct TokenBucket {
    /// Milli-tokens refilled per elapsed millisecond (= rate per second).
    refill_ms: u64,
    /// Bucket capacity in milli-tokens (= burst * 1000).
    capacity: u64,
    /// Current balance in milli-tokens.
    tokens: u64,
    /// Timestamp of the last refill, unix milliseconds.
    last_ms: u64,
}

impl TokenBucket {
    /// A full bucket of `burst` tokens refilling at `per_second`.
    /// `per_second` of 0 means "disabled" and is the caller's job.
    pub(crate) fn new(per_second: u32, burst: u32) -> Self {
        Self {
            refill_ms: u64::from(per_second),
            capacity: u64::from(burst) * 1000,
            tokens: u64::from(burst) * 1000,
            last_ms: 0,
        }
    }

    /// Whether the balance plus the refill accrued since `last_ms`
    /// reaches capacity; a clock that goes backwards refills nothing.
    /// Does not mutate.
    pub(crate) const fn is_full(&self, now_ms: u64) -> bool {
        let refill = now_ms
            .saturating_sub(self.last_ms)
            .saturating_mul(self.refill_ms);
        self.tokens.saturating_add(refill) >= self.capacity
    }

    /// Spend one token at `now_ms`; `false` when the bucket is empty.
    pub(crate) fn take(&mut self, now_ms: u64) -> bool {
        if now_ms > self.last_ms {
            let refill = (now_ms - self.last_ms).saturating_mul(self.refill_ms);
            self.tokens = self.capacity.min(self.tokens.saturating_add(refill));
            self.last_ms = now_ms;
        }
        if self.tokens < 1000 {
            return false;
        }
        self.tokens -= 1000;
        true
    }
}

/// The limits a session enforces: ingest ([`EventLimits`]), REQ-side
/// ([`ReqLimits`]), per-connection rate limits ([`RateLimits`]), and
/// authentication rules ([`AuthRules`]).
#[derive(Debug, Clone, Default)]
pub struct Limits {
    /// Event acceptance limits (structure plus `created_at` windows).
    pub event: EventLimits,
    /// REQ limits.
    pub req: ReqLimits,
    /// Per-connection and per-address EVENT/REQ rate limits.
    pub rate: RateLimits,
    /// NIP-42 authentication and read restriction.
    pub auth: Arc<AuthRules>,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;

    #[test]
    fn bucket_burst_exhausts_then_refills() {
        let mut bucket = TokenBucket::new(10, 3);
        assert!(bucket.take(0));
        assert!(bucket.take(0));
        assert!(bucket.take(0));
        assert!(!bucket.take(0), "burst of 3 is exhausted in one instant");
        // +1000 ms at 10 tokens/s refills back to the capacity of 3.
        assert!(bucket.take(1_000));
        assert!(bucket.take(1_000));
        assert!(bucket.take(1_000));
        assert!(!bucket.take(1_000));
    }

    #[test]
    fn bucket_partial_refill() {
        let mut bucket = TokenBucket::new(10, 2);
        assert!(bucket.take(0) && bucket.take(0));
        // 150 ms -> 1.5 tokens: one take succeeds, one fails.
        assert!(bucket.take(150));
        assert!(!bucket.take(150));
    }

    #[test]
    fn address_key_groups_addresses() {
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        assert_eq!(AddressKey::from(v4), AddressKey::V4(0xcb00_7107));
        assert_eq!(
            AddressKey::from(mapped),
            AddressKey::from(v4),
            "v4-mapped v6 folds to v4"
        );
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::ffff:abcd".parse().unwrap();
        let c: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        assert_eq!(AddressKey::from(a), AddressKey::from(b), "same /64");
        assert_ne!(AddressKey::from(a), AddressKey::from(c), "different /64");
    }

    #[test]
    fn bucket_saturates_at_capacity() {
        let mut bucket = TokenBucket::new(1_000, 5);
        assert!(bucket.take(0));
        // A huge jump refills no more than the burst capacity of 5.
        let later = u64::MAX / 2;
        for _ in 0..5 {
            assert!(bucket.take(later));
        }
        assert!(!bucket.take(later));
    }

    #[test]
    fn bucket_is_full_only_at_capacity() {
        let mut bucket = TokenBucket::new(10, 3);
        assert!(bucket.is_full(0), "a fresh bucket is full");
        assert!(bucket.take(0));
        assert!(!bucket.is_full(0));
        assert!(!bucket.is_full(99), "0.99 of a token is not full");
        assert!(bucket.is_full(100), "one token refilled in 100 ms");
        // `is_full` does not mutate: a second check agrees.
        assert!(bucket.is_full(100));
    }

    /// `is_idle` is true only when every enabled bucket refilled;
    /// disabled buckets count as full.
    #[test]
    fn address_buckets_is_idle() {
        assert!(AddressBuckets::default().is_idle(0));
        let rate = RateLimits {
            events_per_second: 0,
            events_burst: 0,
            reqs_per_second: 0,
            reqs_burst: 0,
            ip_events_per_second: 1,
            ip_events_burst: 2,
            ip_reqs_per_second: 0,
            ip_reqs_burst: 0,
        };
        let buckets = AddressBuckets::new(&rate);
        assert!(buckets.is_idle(0), "fresh buckets are full");
        assert!(buckets.take_event(0));
        assert!(!buckets.is_idle(0));
        assert!(buckets.is_idle(2_000), "2 tokens at 1/s: idle after 2 s");
    }

    #[test]
    fn bucket_backwards_clock_refills_nothing() {
        let mut bucket = TokenBucket::new(10, 1);
        assert!(bucket.take(5_000));
        // Going backwards grants no refill and does not rewind `last`.
        assert!(!bucket.take(1_000));
        // Nor does the same timestamp.
        assert!(!bucket.take(5_000));
        assert!(bucket.take(6_000));
    }

    #[test]
    fn rate_limits_deserialize_defaults() {
        let limits: RateLimits = serde_json::from_str("{}").unwrap();
        assert_eq!(limits, RateLimits::default());
        let custom: RateLimits =
            serde_json::from_str("{\"events_per_second\":0,\"reqs_burst\":5}").unwrap();
        assert_eq!(custom.events_per_second, 0);
        assert_eq!(custom.reqs_per_second, 20);
        assert_eq!(custom.reqs_burst, 5);
        assert!(serde_json::from_str::<RateLimits>("{\"bogus\":1}").is_err());
    }
}
