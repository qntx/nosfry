//! Connection caps: a global count plus a per-client-IP count, and the
//! shared per-address rate-limit buckets handed to each session.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use nosfry_core::limits::{AddressBuckets, AddressKey, RateLimits};

/// Unix time in milliseconds for bucket idle checks (only on the
/// release and sweep paths, never per message).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

/// One tracked client address: its live connection count plus the
/// rate-limit buckets every one of its sessions shares.
#[derive(Debug)]
struct IpEntry {
    count: usize,
    buckets: Arc<AddressBuckets>,
}

/// Caps on simultaneous connections, shared by every accepted socket.
/// A cap of 0 means unlimited for that dimension. Both caps are
/// atomics so a config reload updates them for every connection at
/// once; connections already above a lowered cap are not closed.
#[derive(Debug)]
pub(crate) struct ConnectionLimiter {
    /// Live connections, counted even when `max_total` is unlimited.
    total: AtomicUsize,
    /// Live connections and shared rate-limit buckets per IP key;
    /// populated only when `max_per_ip` or any `ip_*` bucket is
    /// enabled.
    per_ip: Mutex<HashMap<AddressKey, IpEntry, foldhash::fast::RandomState>>,
    /// Maximum `total` (0 = unlimited).
    max_total: AtomicUsize,
    /// Maximum per `AddressKey` (0 = unlimited).
    max_per_ip: AtomicUsize,
    /// `ip_*` rate limits for entries created from now on.
    rate: Mutex<RateLimits>,
    /// Acquisitions since the last `per_ip` sweep; paces the
    /// amortized pruning of emptied entries.
    acquisitions: AtomicUsize,
}

impl ConnectionLimiter {
    /// A limiter with the given caps and address-bucket rates.
    pub(crate) fn new(max_total: usize, max_per_ip: usize, rate: RateLimits) -> Self {
        Self {
            total: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::with_hasher(foldhash::fast::RandomState::default())),
            max_total: AtomicUsize::new(max_total),
            max_per_ip: AtomicUsize::new(max_per_ip),
            rate: Mutex::new(rate),
            acquisitions: AtomicUsize::new(0),
        }
    }

    /// Whether an address needs a `per_ip` entry: the connection cap
    /// tracks it, or a shared `ip_*` bucket must live there.
    fn tracks_addresses(&self, rate: &RateLimits) -> bool {
        self.max_per_ip.load(Ordering::Relaxed) != 0
            || rate.ip_events_per_second > 0
            || rate.ip_reqs_per_second > 0
    }

    /// Update both caps and the address-bucket rates after a config
    /// reload. The new rates build buckets only for `per_ip` entries
    /// created afterwards; an address keeps its current buckets until
    /// its entry is pruned (its last connection closed and the buckets
    /// refilled). Relaxed cap stores can briefly mix old and new —
    /// harmless for admission control.
    pub(crate) fn update_caps(&self, max_total: usize, max_per_ip: usize, rate: RateLimits) {
        self.max_total.store(max_total, Ordering::Relaxed);
        self.max_per_ip.store(max_per_ip, Ordering::Relaxed);
        *self.rate.lock().unwrap_or_else(PoisonError::into_inner) = rate;
    }

    /// Live connections right now (the `nosfry_connections` gauge);
    /// counted even when `max_total` is unlimited.
    pub(crate) fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    /// Count one new connection; `None` when a cap is reached. The
    /// mutexes only ever guard a map update, never an `.await`.
    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionPermit> {
        let rate = *self.rate.lock().unwrap_or_else(PoisonError::into_inner);
        let key = self.tracks_addresses(&rate).then(|| AddressKey::from(ip));
        let buckets = match key {
            Some(key) => self.take_ip(key, &rate)?,
            // Untracked address: a fresh, fully disabled pair.
            None => Arc::new(AddressBuckets::default()),
        };
        if !self.take_total() {
            if let Some(key) = key {
                self.release_ip(key);
            }
            return None;
        }
        Some(ConnectionPermit {
            limiter: Arc::clone(self),
            key,
            buckets,
        })
    }

    /// Take one per-IP slot and return the address's shared buckets;
    /// `None` at the connection cap. The entry — and its buckets, built
    /// from the rate limits current at first acquisition — is created
    /// on the address's first live connection and kept while its
    /// buckets are still spent, so a reconnect reuses them instead of
    /// buying a fresh burst. Emptied entries whose buckets refilled
    /// are pruned here, amortized: at most one `retain` sweep per
    /// `max(map.len(), 64)` acquisitions, keeping the map bounded by
    /// the addresses active within the last burst/rate window (5 s at
    /// the defaults). The map is locked for a counter update only.
    fn take_ip(&self, key: AddressKey, rate: &RateLimits) -> Option<Arc<AddressBuckets>> {
        let mut map = self.per_ip.lock().unwrap_or_else(PoisonError::into_inner);
        if self.acquisitions.fetch_add(1, Ordering::Relaxed) + 1 >= map.len().max(64) {
            let now = now_ms();
            map.retain(|_, entry| entry.count > 0 || !entry.buckets.is_idle(now));
            self.acquisitions.store(0, Ordering::Relaxed);
        }
        let max_per_ip = self.max_per_ip.load(Ordering::Relaxed);
        if max_per_ip != 0 && map.get(&key).is_some_and(|e| e.count >= max_per_ip) {
            return None;
        }
        let entry = map.entry(key).or_insert_with(|| IpEntry {
            count: 0,
            buckets: Arc::new(AddressBuckets::new(rate)),
        });
        entry.count += 1;
        let buckets = Arc::clone(&entry.buckets);
        drop(map);
        Some(buckets)
    }

    /// Take one global slot; `false` at the cap.
    fn take_total(&self) -> bool {
        let max_total = self.max_total.load(Ordering::Relaxed);
        if max_total == 0 {
            self.total.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        let mut current = self.total.load(Ordering::Relaxed);
        loop {
            if current >= max_total {
                return false;
            }
            match self.total.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(next) => current = next,
            }
        }
    }

    /// Release one per-IP slot. An emptied entry is removed at once
    /// only when its buckets refilled: keeping a spent entry makes
    /// the next connection of that address reuse it, so cycling
    /// connections cannot buy a fresh burst. Stale emptied entries
    /// are collected by `take_ip`'s amortized sweep.
    fn release_ip(&self, key: AddressKey) {
        let mut map = self.per_ip.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = map.get_mut(&key) {
            entry.count -= 1;
            if entry.count == 0 && entry.buckets.is_idle(now_ms()) {
                map.remove(&key);
            }
        }
    }
}

/// RAII lease on one connection slot; release happens on drop.
#[derive(Debug)]
pub(crate) struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
    key: Option<AddressKey>,
    /// Rate-limit buckets shared with every live connection of this
    /// client address (disabled when the address is untracked).
    buckets: Arc<AddressBuckets>,
}

impl ConnectionPermit {
    /// The client address's shared token buckets for the session.
    pub(crate) fn buckets(&self) -> Arc<AddressBuckets> {
        Arc::clone(&self.buckets)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.total.fetch_sub(1, Ordering::Relaxed);
        if let Some(key) = self.key {
            self.limiter.release_ip(key);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "unit tests may panic on failure"
)]
mod tests {

    use std::net::Ipv4Addr;

    use super::*;

    /// A `RateLimits` with every bucket disabled: untracked unless
    /// `max_per_ip` is set.
    fn no_rates() -> RateLimits {
        RateLimits {
            events_per_second: 0,
            events_burst: 0,
            reqs_per_second: 0,
            reqs_burst: 0,
            ip_events_per_second: 0,
            ip_events_burst: 0,
            ip_reqs_per_second: 0,
            ip_reqs_burst: 0,
        }
    }

    #[test]
    fn acquire_release_and_map_cleanup() {
        let limiter = Arc::new(ConnectionLimiter::new(0, 2, RateLimits::default()));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let first = limiter.try_acquire(ip).unwrap();
        let second = limiter.try_acquire(ip).unwrap();
        assert!(limiter.try_acquire(ip).is_none(), "third exceeds the cap");
        assert_eq!(limiter.per_ip.lock().unwrap().len(), 1);
        drop(first);
        let third = limiter.try_acquire(ip).expect("a freed slot opens");
        drop(second);
        assert_eq!(
            limiter.per_ip.lock().unwrap().len(),
            1,
            "the still-held slot keeps its entry"
        );
        drop(third);
    }

    #[test]
    fn empty_map_after_last_release() {
        let limiter = Arc::new(ConnectionLimiter::new(0, 2, RateLimits::default()));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        drop(limiter.try_acquire(ip).unwrap());
        assert!(
            limiter.per_ip.lock().unwrap().is_empty(),
            "released IPs leave no map entry"
        );
    }

    #[test]
    fn total_cap() {
        let limiter = Arc::new(ConnectionLimiter::new(1, 0, no_rates()));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let any = limiter.try_acquire(ip).unwrap();
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(limiter.try_acquire(other).is_none(), "total cap reached");
        drop(any);
        assert!(limiter.try_acquire(other).is_some(), "total freed");
        // `max_per_ip = 0` and no `ip_*` bucket tracks nothing.
        assert!(limiter.per_ip.lock().unwrap().is_empty());
    }

    /// Connections of one address share one `Arc<AddressBuckets>`;
    /// a different address gets its own.
    #[test]
    fn permits_share_buckets_per_address() {
        let limiter = Arc::new(ConnectionLimiter::new(0, 0, RateLimits::default()));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let first = limiter.try_acquire(ip).unwrap();
        let second = limiter.try_acquire(ip).unwrap();
        assert!(
            Arc::ptr_eq(&first.buckets(), &second.buckets()),
            "same address must share one bucket pair"
        );
        let other = limiter
            .try_acquire(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .unwrap();
        assert!(
            !Arc::ptr_eq(&first.buckets(), &other.buckets()),
            "a different address has its own buckets"
        );
        // Untracked permits (cap off, all ip buckets disabled) get a
        // fresh disabled pair each.
        let open = Arc::new(ConnectionLimiter::new(0, 0, no_rates()));
        let a = open.try_acquire(ip).unwrap();
        let b = open.try_acquire(ip).unwrap();
        assert!(!Arc::ptr_eq(&a.buckets(), &b.buckets()));
    }

    /// When the last connection of an address drops, an entry whose
    /// buckets refilled is removed while a spent entry stays: the next
    /// connection reuses it instead of buying a fresh burst.
    #[test]
    fn entry_removal_resets_buckets() {
        let limiter = Arc::new(ConnectionLimiter::new(0, 0, RateLimits::default()));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // Idle entry: removed, and the next connection gets fresh
        // buckets built from the then-current rates.
        let first = limiter.try_acquire(ip).unwrap();
        let fresh = first.buckets();
        drop(first);
        assert!(limiter.per_ip.lock().unwrap().is_empty());
        let second = limiter.try_acquire(ip).unwrap();
        assert!(
            !Arc::ptr_eq(&fresh, &second.buckets()),
            "an idle entry leaves; the next connection builds fresh buckets"
        );
        drop(second);
        // Spent entry: kept, and the reconnect reuses its buckets.
        let burst_one = RateLimits {
            ip_events_per_second: 1,
            ip_events_burst: 1,
            ..RateLimits::default()
        };
        let spent_limiter = Arc::new(ConnectionLimiter::new(0, 0, burst_one));
        let third = spent_limiter.try_acquire(ip).unwrap();
        let spent = third.buckets();
        assert!(spent.take_event(now_ms()), "fresh burst of 1");
        drop(third);
        assert_eq!(spent_limiter.per_ip.lock().unwrap().len(), 1);
        let fourth = spent_limiter.try_acquire(ip).unwrap();
        assert!(
            Arc::ptr_eq(&spent, &fourth.buckets()),
            "a spent entry is reused across reconnects"
        );
        assert!(
            !fourth.buckets().take_event(now_ms()),
            "the shared burst is still spent: reconnect bought nothing"
        );
    }
}
