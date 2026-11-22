//! Connection caps: a process-wide count shared by every listener,
//! plus a per-profile per-peer count and the shared per-peer
//! rate-limit buckets handed to each session.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use nosfry_core::limits::{AddressBuckets, RateLimits};

use crate::config::Profile;
use crate::peer::{Peer, PeerKey};

/// Unix time in milliseconds for bucket idle checks (only on the
/// release and sweep paths, never per message).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

/// One tracked peer: its live connection count plus the rate-limit
/// buckets every one of its sessions shares.
#[derive(Debug)]
struct PeerEntry {
    count: usize,
    buckets: Arc<AddressBuckets>,
}

/// The connection cap the open-file limit leaves room for:
/// `soft - 64 - soft/8`. Every WebSocket holds one fd; the formula
/// reserves 64 fds for the process itself (stdio, the LMDB data and
/// lock files, listeners, kqueue/epoll and tokio internals, the
/// write-policy plugin's pipes, log and metrics sockets) plus one
/// eighth of the limit for sockets the cap does not count — plain
/// HTTP requests (NIP-11, NIP-86, `NodeInfo`, /metrics), connections
/// still inside the 10 s header-read window, and upgrades in
/// flight.
///
/// `256 -> 160`, `1024 -> 832`, `65_536 -> 57_280`,
/// `1_000_000 -> 874_936`, `64 -> 0`.
pub(crate) fn connection_ceiling(soft_nofile: u64) -> usize {
    let soft = usize::try_from(soft_nofile).unwrap_or(usize::MAX);
    soft.saturating_sub(64 + soft / 8)
}

/// Caps on simultaneous connections, shared by every accepted socket
/// on every listener. `max_total` is always finite — the server
/// resolves it from `relay.max_connections` and the open-file limit —
/// while each profile's `max_connections_per_peer` keeps 0 =
/// unlimited. Both caps are atomics so a config reload updates them
/// for every connection at once; connections already above a lowered
/// cap are not closed.
#[derive(Debug)]
pub(crate) struct ConnectionLimiter {
    /// Live connections, across all profiles.
    total: AtomicUsize,
    /// Maximum `total` — always finite.
    max_total: AtomicUsize,
    /// One peer limiter per `[relay.profiles.<name>]`. Entries created
    /// by an earlier reload are kept so a peer's live count and spent
    /// buckets survive a profile's cap or rate change.
    profiles: Mutex<HashMap<String, Arc<PeerLimiter>, foldhash::fast::RandomState>>,
}

/// One profile's per-peer caps and shared rate-limit buckets.
#[derive(Debug)]
struct PeerLimiter {
    /// Live connections and shared rate-limit buckets per peer key;
    /// populated only when `max_per_peer` or any `ip_*` bucket is
    /// enabled.
    per_peer: Mutex<HashMap<PeerKey, PeerEntry, foldhash::fast::RandomState>>,
    /// Maximum per `PeerKey` (0 = unlimited).
    max_per_peer: AtomicUsize,
    /// `ip_*` rate limits for entries created from now on.
    rate: Mutex<RateLimits>,
    /// Acquisitions since the last `per_peer` sweep; paces the
    /// amortized pruning of emptied entries.
    acquisitions: AtomicUsize,
}

impl PeerLimiter {
    /// A peer limiter for one profile's caps and bucket rates.
    fn new(profile: &Profile) -> Self {
        Self {
            per_peer: Mutex::new(HashMap::with_hasher(foldhash::fast::RandomState::default())),
            max_per_peer: AtomicUsize::new(profile.max_connections_per_peer),
            rate: Mutex::new(profile.rate_limits),
            acquisitions: AtomicUsize::new(0),
        }
    }

    /// Whether a peer needs a `per_peer` entry: the connection cap
    /// tracks it, or a shared `ip_*` bucket must live there.
    fn tracks_peers(&self, rate: &RateLimits) -> bool {
        self.max_per_peer.load(Ordering::Relaxed) != 0
            || rate.ip_events_per_second > 0
            || rate.ip_reqs_per_second > 0
    }

    /// Update the cap and the bucket rates after a config reload.
    /// The new rates build buckets only for `per_peer` entries
    /// created afterwards; a peer keeps its current buckets until
    /// its entry is pruned (its last connection closed and the buckets
    /// refilled). Relaxed cap stores can briefly mix old and new —
    /// harmless for admission control.
    fn update(&self, profile: &Profile) {
        self.max_per_peer
            .store(profile.max_connections_per_peer, Ordering::Relaxed);
        *self.rate.lock().unwrap_or_else(PoisonError::into_inner) = profile.rate_limits;
    }

    /// Take one per-peer slot and return the peer's shared buckets;
    /// `None` at the connection cap. The entry — and its buckets, built
    /// from the rate limits current at first acquisition — is created
    /// on the peer's first live connection and kept while its
    /// buckets are still spent, so a reconnect reuses them instead of
    /// buying a fresh burst. Emptied entries whose buckets refilled
    /// are pruned here, amortized: at most one `retain` sweep per
    /// `max(map.len(), 64)` acquisitions, keeping the map bounded by
    /// the peers active within the last burst/rate window (5 s at
    /// the defaults). The map is locked for a counter update only.
    fn take_peer(&self, key: PeerKey, rate: &RateLimits) -> Option<Arc<AddressBuckets>> {
        let mut map = self.per_peer.lock().unwrap_or_else(PoisonError::into_inner);
        if self.acquisitions.fetch_add(1, Ordering::Relaxed) + 1 >= map.len().max(64) {
            let now = now_ms();
            map.retain(|_, entry| entry.count > 0 || !entry.buckets.is_idle(now));
            self.acquisitions.store(0, Ordering::Relaxed);
        }
        let max_per_peer = self.max_per_peer.load(Ordering::Relaxed);
        if max_per_peer != 0 && map.get(&key).is_some_and(|e| e.count >= max_per_peer) {
            return None;
        }
        let entry = map.entry(key).or_insert_with(|| PeerEntry {
            count: 0,
            buckets: Arc::new(AddressBuckets::new(rate)),
        });
        entry.count += 1;
        let buckets = Arc::clone(&entry.buckets);
        drop(map);
        Some(buckets)
    }

    /// Release one per-peer slot. An emptied entry is removed at once
    /// only when its buckets refilled: keeping a spent entry makes
    /// the next connection of that peer reuse it, so cycling
    /// connections cannot buy a fresh burst. Stale emptied entries
    /// are collected by `take_peer`'s amortized sweep.
    fn release_peer(&self, key: &PeerKey) {
        let mut map = self.per_peer.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = map.get_mut(key) {
            entry.count -= 1;
            if entry.count == 0 && entry.buckets.is_idle(now_ms()) {
                map.remove(key);
            }
        }
    }
}

impl ConnectionLimiter {
    /// A limiter with the process-wide cap and one peer limiter per
    /// profile.
    pub(crate) fn new(max_total: usize, profiles: &BTreeMap<String, Profile>) -> Self {
        Self {
            total: AtomicUsize::new(0),
            max_total: AtomicUsize::new(max_total),
            profiles: Mutex::new(HashMap::from_iter(
                profiles
                    .iter()
                    .map(|(name, p)| (name.clone(), Arc::new(PeerLimiter::new(p)))),
            )),
        }
    }

    /// Update the process-wide cap and every profile's cap and bucket
    /// rates after a config reload. Profiles added by the reload get
    /// a fresh peer limiter; removed ones (only those no running
    /// listener uses — validation refuses the rest) are dropped.
    pub(crate) fn update_caps(&self, max_total: usize, profiles: &BTreeMap<String, Profile>) {
        self.max_total.store(max_total, Ordering::Relaxed);
        let mut map = self.profiles.lock().unwrap_or_else(PoisonError::into_inner);
        map.retain(|name, _| profiles.contains_key(name));
        for (name, profile) in profiles {
            match map.get(name) {
                Some(limiter) => limiter.update(profile),
                None => {
                    map.insert(name.clone(), Arc::new(PeerLimiter::new(profile)));
                }
            }
        }
    }

    /// Live connections right now (the `nosfry_connections` gauge).
    pub(crate) fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    /// Count one new connection on `profile`; `None` when a cap is
    /// reached (or the profile does not exist — load and reload
    /// validation make that unreachable for a running listener, and
    /// refusing is the safe answer). The mutexes only ever guard a
    /// map update, never an `.await`.
    pub(crate) fn try_acquire(
        self: &Arc<Self>,
        profile: &str,
        peer: &Peer,
    ) -> Option<ConnectionPermit> {
        let peer_limiter = self
            .profiles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(profile)
            .cloned()?;
        let rate = *peer_limiter
            .rate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let key = peer_limiter.tracks_peers(&rate).then(|| peer.key());
        let buckets = match &key {
            Some(key) => peer_limiter.take_peer(key.clone(), &rate)?,
            // Untracked peer: a fresh, fully disabled pair.
            None => Arc::new(AddressBuckets::default()),
        };
        if !self.take_total() {
            if let Some(key) = &key {
                peer_limiter.release_peer(key);
            }
            return None;
        }
        Some(ConnectionPermit {
            limiter: Arc::clone(self),
            peer: key.map(|key| (peer_limiter, key)),
            buckets,
        })
    }

    /// Take one global slot; `false` at the cap.
    fn take_total(&self) -> bool {
        let max_total = self.max_total.load(Ordering::Relaxed);
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
}

/// RAII lease on one connection slot; release happens on drop.
#[derive(Debug)]
pub(crate) struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
    /// The profile's peer limiter plus the peer key, when the peer is
    /// tracked. The `Arc` keeps the limiter alive past a reload that
    /// removed its profile so the count is still returned.
    peer: Option<(Arc<PeerLimiter>, PeerKey)>,
    /// Rate-limit buckets shared with every live connection of this
    /// peer (disabled when the peer is untracked).
    buckets: Arc<AddressBuckets>,
}

impl ConnectionPermit {
    /// The peer's shared token buckets for the session.
    pub(crate) fn buckets(&self) -> Arc<AddressBuckets> {
        Arc::clone(&self.buckets)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.total.fetch_sub(1, Ordering::Relaxed);
        if let Some((limiter, key)) = &self.peer {
            limiter.release_peer(key);
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

    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    /// A `RateLimits` with every bucket disabled: untracked unless
    /// `max_per_peer` is set.
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

    /// One `default` profile map with the given cap and rates.
    fn profiles(
        max_connections_per_peer: usize,
        rate_limits: RateLimits,
    ) -> BTreeMap<String, Profile> {
        BTreeMap::from([(
            "default".to_owned(),
            Profile {
                max_connections_per_peer,
                rate_limits,
            },
        )])
    }

    fn ip() -> Peer {
        Peer::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    /// The fd ceiling reserves 64 fds for the process plus one eighth
    /// of the limit for uncounted sockets.
    #[test]
    fn connection_ceiling_reserves_process_fds() {
        assert_eq!(connection_ceiling(256), 160);
        assert_eq!(connection_ceiling(1_024), 832);
        assert_eq!(connection_ceiling(65_536), 57_280);
        assert_eq!(connection_ceiling(1_000_000), 874_936);
        assert_eq!(connection_ceiling(64), 0);
        assert_eq!(
            connection_ceiling(u64::MAX),
            usize::MAX - 64 - usize::MAX / 8
        );
    }

    #[test]
    fn acquire_release_and_map_cleanup() {
        let limiter = Arc::new(ConnectionLimiter::new(
            usize::MAX,
            &profiles(2, RateLimits::default()),
        ));
        let first = limiter.try_acquire("default", &ip()).unwrap();
        let second = limiter.try_acquire("default", &ip()).unwrap();
        assert!(
            limiter.try_acquire("default", &ip()).is_none(),
            "third exceeds the cap"
        );
        let per_peer_len = |l: &Arc<PeerLimiter>| l.per_peer.lock().unwrap().len();
        {
            let map = limiter.profiles.lock().unwrap();
            assert_eq!(map.values().map(per_peer_len).sum::<usize>(), 1);
        }
        drop(first);
        let third = limiter
            .try_acquire("default", &ip())
            .expect("a freed slot opens");
        drop(second);
        {
            let map = limiter.profiles.lock().unwrap();
            assert_eq!(
                map.values().map(per_peer_len).sum::<usize>(),
                1,
                "the still-held slot keeps its entry"
            );
        }
        drop(third);
    }

    #[test]
    fn empty_map_after_last_release() {
        let limiter = Arc::new(ConnectionLimiter::new(
            usize::MAX,
            &profiles(2, RateLimits::default()),
        ));
        drop(limiter.try_acquire("default", &ip()).unwrap());
        let map = limiter.profiles.lock().unwrap();
        assert!(
            map.values().all(|l| l.per_peer.lock().unwrap().is_empty()),
            "released peers leave no map entry"
        );
        drop(map);
    }

    #[test]
    fn total_cap() {
        let limiter = Arc::new(ConnectionLimiter::new(1, &profiles(0, no_rates())));
        let any = limiter.try_acquire("default", &ip()).unwrap();
        let other = Peer::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(
            limiter.try_acquire("default", &other).is_none(),
            "total cap reached"
        );
        drop(any);
        assert!(
            limiter.try_acquire("default", &other).is_some(),
            "total freed"
        );
        // `max_connections_per_peer = 0` and no `ip_*` bucket tracks
        // nothing.
        let map = limiter.profiles.lock().unwrap();
        assert!(map.values().all(|l| l.per_peer.lock().unwrap().is_empty()));
        drop(map);
    }

    /// Every connection of an addressless-transport listener shares
    /// one peer identity: the per-peer cap counts them listener-wide.
    #[test]
    fn listener_peers_share_the_cap() {
        let limiter = Arc::new(ConnectionLimiter::new(usize::MAX, &profiles(1, no_rates())));
        let listener = Peer::Listener(Arc::from("unix:/run/x.sock"));
        let first = limiter.try_acquire("default", &listener).unwrap();
        assert!(
            limiter.try_acquire("default", &listener).is_none(),
            "a second connection of the same listener hits its cap"
        );
        drop(first);
        assert!(
            limiter.try_acquire("default", &listener).is_some(),
            "a freed listener slot opens"
        );
    }

    /// Two profiles carry independent per-peer caps and buckets.
    #[test]
    fn profiles_have_independent_caps() {
        let map = BTreeMap::from([
            (
                "a".to_owned(),
                Profile {
                    max_connections_per_peer: 1,
                    rate_limits: no_rates(),
                },
            ),
            (
                "b".to_owned(),
                Profile {
                    max_connections_per_peer: 2,
                    rate_limits: no_rates(),
                },
            ),
        ]);
        let limiter = Arc::new(ConnectionLimiter::new(usize::MAX, &map));
        let peer = ip();
        let a_permit = limiter.try_acquire("a", &peer).unwrap();
        assert!(
            limiter.try_acquire("a", &peer).is_none(),
            "profile a's cap of 1 reached"
        );
        assert!(
            limiter.try_acquire("b", &peer).is_some(),
            "profile b's separate counter still admits the peer"
        );
        let first = limiter.try_acquire("b", &peer).unwrap();
        let second = limiter.try_acquire("b", &peer).unwrap();
        assert!(
            !Arc::ptr_eq(&first.buckets(), &a_permit.buckets()),
            "different profiles never share peer buckets"
        );
        drop((first, second, a_permit));
    }

    /// Connections of one peer share one `Arc<AddressBuckets>`;
    /// a different peer gets its own.
    #[test]
    fn permits_share_buckets_per_peer() {
        let limiter = Arc::new(ConnectionLimiter::new(
            usize::MAX,
            &profiles(0, RateLimits::default()),
        ));
        let first = limiter.try_acquire("default", &ip()).unwrap();
        let second = limiter.try_acquire("default", &ip()).unwrap();
        assert!(
            Arc::ptr_eq(&first.buckets(), &second.buckets()),
            "same peer must share one bucket pair"
        );
        let other = limiter
            .try_acquire("default", &Peer::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))))
            .unwrap();
        assert!(
            !Arc::ptr_eq(&first.buckets(), &other.buckets()),
            "a different peer has its own buckets"
        );
        // Untracked permits (cap off, all ip buckets disabled) get a
        // fresh disabled pair each.
        let open = Arc::new(ConnectionLimiter::new(usize::MAX, &profiles(0, no_rates())));
        let a = open.try_acquire("default", &ip()).unwrap();
        let b = open.try_acquire("default", &ip()).unwrap();
        assert!(!Arc::ptr_eq(&a.buckets(), &b.buckets()));
    }

    /// When the last connection of a peer drops, an entry whose
    /// buckets refilled is removed while a spent entry stays: the next
    /// connection reuses it instead of buying a fresh burst.
    #[test]
    fn entry_removal_resets_buckets() {
        let limiter = Arc::new(ConnectionLimiter::new(
            usize::MAX,
            &profiles(0, RateLimits::default()),
        ));
        // Idle entry: removed, and the next connection gets fresh
        // buckets built from the then-current rates.
        let first = limiter.try_acquire("default", &ip()).unwrap();
        let fresh = first.buckets();
        drop(first);
        let peer_map = limiter.profiles.lock().unwrap();
        assert!(
            peer_map
                .values()
                .all(|l| l.per_peer.lock().unwrap().is_empty())
        );
        drop(peer_map);
        let second = limiter.try_acquire("default", &ip()).unwrap();
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
        let spent_limiter = Arc::new(ConnectionLimiter::new(usize::MAX, &profiles(0, burst_one)));
        let third = spent_limiter.try_acquire("default", &ip()).unwrap();
        let spent = third.buckets();
        assert!(spent.take_event(now_ms()).is_ok(), "fresh burst of 1");
        drop(third);
        {
            let map = spent_limiter.profiles.lock().unwrap();
            assert_eq!(
                map.values()
                    .map(|l| l.per_peer.lock().unwrap().len())
                    .sum::<usize>(),
                1
            );
        }
        let fourth = spent_limiter.try_acquire("default", &ip()).unwrap();
        assert!(
            Arc::ptr_eq(&spent, &fourth.buckets()),
            "a spent entry is reused across reconnects"
        );
        assert!(
            fourth.buckets().take_event(now_ms()).is_err(),
            "the shared burst is still spent: reconnect bought nothing"
        );
    }
}
