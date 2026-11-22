//! Client identity across transports. A TCP connection carries a
//! `SocketAddr`; a unix-domain socket (and future transports like a
//! tor onion or iroh endpoint) has no client address at all — for
//! those the *listener* is the peer identity, so per-peer connection
//! caps and rate-limit buckets bind listener-wide. That is the
//! intended semantics for deployments such as torrc
//! `HiddenServicePort unix:` where every connection arrives at one
//! shared socket.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::header::HeaderMap;
use nosfry_core::limits::AddressKey;

/// Who a connection is, for limits, logging, the write-policy plugin,
/// and NIP-86 blocking.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Peer {
    /// An IP client: TCP transport, or any listener whose
    /// `real_ip_header` resolved.
    Ip(IpAddr),
    /// A transport without client addresses (today: a unix-domain
    /// socket). The value is the listener's address string (e.g.
    /// `unix:/run/nosfry/tor.sock`); every connection of such a
    /// listener is the same peer.
    Listener(Arc<str>),
    /// One rendezvous circuit of an embedded onion listener. `circuit`
    /// is a process-local number that appears only in debug logs; the
    /// peer identity is the listener, so caps and buckets bind
    /// listener-wide — the only bound that holds when circuits are
    /// free to open.
    #[cfg(feature = "onion")]
    Circuit {
        /// The listener's address string (`onion:<nickname>`).
        listener: Arc<str>,
        /// The circuit's process-local number.
        circuit: u64,
    },
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Listener(id) => f.write_str(id),
            #[cfg(feature = "onion")]
            Self::Circuit { listener, .. } => f.write_str(listener),
        }
    }
}

impl Peer {
    /// The per-peer limiter key: `AddressKey`'s grouping (IPv4 exact,
    /// IPv6 /64) for IP peers, the listener identity otherwise.
    pub(crate) fn key(&self) -> PeerKey {
        match self {
            Self::Ip(ip) => PeerKey::Addr(AddressKey::from(*ip)),
            Self::Listener(id) => PeerKey::Listener(Arc::clone(id)),
            #[cfg(feature = "onion")]
            Self::Circuit { listener, .. } => PeerKey::Listener(Arc::clone(listener)),
        }
    }
}

/// The per-peer map key: a grouped client address or a listener
/// identity. Two peers share caps and buckets exactly when their keys
/// are equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum PeerKey {
    /// A grouped IP client address.
    Addr(AddressKey),
    /// A listener's address string.
    Listener(Arc<str>),
}

/// One listener's fixed metadata, shared by every connection it
/// accepts.
#[derive(Debug)]
pub(crate) struct ListenerInfo {
    /// The listener's address string (`127.0.0.1:7777`,
    /// `unix:/run/x.sock`): the peer identity for addressless
    /// transports and the `peer` log field's fallback.
    pub(crate) id: Arc<str>,
    /// The `[relay.profiles.<name>]` this listener's connections
    /// resolve their caps and limits from.
    pub(crate) profile: Arc<str>,
    /// Header trusted for the real client IP ("" = none).
    pub(crate) real_ip_header: String,
    /// Unix seconds of the last missing/unparsable `real_ip_header`
    /// warning, throttling it to once per minute.
    pub(crate) last_warn_secs: AtomicU64,
}

/// How one accepted connection reached the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    /// A TCP connection; the socket peer address is the client's.
    Tcp(SocketAddr),
    /// A unix-domain socket; carries no client address.
    Unix,
    /// One rendezvous circuit of an embedded onion listener; carries
    /// no client address, only a process-local circuit number.
    #[cfg(feature = "onion")]
    Circuit(u64),
}

/// The request extension the accept path inserts into every
/// connection: which listener took it, plus the transport. Replaces
/// `ConnectInfo`.
#[derive(Debug, Clone)]
pub(crate) struct Origin {
    /// The accepting listener.
    pub(crate) listener: Arc<ListenerInfo>,
    /// The transport the connection arrived on.
    pub(crate) transport: Transport,
}

impl Origin {
    /// Whether the connection arrived over an embedded onion circuit;
    /// always false in builds without the `onion` feature.
    pub(crate) const fn is_onion(&self) -> bool {
        match self.transport {
            #[cfg(feature = "onion")]
            Transport::Circuit(_) => true,
            _ => false,
        }
    }
}

/// The request's peer, plus whether a configured `real_ip_header`
/// was missing or unparsable so resolution fell back.
///
/// A configured `real_ip_header`'s LAST comma-separated value is
/// trusted — a proxy appends its peer's address, so the last entry is
/// the one written by the trusted proxy in front of nosfry; earlier
/// entries are client-controlled. Set it only behind a proxy that
/// sets or appends the header. Missing or unparsable values fall back
/// to the transport address, then to the listener identity.
pub(crate) fn resolve(origin: &Origin, headers: &HeaderMap) -> (Peer, bool) {
    let info = &origin.listener;
    let trust_header = !info.real_ip_header.is_empty();
    if trust_header
        && let Some(value) = headers.get(info.real_ip_header.as_str())
        && let Ok(value) = value.to_str()
        && let Some(last) = value.split(',').next_back()
        && let Ok(ip) = last.trim().parse()
    {
        return (Peer::Ip(ip), false);
    }
    let peer = match &origin.transport {
        Transport::Tcp(sock) => Peer::Ip(sock.ip()),
        Transport::Unix => Peer::Listener(Arc::clone(&info.id)),
        #[cfg(feature = "onion")]
        Transport::Circuit(circuit) => Peer::Circuit {
            listener: Arc::clone(&info.id),
            circuit: *circuit,
        },
    };
    (peer, trust_header)
}

/// Seconds between `real_ip_header` fallback warnings per listener.
const FALLBACK_WARN_SECS: u64 = 60;

/// Whether a `real_ip_header` fallback warning may fire at
/// `now_secs`: at most once per minute per listener. CAS so
/// concurrent requests warn once.
fn warn_gate(last_warn_secs: &AtomicU64, now_secs: u64) -> bool {
    let last = last_warn_secs.load(Ordering::Relaxed);
    now_secs.saturating_sub(last) >= FALLBACK_WARN_SECS
        && last_warn_secs
            .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// A `real_ip_header` listener just resolved without the header
/// (absent or unparsable): behind a misconfigured proxy every client
/// shares the proxy's address and the per-peer cap throttles them
/// all. Warn at most once per minute per listener; the header value
/// is client-controlled and never logged.
pub(crate) fn warn_fallback(info: &ListenerInfo) {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if warn_gate(&info.last_warn_secs, now_secs) {
        tracing::warn!(
            target: "nosfry::conn",
            listener = %info.id,
            header = %info.real_ip_header,
            "real_ip_header missing or unparsable; falling back to the transport peer"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    fn listener(id: &str, profile: &str, real_ip_header: &str) -> Arc<ListenerInfo> {
        Arc::new(ListenerInfo {
            id: Arc::from(id),
            profile: Arc::from(profile),
            real_ip_header: real_ip_header.to_owned(),
            last_warn_secs: AtomicU64::new(0),
        })
    }

    fn origin(id: &str, real_ip_header: &str, transport: Transport) -> Origin {
        Origin {
            listener: listener(id, "default", real_ip_header),
            transport,
        }
    }

    fn headers(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        headers
    }

    /// A valid real-IP header on a unix listener resolves to the
    /// header's address; the last comma-separated value is trusted.
    #[test]
    fn real_ip_header_on_unix_resolves_to_ip() {
        let origin = origin("unix:/run/x.sock", "x-forwarded-for", Transport::Unix);
        let (peer, fell_back) = resolve(
            &origin,
            &headers("x-forwarded-for", " 1.2.3.4, 203.0.113.7 "),
        );
        assert_eq!(peer, Peer::Ip(IpAddr::from([203, 0, 113, 7])));
        assert!(!fell_back);
    }

    /// No configured header on a unix listener gives the listener
    /// identity: every connection of the socket is the same peer.
    #[test]
    fn unix_without_header_is_the_listener_peer() {
        let origin = origin("unix:/run/x.sock", "", Transport::Unix);
        assert_eq!(
            resolve(&origin, &HeaderMap::new()),
            (Peer::Listener(Arc::from("unix:/run/x.sock")), false)
        );
        // A header key the listener does not trust is ignored.
        assert_eq!(
            resolve(&origin, &headers("x-forwarded-for", "1.2.3.4")),
            (Peer::Listener(Arc::from("unix:/run/x.sock")), false)
        );
    }

    /// A TCP connection resolves to its socket peer address.
    #[test]
    fn tcp_resolves_to_socket_ip() {
        let sock: SocketAddr = "192.0.2.9:4444".parse().unwrap();
        let origin = origin("127.0.0.1:7777", "", Transport::Tcp(sock));
        assert_eq!(
            resolve(&origin, &HeaderMap::new()),
            (Peer::Ip(IpAddr::from([192, 0, 2, 9])), false)
        );
    }

    /// An unparsable header value falls back: unix → listener
    /// identity, TCP → socket address.
    #[test]
    fn malformed_header_falls_back() {
        let unix = origin("unix:/run/x.sock", "x-forwarded-for", Transport::Unix);
        assert_eq!(
            resolve(&unix, &headers("x-forwarded-for", "not-an-ip")),
            (Peer::Listener(Arc::from("unix:/run/x.sock")), true)
        );
        let sock: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let tcp = origin("127.0.0.1:7777", "x-forwarded-for", Transport::Tcp(sock));
        assert_eq!(
            resolve(&tcp, &headers("x-forwarded-for", "not-an-ip")),
            (Peer::Ip(IpAddr::from([10, 0, 0, 1])), true)
        );
    }

    /// An absent trusted header falls back the same way, flagged.
    #[test]
    fn missing_header_falls_back() {
        let origin = origin("unix:/run/x.sock", "x-real-ip", Transport::Unix);
        assert_eq!(
            resolve(&origin, &HeaderMap::new()),
            (Peer::Listener(Arc::from("unix:/run/x.sock")), true)
        );
    }

    /// The once-per-minute fallback-warning gate: fires at t, is
    /// suppressed at t+30, fires again at t+61 — and a fresh listener
    /// warns on its first fallback.
    #[test]
    fn fallback_warn_gates_once_per_minute() {
        let gate = AtomicU64::new(0);
        assert!(warn_gate(&gate, 1_000));
        assert!(!warn_gate(&gate, 1_030));
        assert!(warn_gate(&gate, 1_061));

        let fresh = AtomicU64::new(0);
        assert!(warn_gate(&fresh, 60), "first fallback always warns");
    }

    /// `PeerKey` grouping: IPv4 exact (with v4-mapped-v6 folded),
    /// IPv6 per /64, listeners per identity string.
    #[test]
    fn peer_key_grouping() {
        assert_eq!(
            Peer::Ip("::ffff:1.2.3.4".parse().unwrap()).key(),
            Peer::Ip(IpAddr::from([1, 2, 3, 4])).key(),
        );
        let a = Peer::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        let b = Peer::Ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0xffff, 0, 0, 9,
        )));
        let c = Peer::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)));
        assert_eq!(a.key(), b.key(), "same /64 shares a key");
        assert_ne!(a.key(), c.key(), "different /64 differs");
        assert_eq!(
            Peer::Listener(Arc::from("unix:/a.sock")).key(),
            Peer::Listener(Arc::from("unix:/a.sock")).key(),
        );
        assert_ne!(
            Peer::Listener(Arc::from("unix:/a.sock")).key(),
            Peer::Listener(Arc::from("unix:/b.sock")).key(),
        );
    }
}
