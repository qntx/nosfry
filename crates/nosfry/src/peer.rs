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
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Listener(id) => f.write_str(id),
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
}

/// The request extension the accept path inserts into every
/// connection: which listener took it, plus the transport peer
/// address when the transport has one. Replaces `ConnectInfo`.
#[derive(Debug, Clone)]
pub(crate) struct Origin {
    /// The accepting listener.
    pub(crate) listener: Arc<ListenerInfo>,
    /// The TCP transport peer; `None` for transports without client
    /// addresses (unix sockets).
    pub(crate) transport: Option<SocketAddr>,
}

/// The request's peer. A configured `real_ip_header`'s LAST
/// comma-separated value is trusted — a proxy appends its peer's
/// address, so the last entry is the one written by the trusted proxy
/// in front of nosfry; earlier entries are client-controlled. Set it
/// only behind a proxy that sets or appends the header. Missing or
/// unparsable values fall back to the transport address, then to the
/// listener identity.
pub(crate) fn resolve(origin: &Origin, headers: &HeaderMap) -> Peer {
    let info = &origin.listener;
    if !info.real_ip_header.is_empty()
        && let Some(value) = headers.get(info.real_ip_header.as_str())
        && let Ok(value) = value.to_str()
        && let Some(last) = value.split(',').next_back()
        && let Ok(ip) = last.trim().parse()
    {
        return Peer::Ip(ip);
    }
    origin.transport.map_or_else(
        || Peer::Listener(Arc::clone(&info.id)),
        |sock| Peer::Ip(sock.ip()),
    )
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
        })
    }

    fn origin(id: &str, real_ip_header: &str, transport: Option<SocketAddr>) -> Origin {
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
        let origin = origin("unix:/run/x.sock", "x-forwarded-for", None);
        let peer = resolve(
            &origin,
            &headers("x-forwarded-for", " 1.2.3.4, 203.0.113.7 "),
        );
        assert_eq!(peer, Peer::Ip(IpAddr::from([203, 0, 113, 7])));
    }

    /// No configured header on a unix listener gives the listener
    /// identity: every connection of the socket is the same peer.
    #[test]
    fn unix_without_header_is_the_listener_peer() {
        let origin = origin("unix:/run/x.sock", "", None);
        assert_eq!(
            resolve(&origin, &HeaderMap::new()),
            Peer::Listener(Arc::from("unix:/run/x.sock"))
        );
        // A header key the listener does not trust is ignored.
        assert_eq!(
            resolve(&origin, &headers("x-forwarded-for", "1.2.3.4")),
            Peer::Listener(Arc::from("unix:/run/x.sock"))
        );
    }

    /// A TCP connection resolves to its socket peer address.
    #[test]
    fn tcp_resolves_to_socket_ip() {
        let sock: SocketAddr = "192.0.2.9:4444".parse().unwrap();
        let origin = origin("127.0.0.1:7777", "", Some(sock));
        assert_eq!(
            resolve(&origin, &HeaderMap::new()),
            Peer::Ip(IpAddr::from([192, 0, 2, 9]))
        );
    }

    /// An unparsable header value falls back: unix → listener
    /// identity, TCP → socket address.
    #[test]
    fn malformed_header_falls_back() {
        let unix = origin("unix:/run/x.sock", "x-forwarded-for", None);
        assert_eq!(
            resolve(&unix, &headers("x-forwarded-for", "not-an-ip")),
            Peer::Listener(Arc::from("unix:/run/x.sock"))
        );
        let sock: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let tcp = origin("127.0.0.1:7777", "x-forwarded-for", Some(sock));
        assert_eq!(
            resolve(&tcp, &headers("x-forwarded-for", "not-an-ip")),
            Peer::Ip(IpAddr::from([10, 0, 0, 1]))
        );
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
