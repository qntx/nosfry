//! Resolve and vet a peer URL, then dial it into a byte stream.
//!
//! This is the seam a later onion (Arti) or iroh dialer plugs into:
//! everything after [`dial`] is generic over `S: AsyncRead +
//! AsyncWrite`. Only `ws://`/`wss://` are supported; user info is
//! refused (it would leak into logs); `.onion` is refused outright —
//! there is no Tor dialer yet and a clearnet DNS lookup would leak
//! the address. Every resolved address must be globally routable
//! unless `--allow-private` admits loopback, RFC 1918, CGNAT,
//! link-local and unique-local addresses; unspecified, multicast and
//! broadcast addresses are always refused.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use url::Url;

use super::SyncError;

/// A resolved, vetted dial target: the parsed URL plus the exact
/// addresses the connection may use (no second resolution happens).
#[derive(Debug)]
pub(crate) struct Target {
    /// The URL as parsed — the WebSocket handshake and NIP-11 read it.
    pub(crate) url: Url,
    /// Host for SNI and the `Host` header (no port).
    pub(crate) host: String,
    /// Whether to wrap the stream in TLS (`wss://`).
    pub(crate) tls: bool,
    /// Vetted addresses, in resolution order.
    pub(crate) addrs: Vec<SocketAddr>,
}

/// How an address classifies for dialing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Globally routable — always allowed.
    Global,
    /// Loopback, RFC 1918, CGNAT, link-local, unique-local — only
    /// under `--allow-private`.
    Private,
    /// Unspecified, multicast, broadcast — never allowed.
    Forbidden,
}

/// Classify an IPv4 address (std's `is_global` is unstable).
const fn classify_v4(ip: Ipv4Addr) -> Scope {
    let [a, b, c, _] = ip.octets();
    if a == 0
        // 0.0.0.0/8 "this network"
        || ip.is_multicast() // 224.0.0.0/4
        || (a & 0xf0) == 0xf0 // 240.0.0.0/4 reserved (covers broadcast)
        || (a == 192 && b == 0 && c == 2) // 192.0.2.0/24 TEST-NET-1
        || (a == 198 && b == 51 && c == 100) // 198.51.100.0/24 TEST-NET-2
        || (a == 203 && b == 0 && c == 113)
    // 203.0.113.0/24 TEST-NET-3
    {
        return Scope::Forbidden;
    }
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (a == 100 && (b & 0b1100_0000) == 0b0100_0000) // 100.64.0.0/10 CGNAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24 IETF protocol assignments
        || (a == 198 && (b & 0xfe) == 18)
    // 198.18.0.0/15 benchmarking
    {
        return Scope::Private;
    }
    Scope::Global
}

/// Two u16 segments as an IPv4 address.
const fn v4_of(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

/// Classify an IPv6 address; addresses that embed an IPv4 are
/// classified by that IPv4 (mapped, compatible, NAT64, 6to4).
const fn classify_v6(ip: Ipv6Addr) -> Scope {
    let [s0, s1, s2, s3, s4, s5, s6, s7] = ip.segments();
    if s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && (s5 == 0 || s5 == 0xffff) {
        // ::a.b.c.d compatible and ::ffff:a.b.c.d mapped; :: and ::1
        // fall through to the plain-v6 rules below.
        if !(s5 == 0 && s6 == 0 && s7 <= 1) {
            return classify_v4(v4_of(s6, s7));
        }
    }
    if s0 == 0x0064 && s1 == 0xff9b && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0 {
        // 64:ff9b::/96 NAT64.
        return classify_v4(v4_of(s6, s7));
    }
    if s0 == 0x2002 {
        // 2002::/16 6to4 — the v4 sits in bits 16..48.
        return classify_v4(v4_of(s1, s2));
    }
    if ip.is_unspecified() || ip.is_multicast() {
        return Scope::Forbidden;
    }
    if s0 == 0x2001 && s1 == 0x0db8 {
        // 2001:db8::/32 documentation.
        return Scope::Forbidden;
    }
    if ip.is_loopback()
        || (s0 & 0xfe00) == 0xfc00 // fc00::/7 unique-local
        || (s0 & 0xffc0) == 0xfe80
    // fe80::/10 link-local
    {
        return Scope::Private;
    }
    Scope::Global
}

/// Classify either address family.
const fn classify(ip: IpAddr) -> Scope {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Parse `url`, resolve it, and vet every address. Errors name the
/// rule that fired.
///
/// # Errors
///
/// [`SyncError::Url`] on a non-`ws`/`wss` scheme, user info, an
/// `.onion` host, a resolution failure, an empty answer, or an
/// address class the flags do not admit.
pub(crate) async fn resolve(url: &str, allow_private: bool) -> Result<Target, SyncError> {
    // Never echo the raw URL into an error: it may carry credentials
    // or junk. `url::ParseError` messages are fixed strings.
    let parsed =
        Url::parse(url).map_err(|err| SyncError::Url(format!("invalid peer URL: {err}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(SyncError::Url(
            "user info in the peer URL is refused".to_owned(),
        ));
    }
    let tls = match parsed.scheme() {
        "ws" => false,
        "wss" => true,
        scheme => {
            return Err(SyncError::Url(format!(
                "unsupported scheme {scheme:?}: only ws:// and wss:// are allowed"
            )));
        }
    };
    let Some(host) = parsed.host_str().map(str::to_owned) else {
        return Err(SyncError::Url("the peer URL has no host".to_owned()));
    };
    let onion = host.trim_end_matches('.');
    if onion.eq_ignore_ascii_case("onion") || onion.to_ascii_lowercase().ends_with(".onion") {
        return Err(SyncError::Url(
            "onion dialing is not supported yet (a follow-up adds it)".to_owned(),
        ));
    }
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| SyncError::Url("the peer URL has no port".to_owned()))?;
    let literal = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
        _ => None,
    };
    let addrs: Vec<SocketAddr> = match literal {
        Some(ip) => vec![SocketAddr::new(ip, port)],
        None => tokio::net::lookup_host(format!("{host}:{port}"))
            .await
            .map_err(|err| SyncError::Url(format!("could not resolve {host:?}: {err}")))?
            .collect(),
    };
    if addrs.is_empty() {
        return Err(SyncError::Url(format!("{host:?} resolved to no addresses")));
    }
    for addr in &addrs {
        match classify(addr.ip()) {
            Scope::Global => {}
            Scope::Private if allow_private => {}
            Scope::Private => {
                return Err(SyncError::Url(format!(
                    "refusing private address {}; pass --allow-private",
                    addr.ip()
                )));
            }
            Scope::Forbidden => {
                return Err(SyncError::Url(format!(
                    "refusing non-routable address {}",
                    addr.ip()
                )));
            }
        }
    }
    Ok(Target {
        url: parsed,
        host,
        tls,
        addrs,
    })
}

/// A dialed byte stream, TLS or plain. Everything downstream is
/// generic over `AsyncRead + AsyncWrite`.
#[derive(Debug)]
pub(crate) enum Stream {
    /// `ws://`.
    Plain(TcpStream),
    /// `wss://` — boxed so the enum stays small.
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Tls(s) => Pin::new(&mut **s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            Self::Tls(s) => s.is_write_vectored(),
        }
    }
}

/// The Mozilla root store for `wss://` verification.
fn tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// Connect to the vetted addresses in order, `TCP_NODELAY` on, TLS
/// with SNI when `target.tls`. The last failure is returned.
///
/// # Errors
///
/// `io::Error` when every address fails to connect within `timeout`
/// (in total, not per address) or the TLS handshake fails.
pub(crate) async fn dial(target: &Target, timeout: Duration) -> io::Result<Stream> {
    let tcp = tokio::time::timeout(timeout, async {
        let mut last = io::Error::new(io::ErrorKind::HostUnreachable, "no addresses");
        for addr in &target.addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(err) => last = err,
            }
        }
        Err(last)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
    tcp.set_nodelay(true)?;
    if !target.tls {
        return Ok(Stream::Plain(tcp));
    }
    let Some(host) = target.url.host() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "URL has no host",
        ));
    };
    let name = server_name(&host)?;
    let tls = tokio::time::timeout(timeout, TlsConnector::from(tls_config()).connect(name, tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
    Ok(Stream::Tls(Box::new(tls)))
}

/// The TLS server name: IP literals verify against the certificate's
/// IP SANs and DNS names against DNS SANs — `ServerName::try_from` on
/// a `host_str()` string rejects IP literals like `::1` (and its
/// bracketed `[::1]` form outright), so build the name from the
/// parsed `url::Host` instead.
fn server_name<S: AsRef<str>>(host: &url::Host<S>) -> Result<ServerName<'static>, io::Error> {
    match host {
        url::Host::Ipv4(ip) => Ok(ServerName::IpAddress((*ip).into())),
        url::Host::Ipv6(ip) => Ok(ServerName::IpAddress((*ip).into())),
        url::Host::Domain(name) => ServerName::try_from(name.as_ref().to_owned()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DNS server name {:?}: {err}", name.as_ref()),
            )
        }),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Scope {
        classify(IpAddr::V4(s.parse().unwrap()))
    }

    fn v6(s: &str) -> Scope {
        classify(IpAddr::V6(s.parse().unwrap()))
    }

    #[test]
    fn v4_classification() {
        assert_eq!(v4("8.8.8.8"), Scope::Global);
        // Forbidden.
        for ip in [
            "0.0.0.0",
            "0.1.2.3", // 0.0.0.0/8
            "255.255.255.255",
            "240.1.2.3",
            "245.9.9.9", // 240.0.0.0/4
            "224.0.0.1",
            "239.1.2.3", // multicast
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1", // documentation ranges
        ] {
            assert_eq!(v4(ip), Scope::Forbidden, "{ip}");
        }
        // Private.
        for ip in [
            "127.0.0.1",
            "127.255.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "198.19.255.1",
        ] {
            assert_eq!(v4(ip), Scope::Private, "{ip}");
        }
        // Edges stay global.
        for ip in [
            "100.63.255.255",
            "100.128.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.0.1.1",
            "192.0.3.1",
            "198.17.0.1",
            "198.20.0.1",
            "223.255.255.255",
        ] {
            assert_eq!(v4(ip), Scope::Global, "{ip}");
        }
    }

    #[test]
    fn v6_classification() {
        // Forbidden.
        for ip in ["::", "ff02::1", "2001:db8::1", "2001:db8:ffff::1"] {
            assert_eq!(v6(ip), Scope::Forbidden, "{ip}");
        }
        for ip in ["::1", "fc00::1", "fd12:3456::1", "fe80::1", "febf::ffff"] {
            assert_eq!(v6(ip), Scope::Private, "{ip}");
        }
        assert_eq!(v6("2001:db9::1"), Scope::Global); // past the doc /32
        // v4-embedded forms classify by the embedded v4: mapped,
        // compatible, NAT64 64:ff9b::/96, 6to4 2002::/16.
        assert_eq!(v6("::ffff:127.0.0.1"), Scope::Private);
        assert_eq!(v6("::ffff:8.8.8.8"), Scope::Global);
        assert_eq!(v6("::ffff:0.0.0.0"), Scope::Forbidden);
        assert_eq!(v6("::ffff:224.0.0.1"), Scope::Forbidden);
        assert_eq!(v6("::ffff:100.64.0.1"), Scope::Private);
        assert_eq!(v6("::8.8.8.8"), Scope::Global);
        assert_eq!(v6("::127.0.0.1"), Scope::Private);
        assert_eq!(v6("::224.0.0.1"), Scope::Forbidden);
        assert_eq!(v6("64:ff9b::8.8.8.8"), Scope::Global);
        assert_eq!(v6("64:ff9b::10.0.0.1"), Scope::Private);
        assert_eq!(v6("2002:808:808::"), Scope::Global); // embeds 8.8.8.8
        assert_eq!(v6("2002:a00:1::"), Scope::Private); // embeds 10.0.0.1
    }

    #[test]
    fn server_name_classifies_hosts() {
        fn sn(url: &str) -> ServerName<'static> {
            let parsed = Url::parse(url).unwrap();
            let host = parsed.host().unwrap();
            server_name(&host).unwrap()
        }
        assert!(matches!(sn("wss://127.0.0.1"), ServerName::IpAddress(_)));
        assert!(matches!(sn("wss://[::1]:7777"), ServerName::IpAddress(_)));
        assert!(matches!(
            sn("wss://relay.example.com"),
            ServerName::DnsName(_)
        ));
    }

    #[tokio::test]
    async fn resolve_refuses_url_shapes() {
        for (url, want) in [
            ("http://relay.example.com", "scheme"),
            ("ws://user:pw@relay.example.com", "user info"),
            ("ws://relay.onion", "onion"),
            ("ws://abcxyz.onion:8080", "onion"),
            ("wss://RELAY.ONION.", "onion"), // trailing dot fails .onion suffix? — see below
        ] {
            let err = resolve(url, true).await.err().unwrap().to_string();
            assert!(err.contains(want), "{url} → {err}");
        }
    }

    #[tokio::test]
    async fn resolve_ip_literals() {
        // Loopback literal needs --allow-private.
        assert!(resolve("ws://127.0.0.1:7777", false).await.is_err());
        let target = resolve("ws://127.0.0.1:7777", true).await.unwrap();
        assert_eq!(target.addrs, vec!["127.0.0.1:7777".parse().unwrap()]);
        assert!(!target.tls);
        assert_eq!(target.host, "127.0.0.1");
        // v6 literal.
        let v6 = resolve("wss://[::1]", true).await.unwrap();
        assert!(v6.tls);
        assert_eq!(v6.addrs, vec!["[::1]:443".parse().unwrap()]);
        // A global literal needs no flag.
        assert!(resolve("ws://8.8.8.8:80", false).await.is_ok());
        // Unspecified and multicast are refused even with the flag.
        assert!(resolve("ws://0.0.0.0:80", true).await.is_err());
        assert!(resolve("ws://224.0.0.1:80", true).await.is_err());
        assert!(resolve("ws://[::]:80", true).await.is_err());
    }
}
