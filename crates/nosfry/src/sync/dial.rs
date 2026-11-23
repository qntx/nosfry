//! Resolve and vet a peer URL, then dial it into a byte stream.
//!
//! Three routes plug into the same seam: everything after
//! [`Dialer::dial`] is generic over `S: AsyncRead + AsyncWrite`.
//! `ws://`/`wss://` dial vetted TCP addresses; a `.onion` host never
//! resolves over clearnet DNS — that would leak the address — and
//! needs the `onion` cargo feature: then only `ws://` (the circuit
//! already encrypts and authenticates the service) with a v3
//! address as the label before `.onion` is admitted, and
//! `Route::Onion` is dialed through the embedded Arti client.
//! `iroh:<dial address>` (the `iroh` cargo feature) needs no
//! resolution at all: the endpoint id names the peer, and
//! `Route::Iroh` dials a QUIC connection on the run's shared
//! ephemeral endpoint. User info is refused (it would leak into
//! logs) and a `.iroh` host is refused outright — it is an iroh
//! endpoint name, not a DNS host. Every resolved TCP address must
//! be globally routable unless `--allow-private` admits loopback,
//! RFC 1918, CGNAT, link-local and unique-local addresses;
//! unspecified, multicast and broadcast addresses are always
//! refused. The flag does not apply to `iroh:` — nothing about
//! that route is IP-vetted.

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
#[cfg(feature = "iroh")]
use super::iroh;
#[cfg(feature = "onion")]
use super::tor;

/// A resolved, vetted dial target: the parsed URL plus the route the
/// connection must take (no second resolution happens).
#[derive(Debug)]
pub(crate) struct Target {
    /// The URL the WebSocket handshake and NIP-11 read — the parsed
    /// peer URL, or the iroh listener's `ws://<z32>.iroh` alias.
    pub(crate) url: Url,
    /// The relay name the AUTH `relay` tag carries: the peer URL as
    /// given, or the iroh listener's alias.
    pub(crate) name: String,
    /// Host for SNI and the `Host` header (no port).
    pub(crate) host: String,
    /// Whether to wrap the stream in TLS (`wss://`).
    pub(crate) tls: bool,
    /// How to reach the peer.
    pub(crate) route: Route,
}

/// How a vetted target is reached.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// Vetted clearnet addresses, in resolution order.
    Tcp(Vec<SocketAddr>),
    /// An embedded onion service, dialed through Arti — never a
    /// clearnet lookup (the `onion` cargo feature).
    #[cfg(feature = "onion")]
    Onion,
    /// An iroh endpoint, dialed on the run's shared ephemeral
    /// endpoint (the `iroh` cargo feature).
    #[cfg(feature = "iroh")]
    Iroh(crate::iroh::DialAddr),
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

/// `.onion` hosts without the `onion` feature: refuse, naming it.
/// A clearnet lookup must never happen for one — it would leak the
/// address — so this runs before any resolution.
#[cfg(not(feature = "onion"))]
fn resolve_onion(_: &Url, _: String, _: String) -> Result<Target, SyncError> {
    Err(SyncError::Url(
        "onion URLs need nosfry built with the `onion` cargo feature".to_owned(),
    ))
}

/// An `.onion` target: `ws://` only (the circuit already encrypts
/// and authenticates the service) and the label before `.onion` must
/// be a v3 address — 56 base32 characters, any subdomain labels
/// before it kept for Tor's vhosting. Never a DNS lookup.
#[cfg(feature = "onion")]
fn resolve_onion(parsed: &Url, host: String, name: String) -> Result<Target, SyncError> {
    if parsed.scheme() != "ws" {
        return Err(SyncError::Url(
            "refusing wss:// for an onion service: the circuit already encrypts \
             and authenticates it; use ws://"
                .to_owned(),
        ));
    }
    let label = host
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .strip_suffix(".onion")
        .and_then(|rest| rest.rsplit('.').next().map(str::to_owned));
    let valid = label.is_some_and(|label| {
        label.len() == 56
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    });
    if !valid {
        return Err(SyncError::Url(
            "the label before .onion must be a v3 address (56 base32 characters)".to_owned(),
        ));
    }
    if parsed.port_or_known_default().is_none() {
        return Err(SyncError::Url("the peer URL has no port".to_owned()));
    }
    Ok(Target {
        url: parsed.clone(),
        name,
        host,
        tls: false,
        route: Route::Onion,
    })
}

/// `iroh:` URLs without the `iroh` feature: refuse, naming it.
#[cfg(not(feature = "iroh"))]
fn resolve_iroh(_: &str) -> Result<Target, SyncError> {
    Err(SyncError::Url(
        "iroh peer URLs need nosfry built with the iroh cargo feature \
         (cargo install nosfry --features iroh)"
            .to_owned(),
    ))
}

/// The `iroh:` route: parse the dial address — no resolution, no
/// I/O. The endpoint id names the peer, so the target's URL is the
/// listener's `ws://<z32>.iroh` alias: the name the relay knows
/// itself by, which is what the HTTP layer and the AUTH `relay`
/// tag need.
#[cfg(feature = "iroh")]
fn resolve_iroh(dial_text: &str) -> Result<Target, SyncError> {
    let dial = dial_text
        .parse::<crate::iroh::DialAddr>()
        .map_err(SyncError::Url)?;
    let name = crate::iroh::alias(dial.id.as_bytes());
    let url = Url::parse(&name)
        .map_err(|err| SyncError::Url(format!("the iroh alias is not a URL: {err}")))?;
    let host = crate::iroh::z32(dial.id.as_bytes());
    Ok(Target {
        url,
        name,
        host: format!("{host}.iroh"),
        tls: false,
        route: Route::Iroh(dial),
    })
}

/// Parse `url`, resolve it, and vet every address — or, on `iroh:`,
/// parse the dial address. Errors name the rule that fired.
///
/// # Errors
///
/// [`SyncError::Url`] on a non-`ws`/`wss` scheme, user info, an
/// `.onion` host or `iroh:` URL the build cannot dial, a `.iroh`
/// host, a malformed `iroh:` dial address, a resolution failure, an
/// empty answer, or an address class the flags do not admit.
pub(crate) async fn resolve(url: &str, allow_private: bool) -> Result<Target, SyncError> {
    if let Some(dial_text) = url.strip_prefix(IROH_SCHEME) {
        return resolve_iroh(dial_text);
    }
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
    let bare = host.trim_end_matches('.').to_ascii_lowercase();
    // The last dot-label: `onion`/`*.onion` and `iroh`/`*.iroh`
    // alike.
    let tld = bare.rsplit('.').next().unwrap_or_default();
    if tld == "onion" {
        return resolve_onion(&parsed, host, url.to_owned());
    }
    if tld == "iroh" {
        return Err(SyncError::Url(
            "a .iroh name is an iroh endpoint, not a DNS host: \
             dial it as iroh:<endpoint-id>"
                .to_owned(),
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
        name: url.to_owned(),
        host,
        tls,
        route: Route::Tcp(addrs),
    })
}

/// The `iroh:` peer-URL prefix (`iroh:<dial address>`).
const IROH_SCHEME: &str = "iroh:";

/// A dialed byte stream, TLS, plain, over Tor, or over iroh.
/// Everything downstream is generic over `AsyncRead + AsyncWrite`.
#[derive(Debug)]
pub(crate) enum Stream {
    /// `ws://`.
    Plain(TcpStream),
    /// `wss://` — boxed so the enum stays small.
    Tls(Box<TlsStream<TcpStream>>),
    /// `ws://<v3>.onion` — Arti's stream, boxed like `Tls`.
    #[cfg(feature = "onion")]
    Onion(Box<arti_client::DataStream>),
    /// `iroh:<dial>` — one bidirectional stream on the run's
    /// connection.
    #[cfg(feature = "iroh")]
    Iroh(crate::iroh::BiStream),
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
            #[cfg(feature = "onion")]
            Self::Onion(s) => Pin::new(&mut **s).poll_read(cx, buf),
            #[cfg(feature = "iroh")]
            Self::Iroh(s) => Pin::new(s).poll_read(cx, buf),
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
            #[cfg(feature = "onion")]
            Self::Onion(s) => Pin::new(&mut **s).poll_write(cx, buf),
            #[cfg(feature = "iroh")]
            Self::Iroh(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
            #[cfg(feature = "onion")]
            Self::Onion(s) => Pin::new(&mut **s).poll_flush(cx),
            #[cfg(feature = "iroh")]
            Self::Iroh(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
            #[cfg(feature = "onion")]
            Self::Onion(s) => Pin::new(&mut **s).poll_shutdown(cx),
            #[cfg(feature = "iroh")]
            Self::Iroh(s) => Pin::new(s).poll_shutdown(cx),
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
            #[cfg(feature = "onion")]
            Self::Onion(s) => Pin::new(&mut **s).poll_write_vectored(cx, bufs),
            #[cfg(feature = "iroh")]
            Self::Iroh(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            Self::Tls(s) => s.is_write_vectored(),
            #[cfg(feature = "onion")]
            Self::Onion(s) => s.is_write_vectored(),
            #[cfg(feature = "iroh")]
            Self::Iroh(_) => false,
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

/// One `sync` run's dialer: clearnet targets direct, `.onion`
/// targets over a single Arti client bootstrapped on first use and
/// `iroh:` targets over a single ephemeral endpoint connected on
/// first use — the transports the run lazily creates are shared by
/// both connections of the run (NIP-11, then the WebSocket) and
/// closed by `Dialer::close` (iroh builds only).
pub(crate) struct Dialer<'a> {
    /// `[relay]` — the lazy transports read their sections on first
    /// dial (`relay.onion`, `relay.iroh`).
    relay: &'a crate::config::Relay,
    /// The lazily bootstrapped Tor client; a failed bootstrap leaves
    /// the cell empty so the next dial retries it.
    #[cfg(feature = "onion")]
    tor: tokio::sync::OnceCell<Arc<crate::onion::Client>>,
    /// The lazily bound endpoint and its connection to the peer; a
    /// failed connect leaves the cell empty so the next dial
    /// retries it.
    #[cfg(feature = "iroh")]
    link: tokio::sync::OnceCell<(::iroh::Endpoint, ::iroh::endpoint::Connection)>,
}

// `TorClient` and `iroh::Endpoint` have no `Debug`; show each lazy
// transport's config and whether it exists.
impl std::fmt::Debug for Dialer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Dialer");
        #[cfg(feature = "onion")]
        d.field("onion", &self.relay.onion)
            .field("tor_bootstrapped", &self.tor.initialized());
        #[cfg(feature = "iroh")]
        d.field("iroh", &self.relay.iroh)
            .field("iroh_connected", &self.link.initialized());
        d.finish()
    }
}

impl<'a> Dialer<'a> {
    /// A dialer for one `sync` run: `.onion` targets ride the Arti
    /// state under `relay.onion.state_dir` — the same `state/`/`cache/`
    /// pair the relay's onion listeners use (see `tor`'s module
    /// docs) — and `iroh:` targets an ephemeral endpoint configured
    /// by `[relay.iroh]` (see `sync::iroh`'s module docs). Both are
    /// created on first use.
    pub(crate) const fn new(relay: &'a crate::config::Relay) -> Self {
        Self {
            relay,
            #[cfg(feature = "onion")]
            tor: tokio::sync::OnceCell::const_new(),
            #[cfg(feature = "iroh")]
            link: tokio::sync::OnceCell::const_new(),
        }
    }

    /// Dial the vetted target into a byte stream.
    ///
    /// # Errors
    ///
    /// [`SyncError::Connect`] when every candidate fails within
    /// `timeout`, the TLS handshake fails, or the lazy transport —
    /// Tor client bootstrap, iroh endpoint connect — fails.
    pub(crate) async fn dial(
        &self,
        target: &Target,
        timeout: Duration,
    ) -> Result<Stream, SyncError> {
        // `relay` is only read by the feature-gated routes.
        #[cfg(not(any(feature = "onion", feature = "iroh")))]
        let _ = self.relay;
        match &target.route {
            Route::Tcp(addrs) => dial_tcp(target, addrs, timeout)
                .await
                .map_err(|err| SyncError::Connect(err.to_string())),
            #[cfg(feature = "onion")]
            Route::Onion => {
                let client = self
                    .tor
                    .get_or_try_init(|| tor::client(&self.relay.onion))
                    .await?;
                let port = target.url.port_or_known_default().unwrap_or(80);
                let stream = tor::connect(client, target.host.clone(), port, timeout).await?;
                Ok(Stream::Onion(Box::new(stream)))
            }
            #[cfg(feature = "iroh")]
            Route::Iroh(dial) => {
                let (_, connection) = self
                    .link
                    .get_or_try_init(|| iroh::connect(&self.relay.iroh, dial, timeout))
                    .await?;
                Ok(Stream::Iroh(iroh::open(connection, timeout).await?))
            }
        }
    }

    /// Close the run's iroh endpoint, if a dial created one —
    /// bounded, so a stalled close cannot hang the command. A
    /// no-op when no iroh dial happened.
    #[cfg(feature = "iroh")]
    pub(crate) async fn close(self) {
        if let Some((endpoint, _)) = self.link.into_inner() {
            iroh::close(endpoint).await;
        }
    }
}

/// Connect to the vetted addresses in order, `TCP_NODELAY` on, TLS
/// with SNI when `target.tls`. The last failure is returned.
///
/// # Errors
///
/// `io::Error` when every address fails to connect within `timeout`
/// (in total, not per address) or the TLS handshake fails.
async fn dial_tcp(target: &Target, addrs: &[SocketAddr], timeout: Duration) -> io::Result<Stream> {
    let tcp = tokio::time::timeout(timeout, async {
        let mut last = io::Error::new(io::ErrorKind::HostUnreachable, "no addresses");
        for addr in addrs {
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
            // A `.iroh` host is refused in every build.
            ("ws://abcxyz.iroh", "iroh:<endpoint-id>"),
            ("ws://ABCXYZ.IROH.", "iroh:<endpoint-id>"),
            ("wss://relay.iroh:8080", "iroh:<endpoint-id>"),
            ("ws://iroh", "iroh:<endpoint-id>"),
        ] {
            let err = resolve(url, true).await.err().unwrap().to_string();
            assert!(err.contains(want), "{url} → {err}");
        }
        // `iroh:` itself: feature builds reject a malformed dial
        // address before touching the network, feature-less builds
        // name the flag.
        let err = resolve("iroh:not-a-dial-address", true)
            .await
            .err()
            .unwrap()
            .to_string();
        #[cfg(feature = "iroh")]
        assert!(err.contains("endpoint id"), "{err}");
        #[cfg(not(feature = "iroh"))]
        assert!(err.contains("iroh cargo feature"), "{err}");
    }

    /// `iroh:<z32>` resolves without any I/O to the `Route::Iroh`
    /// target named by the listener's `ws://<z32>.iroh` alias.
    #[cfg(feature = "iroh")]
    #[tokio::test]
    async fn resolve_iroh_targets() {
        let id = ::iroh::SecretKey::generate().public();
        let z = crate::iroh::z32(id.as_bytes());
        for url in [
            format!("iroh:{z}"),
            format!("iroh:{z}@127.0.0.1:7777"),
            format!("iroh:{z}@https://relay.example.com"),
        ] {
            let target = resolve(&url, false).await.unwrap();
            assert_iroh_target(&target, &url, id);
        }
        // --allow-private changes nothing on this route.
        let target = resolve(&format!("iroh:{z}"), true).await.unwrap();
        assert!(matches!(target.route, Route::Iroh(_)));
    }

    /// One `iroh:` dial must land on `Route::Iroh` for the parsed
    /// endpoint id, addressed by its `ws://<z32>.iroh` alias.
    #[cfg(feature = "iroh")]
    fn assert_iroh_target(target: &Target, url: &str, id: ::iroh::PublicKey) {
        let Route::Iroh(dial) = &target.route else {
            panic!("expected an iroh target for {url}");
        };
        let z = crate::iroh::z32(id.as_bytes());
        assert_eq!(dial.id, id, "{url}");
        assert_eq!(target.name, format!("ws://{z}.iroh"), "{url}");
        assert_eq!(target.url.as_str(), format!("ws://{z}.iroh/"), "{url}");
        assert_eq!(target.host, format!("{z}.iroh"), "{url}");
        assert!(!target.tls, "{url}");
    }

    #[cfg(not(feature = "onion"))]
    #[tokio::test]
    async fn resolve_onion_needs_the_feature() {
        for url in [
            "ws://onion",
            "ws://relay.onion",
            "ws://abcxyz.onion:8080",
            "wss://RELAY.ONION.",
        ] {
            let err = resolve(url, true).await.err().unwrap().to_string();
            assert!(err.contains("`onion` cargo feature"), "{url} → {err}");
        }
    }

    #[cfg(feature = "onion")]
    #[tokio::test]
    async fn resolve_onion_targets() {
        // A valid v3 host routes over Arti: default and explicit
        // port, uppercase, and a subdomain label (Tor vhosting).
        let v3 = "a".repeat(56);
        for url in [
            format!("ws://{v3}.onion"),
            format!("ws://{v3}.onion:8080"),
            format!("ws://{}.ONION", v3.to_ascii_uppercase()),
            format!("ws://sub.{v3}.onion"),
        ] {
            let target = resolve(&url, false).await.unwrap();
            assert!(matches!(target.route, Route::Onion), "{url}");
            assert!(!target.tls, "{url}");
        }
        let target = resolve(&format!("ws://{v3}.onion"), false).await.unwrap();
        assert_eq!(target.host, format!("{v3}.onion"));
        for (url, want) in [
            // wss adds nothing: the circuit authenticates the service.
            (format!("wss://{v3}.onion"), "wss"),
            // A short or invalid label is not a v3 address.
            ("ws://onion".to_owned(), "v3"),
            ("ws://abcxyz.onion".to_owned(), "v3"),
            ("ws://relay.onion".to_owned(), "v3"),
            (format!("ws://{}.onion", "0".repeat(56)), "v3"),
        ] {
            let err = resolve(&url, true).await.err().unwrap().to_string();
            assert!(err.contains(want), "{url} → {err}");
        }
    }

    /// `state_dir::prepare` refuses a state dir group/others can
    /// read — the `Dialer` surfaces it as `SyncError` before the
    /// client is built or any network work happens.
    #[cfg(all(feature = "onion", unix))]
    #[tokio::test]
    async fn dialer_refuses_an_open_state_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let mut relay = crate::config::Relay::default();
        relay.onion.state_dir = dir.path().join("state");
        std::fs::create_dir(&relay.onion.state_dir).unwrap();
        std::fs::set_permissions(
            &relay.onion.state_dir,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let target = resolve(&format!("ws://{}.onion", "a".repeat(56)), false)
            .await
            .unwrap();
        let err = Dialer::new(&relay)
            .dial(&target, Duration::from_secs(5))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("mode 755"), "{err}");
    }

    #[tokio::test]
    async fn resolve_ip_literals() {
        // Loopback literal needs --allow-private.
        assert!(resolve("ws://127.0.0.1:7777", false).await.is_err());
        let target = resolve("ws://127.0.0.1:7777", true).await.unwrap();
        assert_eq!(
            target.route,
            Route::Tcp(vec!["127.0.0.1:7777".parse().unwrap()])
        );
        assert!(!target.tls);
        assert_eq!(target.host, "127.0.0.1");
        // v6 literal.
        let v6 = resolve("wss://[::1]", true).await.unwrap();
        assert!(v6.tls);
        assert_eq!(v6.route, Route::Tcp(vec!["[::1]:443".parse().unwrap()]));
        // A global literal needs no flag.
        assert!(resolve("ws://8.8.8.8:80", false).await.is_ok());
        // Unspecified and multicast are refused even with the flag.
        assert!(resolve("ws://0.0.0.0:80", true).await.is_err());
        assert!(resolve("ws://224.0.0.1:80", true).await.is_err());
        assert!(resolve("ws://[::]:80", true).await.is_err());
    }
}
