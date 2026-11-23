//! Embedded iroh listeners (cargo feature `iroh`).
//!
//! Every `iroh:<nickname>` listener binds an iroh endpoint: a QUIC
//! transport that dials peers by public key and punches through
//! NATs, with relay servers as the fallback — the way a relay
//! without a public IP stays reachable. Each accepted bidirectional
//! stream carries one plain HTTP/1.1 connection and enters the same
//! HTTP/WebSocket path a TCP listener uses; the peer is the remote
//! endpoint id the QUIC handshake authenticated.
//!
//! iroh's own machinery reconnects dropped relay connections on a
//! capped exponential backoff (`RelayActor::run` in
//! `iroh/src/socket/transports/relay/actor.rs`), so the listener
//! only reports connectivity through `nosfry_iroh_relay_connected`
//! and never retries itself.

use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use crate::ServerError;
use crate::config::{Config, Iroh, IrohAddressLookup, IrohRelayMode, ListenAddress};

pub mod connect;
pub(crate) mod listen;

pub(crate) use listen::{Bound, accept, supervise};

/// The ALPN every nosfry iroh endpoint offers and requires: one
/// bidirectional QUIC stream carries one HTTP/1.1 connection.
pub const ALPN: &[u8] = b"nosfry/http/1";

/// A QUIC bidirectional stream pair viewed as one byte stream:
/// `poll_read` delegates to the receive half, the write side to the
/// send half, so a peer's FIN (its send-side shutdown) propagates
/// exactly like a TCP half-close and our shutdown sends FIN.
/// Listeners serve it, the sync dialer and the `connect` gateway
/// write it.
#[derive(Debug)]
pub(crate) struct BiStream {
    /// Receive half.
    pub(crate) recv: iroh::endpoint::RecvStream,
    /// Send half.
    pub(crate) send: iroh::endpoint::SendStream,
}

impl tokio::io::AsyncRead for BiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

/// The selected path's kind label — `"direct"` or `"relay"` — or
/// `None` while no path is selected yet. Listeners pin the
/// `nosfry_iroh_connections` `path` label to it; the `connect`
/// gateway logs it.
pub(crate) fn selected_path(conn: &iroh::endpoint::Connection) -> Option<&'static str> {
    conn.paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map(|path| if path.is_relay() { "relay" } else { "direct" })
}

impl tokio::io::AsyncWrite for BiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

/// The endpoint id's z-base-32 text (the pkarr encoding).
///
/// Peer names (`iroh:<z32>`) and relay names (`ws://<z32>.iroh`)
/// build on it. The 32 bytes always come from a TLS-authenticated
/// endpoint id; anything else displays hex rather than nothing.
#[must_use]
pub fn z32(id: &[u8; 32]) -> String {
    iroh::PublicKey::from_bytes(id).map_or_else(|_| faster_hex::hex_string(id), |key| key.to_z32())
}

/// The `ws://` URL nosfry names an iroh listener by.
///
/// There is no standard URL form for an iroh endpoint, so the
/// endpoint id's z32 text sits in the host position under a `.iroh`
/// suffix. `.iroh` is not a delegated top-level domain today: a DNS
/// lookup of the name fails (and would hand the endpoint id to the
/// resolver), so the name only ever travels through iroh-aware
/// paths — a mark no clearnet dialer should resolve.
#[must_use]
pub fn alias(id: &[u8; 32]) -> String {
    format!("ws://{}.iroh", z32(id))
}

/// A parsed dial address: `<endpoint-id>` plus hints.
///
/// The id is its z-base-32 (52 chars) or hex (64) form, optionally
/// followed by `@` and comma-separated hints — an `ip:port` socket
/// address or an `http(s)://` relay URL each. This is the form
/// `nosfry sync iroh:…` and `nosfry connect` take, and the form
/// `supervise` logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialAddr {
    /// The endpoint to connect to.
    pub id: iroh::EndpointId,
    /// Extra reachability hints: direct sockets and relay URLs.
    pub hints: Vec<Hint>,
}

/// One reachability hint in a [`DialAddr`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hint {
    /// A direct `ip:port` socket address.
    Ip(SocketAddr),
    /// A relay server the endpoint is or may be reachable through.
    Relay(iroh::RelayUrl),
}

impl std::fmt::Display for Hint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => addr.fmt(f),
            Self::Relay(url) => url.fmt(f),
        }
    }
}

impl Hint {
    /// One comma-separated hint: `ip:port` first (unambiguous, a URL
    /// always has `://`), else an `http(s)://` relay URL.
    fn parse(value: &str) -> Result<Self, String> {
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(Self::Ip(addr));
        }
        if let Ok(url) = value.parse::<iroh::RelayUrl>()
            && matches!(url::Url::from(url.clone()).scheme(), "http" | "https")
        {
            return Ok(Self::Relay(url));
        }
        Err(format!(
            "hint {value:?} is neither an ip:port socket address nor \
             an http(s):// relay URL"
        ))
    }
}

/// The longest input an error echoes: enough to spot which address
/// was mistyped, never enough to fill a log line.
const TRUNCATE: usize = 24;

/// `value` cut to [`TRUNCATE`] characters for error messages.
fn truncate(value: &str) -> String {
    if value.chars().count() <= TRUNCATE {
        return value.to_owned();
    }
    format!("{}…", value.chars().take(TRUNCATE).collect::<String>())
}

impl FromStr for DialAddr {
    type Err = String;

    /// `<endpoint-id>[@<hint>[,<hint>]…]`; the error names the rule
    /// and echoes at most `TRUNCATE` characters of the input.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (id, hints) = match s.split_once('@') {
            Some((id, hints)) => (id, Some(hints)),
            None => (s, None),
        };
        let id = if id.len() == 52 {
            iroh::EndpointId::from_z32(id).map_err(|_| {
                format!(
                    "dial address {:?}: endpoint id is not 52-character z-base-32",
                    truncate(s)
                )
            })?
        } else {
            id.parse::<iroh::EndpointId>().map_err(|_| {
                format!(
                    "dial address {:?}: endpoint id must be 52-character z-base-32 \
                     or 64-character hex",
                    truncate(s)
                )
            })?
        };
        let mut parsed = Vec::new();
        if let Some(hints) = hints {
            for hint in hints.split(',') {
                parsed.push(
                    Hint::parse(hint)
                        .map_err(|err| format!("dial address {:?}: {err}", truncate(s)))?,
                );
            }
        }
        Ok(Self { id, hints: parsed })
    }
}

/// The dialable form: the z32 id, then `@` and the comma-joined
/// hints when there are any.
impl std::fmt::Display for DialAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        z32(self.id.as_bytes()).fmt(f)?;
        if !self.hints.is_empty() {
            f.write_str("@")?;
            let mut hints = self.hints.iter();
            if let Some(first) = hints.next() {
                first.fmt(f)?;
            }
            for hint in hints {
                write!(f, ",{hint}")?;
            }
        }
        Ok(())
    }
}

impl From<&iroh::EndpointAddr> for DialAddr {
    /// The dial address form of what [`iroh::Endpoint::addr`] or its
    /// watcher reports: the id plus every transport address as a
    /// hint.
    fn from(addr: &iroh::EndpointAddr) -> Self {
        let hints = addr
            .addrs
            .iter()
            .filter_map(|transport| match transport {
                iroh::TransportAddr::Ip(socket) => Some(Hint::Ip(*socket)),
                iroh::TransportAddr::Relay(url) => Some(Hint::Relay(url.clone())),
                _ => None,
            })
            .collect();
        Self { id: addr.id, hints }
    }
}

impl DialAddr {
    /// The [`iroh::EndpointAddr`] a dialer connects with: the id and
    /// every hint, plus — under `relay_mode = "custom"` — every
    /// configured relay URL, so the id alone reaches the peer
    /// through the operator's relay.
    #[must_use]
    pub fn to_endpoint_addr(&self, cfg: &Iroh) -> iroh::EndpointAddr {
        let mut addr = iroh::EndpointAddr::new(self.id);
        for hint in &self.hints {
            addr = match hint {
                Hint::Ip(socket) => addr.with_ip_addr(*socket),
                Hint::Relay(url) => addr.with_relay_url(url.clone()),
            };
        }
        if cfg.relay_mode == IrohRelayMode::Custom {
            for url in cfg
                .relay_urls
                .iter()
                .filter_map(|entry| entry.parse::<iroh::RelayUrl>().ok())
            {
                addr = addr.with_relay_url(url);
            }
        }
        addr
    }
}

/// The endpoint builder the listeners and the dialers share:
/// [`iroh::endpoint::presets::Minimal`] (the ring crypto provider),
/// the configured relay mode and address-lookup services, the
/// [`ALPN`], and the QUIC stream caps — `max_streams_per_connection`
/// bidirectional, no unidirectional streams.
pub(crate) fn builder(cfg: &Iroh) -> iroh::endpoint::Builder {
    let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal);
    builder = match cfg.relay_mode {
        IrohRelayMode::N0 => builder.relay_mode(iroh::RelayMode::Default),
        IrohRelayMode::Custom => builder.relay_mode(iroh::RelayMode::custom(
            cfg.relay_urls
                .iter()
                .filter_map(|entry| entry.parse::<iroh::RelayUrl>().ok()),
        )),
        IrohRelayMode::Disabled => builder.relay_mode(iroh::RelayMode::Disabled),
    };
    if cfg.address_lookup == IrohAddressLookup::N0 {
        // The same three services `presets::N0` adds.
        builder = builder
            .address_lookup(iroh::address_lookup::PkarrPublisher::n0_dns())
            .address_lookup(iroh::address_lookup::PkarrResolver::n0_dns())
            .address_lookup(iroh::address_lookup::DnsAddressLookup::n0_dns());
    }
    builder.alpns(vec![ALPN.to_vec()]).transport_config(
        iroh::endpoint::QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(cfg.max_streams_per_connection.into())
            .max_concurrent_uni_streams(0_u32.into())
            .build(),
    )
}

/// The listener's persistent secret key at
/// `<state_dir>/<nickname>.key`: 32 raw bytes, created `0600` on
/// first use, loaded afterwards. A file of any other length is an
/// error and never overwritten — it is the endpoint's identity.
fn secret_key(cfg: &Iroh, nickname: &str) -> Result<iroh::SecretKey, ServerError> {
    let path = cfg.state_dir.join(format!("{nickname}.key"));
    match std::fs::read(&path) {
        Ok(bytes) => {
            let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                ServerError::Iroh(format!(
                    "iroh key file {} must be exactly 32 bytes; \
                     move it away to mint a new endpoint id",
                    path.display()
                ))
            })?;
            Ok(iroh::SecretKey::from_bytes(&bytes))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let key = iroh::SecretKey::generate();
            write_key(&path, &key)?;
            Ok(key)
        }
        Err(err) => Err(ServerError::Iroh(format!(
            "cannot read iroh key file {}: {err}",
            path.display()
        ))),
    }
}

/// Create `path` with the key's raw bytes, mode 0600, refusing to
/// overwrite (a parallel start gets the race error, then reads).
fn write_key(path: &Path, key: &iroh::SecretKey) -> Result<(), ServerError> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| {
        ServerError::Iroh(format!(
            "cannot create iroh key file {}: {err}",
            path.display()
        ))
    })?;
    file.write_all(&key.to_bytes()).map_err(|err| {
        ServerError::Iroh(format!(
            "cannot write iroh key file {}: {err}",
            path.display()
        ))
    })
}

/// `(dial address, ws:// alias)` per `iroh:` listener.
///
/// In `[[relay.listen]]` order — `nosfry iroh address` output. The
/// dial address carries the configured custom relay URLs as hints,
/// the only hints an offline command can know. Generates any
/// missing key but never binds a socket or touches the network.
///
/// # Errors
///
/// Any state-dir or key-file failure, or no iroh listener in the
/// config.
pub fn addresses(config: &Config) -> Result<Vec<(String, String)>, ServerError> {
    crate::state_dir::prepare(&config.relay.iroh.state_dir, "iroh").map_err(ServerError::Iroh)?;
    let mut rows = Vec::new();
    for listen in &config.relay.listen {
        if let ListenAddress::Iroh(nickname) = &listen.address {
            let key = secret_key(&config.relay.iroh, nickname)?;
            let id = key.public();
            let hints = if config.relay.iroh.relay_mode == IrohRelayMode::Custom {
                config
                    .relay
                    .iroh
                    .relay_urls
                    .iter()
                    .filter_map(|entry| entry.parse::<iroh::RelayUrl>().ok())
                    .map(Hint::Relay)
                    .collect()
            } else {
                Vec::new()
            };
            let dial = DialAddr { id, hints };
            rows.push((dial.to_string(), alias(id.as_bytes())));
        }
    }
    if rows.is_empty() {
        return Err(ServerError::Iroh(
            "relay.listen has no iroh listener".to_owned(),
        ));
    }
    Ok(rows)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "unit tests panic on failure"
)]
mod tests {
    use super::*;
    use crate::config::{Config, Listen};

    fn iroh_config(state_dir: &Path) -> Config {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.db.path = dir.keep();
        config.relay.listen = vec![Listen {
            address: ListenAddress::Iroh("test".to_owned()),
            profile: "default".to_owned(),
            real_ip_header: String::new(),
        }];
        config.relay.iroh.state_dir = state_dir.to_path_buf();
        config.relay.iroh.relay_mode = IrohRelayMode::Disabled;
        config.relay.iroh.address_lookup = IrohAddressLookup::Disabled;
        config
    }

    /// A tempdir ready to be a `state_dir` (tempfile honours the
    /// umask; the iroh rule wants 0700).
    #[cfg(unix)]
    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(not(unix))]
    fn private_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn z32_roundtrip() {
        let key = iroh::SecretKey::generate();
        let id = key.public();
        let text = z32(id.as_bytes());
        assert_eq!(text.len(), 52);
        assert_eq!(iroh::EndpointId::from_z32(&text).unwrap(), id);
    }

    /// `DialAddr` parses z32 and hex ids, and every hint form.
    #[test]
    fn dial_addr_parse_and_display() {
        let id = iroh::SecretKey::generate().public();
        let z = id.to_z32();
        for text in [
            z.clone(),
            id.to_string(),
            format!("{z}@127.0.0.1:7777"),
            format!("{z}@[::1]:7777,https://relay.example.com"),
            format!("{z}@https://relay.example.com,127.0.0.1:7777"),
        ] {
            let dial: DialAddr = text.parse().unwrap();
            assert_eq!(dial.id, id, "{text}");
            let round: DialAddr = dial.to_string().parse().unwrap();
            assert_eq!(round, dial, "{text}");
        }
        let direct: DialAddr = format!("{z}@127.0.0.1:7777").parse().unwrap();
        assert_eq!(
            direct.hints,
            vec![Hint::Ip("127.0.0.1:7777".parse().unwrap())]
        );
        let relayed: DialAddr = format!("{z}@https://relay.example.com").parse().unwrap();
        assert!(matches!(relayed.hints[..], [Hint::Relay(_)]));

        for bad in [
            "",
            "short",
            &"x".repeat(52),
            &format!("{z}@"),
            &format!("{z}@not-a-hint"),
            &format!("{z}@ftp://relay.example.com"),
            &format!("{z}@127.0.0.1"),
        ] {
            assert!(bad.parse::<DialAddr>().is_err(), "{bad}");
        }
    }

    /// `to_endpoint_addr` maps hints, and under `custom` relay mode
    /// adds every configured relay URL.
    #[test]
    fn dial_addr_to_endpoint_addr() {
        let id = iroh::SecretKey::generate().public();
        let mut cfg = Iroh {
            relay_mode: IrohRelayMode::Custom,
            relay_urls: vec!["https://own-relay.example.com".into()],
            ..Iroh::default()
        };
        let dial: DialAddr = format!("{}@127.0.0.1:7777", id.to_z32()).parse().unwrap();
        let addr = dial.to_endpoint_addr(&cfg);
        assert_eq!(addr.id, id);
        assert_eq!(addr.ip_addrs().count(), 1);
        assert_eq!(addr.relay_urls().count(), 1);
        assert_eq!(
            addr.relay_urls().next().unwrap().to_string(),
            "https://own-relay.example.com/"
        );
        // Other relay modes add nothing.
        cfg.relay_mode = IrohRelayMode::N0;
        assert_eq!(dial.to_endpoint_addr(&cfg).relay_urls().count(), 0);
        cfg.relay_mode = IrohRelayMode::Disabled;
        assert_eq!(dial.to_endpoint_addr(&cfg).relay_urls().count(), 0);
        // A Relay hint always lands.
        let hinted: DialAddr = format!("{}@https://peer-relay.example.com", id.to_z32())
            .parse()
            .unwrap();
        assert_eq!(hinted.to_endpoint_addr(&cfg).relay_urls().count(), 1);
    }

    /// `EndpointAddr` converts both ways: every transport address
    /// becomes a hint, and the display reparses.
    #[test]
    fn dial_addr_from_endpoint_addr() {
        let id = iroh::SecretKey::generate().public();
        let addr = iroh::EndpointAddr::new(id)
            .with_ip_addr("127.0.0.1:7777".parse().unwrap())
            .with_relay_url("https://relay.example.com".parse().unwrap());
        let dial = DialAddr::from(&addr);
        assert_eq!(dial.id, id);
        assert_eq!(dial.hints.len(), 2);
        let reparsed: DialAddr = dial.to_string().parse().unwrap();
        assert_eq!(reparsed, dial);
    }

    /// The key file persists the endpoint id, is `0600`, and a
    /// wrong-length file is an error, never overwritten.
    #[cfg(unix)]
    #[test]
    fn secret_key_persists() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = private_dir();
        let cfg = Iroh {
            state_dir: dir.path().to_path_buf(),
            ..Iroh::default()
        };
        let key = secret_key(&cfg, "main").unwrap();
        let path = dir.path().join("main.key");
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(path.metadata().unwrap().len(), 32);
        assert_eq!(secret_key(&cfg, "main").unwrap().public(), key.public());
        // A wrong-length file errors and survives.
        std::fs::write(&path, b"short").unwrap();
        assert!(secret_key(&cfg, "main").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
        // Another nickname gets another id.
        assert_ne!(secret_key(&cfg, "side").unwrap().public(), key.public());
    }

    /// `addresses` is stable across calls, per-nickname distinct,
    /// and carries custom relay URLs as dial hints.
    #[test]
    fn addresses_stable_distinct_hints() {
        let dir = private_dir();
        let mut config = iroh_config(dir.path());
        let first = addresses(&config).unwrap();
        assert_eq!(first.len(), 1);
        let (dial, url) = &first[0];
        assert_eq!(url, &format!("ws://{dial}.iroh"));
        assert_eq!(addresses(&config).unwrap(), first);

        // A second nickname derives its own id.
        config.relay.listen.push(Listen {
            address: ListenAddress::Iroh("other".to_owned()),
            profile: "default".to_owned(),
            real_ip_header: String::new(),
        });
        let both = addresses(&config).unwrap();
        assert_eq!(both[0], first[0]);
        assert_ne!(both[1], first[0]);

        // Custom relay mode: the relay URL rides along as a hint.
        config.relay.iroh.relay_mode = IrohRelayMode::Custom;
        config.relay.iroh.relay_urls = vec!["https://own-relay.example.com".into()];
        let hinted = addresses(&config).unwrap();
        assert!(
            hinted[0].0.ends_with("@https://own-relay.example.com/"),
            "{}",
            hinted[0].0
        );
        assert_eq!(hinted[0].1, first[0].1);

        // No iroh listener is an error.
        let mut none = Config::default();
        none.relay.iroh.state_dir = dir.path().to_path_buf();
        assert!(addresses(&none).is_err());
    }
}
