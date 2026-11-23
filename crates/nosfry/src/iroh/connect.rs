//! `nosfry connect`: a local TCP gateway in front of an iroh
//! endpoint — the dialer's mirror of the listener.
//!
//! Any client that speaks plain TCP/WebSocket (a browser, the
//! conformance suite) reaches `ws://<z32>.iroh` through
//! `127.0.0.1:<port>` without knowing iroh.
//!
//! [`bind`] connects the ephemeral endpoint to the peer first — a
//! dial that cannot complete within `timeout` fails the command —
//! then binds the TCP listener; [`Gateway::serve`] accepts clients
//! onto fresh bidirectional streams of one cached [`Connection`],
//! redialing under capped backoff when it dies. [`run`] is the two
//! steps in one call.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use iroh::endpoint::{ConnectError, Connection, RecvStream, SendStream};
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use super::{ALPN, DialAddr, builder, selected_path, z32};
use crate::ServerError;
use crate::config::Iroh;

/// Clients get this long to finish when shutdown fires, like the
/// HTTP trackers the relay drains.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
/// Redials wait 1 s after the first failure, doubling to this cap.
const DIAL_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// The "client limit reached" warning repeats at most this often.
const FULL_WARN_EVERY: Duration = Duration::from_secs(10);

/// Inputs for one [`run`] — the TCP gateway's knobs.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// The peer: an endpoint id plus optional dial hints.
    pub dial: DialAddr,
    /// The TCP address the gateway listens on; must be loopback
    /// unless `allow_remote`.
    pub listen: SocketAddr,
    /// Concurrent client cap; further clients close immediately.
    pub max_connections: usize,
    /// Allow a non-loopback `listen` (the `--allow-remote` flag).
    pub allow_remote: bool,
    /// The initial connect and each redial deadline.
    pub timeout: Duration,
}

/// A bound gateway: TCP listener up, peer connected, not serving
/// yet. [`Gateway::serve`] consumes it.
#[derive(Debug)]
pub struct Gateway {
    /// The bound TCP listener (`local_addr` is the dialable port).
    listener: TcpListener,
    /// The ephemeral dialer endpoint; `serve` closes it on shutdown.
    endpoint: iroh::Endpoint,
    /// The peer's resolved address for redials.
    addr: iroh::EndpointAddr,
    /// The verified first connection — `serve`'s initial cache.
    connection: Connection,
    /// The remaining options.
    max_connections: usize,
    /// The redial deadline shared with [`bind`]'s first connect.
    timeout: Duration,
}

impl Gateway {
    /// The address clients connect to — the bound port for tests.
    ///
    /// # Errors
    ///
    /// [`ServerError::Io`] when the socket address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.listener.local_addr()?)
    }

    /// Accept TCP clients onto streams of the cached iroh
    /// connection until `shutdown` fires; drain in-flight forwards
    /// for `SHUTDOWN_GRACE`, then close the endpoint.
    ///
    /// # Errors
    ///
    /// [`ServerError::Iroh`] when a client task cannot be spawned.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> Result<(), ServerError> {
        let Self {
            listener,
            endpoint,
            addr,
            connection,
            max_connections,
            timeout,
        } = self;
        let shared = Arc::new(Shared::new(
            connection,
            endpoint.clone(),
            addr,
            max_connections,
            timeout,
        ));
        let tracker = TaskTracker::new();
        let mut last_full_warn: Option<Instant> = None;
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((socket, client)) => admit(
                            socket,
                            client,
                            &shared,
                            &tracker,
                            &mut last_full_warn,
                        ),
                        Err(err) => warn!(%err, "connect: TCP accept failed"),
                    }
                }
            }
        }
        close_all(tracker, endpoint).await;
        Ok(())
    }
}

/// Everything `forward` tasks share: the cached peer connection
/// under its redial bookkeeping, the client cap's semaphore, and
/// the dial inputs for redials.
struct Shared {
    /// The cached [`Connection`] slot.
    state: Mutex<Slot>,
    /// Concurrent client cap; further clients close immediately.
    clients: Arc<Semaphore>,
    /// The cap's value, for the "limit reached" warning.
    max_connections: usize,
    /// The ephemeral dialer endpoint; `serve` closes it on shutdown.
    endpoint: iroh::Endpoint,
    /// The peer's resolved address for redials.
    addr: iroh::EndpointAddr,
    /// The redial deadline shared with [`bind`]'s first connect.
    timeout: Duration,
    /// The `iroh:<z32>` peer name for logs.
    peer: String,
}

impl Shared {
    /// The serve-time state: the first connection cached, the
    /// client cap at `max_connections`.
    fn new(
        connection: Connection,
        endpoint: iroh::Endpoint,
        addr: iroh::EndpointAddr,
        max_connections: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            peer: format!("iroh:{}", z32(connection.remote_id().as_bytes())),
            state: Mutex::new(Slot::ready(connection)),
            clients: Arc::new(Semaphore::new(max_connections)),
            max_connections,
            endpoint,
            addr,
            timeout,
        }
    }
}

/// One accepted client: nodelay, a slot from the semaphore, then
/// the forward task. Clients beyond `max_connections` are closed
/// with a warning at most once per [`FULL_WARN_EVERY`].
fn admit(
    socket: TcpStream,
    client: SocketAddr,
    shared: &Arc<Shared>,
    tracker: &TaskTracker,
    last_full_warn: &mut Option<Instant>,
) {
    if let Err(err) = socket.set_nodelay(true) {
        warn!(%err, "connect: failed to set TCP_NODELAY");
    }
    let Ok(permit) = Arc::clone(&shared.clients).try_acquire_owned() else {
        // `Instant::now` is monotonic here: the warn fires at most
        // once per FULL_WARN_EVERY.
        if last_full_warn.is_none_or(|t| t.elapsed() >= FULL_WARN_EVERY) {
            warn!(
                max_connections = shared.max_connections,
                "connect: client limit reached; closing new clients"
            );
            *last_full_warn = Some(Instant::now());
        }
        return;
    };
    tracker.spawn(forward(socket, client, permit, Arc::clone(shared)));
}

/// Stop accepting: in-flight forwards get [`SHUTDOWN_GRACE`], then
/// the endpoint closes under the same deadline.
async fn close_all(tracker: TaskTracker, endpoint: iroh::Endpoint) {
    tracker.close();
    if tokio::time::timeout(SHUTDOWN_GRACE, tracker.wait())
        .await
        .is_err()
    {
        warn!("connect: shutdown with forwards still in flight");
    }
    if tokio::time::timeout(SHUTDOWN_GRACE, endpoint.close())
        .await
        .is_err()
    {
        warn!("connect: iroh endpoint close stalled");
    }
}

/// The cached peer connection plus the redial bookkeeping the
/// `forward` tasks share — a tokio `Mutex` so only one task ever
/// dials; waiters pick up the fresh connection behind it.
struct Slot {
    /// The live connection, `None` between a close and the next
    /// successful dial.
    connection: Option<Connection>,
    /// Consecutive failed dials — the backoff level.
    failures: u32,
    /// Earliest instant a redial may start.
    next_dial: Instant,
}

impl Slot {
    /// The gateway's starting state: the first connect succeeded in
    /// [`bind`], so a redial is allowed immediately once it dies.
    fn ready(connection: Connection) -> Self {
        Self {
            connection: Some(connection),
            failures: 0,
            next_dial: Instant::now(),
        }
    }

    /// Record a failed dial: the backoff advances a level.
    fn failed(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.next_dial = Instant::now() + dial_backoff(self.failures);
    }
}

/// The redial wait after `failures` consecutive failed dials: 1 s,
/// doubling to [`DIAL_BACKOFF_MAX`].
fn dial_backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(6);
    Duration::from_secs(1 << shift).min(DIAL_BACKOFF_MAX)
}

/// A live connection out of `shared`, redialing once when it died:
/// `None` while backoff holds or the redial itself failed — the
/// caller closes its client.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the lock stays held across the dial so concurrent clients share the single attempt"
)]
async fn connection(shared: &Shared) -> Option<Connection> {
    let mut slot = shared.state.lock().await;
    if let Some(conn) = &slot.connection {
        if conn.close_reason().is_none() {
            return Some(conn.clone());
        }
        slot.connection = None;
    }
    if Instant::now() < slot.next_dial {
        debug!(peer = %shared.peer, "connect: redial in backoff; closing client");
        return None;
    }
    redial(&mut slot, shared).await
}

/// Dial `shared.addr` while `slot` serializes the attempt: success
/// is cached and its path changes logged, failure advances the
/// backoff.
async fn redial(slot: &mut Slot, shared: &Shared) -> Option<Connection> {
    let attempt = shared.endpoint.connect(shared.addr.clone(), ALPN);
    match tokio::time::timeout(shared.timeout, attempt).await {
        Ok(Ok(conn)) => Some(connected(slot, shared, conn)),
        result => dial_failed(slot, shared, &result),
    }
}

/// A dial outcome: the connection, the connect error, or the
/// timeout elapsing first.
type DialOutcome = Result<Result<Connection, ConnectError>, tokio::time::error::Elapsed>;

/// Cache `conn`, reset the backoff, log the selected path, and hand
/// the connection to the caller.
fn connected(slot: &mut Slot, shared: &Shared, conn: Connection) -> Connection {
    slot.failures = 0;
    slot.connection = Some(conn.clone());
    info!(peer = %shared.peer, path = selected_path(&conn).unwrap_or("none"), "connect: iroh connected");
    log_path_changes(&conn, shared.peer.clone());
    conn
}

/// Log a failed dial at debug and advance the backoff; the caller
/// gets `None` and closes its client.
fn dial_failed(slot: &mut Slot, shared: &Shared, result: &DialOutcome) -> Option<Connection> {
    if let Ok(Err(err)) = result {
        debug!(peer = %shared.peer, %err, "connect: iroh redial failed");
    } else {
        debug!(peer = %shared.peer, "connect: iroh redial timed out");
    }
    slot.failed();
    None
}

/// Forget `dead` if it is still the cached connection, so the next
/// `forward` redials at once.
async fn clear_cached(state: &Mutex<Slot>, dead: &Connection) {
    drop(
        state
            .lock()
            .await
            .connection
            .take_if(|cached| cached.stable_id() == dead.stable_id()),
    );
}

/// Log `conn`'s selected path at every change until the connection
/// dies and its event stream ends.
fn log_path_changes(connection: &Connection, peer: String) {
    let conn = connection.clone();
    tokio::spawn(async move {
        let mut events = conn.path_events();
        let mut last = selected_path(&conn);
        while events.next().await.is_some() {
            let kind = selected_path(&conn);
            if kind != last {
                info!(
                    %peer,
                    from = last.unwrap_or("none"),
                    to = kind.unwrap_or("none"),
                    "connect: iroh selected path changed"
                );
                last = kind;
            }
        }
    });
}

/// One accepted TCP client: a fresh bidirectional stream on the
/// cached connection, then [`pump`] relays raw bytes both ways with
/// QUIC FIN as the half-close. The semaphore `permit` frees the
/// client's slot at task end.
async fn forward(
    socket: TcpStream,
    client: SocketAddr,
    _permit: OwnedSemaphorePermit,
    shared: Arc<Shared>,
) {
    let Some((send, recv)) = stream_for(&shared, client).await else {
        return;
    };
    debug!(%client, peer = %shared.peer, "connect: client open");
    pump(socket, client, send, recv, &shared.peer).await;
}

/// `client`'s stream on the cached connection, redialing once when
/// it died; `None` — and the caller closes the client — on backoff
/// or a failed dial or `open_bi`.
async fn stream_for(shared: &Shared, client: SocketAddr) -> Option<(SendStream, RecvStream)> {
    let Some(conn) = connection(shared).await else {
        debug!(%client, "connect: no iroh connection; closing client");
        return None;
    };
    match conn.open_bi().await {
        Ok(pair) => Some(pair),
        Err(err) => {
            debug!(%client, peer = %shared.peer, %err, "connect: iroh stream open failed");
            // A dead connection is dropped on the next call through
            // `close_reason`; clearing it here turns the next client
            // into the redialing one immediately.
            clear_cached(&shared.state, &conn).await;
            None
        }
    }
}

/// Once the download half has ended, a client still draining after
/// a failed upload gets this long to reach its EOF before the
/// socket drops anyway — an uploader that never stops cannot pin
/// the forward task.
const LINGER: Duration = Duration::from_secs(2);

/// Copy bytes between `socket` and the iroh stream in both
/// directions until each ends. Two independent copies: a dead
/// upload half (the peer stopped reading) must not strand download
/// bytes already in flight the way `copy_bidirectional`'s
/// first-error return does.
///
/// A failed upload keeps draining the client into a sink until its
/// EOF: closing a TCP socket with unread bytes answers them with a
/// RST, and on the client's kernel that reset can discard download
/// bytes still queued unread — a peer that stops reading on a
/// protocol error (an oversized frame earns close 1009) would lose
/// its close frame to that reset. Once `down` has finished the
/// drain gets at most [`LINGER`] more, then the socket drops.
async fn pump(
    mut socket: TcpStream,
    client: SocketAddr,
    send: SendStream,
    recv: RecvStream,
    peer: &str,
) {
    let (reader, writer) = socket.split();
    match copies(reader, writer, send, recv).await {
        (Ok(up), Ok(down)) => {
            debug!(%client, %peer, up, down, "connect: client closed");
        }
        (up, down) => {
            debug!(%client, %peer, ?up, ?down, "connect: client closed on error");
        }
    }
}

/// The two copies of [`pump`]: upload client→stream then stream
/// FIN, download stream→client then socket FIN. A failed upload
/// drains the client to EOF; once the download is done the upload
/// gets [`LINGER`] at most. Either result may be an error.
async fn copies(
    mut reader: tokio::net::tcp::ReadHalf<'_>,
    mut writer: tokio::net::tcp::WriteHalf<'_>,
    mut send: SendStream,
    mut recv: RecvStream,
) -> (std::io::Result<u64>, std::io::Result<u64>) {
    let upload = async {
        let res = tokio::io::copy(&mut reader, &mut send).await;
        // FIN even on an upload error — the download half is a
        // separate concern and may still be draining.
        drop(send.shutdown().await);
        if res.is_err() {
            drop(tokio::io::copy(&mut reader, &mut tokio::io::sink()).await);
        }
        res
    };
    let download = async {
        let res = tokio::io::copy(&mut recv, &mut writer).await;
        drop(writer.shutdown().await);
        res
    };
    tokio::pin!(upload);
    tokio::pin!(download);
    tokio::select! {
        res = &mut upload => (res, download.await),
        res = &mut download => (linger(upload.as_mut()).await, res),
    }
}

/// The upload's last word once the download is done: its result
/// within [`LINGER`], `TimedOut` when the deadline lands first.
async fn linger(
    upload: std::pin::Pin<&mut impl Future<Output = std::io::Result<u64>>>,
) -> std::io::Result<u64> {
    tokio::time::timeout(LINGER, upload)
        .await
        .unwrap_or_else(|elapsed| Err(elapsed.into()))
}

/// Connect to `opts.dial` and bind the TCP listener: a usable
/// gateway or a fast failure — the initial connect must complete
/// within `opts.timeout`, and a non-loopback `listen` needs
/// `allow_remote`.
///
/// # Errors
///
/// [`ServerError::Iroh`] on a non-loopback `listen` without
/// `allow_remote`, a failed endpoint bind or a failed first
/// connect; [`ServerError::Io`] on a failed TCP bind.
pub async fn bind(cfg: &Iroh, opts: ConnectOptions) -> Result<Gateway, ServerError> {
    if !opts.listen.ip().is_loopback() && !opts.allow_remote {
        return Err(ServerError::Iroh(format!(
            "connect listen address {} is not loopback; pass --allow-remote",
            opts.listen.ip()
        )));
    }
    let endpoint = builder(cfg)
        .secret_key(iroh::SecretKey::generate())
        .bind()
        .await
        .map_err(|err| ServerError::Iroh(format!("connect endpoint bind failed: {err}")))?;
    let addr = opts.dial.to_endpoint_addr(cfg);
    let result = tokio::time::timeout(opts.timeout, endpoint.connect(addr.clone(), ALPN)).await;
    let connection = match result {
        Ok(Ok(conn)) => conn,
        result => {
            // Dropping an unclosed endpoint logs an abort error over
            // the real one — close gracefully before reporting.
            drop(tokio::time::timeout(Duration::from_secs(5), endpoint.close()).await);
            return Err(match result {
                Ok(Err(err)) => ServerError::Iroh(format!("connect: iroh dial failed: {err}")),
                _ => ServerError::Iroh(format!(
                    "connect: iroh dial timed out after {}s",
                    opts.timeout.as_secs()
                )),
            });
        }
    };
    let peer = format!("iroh:{}", z32(connection.remote_id().as_bytes()));
    info!(
        %peer,
        path = selected_path(&connection).unwrap_or("none"),
        "connect: iroh connected"
    );
    log_path_changes(&connection, peer);
    let listener = TcpListener::bind(opts.listen).await.map_err(|err| {
        ServerError::Iroh(format!("connect: TCP bind {} failed: {err}", opts.listen))
    })?;
    Ok(Gateway {
        listener,
        endpoint,
        addr,
        connection,
        max_connections: opts.max_connections,
        timeout: opts.timeout,
    })
}

/// [`bind`] then [`Gateway::serve`].
///
/// # Errors
///
/// As [`bind`]'s.
pub async fn run(
    cfg: &Iroh,
    opts: ConnectOptions,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServerError> {
    bind(cfg, opts).await?.serve(shutdown).await
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::io::AsyncReadExt as _;
    use tokio::sync::oneshot;

    use super::*;
    use crate::config::{IrohAddressLookup, IrohRelayMode};

    /// `[relay.iroh]` that never leaves the host — the mirror of the
    /// integration tests' `offline_iroh`.
    fn offline() -> Iroh {
        Iroh {
            relay_mode: IrohRelayMode::Disabled,
            address_lookup: IrohAddressLookup::Disabled,
            ..Iroh::default()
        }
    }

    /// One valid dial address for option construction: a fresh
    /// endpoint id, no hints — nothing dials it.
    fn dial() -> DialAddr {
        iroh::SecretKey::generate()
            .public()
            .to_z32()
            .parse()
            .unwrap()
    }

    fn opts(listen: SocketAddr) -> ConnectOptions {
        ConnectOptions {
            dial: dial(),
            listen,
            max_connections: 64,
            allow_remote: false,
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn bind_refuses_non_loopback() {
        let cfg = Iroh::default();
        let listen = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        let err = bind(&cfg, opts(listen)).await.err().unwrap().to_string();
        assert!(err.contains("--allow-remote"), "{err}");
        // The flag admits it — failure now moves past the check to
        // the dial (which cannot connect anywhere in a test).
        let mut remote = opts(listen);
        remote.allow_remote = true;
        let remote_err = bind(&cfg, remote).await.err().unwrap().to_string();
        assert!(!remote_err.contains("--allow-remote"), "{remote_err}");
    }

    #[tokio::test]
    async fn bind_refuses_non_loopback_v6() {
        let cfg = Iroh::default();
        let listen = SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0);
        let err = bind(&cfg, opts(listen)).await.err().unwrap().to_string();
        assert!(err.contains("--allow-remote"), "{err}");
    }

    /// The lingering drain: the upstream reads a little, stops
    /// reading (`STOP_SENDING` — the oversized-frame path) and
    /// answers; the client floods far past every socket buffer, so
    /// its write is still pending when the gateway would drop the
    /// socket. Without the drain the unread bytes turn the close
    /// into a RST that discards the queued answer.
    #[tokio::test]
    async fn gateway_drains_flooding_client_after_upstream_stop() {
        let cfg = offline();
        let key = iroh::SecretKey::generate();
        let upstream = builder(&cfg).secret_key(key.clone()).bind().await.unwrap();
        let port = upstream
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .unwrap()
            .port();
        let payload = vec![0x42_u8; 16 << 20];
        let upstream_task = tokio::spawn(upstream_stops_reading(upstream, payload.clone()));
        let gateway = bind(
            &cfg,
            ConnectOptions {
                dial: format!("{}@127.0.0.1:{port}", key.public().to_z32())
                    .parse()
                    .unwrap(),
                listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                max_connections: 64,
                allow_remote: false,
                timeout: Duration::from_secs(30),
            },
        )
        .await
        .unwrap();
        let addr = gateway.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let serve = gateway.serve(async move {
            stopped.await.ok();
        });
        let serving = tokio::spawn(serve);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut reader, mut writer) = tcp.into_split();
        // Far more than any socket buffer holds: the flood stalls
        // once the gateway stops reading, and the answer — larger
        // than the client's receive buffer — cannot finish before
        // the socket's fate (graceful close vs RST) is decided.
        let flooding = tokio::spawn(async move {
            drop(writer.write_all(&vec![0_u8; 16 << 20]).await);
            drop(writer.shutdown().await);
        });
        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, payload);
        flooding.await.unwrap();
        stop.send(()).ok();
        serving.await.unwrap().unwrap();
        upstream_task.await.unwrap();
    }

    /// The fake upstream of `gateway_drains_flooding_client…`:
    /// accept one stream, read a little, stop reading
    /// (`STOP_SENDING`), answer, then idle until the peer closes.
    async fn upstream_stops_reading(upstream: iroh::Endpoint, payload: Vec<u8>) {
        let conn = upstream
            .accept()
            .await
            .unwrap()
            .accept()
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut buf = [0_u8; 64];
        drop(recv.read(&mut buf).await);
        recv.stop(iroh::endpoint::VarInt::from_u32(0)).unwrap();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        conn.closed().await;
    }

    #[test]
    fn backoff_doubles_to_cap() {
        let delays: Vec<u64> = (1..=8).map(|n| dial_backoff(n).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30]);
        // Defensive: 0 failures still schedules a sane minimum.
        assert_eq!(dial_backoff(0), Duration::from_secs(1));
    }
}
