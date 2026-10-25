//! strfry-compatible write-policy plugin bridge: one child process
//! (`/bin/sh -c <plugin>`) that receives each event as a JSON line on
//! stdin and answers `{"id","action","msg"}` on stdout. The wire
//! protocol lives in [`nosfry_core::policy`].
//!
//! - Non-JSON response lines are skipped with a warning so plugins
//!   may print noise; an id mismatch or unknown action is an error.
//!   Lines over [`MAX_RESPONSE`] bytes are an error.
//! - Any failure (spawn/write/read/timeout/EOF/bad response) rejects
//!   the event `error: internal error`, logs at `error`, and kills the
//!   child; the next event lazily spawns a fresh one.
//! - A plugin command without spaces is a path: its mtime is compared
//!   before every request and the child restarts when it changes.
//!
//! Requests are served strictly in order from a bounded channel —
//! plugins may rely on ordering (strfry is serial too). Queue-full
//! callers wait on their own connection, but all connections share
//! the one serial queue: a slow plugin delays every publisher by up
//! to the queued work, not just its own.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nosfry_core::event::{Event, PublicKey};
use nosfry_core::policy::{Decision, ResponseError, parse_response, request_line};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot};

/// Request queue depth; extra callers wait in place.
const QUEUE: usize = 1024;
/// Response lines longer than this are an error (strfry's max
/// record size).
const MAX_RESPONSE: u64 = 8192;
/// The NIP-01 message for any plugin failure.
const INTERNAL: &str = "error: internal error";

/// A clonable handle to the single policy task. The task exits once
/// every clone is dropped.
#[derive(Debug, Clone)]
pub(crate) struct WritePolicy {
    tx: mpsc::Sender<Request>,
}

impl WritePolicy {
    /// Start the policy task serving `plugin` (`/bin/sh -c <plugin>`,
    /// lazily spawned on the first event).
    pub(crate) fn new(plugin: &str, timeout: Duration) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        tokio::spawn(run(plugin.to_owned(), timeout, rx));
        Self { tx }
    }

    /// Ask the plugin about one verified event. `authed` is the
    /// connection's authenticated pubkey (NIP-42), sent as the
    /// request's `authed` field when present.
    pub(crate) async fn check(
        &self,
        event: &Event,
        source: IpAddr,
        authed: Option<PublicKey>,
    ) -> Decision {
        let received_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let (reply, rx) = oneshot::channel();
        let request = Request {
            line: request_line(event.json(), received_at, source, authed),
            id: event.id().to_string(),
            reply,
        };
        if self.tx.send(request).await.is_err() {
            return Decision::Reject(INTERNAL.to_owned());
        }
        rx.await
            .unwrap_or_else(|_| Decision::Reject(INTERNAL.to_owned()))
    }
}

/// One queued request: the serialized input line plus the event id
/// the response must echo.
struct Request {
    /// The `{"type":"new",...}` line (no trailing newline).
    line: String,
    /// `event.id` in hex.
    id: String,
    /// Where the decision goes.
    reply: oneshot::Sender<Decision>,
}

/// The running child; `kill_on_drop` kills it when dropped.
struct Plugin {
    /// Process handle; kept only so drop kills the child.
    _child: Child,
    /// Request pipe.
    stdin: ChildStdin,
    /// Response pipe.
    stdout: BufReader<ChildStdout>,
    /// The plugin file's mtime when spawned (path commands only).
    mtime: Option<SystemTime>,
}

/// The policy task: owns the child and serves requests in order.
async fn run(plugin: String, timeout: Duration, mut rx: mpsc::Receiver<Request>) {
    let path_cmd = !plugin.contains(' ');
    let mut running: Option<Plugin> = None;
    while let Some(request) = rx.recv().await {
        let decision = serve(&plugin, path_cmd, timeout, &mut running, &request).await;
        drop(request.reply.send(decision));
    }
}

/// Serve one request; errors are logged, kill the child, and become
/// `error: internal error` rejections.
async fn serve(
    plugin: &str,
    path_cmd: bool,
    timeout: Duration,
    running: &mut Option<Plugin>,
    request: &Request,
) -> Decision {
    match try_serve(plugin, path_cmd, timeout, running, request).await {
        Ok(decision) => decision,
        Err(error) => {
            tracing::error!(%error, plugin, "write policy plugin failed");
            // Dropping the child (kill_on_drop) kills it; the next
            // request spawns a fresh process.
            *running = None;
            Decision::Reject(INTERNAL.to_owned())
        }
    }
}

async fn try_serve(
    plugin: &str,
    path_cmd: bool,
    timeout: Duration,
    running: &mut Option<Plugin>,
    request: &Request,
) -> Result<Decision, PolicyError> {
    // Path commands reload whenever the script's mtime changes.
    if path_cmd && running.is_some() {
        let mtime = tokio::fs::metadata(plugin).await?.modified()?;
        if running.as_ref().is_some_and(|p| p.mtime != Some(mtime)) {
            *running = None;
        }
    }
    let child = match running {
        Some(child) => child,
        slot @ None => slot.insert(spawn(plugin, path_cmd).await?),
    };

    timed(timeout, async {
        child.stdin.write_all(request.line.as_bytes()).await?;
        child.stdin.write_all(b"\n").await?;
        child.stdin.flush().await
    })
    .await?;

    // One deadline covers the whole response, noise lines included, so
    // a chatty plugin cannot hold the queue past the timeout.
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let mut line = Vec::new();
        let read = tokio::time::timeout_at(
            deadline,
            (&mut child.stdout)
                .take(MAX_RESPONSE + 1)
                .read_until(b'\n', &mut line),
        )
        .await
        .map_err(|_| PolicyError::Timeout)??;
        if read == 0 {
            return Err(PolicyError::Eof);
        }
        if u64::try_from(line.len()).unwrap_or(u64::MAX) > MAX_RESPONSE {
            return Err(PolicyError::TooLong);
        }
        match parse_response(&line, &request.id) {
            Ok(decision) => return Ok(decision),
            Err(ResponseError::Noise) => {
                tracing::warn!(
                    "unparseable line from write policy plugin: {}",
                    String::from_utf8_lossy(&line)
                );
            }
            Err(ResponseError::Fatal(error)) => return Err(error.into()),
        }
    }
}

/// Spawn `/bin/sh -c <plugin>` with stdio piped and stderr inherited
/// so plugin logs reach the relay log. `kill_on_drop` cleans the
/// process up on error paths and shutdown.
async fn spawn(plugin: &str, path_cmd: bool) -> Result<Plugin, PolicyError> {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(plugin)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let stdin = child.stdin.take().ok_or(PolicyError::Stdio)?;
    let stdout = child.stdout.take().ok_or(PolicyError::Stdio)?;
    let mtime = if path_cmd {
        Some(tokio::fs::metadata(plugin).await?.modified()?)
    } else {
        None
    };
    Ok(Plugin {
        _child: child,
        stdin,
        stdout: BufReader::new(stdout),
        mtime,
    })
}

/// A future bounded by the configured timeout.
async fn timed<T, E: Into<PolicyError>>(
    timeout: Duration,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, PolicyError> {
    tokio::time::timeout(timeout, future).await.map_or_else(
        |_| Err(PolicyError::Timeout),
        |result| result.map_err(Into::into),
    )
}

/// Ways a plugin or its transport can fail a request.
#[derive(Debug, thiserror::Error)]
enum PolicyError {
    /// Child stdio or filesystem error.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Write or read exceeded the configured timeout.
    #[error("timed out")]
    Timeout,
    /// The child closed stdout before answering.
    #[error("plugin closed its response stream")]
    Eof,
    /// A response line over [`MAX_RESPONSE`] bytes.
    #[error("response line exceeds {MAX_RESPONSE} bytes")]
    TooLong,
    /// The response itself fails the protocol.
    #[error(transparent)]
    Response(#[from] nosfry_core::policy::PolicyError),
    /// The child spawned without its stdin/stdout.
    #[error("child stdio unavailable")]
    Stdio,
}
