//! nosfry-bench: complementary relay benchmarks that relayBench does not cover.
//!
//! - `fanout`: S live subscribers, one publisher at a fixed rate; measures
//!   publish-to-delivery latency for every (subscriber, event) pair and checks
//!   that every expected delivery arrives exactly once.
//! - `conns`: C idle subscribed connections; measures the relay's resident
//!   memory per connection and the CPU spent establishing them.
//! - `rtt`, `ingest`, `wake`, `subbudget`, `scan`: deployed-relay
//!   acceptance-gate modes (see `gate.rs`).
//!
//! Every result is printed as one JSON line on stdout.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod ack;
mod corpus;
mod gate;
mod hist;
mod neg;
mod openloop;
mod query;
mod sampler;
mod soak;

use clap::{Parser, Subcommand, ValueEnum};
use futures::{SinkExt, StreamExt};
use secp256k1::{Keypair, schnorr};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, watch};
use yawc::{CompressionLevel, Frame, OpCode, Options, TcpWebSocket, WebSocket};

/// Concurrent WebSocket handshakes while building up subscribers.
const HANDSHAKE_CONCURRENCY: usize = 128;
/// How long to wait for every subscriber to reach EOSE.
const READY_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for straggling deliveries after the last publish.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Fanout {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 1000)]
        subs: usize,
        #[arg(long, default_value_t = 1000)]
        events: usize,
        /// Publish rate in events per second.
        #[arg(long, default_value_t = 200.0)]
        rate: f64,
        #[arg(long, value_enum, default_value_t = Mode::Broadcast)]
        mode: Mode,
        /// Distinct authors; selective subscriber j follows author j % authors.
        #[arg(long, default_value_t = 100)]
        authors: usize,
        #[arg(long)]
        deflate: bool,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long, default_value = "")]
        label: String,
    },
    Conns {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 5000)]
        conns: usize,
        #[arg(long)]
        deflate: bool,
        /// Relay process id for RSS/CPU sampling; skipped when absent
        /// (e.g. a remote or deployed relay).
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long, default_value_t = 5)]
        hold_secs: u64,
        #[arg(long, default_value = "")]
        label: String,
    },
    /// Mixed long-running workload; samples the relay as JSONL.
    Soak {
        #[arg(long)]
        url: String,
        /// `http://host:port/metrics`; skipped when absent.
        #[arg(long)]
        metrics_url: Option<String>,
        #[arg(long)]
        pid: Option<u32>,
        /// Relay db directory; `<db-dir>/data.mdb` is sized per sample.
        #[arg(long)]
        db_dir: Option<std::path::PathBuf>,
        #[arg(long)]
        duration_secs: u64,
        #[arg(long, default_value_t = 60)]
        sample_secs: u64,
        #[arg(long, default_value_t = 8)]
        publishers: usize,
        /// Total publish rate in events per second across publishers.
        #[arg(long, default_value_t = 200.0)]
        rate: f64,
        #[arg(long, default_value_t = 200)]
        subscribers: usize,
        /// Short-lived connections opened per second.
        #[arg(long, default_value_t = 10.0)]
        churn_rate: f64,
        /// Spawn one never-reading `REQ {}` consumer this often; 0 off.
        #[arg(long, default_value_t = 60)]
        slow_every_secs: u64,
        /// Start one negentropy session this often; 0 off.
        #[arg(long, default_value_t = 10)]
        neg_every_secs: u64,
        /// Run one vanish round this often; 0 off.
        #[arg(long, default_value_t = 60)]
        vanish_every_secs: u64,
        #[arg(long, default_value = "")]
        label: String,
        /// Negotiate permessage-deflate on every connection.
        #[arg(long)]
        deflate: bool,
    },
    /// One connection, n sequential REQ→EOSE round-trips.
    Rtt {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 20)]
        n: usize,
    },
    /// Events paced over connections; OK latency and acceptance rate.
    Ingest {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 30)]
        conns: usize,
        #[arg(long, default_value_t = 3000)]
        events: usize,
        #[arg(long, default_value_t = 15.0)]
        rate_per_conn: f64,
    },
    /// Subscribers idle through a hibernation, then fanout delivery.
    Wake {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 1000)]
        subs: usize,
        #[arg(long, default_value_t = 180)]
        idle_secs: u64,
        #[arg(long, default_value_t = 3)]
        rounds: usize,
        #[arg(long, default_value_t = 10)]
        events: usize,
        /// Keep one NIP-42-authenticated restricted subscription alive.
        #[arg(long)]
        auth: bool,
    },
    /// Large-author-list REQs until the subscription byte budget refuses.
    Subbudget {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 1900)]
        authors: usize,
    },
    /// Open-loop ingest: C connections at a fixed scheduled rate.
    IngestOpen {
        #[arg(long)]
        url: String,
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        conns: usize,
        /// Events per second across all connections.
        #[arg(long)]
        rate: f64,
        #[arg(long)]
        duration: u64,
        #[arg(long, default_value_t = 0)]
        warmup: u64,
        #[arg(long)]
        deflate: bool,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long, default_value = "ingest-open")]
        label: String,
        /// Corpus lines to skip before the first send.
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
    /// Closed-loop ingest: K outstanding events per connection.
    IngestClosed {
        #[arg(long)]
        url: String,
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        conns: usize,
        /// Outstanding events per connection.
        #[arg(long)]
        window: usize,
        #[arg(long)]
        duration: u64,
        #[arg(long, default_value_t = 0)]
        warmup: u64,
        #[arg(long)]
        deflate: bool,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long, default_value = "ingest-closed")]
        label: String,
        /// Corpus lines to skip before the first send.
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
    /// Stored-query mix driver: closed REQ->EOSE->CLOSE loops.
    Query {
        #[arg(long)]
        url: String,
        /// `params.json` written by `gen`.
        #[arg(long)]
        params: PathBuf,
        /// Weighted query mix (see `bench/r7/mix.json`).
        #[arg(long)]
        mix: PathBuf,
        /// Per-query JSONL log destination.
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        conns: usize,
        #[arg(long)]
        duration: u64,
        #[arg(long, default_value_t = 0)]
        warmup: u64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long)]
        deflate: bool,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long, default_value = "query")]
        label: String,
    },
    /// Crash-durability ingest: paced sends, acked ids appended to a file.
    AckIngest {
        #[arg(long)]
        url: String,
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        conns: usize,
        /// Events per second across all connections.
        #[arg(long)]
        rate: f64,
        /// `acked.ids` destination, one hex id per line.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "ack-ingest")]
        label: String,
    },
    /// REQ back every id in `acked.ids` after a relay restart.
    AckCheck {
        #[arg(long)]
        url: String,
        #[arg(long)]
        ids: PathBuf,
    },
    /// NIP-77 set reconciliation against a known corpus state.
    Neg {
        #[arg(long)]
        url: String,
        /// regular.jsonl: the relay holds exactly its first `--base` lines.
        #[arg(long)]
        corpus: PathBuf,
        /// First N corpus lines the relay holds.
        #[arg(long)]
        base: usize,
        /// holdout-regular.jsonl: additions the relay does not hold.
        #[arg(long)]
        holdout_corpus: PathBuf,
        /// Percentage of `--base` split evenly between removals and
        /// holdout additions.
        #[arg(long)]
        diff_pct: f64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Per-frame negentropy payload cap in bytes.
        #[arg(long, default_value_t = 60_000)]
        frame_size_limit: u64,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long, default_value = "neg")]
        label: String,
    },
    /// Filter corpus JSONL to the regular-kind set every relay stores.
    CorpusFilter {
        /// Keep only regular kinds (1, 2, 4-44, 1000-9999).
        #[arg(long)]
        regular: bool,
        /// Keep at most N items after filtering and skipping.
        #[arg(long)]
        first: Option<usize>,
        /// Skip this many kept items first (the holdout split).
        #[arg(long, default_value_t = 0)]
        skip: usize,
        /// Input JSONL corpus.
        #[arg(long = "in")]
        input: PathBuf,
        /// Output JSONL corpus.
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate the D2 synthetic corpus and its query sidecar.
    Gen {
        /// D1 template corpus: a JSON array of events, plain or gzipped.
        #[arg(long)]
        template: PathBuf,
        /// N: events written to events.jsonl.
        #[arg(long)]
        events: usize,
        /// H: events written to holdout.jsonl for ingest runs.
        #[arg(long, default_value_t = 0)]
        holdout: usize,
        /// A: author keypairs drawn Zipf-style.
        #[arg(long, default_value_t = 200_000)]
        authors: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long)]
        out: PathBuf,
        /// Generation workers; output is independent of this.
        #[arg(long, default_value_t = 0)]
        threads: usize,
    },
    /// n stored scans of one filter; reports the CPU-ceiling signal.
    Scan {
        #[arg(long)]
        url: String,
        #[arg(long)]
        filter: String,
        #[arg(long, default_value_t = 3)]
        n: usize,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    /// Every subscriber follows `kinds:[1]`; each event goes to every subscriber.
    Broadcast,
    /// Subscriber j follows one author; exercises the relay's live index.
    Selective,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

struct Author {
    keypair: Keypair,
    pk_hex: String,
}

/// Standard base64 with padding (for `hist_b64` and the WS probe key).
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(char::from(T[(n >> 18) as usize & 63]));
        out.push(char::from(T[(n >> 12) as usize & 63]));
        out.push(if chunk.len() > 1 {
            char::from(T[(n >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(T[n as usize & 63])
        } else {
            '='
        });
    }
    out
}

fn author(index: usize) -> Author {
    let mut secret = [0u8; 32];
    secret[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    secret[31] = 0x5a;
    let keypair = Keypair::from_secret_bytes(secret).expect("secret is a valid scalar");
    let pk_hex = hex(&keypair.x_only_public_key().0.to_byte_array());
    Author { keypair, pk_hex }
}

/// Returns `(id_hex, event_json)` for a signed event.
fn sign_event(
    author: &Author,
    created_at: u64,
    kind: u16,
    tags: &Value,
    content: &str,
) -> (String, String) {
    let preimage = json!([0, author.pk_hex, created_at, kind, tags, content]).to_string();
    let id: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
    let sig = schnorr::sign_no_aux_rand(&id, &author.keypair);
    let id_hex = hex(&id);
    let event = json!({
        "id": id_hex,
        "pubkey": author.pk_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": hex(&sig.to_byte_array()),
    });
    (id_hex, event.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn ws_options(deflate: bool) -> Options {
    let mut options = Options::default()
        .with_max_payload_read(16 << 20)
        .with_no_delay();
    if deflate {
        options = options.with_compression_level(CompressionLevel::fast());
    }
    options
}

async fn connect(url: &url::Url, deflate: bool) -> Result<TcpWebSocket, String> {
    WebSocket::connect(url.clone())
        .with_options(ws_options(deflate))
        .await
        .map_err(|e| e.to_string())
}

/// Same connect, bound to a specific loopback address. `conns` uses it
/// to spread 50,000 sockets over 127.0.0.2-127.0.0.9 once the kernel
/// runs out of ports on 127.0.0.1.
async fn connect_bound(
    url: &url::Url,
    deflate: bool,
    addr: std::net::IpAddr,
) -> Result<TcpWebSocket, String> {
    WebSocket::connect(url.clone())
        .with_local_address(addr)
        .with_options(ws_options(deflate))
        .await
        .map_err(|e| e.to_string())
}

/// Connect from the default source; on failure (the kernel ran out of
/// loopback ports) retry bound to one of 127.0.0.2-127.0.0.9. Returns
/// `(socket, used_fallback)`.
async fn connect_spread(
    url: &url::Url,
    deflate: bool,
    j: usize,
) -> Result<(TcpWebSocket, bool), String> {
    match connect(url, deflate).await {
        Ok(ws) => Ok((ws, false)),
        Err(_) => {
            let addr = std::net::IpAddr::from([127, 0, 0, 2 + (j % 8) as u8]);
            connect_bound(url, deflate, addr).await.map(|ws| (ws, true))
        }
    }
}

/// Send a REQ and read until its EOSE. Frames before EOSE are ignored.
async fn subscribe(ws: &mut TcpWebSocket, sub_id: &str, filter: &Value) -> Result<(), String> {
    let req = json!(["REQ", sub_id, filter]).to_string();
    ws.send(Frame::text(req)).await.map_err(|e| e.to_string())?;
    let eose = json!(["EOSE", sub_id]).to_string();
    while let Some(frame) = ws.next().await {
        if frame.opcode() == OpCode::Text {
            let text = frame.as_str();
            if text == eose {
                return Ok(());
            }
            if text.starts_with("[\"CLOSED\"") || text.starts_with("[\"NOTICE\"") {
                return Err(text.to_owned());
            }
        }
    }
    Err("connection closed before EOSE".to_owned())
}

/// Process memory and CPU at one instant.
#[derive(Clone, Copy)]
struct ProcStats {
    /// Resident set size in KiB (includes file-backed LMDB pages).
    rss_kib: u64,
    /// Anonymous resident memory in KiB (Linux only): heap, stacks and
    /// buffers, excluding the file-backed LMDB map.
    rss_anon_kib: Option<u64>,
    /// Cumulative user + system CPU seconds.
    cpu_secs: f64,
    /// Live thread count (Linux `/proc/<pid>/status` only).
    threads: Option<u64>,
}

impl ProcStats {
    /// The memory figure to attribute to connections: anonymous RSS
    /// where available, total RSS otherwise.
    fn mem_kib(self) -> u64 {
        self.rss_anon_kib.unwrap_or(self.rss_kib)
    }
}

/// Memory and CPU of `pid`: `/proc` on Linux, `ps` elsewhere.
fn proc_stats(pid: u32) -> Option<ProcStats> {
    #[cfg(target_os = "linux")]
    {
        proc_stats_linux(pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        proc_stats_ps(pid).map(|(rss_kib, cpu_secs)| ProcStats {
            rss_kib,
            rss_anon_kib: None,
            cpu_secs,
            threads: None,
        })
    }
}

#[cfg(target_os = "linux")]
fn proc_stats_linux(pid: u32) -> Option<ProcStats> {
    use std::sync::OnceLock;
    static CLK_TCK: OnceLock<f64> = OnceLock::new();
    let ticks_per_sec = *CLK_TCK.get_or_init(|| {
        Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(100.0)
    });
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the parenthesized command name; utime/stime are fields 14/15 overall.
    let rest = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime: f64 = fields.get(11)?.parse().ok()?;
    let stime: f64 = fields.get(12)?.parse().ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let kib = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
    };
    Some(ProcStats {
        rss_kib: kib("VmRSS:")?,
        rss_anon_kib: kib("RssAnon:"),
        cpu_secs: (utime + stime) / ticks_per_sec,
        threads: kib("Threads:"),
    })
}

/// Resident set size (KiB) and cumulative CPU seconds of `pid`, via `ps`.
#[cfg(not(target_os = "linux"))]
fn proc_stats_ps(pid: u32) -> Option<(u64, f64)> {
    let out = Command::new("ps")
        .args(["-o", "rss=,time=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let mut fields = text.split_whitespace();
    let rss = fields.next()?.parse().ok()?;
    let time = fields.next()?;
    // `[[hh:]mm:]ss.ff`, or `d-hh:mm:ss` on some systems.
    let (days, clock) = time.split_once('-').unwrap_or(("0", time));
    let mut seconds = days.parse::<f64>().ok()? * 86_400.0;
    let mut unit = 1.0;
    for part in clock.rsplit(':') {
        seconds += part.parse::<f64>().ok()? * unit;
        unit *= 60.0;
    }
    Some((rss, seconds))
}

/// Nearest-rank percentile of `sorted` microseconds, in milliseconds.
fn percentile(sorted: &[u32], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    f64::from(sorted[rank.min(sorted.len() - 1)]) / 1000.0
}

#[derive(Default)]
struct SubOutcome {
    latencies_us: Vec<u32>,
    received: usize,
    duplicates: usize,
    unknown: usize,
    error: Option<String>,
}

/// One live subscriber after EOSE: record the delivery latency of every
/// expected event until all arrived or `stop` fires.
async fn run_subscriber(
    mut ws: TcpWebSocket,
    expected: usize,
    index: Arc<HashMap<String, u32>>,
    sent: Arc<Vec<AtomicU64>>,
    base: Instant,
    done: Arc<AtomicUsize>,
    mut stop: watch::Receiver<bool>,
) -> SubOutcome {
    let mut outcome = SubOutcome::default();
    let mut seen = vec![false; sent.len()];
    if expected == 0 {
        done.fetch_add(1, Ordering::Relaxed);
    }
    loop {
        tokio::select! {
            frame = ws.next() => {
                let Some(frame) = frame else {
                    outcome.error = Some("connection closed".to_owned());
                    break;
                };
                if frame.opcode() != OpCode::Text {
                    continue;
                }
                let now = base.elapsed().as_nanos() as u64;
                let text = frame.as_str();
                if !text.starts_with("[\"EVENT\"") {
                    continue;
                }
                let Some(pos) = text.find("\"id\":\"") else {
                    outcome.unknown += 1;
                    continue;
                };
                let Some(id) = text.get(pos + 6..pos + 70) else {
                    outcome.unknown += 1;
                    continue;
                };
                let Some(&i) = index.get(id) else {
                    outcome.unknown += 1;
                    continue;
                };
                let i = i as usize;
                if seen[i] {
                    outcome.duplicates += 1;
                    continue;
                }
                seen[i] = true;
                let sent_at = sent[i].load(Ordering::Acquire);
                if sent_at == 0 {
                    outcome.unknown += 1;
                    continue;
                }
                let latency_us = now.saturating_sub(sent_at - 1) / 1000;
                outcome.latencies_us.push(u32::try_from(latency_us).unwrap_or(u32::MAX));
                outcome.received += 1;
                if outcome.received == expected {
                    done.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ = stop.changed() => break,
        }
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn fanout(
    url: url::Url,
    subs: usize,
    events: usize,
    rate: f64,
    mode: Mode,
    authors_n: usize,
    deflate: bool,
    pid: Option<u32>,
    label: String,
) -> Result<(), String> {
    let now = unix_now();
    let authors: Vec<Author> = (0..authors_n).map(author).collect();
    // A per-run `t` tag: on a public relay, foreign kind-1 traffic must
    // not count toward this run's deliveries.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let tag = format!("fanout-{nonce:x}");
    let tags = json!([["t", tag]]);
    let mut index = HashMap::with_capacity(events);
    let mut messages = Vec::with_capacity(events);
    for i in 0..events {
        let (id, event) = sign_event(
            &authors[i % authors_n],
            now,
            1,
            &tags,
            &format!("fanout {nonce} {i}"),
        );
        index.insert(id, u32::try_from(i).expect("events fit in u32"));
        messages.push(format!("[\"EVENT\",{event}]"));
    }
    let index = Arc::new(index);
    let sent: Arc<Vec<AtomicU64>> = Arc::new((0..events).map(|_| AtomicU64::new(0)).collect());
    let base = Instant::now();

    // Per-subscriber expectation and filter.
    let per_author = |a: usize| events / authors_n + usize::from(a < events % authors_n);
    let plan: Vec<(usize, Value)> = (0..subs)
        .map(|j| match mode {
            Mode::Broadcast => (
                events,
                json!({"kinds": [1], "#t": [tag], "since": now}),
            ),
            Mode::Selective => {
                let a = j % authors_n;
                (
                    per_author(a),
                    json!({"kinds": [1], "#t": [tag], "authors": [authors[a].pk_hex], "since": now}),
                )
            }
        })
        .collect();
    let expected_total: usize = plan.iter().map(|(n, _)| n).sum();

    // Build up subscribers; each task signals readiness after EOSE.
    let (stop_tx, stop_rx) = watch::channel(false);
    let ready = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Semaphore::new(HANDSHAKE_CONCURRENCY));
    let mut tasks = Vec::with_capacity(subs);
    for (j, (expected, filter)) in plan.into_iter().enumerate() {
        let (url, index, sent, done, stop, ready, failed, gate) = (
            url.clone(),
            Arc::clone(&index),
            Arc::clone(&sent),
            Arc::clone(&done),
            stop_rx.clone(),
            Arc::clone(&ready),
            Arc::clone(&failed),
            Arc::clone(&gate),
        );
        tasks.push(tokio::spawn(async move {
            let permit = gate.acquire_owned().await.expect("semaphore open");
            let mut ws = match connect(&url, deflate).await {
                Ok(ws) => ws,
                Err(e) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    return SubOutcome {
                        error: Some(e),
                        ..SubOutcome::default()
                    };
                }
            };
            if let Err(e) = subscribe(&mut ws, &format!("s{j}"), &filter).await {
                failed.fetch_add(1, Ordering::Relaxed);
                return SubOutcome {
                    error: Some(e),
                    ..SubOutcome::default()
                };
            }
            drop(permit);
            ready.fetch_add(1, Ordering::Relaxed);
            run_subscriber(ws, expected, index, sent, base, done, stop).await
        }));
    }
    let extensions = openloop::server_extensions(&url, deflate);
    let ready_deadline = Instant::now() + READY_TIMEOUT;
    while ready.load(Ordering::Relaxed) + failed.load(Ordering::Relaxed) < subs {
        if Instant::now() >= ready_deadline {
            return Err(format!(
                "subscribers not ready in {}s",
                READY_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let subs_ready = ready.load(Ordering::Relaxed);
    let subs_failed = failed.load(Ordering::Relaxed);

    // Publisher.
    let publisher = connect(&url, deflate).await?;
    let (mut sink, mut stream) = publisher.split();
    let oks = tokio::spawn(async move {
        let (mut accepted, mut rejected) = (0usize, 0usize);
        while accepted + rejected < events {
            let Some(frame) = stream.next().await else {
                break;
            };
            if frame.opcode() != OpCode::Text {
                continue;
            }
            let text = frame.as_str();
            if !text.starts_with("[\"OK\"") {
                continue;
            }
            if text.contains(",true,") {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        (accepted, rejected)
    });

    let meter = sampler::HarnessMeter::begin();
    let sampler = pid.map(sampler::Sampler::start);
    let before = pid.and_then(proc_stats);
    let publish_start = Instant::now();
    // `sent[i]` carries the scheduled target, not the actual send
    // time: delivery latency then measures the relay, not the
    // harness's send lag, which goes to its own histogram.
    let publish_offset_ns = publish_start.duration_since(base).as_nanos() as u64;
    let mut send_lag = hist::Hist::new();
    for (i, message) in messages.into_iter().enumerate() {
        let scheduled_ns = publish_offset_ns + (i as f64 / rate * 1e9) as u64;
        let target = publish_start + Duration::from_nanos(scheduled_ns - publish_offset_ns);
        tokio::time::sleep_until(target.into()).await;
        let now = base.elapsed().as_nanos() as u64;
        sent[i].store(scheduled_ns + 1, Ordering::Release);
        send_lag.record_us(now.saturating_sub(scheduled_ns) / 1000);
        sink.send(Frame::text(message))
            .await
            .map_err(|e| format!("publish send: {e}"))?;
    }
    let publish_secs = publish_start.elapsed().as_secs_f64();
    let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
    while done.load(Ordering::Relaxed) < subs_ready && Instant::now() < drain_deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let elapsed_secs = publish_start.elapsed().as_secs_f64();
    let sampler_json = sampler.map(sampler::Sampler::finish);
    let meter_json = meter.finish();
    let after = pid.and_then(proc_stats);
    let (accepted, rejected) = tokio::time::timeout(DRAIN_TIMEOUT, oks)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or((0, 0));
    stop_tx.send_replace(true);

    let mut latencies = hist::Hist::new();
    let (mut received, mut duplicates, mut unknown, mut errors) = (0, 0, 0, 0);
    for task in tasks {
        let outcome = task.await.unwrap_or_default();
        received += outcome.received;
        duplicates += outcome.duplicates;
        unknown += outcome.unknown;
        errors += usize::from(outcome.error.is_some());
        for us in outcome.latencies_us {
            latencies.record_us(u64::from(us));
        }
    }
    let latency_ms = latencies.json();
    let missing = expected_total.saturating_sub(received);
    let result = json!({
        "scenario": "fanout",
        "label": label,
        "mode": format!("{mode:?}").to_lowercase(),
        "deflate": deflate,
        "subs": subs,
        "subs_ready": subs_ready,
        "subs_failed": subs_failed,
        "events": events,
        "rate": rate,
        "ok_accepted": accepted,
        "ok_rejected": rejected,
        "expected": expected_total,
        "delivered": received,
        "missing": missing,
        "duplicates": duplicates,
        "unknown": unknown,
        "subscriber_errors": errors,
        "valid": missing == 0
            && duplicates == 0
            && subs_failed == 0
            && errors == 0
            && unknown == 0
            && meter_json["harness_saturated"].as_bool() == Some(false),
        "publish_secs": publish_secs,
        "elapsed_secs": elapsed_secs,
        "latency_p50_ms": latency_ms["p50_ms"],
        "latency_p99_ms": latency_ms["p99_ms"],
        "latency_ms": {
            "p50": latency_ms["p50_ms"],
            "p90": latency_ms["p90_ms"],
            "p99": latency_ms["p99_ms"],
            "p999": latency_ms["p999_ms"],
            "max": latency_ms["max_ms"],
        },
        "latency_hist": latency_ms,
        "send_lag": send_lag.json(),
        "server_extensions": extensions,
        "sampler": sampler_json,
        "harness": meter_json,
        "relay_cpu_secs": match (before, after) { (Some(b), Some(a)) => json!(a.cpu_secs - b.cpu_secs), _ => Value::Null },
        "relay_rss_kib_after": after.map(|a| a.rss_kib),
        "relay_rss_anon_kib_after": after.and_then(|a| a.rss_anon_kib),
    });
    println!("{result}");
    Ok(())
}

async fn conns(
    url: url::Url,
    n: usize,
    deflate: bool,
    pid: Option<u32>,
    hold_secs: u64,
    label: String,
) {
    let before = pid.and_then(proc_stats);
    let (stop_tx, stop_rx) = watch::channel(false);
    let ready = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let bind_fallbacks = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Semaphore::new(HANDSHAKE_CONCURRENCY));
    let start = Instant::now();
    let mut tasks = Vec::with_capacity(n);
    for j in 0..n {
        let (url, ready, failed, dropped, bind_fallbacks, gate, mut stop) = (
            url.clone(),
            Arc::clone(&ready),
            Arc::clone(&failed),
            Arc::clone(&dropped),
            Arc::clone(&bind_fallbacks),
            Arc::clone(&gate),
            stop_rx.clone(),
        );
        tasks.push(tokio::spawn(async move {
            let permit = gate.acquire_owned().await.expect("semaphore open");
            // Primary bind is 127.0.0.1; when the kernel runs out of
            // ports, retry spread over 127.0.0.2-127.0.0.9.
            let (mut ws, fallback) = match connect_spread(&url, deflate, j).await {
                Ok(pair) => pair,
                Err(_) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            if fallback {
                bind_fallbacks.fetch_add(1, Ordering::Relaxed);
            }
            if subscribe(
                &mut ws,
                &format!("c{j}"),
                &json!({"kinds": [1], "limit": 1}),
            )
            .await
            .is_err()
            {
                failed.fetch_add(1, Ordering::Relaxed);
                return;
            }
            drop(permit);
            ready.fetch_add(1, Ordering::Relaxed);
            loop {
                tokio::select! {
                    frame = ws.next() => {
                        if frame.is_none() {
                            // A socket that ended before the hold was
                            // released dropped during the hold.
                            if !*stop.borrow() {
                                dropped.fetch_add(1, Ordering::Relaxed);
                            }
                            break;
                        }
                    },
                    _ = stop.changed() => break,
                }
            }
        }));
    }
    let deadline = Instant::now() + READY_TIMEOUT;
    while ready.load(Ordering::Relaxed) + failed.load(Ordering::Relaxed) < n {
        assert!(Instant::now() < deadline, "connections not ready in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let setup_secs = start.elapsed().as_secs_f64();
    tokio::time::sleep(Duration::from_secs(hold_secs)).await;
    let held = pid.and_then(proc_stats);
    let opened = ready.load(Ordering::Relaxed);
    stop_tx.send_replace(true);
    for task in tasks {
        let _ = task.await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let released = pid.and_then(proc_stats);
    let mem = |a: Option<ProcStats>| a.map(ProcStats::mem_kib);
    let result = json!({
        "scenario": "conns",
        "label": label,
        "deflate": deflate,
        "requested": n,
        "accepted": opened,
        "failed": failed.load(Ordering::Relaxed),
        "local_bind_fallbacks": bind_fallbacks.load(Ordering::Relaxed),
        "dropped_during_hold": dropped.load(Ordering::Relaxed),
        "setup_secs": setup_secs,
        "rss_kib_before": before.map(|b| b.rss_kib),
        "rss_kib_held": held.map(|h| h.rss_kib),
        "rss_kib_after_close": released.map(|r| r.rss_kib),
        "rss_anon_kib_before": before.and_then(|b| b.rss_anon_kib),
        "rss_anon_kib_held": held.and_then(|h| h.rss_anon_kib),
        "rss_anon_kib_after_close": released.and_then(|r| r.rss_anon_kib),
        "mem_metric": match held {
            Some(h) if h.rss_anon_kib.is_some() => json!("RssAnon"),
            Some(_) => json!("RSS"),
            None => Value::Null,
        },
        "kib_per_conn": match (mem(before), mem(held)) {
            (Some(b), Some(h)) if opened > 0 => json!((h as f64 - b as f64) / opened as f64),
            _ => Value::Null,
        },
        "relay_cpu_secs_setup": match (before, held) {
            (Some(b), Some(h)) => json!(h.cpu_secs - b.cpu_secs),
            _ => Value::Null,
        },
    });
    println!("{result}");
}

#[tokio::main]
async fn main() -> Result<(), String> {
    match Cli::parse().cmd {
        Cmd::Fanout {
            url,
            subs,
            events,
            rate,
            mode,
            authors,
            deflate,
            pid,
            label,
        } => {
            let url = url.parse().expect("valid ws url");
            fanout(
                url,
                subs,
                events,
                rate,
                mode,
                authors.max(1),
                deflate,
                pid,
                label,
            )
            .await
            .map_err(|e| format!("fanout: {e}"))?;
        }
        Cmd::Conns {
            url,
            conns: n,
            deflate,
            pid,
            hold_secs,
            label,
        } => {
            let url = url.parse().expect("valid ws url");
            conns(url, n, deflate, pid, hold_secs, label).await;
        }
        Cmd::Rtt { url, n } => {
            let url = url.parse().expect("valid ws(s) url");
            gate::rtt(url, n).await;
        }
        Cmd::Ingest {
            url,
            conns,
            events,
            rate_per_conn,
        } => {
            let url = url.parse().expect("valid ws(s) url");
            gate::ingest(url, conns, events, rate_per_conn).await;
        }
        Cmd::Wake {
            url,
            subs,
            idle_secs,
            rounds,
            events,
            auth,
        } => {
            let url = url.parse().expect("valid ws(s) url");
            gate::wake(url, subs, idle_secs, rounds, events, auth).await;
        }
        Cmd::IngestOpen {
            url,
            corpus,
            conns,
            rate,
            duration,
            warmup,
            deflate,
            pid,
            label,
            skip,
        } => {
            let url = url.parse().expect("valid ws url");
            let opts = openloop::IngestOpts {
                corpus,
                conns,
                duration,
                warmup,
                deflate,
                pid,
                label,
                skip,
            };
            openloop::ingest_open(url, opts, rate)
                .await
                .map_err(|e| format!("ingest-open: {e}"))?;
        }
        Cmd::IngestClosed {
            url,
            corpus,
            conns,
            window,
            duration,
            warmup,
            deflate,
            pid,
            label,
            skip,
        } => {
            let url = url.parse().expect("valid ws url");
            let opts = openloop::IngestOpts {
                corpus,
                conns,
                duration,
                warmup,
                deflate,
                pid,
                label,
                skip,
            };
            openloop::ingest_closed(url, opts, window)
                .await
                .map_err(|e| format!("ingest-closed: {e}"))?;
        }
        Cmd::Query {
            url,
            params,
            mix,
            log,
            conns,
            duration,
            warmup,
            seed,
            deflate,
            pid,
            label,
        } => {
            let url = url.parse().expect("valid ws url");
            let opts = query::QueryOpts {
                params,
                mix,
                log,
                conns,
                duration,
                warmup,
                seed,
                deflate,
                pid,
                label,
            };
            query::query(url, opts)
                .await
                .map_err(|e| format!("query: {e}"))?;
        }
        Cmd::AckIngest {
            url,
            corpus,
            conns,
            rate,
            out,
            label,
        } => {
            let url = url.parse().expect("valid ws url");
            ack::ack_ingest(url, corpus, conns, rate, out, label)
                .await
                .map_err(|e| format!("ack-ingest: {e}"))?;
        }
        Cmd::AckCheck { url, ids } => {
            let url = url.parse().expect("valid ws url");
            ack::ack_check(url, ids)
                .await
                .map_err(|e| format!("ack-check: {e}"))?;
        }
        Cmd::Neg {
            url,
            corpus,
            base,
            holdout_corpus,
            diff_pct,
            seed,
            frame_size_limit,
            pid,
            label,
        } => {
            let url = url.parse().expect("valid ws url");
            neg::neg(
                url,
                corpus,
                holdout_corpus,
                base,
                diff_pct,
                seed,
                frame_size_limit,
                pid,
                label,
            )
            .await
            .map_err(|e| format!("neg: {e}"))?;
        }
        Cmd::CorpusFilter {
            regular,
            first,
            skip,
            input,
            out,
        } => {
            corpus::corpus_filter(regular, first, skip, &input, &out)
                .map_err(|e| format!("corpus-filter: {e}"))?;
        }
        Cmd::Gen {
            template,
            events,
            holdout,
            authors,
            seed,
            out,
            threads,
        } => {
            let threads = if threads == 0 {
                std::thread::available_parallelism().map_or(1, |n| n.get())
            } else {
                threads
            };
            let opts = corpus::GenOpts {
                template,
                events,
                holdout,
                authors,
                seed,
                out,
                threads,
            };
            let result = corpus::run(&opts).map_err(|e| format!("gen: {e}"))?;
            println!("{result}");
        }
        Cmd::Subbudget { url, authors } => {
            let url = url.parse().expect("valid ws(s) url");
            gate::subbudget(url, authors).await;
        }
        Cmd::Scan { url, filter, n } => {
            let url = url.parse().expect("valid ws(s) url");
            gate::scan(url, &filter, n).await;
        }
        Cmd::Soak {
            url,
            metrics_url,
            pid,
            db_dir,
            duration_secs,
            sample_secs,
            publishers,
            rate,
            subscribers,
            churn_rate,
            slow_every_secs,
            neg_every_secs,
            vanish_every_secs,
            label,
            deflate,
        } => {
            let url = url.parse().expect("valid ws url");
            let metrics_url = metrics_url.map(|u| u.parse().expect("valid metrics url"));
            soak::run(
                url,
                metrics_url,
                pid,
                db_dir,
                duration_secs,
                sample_secs,
                publishers,
                rate,
                subscribers,
                churn_rate,
                slow_every_secs,
                neg_every_secs,
                vanish_every_secs,
                label,
                deflate,
            )
            .await;
        }
    }
    Ok(())
}
