//! `query`: the stored-query driver.
//!
//! `C` connections each run a closed REQ→EOSE→CLOSE loop for `W + D`
//! seconds. A connection picks a mix entry by weight and fills the
//! template's placeholders from `params.json` with its own rng —
//! keyed by `seed + k`, so identical seeds replay identical query
//! sequences on every relay. Every query appends one JSONL line to
//! `--log`; only queries whose EOSE lands inside `[W, W+D]` feed the
//! measured counts, while errors are tallied whenever they happen.

use std::collections::BTreeMap;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use rand::RngExt;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use yawc::{Frame, OpCode};

use crate::corpus::keyed_rng;
use crate::hist::Hist;
use crate::sampler::{HarnessMeter, Sampler};

/// How long one REQ may wait for its EOSE.
const REQ_TIMEOUT: Duration = Duration::from_secs(30);

/// CLI arguments for `query`.
pub(crate) struct QueryOpts {
    /// `params.json` produced by `gen`.
    pub(crate) params: PathBuf,
    /// The weighted query mix.
    pub(crate) mix: PathBuf,
    /// Per-query JSONL log destination.
    pub(crate) log: PathBuf,
    /// Parallel query connections.
    pub(crate) conns: usize,
    /// `--duration` of the measured phase, in seconds.
    pub(crate) duration: u64,
    /// `--warmup` before the measured phase, in seconds.
    pub(crate) warmup: u64,
    /// Draw seed; connection `k` reseeds on `seed + k`.
    pub(crate) seed: u64,
    /// Negotiate permessage-deflate.
    pub(crate) deflate: bool,
    /// Relay process to sample.
    pub(crate) pid: Option<u32>,
    /// Run label echoed into the result.
    pub(crate) label: String,
}

/// One `params.json` `(kind, pubkey, d)` addressable triple.
#[derive(Clone, Deserialize)]
struct Addr {
    kind: u64,
    pubkey: String,
    d: String,
}

/// The generator's query sidecar.
#[derive(Deserialize)]
struct Params {
    #[serde(default)]
    authors_popular: Vec<String>,
    #[serde(default)]
    authors_random: Vec<String>,
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    tag_t: Vec<String>,
    #[serde(default)]
    follows: Vec<Vec<String>>,
    created_at: [u64; 2],
    #[serde(default)]
    addr: Vec<Addr>,
    #[serde(default)]
    pool_ids: Vec<String>,
}

/// One weighted mix entry.
#[derive(Deserialize)]
struct MixEntry {
    name: String,
    weight: u32,
    template: Value,
}

/// Load a JSON file and report the path on failure.
fn load<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path:?}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{what} {path:?}: {e}"))
}

/// Pick one element of `pool`; `None` when empty.
fn pick<'a, T>(pool: &'a [T], rng: &mut ChaCha20Rng) -> Option<&'a T> {
    (!pool.is_empty()).then(|| &pool[rng.random_range(0..pool.len())])
}

/// Per-query placeholder resolution. `windows` and `addr` are cached
/// so `{window:S}.since`/`.until` and the three `{addr}` fields of one
/// filter agree.
struct Filler<'a> {
    params: &'a Params,
    rng: &'a mut ChaCha20Rng,
    windows: BTreeMap<u64, (u64, u64)>,
    addr: Option<Addr>,
}

impl Filler<'_> {
    /// `{name[:arg][.field]}` → its drawn value, `None` to keep the
    /// literal (unresolvable placeholders fail validation up front).
    fn resolve(&mut self, s: &str) -> Option<Value> {
        let close = s.find('}')?;
        if !s.starts_with('{') {
            return None;
        }
        let inner = &s[1..close];
        let (name, arg) = inner.split_once(':').unwrap_or((inner, ""));
        let field = s[close + 1..].strip_prefix('.');
        let rng = &mut *self.rng;
        match name {
            "author" => pick(&self.params.authors_random, rng).map(|a| json!(a)),
            "author_pop" => pick(&self.params.authors_popular, rng).map(|a| json!(a)),
            "authors" => {
                let n: usize = arg.parse().ok()?;
                let pool = &self.params.authors_random;
                if pool.is_empty() {
                    return None;
                }
                Some(
                    (0..n)
                        .map(|_| json!(pool[rng.random_range(0..pool.len())]))
                        .collect(),
                )
            }
            "follow" => pick(&self.params.follows, rng).map(|f| json!(f)),
            "ids" => {
                let n: usize = arg.parse().ok()?;
                let pool = &self.params.ids;
                if pool.is_empty() {
                    return None;
                }
                Some(
                    (0..n)
                        .map(|_| json!(pool[rng.random_range(0..pool.len())]))
                        .collect(),
                )
            }
            "tag_t" => pick(&self.params.tag_t, rng).map(|t| json!(t)),
            "event_id" => pick(&self.params.pool_ids, rng).map(|id| json!(id)),
            "window" => {
                let secs: u64 = arg.parse().ok()?;
                let [min, max] = self.params.created_at;
                let (since, until) = *self.windows.entry(secs).or_insert_with(|| {
                    let slack = max.saturating_sub(min + secs);
                    let since = min + rng.random_range(0..=slack);
                    (since, since + secs)
                });
                match field {
                    Some("since") => Some(json!(since)),
                    Some("until") => Some(json!(until)),
                    _ => None,
                }
            }
            "addr" => {
                if self.addr.is_none() {
                    self.addr = pick(&self.params.addr, rng).cloned();
                }
                let addr = self.addr.as_ref()?;
                match field {
                    Some("kind") => Some(json!(addr.kind)),
                    Some("pubkey") => Some(json!(addr.pubkey)),
                    Some("d") => Some(json!(addr.d)),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

/// Deep-substitute placeholders in a template filter.
fn fill(template: &Value, f: &mut Filler) -> Value {
    match template {
        Value::String(s) => f.resolve(s).unwrap_or_else(|| template.clone()),
        Value::Array(a) => Value::Array(a.iter().map(|e| fill(e, f)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), fill(v, f))).collect()),
        _ => template.clone(),
    }
}

/// `true` when a filled filter still carries an unresolved
/// placeholder string — a mix entry pointing at an empty sidecar pool.
fn unresolved(v: &Value) -> bool {
    match v {
        Value::String(s) => s.starts_with('{') && s.contains('}'),
        Value::Array(a) => a.iter().any(unresolved),
        Value::Object(o) => o.values().any(unresolved),
        _ => false,
    }
}

/// One template's measured tallies.
#[derive(Default)]
struct TemplateOut {
    queries: usize,
    latency: Hist,
    /// Per-query event counts, for the mean and p50.
    events: Vec<u64>,
}

/// What one connection brings back.
#[derive(Default)]
struct ConnOut {
    by_name: BTreeMap<String, TemplateOut>,
    overall: TemplateOut,
    /// Error reason → count, measured or not.
    errors: BTreeMap<String, usize>,
}

/// The JSONL sink shared by every connection.
struct QueryLog(Mutex<BufWriter<std::fs::File>>);

impl QueryLog {
    fn append(&self, entry: &Value) {
        let mut w = self.0.lock().expect("query log");
        if writeln!(w, "{entry}").is_err() {
            eprintln!("query: log write failed");
        }
    }
}

/// Send `REQ` and read until its EOSE, then `CLOSE`. Returns the
/// number of EVENT frames and the REQ→EOSE latency in microseconds.
async fn round_trip(
    sink: &mut futures::stream::SplitSink<yawc::TcpWebSocket, Frame>,
    stream: &mut futures::stream::SplitStream<yawc::TcpWebSocket>,
    sub_id: &str,
    filter: &Value,
) -> Result<(usize, u64), String> {
    let req = json!(["REQ", sub_id, filter]).to_string();
    let t0 = Instant::now();
    sink.send(Frame::text(req))
        .await
        .map_err(|e| format!("send: {e}"))?;
    let read = async {
        let mut n_events = 0usize;
        while let Some(frame) = stream.next().await {
            if frame.opcode() != OpCode::Text {
                continue;
            }
            let text = frame.as_str();
            if text.starts_with("[\"EVENT\"") {
                n_events += 1;
            } else if text.starts_with("[\"EOSE\"") {
                return Ok(n_events);
            } else if text.starts_with("[\"CLOSED\"") {
                let reason = serde_json::from_str::<Vec<Value>>(text)
                    .ok()
                    .and_then(|a| a.get(2).and_then(Value::as_str).map(str::to_owned))
                    .unwrap_or_default();
                return Err(format!("closed:{reason}"));
            }
        }
        Err("connection closed".to_owned())
    };
    let n_events = tokio::time::timeout(REQ_TIMEOUT, read)
        .await
        .map_err(|_| "timeout".to_owned())??;
    sink.send(Frame::text(json!(["CLOSE", sub_id]).to_string()))
        .await
        .map_err(|e| format!("close: {e}"))?;
    Ok((n_events, t0.elapsed().as_micros() as u64))
}

/// Everything one query connection needs, bundled to keep
/// `query_conn` under the argument-count lint.
#[derive(Clone)]
struct ConnSpec {
    opts: Arc<QueryOpts>,
    mix: Arc<Vec<MixEntry>>,
    cum_weights: Arc<Vec<u64>>,
    params: Arc<Params>,
    log: Arc<QueryLog>,
    end_ns: u64,
    base: Instant,
}

/// One query connection's closed REQ loop until `spec.end_ns`.
async fn query_conn(url: url::Url, k: usize, spec: ConnSpec) -> ConnOut {
    let mut out = ConnOut::default();
    let ws = match crate::connect(&url, spec.opts.deflate).await {
        Ok(ws) => ws,
        Err(e) => {
            *out.errors.entry(format!("connect: {e}")).or_default() += 1;
            return out;
        }
    };
    let (mut sink, mut stream) = ws.split();
    let mut rng = keyed_rng(spec.opts.seed + k as u64, b"query", 0);
    let warm_ns = spec.opts.warmup * 1_000_000_000;
    let total_weight = *spec.cum_weights.last().unwrap_or(&0);
    let mut seq = 0usize;
    while spec.base.elapsed().as_nanos() as u64 <= spec.end_ns {
        let draw = rng.random_range(0..total_weight);
        let idx = spec
            .cum_weights
            .iter()
            .position(|&c| draw < c)
            .unwrap_or(spec.mix.len() - 1);
        let entry = &spec.mix[idx];
        let filter = fill(
            &entry.template,
            &mut Filler {
                params: &spec.params,
                rng: &mut rng,
                windows: BTreeMap::new(),
                addr: None,
            },
        );
        let filter_sha: [u8; 32] = Sha256::digest(filter.to_string().as_bytes()).into();
        let sub_id = format!("q{k}-{seq}");
        match round_trip(&mut sink, &mut stream, &sub_id, &filter).await {
            Ok((n_events, latency_us)) => {
                let now = spec.base.elapsed().as_nanos() as u64;
                spec.log.append(&json!({
                    "conn": k,
                    "seq": seq,
                    "name": entry.name,
                    "filter_sha256": crate::hex(&filter_sha),
                    "n_events": n_events,
                    "latency_us": latency_us,
                }));
                if (warm_ns..=spec.end_ns).contains(&now) {
                    let slot = out.by_name.entry(entry.name.clone()).or_default();
                    slot.queries += 1;
                    slot.latency.record_us(latency_us);
                    slot.events.push(n_events as u64);
                    out.overall.queries += 1;
                    out.overall.latency.record_us(latency_us);
                    out.overall.events.push(n_events as u64);
                }
            }
            Err(e) => {
                // `send:`/`close:`/connection loss kills the socket;
                // protocol-level errors leave the loop running.
                let fatal =
                    e == "connection closed" || e.starts_with("send:") || e.starts_with("close:");
                *out.errors.entry(e).or_default() += 1;
                if fatal {
                    break;
                }
            }
        }
        seq += 1;
    }
    out
}

/// The `events_mean`/`events_p50` block for one template or overall.
fn template_json(slot: &mut TemplateOut) -> Value {
    slot.events.sort_unstable();
    let p50 = if slot.events.is_empty() {
        Value::Null
    } else {
        let rank = (50.0 / 100.0 * (slot.events.len() - 1) as f64).round() as usize;
        json!(slot.events[rank.min(slot.events.len() - 1)])
    };
    let mean = if slot.events.is_empty() {
        Value::Null
    } else {
        json!(slot.events.iter().sum::<u64>() as f64 / slot.events.len() as f64)
    };
    json!({
        "queries": slot.queries,
        "latency": slot.latency.json(),
        "events_mean": mean,
        "events_p50": p50,
    })
}

/// `query --params P --mix M --log L --conns C --duration D --warmup W`.
pub(crate) async fn query(url: url::Url, opts: QueryOpts) -> Result<(), String> {
    let started_utc = crate::unix_now();
    let params: Params = load(&opts.params, "params")?;
    let mix: Vec<MixEntry> = load(&opts.mix, "mix")?;
    if mix.is_empty() {
        return Err("mix has no entries".to_owned());
    }
    // Fail fast: every placeholder in every template must resolve
    // against this params.json.
    let mut probe = keyed_rng(opts.seed, b"query-validate", 0);
    for entry in &mix {
        if entry.weight == 0 {
            return Err(format!("mix entry {:?} has weight 0", entry.name));
        }
        let filled = fill(
            &entry.template,
            &mut Filler {
                params: &params,
                rng: &mut probe,
                windows: BTreeMap::new(),
                addr: None,
            },
        );
        if unresolved(&filled) {
            return Err(format!(
                "mix entry {:?} has a placeholder params.json cannot fill",
                entry.name
            ));
        }
    }
    let mut cum_weights = Vec::with_capacity(mix.len());
    let mut acc = 0u64;
    for e in &mix {
        acc += u64::from(e.weight);
        cum_weights.push(acc);
    }

    let log = std::fs::File::create(&opts.log)
        .map(BufWriter::new)
        .map(Mutex::new)
        .map(QueryLog)
        .map_err(|e| format!("{:?}: {e}", opts.log))?;
    let extensions = crate::openloop::server_extensions(&url, opts.deflate);

    let base = Instant::now();
    let warm_ns = opts.warmup * 1_000_000_000;
    let end_ns = (opts.warmup + opts.duration) * 1_000_000_000;
    let spec = ConnSpec {
        end_ns,
        base,
        opts: Arc::new(opts),
        mix: Arc::new(mix),
        cum_weights: Arc::new(cum_weights),
        params: Arc::new(params),
        log: Arc::new(log),
    };

    let mut tasks = Vec::with_capacity(spec.opts.conns);
    for k in 0..spec.opts.conns {
        let (url, spec) = (url.clone(), spec.clone());
        tasks.push(tokio::spawn(async move { query_conn(url, k, spec).await }));
    }

    // Instrument exactly the measured window [W, W+D].
    tokio::time::sleep_until((base + Duration::from_nanos(warm_ns)).into()).await;
    let meter = HarnessMeter::begin();
    let sampler = spec.opts.pid.map(Sampler::start);
    tokio::time::sleep_until((base + Duration::from_nanos(end_ns)).into()).await;
    let sampler_json = sampler.map(Sampler::finish);
    let meter_json = meter.finish();

    let mut by_name: BTreeMap<String, TemplateOut> = BTreeMap::new();
    let mut overall = TemplateOut::default();
    let mut errors: BTreeMap<String, usize> = BTreeMap::new();
    for t in tasks {
        let out = t.await.map_err(|e| e.to_string())?;
        for (name, slot) in out.by_name {
            let dst = by_name.entry(name).or_default();
            dst.queries += slot.queries;
            dst.latency.merge(&slot.latency);
            dst.events.extend(slot.events);
        }
        overall.queries += out.overall.queries;
        overall.latency.merge(&out.overall.latency);
        overall.events.extend(out.overall.events);
        for (reason, n) in out.errors {
            *errors.entry(reason).or_default() += n;
        }
    }

    let mut queries = serde_json::Map::new();
    queries.insert("overall".to_owned(), template_json(&mut overall));
    for (name, mut slot) in by_name {
        queries.insert(name, template_json(&mut slot));
    }
    let events_served: u64 = overall.events.iter().sum();
    let secs = spec.opts.duration.max(1) as f64;
    let cpu = sampler_json
        .as_ref()
        .and_then(|s| s["relay_cpu_secs"].as_f64());
    let result = json!({
        "scenario": "query",
        "label": spec.opts.label,
        "seed": spec.opts.seed,
        "conns": spec.opts.conns,
        "duration": spec.opts.duration,
        "warmup": spec.opts.warmup,
        "deflate": spec.opts.deflate,
        "params": spec.opts.params.display().to_string(),
        "mix": spec.opts.mix.display().to_string(),
        "log": spec.opts.log.display().to_string(),
        "queries": queries,
        "events_per_sec": events_served as f64 / secs,
        "relay_cpu_secs_per_1000_events": cpu
            .map(|c| json!(c / events_served.max(1) as f64 * 1000.0))
            .unwrap_or(Value::Null),
        "errors": errors,
        "valid": errors.is_empty()
            && events_served > 0
            && meter_json["harness_saturated"].as_bool() == Some(false),
        "server_extensions": extensions,
        "sampler": sampler_json,
        "harness": meter_json,
        "harness_sha": env!("GIT_SHA"),
        "started_utc": started_utc,
        "ended_utc": crate::unix_now(),
    });
    spec.log
        .0
        .lock()
        .expect("query log")
        .flush()
        .map_err(|e| e.to_string())?;
    println!("{result}");
    Ok(())
}
