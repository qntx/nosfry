//! `ingest-open` and `ingest-closed`: the ingest drivers.
//!
//! Open loop schedules every send in advance (`t0 + slot / rate`) so a
//! slow harness shows up as send lag instead of silently shrinking the
//! offered rate — the coordinated-omission-safe design. Closed loop
//! keeps `--window` events in flight per connection and measures the
//! relay's saturation throughput.
//!
//! Both match `OK` replies by event id against a pending map,
//! classify the reply (`accepted`, `duplicate`, `rate-limited`, other
//! rejections), and record latencies only inside the measured window
//! `[W, W+D]` — by scheduled time for open loop, by `OK` receipt for
//! closed.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::watch;
use yawc::{Frame, OpCode, TcpWebSocket};

use crate::hist::Hist;
use crate::sampler::{HarnessMeter, Sampler, probe_extensions};

/// How long to wait for outstanding `OK`s after the last send.
const DRAIN: Duration = Duration::from_secs(30);
/// Sends start one second after connection setup so sockets settle.
const SETTLE: Duration = Duration::from_secs(1);
/// Upper bound on the corpus preload for `ingest-closed`, whose send
/// count is not known up front: 4M lines ≈ 4 GiB of event JSON.
const CLOSED_PRELOAD_MAX: usize = 4_000_000;

/// CLI arguments shared by both ingest modes.
pub(crate) struct IngestOpts {
    /// `holdout.jsonl` from `gen`.
    pub(crate) corpus: std::path::PathBuf,
    /// Parallel connections.
    pub(crate) conns: usize,
    /// `--duration` of the measured phase, in seconds.
    pub(crate) duration: u64,
    /// `--warmup` before the measured phase, in seconds.
    pub(crate) warmup: u64,
    /// Negotiate permessage-deflate.
    pub(crate) deflate: bool,
    /// Relay process to sample.
    pub(crate) pid: Option<u32>,
    /// Run label echoed into the result.
    pub(crate) label: String,
    /// Corpus lines to skip before the first send (warmup included).
    pub(crate) skip: usize,
}

/// One corpus line ready to send: the `["EVENT",..]` wire message
/// plus the event's id bytes for `OK` matching.
#[derive(Clone)]
pub(crate) struct Ready {
    pub(crate) id: [u8; 32],
    pub(crate) msg: String,
}

/// Decode 64 hex chars into 32 bytes.
pub(crate) fn unhex(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (b[2 * i] as char).to_digit(16)? as u8;
        let lo = (b[2 * i + 1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Read at most `limit` corpus lines after discarding the first
/// `skip` lines, wrapping each in `["EVENT",]` and extracting its
/// `id`.
pub(crate) fn load_corpus(path: &Path, limit: usize, skip: usize) -> Result<Vec<Ready>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{path:?}: {e}"))?;
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut out = Vec::with_capacity(limit.min(1 << 20));
    let mut line = String::with_capacity(4096);
    for _ in 0..skip {
        line.clear();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
    }
    while out.len() < limit {
        line.clear();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let pos = line
            .find("\"id\":\"")
            .ok_or("corpus line without an id field")?;
        let id = unhex(line.get(pos + 6..pos + 70).unwrap_or(""))
            .ok_or("corpus line with a malformed id")?;
        out.push(Ready {
            id,
            msg: format!("[\"EVENT\",{line}]"),
        });
    }
    Ok(out)
}

/// Counters one connection brings back; hists merge afterwards.
#[derive(Default)]
struct ConnOut {
    accepted: usize,
    /// Rejected `OK`s that are really duplicates or superseded
    /// replaceable versions: nosfry `duplicate:`, strfry `replaced:`.
    accepted_duplicate: usize,
    rejected_rate_limited: usize,
    rejected_other: usize,
    /// Measured sends that never saw an `OK` by drain end.
    timeouts: usize,
    /// Warmup sends that never saw an `OK`.
    timeouts_warmup: usize,
    /// `OK`s received for measured sends after the window closed.
    late_acks: usize,
    ok_latency: Hist,
    error: Option<String>,
}

/// What the pending map records about one in-flight event: the send's
/// scheduled and actual time (nanos since `base`) and whether the
/// send falls inside the measured window.
struct Pending {
    scheduled_ns: u64,
    sent_ns: u64,
    measured: bool,
}

/// Classify an `OK` frame: `["OK","<id>",<bool>,"<reason>"]`.
pub(crate) fn classify_ok(text: &str) -> Option<(&str, bool, &str)> {
    if !text.starts_with("[\"OK\",\"") {
        return None;
    }
    let id = text.get(7..71)?;
    let rest = &text[72..];
    let accepted = rest.starts_with(",true");
    let reason = rest
        .split(',')
        .nth(2)
        .unwrap_or("")
        .trim_matches(|c| c == '"' || c == ']');
    Some((id, accepted, reason))
}

/// Count one `OK` toward the counters and the latency histogram.
fn count_ok(out: &mut ConnOut, accepted: bool, reason: &str, latency_us: u64) {
    if accepted {
        out.accepted += 1;
    } else {
        match reason.split(':').next().unwrap_or("") {
            "duplicate" | "replaced" => out.accepted_duplicate += 1,
            "rate-limited" => out.rejected_rate_limited += 1,
            _ => out.rejected_other += 1,
        }
    }
    out.ok_latency.record_us(latency_us);
}

/// Tally the sends still waiting for an `OK` into `timeouts` and
/// `timeouts_warmup`.
fn count_timeouts(out: &mut ConnOut, pending: &HashMap<[u8; 32], Pending>) {
    for p in pending.values() {
        if p.measured {
            out.timeouts += 1;
        } else {
            out.timeouts_warmup += 1;
        }
    }
}

/// The relay's negotiated extensions, probed before a `--deflate`
/// measured phase. `None` when the probe could not run.
pub(crate) fn server_extensions(url: &url::Url, deflate: bool) -> Value {
    if !deflate {
        return Value::Null;
    }
    match probe_extensions(url, true) {
        Ok(ext) => ext.map_or(Value::Null, Value::String),
        Err(e) => json!({ "probe_error": e }),
    }
}

/// The reader half of an open-loop connection: match every `OK` by
/// id, record `ok_time - scheduled`, count by class.
async fn open_reader(
    mut stream: futures::stream::SplitStream<TcpWebSocket>,
    pending: Arc<Mutex<HashMap<[u8; 32], Pending>>>,
    end_ns: u64,
    base: Instant,
    mut stop: watch::Receiver<bool>,
) -> ConnOut {
    let mut out = ConnOut::default();
    loop {
        tokio::select! {
            frame = stream.next() => {
                let Some(frame) = frame else {
                    out.error = Some("connection closed".to_owned());
                    break;
                };
                if frame.opcode() != OpCode::Text {
                    continue;
                }
                let Some((id_hex, accepted, reason)) = classify_ok(frame.as_str()) else {
                    continue;
                };
                let Some(id) = unhex(id_hex) else {
                    continue;
                };
                let Some(p) = pending.lock().expect("pending").remove(&id) else {
                    continue;
                };
                if !p.measured {
                    continue;
                }
                let ok_ns = base.elapsed().as_nanos() as u64;
                count_ok(&mut out, accepted, reason, ok_ns.saturating_sub(p.scheduled_ns) / 1000);
                if ok_ns > end_ns {
                    out.late_acks += 1;
                }
            }
            _ = stop.changed() => break,
        }
    }
    out
}

/// One connection's open-loop schedule: global slot `j * conns + k`
/// at `rate` events per second over `[SETTLE, end_ns)`, measured from
/// `warm_ns`.
struct OpenSched {
    k: usize,
    conns: usize,
    rate: f64,
    warm_ns: u64,
    end_ns: u64,
}

/// The sender half of an open-loop connection: fire at the scheduled
/// slot `j * conns + k`, record the lag, register the event. Returns
/// `(measured sends, lag histogram, error)`.
async fn open_sender(
    mut sink: futures::stream::SplitSink<TcpWebSocket, Frame>,
    sched: &OpenSched,
    corpus: Arc<Vec<Ready>>,
    pending: Arc<Mutex<HashMap<[u8; 32], Pending>>>,
    base: Instant,
) -> (usize, Hist, Option<String>) {
    let mut sent = 0usize;
    let mut lag = Hist::new();
    let mut j = 0usize;
    loop {
        let slot = j * sched.conns + sched.k;
        let Some(ev) = corpus.get(slot) else {
            break;
        };
        let scheduled = SETTLE.as_nanos() as u64 + (slot as f64 / sched.rate * 1e9) as u64;
        if scheduled > sched.end_ns {
            break;
        }
        tokio::time::sleep_until((base + Duration::from_nanos(scheduled)).into()).await;
        let now = base.elapsed().as_nanos() as u64;
        let measured = scheduled >= sched.warm_ns;
        if measured {
            lag.record_us(now.saturating_sub(scheduled) / 1000);
            sent += 1;
        }
        pending.lock().expect("pending").insert(
            ev.id,
            Pending {
                scheduled_ns: scheduled,
                sent_ns: now,
                measured,
            },
        );
        if let Err(e) = sink.send(Frame::text(ev.msg.clone())).await {
            return (sent, lag, Some(format!("send: {e}")));
        }
        j += 1;
    }
    (sent, lag, None)
}

/// `ingest-open --corpus F --conns C --rate R --duration D --warmup W`.
pub(crate) async fn ingest_open(url: url::Url, opts: IngestOpts, rate: f64) -> Result<(), String> {
    let started_utc = crate::unix_now();
    if rate <= 0.0 {
        return Err("--rate must be positive".to_owned());
    }
    let need = (rate * (opts.warmup + opts.duration) as f64 * 1.05).ceil() as usize + opts.conns;
    let corpus = Arc::new(load_corpus(&opts.corpus, need, opts.skip)?);
    if corpus.len() < (rate * (opts.warmup + opts.duration) as f64) as usize {
        return Err(format!(
            "corpus too short: {} events < R*(W+D) needed",
            corpus.len()
        ));
    }
    let extensions = server_extensions(&url, opts.deflate);

    let base = Instant::now();
    let warm_ns = SETTLE.as_nanos() as u64 + opts.warmup * 1_000_000_000;
    let end_ns = warm_ns + opts.duration * 1_000_000_000;

    let mut senders = Vec::with_capacity(opts.conns);
    let mut readers = Vec::with_capacity(opts.conns);
    let mut pendings = Vec::with_capacity(opts.conns);
    let (stop_tx, stop_rx) = watch::channel(false);
    for k in 0..opts.conns {
        let ws = crate::connect(&url, opts.deflate).await?;
        let (sink, stream) = ws.split();
        let pending: Arc<Mutex<HashMap<[u8; 32], Pending>>> = Arc::new(Mutex::new(HashMap::new()));
        let sched = OpenSched {
            k,
            conns: opts.conns,
            rate,
            warm_ns,
            end_ns,
        };
        let (corpus, sender_pending) = (Arc::clone(&corpus), Arc::clone(&pending));
        senders.push(tokio::spawn(async move {
            open_sender(sink, &sched, corpus, sender_pending, base).await
        }));
        readers.push(tokio::spawn(open_reader(
            stream,
            Arc::clone(&pending),
            end_ns,
            base,
            stop_rx.clone(),
        )));
        pendings.push(pending);
    }

    // Instrument exactly the measured window [W, W+D].
    tokio::time::sleep_until((base + Duration::from_nanos(warm_ns)).into()).await;
    let meter = HarnessMeter::begin();
    let sampler = opts.pid.map(Sampler::start);
    tokio::time::sleep_until((base + Duration::from_nanos(end_ns)).into()).await;
    let sampler_json = sampler.map(Sampler::finish);
    let meter_json = meter.finish();

    // Senders finish their schedules; then drain up to 30 s for the
    // remaining OKs, then whatever is left is a timeout.
    let mut sends = 0usize;
    let mut send_lag = Hist::new();
    let mut errors = Vec::new();
    for s in senders {
        let (sent, lag, err) = s.await.map_err(|e| e.to_string())?;
        sends += sent;
        send_lag.merge(&lag);
        if let Some(e) = err {
            errors.push(e);
        }
    }
    let drain_deadline = Instant::now() + DRAIN;
    while pendings
        .iter()
        .any(|p| !p.lock().expect("pending").is_empty())
    {
        if Instant::now() >= drain_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop_tx.send_replace(true);

    let mut totals = ConnOut::default();
    for p in &pendings {
        count_timeouts(&mut totals, &p.lock().expect("pending"));
    }
    let mut ok_hist = Hist::new();
    for r in readers {
        let out = r.await.map_err(|e| e.to_string())?;
        totals.accepted += out.accepted;
        totals.accepted_duplicate += out.accepted_duplicate;
        totals.rejected_rate_limited += out.rejected_rate_limited;
        totals.rejected_other += out.rejected_other;
        totals.late_acks += out.late_acks;
        ok_hist.merge(&out.ok_latency);
        if let Some(e) = out.error {
            errors.push(e);
        }
    }
    let send_lag_json = send_lag.json();
    let result = json!({
        "scenario": "ingest-open",
        "label": opts.label,
        "deflate": opts.deflate,
        "conns": opts.conns,
        "rate": rate,
        "duration": opts.duration,
        "warmup": opts.warmup,
        "corpus": opts.corpus,
        "skip": opts.skip,
        "offered_rate": rate,
        "achieved_send_rate": sends as f64 / opts.duration.max(1) as f64,
        "sends_measured": sends,
        "accepted": totals.accepted,
        "accepted_duplicate": totals.accepted_duplicate,
        "rejected_rate_limited": totals.rejected_rate_limited,
        "rejected_other": totals.rejected_other,
        "timeouts": totals.timeouts,
        "timeouts_warmup": totals.timeouts_warmup,
        "late_acks": totals.late_acks,
        "ok_latency": ok_hist.json(),
        "send_lag": send_lag_json,
        "server_extensions": extensions,
        "sampler": sampler_json,
        "harness": meter_json,
        "errors": errors,
        "valid": totals.timeouts == 0
            && totals.rejected_other == 0
            && send_lag_json["p99_ms"].as_f64().unwrap_or(f64::INFINITY) < 5.0
            && meter_json["harness_saturated"].as_bool() == Some(false),
        "harness_sha": env!("GIT_SHA"),
        "started_utc": started_utc,
        "ended_utc": crate::unix_now(),
    });
    println!("{result}");
    Ok(())
}

/// Send the next corpus event on a closed-loop connection.
async fn send_next(
    sink: &mut futures::stream::SplitSink<TcpWebSocket, Frame>,
    pending: &mut HashMap<[u8; 32], Pending>,
    spec: &ClosedSpec,
    base: Instant,
) -> Result<(), String> {
    let i = spec.next_idx.fetch_add(1, Ordering::Relaxed);
    let ev = spec
        .corpus
        .get(i)
        .ok_or_else(|| "corpus exhausted".to_owned())?;
    let sent = base.elapsed().as_nanos() as u64;
    pending.insert(
        ev.id,
        Pending {
            scheduled_ns: sent,
            sent_ns: sent,
            measured: sent >= spec.warm_ns,
        },
    );
    sink.send(Frame::text(ev.msg.clone()))
        .await
        .map_err(|e| format!("send: {e}"))
}

/// Shared inputs for one closed-loop connection.
struct ClosedSpec {
    deflate: bool,
    window: usize,
    warm_ns: u64,
    end_ns: u64,
    corpus: Arc<Vec<Ready>>,
    next_idx: Arc<AtomicUsize>,
}

/// One closed-loop connection: hold `window` sends in flight, fire a
/// replacement for every `OK`. Single task owns both halves, so the
/// pending map needs no lock.
async fn closed_conn(url: url::Url, spec: ClosedSpec, base: Instant) -> ConnOut {
    let mut out = ConnOut::default();
    let ws = match crate::connect(&url, spec.deflate).await {
        Ok(ws) => ws,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    };
    let (mut sink, mut stream) = ws.split();
    let mut pending: HashMap<[u8; 32], Pending> = HashMap::new();
    for _ in 0..spec.window {
        if let Err(e) = send_next(&mut sink, &mut pending, &spec, base).await {
            out.error = Some(e);
            return out;
        }
    }
    let deadline = tokio::time::Instant::now()
        + DRAIN
        + Duration::from_nanos(spec.end_ns.saturating_sub(base.elapsed().as_nanos() as u64));
    loop {
        let now = base.elapsed().as_nanos() as u64;
        if now > spec.end_ns && pending.is_empty() {
            break;
        }
        let frame = match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(f) => f,
            Err(_) => break,
        };
        let Some(frame) = frame else {
            out.error = Some("connection closed".to_owned());
            break;
        };
        if frame.opcode() != OpCode::Text {
            continue;
        }
        let Some((id_hex, accepted, reason)) = classify_ok(frame.as_str()) else {
            continue;
        };
        let Some(id) = unhex(id_hex) else {
            continue;
        };
        let Some(p) = pending.remove(&id) else {
            continue;
        };
        let now = base.elapsed().as_nanos() as u64;
        // Measurement is by OK receipt time: only OKs inside the
        // window feed the counters and the closed-loop histogram; a
        // measured send whose OK lands late is a late ack.
        if (spec.warm_ns..=spec.end_ns).contains(&now) {
            count_ok(
                &mut out,
                accepted,
                reason,
                now.saturating_sub(p.sent_ns) / 1000,
            );
        } else if p.measured {
            out.late_acks += 1;
        }
        if now <= spec.end_ns
            && let Err(e) = send_next(&mut sink, &mut pending, &spec, base).await
        {
            out.error = Some(e);
            break;
        }
    }
    count_timeouts(&mut out, &pending);
    out
}

/// `ingest-closed --corpus F --conns C --window K --duration D --warmup W`.
pub(crate) async fn ingest_closed(
    url: url::Url,
    opts: IngestOpts,
    window: usize,
) -> Result<(), String> {
    let started_utc = crate::unix_now();
    let corpus = Arc::new(load_corpus(&opts.corpus, CLOSED_PRELOAD_MAX, opts.skip)?);
    if corpus.len() < opts.conns * window {
        return Err(format!(
            "corpus too short: {} events < C*K needed",
            corpus.len()
        ));
    }
    let extensions = server_extensions(&url, opts.deflate);

    let base = Instant::now();
    let warm_ns = SETTLE.as_nanos() as u64 + opts.warmup * 1_000_000_000;
    let end_ns = warm_ns + opts.duration * 1_000_000_000;
    // Events are handed out in corpus order across all connections.
    let next_idx = Arc::new(AtomicUsize::new(0));

    let mut tasks = Vec::with_capacity(opts.conns);
    for _k in 0..opts.conns {
        let spec = ClosedSpec {
            deflate: opts.deflate,
            window,
            warm_ns,
            end_ns,
            corpus: Arc::clone(&corpus),
            next_idx: Arc::clone(&next_idx),
        };
        tasks.push(tokio::spawn(closed_conn(url.clone(), spec, base)));
    }

    // Instrument exactly the measured window [W, W+D].
    tokio::time::sleep_until((base + Duration::from_nanos(warm_ns)).into()).await;
    let meter = HarnessMeter::begin();
    let sampler = opts.pid.map(Sampler::start);
    tokio::time::sleep_until((base + Duration::from_nanos(end_ns)).into()).await;
    let sampler_json = sampler.map(Sampler::finish);
    let meter_json = meter.finish();

    let mut totals = ConnOut::default();
    let mut errors = Vec::new();
    for t in tasks {
        let out = t.await.map_err(|e| e.to_string())?;
        totals.accepted += out.accepted;
        totals.accepted_duplicate += out.accepted_duplicate;
        totals.rejected_rate_limited += out.rejected_rate_limited;
        totals.rejected_other += out.rejected_other;
        totals.timeouts += out.timeouts;
        totals.timeouts_warmup += out.timeouts_warmup;
        totals.late_acks += out.late_acks;
        totals.ok_latency.merge(&out.ok_latency);
        if let Some(e) = out.error {
            errors.push(e);
        }
    }
    let result = json!({
        "scenario": "ingest-closed",
        "label": opts.label,
        "deflate": opts.deflate,
        "conns": opts.conns,
        "window": window,
        "duration": opts.duration,
        "warmup": opts.warmup,
        "corpus": opts.corpus,
        "skip": opts.skip,
        "accepted_per_sec": totals.accepted as f64 / opts.duration.max(1) as f64,
        "accepted": totals.accepted,
        "accepted_duplicate": totals.accepted_duplicate,
        "rejected_rate_limited": totals.rejected_rate_limited,
        "rejected_other": totals.rejected_other,
        "timeouts": totals.timeouts,
        "timeouts_warmup": totals.timeouts_warmup,
        "late_acks": totals.late_acks,
        "ok_latency_closed": totals.ok_latency.json(),
        "server_extensions": extensions,
        "sampler": sampler_json,
        "harness": meter_json,
        "conn_errors": errors,
        "valid": totals.timeouts == 0
            && totals.rejected_other == 0
            && errors.is_empty()
            && meter_json["harness_saturated"].as_bool() == Some(false),
        "harness_sha": env!("GIT_SHA"),
        "started_utc": started_utc,
        "ended_utc": crate::unix_now(),
    });
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ok_parses_the_wire_shape() {
        let id = "ab".repeat(32);
        let frame = format!("[\"OK\",\"{id}\",true,\"\"]");
        let (got, accepted, reason) = classify_ok(&frame).unwrap();
        assert_eq!(got, id);
        assert!(accepted);
        assert_eq!(reason, "");

        let frame = format!("[\"OK\",\"{id}\",false,\"duplicate: already have this event\"]");
        let (_, accepted, reason) = classify_ok(&frame).unwrap();
        assert!(!accepted);
        assert_eq!(reason, "duplicate: already have this event");

        assert!(classify_ok(r#"["EVENT","s",{}]"#).is_none());
    }

    #[test]
    fn count_ok_buckets_duplicates_and_superseded() {
        let mut out = ConnOut::default();
        count_ok(&mut out, true, "", 0);
        count_ok(&mut out, false, "duplicate: have a newer version", 0);
        // strfry's answer to an older replaceable event.
        count_ok(&mut out, false, "replaced: have newer event", 0);
        count_ok(&mut out, false, "rate-limited: slow down", 0);
        count_ok(&mut out, false, "invalid: bad sig", 0);
        assert_eq!(out.accepted, 1);
        assert_eq!(out.accepted_duplicate, 2);
        assert_eq!(out.rejected_rate_limited, 1);
        assert_eq!(out.rejected_other, 1);
    }

    #[test]
    fn unhex_roundtrips() {
        let id = "ab".repeat(32);
        assert_eq!(unhex(&id), Some([0xab; 32]));
        assert_eq!(unhex(&id[..63]), None);
        assert_eq!(unhex(&format!("z{}", &id[..63])), None);
    }
}
