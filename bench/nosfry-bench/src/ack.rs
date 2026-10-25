//! `ack-ingest` and `ack-check`: the crash-durability driver pair.
//!
//! `ack-ingest` publishes a corpus paced like `ingest-open` but with no
//! warm-up and no duration: it runs until the corpus is exhausted or
//! the connection drops (the orchestrator kills the relay, never the
//! harness). Every `OK` whose accepted flag is `true` — `duplicate:`
//! reasons included — has its id appended to `--out`, one hex id per
//! line, flushed every 100 lines and on exit, so a killed run still
//! leaves an almost-complete record of what the relay acknowledged.
//!
//! `ack-check` then REQ-fetches those ids back in `{"ids":[…500…]}`
//! batches and reports `acked`, `found` and `missing` — the evidence
//! of what the restart actually kept.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{FutureExt, SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::watch;
use yawc::{Frame, OpCode};

use crate::openloop::{Ready, classify_ok, load_corpus, unhex};
use crate::{connect, unix_now};

/// How many ids per `{"ids":[…]}` REQ in `ack-check`.
const IDS_BATCH: usize = 500;
/// `acked.ids` is flushed to disk every this many lines.
const FLUSH_EVERY: u64 = 100;
/// Sends start one second after connect so the socket settles.
const SETTLE: Duration = Duration::from_secs(1);
/// After the corpus runs out, wait this long for the last `OK`s.
const DRAIN: Duration = Duration::from_secs(30);

/// Shared `acked.ids` writer: line-buffered by policy, not luck.
struct AckedFile {
    writer: BufWriter<File>,
    written: u64,
}

impl AckedFile {
    fn record(&mut self, id_hex: &str) -> Result<(), String> {
        self.writer
            .write_all(id_hex.as_bytes())
            .and_then(|()| self.writer.write_all(b"\n"))
            .map_err(|e| e.to_string())?;
        self.written += 1;
        if self.written.is_multiple_of(FLUSH_EVERY) {
            self.writer.flush().map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// Per-run counters shared by all connections.
#[derive(Default)]
struct AckCounters {
    sends: AtomicUsize,
    acked: AtomicUsize,
    rejected: AtomicUsize,
    /// Connections that hit a send/receive error or a write failure.
    errors: AtomicUsize,
    /// Connections whose send loop exhausted the corpus.
    done: AtomicUsize,
    /// Wall-clock seconds of the newest accepted `OK`; 0 until first.
    last_ok_ts: AtomicU64,
    /// First failure note, kept for the result line.
    note: Mutex<Option<String>>,
}

impl AckCounters {
    fn note(&self, msg: String) {
        let mut slot = self.note.lock().expect("note");
        if slot.is_none() {
            *slot = Some(msg);
        }
    }
}

/// Handle one text frame as an `OK` if it is one. `false` means the
/// connection must stop: the socket died or `acked.ids` failed.
fn record_ok(
    text: &str,
    pending: &mut HashSet<[u8; 32]>,
    acked: &mut AckedFile,
    counters: &AckCounters,
) -> bool {
    let Some((id_hex, accepted, _reason)) = classify_ok(text) else {
        return true;
    };
    let Some(id) = unhex(id_hex) else {
        return true;
    };
    if !pending.remove(&id) {
        return true;
    }
    if accepted {
        // `true` is `true` — `duplicate:` still means the relay has it.
        counters.last_ok_ts.store(unix_now(), Ordering::Relaxed);
        match acked.record(id_hex) {
            Ok(()) => {
                counters.acked.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
                counters.note(format!("acked.ids: {e}"));
                return false;
            }
        }
    } else {
        counters.rejected.fetch_add(1, Ordering::Relaxed);
    }
    true
}

/// Poll every already-arrived frame without yielding; `false` stops
/// the connection.
fn drain_ready(
    stream: &mut futures::stream::SplitStream<yawc::TcpWebSocket>,
    pending: &mut HashSet<[u8; 32]>,
    acked: &Arc<Mutex<AckedFile>>,
    counters: &AckCounters,
) -> bool {
    while let Some(Some(frame)) = stream.next().now_or_never() {
        if frame.opcode() != OpCode::Text {
            continue;
        }
        let mut file = acked.lock().expect("acked");
        if !record_ok(frame.as_str(), pending, &mut file, counters) {
            return false;
        }
    }
    true
}

/// Read `OK`s until `pending` is empty or the socket ends.
async fn drain_oks(
    stream: &mut futures::stream::SplitStream<yawc::TcpWebSocket>,
    pending: &mut HashSet<[u8; 32]>,
    acked: &Arc<Mutex<AckedFile>>,
    counters: &AckCounters,
) -> Result<(), String> {
    while !pending.is_empty() {
        let Some(frame) = stream.next().await else {
            return Err("connection closed".to_owned());
        };
        if frame.opcode() != OpCode::Text {
            continue;
        }
        let mut file = acked.lock().expect("acked");
        if !record_ok(frame.as_str(), pending, &mut file, counters) {
            return Err("acked.ids write failed".to_owned());
        }
    }
    Ok(())
}

/// One connection's paced send loop plus `OK` reader, ending when the
/// corpus runs out, the socket drops, or `stop` fires.
#[allow(clippy::too_many_arguments)]
async fn ack_conn(
    url: url::Url,
    k: usize,
    conns: usize,
    rate: f64,
    corpus: Arc<Vec<Ready>>,
    acked: Arc<Mutex<AckedFile>>,
    counters: Arc<AckCounters>,
    base: Instant,
    stop_tx: watch::Sender<bool>,
    mut stop: watch::Receiver<bool>,
) {
    let mut pending: HashSet<[u8; 32]> = HashSet::new();
    let result = async {
        let ws = connect(&url, false).await?;
        let (mut sink, mut stream) = ws.split();
        let mut j = 0usize;
        loop {
            let slot = j * conns + k;
            let Some(ev) = corpus.get(slot) else {
                break;
            };
            let scheduled = SETTLE + Duration::from_nanos((slot as f64 / rate * 1e9) as u64);
            tokio::select! {
                _ = tokio::time::sleep_until((base + scheduled).into()) => {}
                _ = stop.changed() => return Ok::<(), String>(()),
            }
            pending.insert(ev.id);
            counters.sends.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = sink.send(Frame::text(ev.msg.clone())).await {
                return Err(format!("send: {e}"));
            }
            // Read the `OK`s that arrived by the next scheduled send;
            // the reader never blocks the sender past its slot.
            if !drain_ready(&mut stream, &mut pending, &acked, &counters) {
                return Err("acked.ids write failed".to_owned());
            }
            j += 1;
        }
        // Corpus exhausted on this connection: drain `OK`s until
        // `pending` is empty, the socket dies, or `stop` fires.
        let drained = drain_oks(&mut stream, &mut pending, &acked, &counters);
        tokio::select! {
            r = tokio::time::timeout(DRAIN, drained) => match r {
                Ok(inner) => inner,
                Err(_) => {
                    counters.note("drain timed out with pending OKs".to_owned());
                    Ok(())
                }
            },
            _ = stop.changed() => Ok(()),
        }
    }
    .await;
    match result {
        Ok(()) => {
            // When every connection finished its send loop the run is
            // over; the last one releases the others' drains.
            if counters.done.fetch_add(1, Ordering::Relaxed) + 1 == conns {
                stop_tx.send_replace(true);
            }
        }
        Err(e) => {
            counters.errors.fetch_add(1, Ordering::Relaxed);
            counters.note(e);
            // A dropped connection ends the run (the relay died).
            stop_tx.send_replace(true);
        }
    }
}

/// Ids already in `--out` from earlier cycles: `ack-ingest` resumes
/// the corpus where the last killed run left off.
fn prior_acked(out: &std::path::Path) -> Result<HashSet<[u8; 32]>, String> {
    let mut set = HashSet::new();
    let Ok(file) = File::open(out) else {
        return Ok(set);
    };
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| format!("{}: {e}", out.display()))?;
        // A partially flushed tail line is not an id; skip it.
        if let Some(id) = unhex(line.trim()) {
            set.insert(id);
        }
    }
    Ok(set)
}

/// `ack-ingest --url U --corpus F --conns C --rate R --out acked.ids`.
pub(crate) async fn ack_ingest(
    url: url::Url,
    corpus_path: PathBuf,
    conns: usize,
    rate: f64,
    out: PathBuf,
    label: String,
) -> Result<(), String> {
    let prior = prior_acked(&out)?;
    let resumed = prior.len();
    let full = load_corpus(&corpus_path, usize::MAX, 0)?;
    let corpus = Arc::new(
        full.iter()
            .filter(|ev| !prior.contains(&ev.id))
            .cloned()
            .collect::<Vec<Ready>>(),
    );
    if corpus.is_empty() {
        return Err(format!("corpus {} is empty", corpus_path.display()));
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    let acked = Arc::new(Mutex::new(AckedFile {
        writer: BufWriter::new(file),
        written: 0,
    }));
    let counters = Arc::new(AckCounters::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let base = Instant::now();
    let mut tasks = Vec::with_capacity(conns);
    for k in 0..conns {
        tasks.push(tokio::spawn(ack_conn(
            url.clone(),
            k,
            conns,
            rate,
            Arc::clone(&corpus),
            Arc::clone(&acked),
            Arc::clone(&counters),
            base,
            stop_tx.clone(),
            stop_rx.clone(),
        )));
    }
    // The run ends when every connection is done — by corpus
    // exhaustion, a dropped socket, or the relay dying under us.
    for task in tasks {
        let _ = task.await;
    }
    stop_tx.send_replace(true);
    let write_error = acked.lock().expect("acked").writer.flush().err();
    let last = counters.last_ok_ts.load(Ordering::Relaxed);
    let result = json!({
        "scenario": "ack-ingest",
        "label": label,
        "harness_sha": env!("GIT_SHA"),
        "url": url.to_string(),
        "conns": conns,
        "rate": rate,
        "sends": counters.sends.load(Ordering::Relaxed),
        "resumed": resumed,
        "acked": counters.acked.load(Ordering::Relaxed),
        "rejected": counters.rejected.load(Ordering::Relaxed),
        "errors": counters.errors.load(Ordering::Relaxed),
        "note": counters.note.lock().expect("note").clone(),
        "write_error": write_error.map(|e| e.to_string()),
        "last_ok_ts": if last == 0 { Value::Null } else { json!(last) },
        "wall_secs": base.elapsed().as_secs_f64(),
    });
    println!("{result}");
    Ok(())
}

/// `ack-check --url U --ids acked.ids`: REQ every acknowledged id back
/// in 500-id batches and report what survived the restart.
pub(crate) async fn ack_check(url: url::Url, ids_path: PathBuf) -> Result<(), String> {
    let file = File::open(&ids_path).map_err(|e| format!("{}: {e}", ids_path.display()))?;
    let ids: Vec<String> = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect();
    if ids.is_empty() {
        return Err(format!("{}: no ids to check", ids_path.display()));
    }
    let want: HashSet<&str> = ids.iter().map(String::as_str).collect();
    let mut ws = connect(&url, false).await?;
    let mut found: HashSet<String> = HashSet::with_capacity(ids.len());
    let mut errors: Vec<String> = Vec::new();
    for (b, chunk) in ids.chunks(IDS_BATCH).enumerate() {
        let sub = format!("ack{b}");
        let req = json!(["REQ", sub, { "ids": chunk }]).to_string();
        ws.send(Frame::text(req)).await.map_err(|e| e.to_string())?;
        let eose = json!(["EOSE", sub]).to_string();
        loop {
            let Some(frame) = ws.next().await else {
                errors.push("connection closed before EOSE".to_owned());
                break;
            };
            if frame.opcode() != OpCode::Text {
                continue;
            }
            let text = frame.as_str();
            if text == eose {
                break;
            }
            if text.starts_with("[\"CLOSED\"") || text.starts_with("[\"NOTICE\"") {
                errors.push(text.to_owned());
                break;
            }
            if !text.starts_with("[\"EVENT\"") {
                continue;
            }
            let Some(pos) = text.find("\"id\":\"") else {
                continue;
            };
            let Some(id) = text.get(pos + 6..pos + 70) else {
                continue;
            };
            if want.contains(id) {
                found.insert(id.to_owned());
            }
        }
        let close = json!(["CLOSE", sub]).to_string();
        let _ = ws.send(Frame::text(close)).await;
    }
    let found_set: HashSet<&str> = found.iter().map(String::as_str).collect();
    let mut missing: Vec<String> = want
        .difference(&found_set)
        .map(|s| (*s).to_owned())
        .collect();
    missing.sort_unstable();
    let result = json!({
        "scenario": "ack-check",
        "harness_sha": env!("GIT_SHA"),
        "url": url.to_string(),
        "acked": ids.len(),
        "found": found.len(),
        "missing": missing.len(),
        "missing_sample": missing.iter().take(20).collect::<Vec<_>>(),
        "errors": errors,
        "valid": errors.is_empty(),
    });
    println!("{result}");
    Ok(())
}
