//! Crash-recovery tests against the real `nosfry` binary.
//!
//! `kill -9` exercises the commit protocol and LMDB's crash recovery:
//! a write transaction either committed (its OK was sent after the
//! fsync) or rolled back, and the OS keeps the page cache, so nothing
//! acknowledged can be lost and no half-written state can appear.
//! This does NOT simulate power loss, where the kernel page cache
//! also dies — that relies on the fsync-before-OK durability policy,
//! which a host crash cannot demonstrate.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::shadow_unrelated,
    clippy::excessive_nesting,
    clippy::too_many_lines,
    unused_crate_dependencies,
    reason = "tests may panic on failure paths; deps cover every test binary"
)]

mod common;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{event, event_wire, key, req_wire, send_text};
use futures_util::{SinkExt, StreamExt};
use nosfry_core::event::{EventLimits, UnverifiedEvent};
use nosfry_lmdb::{Store, StoreOptions};
use secp256k1::Keypair;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_nosfry");

/// Minimal deterministic PRNG for publish timings (xorshift64*).
struct Rng(u64);

impl Rng {
    const fn cycle(cycle: usize) -> Self {
        Self(0x9E37_79B9_7F4A_7C15 ^ (cycle as u64).wrapping_mul(0x2545_F491_4F6C_DD1D))
    }

    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11
    }

    const fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }
}

/// A free TCP port for a spawned relay.
fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Write a relay config into `dir`: rate limits and the per-IP cap off,
/// a large `max_filter_limit` so verification REQs are never capped.
fn write_config(dir: &Path, port: u16) -> PathBuf {
    let path = dir.join("nosfry.toml");
    std::fs::write(
        &path,
        format!(
            "[db]\npath = \"{}\"\n\
             [relay]\nport = {port}\nnofiles = 0\nmax_connections_per_ip = 0\n\
             [relay.limits]\nmax_filter_limit = 100_000\n\
             [relay.rate_limits]\nevents_per_second = 0\nevents_burst = 0\n\
             reqs_per_second = 0\nreqs_burst = 0\n",
            dir.join("db").display()
        ),
    )
    .unwrap();
    path
}

/// `write_config` plus `service_url`: AUTH on, so restricted kinds
/// (gift wraps) are writeable and reads are gated.
fn write_auth_config(dir: &Path, port: u16) -> PathBuf {
    let path = dir.join("nosfry.toml");
    std::fs::write(
        &path,
        format!(
            "[db]\npath = \"{}\"\n\
             [relay]\nport = {port}\nnofiles = 0\nmax_connections_per_ip = 0\n\
             service_url = \"ws://127.0.0.1:{port}\"\n\
             [relay.limits]\nmax_filter_limit = 100_000\n\
             [relay.rate_limits]\nevents_per_second = 0\nevents_burst = 0\n\
             reqs_per_second = 0\nreqs_burst = 0\n",
            dir.join("db").display()
        ),
    )
    .unwrap();
    path
}

/// At most 10 ids of a sorted vector, for failure messages.
fn head(ids: &[String]) -> &[String] {
    &ids[..ids.len().min(10)]
}

/// Current unix seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn stderr_log(path: &Path) -> Stdio {
    Stdio::from(std::fs::File::create(path).unwrap())
}

/// `nosfry relay --config <cfg>`, stderr to a log file.
fn spawn_relay(cfg: &Path, err_log: &Path) -> Child {
    Command::new(BIN)
        .args(["relay", "--config"])
        .arg(cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_log(err_log))
        .spawn()
        .unwrap()
}

/// `nosfry export --config <cfg>` with a piped stdout that is never
/// read: the child fills the pipe and blocks mid-scan holding a read
/// transaction.
fn spawn_blocked_export(cfg: &Path, err_log: &Path) -> Child {
    Command::new(BIN)
        .args(["export", "--config"])
        .arg(cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(stderr_log(err_log))
        .spawn()
        .unwrap()
}

/// Wait until `child` has been alive `block_ms` — with more output
/// pending than fits the pipe, still-alive means blocked on write.
#[allow(clippy::disallowed_methods, reason = "sync test helper")]
fn wait_until_blocked(child: &mut Child, block_ms: u64) {
    let start = Instant::now();
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "export exited instead of blocking on a full pipe"
        );
        if start.elapsed() >= Duration::from_millis(block_ms) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Fill the store with enough kind-1 events that `export` emits far
/// more than any pipe buffer holds.
fn seed_events(store: &Store, count: u64) {
    let k = key(99);
    let content = "x".repeat(300);
    for base in (0..count).step_by(500) {
        let batch: Vec<_> = (base..(base + 500).min(count))
            .map(|i| event(&k, 1, 1_000_000 + i, &json!([]), &format!("{content}-{i}")))
            .collect();
        store.write(&batch, None).unwrap();
    }
}

/// A killed `nosfry export` blocked on a full pipe leaves its read
/// transaction's slot in the lock table; `clear_stale_readers` reaps it.
#[test]
fn killed_export_leaves_stale_reader() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), 0);
    let db = dir.path().join("db");
    let store = Store::open(&db, &StoreOptions::default()).unwrap();
    seed_events(&store, 4_000);

    let mut child = spawn_blocked_export(&cfg, &dir.path().join("export.err"));
    wait_until_blocked(&mut child, 800);
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(
        store.clear_stale_readers().unwrap(),
        1,
        "the killed exporter's reader slot must be stale"
    );
    assert_eq!(store.clear_stale_readers().unwrap(), 0);
}

/// With the relay running, its 10 s expiry sweep clears the stale slot
/// before any other opener can: the warn line is the proof the relay —
/// not this process's `Store::open` — did the reaping.
#[test]
#[allow(clippy::disallowed_methods, reason = "sync test")]
fn relay_expiry_clears_stale_reader() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = write_config(dir.path(), port);
    let db = dir.path().join("db");
    // Seed before the relay starts; keep this env open throughout —
    // its open-time check ran while the exporter was still alive.
    let store = Store::open(&db, &StoreOptions::default()).unwrap();
    seed_events(&store, 4_000);

    let relay_err = dir.path().join("relay.err");
    let mut relay = spawn_relay(&cfg, &relay_err);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "relay never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let mut child = spawn_blocked_export(&cfg, &dir.path().join("export.err"));
    wait_until_blocked(&mut child, 800);
    child.kill().unwrap();
    child.wait().unwrap();

    // The sweep clears the slot and logs it, within one 10 s tick.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let log = std::fs::read_to_string(&relay_err).unwrap_or_default();
        if log.contains("cleared stale LMDB readers") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "relay never cleared the stale reader: {log}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // Whatever the relay already reaped stays gone.
    assert_eq!(store.clear_stale_readers().unwrap(), 0);

    let status = Command::new("kill")
        .args(["-TERM", &relay.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    relay.wait().unwrap();
}

/// Read one text frame; `None` on close, error, or timeout — never
/// panics, so publisher tasks wind down when the socket dies.
async fn recv_frame(ws: &mut yawc::TcpWebSocket) -> Option<String> {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .ok()??;
        match frame.opcode() {
            yawc::OpCode::Text => {
                return std::str::from_utf8(frame.payload()).ok().map(str::to_owned);
            }
            yawc::OpCode::Close => return None,
            _ => {}
        }
    }
}

/// Send one text frame; `false` when the socket is already dead.
async fn try_send(ws: &mut yawc::TcpWebSocket, text: &str) -> bool {
    ws.send(yawc::Frame::text(text.to_owned())).await.is_ok()
}

/// Await the OK for `id`, skipping other frames; `None` when the
/// socket dies first.
async fn recv_ok(ws: &mut yawc::TcpWebSocket, id: &str) -> Option<Value> {
    while let Some(text) = recv_frame(ws).await {
        let Ok(frame) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if frame.get(0).and_then(Value::as_str) == Some("OK")
            && frame.get(1).and_then(Value::as_str) == Some(id)
        {
            return Some(frame);
        }
    }
    None
}

/// Open a websocket, retrying briefly while the relay comes up.
async fn connect(addr: SocketAddr) -> Option<yawc::TcpWebSocket> {
    let url = format!("ws://{addr}/");
    for _ in 0..50 {
        if let Ok(ws) = yawc::WebSocket::connect(url.parse().unwrap()).await {
            return Some(ws);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// Per-publisher outcome of one crash cycle.
#[derive(Default)]
struct PublisherStats {
    /// EVENTs sent.
    sent: usize,
    /// EVENTs the relay answered at all.
    answered: usize,
    /// EVENTs stored (`OK true` with an empty message).
    acked: usize,
    /// Acked kind-1 ids (`OK true` with an empty message = stored).
    regular: HashSet<String>,
    /// Ids this publisher provably deleted via an acked kind-5.
    deleted: HashSet<String>,
    /// Targets of kind-5s whose send or OK was lost to the kill: the
    /// deletion may or may not have committed.
    in_flight_deleted: HashSet<String>,
    /// Highest `created_at` of an acked kind-0.
    kind0_max: u64,
}

/// Publish back-to-back until the socket dies: mostly kind-1, every
/// 10th an increasing kind-0, every 25th a kind-5 deleting an earlier
/// acked kind-1 of the same key. `cycle_acks` counts stored events so
/// the killer can wait for a non-vacuous cycle.
async fn publish_loop(
    addr: SocketAddr,
    kp: Keypair,
    index: usize,
    cycle: usize,
    cycle_acks: &AtomicUsize,
) -> PublisherStats {
    let mut stats = PublisherStats::default();
    let Some(mut ws) = connect(addr).await else {
        return stats;
    };
    let mut own_regular: Vec<String> = Vec::new();
    let base = now_secs();
    let mut n = 0usize;
    loop {
        n += 1;
        let (kind, tags, content, created_at, target) =
            if n.is_multiple_of(25) && !own_regular.is_empty() {
                let idx = (n / 25 - 1) % own_regular.len();
                let id = own_regular[idx].clone();
                (5, json!([["e", id]]), String::new(), now_secs(), Some(id))
            } else if n.is_multiple_of(10) {
                (0, json!([]), format!("meta-{index}"), base + n as u64, None)
            } else {
                (
                    1,
                    json!([]),
                    format!("p{index}c{cycle}n{n}"),
                    now_secs(),
                    None,
                )
            };
        let ev = event(&kp, kind, created_at, &tags, &content);
        let id_hex = ev.id().to_string();
        if !try_send(&mut ws, &event_wire(&ev)).await {
            // A failed send may still have reached the relay.
            if let Some(target) = target {
                stats.in_flight_deleted.insert(target);
            }
            break;
        }
        stats.sent += 1;
        let Some(ok) = recv_ok(&mut ws, &id_hex).await else {
            // Sent, maybe committed; the OK was lost to the kill.
            if let Some(target) = target {
                stats.in_flight_deleted.insert(target);
            }
            break;
        };
        stats.answered += 1;
        let accepted = ok.get(2).and_then(Value::as_bool).unwrap_or_default();
        let empty_msg = ok.get(3).and_then(Value::as_str) == Some("");
        if !(accepted && empty_msg) {
            continue;
        }
        stats.acked += 1;
        cycle_acks.fetch_add(1, Ordering::Relaxed);
        match kind {
            1 => {
                own_regular.push(id_hex.clone());
                stats.regular.insert(id_hex);
            }
            0 => stats.kind0_max = stats.kind0_max.max(created_at),
            5 => {
                if let Some(target) = target {
                    stats.deleted.insert(target);
                }
            }
            _ => {}
        }
    }
    stats
}

/// Wait until the spawned relay accepts TCP connections.
async fn wait_for_tcp(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "relay never listened on {addr}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// REQ `filter`, collect every `EVENT` payload until `EOSE`.
async fn collect_events(ws: &mut yawc::TcpWebSocket, filter: &Value) -> Vec<Value> {
    let mut events = Vec::new();
    send_text(ws, &req_wire("crash-q", &filter.to_string())).await;
    while let Some(text) = recv_frame(ws).await {
        let Ok(frame) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match frame.get(0).and_then(Value::as_str) {
            Some("EVENT") if frame.get(1).and_then(Value::as_str) == Some("crash-q") => {
                events.push(frame.get(2).cloned().unwrap_or(Value::Null));
            }
            Some("EOSE") if frame.get(1).and_then(Value::as_str) == Some("crash-q") => {
                return events;
            }
            _ => {}
        }
    }
    panic!("REQ ended without EOSE");
}

/// kill -9 the relay repeatedly while publishers write: nothing the
/// relay ever answered `OK true` to may be missing after restart.
/// `NOSFRY_CRASH_CYCLES` overrides the default of 6 crash/restart
/// cycles (raise it for long runs before a release).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kill9_loses_no_acknowledged_event() {
    let cycles: usize = std::env::var("NOSFRY_CRASH_CYCLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = write_config(dir.path(), port);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let keys: Vec<Keypair> = (1..=4).map(key).collect();
    let pk_hex: Vec<String> = keys
        .iter()
        .map(|k| faster_hex::hex_string(&k.x_only_public_key().0.to_byte_array()))
        .collect();

    let mut acked_regular = HashSet::new();
    let mut acked_deleted = HashSet::new();
    let mut in_flight_deleted = HashSet::new();
    let mut kind0_max: HashMap<usize, u64> = HashMap::new();
    let mut total_unacked = 0usize;

    for cycle in 0..cycles {
        let mut rng = Rng::cycle(cycle);
        let mut child = spawn_relay(&cfg, &dir.path().join(format!("relay-{cycle}.err")));
        wait_for_tcp(addr).await;

        let cycle_acks = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for (index, kp) in keys.iter().enumerate() {
            let acks = Arc::clone(&cycle_acks);
            let kp = *kp;
            handles.push(tokio::spawn(async move {
                publish_loop(addr, kp, index, cycle, &acks).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(rng.range(300, 1500))).await;
        // The kill waits for ≥ 50 stored events so a cycle is never
        // vacuous: restarts on a grown db can outlast the random delay.
        let floor = Instant::now() + Duration::from_secs(10);
        while cycle_acks.load(Ordering::Relaxed) < 50 && Instant::now() < floor {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        child.kill().unwrap();
        child.wait().unwrap();

        let mut cycle_acked = 0usize;
        for (index, handle) in handles.into_iter().enumerate() {
            let stats = tokio::time::timeout(Duration::from_secs(15), handle)
                .await
                .expect("publisher never ended")
                .unwrap();
            cycle_acked += stats.acked;
            total_unacked += stats.sent - stats.answered;
            acked_regular.extend(stats.regular);
            acked_deleted.extend(stats.deleted);
            in_flight_deleted.extend(stats.in_flight_deleted);
            if stats.kind0_max > 0 {
                let entry = kind0_max.entry(index).or_insert(0);
                *entry = (*entry).max(stats.kind0_max);
            }
        }
        assert!(
            cycle_acked >= 50,
            "cycle {cycle} was vacuous: {cycle_acked}"
        );
    }

    // Final restart on the same db: verify everything cumulative.
    let err_log = dir.path().join("relay-final.err");
    let mut child = spawn_relay(&cfg, &err_log);
    wait_for_tcp(addr).await;
    let mut ws = connect(addr).await.expect("verify connection failed");

    // Every acked kind-1 that was never deleted comes back by id;
    // every deleted one is absent. An in-flight kind-5 (sent, OK lost
    // to the kill) may or may not have committed, so its target is
    // allowed either way — but a target whose deletion WAS acked must
    // still never be served (the `served_deleted` check).
    let expected: HashSet<String> = acked_regular
        .difference(&acked_deleted)
        .filter(|id| !in_flight_deleted.contains(*id))
        .cloned()
        .collect();
    let all_ids: HashSet<String> = acked_regular.union(&acked_deleted).cloned().collect();
    let all_vec: Vec<&String> = all_ids.iter().collect();
    let mut returned = HashSet::new();
    for chunk in all_vec.chunks(500) {
        let events = collect_events(&mut ws, &json!({"ids": chunk})).await;
        for ev in events {
            returned.insert(
                ev.get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
    }
    // Report each failure class separately: acked events that are
    // gone (a durability bug), deletions that still serve their
    // target, and ids that were never acked at all. At most 10 ids each.
    let mut missing: Vec<String> = expected.difference(&returned).cloned().collect();
    missing.sort_unstable();
    let mut served_deleted: Vec<String> = returned.intersection(&acked_deleted).cloned().collect();
    served_deleted.sort_unstable();
    let mut stray: Vec<String> = returned.difference(&all_ids).cloned().collect();
    stray.sort_unstable();
    assert!(
        missing.is_empty() && served_deleted.is_empty() && stray.is_empty(),
        "acked events missing or deleted ones served:\n  \
         missing {}: {:?}\n  \
         served_deleted {}: {:?}\n  \
         stray {}: {:?}",
        missing.len(),
        head(&missing),
        served_deleted.len(),
        head(&served_deleted),
        stray.len(),
        head(&stray),
    );

    // For each key, the stored kind-0 is at least as new as the max acked.
    for (index, max_ca) in &kind0_max {
        let events =
            collect_events(&mut ws, &json!({"authors": [pk_hex[*index]], "kinds": [0]})).await;
        assert_eq!(events.len(), 1, "kind-0 for {index}");
        let ca = events[0]
            .get("created_at")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        assert!(ca >= *max_ca, "stored kind-0 older than an acked one");
    }

    // Index consistency: the kind index and the author index must
    // agree on the kind-1 set per publisher.
    let mut per_key_kind1 = Vec::new();
    for pk in &pk_hex {
        let by_kind = collect_events(
            &mut ws,
            &json!({"authors": [pk], "kinds": [1], "limit": 100_000}),
        )
        .await;
        let by_kind: HashSet<String> = by_kind
            .iter()
            .filter_map(|e| e.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let by_author = collect_events(&mut ws, &json!({"authors": [pk], "limit": 100_000})).await;
        let kind1_only: HashSet<String> = by_author
            .iter()
            .filter(|e| e.get("kind").and_then(Value::as_u64) == Some(1))
            .filter_map(|e| e.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        assert_eq!(by_kind, kind1_only, "index mismatch for {pk}");
        per_key_kind1.push(by_kind);
    }
    drop(ws);

    // Stop the relay cleanly, then the export CLI must emit exactly
    // the same sets — and every line must parse and verify.
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    child.wait().unwrap();

    let output = Command::new(BIN)
        .args(["export", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(output.status.success());
    let mut exported: Vec<HashSet<String>> = vec![HashSet::new(); pk_hex.len()];
    let stdout = String::from_utf8(output.stdout).unwrap();
    for line in stdout.lines() {
        let event = UnverifiedEvent::parse(line, &EventLimits::default())
            .unwrap_or_else(|_| panic!("export line does not parse: {line}"))
            .verify(&EventLimits::default())
            .expect("export line does not verify");
        if event.kind().0 == 1 {
            for (index, pk) in pk_hex.iter().enumerate() {
                if event.pubkey().to_string() == *pk {
                    exported[index].insert(event.id().to_string());
                }
            }
        }
    }
    for (index, set) in exported.into_iter().enumerate() {
        assert_eq!(set, per_key_kind1[index], "export mismatch for {index}");
    }

    eprintln!(
        "cycles={cycles} acked_regular={} deleted={} sent_unacked={total_unacked}",
        acked_regular.len(),
        acked_deleted.len()
    );
}

/// NIP-59 across a crash: the `ix_deletion` row the recipient's
/// kind 5 wrote must survive kill -9 — a republished wrap still
/// answers `blocked:` after restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrap_deletion_block_survives_crash() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = write_auth_config(dir.path(), port);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut child = spawn_relay(&cfg, &dir.path().join("relay.err"));
    wait_for_tcp(addr).await;

    let w = key(7); // the wrap's random signing key
    let r = key(8); // the recipient whose kind 5 deletes it
    let r_hex = faster_hex::hex_string(&r.x_only_public_key().0.to_byte_array());
    let wrap = event(&w, 1059, now_secs(), &json!([["p", r_hex]]), "wrap");
    let del = event(
        &r,
        5,
        now_secs(),
        &json!([["e", wrap.id().to_string()], ["k", "1059"]]),
        "",
    );

    let mut ws = connect(addr).await.expect("connect failed");
    send_text(&mut ws, &event_wire(&wrap)).await;
    let ok = recv_ok(&mut ws, &wrap.id().to_string()).await.unwrap();
    assert_eq!(ok.get(2).and_then(Value::as_bool), Some(true), "{ok}");
    send_text(&mut ws, &event_wire(&del)).await;
    let ok = recv_ok(&mut ws, &del.id().to_string()).await.unwrap();
    assert_eq!(ok.get(2).and_then(Value::as_bool), Some(true), "{ok}");

    child.kill().unwrap();
    child.wait().unwrap();

    let mut child = spawn_relay(&cfg, &dir.path().join("relay-2.err"));
    wait_for_tcp(addr).await;
    let mut ws = connect(addr).await.expect("reconnect failed");
    send_text(&mut ws, &event_wire(&wrap)).await;
    let ok = recv_ok(&mut ws, &wrap.id().to_string()).await.unwrap();
    assert_eq!(ok.get(2).and_then(Value::as_bool), Some(false), "{ok}");
    assert!(
        ok.get(3)
            .and_then(Value::as_str)
            .is_some_and(|m| m.starts_with("blocked:")),
        "republished wrap after crash: {ok}"
    );

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    child.wait().unwrap();
}
