//! `nosfry sync` end-to-end: NIP-77 reconciliation against the
//! in-process relay, a scripted WebSocket peer (hyper + yawc server
//! side), and the `nosfry` binary for exit codes, kill-resume, and
//! multi-process LMDB sharing.

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

use std::collections::BTreeSet;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use futures_util::{SinkExt, future::poll_fn};
use hyper::body::Incoming;
use hyper::header::UPGRADE;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use nosfry::config::Config;
use nosfry::sync::{Direction, Outcome, SyncOptions};
use nosfry_core::event::Event;
use nosfry_core::moderation::ModOp;
use nosfry_lmdb::Store;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use yawc::{Frame, OpCode};

const T: Duration = Duration::from_secs(30);
/// Small LMDB map so a test process can hold many envs at once.
const MAP_SIZE: usize = 1 << 30;

/// Unix seconds now; test events must stay inside the relay's
/// `reject_events_older/newer` window.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `SyncOptions` for `url` with test defaults.
const fn opts(url: String, dir: Direction) -> SyncOptions {
    let mut o = SyncOptions::new(url);
    o.direction = dir;
    o.allow_private = true;
    o.timeout = T;
    o
}

fn relay_opts(relay: &Relay, dir: Direction) -> SyncOptions {
    opts(format!("ws://{}", relay.addr), dir)
}

/// A local config and store in `dir` (small LMDB map — the default
/// reserves 10 TiB per env, which exhausts mappings under load).
fn local(dir: &Path) -> (Config, Store) {
    let mut config = config();
    config.db.path = dir.to_path_buf();
    config.db.map_size = MAP_SIZE;
    let store = Store::open(&config.db.path, &config.store_options()).unwrap();
    (config, store)
}

/// An in-process peer relay with a small LMDB map.
async fn peer() -> Relay {
    let mut config = config();
    config.db.map_size = MAP_SIZE;
    Relay::start_with(config).await
}

/// Write `events` into `store` like the network write path does.
fn seed(store: &Store, config: &Config, events: &[Arc<Event>]) {
    let limits = config.limits().unwrap();
    store.write(events, limits.auth.names()).unwrap();
}

/// `n` events from rotating keys at spread timestamps.
fn events(n: usize, kind: u16, base_ts: u64, step: u64) -> Vec<Arc<Event>> {
    (0..n)
        .map(|i| {
            event(
                &key(u8::try_from(i % 8).unwrap() + 1),
                kind,
                base_ts + i as u64 * step,
                &json!([]),
                &format!("event {i}"),
            )
        })
        .collect()
}

/// Publish `events` over one connection, asserting `OK true`. At most
/// 64 publishes are in flight: blasting thousands of EVENTs before
/// reading a single OK lets the relay shed the connection.
async fn publish(relay: &Relay, evs: &[Arc<Event>]) {
    let mut ws = relay.connect().await;
    let mut sent = 0;
    let mut ok = 0;
    while ok < evs.len() {
        while sent < evs.len() && sent - ok < 64 {
            send_text(&mut ws, &event_wire(&evs[sent])).await;
            sent += 1;
        }
        let frame: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
        if frame[0] == "OK" {
            assert_eq!(frame[2], true, "{frame}");
            ok += 1;
        }
    }
}

/// Publish serially, waiting out `rate-limited` OKs and resending —
/// for peers configured to rate-limit writes.
async fn publish_lenient(relay: &Relay, evs: &[Arc<Event>]) {
    let mut ws = relay.connect().await;
    'outer: for ev in evs {
        let wire = event_wire(ev);
        for _ in 0..50 {
            send_text(&mut ws, &wire).await;
            let ok: Value = loop {
                let frame: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
                if frame[0] == "OK" {
                    break frame;
                }
            };
            if ok[2] == true {
                continue 'outer;
            }
            assert_eq!(
                ok[3].as_str().unwrap().split(':').next(),
                Some("rate-limited"),
                "{ok}"
            );
            let hint = ok[4]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(100);
            tokio::time::sleep(Duration::from_millis(hint + 50)).await;
        }
        panic!("event never accepted: {wire}");
    }
}

/// All ids in `store`, via the export path.
fn local_ids(store: &Store) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    store
        .export(0, u64::MAX, false, &mut |json| {
            let v: Value = serde_json::from_str(json).unwrap();
            ids.insert(v["id"].as_str().unwrap().to_owned());
            Ok(())
        })
        .unwrap();
    ids
}

fn local_count(store: &Store) -> u64 {
    store.export(0, u64::MAX, false, &mut |_| Ok(())).unwrap()
}

/// Page `{"limit":500,"until":…}` REQs over `ws` until `EOSE` yields
/// nothing (the peer clamps `limit` at `max_filter_limit`).
async fn collect_ids<S>(ws: &mut yawc::WebSocket<S>) -> BTreeSet<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut ids = BTreeSet::new();
    let mut until = u64::MAX;
    loop {
        send_text(
            ws,
            &req_wire("q", &json!({"limit": 500, "until": until}).to_string()),
        )
        .await;
        let mut got = 0usize;
        let mut oldest = until;
        let mut wait_ms = None;
        loop {
            let frame: Value = serde_json::from_str(&recv_text(ws, T).await).unwrap();
            match frame[0].as_str().unwrap() {
                "EVENT" => {
                    let ev = &frame[2];
                    ids.insert(ev["id"].as_str().unwrap().to_owned());
                    oldest = oldest.min(ev["created_at"].as_u64().unwrap());
                    got += 1;
                }
                "EOSE" => break,
                "CLOSED" => {
                    let msg = frame[2].as_str().unwrap_or("");
                    if msg.starts_with("rate-limited") {
                        wait_ms = Some(
                            frame[3]
                                .as_str()
                                .and_then(|s| s.parse::<u64>().ok())
                                .or_else(|| frame[3].as_u64())
                                .unwrap_or(200)
                                .min(60_000),
                        );
                    }
                    break;
                }
                _ => {}
            }
        }
        if let Some(ms) = wait_ms {
            tokio::time::sleep(Duration::from_millis(ms.max(10))).await;
            continue;
        }
        if got == 0 || oldest == 0 {
            break;
        }
        until = oldest - 1;
    }
    ids
}

/// All ids the peer serves.
async fn remote_ids(relay: &Relay) -> BTreeSet<String> {
    let mut ws = relay.connect().await;
    collect_ids(&mut ws).await
}

/// `COUNT` of all events the peer serves.
async fn remote_count(relay: &Relay) -> u64 {
    let mut ws = relay.connect().await;
    send_text(&mut ws, &count_wire("c", "{}")).await;
    loop {
        let frame: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
        if frame[0] == "COUNT" {
            return frame[2]["count"].as_u64().unwrap();
        }
    }
}

#[tokio::test]
async fn down_converges() {
    let peer = peer().await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let evs = events(60, 1, now_secs() - 3_600, 10);
    publish(&peer, &evs).await;
    let report = nosfry::sync::run(&store, &config, relay_opts(&peer, Direction::Down))
        .await
        .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(report.stats.downloaded, 60);
    assert_eq!(report.stats.failed, 0);
    assert_eq!(local_ids(&store), remote_ids(&peer).await);
    peer.stop().await;
}

#[tokio::test]
async fn up_converges() {
    let peer = peer().await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let evs = events(40, 1, now_secs() - 3_600, 10);
    seed(&store, &config, &evs);
    let report = nosfry::sync::run(&store, &config, relay_opts(&peer, Direction::Up))
        .await
        .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(report.stats.uploaded, 40);
    assert_eq!(remote_ids(&peer).await, local_ids(&store));
    peer.stop().await;
}

#[tokio::test]
async fn up_skips_restricted_and_protected() {
    // Local AUTH enabled: restricted kinds and protected events must
    // still never leave the relay — the peer is not an authenticated
    // author or recipient.
    let peer = peer().await;
    let dir = tempfile::tempdir().unwrap();
    let (mut config, store) = local(dir.path());
    config.relay.service_url = "wss://local.example".to_owned();
    config.relay.auth.restricted_read_kinds = vec![4];
    let t = now_secs() - 60;
    let dm_pk = faster_hex::hex_string(&key(6).x_only_public_key().0.to_byte_array());
    let dm = event(&key(5), 4, t, &json!([["p", dm_pk]]), "a direct message");
    let repost = event(
        &key(5),
        16,
        t + 1,
        &json!([]),
        "repost of {\"tags\":[[\"-\"]]}",
    );
    let note = event(&key(5), 1, t + 2, &json!([]), "public");
    let evs = vec![Arc::clone(&dm), Arc::clone(&repost), Arc::clone(&note)];
    seed(&store, &config, &evs);
    let report = nosfry::sync::run(&store, &config, relay_opts(&peer, Direction::Up))
        .await
        .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(report.stats.skipped, 2, "{:?}", report.stats);
    assert_eq!(report.stats.uploaded, 1, "{:?}", report.stats);
    assert_eq!(
        remote_ids(&peer).await,
        BTreeSet::from([note.id().to_string()])
    );
    peer.stop().await;
}

#[tokio::test]
async fn both_converges_and_is_idempotent() {
    let peer = peer().await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let t = now_secs() - 100_000;
    let shared = events(10, 1, t, 10);
    let mine = events(20, 1, t + 50_000, 10);
    let theirs = events(20, 1, t + 60_000, 10);
    let mut peer_seed = shared.clone();
    peer_seed.extend(theirs.iter().cloned());
    publish(&peer, &peer_seed).await;
    let mut local_seed = shared;
    local_seed.extend(mine.iter().cloned());
    seed(&store, &config, &local_seed);
    let o = relay_opts(&peer, Direction::Both);
    let report = nosfry::sync::run(&store, &config, o.clone()).await.unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(report.stats.downloaded, 20);
    assert_eq!(report.stats.uploaded, 20);
    assert_eq!(local_ids(&store), remote_ids(&peer).await);
    // A second run transfers nothing.
    let again = nosfry::sync::run(&store, &config, o).await.unwrap();
    assert_eq!(again.outcome, Outcome::Complete);
    assert_eq!(again.stats.downloaded, 0);
    assert_eq!(again.stats.uploaded, 0);
    peer.stop().await;
}

#[tokio::test]
async fn filter_and_window_bounds() {
    let peer = peer().await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let t = now_secs() - 20_000;
    let want = events(15, 1, t, 10);
    let wrong_kind = events(10, 7, t, 10);
    let out_of_range = events(10, 1, t - 10_000, 10);
    let mut all = want.clone();
    all.extend(wrong_kind.iter().cloned());
    all.extend(out_of_range.iter().cloned());
    publish(&peer, &all).await;
    let mut o = relay_opts(&peer, Direction::Down);
    o.filter = Some("{\"kinds\":[1]}".to_owned());
    o.since = Some(t);
    o.until = Some(t + 140);
    let report = nosfry::sync::run(&store, &config, o).await.unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    let got = local_ids(&store);
    assert_eq!(got.len(), 15, "only in-range kind-1 events arrive");
    for ev in &want {
        assert!(got.contains(&ev.id().to_string()));
    }
    // `limit`/`search` in --filter are usage errors.
    for bad in ["{\"limit\":5}", "{\"search\":\"x\"}"] {
        let mut o = relay_opts(&peer, Direction::Down);
        o.filter = Some(bad.to_owned());
        let err = nosfry::sync::run(&store, &config, o).await.err().unwrap();
        assert!(err.to_string().contains("--filter"), "{err}");
    }
    peer.stop().await;
}

#[tokio::test]
async fn peer_limits_are_used() {
    // A small NIP-11 max_message_length caps the client's negentropy
    // frames; ignoring it would blow the peer's WebSocket cap.
    let mut peer_config = config();
    peer_config.db.map_size = MAP_SIZE;
    // NIP-11 reports min(payload, max_event_size + 10); keep it big
    // enough that `neg_frame_limit` (≥ 4096) still fits.
    peer_config.events.max_event_size = 12_000;
    peer_config.relay.max_websocket_payload_size = 16_384;
    peer_config.relay.limits.max_filter_limit = 10;
    let peer = Relay::start_with(peer_config).await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let evs = events(50, 1, now_secs() - 3_600, 10);
    publish(&peer, &evs).await;
    let report = nosfry::sync::run(&store, &config, relay_opts(&peer, Direction::Down))
        .await
        .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(report.stats.downloaded, 50);
    assert_eq!(local_ids(&store), remote_ids(&peer).await);
    peer.stop().await;
}

#[tokio::test]
async fn blocked_too_many_splits() {
    // The peer refuses `NEG-OPEN` over `max_sync_events` with
    // `blocked:` and a limit; the client splits windows down.
    let mut peer_config = config();
    peer_config.db.map_size = MAP_SIZE;
    peer_config.relay.limits.max_sync_events = 20;
    let peer = Relay::start_with(peer_config).await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let evs = events(200, 1, now_secs() - 20_000, 10);
    publish(&peer, &evs).await;
    let report = nosfry::sync::run(&store, &config, relay_opts(&peer, Direction::Down))
        .await
        .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(report.stats.downloaded, 200);
    assert!(report.stats.windows > 1);
    peer.stop().await;
}

#[tokio::test]
async fn tiny_windows_converge() {
    // Shrink the client-side caps: the record cap and kept-id cap
    // force window splits, and same-second events exercise the
    // point-window requeue path.
    let peer = peer().await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let t = now_secs() - 20_000;
    let mut evs = events(150, 1, t, 30);
    evs.extend(events(30, 1, t + 5_000, 0)); // 30 events in one second
    publish(&peer, &evs).await;
    let mut o = relay_opts(&peer, Direction::Down);
    o.window_records = 7;
    o.pending_ids = 5;
    let report = nosfry::sync::run(&store, &config, o).await.unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(report.stats.downloaded, 180);
    peer.stop().await;
}

#[tokio::test]
async fn rate_limited_peer_converges() {
    // EVENTs and REQs get `rate-limited` rejections with retry hints;
    // the client waits and retries.
    let mut peer_config = config();
    peer_config.db.map_size = MAP_SIZE;
    let profile = default_profile(&mut peer_config);
    // Tiny bursts force `rate-limited` OKs; high sustained rates let
    // the hint-paced retries still converge within the attempt cap.
    profile.rate_limits.events_per_second = 200;
    profile.rate_limits.events_burst = 4;
    profile.rate_limits.reqs_per_second = 5;
    profile.rate_limits.reqs_burst = 1;
    let peer = Relay::start_with(peer_config).await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let t = now_secs() - 100_000;
    let theirs = events(12, 1, t, 10);
    let mine = events(12, 1, t + 50_000, 10);
    publish_lenient(&peer, &theirs).await;
    seed(&store, &config, &mine);
    let start = Instant::now();
    let report = nosfry::sync::run(&store, &config, relay_opts(&peer, Direction::Both))
        .await
        .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(local_ids(&store), remote_ids(&peer).await);
    assert!(
        start.elapsed() < Duration::from_secs(300),
        "rate-limited sync took {:?}",
        start.elapsed()
    );
    peer.stop().await;
}

/// A scripted-peer WebSocket: a real `yawc` server endpoint handed
/// out by the fake listener. Pings are auto-answered by yawc.
struct FakeWs {
    ws: yawc::HttpWebSocket,
}

impl FakeWs {
    async fn send(&mut self, text: &str) {
        self.ws.send(Frame::text(text.to_owned())).await.unwrap();
    }

    /// The next text payload; `None` on close/eof.
    async fn recv(&mut self) -> Option<String> {
        loop {
            let frame = poll_fn(|cx| self.ws.poll_next_frame(cx)).await.ok()?;
            match frame.opcode() {
                OpCode::Text => {
                    return String::from_utf8(frame.payload().to_vec()).ok();
                }
                OpCode::Close => return None,
                _ => {}
            }
        }
    }
}

/// Run a fake relay: each accepted TCP conn is a hyper h1 connection;
/// upgrade requests become `FakeWs` handed to `script`, anything else
/// (the NIP-11 GET) gets a 404. `script` runs once per upgrade.
async fn fake_peer<F, Fut>(script: F) -> SocketAddr
where
    F: Fn(FakeWs) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let script = Arc::new(script);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((io, _)) = listener.accept().await {
            let script = Arc::clone(&script);
            tokio::spawn(async move {
                let (tx, mut rx) = mpsc::unbounded_channel::<yawc::HttpWebSocket>();
                let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
                    let tx = tx.clone();
                    let is_upgrade = req
                        .headers()
                        .get(UPGRADE)
                        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
                    async move {
                        if is_upgrade
                            && let Ok((response, fut)) = yawc::WebSocket::upgrade(&mut req)
                        {
                            tokio::spawn(async move {
                                if let Ok(ws) = fut.await {
                                    drop(tx.send(ws));
                                }
                            });
                            return Ok::<_, std::convert::Infallible>(response);
                        }
                        Ok(Response::builder()
                            .status(404)
                            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
                            .unwrap())
                    }
                });
                // Drive the connection to completion first: the
                // upgrade detaches the socket when `conn` resolves,
                // and only then does the `fut` above hand us the
                // WebSocket. Draining `rx` afterwards cannot lose it.
                let conn = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(io), svc)
                    .with_upgrades();
                drop(conn.await);
                while let Some(ws) = rx.recv().await {
                    let script = Arc::clone(&script);
                    tokio::spawn(async move {
                        script(FakeWs { ws }).await;
                    });
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn notice_on_neg_open_is_fatal() {
    let addr = fake_peer(|ws| async move {
        let mut ws = ws;
        if ws.recv().await.is_some() {
            ws.send("[\"NOTICE\",\"no negentropy here\"]").await;
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let err = nosfry::sync::run(
        &store,
        &config,
        opts(format!("ws://{addr}"), Direction::Down),
    )
    .await
    .err()
    .unwrap();
    assert!(err.to_string().contains("NIP-77"), "{err}");
}

#[tokio::test]
async fn silent_peer_stalls() {
    let addr = fake_peer(|ws| async move {
        // Hold the socket open but say nothing until the client
        // gives up and disconnects.
        let mut ws = ws;
        while ws.recv().await.is_some() {}
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let mut o = opts(format!("ws://{addr}"), Direction::Down);
    o.timeout = Duration::from_secs(2);
    let start = Instant::now();
    let err = nosfry::sync::run(&store, &config, o).await.err().unwrap();
    // A peer that never answers the first NEG-OPEN probably does not
    // speak NIP-77 — the error says so and names the wait.
    assert!(err.to_string().contains("NIP-77"), "{err}");
    assert!(err.to_string().contains("no reply to NEG-OPEN"), "{err}");
    assert!(start.elapsed() < Duration::from_secs(20));
}

/// A real NIP-77 responder over `records`: on NEG-OPEN it answers
/// rounds until the diff is done; REQ gets `downloads` + EOSE. When
/// `notice` is set a NOTICE goes out right after the first NEG-MSG.
async fn neg_script(
    mut ws: FakeWs,
    records: Vec<(u64, [u8; 32])>,
    downloads: Vec<String>,
    notice: bool,
) {
    let mut neg: Option<negentropy::Negentropy<'static, negentropy::NegentropyStorageVector>> =
        None;
    let mut neg_sub = String::new();
    while let Some(text) = ws.recv().await {
        let Ok(frame) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match frame[0].as_str().unwrap_or("") {
            "NEG-OPEN" => {
                neg_sub = frame[1].as_str().unwrap().to_owned();
                let mut storage = negentropy::NegentropyStorageVector::with_capacity(records.len());
                for (ts, id) in &records {
                    storage
                        .insert(*ts, negentropy::Id::from_byte_array(*id))
                        .unwrap();
                }
                storage.seal().unwrap();
                let mut n = negentropy::Negentropy::owned(storage, 500_000).unwrap();
                let mut buf = vec![0u8; frame[3].as_str().unwrap().len() / 2];
                faster_hex::hex_decode(frame[3].as_str().unwrap().as_bytes(), &mut buf).unwrap();
                let reply = n.reconcile(&buf).unwrap();
                neg = Some(n);
                ws.send(&format!(
                    "[\"NEG-MSG\",\"{neg_sub}\",\"{}\"]",
                    faster_hex::hex_string(&reply)
                ))
                .await;
                if notice {
                    ws.send("[\"NOTICE\",\"thanks for syncing\"]").await;
                }
            }
            "NEG-MSG" => {
                let Some(n) = neg.as_mut() else { continue };
                let hex = frame[2].as_str().unwrap();
                let mut buf = vec![0u8; hex.len() / 2];
                faster_hex::hex_decode(hex.as_bytes(), &mut buf).unwrap();
                let reply = n.reconcile(&buf).unwrap();
                if reply.len() > 1 {
                    ws.send(&format!(
                        "[\"NEG-MSG\",\"{neg_sub}\",\"{}\"]",
                        faster_hex::hex_string(&reply)
                    ))
                    .await;
                }
            }
            "REQ" => {
                let sub = frame[1].as_str().unwrap().to_owned();
                for json in &downloads {
                    ws.send(&format!("[\"EVENT\",\"{sub}\",{json}]")).await;
                }
                ws.send(&format!("[\"EOSE\",\"{sub}\"]")).await;
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn notice_after_first_neg_msg_is_ignored() {
    // NIP-77 detection is run-level: once the first NEG-MSG proves
    // the peer speaks it, a stray NOTICE is noise, not fatal.
    let good = events(3, 1, now_secs() - 60, 10);
    let records: Vec<(u64, [u8; 32])> =
        good.iter().map(|ev| (ev.created_at(), ev.id().0)).collect();
    let downloads: Vec<String> = good.iter().map(|ev| ev.json().to_owned()).collect();
    let addr = fake_peer(move |ws| {
        let records = records.clone();
        let downloads = downloads.clone();
        neg_script(ws, records, downloads, true)
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let report = nosfry::sync::run(
        &store,
        &config,
        opts(format!("ws://{addr}"), Direction::Down),
    )
    .await
    .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(report.stats.downloaded, 3);
    assert_eq!(local_ids(&store).len(), 3);
}

#[tokio::test]
async fn auth_required_needs_key_file() {
    let addr = fake_peer(|ws| async move {
        let mut ws = ws;
        while let Some(text) = ws.recv().await {
            let Ok(frame) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            if frame[0] == "NEG-OPEN" {
                ws.send(&format!(
                    "[\"NEG-ERR\",\"{}\",\"auth-required: we only sync authed\"]",
                    frame[1].as_str().unwrap()
                ))
                .await;
            }
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let err = nosfry::sync::run(
        &store,
        &config,
        opts(format!("ws://{addr}"), Direction::Down),
    )
    .await
    .err()
    .unwrap();
    assert!(err.to_string().contains("--auth-key-file"), "{err}");
}

#[tokio::test]
async fn bogus_events_are_refused() {
    // A scripted peer speaking real NIP-77: one `closed:` retry on
    // the first NEG-OPEN, then a responder over three records. Its
    // REQ answer adds an unrequested id and a bad signature.
    let good = events(3, 1, now_secs() - 60, 10);
    let records: Vec<(u64, [u8; 32])> =
        good.iter().map(|ev| (ev.created_at(), ev.id().0)).collect();
    let unrequested = event(&key(9), 1, now_secs() - 60, &json!([]), "not asked for");
    let mut bad: Value = serde_json::from_str(good[0].json()).unwrap();
    bad["sig"] = json!("0".repeat(128));
    let mut downloads: Vec<String> = good.iter().map(|ev| ev.json().to_owned()).collect();
    downloads.push(unrequested.json().to_owned());
    downloads.push(bad.to_string());
    let addr = fake_peer(move |ws| {
        let records = records.clone();
        let downloads = downloads.clone();
        async move {
            let mut ws = ws;
            let mut neg: Option<
                negentropy::Negentropy<'static, negentropy::NegentropyStorageVector>,
            > = None;
            let mut neg_sub = String::new();
            let mut refused_once = false;
            while let Some(text) = ws.recv().await {
                let Ok(frame) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                match frame[0].as_str().unwrap_or("") {
                    "NEG-OPEN" => {
                        if !refused_once {
                            refused_once = true;
                            ws.send(&format!(
                                "[\"NEG-ERR\",\"{}\",\"closed: try again\"]",
                                frame[1].as_str().unwrap()
                            ))
                            .await;
                            continue;
                        }
                        neg_sub = frame[1].as_str().unwrap().to_owned();
                        let mut storage =
                            negentropy::NegentropyStorageVector::with_capacity(records.len());
                        for (ts, id) in &records {
                            storage
                                .insert(*ts, negentropy::Id::from_byte_array(*id))
                                .unwrap();
                        }
                        storage.seal().unwrap();
                        let mut n = negentropy::Negentropy::owned(storage, 500_000).unwrap();
                        let hex = frame[3].as_str().unwrap();
                        let mut buf = vec![0u8; hex.len() / 2];
                        faster_hex::hex_decode(hex.as_bytes(), &mut buf).unwrap();
                        let reply = n.reconcile(&buf).unwrap();
                        neg = Some(n);
                        ws.send(&format!(
                            "[\"NEG-MSG\",\"{neg_sub}\",\"{}\"]",
                            faster_hex::hex_string(&reply)
                        ))
                        .await;
                    }
                    "NEG-MSG" => {
                        let Some(n) = neg.as_mut() else { continue };
                        let hex = frame[2].as_str().unwrap();
                        let mut buf = vec![0u8; hex.len() / 2];
                        faster_hex::hex_decode(hex.as_bytes(), &mut buf).unwrap();
                        let reply = n.reconcile(&buf).unwrap();
                        if reply.len() > 1 {
                            ws.send(&format!(
                                "[\"NEG-MSG\",\"{neg_sub}\",\"{}\"]",
                                faster_hex::hex_string(&reply)
                            ))
                            .await;
                        }
                    }
                    "REQ" => {
                        let sub = frame[1].as_str().unwrap().to_owned();
                        for json in &downloads {
                            ws.send(&format!("[\"EVENT\",\"{sub}\",{json}]")).await;
                        }
                        ws.send(&format!("[\"EOSE\",\"{sub}\"]")).await;
                    }
                    _ => {}
                }
            }
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (config, store) = local(dir.path());
    let report = nosfry::sync::run(
        &store,
        &config,
        opts(format!("ws://{addr}"), Direction::Down),
    )
    .await
    .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert_eq!(report.stats.downloaded, 3);
    assert!(report.stats.refused_remote >= 2, "{:?}", report.stats);
    let ids = local_ids(&store);
    assert_eq!(ids.len(), 3);
    assert!(!ids.contains(&unrequested.id().to_string()));
}

/// Write a `nosfry.toml` for binary-child tests (small LMDB map).
fn write_config(dir: &Path, db: &Path, listen: Option<u16>) -> PathBuf {
    let mut text = format!(
        "[db]\npath = {:?}\nmap_size = {MAP_SIZE}\n",
        db.display().to_string()
    );
    if let Some(port) = listen {
        use std::fmt::Write as _;
        write!(
            text,
            "[[relay.listen]]\naddress = \"127.0.0.1:{port}\"\nprofile = \"default\"\nreal_ip_header = \"\"\n"
        )
        .unwrap();
    }
    let path = dir.join("nosfry.toml");
    std::fs::write(&path, text).unwrap();
    path
}

/// The `nosfry` binary as an async `Command`: blocking waits would
/// freeze the in-process relay that shares this test's runtime.
fn nosfry(config: &Path, args: &[&str]) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_nosfry"));
    cmd.arg("--config").arg(config).args(args);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    cmd
}

#[cfg(unix)]
#[tokio::test]
async fn interrupted_run_resumes() {
    // Kill `nosfry sync` mid-download with SIGKILL; the rerun must
    // converge (rerun-based resumption — no persisted cursor).
    const N: usize = 10_000;
    let peer = peer().await;
    let evs = events(N, 1, now_secs() - 30_000, 1);
    publish(&peer, &evs).await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    let cfg = write_config(dir.path(), &db, None);
    let url = format!("ws://{}", peer.addr);
    let args = ["sync", url.as_str(), "--allow-private", "--timeout", "60"];
    let mut child = nosfry(&cfg, &args).spawn().unwrap();
    // Wait until the download is visibly in flight, then SIGKILL.
    let mut probe_config = config();
    probe_config.db.map_size = MAP_SIZE;
    let probe = Store::open(&db, &probe_config.store_options()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    while local_count(&probe) == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let partial = local_count(&probe);
    assert!(partial > 0, "no download progress before kill");
    let status = std::process::Command::new("kill")
        .args(["-9", &child.id().unwrap().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    child.wait().await.unwrap();
    // The partial download may or may not have finished before the
    // signal landed; the rerun converges either way.
    let status = nosfry(&cfg, &args).status().await.unwrap();
    assert!(status.success(), "rerun failed: {status}");
    assert_eq!(local_count(&probe), remote_count(&peer).await);
    peer.stop().await;
}

#[tokio::test]
async fn binary_exit_codes() {
    let peer = peer().await;
    publish(&peer, &events(5, 1, now_secs() - 60, 10)).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &dir.path().join("db"), None);
    let url = format!("ws://{}", peer.addr);
    // Complete → 0.
    let status = nosfry(&cfg, &["sync", url.as_str(), "--allow-private"])
        .status()
        .await
        .unwrap();
    assert!(status.success(), "{status}");
    // Private address without --allow-private → 1.
    let status = nosfry(&cfg, &["sync", "ws://127.0.0.1:9"])
        .status()
        .await
        .unwrap();
    assert_eq!(status.code(), Some(1));
    // A peer refusing uploads with `error:` → 3 (partial). The peer's
    // write-policy plugin rejects every event.
    let reject_dir = tempfile::tempdir().unwrap();
    let plugin = reject_dir.path().join("reject.sh");
    std::fs::write(
        &plugin,
        "#!/bin/sh\nwhile IFS= read -r line; do\n\
         \tid=\"${line#*\\\"id\\\":\\\"}\"; id=\"${id%%\\\"*}\";\n\
         \tprintf '{\"id\":\"%s\",\"action\":\"reject\",\"msg\":\"error: rejected\"}\\n' \"$id\"\n\
         done\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut peer_config = config();
    peer_config.db.map_size = MAP_SIZE;
    peer_config.relay.write_policy.plugin = plugin.display().to_string();
    let reject_peer = Relay::start_with(peer_config).await;
    let dir2 = tempfile::tempdir().unwrap();
    let (config, store) = local(dir2.path());
    seed(&store, &config, &events(3, 1, now_secs() - 60, 10));
    let cfg2 = write_config(dir2.path(), dir2.path(), None);
    let url2 = format!("ws://{}", reject_peer.addr);
    let status = nosfry(
        &cfg2,
        &["sync", url2.as_str(), "--dir", "up", "--allow-private"],
    )
    .status()
    .await
    .unwrap();
    assert_eq!(status.code(), Some(3));
    peer.stop().await;
    reject_peer.stop().await;
}

#[tokio::test]
async fn nip42_authenticated_sync() {
    // Peer with AUTH enabled and kind 4 restricted to involved
    // pubkeys: the authed sync downloads the DMs addressed to the
    // key, the unauthed one gets public notes only.
    let mut peer_config = config();
    peer_config.db.map_size = MAP_SIZE;
    peer_config.relay.auth.restricted_read_kinds = vec![4];
    peer_config.relay.auth.restrict_read_to_involved = true;
    let peer = Relay::start_with(peer_config.clone()).await;
    let mut with_url = peer_config;
    with_url.relay.service_url = format!("ws://{}", peer.addr);
    peer.reload(with_url);
    // Give the reload a moment to propagate before syncing.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let dm_key = key(20);
    let dm_pk = faster_hex::hex_string(&dm_key.x_only_public_key().0.to_byte_array());
    let t = now_secs() - 60;
    let dm = event(&key(21), 4, t, &json!([["p", dm_pk]]), "a direct message");
    let notes = events(10, 1, t + 10, 10);
    let mut all = vec![Arc::clone(&dm)];
    all.extend(notes.iter().cloned());
    publish(&peer, &all).await;
    let dir = tempfile::tempdir().unwrap();
    let (mut config, store) = local(dir.path());
    // The local relay refuses restricted kinds it cannot itself gate
    // — clear them so synced DMs are admitted.
    config.relay.auth.restricted_read_kinds = vec![];
    // No key: public notes only, still Complete.
    let report = nosfry::sync::run(&store, &config, relay_opts(&peer, Direction::Down))
        .await
        .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    let ids = local_ids(&store);
    assert_eq!(ids.len(), 10, "{ids:?}");
    assert!(!ids.contains(&dm.id().to_string()));
    // With K's key file: the DM arrives too.
    let key_dir = tempfile::tempdir().unwrap();
    let key_path = key_dir.path().join("key");
    std::fs::write(&key_path, faster_hex::hex_string(&dm_key.to_secret_bytes())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut o = relay_opts(&peer, Direction::Down);
    o.auth_key_file = Some(key_path);
    let report = nosfry::sync::run(&store, &config, o).await.unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    assert!(local_ids(&store).contains(&dm.id().to_string()));
    peer.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn sync_shares_db_with_running_relay() {
    // A `nosfry relay` child holds the local db; a `nosfry sync`
    // child writes into the same LMDB env while the relay serves
    // reads and takes live publishes.
    let dir = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let relay_cfg = write_config(dir.path(), &dir.path().join("db"), Some(port));
    let mut relay_child = nosfry(&relay_cfg, &["relay"]).spawn().unwrap();
    let relay_url = format!("ws://127.0.0.1:{port}");
    for _ in 0..300 {
        if TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let peer = peer().await;
    let synced = events(200, 1, now_secs() - 3_600, 10);
    publish(&peer, &synced).await;
    let peer_url = format!("ws://{}", peer.addr);
    let sync_cfg = write_config(dir.path(), &dir.path().join("db"), None);
    let mut sync_child = nosfry(
        &sync_cfg,
        &[
            "sync",
            peer_url.as_str(),
            "--allow-private",
            "--timeout",
            "60",
        ],
    )
    .spawn()
    .unwrap();
    // Publish live events to the running relay during the sync.
    let mut ws = yawc::WebSocket::connect(relay_url.parse().unwrap())
        .await
        .unwrap();
    let live = events(20, 1, now_secs() - 500, 10);
    for ev in &live {
        send_text(&mut ws, &event_wire(ev)).await;
    }
    let mut ok = 0;
    while ok < live.len() {
        let frame: Value = serde_json::from_str(&recv_text(&mut ws, T).await).unwrap();
        if frame[0] == "OK" {
            assert_eq!(frame[2], true, "{frame}");
            ok += 1;
        }
    }
    let status = sync_child.wait().await.unwrap();
    assert!(status.success(), "sync exited {status}");
    // The running relay serves both live and synced events.
    let ids = collect_ids(&mut ws).await;
    for ev in synced.iter().chain(live.iter()) {
        assert!(ids.contains(&ev.id().to_string()), "missing {}", ev.id());
    }
    relay_child.start_kill().unwrap();
    relay_child.wait().await.unwrap();
    peer.stop().await;
}

#[tokio::test]
async fn moderation_and_write_policy_refuse() {
    // Local moderation (banned pubkey) and a local write-policy
    // plugin rejecting one id both refuse downloads; the rest store.
    let peer = peer().await;
    let t = now_secs() - 60;
    let banned = event(&key(7), 1, t, &json!([]), "banned author");
    let rejected = event(&key(8), 1, t + 10, &json!([]), "policy says no");
    let fine = events(5, 1, t + 20, 10);
    let mut all = vec![Arc::clone(&banned), Arc::clone(&rejected)];
    all.extend(fine.iter().cloned());
    publish(&peer, &all).await;
    let dir = tempfile::tempdir().unwrap();
    let (mut config, store) = local(dir.path());
    store
        .moderate(ModOp::BanPubkey {
            pubkey: banned.pubkey(),
            reason: None,
        })
        .unwrap();
    let plugin_dir = tempfile::tempdir().unwrap();
    let plugin = plugin_dir.path().join("policy.sh");
    let target = rejected.id().to_string();
    std::fs::write(
        &plugin,
        format!(
            "#!/bin/sh\nwhile IFS= read -r line; do\n\
             \tid=\"${{line#*\\\"id\\\":\\\"}}\"; id=\"${{id%%\\\"*}}\";\n\
             \tif [ \"$id\" = \"{target}\" ]; then\n\
             \t\tprintf '{{\"id\":\"%s\",\"action\":\"reject\",\"msg\":\"blocked: no\"}}\\n' \"$id\"\n\
             \telse\n\
             \t\tprintf '{{\"id\":\"%s\",\"action\":\"accept\"}}\\n' \"$id\"\n\
             \tfi\ndone\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    config.relay.write_policy.plugin = plugin.display().to_string();
    let report = nosfry::sync::run(&store, &config, relay_opts(&peer, Direction::Down))
        .await
        .unwrap();
    assert_eq!(report.outcome, Outcome::Complete);
    let ids = local_ids(&store);
    assert_eq!(ids.len(), 5);
    assert!(!ids.contains(&banned.id().to_string()));
    assert!(!ids.contains(&rejected.id().to_string()));
    assert!(report.stats.refused_local >= 2, "{:?}", report.stats);
    peer.stop().await;
}
