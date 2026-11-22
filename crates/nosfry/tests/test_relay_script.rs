//! `contrib/test-relay/nosfry-test-relay.sh` end to end: seed import,
//! NIP-11 readiness, a REQ serving the seed, and deterministic
//! cleanup (graceful relay exit, temp dir removed) on SIGTERM.

#![allow(
    unused_crate_dependencies,
    reason = "each test binary uses a subset of the workspace dependencies"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "each file is a single integration test"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may panic"
)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{event, key};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::time::timeout;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// The port of a just-dropped probe bind: a small race the script's
/// "relay exited during startup" error surfaces plainly.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `kill -TERM` the script through its printed stdout contract.
fn sigterm(child: &Child) {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill -TERM failed");
}

/// The plain-HTTP NIP-11 document, or an empty body on failure.
fn nip11(port: u16) -> String {
    let mut conn = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nAccept: application/nostr+json\r\n\r\n")
        .unwrap();
    let mut buf = String::new();
    conn.read_to_string(&mut buf).unwrap();
    buf
}

/// Collect EVENT ids until EOSE on an already-open subscription.
async fn recv_until_eose(ws: &mut yawc::TcpWebSocket) -> Vec<String> {
    let mut ids = Vec::new();
    while let Some(frame) = ws.next().await {
        if frame.opcode() != yawc::OpCode::Text {
            continue;
        }
        let v: Value = serde_json::from_slice(frame.payload()).unwrap();
        match v[0].as_str().unwrap() {
            "EVENT" => ids.push(v[2]["id"].as_str().unwrap().to_owned()),
            "EOSE" => return ids,
            _ => {}
        }
    }
    panic!("connection closed before EOSE");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(unix)]
async fn contrib_test_relay_script_serves_and_cleans_up() {
    let script = repo_root().join("contrib/test-relay/nosfry-test-relay.sh");
    assert!(script.exists(), "script missing: {script:?}");
    let bin = env!("CARGO_BIN_EXE_nosfry");

    let dir = tempfile::tempdir().unwrap();
    let k = key(9);
    let e1 = event(&k, 1, 1_700_000_001, &json!([]), "seed one");
    let e2 = event(&k, 1, 1_700_000_002, &json!([]), "seed two");
    let seed = dir.path().join("seed.jsonl");
    std::fs::write(&seed, format!("{}\n{}\n", e1.json(), e2.json())).unwrap();
    let want_ids: Vec<String> = [&e1, &e2]
        .iter()
        .map(|e| {
            serde_json::from_str::<Value>(e.json()).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();

    let port = free_port();
    let mut child = Command::new("bash")
        .arg(&script)
        .args(["--bin", bin])
        .args(["--port", &port.to_string()])
        .args(["--seed", seed.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // The stdout contract: NOSFRY_URL, NOSFRY_RELAY_PID, NOSFRY_TMPDIR.
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut url = String::new();
    let mut tmpdir = String::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while url.is_empty() || tmpdir.is_empty() {
        assert!(Instant::now() < deadline, "no stdout contract within 30 s");
        let line = lines
            .next()
            .expect("script stdout closed early")
            .expect("script stdout error");
        if let Some(v) = line.strip_prefix("NOSFRY_URL=") {
            url = v.to_owned();
        }
        if let Some(v) = line.strip_prefix("NOSFRY_TMPDIR=") {
            tmpdir = v.to_owned();
        }
    }
    assert_eq!(url, format!("ws://127.0.0.1:{port}"));
    assert!(Path::new(&tmpdir).is_dir(), "tmpdir not created: {tmpdir}");

    // NIP-11 answers on the same port.
    let doc = nip11(port);
    assert!(doc.contains("\"max_limit\""), "no NIP-11 document: {doc:?}");

    // A REQ over WebSocket serves both seeded events.
    let mut ws = yawc::WebSocket::connect(url.parse().unwrap())
        .await
        .unwrap();
    ws.send(yawc::Frame::text("[\"REQ\",\"s\",{}]".to_owned()))
        .await
        .unwrap();
    let mut got = timeout(Duration::from_secs(10), recv_until_eose(&mut ws))
        .await
        .unwrap();
    got.sort_unstable();
    let mut want = want_ids;
    want.sort_unstable();
    assert_eq!(got, want, "seeded events not served");

    // SIGTERM the script: relay exits gracefully, temp dir removed.
    sigterm(&child);
    let status = timeout(
        Duration::from_secs(15),
        tokio::task::spawn_blocking(move || child.wait_with_output().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(status.status.success(), "script exit: {status:?}");
    assert!(
        !Path::new(&tmpdir).exists(),
        "temp dir not removed: {tmpdir}"
    );
}

#[cfg(not(unix))]
#[test]
fn contrib_test_relay_script_skipped_off_unix() {}
