//! Black-box NIP conformance: the identical assertions run against
//! the native and the Workers editions. Every test needs `NOSFRY_URL`
//! (`ws://…`) pointing at a relay configured with `profile.toml` plus
//! an injected `service_url`; `run.sh` provides both.
//!
//! Every test signs with a fresh random key, so tests isolate on a
//! shared relay and may run in parallel.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::shadow_unrelated,
    reason = "conformance assertions may panic on black-box replies"
)]

use std::fmt::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use nosfry_core::event::Event;
use nosfry_core::sign;
use secp256k1::Keypair;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(10);
fn url() -> String {
    std::env::var("NOSFRY_URL").expect("NOSFRY_URL must point at the relay under test")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A fresh keypair — never the deterministic pool, so reruns against
/// the same relay do not collide with stale state.
fn key() -> Keypair {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).unwrap();
        if let Ok(secret) = secp256k1::SecretKey::from_secret_bytes(bytes) {
            return Keypair::from_secret_key(&secret);
        }
    }
}

fn pubkey(k: &Keypair) -> String {
    format!("{}", k.x_only_public_key().0)
}

fn event_wire(ev: &Event) -> String {
    format!("[\"EVENT\",{}]", ev.json())
}

fn req_wire(id: &str, filter: &str) -> String {
    format!("[\"REQ\",\"{id}\",{filter}]")
}

fn count_wire(id: &str, filter: &str) -> String {
    format!("[\"COUNT\",\"{id}\",{filter}]")
}

async fn connect() -> yawc::TcpWebSocket {
    yawc::WebSocket::connect(url().parse().unwrap())
        .await
        .unwrap()
}

async fn send(ws: &mut yawc::TcpWebSocket, text: &str) {
    ws.send(yawc::Frame::text(text.to_owned())).await.unwrap();
}

/// The next text frame, parsed as JSON; non-text frames are skipped.
async fn recv_json(ws: &mut yawc::TcpWebSocket) -> Value {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let frame = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("timed out waiting for a frame")
            .expect("connection closed while waiting for a frame");
        if frame.opcode() == yawc::OpCode::Text {
            return serde_json::from_slice(frame.payload()).unwrap();
        }
    }
}

/// Frames until `pred` matches one; returns everything collected.
async fn collect_until(ws: &mut yawc::TcpWebSocket, pred: impl Fn(&Value) -> bool) -> Vec<Value> {
    let mut frames = Vec::new();
    while !frames.iter().any(&pred) {
        frames.push(recv_json(ws).await);
    }
    frames
}

/// Publish and assert the OK frame, returning its message field.
async fn publish(ws: &mut yawc::TcpWebSocket, ev: &Event) -> (bool, String) {
    send(ws, &event_wire(ev)).await;
    let ok = collect_until(ws, |v| v[0] == "OK").await;
    let ok = &ok[ok.len() - 1];
    assert_eq!(ok[1], ev.id().to_string(), "OK id mismatch");
    (ok[2].as_bool().unwrap(), ok[3].as_str().unwrap().to_owned())
}

/// Issue a REQ and return the frames up to and including EOSE or
/// CLOSED.
async fn req(ws: &mut yawc::TcpWebSocket, id: &str, filter: &str) -> Vec<Value> {
    send(ws, &req_wire(id, filter)).await;
    collect_until(ws, |v| v[0] == "EOSE" || v[0] == "CLOSED").await
}

/// Send a COUNT and return its `{"count":…}` body.
async fn count(ws: &mut yawc::TcpWebSocket, id: &str, filter: &str) -> Value {
    send(ws, &count_wire(id, filter)).await;
    let frames = collect_until(ws, |v| v[0] == "COUNT" || v[0] == "CLOSED").await;
    let frame = frames.last().unwrap();
    assert_eq!(frame[0], "COUNT", "COUNT refused: {frame}");
    assert_eq!(frame[1], id, "{frame}");
    frame[2].clone()
}

fn events(frames: &[Value]) -> Vec<&Value> {
    frames
        .iter()
        .filter(|v| v[0] == "EVENT")
        .map(|v| &v[2])
        .collect()
}

/// A plain HTTP GET (no NIP-11 Accept), returning (status,
/// content-type, body).
async fn http_get(path: &str) -> (u16, String, String) {
    let url = url();
    let authority = url
        .strip_prefix("ws://")
        .expect("NOSFRY_URL must use ws://")
        .trim_end_matches('/');
    let mut tcp = tokio::net::TcpStream::connect(authority).await.unwrap();
    tcp.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8(buf).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let content_type = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
        .map_or_default(|l| l.split_once(':').map(|(_, v)| v.trim().to_owned()).unwrap());
    (status, content_type, body.to_owned())
}

/// The relay's NIP-11 document over plain HTTP.
async fn nip11() -> Value {
    let url = url();
    let authority = url
        .strip_prefix("ws://")
        .expect("NOSFRY_URL must use ws://")
        .trim_end_matches('/');
    let mut tcp = tokio::net::TcpStream::connect(authority).await.unwrap();
    tcp.write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8(buf).unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap();
    serde_json::from_str(body).unwrap()
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip11_document() {
    let doc = nip11().await;
    assert_eq!(doc["name"], "nosfry conformance");
    assert_eq!(doc["software"], "https://github.com/qntx/nosfry");
    assert!(doc["version"].is_string());
    assert!(doc["limitation"].is_object());
    assert_eq!(doc["banner"], "https://example.com/banner.png");
    assert_eq!(
        doc["self"],
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    );
    assert_eq!(doc["terms_of_service"], "https://example.com/terms");
    assert_eq!(doc["privacy_policy"], "https://example.com/privacy");
    let nips: Vec<u64> = doc["supported_nips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    for nip in [1, 9, 11, 40, 42, 45, 59, 62, 70, 77, 86] {
        assert!(nips.contains(&nip), "missing NIP-{nip}: {nips:?}");
    }
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn http_surface() {
    // GET / without a NIP-11 Accept is the HTML landing page.
    let (status, content_type, body) = http_get("/").await;
    assert_eq!(status, 200);
    assert!(content_type.starts_with("text/html"), "{content_type}");
    assert!(body.contains("nosfry conformance"), "{body}");

    // /nodeinfo/2.1 is the NodeInfo document.
    let (status, content_type, body) = http_get("/nodeinfo/2.1").await;
    assert_eq!(status, 200);
    assert!(content_type.contains("application/json"), "{content_type}");
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["version"], "2.1");
    assert_eq!(doc["software"]["name"], "nosfry");

    // /.well-known/nodeinfo links at the service_url host — run.sh
    // injects ws://127.0.0.1:PORT, so the href is its http:// twin.
    let (status, _, body) = http_get("/.well-known/nodeinfo").await;
    assert_eq!(status, 200);
    let doc: Value = serde_json::from_str(&body).unwrap();
    let url = url();
    let authority = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    assert_eq!(
        doc["links"][0]["href"],
        format!("http://{authority}/nodeinfo/2.1")
    );

    // Unknown paths are 404 without reaching the relay.
    let (status, _, _) = http_get("/nope").await;
    assert_eq!(status, 404);
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn publish_ok_duplicate_and_bad_signature() {
    let k = key();
    let ev = sign::event(&k, 1, now(), &json!([]), "conformance publish");
    let mut ws = connect().await;
    let (ok, _) = publish(&mut ws, &ev).await;
    assert!(ok, "first publish rejected");

    let (ok, reason) = publish(&mut ws, &ev).await;
    // A byte-identical re-publish is accepted with `duplicate:`.
    assert!(
        ok && reason.starts_with("duplicate:"),
        "re-publish: {reason}"
    );

    // Corrupt one hex nibble inside the signature; the JSON stays valid.
    let mut doc = serde_json::from_str::<Value>(ev.json()).unwrap();
    let sig = doc["sig"].as_str().unwrap();
    let last = sig.chars().last().unwrap();
    let flipped = if last == '0' { '1' } else { '0' };
    doc["sig"] = json!(format!("{}{}", &sig[..sig.len() - 1], flipped));
    send(
        &mut ws,
        &format!("[\"EVENT\",{}]", serde_json::to_string(&doc).unwrap()),
    )
    .await;
    let ok = recv_json(&mut ws).await;
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], false);
    assert!(ok[3].as_str().unwrap().starts_with("invalid:"), "{ok}");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn req_newest_first_limit_eose() {
    let k = key();
    let base = now() - 4;
    let mut ws = connect().await;
    for i in 0..3u64 {
        let ev = sign::event(&k, 1, base + i, &json!([]), &format!("e{i}"));
        let (ok, reason) = publish(&mut ws, &ev).await;
        assert!(ok, "publish {i}: {reason}");
    }
    let filter = format!("{{\"authors\":[\"{}\"],\"limit\":2}}", pubkey(&k));
    let frames = req(&mut ws, "s", &filter).await;
    assert_eq!(frames.last().unwrap()[0], "EOSE");
    let got = events(&frames);
    assert_eq!(got.len(), 2);
    // Newest first: created_at descending.
    assert!(
        got[0]["created_at"].as_u64().unwrap() > got[1]["created_at"].as_u64().unwrap(),
        "{got:?}"
    );
    assert_eq!(got[0]["content"], "e2");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn live_delivery_after_eose() {
    let k = key();
    let mut sub = connect().await;
    let mut writer = connect().await;
    let filter = format!("{{\"authors\":[\"{}\"]}}", pubkey(&k));
    let frames = req(&mut sub, "s", &filter).await;
    assert_eq!(frames.last().unwrap()[0], "EOSE");
    assert!(events(&frames).is_empty(), "unexpected events: {frames:?}");

    let ev = sign::event(&k, 1, now(), &json!([]), "live");
    let (ok, reason) = publish(&mut writer, &ev).await;
    assert!(ok, "publish: {reason}");
    let frame = recv_json(&mut sub).await;
    assert_eq!(frame[0], "EVENT");
    assert_eq!(frame[2]["id"], ev.id().to_string());
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn close_stops_delivery() {
    let k = key();
    let mut sub = connect().await;
    let mut writer = connect().await;
    let filter = format!("{{\"authors\":[\"{}\"]}}", pubkey(&k));
    req(&mut sub, "s", &filter).await;
    send(&mut sub, "[\"CLOSE\",\"s\"]").await;
    // Inbound frames apply in order, so the barrier's EOSE proves the
    // CLOSE took effect before the other connection publishes.
    req(&mut sub, "barrier", "{\"ids\":[]}").await;

    let ev = sign::event(&k, 1, now(), &json!([]), "after close");
    let (ok, reason) = publish(&mut writer, &ev).await;
    assert!(ok, "publish: {reason}");
    // After CLOSE no EVENT may arrive; a quiet two seconds proves it
    // (pings and pongs are not relay traffic and don't count).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(Some(f)) = tokio::time::timeout_at(deadline, sub.next()).await {
        assert_ne!(
            f.opcode(),
            yawc::OpCode::Text,
            "frame after CLOSE: {:?}",
            String::from_utf8_lossy(f.payload())
        );
    }
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn replaceable_newer_wins() {
    let k = key();
    let base = now() - 10;
    let older = sign::event(&k, 0, base, &json!([]), "older");
    let newer = sign::event(&k, 0, base + 5, &json!([]), "newer");
    let mut ws = connect().await;

    let (ok, reason) = publish(&mut ws, &older).await;
    assert!(ok, "older: {reason}");
    let (ok, reason) = publish(&mut ws, &newer).await;
    assert!(ok, "newer: {reason}");
    let (ok, reason) = publish(&mut ws, &older).await;
    assert!(
        !ok && reason == "duplicate: have a newer version",
        "older again: {reason}"
    );

    let filter = format!("{{\"kinds\":[0],\"authors\":[\"{}\"]}}", pubkey(&k));
    let frames = req(&mut ws, "s", &filter).await;
    let got = events(&frames);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["id"], newer.id().to_string());
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn addressable_replaced_by_d() {
    let k = key();
    let base = now() - 10;
    let older = sign::event(&k, 30023, base, &json!([["d", "conformance"]]), "v1");
    let newer = sign::event(&k, 30023, base + 5, &json!([["d", "conformance"]]), "v2");
    let mut ws = connect().await;
    assert!(publish(&mut ws, &older).await.0);
    assert!(publish(&mut ws, &newer).await.0);

    let filter = format!("{{\"kinds\":[30023],\"authors\":[\"{}\"]}}", pubkey(&k));
    let frames = req(&mut ws, "s", &filter).await;
    let got = events(&frames);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["content"], "v2");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn ephemeral_live_only() {
    let k = key();
    let mut sub = connect().await;
    let mut writer = connect().await;
    let filter = format!("{{\"authors\":[\"{}\"],\"kinds\":[20001]}}", pubkey(&k));
    req(&mut sub, "s", &filter).await;

    let ev = sign::event(&k, 20001, now(), &json!([]), "ephemeral");
    let (ok, reason) = publish(&mut writer, &ev).await;
    assert!(ok, "ephemeral publish: {reason}");
    let frame = recv_json(&mut sub).await;
    assert_eq!(frame[0], "EVENT");
    assert_eq!(frame[2]["id"], ev.id().to_string());

    let frames = req(&mut writer, "t", &filter).await;
    assert_eq!(frames.last().unwrap()[0], "EOSE");
    assert!(events(&frames).is_empty(), "ephemeral event was stored");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip09_e_deletion() {
    let k = key();
    let ev = sign::event(&k, 1, now() - 5, &json!([]), "to be deleted");
    let mut ws = connect().await;
    assert!(publish(&mut ws, &ev).await.0);

    let del = sign::event(
        &k,
        5,
        now(),
        &json!([["e", &*ev.id().to_string()]]),
        "deleted",
    );
    let (ok, reason) = publish(&mut ws, &del).await;
    assert!(ok, "deletion: {reason}");

    let filter = format!("{{\"ids\":[\"{}\"]}}", ev.id());
    let frames = req(&mut ws, "s", &filter).await;
    assert!(
        events(&frames).is_empty(),
        "deleted event served: {frames:?}"
    );

    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(
        !ok && reason == "blocked: deleted by its author",
        "re-publish of a deleted event: {reason}"
    );
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip09_a_deletion() {
    let k = key();
    let ev = sign::event(&k, 30023, now() - 5, &json!([["d", "nip09a"]]), "v1");
    let mut ws = connect().await;
    assert!(publish(&mut ws, &ev).await.0);

    let del = sign::event(
        &k,
        5,
        now(),
        &json!([["a", format!("30023:{}:nip09a", pubkey(&k))]]),
        "deleted",
    );
    assert!(publish(&mut ws, &del).await.0);

    let filter = format!("{{\"kinds\":[30023],\"authors\":[\"{}\"]}}", pubkey(&k));
    let frames = req(&mut ws, "s", &filter).await;
    assert!(events(&frames).is_empty(), "deleted article served");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip40_expired_rejected() {
    let k = key();
    let ev = sign::event(
        &k,
        1,
        now() - 30,
        &json!([["expiration", (now() - 10).to_string()]]),
        "already expired",
    );
    let mut ws = connect().await;
    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(!ok && reason.starts_with("invalid:"), "{reason}");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip40_expiry_removes_from_results() {
    let k = key();
    let ev = sign::event(
        &k,
        1,
        now() - 1,
        &json!([["expiration", (now() + 2).to_string()]]),
        "expiring soon",
    );
    let mut ws = connect().await;
    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(ok, "publish: {reason}");

    tokio::time::sleep(Duration::from_secs(3)).await;
    let filter = format!("{{\"authors\":[\"{}\"]}}", pubkey(&k));
    let frames = req(&mut ws, "s", &filter).await;
    assert!(
        events(&frames).is_empty(),
        "expired event served: {frames:?}"
    );
}

/// The NIP-42 flow shared by the AUTH tests: REQ a restricted kind,
/// capture the challenge from the AUTH frame, sign kind 22242 as
/// `signer`, and assert acceptance.
async fn authenticate(ws: &mut yawc::TcpWebSocket, signer: &Keypair, req_filter: &str) {
    let frames = req(ws, "r", req_filter).await;
    let challenge = frames
        .iter()
        .find(|v| v[0] == "AUTH")
        .map(|v| v[1].as_str().unwrap().to_owned())
        .expect("no AUTH challenge sent");
    assert!(
        frames
            .iter()
            .any(|v| v[0] == "CLOSED" && v[2].as_str().unwrap().starts_with("auth-required:")),
        "restricted REQ not refused: {frames:?}"
    );
    let auth = sign::event(
        signer,
        22242,
        now(),
        &json!([["relay", url()], ["challenge", challenge]]),
        "",
    );
    send(ws, &format!("[\"AUTH\",{}]", auth.json())).await;
    let ok = collect_until(ws, |v| v[0] == "OK").await;
    assert_eq!(ok.last().unwrap()[2], true, "AUTH rejected");
}

/// Authenticate `ws` as `signer` against a challenge the relay
/// already sent (a maybe-restricted filter stays open, so the
/// challenge may not come with a CLOSED).
async fn auth_as(ws: &mut yawc::TcpWebSocket, signer: &Keypair, challenge: &str) {
    let auth = sign::event(
        signer,
        22242,
        now(),
        &json!([["relay", url()], ["challenge", challenge]]),
        "",
    );
    send(ws, &format!("[\"AUTH\",{}]", auth.json())).await;
    let ok = collect_until(ws, |v| v[0] == "OK").await;
    assert_eq!(ok.last().unwrap()[2], true, "AUTH rejected");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip42_restricted_reads() {
    let author = key();
    let reader = key();
    let involved = sign::event(
        &author,
        4,
        now() - 5,
        &json!([["p", pubkey(&reader)]]),
        "restricted dm",
    );
    {
        let mut publisher = connect().await;
        let (ok, reason) = publish(&mut publisher, &involved).await;
        assert!(ok, "restricted publish: {reason}");
    }

    let mut ws = connect().await;
    let filter = format!("{{\"kinds\":[4],\"authors\":[\"{}\"]}}", pubkey(&author));
    authenticate(&mut ws, &reader, &filter).await;

    let frames = req(&mut ws, "s", &filter).await;
    let got = events(&frames);
    assert_eq!(got.len(), 1, "restricted event not served: {frames:?}");
    assert_eq!(got[0]["id"], involved.id().to_string());
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip70_protected_events() {
    let k = key();
    let ev = sign::event(&k, 1, now(), &json!([["-"]]), "protected");
    let mut ws = connect().await;
    send(&mut ws, &event_wire(&ev)).await;
    let frames = collect_until(&mut ws, |v| v[0] == "OK").await;
    let ok = frames.last().unwrap();
    let reason = ok[3].as_str().unwrap();
    assert!(
        ok[2] == false && reason.starts_with("auth-required:"),
        "unauthenticated protected publish: {reason}"
    );

    // The relay sent its challenge alongside the rejection.
    let challenge = frames
        .iter()
        .find(|v| v[0] == "AUTH")
        .map(|v| v[1].as_str().unwrap().to_owned())
        .expect("no AUTH challenge sent");
    let auth = sign::event(
        &k,
        22242,
        now(),
        &json!([["relay", url()], ["challenge", challenge]]),
        "",
    );
    send(&mut ws, &format!("[\"AUTH\",{}]", auth.json())).await;
    let ok = collect_until(&mut ws, |v| v[0] == "OK").await;
    assert_eq!(ok.last().unwrap()[2], true, "AUTH rejected");

    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(ok, "protected publish after AUTH: {reason}");
}

/// NIP-45: an exact count for the fresh author, union dedup over
/// overlapping filters, and `limit` ignored — all scoped to the
/// author's pubkey so parallel tests never see each other.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn count_exact_union_and_limit_ignored() {
    let k = key();
    let mut pub_ws = connect().await;
    for (kind, content) in [(1u16, "a"), (1, "b"), (3, "c")] {
        let ev = sign::event(&k, kind, now(), &json!([]), content);
        let (ok, reason) = publish(&mut pub_ws, &ev).await;
        assert!(ok, "publish: {reason}");
    }

    let mut ws = connect().await;
    let scoped = format!("{{\"kinds\":[1],\"authors\":[\"{}\"]}}", pubkey(&k));
    let body = count(&mut ws, "c", &scoped).await;
    assert_eq!(body["count"], 2, "{body}");
    assert!(body.get("approximate").is_none(), "{body}");

    // Overlapping filters count each event once: the author's 2
    // kind-1s plus their kind-3 — not 2 + 3. Both filters are
    // author-scoped so parallel tests never inflate the union.
    let wire = format!(
        "[\"COUNT\",\"d\",{{\"kinds\":[1],\"authors\":[\"{0}\"]}},{{\"authors\":[\"{0}\"]}}]",
        pubkey(&k)
    );
    send(&mut ws, &wire).await;
    let frames = collect_until(&mut ws, |v| v[0] == "COUNT").await;
    assert_eq!(frames.last().unwrap()[2]["count"], 3);

    // A filter `limit` is ignored for COUNT.
    let scoped = format!(
        "{{\"kinds\":[1],\"authors\":[\"{}\"],\"limit\":1}}",
        pubkey(&k)
    );
    assert_eq!(count(&mut ws, "e", &scoped).await["count"], 2);
}

/// NIP-45: a single-filter, single-tag-condition, single-value COUNT
/// is sketch-eligible and returns the 512-hex `hll` registers.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn count_hll_for_a_single_tag_value() {
    let reader = key();
    let mut pub_ws = connect().await;
    for _ in 0..3 {
        let ev = sign::event(&key(), 3, now(), &json!([["p", pubkey(&reader)]]), "");
        let (ok, reason) = publish(&mut pub_ws, &ev).await;
        assert!(ok, "publish: {reason}");
    }
    let mut ws = connect().await;
    let body = count(
        &mut ws,
        "h",
        &format!("{{\"#p\":[\"{}\"]}}", pubkey(&reader)),
    )
    .await;
    assert_eq!(body["count"], 3, "{body}");
    let hll = body["hll"]
        .as_str()
        .unwrap_or_else(|| panic!("hll missing: {body}"));
    assert_eq!(hll.len(), 512, "hll must be 512 hex chars: {hll}");
    assert!(hll.bytes().all(|b| b.is_ascii_hexdigit()), "{hll}");
}

/// NIP-45 + NIP-42: a fully restricted COUNT is refused
/// unauthenticated; after AUTH the involved pubkey's events count.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn count_restricted_kind_needs_auth() {
    let author = key();
    let reader = key();
    let dm = sign::event(
        &author,
        4,
        now() - 5,
        &json!([["p", pubkey(&reader)]]),
        "restricted dm",
    );
    {
        let mut publisher = connect().await;
        let (ok, reason) = publish(&mut publisher, &dm).await;
        assert!(ok, "restricted publish: {reason}");
    }

    let mut ws = connect().await;
    let filter = format!("{{\"kinds\":[4],\"authors\":[\"{}\"]}}", pubkey(&author));
    send(&mut ws, &count_wire("c", &filter)).await;
    let frames = collect_until(&mut ws, |v| v[0] == "COUNT" || v[0] == "CLOSED").await;
    let challenge = frames
        .iter()
        .find(|v| v[0] == "AUTH")
        .map(|v| v[1].as_str().unwrap().to_owned())
        .expect("no AUTH challenge sent");
    assert!(
        frames
            .iter()
            .any(|v| v[0] == "CLOSED" && v[2].as_str().unwrap().starts_with("auth-required:")),
        "restricted COUNT not refused: {frames:?}"
    );

    let auth = sign::event(
        &reader,
        22242,
        now(),
        &json!([["relay", url()], ["challenge", challenge]]),
        "",
    );
    send(&mut ws, &format!("[\"AUTH\",{}]", auth.json())).await;
    let ok = collect_until(&mut ws, |v| v[0] == "OK").await;
    assert_eq!(ok.last().unwrap()[2], true, "AUTH rejected");
    assert_eq!(count(&mut ws, "d", &filter).await["count"], 1);
}

/// NIP-62: a request to vanish (`["relay","ALL_RELAYS"]`) deletes
/// the author's older events and `p`-tagged gift wraps, keeps the
/// request itself, and blocks a later equal-or-older publish. The
/// worker sweeps in the Durable Object alarm and the native writer
/// asynchronously — the polls wait for the sweep instead of
/// assuming it.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn request_to_vanish_sweeps_and_blocks() {
    let author = key();
    let mut ws = connect().await;
    for content in ["a", "b", "c"] {
        let ev = sign::event(&author, 1, now() - 20, &json!([]), content);
        let (ok, reason) = publish(&mut ws, &ev).await;
        assert!(ok, "publish: {reason}");
    }
    let wrap = sign::event(
        &key(),
        1059,
        now() - 10,
        &json!([["p", pubkey(&author)]]),
        "gift",
    );
    let (ok, reason) = publish(&mut ws, &wrap).await;
    assert!(ok, "wrap publish: {reason}");
    let vanish = sign::event(&author, 62, now(), &json!([["relay", "ALL_RELAYS"]]), "");
    let (ok, reason) = publish(&mut ws, &vanish).await;
    assert!(ok, "vanish publish: {reason}");

    // Poll until the author's stream holds only the request and no
    // wrap `p`-tagged to them remains — the sweep is asynchronous on
    // both editions.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let author_filter = format!("{{\"authors\":[\"{}\"]}}", pubkey(&author));
    let wrap_filter = format!("{{\"#p\":[\"{}\"]}}", pubkey(&author));
    let mut round = 0;
    loop {
        round += 1;
        let sub = format!("v{round}");
        let gone = {
            let frames = req(&mut ws, &sub, &author_filter).await;
            let got = events(&frames);
            got.len() == 1 && got[0]["kind"] == 62
        } && {
            let sub = format!("w{round}");
            let frames = req(&mut ws, &sub, &wrap_filter).await;
            events(&frames).is_empty()
        };
        if gone {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "vanish sweep did not finish in 15 s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // An equal-or-older publish by the author is refused.
    let old = sign::event(&author, 1, now() - 5, &json!([]), "late");
    let (ok, reason) = publish(&mut ws, &old).await;
    assert!(!ok, "vanished author republish accepted");
    assert_eq!(reason, "blocked: request to vanish", "{reason}");
}

// NIP-86: the management RPC over HTTP POST. Mutations stay scoped to
// fresh keys and ids so parallel tests are undisturbed.

/// The fixed admin key the shared profile lists under
/// `[relay.management] admins`.
fn admin() -> Keypair {
    sign::key(9)
}

/// `Authorization: Nostr <base64>` — the NIP-98 kind-27235 event
/// covering `hashed` as its `payload` tag (pass a body the request
/// does not carry to exercise the hash check).
fn nip98(signer: &Keypair, hashed: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = faster_hex::hex_string(&sha2::Sha256::digest(hashed));
    let ev = sign::event(
        signer,
        27_235,
        now(),
        &json!([["u", url()], ["method", "POST"], ["payload", digest],]),
        "",
    );
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(ev.json())
    )
}

/// One NIP-86 `POST /`; returns (HTTP status, response body text).
async fn manage_call(body: &Value, authorization: Option<&str>) -> (u16, String) {
    let bytes = serde_json::to_vec(body).unwrap();
    let relay = url();
    let authority = relay.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let mut tcp = tokio::net::TcpStream::connect(authority).await.unwrap();
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        nosfry_core::management::CONTENT_TYPE,
        bytes.len()
    );
    if let Some(auth) = authorization {
        write!(request, "Authorization: {auth}\r\n").unwrap();
    }
    request.push_str("\r\n");
    tcp.write_all(request.as_bytes()).await.unwrap();
    tcp.write_all(&bytes).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let status: u16 = head
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let length: usize = head
        .split("\r\n")
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(str::to_owned)
        })
        .unwrap()
        .parse()
        .unwrap();
    let mut body = vec![0u8; length];
    tcp.read_exact(&mut body).await.unwrap();
    (status, String::from_utf8(body).unwrap())
}

/// An authorized NIP-86 call; asserts 200 and returns the parsed body.
async fn rpc(method: &str, params: Value) -> Value {
    let body = json!({"method": method, "params": params});
    let bytes = serde_json::to_vec(&body).unwrap();
    let (status, text) = manage_call(&body, Some(&nip98(&admin(), &bytes))).await;
    assert_eq!(status, 200, "{text}");
    serde_json::from_str(&text).unwrap()
}

/// A raw HTTP request on `/`; returns (status, head, body). `extra`
/// carries request header lines, `body` the bytes after the head.
async fn http_raw(method: &str, extra: &str, body: &[u8]) -> (u16, String, String) {
    let url = url();
    let authority = url
        .strip_prefix("ws://")
        .expect("NOSFRY_URL must use ws://")
        .trim_end_matches('/');
    let mut tcp = tokio::net::TcpStream::connect(authority).await.unwrap();
    tcp.write_all(
        format!(
            "{method} / HTTP/1.1\r\nHost: x\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    tcp.write_all(body).await.unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8(buf).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (
        head.split_ascii_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap(),
        head.to_owned(),
        body.to_owned(),
    )
}

/// CORS: a browser admin tool's preflight sees POST + Authorization
/// (the Fetch wildcard never covers it), and an unauthenticated
/// NIP-86 POST answers 401 still carrying the allow-origin header.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn cors_preflight_and_nip86() {
    let (status, head, _) = http_raw("OPTIONS", "", b"").await;
    assert_eq!(status, 204, "{head}");
    // Header name case differs across editions; compare lowered.
    let head = head.to_lowercase();
    for want in [
        "access-control-allow-origin: *",
        "access-control-allow-methods: get, post, options",
        "access-control-allow-headers: authorization, *",
        "access-control-max-age: 86400",
    ] {
        assert!(head.contains(want), "{want} missing: {head}");
    }

    let body = serde_json::to_vec(&json!({"method": "supportedmethods", "params": []})).unwrap();
    let extra = format!(
        "Content-Type: {}\r\n",
        nosfry_core::management::CONTENT_TYPE
    );
    let (status, head, _) = http_raw("POST", &extra, &body).await;
    assert_eq!(status, 401, "{head}");
    assert!(
        head.to_lowercase()
            .contains("access-control-allow-origin: *"),
        "{head}"
    );
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip86_requires_nip98() {
    let body = json!({"method": "supportedmethods", "params": []});
    let (status, text) = manage_call(&body, None).await;
    assert_eq!(status, 401, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["error"],
        "unauthorized: missing authorization header"
    );
    // A `payload` tag covering different bytes fails the hash check.
    let (status, text) = manage_call(&body, Some(&nip98(&admin(), b"other"))).await;
    assert_eq!(status, 401, "{text}");
    assert!(
        text.contains("`payload` tag does not match the body"),
        "{text}"
    );
    // A well-formed NIP-98 from a non-admin key is refused.
    let bytes = serde_json::to_vec(&body).unwrap();
    let (status, text) = manage_call(&body, Some(&nip98(&key(), &bytes))).await;
    assert_eq!(status, 401, "{text}");
    assert!(text.contains("pubkey is not an admin"), "{text}");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip86_supportedmethods() {
    let answer = rpc("supportedmethods", json!([])).await;
    let methods: Vec<&str> = answer["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(methods, nosfry_core::management::METHODS, "{answer}");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip86_ban_list_unban_pubkey() {
    let k = key();
    let mut ws = connect().await;
    let ev = sign::event(&k, 1, now(), &json!([]), "pre-ban");
    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(ok, "pre-ban publish: {reason}");

    let answer = rpc("banpubkey", json!([pubkey(&k), "conformance"])).await;
    assert_eq!(answer["result"], true, "{answer}");
    let answer = rpc("listbannedpubkeys", json!([])).await;
    assert!(
        answer["result"]
            .as_array()
            .unwrap()
            .contains(&json!({"pubkey": pubkey(&k), "reason": "conformance"})),
        "{answer}"
    );
    let ev = sign::event(&k, 1, now(), &json!([]), "while banned");
    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(
        !ok && reason == "blocked: pubkey not allowed",
        "banned publish: {reason}"
    );

    let answer = rpc("unbanpubkey", json!([pubkey(&k)])).await;
    assert_eq!(answer["result"], true, "{answer}");
    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(ok, "publish after unban: {reason}");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip86_banevent_removes_the_event() {
    let k = key();
    let ev = sign::event(&k, 1, now(), &json!([]), "to ban");
    let mut ws = connect().await;
    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(ok, "publish: {reason}");
    let id = ev.id().to_string();

    let answer = rpc("banevent", json!([id, "conformance"])).await;
    assert_eq!(answer["result"], true, "{answer}");
    let answer = rpc("listbannedevents", json!([])).await;
    assert!(
        answer["result"]
            .as_array()
            .unwrap()
            .contains(&json!({"id": id, "reason": "conformance"})),
        "{answer}"
    );
    let frames = req(&mut ws, "b", &format!("{{\"ids\":[\"{id}\"]}}")).await;
    assert!(
        events(&frames).is_empty(),
        "banned event served: {frames:?}"
    );
    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(
        !ok && reason == "blocked: event banned",
        "banned republish: {reason}"
    );
    let answer = rpc("unbanevent", json!([id])).await;
    assert_eq!(answer["result"], true, "{answer}");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip86_kind_disallow() {
    // Kind 9000 is unused by the suite, and the op persists: NIP-86
    // has no undisallow. allowkind is deliberately not exercised —
    // even a momentary non-empty allow list switches the relay to
    // allow-list mode and blocks the suite's parallel publishes (the
    // allow↔disallow exclusivity is covered by the shared store
    // moderation script).
    let answer = rpc("disallowkind", json!([9000])).await;
    assert_eq!(answer["result"], true, "{answer}");
    let answer = rpc("listdisallowedkinds", json!([])).await;
    assert!(
        answer["result"].as_array().unwrap().contains(&json!(9000)),
        "{answer}"
    );
    let ev = sign::event(&key(), 9000, now(), &json!([]), "disallowed kind");
    let mut ws = connect().await;
    let (ok, reason) = publish(&mut ws, &ev).await;
    assert!(
        !ok && reason == "blocked: kind not allowed",
        "disallowed kind publish: {reason}"
    );
    // Nothing else was touched: the allow list stays empty.
    let answer = rpc("listallowedkinds", json!([])).await;
    assert_eq!(answer["result"], json!([]), "allow list populated");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip86_block_list_unblock_ip() {
    // 192.0.2.0/24 is TEST-NET-1: it is never a real client address.
    let answer = rpc("blockip", json!(["192.0.2.1", "conformance"])).await;
    assert_eq!(answer["result"], true, "{answer}");
    let answer = rpc("listblockedips", json!([])).await;
    assert!(
        answer["result"]
            .as_array()
            .unwrap()
            .contains(&json!({"ip": "192.0.2.1", "reason": "conformance"})),
        "{answer}"
    );
    let answer = rpc("unblockip", json!(["192.0.2.1"])).await;
    assert_eq!(answer["result"], true, "{answer}");
    let answer = rpc("listblockedips", json!([])).await;
    assert_eq!(answer["result"], json!([]), "blocked ip left listed");
}

#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip86_icon_override_and_restore() {
    let answer = rpc("changerelayicon", json!(["https://icon.example/m.png"])).await;
    assert_eq!(answer["result"], true, "{answer}");
    let doc = nip11().await;
    assert_eq!(doc["icon"], "https://icon.example/m.png", "{doc}");
    // Restore: the profile sets no icon, so the override returns to
    // the empty value (absent from the document as before).
    let answer = rpc("changerelayicon", json!([""])).await;
    assert_eq!(answer["result"], true, "{answer}");
    let doc = nip11().await;
    assert_ne!(doc["icon"], "https://icon.example/m.png", "{doc}");
}

/// `["NEG-OPEN",sub,filter,"<hex>"]`.
fn neg_open_wire(id: &str, filter: &str, msg: &[u8]) -> String {
    format!(
        "[\"NEG-OPEN\",\"{id}\",{filter},\"{}\"]",
        faster_hex::hex_string(msg)
    )
}

/// `["NEG-MSG",sub,"<hex>"]`.
fn neg_msg_wire(id: &str, msg: &[u8]) -> String {
    format!("[\"NEG-MSG\",\"{id}\",\"{}\"]", faster_hex::hex_string(msg))
}

/// Hex-decode a wire payload.
fn unhex(text: &str) -> Vec<u8> {
    let mut buf = vec![0u8; text.len() / 2];
    faster_hex::hex_decode(text.as_bytes(), &mut buf).unwrap();
    buf
}

/// NIP-77: the client's `negentropy` set reconciles against the
/// relay's records — have/need report the true differences both
/// ways — then `NEG-CLOSE` ends the session and a further `NEG-MSG`
/// is answered `closed: unknown subscription`.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn negentropy_converges_and_closes() {
    use negentropy::{Id, Negentropy, NegentropyStorageVector};

    let author = key();
    let mut ws = connect().await;
    let a = sign::event(&author, 1, now() - 30, &json!([]), "a");
    let b = sign::event(&author, 1, now() - 20, &json!([]), "b");
    let c = sign::event(&author, 1, now() - 10, &json!([]), "c");
    for ev in [&a, &b, &c] {
        let (ok, reason) = publish(&mut ws, ev).await;
        assert!(ok, "publish: {reason}");
    }
    // The client's storage shares a and b, claims a phantom the
    // relay lacks, and misses c.
    let phantom = sign::event(&key(), 1, now() - 5, &json!([]), "phantom");
    let records = [
        (a.created_at(), a.id().0),
        (b.created_at(), b.id().0),
        (phantom.created_at(), phantom.id().0),
    ];
    let mut storage = NegentropyStorageVector::with_capacity(records.len());
    for (created_at, id) in records {
        storage.insert(created_at, Id::from_byte_array(id)).unwrap();
    }
    storage.seal().unwrap();
    let mut neg = Negentropy::owned(storage, 500_000).unwrap();
    let init = neg.initiate().unwrap();

    let filter = format!("{{\"authors\":[\"{}\"]}}", pubkey(&author));
    send(&mut ws, &neg_open_wire("neg", &filter, &init)).await;
    let mut have_ids = Vec::new();
    let mut need_ids = Vec::new();
    for _ in 0..16 {
        let frame = recv_json(&mut ws).await;
        if frame[0] == "AUTH" {
            continue; // a no-kinds filter may match restricted kinds
        }
        assert_eq!(frame[0], "NEG-MSG", "{frame}");
        assert_eq!(frame[1], "neg", "{frame}");
        let reply = unhex(frame[2].as_str().unwrap());
        let next = neg
            .reconcile_with_ids(&reply, &mut have_ids, &mut need_ids)
            .unwrap();
        match next {
            Some(msg) => send(&mut ws, &neg_msg_wire("neg", &msg)).await,
            None => break,
        }
    }
    let hexes = |ids: &[Id]| -> Vec<String> {
        ids.iter()
            .map(|id| faster_hex::hex_string(id.as_bytes()))
            .collect()
    };
    assert_eq!(hexes(&have_ids), [phantom.id().to_string()]);
    assert_eq!(hexes(&need_ids), [c.id().to_string()]);

    send(&mut ws, "[\"NEG-CLOSE\",\"neg\"]").await;
    send(&mut ws, &neg_msg_wire("neg", &[0x60])).await;
    let frame = recv_json(&mut ws).await;
    assert_eq!(
        frame,
        json!(["NEG-ERR", "neg", "closed: unknown subscription"]),
        "{frame}"
    );
}

/// The write-policy fixture — `policy/policy.py` on native, the
/// `nosfry-policy` service worker on Workers — keys verdicts on the
/// event's `content`: `policy:reject` → reject `blocked: test
/// policy`, `policy:reject-empty` → a bare reject (the NIP-01
/// default message), `policy:shadow` → `shadowReject "shadowed"`,
/// anything else → accept.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn write_policy_verdicts() {
    let k = key();
    let filter = format!("{{\"authors\":[\"{}\"]}}", pubkey(&k));
    let mut ws = connect().await;
    // A watcher subscribed before any publish verifies live delivery.
    let mut watcher = connect().await;
    let _ = req(&mut watcher, "watch", &filter).await;

    // reject carries the policy's own message.
    let ev = sign::event(&k, 1, now(), &json!([]), "policy:reject");
    let (ok, msg) = publish(&mut ws, &ev).await;
    assert!(!ok && msg == "blocked: test policy", "{ok} {msg}");

    // An empty msg falls back to the NIP-01 default.
    let ev = sign::event(&k, 1, now(), &json!([]), "policy:reject-empty");
    let (ok, msg) = publish(&mut ws, &ev).await;
    assert!(
        !ok && msg == "blocked: rejected by write policy",
        "{ok} {msg}"
    );

    // shadowReject acknowledges yet stores and broadcasts nothing.
    let shadow = sign::event(&k, 1, now(), &json!([]), "policy:shadow");
    let (ok, msg) = publish(&mut ws, &shadow).await;
    assert!(ok && msg == "shadowed", "{ok} {msg}");

    // An accepted event proves the watcher is live.
    let accepted = sign::event(&k, 1, now(), &json!([]), "policy:accepted");
    let (ok, msg) = publish(&mut ws, &accepted).await;
    assert!(ok && msg.is_empty(), "{ok} {msg}");

    // The watcher got the accepted event live — and never saw the
    // shadowed one before it.
    let frames = collect_until(&mut watcher, |v| {
        v[0] == "EVENT" && v[2]["id"].as_str() == Some(&accepted.id().to_string())
    })
    .await;
    for frame in &frames {
        assert_ne!(
            frame[2]["id"].as_str(),
            Some(&shadow.id().to_string()[..]),
            "shadowed event was broadcast: {frame}"
        );
    }

    // The stored set holds only the accepted event.
    let frames = req(&mut ws, "s", &filter).await;
    let got = events(&frames);
    assert_eq!(got.len(), 1, "{frames:?}");
    assert_eq!(got[0]["content"], "policy:accepted");
}

/// `[relay.filter_validation]` (enabled in the shared profile): a
/// REQ over the filter-count bound answers the same
/// `CLOSED blocked:` on both editions, and the refused REQ
/// registered nothing — the id opens a valid subscription.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn filter_validation_refuses_req() {
    let mut ws = connect().await;
    send(&mut ws, "[\"REQ\",\"fv\",{},{},{},{}]").await;
    let closed = collect_until(&mut ws, |v| v[0] == "CLOSED").await;
    assert_eq!(
        closed.last().unwrap(),
        &json!(["CLOSED", "fv", "blocked: invalid number of filters: 4"])
    );
    let frames = req(&mut ws, "fv", "{\"kinds\":[1]}").await;
    assert_eq!(frames.last().unwrap()[0], "EOSE", "{frames:?}");
}

/// NIP-59: the wrap recipient's kind-5 `e` deletion removes a stored
/// gift wrap `p`-tagged to them (the wrap's signing key is random, so
/// author-matching alone can never cover it), while a third party's
/// kind 5 does nothing and re-publication stays blocked.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn nip59_wrap_recipient_deletes() {
    let wrap_author = key();
    let recipient = key();
    let third = key();
    let wrap = sign::event(
        &wrap_author,
        1059,
        now() - 5,
        &json!([["p", pubkey(&recipient)]]),
        "wrap",
    );
    let other_wrap = sign::event(
        &wrap_author,
        1059,
        now() - 4,
        &json!([["p", pubkey(&recipient)]]),
        "wrap2",
    );
    let mut ws = connect().await;
    for ev in [&wrap, &other_wrap] {
        let (ok, reason) = publish(&mut ws, ev).await;
        assert!(ok, "wrap publish: {reason}");
    }

    // A third party's kind 5 on the other wrap deletes nothing.
    let foreign = sign::event(
        &third,
        5,
        now() - 3,
        &json!([["e", other_wrap.id().to_string()], ["k", "1059"]]),
        "",
    );
    let (ok, reason) = publish(&mut ws, &foreign).await;
    assert!(ok, "foreign kind 5: {reason}");

    // The recipient's kind 5 deletes the wrap.
    let del = sign::event(
        &recipient,
        5,
        now() - 2,
        &json!([["e", wrap.id().to_string()], ["k", "1059"]]),
        "",
    );
    let (ok, reason) = publish(&mut ws, &del).await;
    assert!(ok, "recipient kind 5: {reason}");

    // Authenticated as the recipient: the deleted wrap is gone and
    // the foreign-targeted one is still served.
    authenticate(&mut ws, &recipient, "{\"kinds\":[1059]}").await;
    let frames = req(
        &mut ws,
        "s",
        &format!("{{\"ids\":[\"{}\",\"{}\"]}}", wrap.id(), other_wrap.id()),
    )
    .await;
    let got = events(&frames);
    assert_eq!(got.len(), 1, "{frames:?}");
    assert_eq!(got[0]["id"], other_wrap.id().to_string());

    // Re-publication of the deleted wrap stays blocked.
    let (ok, reason) = publish(&mut ws, &wrap).await;
    assert!(!ok, "republished wrap accepted");
    assert!(reason.starts_with("blocked:"), "{reason}");
}

/// NIP-59: the ephemeral wrap kind 21059 is restricted like its
/// stored sibling — unauthenticated REQs are refused, and a live
/// wrap reaches only its authenticated `p` recipient.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn ephemeral_wrap_restricted_to_recipient() {
    let recipient = key();
    let other = key();
    let rp = pubkey(&recipient);

    // An unauthenticated REQ for the restricted kind is challenged
    // then refused.
    let mut ws_r = connect().await;
    let frames = req(&mut ws_r, "r", "{\"kinds\":[21059]}").await;
    let challenge = frames.iter().find(|v| v[0] == "AUTH").map_or_else(
        || panic!("no AUTH challenge: {frames:?}"),
        |v| v[1].as_str().unwrap().to_owned(),
    );
    assert!(
        frames
            .iter()
            .any(|v| v[0] == "CLOSED" && v[2].as_str().unwrap().starts_with("auth-required:")),
        "{frames:?}"
    );
    auth_as(&mut ws_r, &recipient, &challenge).await;
    send(
        &mut ws_r,
        &req_wire("w", &format!("{{\"kinds\":[21059],\"#p\":[\"{rp}\"]}}")),
    )
    .await;
    let eose = recv_json(&mut ws_r).await;
    assert_eq!(eose[0], "EOSE", "{eose}");

    // An uninvolved authenticated subscriber watches wraps plus a
    // public kind, so a later marker bounds the window.
    let mut ws_x = connect().await;
    let frames = req(&mut ws_x, "r", "{\"kinds\":[21059]}").await;
    let challenge = frames.iter().find(|v| v[0] == "AUTH").map_or_else(
        || panic!("no AUTH challenge: {frames:?}"),
        |v| v[1].as_str().unwrap().to_owned(),
    );
    auth_as(&mut ws_x, &other, &challenge).await;
    send(&mut ws_x, &req_wire("w", "{\"kinds\":[21059,1]}")).await;
    // Live events from other tests may interleave; EOSE on "w" ends
    // the window and nothing kind-21059 may leak before it.
    loop {
        let frame = recv_json(&mut ws_x).await;
        match (frame[0].as_str().unwrap(), frame[1].as_str().unwrap()) {
            ("EVENT", "w") => assert_ne!(frame[2]["kind"], 21059, "gate leak: {frame}"),
            ("EOSE", "w") => break,
            _ => {}
        }
    }

    // A live wrap to the recipient plus a public marker: ws_x must
    // see the marker but never the wrap.
    let mut ws_pub = connect().await;
    let wrap = sign::event(&key(), 21059, now(), &json!([["p", rp]]), "gift");
    let (ok, reason) = publish(&mut ws_pub, &wrap).await;
    assert!(ok, "ephemeral publish: {reason}");
    let marker = sign::event(&key(), 1, now(), &json!([]), "marker");
    let (ok, reason) = publish(&mut ws_pub, &marker).await;
    assert!(ok, "marker publish: {reason}");

    let live = recv_json(&mut ws_r).await;
    assert_eq!(live[0], "EVENT", "{live}");
    assert_eq!(live[2]["id"], wrap.id().to_string(), "{live}");

    // ws_x's stream yields only the marker; a follow-up stored REQ
    // proves delivery was settled (its EOSE is queued last).
    send(&mut ws_x, &req_wire("barrier", "{\"kinds\":[1]}")).await;
    let mut live_ids = Vec::new();
    loop {
        let frame = recv_json(&mut ws_x).await;
        match (frame[0].as_str().unwrap(), frame[1].as_str().unwrap()) {
            ("EVENT", "w") => live_ids.push(frame[2]["id"].as_str().unwrap().to_owned()),
            ("EOSE", "barrier") => break,
            _ => {}
        }
    }
    assert!(
        !live_ids.contains(&wrap.id().to_string()),
        "uninvolved reader got the wrap: {live_ids:?}"
    );
    assert!(
        live_ids.contains(&marker.id().to_string()),
        "marker never arrived: {live_ids:?}"
    );
}

/// Filters that may match a restricted kind earn an AUTH challenge
/// ahead of the operation's own frames — but still proceed (the
/// read gate hides what must stay hidden). Fully public filters get
/// no challenge.
#[tokio::test]
#[ignore = "needs NOSFRY_URL"]
async fn maybe_restricted_filters_challenge_before_output() {
    use negentropy::{Negentropy, NegentropyStorageVector};

    let recipient = key();
    let rp = pubkey(&recipient);
    // A stored wrap only `recipient` may read.
    let wrap = sign::event(&key(), 1059, now() - 5, &json!([["p", rp]]), "wrap");
    let mut ws_pub = connect().await;
    let (ok, reason) = publish(&mut ws_pub, &wrap).await;
    assert!(ok, "wrap publish: {reason}");

    // Fresh connection per check: the challenge is once per conn.
    let position = |frames: &[Value], verb: &str| frames.iter().position(|v| v[0] == verb);

    // A mixed group may match restricted kinds.
    let mut ws = connect().await;
    let one = format!("{{\"kinds\":[1],\"#p\":[\"{rp}\"]}}");
    let two = format!("{{\"kinds\":[1059],\"#p\":[\"{rp}\"]}}");
    send(&mut ws, &format!("[\"REQ\",\"a\",{one},{two}]")).await;
    let frames = collect_until(&mut ws, |v| v[0] == "EOSE" || v[0] == "CLOSED").await;
    assert_eq!(position(&frames, "AUTH"), Some(0), "{frames:?}");
    assert_eq!(
        position(&frames, "EOSE"),
        Some(frames.len() - 1),
        "{frames:?}"
    );
    assert!(
        !events(&frames).iter().any(|v| v["kind"] == 1059),
        "wrap leaked unauthenticated: {frames:?}"
    );

    // A no-kinds filter may match restricted kinds.
    let mut ws = connect().await;
    let frames = req(&mut ws, "a", &format!("{{\"#p\":[\"{rp}\"]}}")).await;
    assert_eq!(position(&frames, "AUTH"), Some(0), "{frames:?}");
    assert_eq!(frames.last().unwrap()[0], "EOSE", "{frames:?}");

    // A purely public filter is never challenged.
    let mut ws = connect().await;
    let frames = req(&mut ws, "a", "{\"kinds\":[1]}").await;
    assert!(
        !frames.iter().any(|v| v[0] == "AUTH"),
        "public REQ challenged: {frames:?}"
    );
    assert_eq!(frames.last().unwrap()[0], "EOSE", "{frames:?}");

    // COUNT gets the challenge ahead of its answer.
    let mut ws = connect().await;
    send(&mut ws, &count_wire("c", &format!("{{\"#p\":[\"{rp}\"]}}"))).await;
    let frames = collect_until(&mut ws, |v| v[0] == "COUNT" || v[0] == "CLOSED").await;
    assert_eq!(position(&frames, "AUTH"), Some(0), "{frames:?}");
    assert_eq!(frames.last().unwrap()[0], "COUNT", "{frames:?}");

    // NEG-OPEN gets the challenge ahead of the first NEG-MSG.
    let mut storage = NegentropyStorageVector::with_capacity(0);
    storage.seal().unwrap();
    let mut neg = Negentropy::owned(storage, 500_000).unwrap();
    let init = neg.initiate().unwrap();
    let mut ws = connect().await;
    send(
        &mut ws,
        &neg_open_wire("n", &format!("{{\"#p\":[\"{rp}\"]}}"), &init),
    )
    .await;
    let frames = collect_until(&mut ws, |v| v[0] == "NEG-MSG" || v[0] == "NEG-ERR").await;
    assert_eq!(position(&frames, "AUTH"), Some(0), "{frames:?}");
    assert_eq!(frames.last().unwrap()[0], "NEG-MSG", "{frames:?}");
}

/// Pass 2 (profile-alt, AUTH disabled): restricted kinds are
/// refused on write with `restricted:`, ordinary kinds publish, and
/// NIP-11 advertises neither AUTH nor gift wraps.
#[tokio::test]
#[ignore = "needs NOSFRY_URL (a profile-alt relay — run.sh pass 2)"]
async fn alt_restricted_kinds_refused_without_auth() {
    let mut ws = connect().await;
    for kind in [1059u16, 4] {
        let ev = sign::event(
            &key(),
            kind,
            now(),
            &json!([["p", pubkey(&key())]]),
            "restricted",
        );
        let (ok, reason) = publish(&mut ws, &ev).await;
        assert!(!ok, "kind {kind} accepted without AUTH");
        assert!(
            reason.starts_with("restricted:"),
            "kind {kind} reason: {reason}"
        );
    }
    let note = sign::event(&key(), 1, now(), &json!([]), "note");
    let (ok, reason) = publish(&mut ws, &note).await;
    assert!(ok, "kind 1 refused: {reason}");

    let doc = nip11().await;
    let nips: Vec<u64> = doc["supported_nips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert!(!nips.contains(&42), "NIP-42 advertised: {nips:?}");
    assert!(!nips.contains(&59), "NIP-59 advertised: {nips:?}");
}
