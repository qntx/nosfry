//! Black-box probe of a Nostr relay's handling of Marmot traffic shapes:
//! kind-445 group-message bursts, NIP-59 gift wraps behind NIP-42,
//! addressable KeyPackage (30443) slot semantics, relay lists
//! (10002/10050), NIP-40 expiration, and oversized events.
//!
//! Usage: marmot-relay-probe <ws-url> [--auth] [--only P1,P5] [--out FILE]

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RECV_TIMEOUT: Duration = Duration::from_secs(20);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).expect("getrandom");
    v
}

fn random_hex(bytes: usize) -> String {
    faster_hex::hex_string(&random_bytes(bytes))
}

fn fresh_key() -> Keypair {
    loop {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&random_bytes(32));
        if let Ok(sk) = SecretKey::from_secret_bytes(buf) {
            return Keypair::from_secret_key(&sk);
        }
    }
}

fn pubkey_hex(kp: &Keypair) -> String {
    format!("{}", kp.x_only_public_key().0)
}

fn sign_event(kp: &Keypair, kind: u16, created_at: u64, tags: &Value, content: &str) -> Value {
    let pubkey = pubkey_hex(kp);
    let preimage =
        serde_json::to_string(&json!([0, pubkey, created_at, kind, tags, content])).expect("json");
    let id = Sha256::digest(preimage.as_bytes());
    let sig = secp256k1::schnorr::sign_no_aux_rand(&id, kp);
    json!({
        "id": faster_hex::hex_string(&id),
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": faster_hex::hex_string(&sig.to_byte_array()),
    })
}

fn group_445(kp: &Keypair, group: &str, created_at: u64, content: &str) -> Value {
    sign_event(kp, 445, created_at, &json!([["h", group]]), content)
}

// ---------------------------------------------------------------- ws layer

async fn connect(url: &str) -> Result<yawc::TcpWebSocket, String> {
    let uri = url.parse().map_err(|e| format!("url parse: {e}"))?;
    yawc::WebSocket::connect(uri)
        .await
        .map_err(|e| format!("connect: {e}"))
}

async fn send_text(ws: &mut yawc::TcpWebSocket, text: &str) -> Result<(), String> {
    ws.send(yawc::Frame::text(text.to_owned()))
        .await
        .map_err(|e| format!("send: {e}"))
}

/// Text frames until `pred` matches, the peer closes, or the deadline
/// passes. Returns (frames, "matched" | "timeout" | "closed").
async fn collect(
    ws: &mut yawc::TcpWebSocket,
    pred: impl Fn(&Value) -> bool,
    timeout: Duration,
) -> (Vec<Value>, &'static str) {
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if frames.iter().any(&pred) {
            return (frames, "matched");
        }
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return (frames, "timeout"),
            Ok(None) => return (frames, "closed"),
            Ok(Some(frame)) => {
                if frame.opcode() == yawc::OpCode::Text
                    && let Ok(v) = serde_json::from_slice::<Value>(frame.payload())
                {
                    frames.push(v);
                }
            }
        }
    }
}

async fn send_event(ws: &mut yawc::TcpWebSocket, ev: &Value) -> Result<(), String> {
    send_text(ws, &json!(["EVENT", ev]).to_string()).await
}

/// Publish one event and wait for its OK. Returns (accepted, reason,
/// ended_by) — ended_by "closed"/"timeout" means no OK arrived.
async fn publish(ws: &mut yawc::TcpWebSocket, ev: &Value, timeout: Duration) -> (bool, String, &'static str) {
    let id = ev["id"].as_str().unwrap_or_default().to_owned();
    if let Err(e) = send_event(ws, ev).await {
        return (false, format!("send failed: {e}"), "send-error");
    }
    let (frames, ended) = collect(
        ws,
        |v| v[0] == "OK" && v[1].as_str() == Some(id.as_str()),
        timeout,
    )
    .await;
    for f in &frames {
        if f[0] == "OK" && f[1].as_str() == Some(id.as_str()) {
            return (
                f[2].as_bool().unwrap_or(false),
                f[3].as_str().unwrap_or_default().to_owned(),
                ended,
            );
        }
    }
    (false, format!("no OK ({ended})"), ended)
}

/// REQ and collect through the matching EOSE or CLOSED. `filters` is a
/// single filter object or an array of filter objects.
async fn req(
    ws: &mut yawc::TcpWebSocket,
    id: &str,
    filters: &Value,
    timeout: Duration,
) -> (Vec<Value>, &'static str) {
    let mut wire = vec![json!("REQ"), json!(id)];
    match filters {
        Value::Array(list) => wire.extend(list.iter().cloned()),
        f => wire.push(f.clone()),
    }
    if let Err(e) = send_text(ws, &Value::Array(wire).to_string()).await {
        return (vec![json!(["LOCAL-ERROR", e])], "send-error");
    }
    collect(
        ws,
        |v| {
            (v[0] == "EOSE" || v[0] == "CLOSED") && v[1].as_str() == Some(id)
        },
        timeout,
    )
    .await
}

fn sub_events(frames: &[Value], sub: &str) -> Vec<Value> {
    frames
        .iter()
        .filter(|v| v[0] == "EVENT" && v[1].as_str() == Some(sub))
        .map(|v| v[2].clone())
        .collect()
}

fn closed_reason(frames: &[Value], sub: &str) -> Option<String> {
    frames
        .iter()
        .find(|v| v[0] == "CLOSED" && v[1].as_str() == Some(sub))
        .and_then(|v| v[2].as_str().map(str::to_owned))
}

fn auth_challenge(frames: &[Value]) -> Option<String> {
    frames
        .iter()
        .find(|v| v[0] == "AUTH")
        .and_then(|v| v[1].as_str().map(str::to_owned))
}

/// NIP-42: authenticate `ws` as `signer` given a challenge.
async fn do_auth(ws: &mut yawc::TcpWebSocket, url: &str, signer: &Keypair, challenge: &str) -> (bool, String) {
    let ev = sign_event(
        signer,
        22242,
        now(),
        &json!([["relay", url], ["challenge", challenge]]),
        "",
    );
    if let Err(e) = send_text(ws, &json!(["AUTH", ev]).to_string()).await {
        return (false, format!("send failed: {e}"));
    }
    let (frames, ended) = collect(ws, |v| v[0] == "OK", RECV_TIMEOUT).await;
    for f in &frames {
        if f[0] == "OK" {
            return (
                f[2].as_bool().unwrap_or(false),
                f[3].as_str().unwrap_or_default().to_owned(),
            );
        }
    }
    (false, format!("no OK ({ended})"))
}

fn reason_prefix(reason: &str) -> String {
    reason.split(':').next().unwrap_or(reason).to_owned()
}

fn b64(n_bytes: usize) -> String {
    B64.encode(random_bytes(n_bytes))
}

// ---------------------------------------------------------------- probes

async fn p1_nip11(url: &str) -> Value {
    let authority = url
        .strip_prefix("ws://")
        .map(str::to_owned)
        .or_else(|| url.strip_prefix("wss://").map(str::to_owned));
    let Some(authority) = authority else {
        return json!({"error": "not a ws:// or wss:// url"});
    };
    let authority = authority.trim_end_matches('/').to_owned();
    let mut tcp = match tokio::net::TcpStream::connect(&authority).await {
        Ok(t) => t,
        Err(e) => return json!({"error": format!("tcp connect: {e}")}),
    };
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {authority}\r\nAccept: application/nostr+json\r\nUser-Agent: marmot-relay-probe\r\nConnection: close\r\n\r\n"
    );
    if tcp.write_all(req.as_bytes()).await.is_err() {
        return json!({"error": "write failed"});
    }
    let mut buf = Vec::new();
    if tokio::time::timeout(RECV_TIMEOUT, tcp.read_to_end(&mut buf))
        .await
        .is_err()
    {
        return json!({"error": "read timeout"});
    }
    let text = String::from_utf8_lossy(&buf);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return json!({"error": "no http response", "raw": text.to_string()});
    };
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok());
    match serde_json::from_str::<Value>(body) {
        Ok(doc) => json!({
            "http_status": status,
            "supported_nips": doc.get("supported_nips").cloned().unwrap_or(Value::Null),
            "limitation": doc.get("limitation").cloned().unwrap_or(Value::Null),
            "doc": doc,
        }),
        Err(e) => json!({"http_status": status, "error": format!("body not json: {e}"), "body": body}),
    }
}

/// Build the 200-event kind-445 burst payload for one mode.
fn burst_events(group: &str, created_at: u64, n: usize) -> Vec<Value> {
    (0..n)
        .map(|i| {
            let len = 100 + ((i * 7919) % 901);
            group_445(&fresh_key(), group, created_at, &b64(len))
        })
        .collect()
}

async fn p2_burst(url: &str, paced: bool) -> Value {
    let group = random_hex(32);
    let created_at = now();
    let events = burst_events(&group, created_at, 200);
    let mut ws = match connect(url).await {
        Ok(w) => w,
        Err(e) => return json!({"error": e, "group": group}),
    };
    let send_start = tokio::time::Instant::now();
    for ev in &events {
        if let Err(e) = send_event(&mut ws, ev).await {
            return json!({"error": format!("send aborted: {e}"), "group": group});
        }
        if paced {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let sent_in_ms = send_start.elapsed().as_millis() as u64;
    let ids: std::collections::BTreeSet<String> = events
        .iter()
        .map(|e| e["id"].as_str().unwrap().to_owned())
        .collect();
    // Read until every event has its OK, or the connection stalls.
    let mut frames: Vec<Value> = Vec::new();
    let mut ended = "timeout";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let oks_so_far = frames
            .iter()
            .filter(|v| v[0] == "OK" && ids.contains(v[1].as_str().unwrap_or("")))
            .count();
        if oks_so_far >= events.len() {
            ended = "matched";
            break;
        }
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => break,
            Ok(None) => {
                ended = "closed";
                break;
            }
            Ok(Some(frame)) => {
                if frame.opcode() == yawc::OpCode::Text
                    && let Ok(v) = serde_json::from_slice::<Value>(frame.payload())
                {
                    frames.push(v);
                }
            }
        }
    }
    let oks: Vec<Value> = frames
        .iter()
        .filter(|v| v[0] == "OK" && ids.contains(v[1].as_str().unwrap_or("")))
        .cloned()
        .collect();
    let mut ok_true = 0usize;
    let mut ok_false = 0usize;
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for ok in &oks {
        if ok[2].as_bool() == Some(true) {
            ok_true += 1;
        } else {
            ok_false += 1;
            *reasons
                .entry(reason_prefix(ok[3].as_str().unwrap_or("")))
                .or_default() += 1;
        }
    }
    let notices: Vec<String> = frames
        .iter()
        .filter(|v| v[0] == "NOTICE")
        .filter_map(|v| v[1].as_str().map(str::to_owned))
        .collect();
    json!({
        "group": group,
        "created_at": created_at,
        "paced_50_per_s": paced,
        "sent": events.len(),
        "sent_in_ms": sent_in_ms,
        "ok_true": ok_true,
        "ok_false": ok_false,
        "ok_missing": events.len() - oks.len(),
        "false_reasons_by_prefix": reasons,
        "notices": notices,
        "collection_ended": ended,
    })
}

/// Canonical order check: created_at descending, ties by id ascending.
fn canonical_order(events: &[Value]) -> Vec<String> {
    let mut items: Vec<(u64, String)> = events
        .iter()
        .map(|e| {
            (
                e["created_at"].as_u64().unwrap_or(0),
                e["id"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    items.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    items.into_iter().map(|(_, id)| id).collect()
}

fn event_ids(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .map(|e| e["id"].as_str().unwrap_or("").to_owned())
        .collect()
}

async fn p3_stored(url: &str, group: &str, burst_created_at: u64) -> Value {
    let mut ws = match connect(url).await {
        Ok(w) => w,
        Err(e) => return json!({"error": e}),
    };
    let filter = |extra: Value| {
        let mut f = json!({"kinds": [445], "#h": [group]});
        for (k, v) in extra.as_object().unwrap() {
            f[k] = v.clone();
        }
        f
    };
    // REQ 1: limit 500
    let (f1, e1) = req(&mut ws, "a", &filter(json!({"limit": 500})), RECV_TIMEOUT).await;
    let evs1 = sub_events(&f1, "a");
    let order_ok = event_ids(&evs1) == canonical_order(&evs1);
    // REQ 2: repeat → identical order?
    let (f2, _) = req(&mut ws, "b", &filter(json!({"limit": 500})), RECV_TIMEOUT).await;
    let evs2 = sub_events(&f2, "b");
    let repeat_identical = event_ids(&evs1) == event_ids(&evs2);
    // REQ 3: limit 100 → which 100 of the canonical order
    let (f3, _) = req(&mut ws, "c", &filter(json!({"limit": 100})), RECV_TIMEOUT).await;
    let evs3 = sub_events(&f3, "c");
    let first_100_of_full: Vec<String> = event_ids(&evs1).into_iter().take(100).collect();
    let limit100_is_first = event_ids(&evs3) == first_100_of_full;
    let last_100_of_full: Vec<String> = event_ids(&sub_events(&f1, "a"))
        .into_iter()
        .skip(evs1.len().saturating_sub(100))
        .collect();
    let limit100_is_last = event_ids(&evs3) == last_100_of_full;
    // REQ 4: since = burst created_at → inclusive?
    let (f4, _) = req(
        &mut ws,
        "d",
        &filter(json!({"limit": 500, "since": burst_created_at})),
        RECV_TIMEOUT,
    )
    .await;
    let evs4 = sub_events(&f4, "d");
    let all_at_t = evs1
        .iter()
        .all(|e| e["created_at"].as_u64() == Some(burst_created_at));
    json!({
        "group": group,
        "burst_created_at": burst_created_at,
        "count_limit500": evs1.len(),
        "ended": e1,
        "closed_reason": closed_reason(&f1, "a"),
        "all_events_at_burst_created_at": all_at_t,
        "order_created_at_desc_id_asc": order_ok,
        "repeat_req_identical_order": repeat_identical,
        "limit100_count": evs3.len(),
        "limit100_matches_first_100_of_full_order": limit100_is_first,
        "limit100_matches_last_100_of_full_order": limit100_is_last,
        "limit100_first_id": evs3.first().and_then(|e| e["id"].as_str().map(str::to_owned)),
        "limit100_last_id": evs3.last().and_then(|e| e["id"].as_str().map(str::to_owned)),
        "since_eq_created_at_count": evs4.len(),
        "since_inclusive": evs4.len() == evs1.len() && all_at_t,
    })
}

async fn p4_live(url: &str) -> Value {
    let group = random_hex(32);
    let mut sub_ws = match connect(url).await {
        Ok(w) => w,
        Err(e) => return json!({"error": e}),
    };
    // Barrier: EOSE on an empty group.
    let (_, eose) = req(
        &mut sub_ws,
        "live",
        &json!({"kinds": [445], "#h": [group]}),
        RECV_TIMEOUT,
    )
    .await;
    if eose != "matched" {
        return json!({"error": format!("no EOSE ({eose})"), "group": group});
    }
    let mut pub_ws = match connect(url).await {
        Ok(w) => w,
        Err(e) => return json!({"error": e, "group": group}),
    };
    let created_at = now();
    let events = burst_events(&group, created_at, 100);
    for ev in &events {
        if let Err(e) = send_event(&mut pub_ws, ev).await {
            return json!({"error": format!("publish send: {e}"), "group": group});
        }
    }
    // Drain the subscriber for a fixed window, then count.
    let mut got: Vec<Value> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got.len() < events.len() {
        let (frames, ended) = collect(
            &mut sub_ws,
            |v| v[0] == "EVENT" && v[1].as_str() == Some("live"),
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await;
        got.extend(sub_events(&frames, "live"));
        if ended != "matched" {
            break;
        }
    }
    let order_ok = event_ids(&got) == canonical_order(&got);
    json!({
        "group": group,
        "published": events.len(),
        "received_live": got.len(),
        "live_order_created_at_desc_id_asc": order_ok,
    })
}

async fn p5_gift_wrap(url: &str, auth: bool, known_group: Option<&str>) -> Value {
    let recipient = fresh_key();
    let r_hex = pubkey_hex(&recipient);
    let wrap = sign_event(
        &fresh_key(),
        1059,
        now().saturating_sub(36 * 3600),
        &json!([["p", r_hex]]),
        &b64(200),
    );
    let mut ws = match connect(url).await {
        Ok(w) => w,
        Err(e) => return json!({"error": e}),
    };
    let (accepted, reason, _) = publish(&mut ws, &wrap, RECV_TIMEOUT).await;
    // Unauthenticated restricted REQ.
    let filter = json!({"kinds": [1059], "#p": [r_hex]});
    let (f, _) = req(&mut ws, "w", &filter, RECV_TIMEOUT).await;
    let unauth = json!({
        "events": sub_events(&f, "w").len(),
        "closed": closed_reason(&f, "w"),
        "auth_frame": auth_challenge(&f).is_some(),
        "frames": f,
    });
    // Mixed REQ: one restricted filter + one unrestricted filter.
    let mut mixed = Value::Null;
    if let Some(g) = known_group {
        let (mf, _) = req(
            &mut ws,
            "m",
            &json!([
                {"kinds": [1059], "#p": [r_hex]},
                {"kinds": [445], "#h": [g], "limit": 3}
            ]),
            RECV_TIMEOUT,
        )
        .await;
        let kinds: Vec<u16> = sub_events(&mf, "m")
            .iter()
            .filter_map(|e| e["kind"].as_u64().map(|k| k as u16))
            .collect();
        mixed = json!({
            "events_served": kinds.len(),
            "served_kinds": kinds,
            "closed": closed_reason(&mf, "m"),
            "auth_frame": auth_challenge(&mf).is_some(),
        });
    }
    let mut authed = Value::Null;
    if auth {
        // AUTH as the wrap's recipient.
        let mut ws2 = match connect(url).await {
            Ok(w) => w,
            Err(e) => return json!({"error": e, "publish": [accepted, reason], "unauth_req": unauth, "mixed_req": mixed}),
        };
        let (f2, _) = req(&mut ws2, "w", &filter, RECV_TIMEOUT).await;
        let challenge = auth_challenge(&f2);
        let mut as_recipient = json!({"challenge": challenge});
        if let Some(ch) = &challenge {
            let (ok, msg) = do_auth(&mut ws2, url, &recipient, ch).await;
            let (f3, _) = req(&mut ws2, "w2", &filter, RECV_TIMEOUT).await;
            as_recipient = json!({
                "auth_ok": ok,
                "auth_reason": msg,
                "events": sub_events(&f3, "w2").len(),
                "closed": closed_reason(&f3, "w2"),
            });
        }
        // AUTH as a stranger (uninvolved key).
        let stranger = fresh_key();
        let mut ws3 = match connect(url).await {
            Ok(w) => w,
            Err(e) => return json!({"error": e}),
        };
        let (f4, _) = req(&mut ws3, "w", &filter, RECV_TIMEOUT).await;
        let challenge2 = auth_challenge(&f4);
        let mut as_stranger = json!({"challenge": challenge2});
        if let Some(ch) = &challenge2 {
            let (ok, msg) = do_auth(&mut ws3, url, &stranger, ch).await;
            let (f5, _) = req(&mut ws3, "w2", &filter, RECV_TIMEOUT).await;
            as_stranger = json!({
                "auth_ok": ok,
                "auth_reason": msg,
                "events": sub_events(&f5, "w2").len(),
                "closed": closed_reason(&f5, "w2"),
            });
        }
        authed = json!({"as_recipient": as_recipient, "as_stranger": as_stranger});
    }
    json!({
        "recipient": r_hex,
        "created_at_age_hours": 36,
        "publish_ok": accepted,
        "publish_reason": reason,
        "unauth_req": unauth,
        "mixed_req": mixed,
        "auth": authed,
    })
}

async fn p6_key_package(url: &str) -> Value {
    let author = fresh_key();
    let a_hex = pubkey_hex(&author);
    let t = now();
    let mut ws = match connect(url).await {
        Ok(w) => w,
        Err(e) => return json!({"error": e}),
    };
    async fn query(
        ws: &mut yawc::TcpWebSocket,
        a_hex: &str,
        sub: &'static str,
    ) -> Vec<Value> {
        let (f, _) = req(
            ws,
            sub,
            &json!({"kinds": [30443], "authors": [a_hex]}),
            RECV_TIMEOUT,
        )
        .await;
        sub_events(&f, sub)
    }
    let mut out = json!({"author": a_hex, "t0": t});

    // Slot replace by newer created_at.
    let e1 = sign_event(&author, 30443, t, &json!([["d", "pd1"]]), "kp-t");
    let e2 = sign_event(&author, 30443, t + 1, &json!([["d", "pd1"]]), "kp-t+1");
    let (o1, r1, _) = publish(&mut ws, &e1, RECV_TIMEOUT).await;
    let (o2, r2, _) = publish(&mut ws, &e2, RECV_TIMEOUT).await;
    let slot = query(&mut ws, &a_hex, "q1").await;
    out["replace"] = json!({
        "ok": [o1, o2], "reasons": [r1, r2],
        "served_ids": event_ids(&slot),
        "only_newer_served": slot.len() == 1 && slot[0]["id"] == e2["id"],
    });

    // Same-created_at pair in one slot: which survives.
    let pair = |d: &str| {
        let a = sign_event(&author, 30443, t + 2, &json!([["d", d]]), &format!("kp-{d}-a"));
        let b = sign_event(&author, 30443, t + 2, &json!([["d", d]]), &format!("kp-{d}-b"));
        (a, b)
    };
    // d2: send higher id first; d3: send lower id first.
    let (d2a, d2b) = pair("pd2");
    let (hi2, lo2) = if d2a["id"].as_str().unwrap() < d2b["id"].as_str().unwrap() {
        (d2b.clone(), d2a.clone())
    } else {
        (d2a.clone(), d2b.clone())
    };
    let (hi2o, hi2r, _) = publish(&mut ws, &hi2, RECV_TIMEOUT).await;
    let (lo2o, lo2r, _) = publish(&mut ws, &lo2, RECV_TIMEOUT).await;
    let (d3a, d3b) = pair("pd3");
    let (hi3, lo3) = if d3a["id"].as_str().unwrap() < d3b["id"].as_str().unwrap() {
        (d3b.clone(), d3a.clone())
    } else {
        (d3a.clone(), d3b.clone())
    };
    let (lo3o, lo3r, _) = publish(&mut ws, &lo3, RECV_TIMEOUT).await;
    let (hi3o, hi3r, _) = publish(&mut ws, &hi3, RECV_TIMEOUT).await;
    let slot2 = query(&mut ws, &a_hex, "q2").await;
    let served2: Vec<Value> = slot2
        .iter()
        .filter(|e| {
            e["tags"].as_array().is_some_and(|t| {
                t.iter()
                    .any(|tag| tag[1].as_str() == Some("pd2") || tag[1].as_str() == Some("pd3"))
            })
        })
        .cloned()
        .collect();
    out["tie"] = json!({
        "pd2_send_order": ["higher-id", "lower-id"],
        "pd2_ok": [[hi2o, hi2r], [lo2o, lo2r]],
        "pd3_send_order": ["lower-id", "higher-id"],
        "pd3_ok": [[lo3o, lo3r], [hi3o, hi3r]],
        "served": served2.iter().map(|e| json!({"id": e["id"], "d": e["tags"][0][1], "content": e["content"]})).collect::<Vec<_>>(),
        "lower_id_survives": served2.iter().all(|e| {
            let d = e["tags"][0][1].as_str().unwrap_or("");
            let lo = if d == "pd2" { &lo2 } else { &lo3 };
            e["id"] == lo["id"]
        }),
    });

    // kind 5 slot deletion (a + k).
    let del = sign_event(
        &author,
        5,
        t + 3,
        &json!([["a", format!("30443:{a_hex}:pd1")], ["k", "30443"]]),
        "del-slot",
    );
    let (dok, dreason, _) = publish(&mut ws, &del, RECV_TIMEOUT).await;
    let slot3 = query(&mut ws, &a_hex, "q3").await;
    let pd1_gone = !slot3.iter().any(|e| {
        e["tags"].as_array().is_some_and(|t| t.iter().any(|tag| tag[1].as_str() == Some("pd1")))
    });
    out["slot_delete"] = json!({
        "ok": dok, "reason": dreason, "pd1_served_after": !pd1_gone,
        "served_ids": event_ids(&slot3),
    });

    // Re-publish into the deleted slot at a newer created_at.
    let e3 = sign_event(&author, 30443, t + 4, &json!([["d", "pd1"]]), "kp-t+4");
    let (o3, r3, _) = publish(&mut ws, &e3, RECV_TIMEOUT).await;
    let slot4 = query(&mut ws, &a_hex, "q4").await;
    let e3_served = slot4.iter().any(|e| e["id"] == e3["id"]);
    out["republish_after_delete"] = json!({
        "ok": o3, "reason": r3, "served": e3_served,
    });

    // kind 5 single-event deletion (e + k) of the re-published event.
    let del2 = sign_event(
        &author,
        5,
        t + 5,
        &json!([["e", e3["id"]], ["k", "30443"]]),
        "del-one",
    );
    let (d2ok, d2reason, _) = publish(&mut ws, &del2, RECV_TIMEOUT).await;
    let slot5 = query(&mut ws, &a_hex, "q5").await;
    let e3_gone = !slot5.iter().any(|e| e["id"] == e3["id"]);
    out["event_delete"] = json!({
        "ok": d2ok, "reason": d2reason, "e3_served_after": !e3_gone,
    });
    out
}

async fn p7_relay_lists(url: &str) -> Value {
    let author = fresh_key();
    let t = now();
    let mut ws = match connect(url).await {
        Ok(w) => w,
        Err(e) => return json!({"error": e}),
    };
    let mut out = json!({});
    for (kind, tag) in [(10002u16, "r"), (10050u16, "r")] {
        let e1 = sign_event(&author, kind, t, &json!([[tag, "wss://old.example"]]), "");
        let e2 = sign_event(&author, kind, t + 1, &json!([[tag, "wss://new.example"]]), "");
        publish(&mut ws, &e1, RECV_TIMEOUT).await;
        publish(&mut ws, &e2, RECV_TIMEOUT).await;
        let sub = format!("k{kind}");
        let (f, _) = req(
            &mut ws,
            &sub,
            &json!({"kinds": [kind], "authors": [pubkey_hex(&author)]}),
            RECV_TIMEOUT,
        )
        .await;
        let evs = sub_events(&f, &sub);
        out[kind.to_string()] = json!({
            "served": evs.len(),
            "served_ids": event_ids(&evs),
            "only_newest_served": evs.len() == 1 && evs[0]["id"] == e2["id"],
        });
    }
    out
}

async fn p8_expiration(url: &str) -> Value {
    let t = now();
    let g = random_hex(32);
    let mut ws = match connect(url).await {
        Ok(w) => w,
        Err(e) => return json!({"error": e}),
    };
    let expired = sign_event(
        &fresh_key(),
        445,
        t,
        &json!([["h", g], ["expiration", (t - 10).to_string()]]),
        "expired-payload",
    );
    let soon = sign_event(
        &fresh_key(),
        445,
        t,
        &json!([["h", g], ["expiration", (t + 3).to_string()]]),
        "expires-soon",
    );
    let (o1, r1, _) = publish(&mut ws, &expired, RECV_TIMEOUT).await;
    let (o2, r2, _) = publish(&mut ws, &soon, RECV_TIMEOUT).await;
    let filter = json!({"kinds": [445], "#h": [g]});
    let (f1, _) = req(&mut ws, "x", &filter, RECV_TIMEOUT).await;
    let served_immediately = sub_events(&f1, "x").len();
    tokio::time::sleep(Duration::from_secs(6)).await;
    let (f2, _) = req(&mut ws, "y", &filter, RECV_TIMEOUT).await;
    let served_after = sub_events(&f2, "y").len();
    json!({
        "expired_at_publish_ok": o1,
        "expired_at_publish_reason": r1,
        "expiring_soon_ok": o2,
        "expiring_soon_reason": r2,
        "served_immediately": served_immediately,
        "served_after_6s": served_after,
    })
}

/// Build an event of `kind` whose serialized JSON is ~`target` bytes.
fn padded_event(kind: u16, target: usize) -> Value {
    let kp = fresh_key();
    let tag = if kind == 1059 {
        json!(["p", pubkey_hex(&fresh_key())])
    } else {
        json!(["h", random_hex(32)])
    };
    let t = now();
    let probe = sign_event(&kp, kind, t, &json!([tag.clone()]), "");
    let overhead = serde_json::to_string(&probe).unwrap().len();
    // Content is base64 (4 chars per 3 bytes).
    let content_chars = target.saturating_sub(overhead + 8) / 4 * 4;
    let ev = sign_event(
        &kp,
        kind,
        t,
        &json!([tag]),
        &b64(content_chars * 3 / 4),
    );
    ev
}

async fn p9_sizes(url: &str) -> Value {
    let targets = [60 * 1024, 70 * 1024, 120 * 1024, 200 * 1024, 2_000_000, 2_097_152];
    let mut out = json!({});
    for kind in [445u16, 1059u16] {
        let mut rows = Vec::new();
        for target in targets {
            let ev = padded_event(kind, target);
            let wire = json!(["EVENT", ev]).to_string();
            let wire_len = wire.len();
            let mut ws = match connect(url).await {
                Ok(w) => w,
                Err(e) => {
                    rows.push(json!({"target": target, "wire_bytes": wire_len, "outcome": format!("connect failed: {e}")}));
                    continue;
                }
            };
            let send_res = send_text(&mut ws, &wire).await;
            let outcome = match send_res {
                Err(e) => format!("send failed: {e}"),
                Ok(()) => {
                    let (frames, ended) = collect(&mut ws, |_| true, Duration::from_secs(15)).await;
                    if let Some(f) = frames.first() {
                        if f[0] == "OK" {
                            format!("OK {} {}", f[2], f[3].as_str().unwrap_or(""))
                        } else {
                            format!("{}: {}", f[0], f)
                        }
                    } else {
                        format!("no response ({ended})")
                    }
                }
            };
            rows.push(json!({"target": target, "wire_bytes": wire_len, "outcome": outcome}));
        }
        out[kind.to_string()] = Value::Array(rows);
    }
    out
}

// ---------------------------------------------------------------- main

fn parse_args() -> (String, bool, Vec<String>, Option<String>) {
    let mut url = None;
    let mut auth = false;
    let mut only: Vec<String> = Vec::new();
    let mut out = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--auth" => auth = true,
            "--only" => {
                if let Some(v) = it.next() {
                    only = v.split(',').map(|s| s.trim().to_uppercase()).collect();
                }
            }
            "--out" => out = it.next(),
            _ if a.starts_with("--only=") => {
                only = a[7..].split(',').map(|s| s.trim().to_uppercase()).collect();
            }
            _ if a.starts_with("--out=") => out = Some(a[6..].to_owned()),
            _ if url.is_none() => url = Some(a),
            _ => {}
        }
    }
    (
        url.expect("usage: marmot-relay-probe <ws-url> [--auth] [--only P1,P5] [--out FILE]"),
        auth,
        only,
        out,
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let (url, auth, only, out_path) = parse_args();
    let run = |name: &str| only.is_empty() || only.iter().any(|o| o == name);
    let mut results = json!({
        "relay": url.trim_end_matches('/'),
        "auth_flag": auth,
        "started_at_unix": now(),
        "probes": {},
    });
    let mut table: Vec<(String, String)> = Vec::new();
    let mut record = |name: &str, value: Value, summary: String| {
        results["probes"][name] = value;
        table.push((name.to_owned(), summary));
    };

    if run("P1") {
        eprintln!("P1 nip11…");
        let r = p1_nip11(&url).await;
        let summary = format!(
            "nips={} max_limit={} auth_required={} restricted_writes={}",
            r["supported_nips"],
            r["limitation"]["max_limit"],
            r["limitation"]["auth_required"],
            r["limitation"]["restricted_writes"]
        );
        record("P1", r, summary);
    }

    let mut group_a: Option<String> = None;
    let mut group_b: Option<String> = None;
    let mut burst_t: u64 = 0;
    if run("P2") {
        eprintln!("P2a burst back-to-back…");
        let ra = p2_burst(&url, false).await;
        group_a = ra["group"].as_str().map(str::to_owned);
        burst_t = ra["created_at"].as_u64().unwrap_or(0);
        record(
            "P2a",
            ra.clone(),
            format!(
                "ok={} false={} missing={} reasons={}",
                ra["ok_true"], ra["ok_false"], ra["ok_missing"], ra["false_reasons_by_prefix"]
            ),
        );
        eprintln!("P2b paced 50/s…");
        let rb = p2_burst(&url, true).await;
        group_b = rb["group"].as_str().map(str::to_owned);
        record(
            "P2b",
            rb.clone(),
            format!(
                "ok={} false={} missing={} reasons={}",
                rb["ok_true"], rb["ok_false"], rb["ok_missing"], rb["false_reasons_by_prefix"]
            ),
        );
    }

    if run("P3") {
        eprintln!("P3 stored queries…");
        let mut r = json!({});
        if let Some(g) = &group_a {
            r["burst_group"] = p3_stored(&url, g, burst_t).await;
        }
        if let Some(g) = &group_b {
            r["paced_group"] = p3_stored(&url, g, burst_t).await;
        }
        if r.as_object().unwrap().is_empty() {
            // P2 was skipped: probe a fresh group of our own.
            let g = random_hex(32);
            let mut ws = connect(&url).await.expect("connect");
            for ev in burst_events(&g, now(), 50) {
                let _ = publish(&mut ws, &ev, RECV_TIMEOUT).await;
            }
            r["fresh_group"] = p3_stored(&url, &g, now()).await;
        }
        record("P3", r.clone(), format!("{}", serde_json::to_string_pretty(&r).unwrap()));
    }

    if run("P4") {
        eprintln!("P4 live subscription…");
        let r = p4_live(&url).await;
        record(
            "P4",
            r.clone(),
            format!("live={}/{} ordered={}", r["received_live"], r["published"], r["live_order_created_at_desc_id_asc"]),
        );
    }

    if run("P5") {
        eprintln!("P5 gift wrap…");
        let r = p5_gift_wrap(&url, auth, group_a.as_deref()).await;
        record("P5", r.clone(), format!("unauth_closed={:?}", r["unauth_req"]["closed"]));
    }

    if run("P6") {
        eprintln!("P6 keypackage slot…");
        let r = p6_key_package(&url).await;
        record("P6", r.clone(), format!("tie_lower_id={}", r["tie"]["lower_id_survives"]));
    }

    if run("P7") {
        eprintln!("P7 relay lists…");
        let r = p7_relay_lists(&url).await;
        record("P7", r.clone(), format!("10002={} 10050={}", r["10002"]["only_newest_served"], r["10050"]["only_newest_served"]));
    }

    if run("P8") {
        eprintln!("P8 expiration…");
        let r = p8_expiration(&url).await;
        record(
            "P8",
            r.clone(),
            format!(
                "expired_ok={} soon_ok={} served0={} served6s={}",
                r["expired_at_publish_ok"], r["expiring_soon_ok"], r["served_immediately"], r["served_after_6s"]
            ),
        );
    }

    if run("P9") {
        eprintln!("P9 sizes…");
        let r = p9_sizes(&url).await;
        record("P9", r.clone(), "see json".to_owned());
    }

    println!("\n==== probe results for {} ====", url);
    for (name, summary) in &table {
        println!("{name}: {summary}");
    }
    let path = out_path.unwrap_or_else(|| {
        format!(
            "probe-{}.json",
            url.trim_start_matches("ws://")
                .trim_start_matches("wss://")
                .replace(['/', ':', '.'], "-")
        )
    });
    std::fs::write(&path, serde_json::to_string_pretty(&results).unwrap()).expect("write json");
    println!("wrote {path}");
}
