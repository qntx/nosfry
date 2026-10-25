//! In-process relay integration tests over real websockets.

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

use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::{Relay, close_wire, count_wire, event_wire, key, recv_text, req_wire, send_text};
use futures_util::{SinkExt, StreamExt};
use nosfry_core::event::Event;
use serde_json::{Value, json};
use sha2::Digest as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const T: Duration = Duration::from_secs(15);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn json(frame: &str) -> Value {
    serde_json::from_str(frame).unwrap()
}

#[tokio::test]
async fn publish_ok_and_duplicate() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let ev = common::event(&key(1), 1, now(), &json!([]), "hi");
    send_text(&mut ws, &event_wire(&ev)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(
        ok[1].as_str().unwrap(),
        json(ev.json())["id"].as_str().unwrap()
    );
    assert_eq!(ok[2], true);

    send_text(&mut ws, &event_wire(&ev)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], true);
    assert!(ok[3].as_str().unwrap().starts_with("duplicate:"));
    relay.stop().await;
}

#[tokio::test]
async fn publish_bad_signature_and_time_window() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;

    // Corrupt one hex nibble inside the signature, JSON stays valid.
    let ev = common::event(&key(2), 1, now(), &json!([]), "x");
    let mut doc = json(ev.json());
    let sig = doc["sig"].as_str().unwrap();
    let last = sig.chars().last().unwrap();
    let flipped = if last == '0' { '1' } else { '0' };
    doc["sig"] = json!(format!("{}{}", &sig[..sig.len() - 1], flipped));
    send_text(
        &mut ws,
        &format!("[\"EVENT\",{}]", serde_json::to_string(&doc).unwrap()),
    )
    .await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], false);
    assert!(ok[3].as_str().unwrap().starts_with("invalid:"));

    // Far-future event.
    let future = common::event(&key(2), 1, now() + 60 * 60 * 24, &json!([]), "f");
    send_text(&mut ws, &event_wire(&future)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], false);
    assert!(ok[3].as_str().unwrap().starts_with("invalid:"));
    relay.stop().await;
}

#[tokio::test]
async fn req_returns_stored_events_then_eose() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let base = now() - 100;
    let mut events = Vec::new();
    for i in 0..5u64 {
        let ev = common::event(&key(3), 1, base + i, &json!([]), &format!("e{i}"));
        send_text(&mut ws, &event_wire(&ev)).await;
        let _ok = recv_text(&mut ws, T).await;
        events.push(ev);
    }
    send_text(&mut ws, &req_wire("s1", "{\"kinds\":[1]}")).await;
    let mut got = Vec::new();
    loop {
        let frame = json(&recv_text(&mut ws, T).await);
        match frame[0].as_str().unwrap() {
            "EVENT" => got.push(frame[2]["id"].as_str().unwrap().to_owned()),
            "EOSE" => break,
            other => panic!("unexpected frame {other}"),
        }
    }
    // Newest first.
    let want: Vec<_> = events.iter().rev().map(|e| e.json().to_owned()).collect();
    let want_ids: Vec<String> = want
        .iter()
        .map(|j| json(j)["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(got, want_ids);
    relay.stop().await;
}

/// A 500-event stored result arrives complete and in newest-first
/// order before EOSE through the reader's chunked `Out::Frames` path.
#[tokio::test]
async fn req_500_events_complete_in_order_before_eose() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let base = now() - 10_000;
    let mut events = Vec::new();
    for i in 0..500u64 {
        let ev = common::event(&key(5), 1, base + i, &json!([]), &format!("e{i}"));
        send_text(&mut ws, &event_wire(&ev)).await;
        let _ok = recv_text(&mut ws, T).await;
        events.push(ev);
    }
    send_text(&mut ws, &req_wire("s", "{\"kinds\":[1],\"limit\":500}")).await;
    let mut got = Vec::new();
    loop {
        let frame = json(&recv_text(&mut ws, T).await);
        match frame[0].as_str().unwrap() {
            "EVENT" => got.push(frame[2]["id"].as_str().unwrap().to_owned()),
            "EOSE" => break,
            other => panic!("unexpected frame {other}"),
        }
    }
    let want: Vec<String> = events
        .iter()
        .rev()
        .map(|e| json(e.json())["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(got, want);
    relay.stop().await;
}

#[tokio::test]
async fn req_limit_and_multi_filter_dedup() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let base = now() - 100;
    for i in 0..10u64 {
        let ev = common::event(&key(4), 1, base + i, &json!([]), "x");
        send_text(&mut ws, &event_wire(&ev)).await;
        let _ok = recv_text(&mut ws, T).await;
    }
    send_text(
        &mut ws,
        &req_wire(
            "s",
            "{\"kinds\":[1],\"limit\":3},{\"kinds\":[1],\"limit\":3}",
        ),
    )
    .await;
    let mut got = std::collections::HashSet::new();
    loop {
        let frame = json(&recv_text(&mut ws, T).await);
        match frame[0].as_str().unwrap() {
            "EVENT" => {
                got.insert(frame[2]["id"].as_str().unwrap().to_owned());
            }
            "EOSE" => break,
            other => panic!("unexpected {other}"),
        }
    }
    // Two identical filters dedup to the first one's 3 events.
    assert_eq!(got.len(), 3);
    relay.stop().await;
}

#[tokio::test]
async fn live_event_after_eose_and_close_stops() {
    let relay = Relay::start().await;
    let mut sub_ws = relay.connect().await;
    let mut pub_ws = relay.connect().await;
    send_text(&mut sub_ws, &req_wire("s", "{\"kinds\":[1]}")).await;
    loop {
        let frame = json(&recv_text(&mut sub_ws, T).await);
        if frame[0] == "EOSE" {
            break;
        }
    }
    let ev = common::event(&key(5), 1, now(), &json!([]), "live");
    send_text(&mut pub_ws, &event_wire(&ev)).await;
    let _ok = recv_text(&mut pub_ws, T).await;
    let frame = json(&recv_text(&mut sub_ws, T).await);
    assert_eq!(frame[0], "EVENT");
    assert_eq!(
        frame[2]["id"],
        json(ev.json()).get("id").unwrap().as_str().unwrap()
    );

    // CLOSE stops delivery. There is no cross-connection ordering, so
    // barrier on sub_ws first: inbound frames are processed in order,
    // and the EOSE for the impossible filter proves the CLOSE was
    // applied in the session before the barrier's scan ran.
    send_text(&mut sub_ws, &close_wire("s")).await;
    send_text(&mut sub_ws, &req_wire("barrier", "{\"ids\":[]}")).await;
    loop {
        let frame = json(&recv_text(&mut sub_ws, T).await);
        if frame[0] == "EOSE" && frame[1] == "barrier" {
            break;
        }
    }
    let ev2 = common::event(&key(5), 1, now(), &json!([]), "live2");
    send_text(&mut pub_ws, &event_wire(&ev2)).await;
    let _ok = recv_text(&mut pub_ws, T).await;
    let frame = tokio::time::timeout(Duration::from_millis(800), sub_ws.next()).await;
    if let Ok(Some(f)) = frame
        && f.opcode() == yawc::OpCode::Text
    {
        panic!("unexpected delivery after CLOSE: {:?}", f.payload());
    }
    relay.stop().await;
}

/// Read-your-writes: the writer queues each batch on every shard
/// before pushing the publisher's `OK`, so a `REQ` sent right after
/// `OK` must find the event in its snapshot and emit it before `EOSE`.
#[tokio::test]
async fn req_after_ok_sees_event_before_eose() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    for i in 0..200u32 {
        let ev = common::event(&key(10), 1, now(), &json!([]), &format!("ryw{i}"));
        let id = json(ev.json())["id"].as_str().unwrap().to_owned();
        send_text(&mut ws, &event_wire(&ev)).await;
        let ok = json(&recv_text(&mut ws, T).await);
        assert_eq!(ok[0], "OK");
        assert_eq!(ok[2], true);
        let sub = format!("s{i}");
        send_text(&mut ws, &req_wire(&sub, &format!("{{\"ids\":[\"{id}\"]}}"))).await;
        let frame = json(&recv_text(&mut ws, T).await);
        assert_eq!(frame[0], "EVENT", "iteration {i}: event must precede EOSE");
        assert_eq!(frame[2]["id"], id);
        assert_eq!(json(&recv_text(&mut ws, T).await)[0], "EOSE");
    }
    relay.stop().await;
}

#[tokio::test]
async fn re_req_same_id_replaces_generation() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    send_text(&mut ws, &req_wire("s", "{\"kinds\":[1]}")).await;
    // Drain EOSE.
    loop {
        if json(&recv_text(&mut ws, T).await)[0] == "EOSE" {
            break;
        }
    }
    // Re-REQ under the same id with a different filter.
    send_text(&mut ws, &req_wire("s", "{\"kinds\":[2]}")).await;
    loop {
        if json(&recv_text(&mut ws, T).await)[0] == "EOSE" {
            break;
        }
    }
    // A kind-1 event must no longer be delivered on "s".
    let ev1 = common::event(&key(6), 1, now(), &json!([]), "old-filter");
    send_text(&mut ws, &event_wire(&ev1)).await;
    let _ok = recv_text(&mut ws, T).await;
    let ev2 = common::event(&key(6), 2, now(), &json!([]), "new-filter");
    send_text(&mut ws, &event_wire(&ev2)).await;
    let frame = loop {
        let frame = json(&recv_text(&mut ws, T).await);
        if frame[0] == "EVENT" {
            break frame;
        }
    };
    assert_eq!(frame[1], "s");
    assert_eq!(frame[2]["id"], json(ev2.json())["id"]);
    relay.stop().await;
}

#[tokio::test]
async fn replaceable_superseded_and_latest_only() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let k = key(7);
    let v2 = common::event(&k, 0, now(), &json!([]), "newer");
    let v1 = common::event(&k, 0, now() - 100, &json!([]), "older");
    let v3 = common::event(&k, 0, now() + 1, &json!([]), "newest");
    send_text(&mut ws, &event_wire(&v2)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[2], true);
    // Older version rejected as superseded.
    send_text(&mut ws, &event_wire(&v1)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], false);
    assert_eq!(ok[3], "duplicate: have a newer version");
    // Newer version replaces.
    send_text(&mut ws, &event_wire(&v3)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[2], true);
    send_text(&mut ws, &req_wire("s", "{\"kinds\":[0]}")).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame[0], "EVENT");
    assert_eq!(frame[2]["id"], json(v3.json())["id"]);
    assert_eq!(json(&recv_text(&mut ws, T).await)[0], "EOSE");
    relay.stop().await;
}

#[tokio::test]
async fn ephemeral_live_only() {
    let relay = Relay::start().await;
    let mut sub_ws = relay.connect().await;
    let mut pub_ws = relay.connect().await;
    send_text(&mut sub_ws, &req_wire("s", "{\"kinds\":[20000]}")).await;
    loop {
        if json(&recv_text(&mut sub_ws, T).await)[0] == "EOSE" {
            break;
        }
    }
    let ev = common::event(&key(8), 20_000, now(), &json!([]), "eph");
    send_text(&mut pub_ws, &event_wire(&ev)).await;
    let ok = json(&recv_text(&mut pub_ws, T).await);
    assert_eq!(ok[2], true);
    let frame = json(&recv_text(&mut sub_ws, T).await);
    assert_eq!(frame[0], "EVENT");
    // A later REQ finds nothing stored.
    send_text(&mut sub_ws, &req_wire("s2", "{\"kinds\":[20000]}")).await;
    assert_eq!(json(&recv_text(&mut sub_ws, T).await)[0], "EOSE");
    relay.stop().await;
}

#[tokio::test]
async fn durability_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let config = |path: &std::path::Path| {
        let mut c = common::config();
        c.db.path = path.to_path_buf();
        c
    };
    let ev = common::event(&key(9), 1, now(), &json!([]), "durable");
    {
        let relay = Relay::start_with(config(dir.path())).await;
        let mut ws = relay.connect().await;
        send_text(&mut ws, &event_wire(&ev)).await;
        let _ok = recv_text(&mut ws, T).await;
        relay.stop().await;
    }
    {
        let relay = Relay::start_with(config(dir.path())).await;
        let mut ws = relay.connect().await;
        send_text(&mut ws, &req_wire("s", "{\"kinds\":[1]}")).await;
        let frame = json(&recv_text(&mut ws, T).await);
        assert_eq!(frame[0], "EVENT");
        assert_eq!(frame[2]["id"], json(ev.json())["id"]);
        assert_eq!(json(&recv_text(&mut ws, T).await)[0], "EOSE");
        relay.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exactly_once_across_stored_and_live() {
    const PUBLISHERS: usize = 4;
    const PER_PUB: usize = 250;
    let mut config = common::config();
    config.relay.query_timeslice_budget_microseconds = 1;
    config.relay.limits.max_filter_limit = 5_000;
    let relay = Relay::start_with(config).await;

    // Publishers send continuously.
    let mut pub_tasks = Vec::new();
    for p in 0..PUBLISHERS {
        let addr = relay.addr;
        pub_tasks.push(tokio::spawn(async move {
            let url = format!("ws://{addr}/");
            let mut ws = yawc::WebSocket::connect(url.parse().unwrap())
                .await
                .unwrap();
            let k = key(20 + u8::try_from(p).unwrap());
            let base = now();
            let mut oks = 0usize;
            for i in 0..PER_PUB as u64 {
                let ev = common::event(&k, 1, base + i, &json!([]), &format!("p{p}e{i}"));
                ws.send(yawc::Frame::text(event_wire(&ev))).await.unwrap();
                // Drain OKs lazily to keep the socket writable.
                if i % 50 == 49 {
                    while let Ok(Some(f)) =
                        tokio::time::timeout(Duration::from_millis(50), ws.next()).await
                    {
                        if f.opcode() == yawc::OpCode::Text
                            && json(std::str::from_utf8(f.payload()).unwrap())[0] == "OK"
                        {
                            oks += 1;
                        }
                    }
                }
            }
            // Await every OK so the peer's replies do not linger in our
            // receive buffer; dropping the socket with unread inbound data
            // sends a TCP RST that discards our un-acked tail frames.
            let deadline = Instant::now() + Duration::from_secs(30);
            while oks < PER_PUB && Instant::now() < deadline {
                match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                    Ok(Some(f)) if f.opcode() == yawc::OpCode::Text => {
                        let v = json(std::str::from_utf8(f.payload()).unwrap());
                        if v[0] == "OK" {
                            assert_eq!(v[2], true, "pub{p} rejected: {v}");
                            oks += 1;
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
            assert_eq!(oks, PER_PUB, "pub{p} missing OKs");
            // Graceful close handshake, then drain until EOF so the FIN is
            // not upgraded to an RST by lingering inbound data.
            ws.send(yawc::Frame::close(yawc::close::CloseCode::Normal, &[][..]))
                .await
                .ok();
            while let Ok(Some(_)) = tokio::time::timeout(Duration::from_secs(5), ws.next()).await {}
        }));
    }

    // Subscribers issue REQs at staggered moments.
    let mut sub_tasks = Vec::new();
    for s in 0..3usize {
        let addr = relay.addr;
        sub_tasks.push(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100 * s as u64)).await;
            let url = format!("ws://{addr}/");
            let mut ws = yawc::WebSocket::connect(url.parse().unwrap())
                .await
                .unwrap();
            send_text(&mut ws, &req_wire("s", "{\"kinds\":[1],\"limit\":5000}")).await;
            let mut ids = std::collections::HashSet::new();
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline && ids.len() < PUBLISHERS * PER_PUB {
                let Ok(Some(frame)) =
                    tokio::time::timeout(Duration::from_secs(10), ws.next()).await
                else {
                    continue;
                };
                if frame.opcode() != yawc::OpCode::Text {
                    continue;
                }
                let v = json(std::str::from_utf8(frame.payload()).unwrap());
                if v[0] == "EVENT" {
                    let id = v[2]["id"].as_str().unwrap().to_owned();
                    assert!(ids.insert(id), "duplicate delivery: {v}");
                }
            }
            ids.len()
        }));
    }
    for t in pub_tasks {
        t.await.unwrap();
    }
    for t in sub_tasks {
        let count = t.await.unwrap();
        assert_eq!(count, PUBLISHERS * PER_PUB);
    }
    relay.stop().await;
}

#[tokio::test]
async fn too_many_subs_and_unknown_filter_key() {
    let mut config = common::config();
    config.relay.limits.max_subs_per_connection = 1;
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;
    send_text(&mut ws, &req_wire("a", "{\"kinds\":[1]}")).await;
    loop {
        if json(&recv_text(&mut ws, T).await)[0] == "EOSE" {
            break;
        }
    }
    send_text(&mut ws, &req_wire("b", "{\"kinds\":[2]}")).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame[0], "CLOSED");
    assert_eq!(frame[1], "b");
    assert!(frame[2].as_str().unwrap().starts_with("error:"));

    send_text(&mut ws, &req_wire("a", "{\"kinds\":[1],\"bogus\":true}")).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame[0], "CLOSED");
    assert!(frame[2].as_str().unwrap().starts_with("unsupported:"));
    relay.stop().await;
}

#[tokio::test]
async fn oversized_frame_closes_connection() {
    let mut config = common::config();
    config.relay.max_websocket_payload_size = 1024;
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;
    let big = format!(
        "[\"REQ\",\"s\",{{\"kinds\":[1],\"search\":\"{}\"}}]",
        "x".repeat(4096)
    );
    send_text(&mut ws, &big).await;
    // The connection should be torn down without a valid relay reply.
    let deadline = Instant::now() + T;
    loop {
        let Some(frame) = tokio::time::timeout(T, ws.next()).await.ok().flatten() else {
            break;
        };
        if Instant::now() > deadline || frame.opcode() == yawc::OpCode::Close {
            break;
        }
        assert_ne!(
            frame.opcode(),
            yawc::OpCode::Text,
            "unexpected reply to oversized frame"
        );
    }
    relay.stop().await;
}

/// A raw WebSocket client that negotiates permessage-deflate by hand:
/// the tests need to see RSV1 bits and craft frames whose wire size
/// differs from the inflated size, which a library client hides.
struct DeflateSocket {
    stream: tokio::net::TcpStream,
    /// Inflate state persists across messages when the negotiation
    /// kept context takeover; otherwise it resets per message.
    inflater: flate2::Decompress,
    /// The server's `Sec-WebSocket-Extensions` value, lowercased.
    extensions: String,
    /// Whether the server kept the sliding window for its sender.
    takeover: bool,
}

impl DeflateSocket {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: nosfry-test\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Extensions: permessage-deflate\r\n",
            "\r\n",
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        let extensions = head
            .to_ascii_lowercase()
            .lines()
            .find_map(|line| line.strip_prefix("sec-websocket-extensions:"))
            .map(str::trim)
            .unwrap_or_default()
            .to_owned();
        assert!(
            extensions.contains("permessage-deflate"),
            "deflate was not negotiated: {head}"
        );
        Self {
            stream,
            inflater: flate2::Decompress::new(false),
            takeover: !extensions.contains("server_no_context_takeover"),
            extensions,
        }
    }

    /// One masked client frame of the given opcode.
    async fn send_frame(&mut self, compressed: bool, opcode: u8, payload: &[u8]) {
        let mask = [0x12, 0x34, 0x56, 0x78u8];
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | (u8::from(compressed) << 6) | opcode);
        let len = payload.len();
        if len <= 125 {
            frame.push(0x80 | u8::try_from(len).unwrap());
        } else if u16::try_from(len).is_ok() {
            frame.push(0x80 | 0x7e);
            frame.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        } else {
            frame.push(0x80 | 0x7f);
            frame.extend_from_slice(&u64::try_from(len).unwrap().to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        self.stream.write_all(&frame).await.unwrap();
    }

    /// One server frame; `None` on EOF. The relay does not fragment.
    async fn read(&mut self) -> Option<(bool, u8, Vec<u8>)> {
        let mut header = [0u8; 2];
        self.stream.read_exact(&mut header).await.ok()?;
        let rsv1 = header[0] & 0x40 != 0;
        let opcode = header[0] & 0x0f;
        let mut len = u64::from(header[1] & 0x7f);
        if len == 126 {
            let mut ext = [0u8; 2];
            self.stream.read_exact(&mut ext).await.ok()?;
            len = u64::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            let mut ext = [0u8; 8];
            self.stream.read_exact(&mut ext).await.ok()?;
            len = u64::from_be_bytes(ext);
        }
        let mut payload = vec![0u8; usize::try_from(len).unwrap()];
        self.stream.read_exact(&mut payload).await.ok()?;
        if rsv1 {
            payload = self.inflate(&payload);
        }
        Some((rsv1, opcode, payload))
    }

    /// Decompress one message. Without context takeover each message
    /// is a fresh deflate stream, so the inflater resets first.
    fn inflate(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.takeover {
            self.inflater.reset(false);
        }
        let mut wire = data.to_vec();
        wire.extend_from_slice(&[0, 0, 0xff, 0xff]);
        let mut out = Vec::with_capacity(wire.len() * 4 + 64);
        let base = self.inflater.total_in();
        while (self.inflater.total_in() - base) < wire.len() as u64 {
            let before = self.inflater.total_in();
            self.inflater
                .decompress_vec(&wire, &mut out, flate2::FlushDecompress::Sync)
                .unwrap();
            assert!(self.inflater.total_in() > before, "inflate stalled");
        }
        out
    }

    /// The next data or close frame; pings get an automatic pong and
    /// other control frames are skipped.
    async fn read_data(&mut self) -> Option<(bool, u8, Vec<u8>)> {
        loop {
            let (rsv1, opcode, payload) = self.read().await?;
            match opcode {
                0x9 => self.send_frame(false, 0xa, &payload).await,
                0xa => {}
                _ => return Some((rsv1, opcode, payload)),
            }
        }
    }
}

/// Raw permessage-deflate message compression (`Z_SYNC_FLUSH` tail
/// stripped, as RFC 7692 requires).
fn deflate(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 64);
    flate2::Compress::new(flate2::Compression::fast(), false)
        .compress_vec(text, &mut out, flate2::FlushCompress::Sync)
        .unwrap();
    out.truncate(out.len() - 4);
    out
}

/// A frame whose wire size is tiny but whose inflated size exceeds
/// `max_websocket_payload_size` must close the connection with 1009
/// without delivering anything (yawc#55, fixed by 0.4.4).
#[tokio::test]
async fn compressed_inflation_over_limit_closes_1009() {
    let mut config = common::config();
    config.relay.compression.enabled = true;
    config.relay.max_websocket_payload_size = 4096;
    let relay = Relay::start_with(config).await;
    let mut ws = DeflateSocket::connect(relay.addr).await;

    let text = "x".repeat(4097);
    ws.send_frame(true, 0x1, &deflate(text.as_bytes())).await;
    let deadline = Instant::now() + T;
    loop {
        let frame = tokio::time::timeout(T, ws.read_data()).await.unwrap();
        let Some((_, opcode, payload)) = frame else {
            panic!("connection dropped without a close frame");
        };
        assert!(Instant::now() <= deadline, "no close frame within deadline");
        assert_ne!(opcode, 0x1, "oversized message must not be delivered");
        if opcode == 0x8 {
            assert_eq!(
                u16::from_be_bytes([payload[0], payload[1]]),
                1009,
                "close code"
            );
            break;
        }
    }
    relay.stop().await;
}

/// Default compression negotiates no context takeover in both
/// directions; replies under the threshold (OK, EOSE) leave
/// uncompressed while an EVENT delivery keeps RSV1 and inflates to
/// the right JSON.
#[tokio::test]
async fn compressed_event_round_trip() {
    let mut config = common::config();
    config.relay.compression.enabled = true;
    let relay = Relay::start_with(config).await;
    let mut ws = DeflateSocket::connect(relay.addr).await;
    assert!(ws.extensions.contains("server_no_context_takeover"));
    assert!(ws.extensions.contains("client_no_context_takeover"));

    let ev = common::event(&key(7), 1, now(), &json!([]), "compressed");
    let id = json(ev.json())["id"].as_str().unwrap().to_owned();
    ws.send_frame(true, 0x1, &deflate(event_wire(&ev).as_bytes()))
        .await;
    let (rsv1, opcode, payload) = ws.read_data().await.unwrap();
    assert!(!rsv1, "an OK is under the compression threshold");
    assert_eq!(opcode, 0x1);
    let ok = json(std::str::from_utf8(&payload).unwrap());
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[1], id);
    assert_eq!(ok[2], true);

    ws.send_frame(
        true,
        0x1,
        &deflate(req_wire("s", &format!("{{\"ids\":[\"{id}\"]}}")).as_bytes()),
    )
    .await;
    let mut saw_event = false;
    let mut saw_eose = false;
    for _ in 0..4 {
        let (rsv1, opcode, payload) = ws.read_data().await.unwrap();
        assert_eq!(opcode, 0x1);
        let frame = json(std::str::from_utf8(&payload).unwrap());
        match frame[0].as_str().unwrap() {
            "EVENT" => {
                assert!(rsv1, "an event message is over the threshold");
                assert_eq!(frame[2]["id"], id);
                saw_event = true;
            }
            "EOSE" => {
                assert!(!rsv1, "an EOSE is under the compression threshold");
                saw_eose = true;
            }
            other => panic!("unexpected frame: {other}"),
        }
        if saw_event && saw_eose {
            break;
        }
    }
    assert!(saw_event && saw_eose);
    relay.stop().await;
}

/// With `sliding_window` the negotiation offers neither
/// no-context-takeover parameter and one persistent inflater decodes
/// consecutive compressed EVENTs (the second may back-reference the
/// first).
#[tokio::test]
async fn sliding_window_decodes_with_one_inflater() {
    let mut config = common::config();
    config.relay.compression.sliding_window = true;
    let relay = Relay::start_with(config).await;
    let mut ws = DeflateSocket::connect(relay.addr).await;
    assert!(!ws.extensions.contains("no_context_takeover"));

    ws.send_frame(
        true,
        0x1,
        &deflate(req_wire("s", "{\"kinds\":[1],\"#t\":[\"sw-x\"],\"limit\":0}").as_bytes()),
    )
    .await;
    let (_, opcode, _) = ws.read_data().await.unwrap();
    assert_eq!(opcode, 0x1, "EOSE expected");

    let mut publisher = relay.connect().await;
    let mut ids = Vec::new();
    for content in ["first", "second"] {
        let ev = common::event(&key(7), 1, now(), &json!([["t", "sw-x"]]), content);
        ids.push(json(ev.json())["id"].as_str().unwrap().to_owned());
        send_text(&mut publisher, &event_wire(&ev)).await;
        let ok = json(&recv_text(&mut publisher, T).await);
        assert_eq!(ok[0], "OK");
    }
    for want in &ids {
        let (rsv1, opcode, payload) = ws.read_data().await.unwrap();
        assert!(rsv1, "an event message is over the threshold");
        assert_eq!(opcode, 0x1);
        let frame = json(std::str::from_utf8(&payload).unwrap());
        assert_eq!(frame[0], "EVENT");
        assert_eq!(frame[2]["id"], *want);
    }
    relay.stop().await;
}

/// One HTTP GET with the NIP-11 Accept, returning the raw response
/// text.
async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    http_get_accept(addr, path, "application/nostr+json").await
}

/// One HTTP GET without the NIP-11 Accept (a browser fetch).
async fn http_get_browser(addr: std::net::SocketAddr, path: &str) -> String {
    http_get_accept(addr, path, "text/html").await
}

/// One HTTP GET returning the raw response text.
async fn http_get_accept(addr: std::net::SocketAddr, path: &str, accept: &str) -> String {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nAccept: {accept}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

fn nip11_body(text: &str) -> Value {
    let (_, body) = text.split_once("\r\n\r\n").expect("http head/body split");
    serde_json::from_str(body).expect("nip11 json")
}

#[tokio::test]
async fn nip11_document() {
    // Empty info fields are omitted; `name` stays unconditionally.
    let relay = Relay::start().await;
    let text = http_get(relay.addr, "/").await;
    assert!(text.contains("content-type: application/nostr+json"));
    assert!(text.contains("access-control-allow-origin: *"));
    let doc = nip11_body(&text);
    assert_eq!(doc["name"], "nosfry");
    for key in ["description", "pubkey", "contact", "icon"] {
        assert!(doc.get(key).is_none(), "{key} must be omitted when empty");
    }
    assert_eq!(doc["supported_nips"], json!([1, 9, 11, 40, 45, 62, 70, 77]));
    assert_eq!(doc["software"], "https://github.com/qntx/nosfry");
    assert_eq!(doc["limitation"]["max_subscriptions"], 200);
    assert_eq!(
        doc["limitation"]["max_subid_length"],
        nosfry_core::message::SUB_ID_MAX_CHARS as u64
    );
    relay.stop().await;

    // Configured fields are emitted verbatim.
    let mut config = common::config();
    config.relay.info.description = "test relay".to_owned();
    config.relay.info.pubkey = "ab".repeat(32);
    config.relay.info.contact = "admin@example.com".to_owned();
    config.relay.info.icon = "https://example.com/icon.png".to_owned();
    config.relay.info.banner = "https://example.com/banner.png".to_owned();
    config.relay.info.self_pubkey = "cd".repeat(32);
    config.relay.info.terms_of_service = "https://example.com/terms".to_owned();
    config.relay.info.privacy_policy = "https://example.com/privacy".to_owned();
    let relay = Relay::start_with(config).await;
    let doc = nip11_body(&http_get(relay.addr, "/").await);
    assert_eq!(doc["description"], "test relay");
    assert_eq!(doc["pubkey"], "ab".repeat(32));
    assert_eq!(doc["contact"], "admin@example.com");
    assert_eq!(doc["icon"], "https://example.com/icon.png");
    assert_eq!(doc["banner"], "https://example.com/banner.png");
    assert_eq!(doc["self"], "cd".repeat(32));
    assert_eq!(doc["terms_of_service"], "https://example.com/terms");
    assert_eq!(doc["privacy_policy"], "https://example.com/privacy");
    relay.stop().await;
}

#[tokio::test]
async fn landing_page_and_nodeinfo() {
    // GET / without a NIP-11 Accept is the HTML landing page.
    let mut config = common::config();
    config.relay.info.name = "test <relay>".to_owned();
    config.relay.service_url = "wss://relay.example.com".to_owned();
    let relay = Relay::start_with(config).await;
    let text = http_get_browser(relay.addr, "/").await;
    assert!(text.contains("content-type: text/html"));
    let (_, body) = text.split_once("\r\n\r\n").expect("http head/body split");
    assert!(body.contains("<!doctype html>"), "{body}");
    assert!(body.contains("<h1>test &lt;relay&gt;</h1>"), "{body}");
    assert!(
        body.contains("<code>wss://relay.example.com</code>"),
        "{body}"
    );

    // `/nodeinfo/2.1` is the NodeInfo document with its profile type.
    let text = http_get_browser(relay.addr, "/nodeinfo/2.1").await;
    assert!(text.contains("profile=\"http://nodeinfo.diaspora.software/ns/schema/2.1#\""));
    let doc = nip11_body(&text);
    assert_eq!(doc["version"], "2.1");
    assert_eq!(doc["software"]["name"], "nosfry");

    // `/.well-known/nodeinfo` links at the service_url host.
    let text = http_get_browser(relay.addr, "/.well-known/nodeinfo").await;
    let doc = nip11_body(&text);
    assert_eq!(
        doc["links"][0]["href"],
        "https://relay.example.com/nodeinfo/2.1"
    );

    // Unknown paths stay 404.
    let text = http_get_browser(relay.addr, "/nope").await;
    assert!(text.starts_with("HTTP/1.1 404"), "{text}");
    relay.stop().await;

    // Without `service_url` the discovery document is 404 too.
    let relay = Relay::start().await;
    let text = http_get_browser(relay.addr, "/.well-known/nodeinfo").await;
    assert!(text.starts_with("HTTP/1.1 404"), "{text}");
    relay.stop().await;
}

#[tokio::test]
async fn slow_consumer_is_disconnected() {
    let mut config = common::config();
    config.relay.max_pending_outbound_bytes = 4096;
    let relay = Relay::start_with(config).await;
    // Fill the store: the scan will push more than 4 KiB of events.
    {
        let mut ws = relay.connect().await;
        for i in 0..50u64 {
            let ev = common::event(&key(30), 1, now(), &json!([]), &format!("e{i:03}"));
            send_text(&mut ws, &event_wire(&ev)).await;
            let _ok = recv_text(&mut ws, T).await;
        }
    }
    // This client never reads; its outbound queue must overflow.
    let mut ws = relay.connect().await;
    {
        ws.send(yawc::Frame::text(req_wire("s", "{\"kinds\":[1]}")))
            .await
            .unwrap();
    }
    let close = tokio::time::timeout(T, async {
        loop {
            match ws.next().await {
                Some(f) if f.opcode() == yawc::OpCode::Close => break Some(f),
                Some(_) => {}
                None => break None,
            }
        }
    })
    .await;
    match close {
        Ok(Some(frame)) => {
            let reason = String::from_utf8_lossy(frame.payload());
            assert!(reason.contains("slow consumer") || frame.close_code().is_some());
        }
        Ok(None) => {} // server dropped the connection outright
        Err(err) => panic!("connection stayed open past the outbound cap: {err}"),
    }
    relay.stop().await;
}

#[tokio::test]
async fn slow_consumer_releases_outbound_bytes() {
    let mut config = common::config();
    config.relay.metrics = true;
    config.relay.max_pending_outbound_bytes = 256 * 1024;
    // The write deadline and the silent-client keepalive timeout both
    // scale with the ping interval; shrink it so the cut happens fast.
    config.relay.auto_ping_seconds = 2;
    let relay = Relay::start_with(config).await;

    // Live-only subscriber (`limit: 0` skips the stored scan) that
    // never reads its socket.
    let mut slow = relay.connect().await;
    send_text(&mut slow, &req_wire("s", "{\"kinds\":[1],\"limit\":0}")).await;

    // Live fan-out is what trips the per-connection byte cap: ~8 MiB
    // of 32 KiB events far exceeds both the socket buffers and the
    // 256 KiB queue.
    let mut pub_ws = relay.connect().await;
    let content = "x".repeat(32 * 1024);
    for i in 0..256u64 {
        let ev = common::event(&key(30), 1, now(), &json!([]), &format!("{content}{i}"));
        send_text(&mut pub_ws, &event_wire(&ev)).await;
        let ok = json(&recv_text(&mut pub_ws, T).await);
        assert_eq!(ok[2], true, "{ok}");
    }

    // The slow consumer was cut; once its connection is gone its
    // queued bytes must leave the process-wide gauge at 0.
    let deadline = Instant::now() + T;
    let mut pending = None;
    while Instant::now() < deadline {
        let body = http_get(relay.addr, "/metrics").await;
        pending = metric_value(&body, "nosfry_outbound_pending_bytes");
        if pending == Some(0) && metric_value(&body, "nosfry_connections") == Some(1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        pending,
        Some(0),
        "queued bytes stayed charged to a closed connection"
    );
    relay.stop().await;
}

#[tokio::test]
async fn half_open_connection_times_out() {
    let mut config = common::config();
    config.relay.auto_ping_seconds = 1;
    let relay = Relay::start_with(config).await;

    // A raw client that completes the upgrade and then goes silent:
    // it never reads or answers the server's pings.
    let mut tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        relay.addr
    );
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    while !response.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tcp.read(&mut chunk).await.unwrap();
        assert!(n > 0, "upgrade failed: {response:?}");
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(response.starts_with(b"HTTP/1.1 101"));

    // The server must close the silent connection after two ping
    // intervals. Read until EOF and pull the code out of the close
    // frame (server frames are unmasked).
    let mut close_code = None;
    let mut buf = Vec::new();
    tokio::time::timeout(T, async {
        tcp.read_to_end(&mut buf).await.unwrap();
        let mut i = 0;
        while i + 2 <= buf.len() {
            let opcode = buf[i] & 0x0f;
            let (len, hdr) = match buf[i + 1] & 0x7f {
                126 if i + 4 <= buf.len() => {
                    (usize::from(u16::from_be_bytes([buf[i + 2], buf[i + 3]])), 4)
                }
                127 if i + 10 <= buf.len() => (
                    usize::try_from(u64::from_be_bytes(buf[i + 2..i + 10].try_into().unwrap()))
                        .unwrap(),
                    10,
                ),
                n @ 0..=125 => (usize::from(n), 2),
                _ => break,
            };
            if i + hdr + len > buf.len() {
                break;
            }
            if opcode == 0x8 && len >= 2 {
                close_code = Some(u16::from_be_bytes([buf[i + hdr], buf[i + hdr + 1]]));
            }
            i += hdr + len;
        }
    })
    .await
    .expect("half-open connection was not closed");
    assert_eq!(close_code, Some(1001));
    relay.stop().await;
}

#[tokio::test]
async fn shutdown_with_stuck_client_returns() {
    let mut config = common::config();
    config.relay.auto_ping_seconds = 1;
    let relay = Relay::start_with(config).await;
    // Fill the store so the REQ produces a large outbound backlog.
    {
        let mut ws = relay.connect().await;
        for i in 0..200u64 {
            let ev = common::event(&key(40), 1, now(), &json!([]), &format!("e{i:03}"));
            send_text(&mut ws, &event_wire(&ev)).await;
            let _ok = recv_text(&mut ws, T).await;
        }
    }
    // This client issues the REQ and never reads another frame.
    let ws = relay.connect().await;
    {
        let mut ws = ws;
        ws.send(yawc::Frame::text(req_wire("s", "{\"kinds\":[1]}")))
            .await
            .unwrap();
    }
    // `serve` must return even though the client never drains its
    // socket: write timeouts and the tracker deadline bound it.
    tokio::time::timeout(Duration::from_secs(15), relay.stop())
        .await
        .expect("serve did not return with a stuck client");
}

/// Collect the event ids of one REQ until EOSE.
async fn req_ids(ws: &mut yawc::TcpWebSocket, sub: &str, filter: &str) -> Vec<String> {
    send_text(ws, &req_wire(sub, filter)).await;
    let mut got = Vec::new();
    loop {
        let frame = json(&recv_text(ws, T).await);
        match frame[0].as_str().unwrap() {
            "EVENT" => got.push(frame[2]["id"].as_str().unwrap().to_owned()),
            "EOSE" => return got,
            other => panic!("unexpected frame {other}"),
        }
    }
}

#[tokio::test]
async fn nip09_delete_by_id_hides_and_blocks() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let k = key(30);
    let note = common::event(&k, 1, now(), &json!([]), "gone");
    let note_id = json(note.json())["id"].as_str().unwrap().to_owned();
    send_text(&mut ws, &event_wire(&note)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[2], true);

    let kind5 = common::event(&k, 5, now(), &json!([["e", note_id]]), "");
    send_text(&mut ws, &event_wire(&kind5)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[2], true);

    // The deleted event no longer matches a REQ; the kind 5 remains.
    let got = req_ids(&mut ws, "d1", "{}").await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0], json(kind5.json())["id"].as_str().unwrap());

    // Republishing the deleted id is blocked.
    send_text(&mut ws, &event_wire(&note)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], false);
    assert!(ok[3].as_str().unwrap().starts_with("blocked:"));
    relay.stop().await;
}

#[tokio::test]
async fn nip09_delete_by_address() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let k = key(31);
    let pk = format!("{}", k.x_only_public_key().0);
    let v1 = common::event(&k, 30_023, now(), &json!([["d", "art"]]), "v1");
    let v1_id = json(v1.json())["id"].as_str().unwrap().to_owned();
    send_text(&mut ws, &event_wire(&v1)).await;
    let _ok = recv_text(&mut ws, T).await;

    let kind5 = common::event(&k, 5, now(), &json!([["a", format!("30023:{pk}:art")]]), "");
    send_text(&mut ws, &event_wire(&kind5)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[2], true);

    let got = req_ids(&mut ws, "a1", "{\"kinds\":[30023]}").await;
    assert!(got.is_empty(), "addressable event still visible: {got:?}");
    // Close a1: a stored republish would otherwise be delivered live
    // on this socket, racing the OK frame the reads below expect.
    send_text(&mut ws, &close_wire("a1")).await;

    // Same-address republish at an older timestamp is blocked; a newer
    // version is accepted.
    send_text(&mut ws, &event_wire(&v1)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[2], false);
    assert!(ok[3].as_str().unwrap().starts_with("blocked:"));
    let v2 = common::event(&k, 30_023, now() + 1, &json!([["d", "art"]]), "v2");
    send_text(&mut ws, &event_wire(&v2)).await;
    let ok = recv_ok(&mut ws, &v2).await;
    assert_eq!(ok[2], true, "newer version rejected: {ok}");
    let _ = v1_id;
    relay.stop().await;
}

#[tokio::test]
async fn req_addressable_kinds_without_d_returns_all_addresses() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let k = key(33);
    let pk = format!("{}", k.x_only_public_key().0);
    let mut ids = Vec::new();
    let mut b_id = String::new();
    for d in ["a", "b", "c"] {
        let ev = common::event(&k, 30_023, now(), &json!([["d", d]]), d);
        send_text(&mut ws, &event_wire(&ev)).await;
        assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
        if d == "b" {
            b_id = ev.id().to_string();
        }
        ids.push(ev.id().to_string());
    }
    // `intrinsic_limit` must not bound an addressable author+kind
    // query that has no `#d` condition.
    let mut got = req_ids(
        &mut ws,
        "al",
        &format!("{{\"kinds\":[30023],\"authors\":[\"{pk}\"]}}"),
    )
    .await;
    got.sort();
    ids.sort();
    assert_eq!(got, ids);
    // With `#d` only the listed addresses match.
    let got = req_ids(
        &mut ws,
        "dx",
        &format!("{{\"kinds\":[30023],\"authors\":[\"{pk}\"],\"#d\":[\"b\"]}}"),
    )
    .await;
    assert_eq!(got, vec![b_id]);
    relay.stop().await;
}

#[tokio::test]
async fn nip40_expired_event_rejected_on_ingest() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let ev = common::event(
        &key(32),
        1,
        now(),
        &json!([["expiration", (now() - 10).to_string()]]),
        "stale",
    );
    send_text(&mut ws, &event_wire(&ev)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], false);
    assert!(ok[3].as_str().unwrap().starts_with("invalid:"));
    relay.stop().await;
}

#[tokio::test]
async fn nip40_expiring_event_hidden_after_expiry() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let ev = common::event(
        &key(33),
        1,
        now(),
        &json!([["expiration", (now() + 2).to_string()]]),
        "short-lived",
    );
    let ev_id = json(ev.json())["id"].as_str().unwrap().to_owned();
    send_text(&mut ws, &event_wire(&ev)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[2], true);

    // Visible before expiry.
    let got = req_ids(&mut ws, "x1", "{\"kinds\":[1]}").await;
    assert_eq!(got, vec![ev_id.clone()]);

    // Past the expiration the same REQ hides it — before any sweep.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let got = req_ids(&mut ws, "x2", "{\"kinds\":[1]}").await;
    assert!(got.is_empty(), "expired event still served: {got:?}");
    relay.stop().await;
}

/// A client holding a TCP connection without finishing its request
/// head is dropped once the header-read deadline passes (slowloris).
#[tokio::test]
async fn incomplete_request_headers_time_out() {
    let relay = Relay::start().await;
    let mut tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    // A partial request line and one header, never completed.
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(12), tcp.read(&mut buf)).await;
    match read {
        Ok(Ok(0) | Err(..)) => {}
        Ok(Ok(n)) => panic!("server kept a stalled request head alive: {n} bytes read"),
        Err(..) => panic!("header-read deadline never fired"),
    }
    assert!(
        start.elapsed() >= Duration::from_secs(9),
        "connection closed early: {:?}",
        start.elapsed()
    );
    relay.stop().await;
}

/// A client-sent (masked) frame; `first` carries FIN/RSV/opcode.
fn masked_frame(first: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x11, 0x22, 0x33, 0x44];
    let mut frame = vec![first];
    match payload.len() {
        0..=125 => frame.push(0x80 | u8::try_from(payload.len()).unwrap()),
        126..=65535 => {
            frame.push(0x80 | 0x7E);
            frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        }
        n => {
            frame.push(0x80 | 0x7F);
            frame.extend_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

/// Read raw (unmasked) server frames into `(opcode, payload)` pairs.
async fn read_server_frames(tcp: &mut tokio::net::TcpStream) -> Vec<(u8, Vec<u8>)> {
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let mut frames = Vec::new();
    let mut i = 0;
    while i + 2 <= buf.len() {
        let opcode = buf[i] & 0x0f;
        let (len, hdr) = match buf[i + 1] & 0x7f {
            126 if i + 4 <= buf.len() => {
                (usize::from(u16::from_be_bytes([buf[i + 2], buf[i + 3]])), 4)
            }
            127 if i + 10 <= buf.len() => (
                usize::try_from(u64::from_be_bytes(buf[i + 2..i + 10].try_into().unwrap()))
                    .unwrap(),
                10,
            ),
            n @ 0..=125 => (usize::from(n), 2),
            _ => break,
        };
        if i + hdr + len > buf.len() {
            break;
        }
        frames.push((opcode, buf[i + hdr..i + hdr + len].to_vec()));
        i += hdr + len;
    }
    frames
}

/// With permessage-deflate disabled a client offering it gets no
/// extension header back, and a compressed (RSV1) frame is a protocol
/// error.
#[tokio::test]
async fn compression_not_negotiated_and_rsv1_rejected() {
    let mut config = common::config();
    config.relay.compression.enabled = false;
    let relay = Relay::start_with(config).await;
    let mut tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
        relay.addr
    );
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    while !response.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tcp.read(&mut chunk).await.unwrap();
        assert!(n > 0, "upgrade failed: {response:?}");
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(response.starts_with(b"HTTP/1.1 101"), "{response:?}");
    let head = String::from_utf8_lossy(&response).to_lowercase();
    assert!(
        !head.contains("sec-websocket-extensions"),
        "compression negotiated despite being off: {head}"
    );

    // A compressed frame (FIN|RSV1|text) must close the connection
    // with a 1002 protocol error, not be processed.
    tcp.write_all(&masked_frame(0xC1, b"hi")).await.unwrap();
    let mut close_code = None;
    tokio::time::timeout(T, async {
        for (opcode, payload) in read_server_frames(&mut tcp).await {
            if opcode == 0x8 && payload.len() >= 2 {
                close_code = Some(u16::from_be_bytes([payload[0], payload[1]]));
            }
        }
    })
    .await
    .expect("RSV1 frame did not close the connection");
    assert_eq!(close_code, Some(1002));
    relay.stop().await;
}

/// Automatic pongs flush on inbound pings: 1000 back-to-back pings get
/// their pongs without waiting for other outbound traffic.
#[tokio::test]
async fn pings_are_answered_while_idle() {
    const N: u64 = 1_000;
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    for i in 0..N {
        ws.send(yawc::frame::Frame::ping(i.to_le_bytes().to_vec()))
            .await
            .unwrap();
    }
    let mut pongs = 0u64;
    tokio::time::timeout(Duration::from_secs(10), async {
        while pongs < N {
            let frame = ws.next().await.expect("connection closed");
            match frame.opcode() {
                yawc::OpCode::Pong => pongs += 1,
                yawc::OpCode::Ping => ws.send(yawc::frame::Frame::pong(Vec::new())).await.unwrap(),
                other => panic!("unexpected frame: {other:?}"),
            }
        }
    })
    .await
    .expect("pongs did not arrive");
    assert_eq!(pongs, N);
    relay.stop().await;
}

/// Raw HTTP/1.1 WebSocket upgrade attempt; returns the response
/// status line ("HTTP/1.1 101 ..." / "... 429 ..."). The connection
/// is dropped right after the status line is read.
async fn upgrade_status(addr: std::net::SocketAddr) -> String {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        b"GET / HTTP/1.1\r\nHost: nosfry\r\nUpgrade: websocket\r\n\
          Connection: upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = [0u8; 512];
    let n = tcp.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn connection_cap_per_ip() {
    let mut config = common::config();
    config.relay.max_connections_per_ip = 2;
    let relay = Relay::start_with(config).await;
    let ws1 = relay.connect().await;
    let ws2 = relay.connect().await;
    // A third upgrade from the same IP is refused before the upgrade.
    let status = upgrade_status(relay.addr).await;
    assert!(status.contains("429"), "{status}");
    // Freeing a slot admits the next connection. The release happens
    // when the server task observes the close, so poll briefly.
    drop(ws1);
    let mut status = String::new();
    for _ in 0..30 {
        status = upgrade_status(relay.addr).await;
        if status.contains("101") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(status.contains("101"), "{status}");
    drop(ws2);
    relay.stop().await;
}

#[tokio::test]
async fn connection_cap_total() {
    let mut config = common::config();
    config.relay.max_connections = 1;
    let relay = Relay::start_with(config).await;
    let _ws1 = relay.connect().await;
    let status = upgrade_status(relay.addr).await;
    assert!(status.contains("429"), "{status}");
    relay.stop().await;
}

#[tokio::test]
async fn event_rate_limit_is_per_connection() {
    let mut config = common::config();
    config.relay.rate_limits = nosfry_core::limits::RateLimits::default();
    let relay = Relay::start_with(config).await;

    // Client A floods 500 events: past the 100-event burst the OKs
    // turn `rate-limited:` while the connection stays open.
    let mut a = relay.connect().await;
    let base = now();
    for i in 0..500u64 {
        let ev = common::event(&key(30), 1, base, &json!([]), &format!("a{i}"));
        send_text(&mut a, &event_wire(&ev)).await;
    }
    let (mut accepted, mut limited) = (0usize, 0usize);
    for _ in 0..500 {
        let ok = recv_text(&mut a, T).await;
        if ok.contains("rate-limited: slow down") {
            limited += 1;
        } else {
            accepted += 1;
        }
    }
    assert!(limited > 0, "500 events never hit the rate limit");
    assert!(
        accepted <= 150,
        "burst is 100 plus ~20/s refill while reading: {accepted}"
    );

    // Client B on its own connection keeps a full-rate bucket: it
    // publishes and receives `OK true` and its live subscriber gets
    // the event inside a second.
    let mut b = relay.connect().await;
    send_text(&mut b, &req_wire("sub", "{\"kinds\":[1]}")).await;
    let ev_b = common::event(&key(31), 1, now(), &json!([]), "b");
    let id_b = json(ev_b.json())["id"].clone();
    send_text(&mut b, &event_wire(&ev_b)).await;
    let (mut saw_ok, mut saw_event) = (false, false);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !(saw_ok && saw_event) {
            let frame = ws_recv(&mut b).await;
            match frame[0].as_str() {
                Some("OK") => saw_ok = frame[2].as_bool() == Some(true),
                Some("EVENT") => saw_event = frame[2]["id"] == id_b,
                _ => {}
            }
        }
    })
    .await
    .expect("client B was not served within 1s");
    relay.stop().await;
}

/// Shared per-address EVENT buckets: two connections of one address
/// drain one bucket between them.
#[tokio::test]
async fn ip_rate_limit_shared_across_connections() {
    let mut config = common::config();
    config.relay.rate_limits.ip_events_per_second = 1;
    config.relay.rate_limits.ip_events_burst = 3;
    let relay = Relay::start_with(config).await;
    let mut a = relay.connect().await;
    let mut b = relay.connect().await;
    // The shared burst admits exactly 3 events across both sockets
    // (per-connection buckets are disabled by `common::config`).
    for i in 0..3u64 {
        let ws = if i == 1 { &mut b } else { &mut a };
        let ev = common::event(&key(50), 1, now(), &json!([]), &format!("burst{i}"));
        send_text(ws, &event_wire(&ev)).await;
        assert_eq!(recv_ok(ws, &ev).await[2], true, "burst {i}");
    }
    let ev = common::event(&key(50), 1, now(), &json!([]), "over");
    send_text(&mut b, &event_wire(&ev)).await;
    let ok = recv_ok(&mut b, &ev).await;
    assert_eq!(ok[2], false, "{ok}");
    assert_eq!(ok[3], "rate-limited: slow down");
    relay.stop().await;
}

/// A reconnect cannot buy a fresh address burst: the spent entry
/// survives at count 0 and the next connection reuses its buckets.
#[tokio::test]
async fn ip_rate_limit_survives_reconnect() {
    let mut config = common::config();
    config.relay.metrics = true;
    config.relay.rate_limits.ip_events_per_second = 1;
    config.relay.rate_limits.ip_events_burst = 3;
    let relay = Relay::start_with(config).await;
    {
        let mut a = relay.connect().await;
        for i in 0..3u64 {
            let ev = common::event(&key(51), 1, now(), &json!([]), &format!("x{i}"));
            send_text(&mut a, &event_wire(&ev)).await;
            assert_eq!(recv_ok(&mut a, &ev).await[2], true, "burst {i}");
        }
    }
    // Wait until the relay accounts the close before reconnecting.
    let deadline = Instant::now() + T;
    loop {
        let body = http_get(relay.addr, "/metrics").await;
        if metric_value(&body, "nosfry_connections") == Some(0) {
            break;
        }
        assert!(Instant::now() < deadline, "close was not processed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut b = relay.connect().await;
    let ev = common::event(&key(51), 1, now(), &json!([]), "over");
    send_text(&mut b, &event_wire(&ev)).await;
    let ok = recv_ok(&mut b, &ev).await;
    assert_eq!(ok[2], false, "{ok}");
    assert_eq!(ok[3], "rate-limited: slow down");
    relay.stop().await;
}

async fn ws_recv(ws: &mut yawc::TcpWebSocket) -> Value {
    json(&recv_text(ws, T).await)
}

/// The integer value of one Prometheus series line (`<series> <value>`),
/// matched on the whole label block so `{kind="1"}` cannot match
/// `{kind="11"}`.
fn metric_value(body: &str, series: &str) -> Option<u64> {
    body.lines().find_map(|line| {
        let (head, value) = line.rsplit_once(' ')?;
        (head == series).then(|| value.parse().ok()).flatten()
    })
}

#[tokio::test]
async fn metrics_endpoint_reports_prometheus_series() {
    let mut config = common::config();
    config.relay.metrics = true;
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;

    let ev = common::event(&key(40), 1, now(), &json!([]), "m");
    send_text(&mut ws, &event_wire(&ev)).await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], true);

    send_text(&mut ws, &req_wire("m", "{\"kinds\":[1]}")).await;
    loop {
        let frame = json(&recv_text(&mut ws, T).await);
        assert!(frame[0] == "EVENT" || frame[0] == "EOSE", "{frame}");
        if frame[0] == "EOSE" {
            break;
        }
    }

    let body = http_get(relay.addr, "/metrics").await;
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert!(
        body.contains("content-type: text/plain; version=0.0.4"),
        "{body}"
    );
    assert_eq!(
        metric_value(&body, "nostr_client_messages_total{verb=\"EVENT\"}"),
        Some(1),
        "{body}"
    );
    assert_eq!(
        metric_value(&body, "nostr_client_messages_total{verb=\"REQ\"}"),
        Some(1),
        "{body}"
    );
    assert_eq!(
        metric_value(&body, "nostr_events_total{kind=\"1\"}"),
        Some(1),
        "{body}"
    );
    assert_eq!(
        metric_value(&body, "nostr_relay_messages_total{verb=\"OK\"}"),
        Some(1),
        "{body}"
    );
    assert_eq!(
        metric_value(&body, "nostr_relay_messages_total{verb=\"EOSE\"}"),
        Some(1),
        "{body}"
    );
    // The metrics GET itself is plain HTTP and must not count.
    assert_eq!(metric_value(&body, "nosfry_connections"), Some(1), "{body}");
    relay.stop().await;
}

/// `[relay] max_subscription_bytes_total`: each REQ is charged its
/// filters' `approx_bytes`; over budget the REQ answers `CLOSED
/// blocked: subscription capacity exhausted`, a `CLOSE` frees room,
/// and disconnect drains the shared gauge to zero.
#[tokio::test]
async fn subscription_bytes_budget() {
    let mut config = common::config();
    config.relay.metrics = true;
    let one = nosfry_core::filter::Filter::parse("{\"kinds\":[1]}")
        .unwrap()
        .approx_bytes();
    config.relay.max_subscription_bytes_total = one * 2;
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;

    send_text(&mut ws, &req_wire("s1", "{\"kinds\":[1]}")).await;
    assert_eq!(json(&recv_text(&mut ws, T).await)[0], "EOSE");
    send_text(&mut ws, &req_wire("s2", "{\"kinds\":[1]}")).await;
    assert_eq!(json(&recv_text(&mut ws, T).await)[0], "EOSE");

    send_text(&mut ws, &req_wire("s3", "{\"kinds\":[1]}")).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(
        frame,
        json!(["CLOSED", "s3", "blocked: subscription capacity exhausted"]),
    );

    // A refused sub frees its session slot by itself; CLOSE on a live
    // sub frees the charge, so a fresh REQ now fits.
    send_text(&mut ws, &close_wire("s1")).await;
    send_text(&mut ws, &req_wire("s4", "{\"kinds\":[1]}")).await;
    assert_eq!(json(&recv_text(&mut ws, T).await)[0], "EOSE");

    drop(ws);
    let deadline = Instant::now() + T;
    loop {
        let body = http_get(relay.addr, "/metrics").await;
        if metric_value(&body, "nosfry_subscription_bytes") == Some(0) {
            break;
        }
        assert!(Instant::now() < deadline, "subscription charge leaked");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    relay.stop().await;
}

#[tokio::test]
async fn metrics_endpoint_is_404_by_default() {
    let relay = Relay::start().await;
    let body = http_get(relay.addr, "/metrics").await;
    assert!(body.starts_with("HTTP/1.1 404"), "{body}");
    relay.stop().await;
}

#[tokio::test]
async fn metrics_count_rate_limited_events() {
    let mut config = common::config();
    config.relay.metrics = true;
    config.relay.rate_limits = nosfry_core::limits::RateLimits::default();
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;

    let base = now();
    for i in 0..300u64 {
        let ev = common::event(&key(41), 1, base, &json!([]), &format!("f{i}"));
        send_text(&mut ws, &event_wire(&ev)).await;
    }
    let mut saw_limited = false;
    for _ in 0..300 {
        if recv_text(&mut ws, T).await.contains("rate-limited:") {
            saw_limited = true;
        }
    }
    assert!(saw_limited, "300 events never hit the rate limit");

    let body = http_get(relay.addr, "/metrics").await;
    assert!(
        metric_value(&body, "nosfry_rate_limited_total{verb=\"EVENT\"}").unwrap_or(0) > 0,
        "{body}"
    );
    relay.stop().await;
}

#[tokio::test]
async fn metrics_count_rejected_upgrades() {
    let mut config = common::config();
    config.relay.metrics = true;
    config.relay.max_connections_per_ip = 1;
    let relay = Relay::start_with(config).await;
    let _ws = relay.connect().await;
    let status = upgrade_status(relay.addr).await;
    assert!(status.contains("429"), "{status}");
    let body = http_get(relay.addr, "/metrics").await;
    assert_eq!(
        metric_value(&body, "nosfry_connections_rejected_total"),
        Some(1),
        "{body}"
    );
    assert_eq!(metric_value(&body, "nosfry_connections"), Some(1), "{body}");
    relay.stop().await;
}

// Write-policy plugin tests: real `/bin/sh -c` scripts in tempdirs.

/// The `sed` extraction every test plugin shares: `event.id` is the
/// first field of the canonical event JSON.
const PLUGIN_SED: &str =
    r#"id=$(printf '%s' "$line" | sed -n 's/.*"event":{"id":"\([0-9a-f]\{64\}\)".*/\1/p')"#;

/// A `while read` plugin loop running `body` once per request line.
fn loop_plugin(body: &str) -> String {
    format!("while IFS= read -r line; do\n  {PLUGIN_SED}\n  {body}\ndone\n")
}

/// Write a POSIX `sh` plugin into a tempdir. `/bin/sh -c <path>`
/// execs the file, so it needs the exec bit; the returned dir keeps
/// it alive.
fn write_plugin(script: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.sh");
    std::fs::write(&path, script).unwrap();
    make_executable(&path);
    (dir, path.to_str().unwrap().to_owned())
}

/// `chmod +x` for plugin files.
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).unwrap();
}

/// Relay config with the write-policy plugin enabled.
fn policy_config(plugin: &str, timeout_seconds: u64) -> nosfry::config::Config {
    let mut config = common::config();
    config.relay.write_policy = nosfry::config::WritePolicy {
        plugin: plugin.to_owned(),
        timeout_seconds,
    };
    config
}

/// Receive one frame and assert it is `["OK", <event id>, ...]`.
async fn recv_ok(ws: &mut yawc::TcpWebSocket, event: &Event) -> Value {
    let ok = json(&recv_text(ws, T).await);
    assert_eq!(ok[0], "OK", "{ok}");
    assert_eq!(ok[1], event.id().to_string(), "{ok}");
    ok
}

#[tokio::test]
async fn write_policy_accept_stores_and_delivers() {
    let (_dir, plugin) = write_plugin(&loop_plugin(
        r#"printf '{"id":"%s","action":"accept"}\n' "$id""#,
    ));
    let relay = Relay::start_with(policy_config(&plugin, 10)).await;
    let mut sub = relay.connect().await;
    send_text(&mut sub, &req_wire("s", r#"{"kinds":[1]}"#)).await;
    assert_eq!(json(&recv_text(&mut sub, T).await), json!(["EOSE", "s"]));

    let mut pub_ws = relay.connect().await;
    let ev = common::event(&key(7), 1, now(), &json!([]), "hi");
    send_text(&mut pub_ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut pub_ws, &ev).await[2], true);

    let live = json(&recv_text(&mut sub, T).await);
    assert_eq!(live[0], "EVENT");
    assert_eq!(live[2]["id"], ev.id().to_string());

    let mut query = relay.connect().await;
    send_text(
        &mut query,
        &req_wire("q", &format!(r#"{{"ids":["{}"]}}"#, ev.id())),
    )
    .await;
    assert_eq!(
        json(&recv_text(&mut query, T).await)[2]["id"],
        ev.id().to_string()
    );
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_reject_message_and_default() {
    let (_dir, plugin) = write_plugin(&loop_plugin(
        r#"case "$line" in
    *'"kind":2'*) printf '{"id":"%s","action":"reject"}\n' "$id" ;;
    *) printf '{"id":"%s","action":"reject","msg":"blocked: spam"}\n' "$id" ;;
  esac"#,
    ));
    let relay = Relay::start_with(policy_config(&plugin, 10)).await;
    let mut ws = relay.connect().await;

    let ev = common::event(&key(7), 1, now(), &json!([]), "spam");
    send_text(&mut ws, &event_wire(&ev)).await;
    let ok = recv_ok(&mut ws, &ev).await;
    assert_eq!(
        ok,
        json!(["OK", ev.id().to_string(), false, "blocked: spam"])
    );

    // An absent `msg` falls back to the NIP-01 default reason.
    let ev = common::event(&key(7), 2, now(), &json!([]), "quiet");
    send_text(&mut ws, &event_wire(&ev)).await;
    let ok = recv_ok(&mut ws, &ev).await;
    assert_eq!(
        ok,
        json!([
            "OK",
            ev.id().to_string(),
            false,
            "blocked: rejected by write policy"
        ])
    );
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_shadow_reject() {
    let (_dir, plugin) = write_plugin(&loop_plugin(
        r#"printf '{"id":"%s","action":"shadowReject","msg":"shh"}\n' "$id""#,
    ));
    let relay = Relay::start_with(policy_config(&plugin, 10)).await;
    let mut sub = relay.connect().await;
    send_text(&mut sub, &req_wire("s", r#"{"kinds":[1]}"#)).await;
    assert_eq!(json(&recv_text(&mut sub, T).await), json!(["EOSE", "s"]));

    let mut pub_ws = relay.connect().await;
    let ev = common::event(&key(7), 1, now(), &json!([]), "ghost");
    send_text(&mut pub_ws, &event_wire(&ev)).await;
    assert_eq!(
        recv_ok(&mut pub_ws, &ev).await,
        json!(["OK", ev.id().to_string(), true, "shh"])
    );

    // Not broadcast to the live subscriber and not stored.
    let mut text_frame = None;
    drop(
        tokio::time::timeout(Duration::from_millis(400), async {
            while let Some(frame) = sub.next().await {
                if frame.opcode() == yawc::OpCode::Text {
                    text_frame = Some(String::from_utf8_lossy(frame.payload()).into_owned());
                }
            }
        })
        .await,
    );
    assert!(
        text_frame.is_none(),
        "shadow-rejected event reached a subscriber: {text_frame:?}"
    );
    let ids = req_ids(&mut pub_ws, "q", r#"{"kinds":[1]}"#).await;
    assert!(ids.is_empty(), "{ids:?}");
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_ephemeral_rejected_not_broadcast() {
    let (_dir, plugin) = write_plugin(&loop_plugin(
        r#"case "$line" in
    *'"kind":20000'*) printf '{"id":"%s","action":"reject","msg":"blocked: eph"}\n' "$id" ;;
    *) printf '{"id":"%s","action":"accept"}\n' "$id" ;;
  esac"#,
    ));
    let relay = Relay::start_with(policy_config(&plugin, 10)).await;
    let mut sub = relay.connect().await;
    send_text(&mut sub, &req_wire("s", r#"{"kinds":[20000,20001]}"#)).await;
    assert_eq!(json(&recv_text(&mut sub, T).await), json!(["EOSE", "s"]));

    let mut pub_ws = relay.connect().await;
    let rejected = common::event(&key(8), 20_000, now(), &json!([]), "no");
    send_text(&mut pub_ws, &event_wire(&rejected)).await;
    let ok = recv_ok(&mut pub_ws, &rejected).await;
    assert_eq!(
        ok,
        json!(["OK", rejected.id().to_string(), false, "blocked: eph"])
    );

    let accepted = common::event(&key(8), 20_001, now(), &json!([]), "yes");
    send_text(&mut pub_ws, &event_wire(&accepted)).await;
    assert_eq!(recv_ok(&mut pub_ws, &accepted).await[2], true);

    // Single-stream ordering: had the rejected event been broadcast
    // it would precede the accepted one.
    let live = json(&recv_text(&mut sub, T).await);
    assert_eq!(live[0], "EVENT");
    assert_eq!(live[2]["id"], accepted.id().to_string());
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_timeout_then_fresh_process() {
    let (dir, plugin) = write_plugin("exec sleep 60\n");
    let relay = Relay::start_with(policy_config(&plugin, 1)).await;
    let mut ws = relay.connect().await;

    let ev = common::event(&key(7), 1, now(), &json!([]), "slow");
    let started = Instant::now();
    send_text(&mut ws, &event_wire(&ev)).await;
    let ok = recv_ok(&mut ws, &ev).await;
    assert_eq!(
        ok,
        json!(["OK", ev.id().to_string(), false, "error: internal error"])
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );

    // Fix the plugin at the same path: the next event spawns a fresh
    // process running the new script.
    std::fs::write(
        dir.path().join("policy.sh"),
        loop_plugin(r#"printf '{"id":"%s","action":"accept"}\n' "$id""#),
    )
    .unwrap();
    let ev = common::event(&key(7), 1, now(), &json!([]), "fixed");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_eof_recovers_with_fresh_process() {
    let (_dir, plugin) = write_plugin(&format!(
        "IFS= read -r line\n  {PLUGIN_SED}\n  \
         printf '{{\"id\":\"%s\",\"action\":\"accept\"}}\\n' \"$id\"\n"
    ));
    let relay = Relay::start_with(policy_config(&plugin, 10)).await;
    let mut ws = relay.connect().await;

    // The plugin answers once and exits; the next event discovers the
    // dead child and is rejected, the one after spawns a fresh plugin.
    let ev = common::event(&key(7), 1, now(), &json!([]), "one");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    let ev = common::event(&key(7), 1, now(), &json!([]), "two");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(
        recv_ok(&mut ws, &ev).await,
        json!(["OK", ev.id().to_string(), false, "error: internal error"])
    );
    let ev = common::event(&key(7), 1, now(), &json!([]), "three");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_noise_line_skipped() {
    let (_dir, plugin) = write_plugin(&loop_plugin(
        r#"echo "plugin startup noise"
  printf '{"id":"%s","action":"accept"}\n' "$id""#,
    ));
    let relay = Relay::start_with(policy_config(&plugin, 10)).await;
    let mut ws = relay.connect().await;
    let ev = common::event(&key(7), 1, now(), &json!([]), "hi");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_id_mismatch_is_internal_error() {
    let (_dir, plugin) = write_plugin(&loop_plugin(
        r#"printf '{"id":"0000000000000000000000000000000000000000000000000000000000000000","action":"accept"}\n'"#,
    ));
    let relay = Relay::start_with(policy_config(&plugin, 10)).await;
    let mut ws = relay.connect().await;
    let ev = common::event(&key(7), 1, now(), &json!([]), "hi");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(
        recv_ok(&mut ws, &ev).await,
        json!(["OK", ev.id().to_string(), false, "error: internal error"])
    );
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_mtime_reload() {
    let (dir, plugin) = write_plugin(&loop_plugin(
        r#"printf '{"id":"%s","action":"accept"}\n' "$id""#,
    ));
    let relay = Relay::start_with(policy_config(&plugin, 10)).await;
    let mut ws = relay.connect().await;
    let ev = common::event(&key(7), 1, now(), &json!([]), "before");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);

    // Rewriting a no-space plugin command reloads it on the next event.
    tokio::time::sleep(Duration::from_millis(50)).await;
    std::fs::write(
        dir.path().join("policy.sh"),
        loop_plugin(r#"printf '{"id":"%s","action":"reject","msg":"blocked: reloaded"}\n' "$id""#),
    )
    .unwrap();
    let ev = common::event(&key(7), 1, now(), &json!([]), "after");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(
        recv_ok(&mut ws, &ev).await,
        json!(["OK", ev.id().to_string(), false, "blocked: reloaded"])
    );
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_request_line_shape() {
    /// The plugin protocol's wire shape, for assertions.
    #[derive(serde::Deserialize)]
    struct PluginRequest<'a> {
        #[serde(rename = "type")]
        kind: String,
        #[serde(borrow)]
        event: &'a serde_json::value::RawValue,
        #[serde(rename = "receivedAt")]
        received_at: u64,
        #[serde(rename = "sourceType")]
        source_type: String,
        #[serde(rename = "sourceInfo")]
        source_info: String,
    }

    let dir = tempfile::tempdir().unwrap();
    let seen = dir.path().join("requests.jsonl");
    let plugin = dir.path().join("policy.sh");
    std::fs::write(
        &plugin,
        format!(
            "while IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  \
             {PLUGIN_SED}\n  \
             printf '{{\"id\":\"%s\",\"action\":\"accept\"}}\\n' \"$id\"\ndone\n",
            seen.display()
        ),
    )
    .unwrap();
    make_executable(&plugin);
    let relay = Relay::start_with(policy_config(plugin.to_str().unwrap(), 10)).await;
    let mut ws = relay.connect().await;
    let before = now();
    let ev = common::event(&key(7), 1, now(), &json!([]), "probe");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    relay.stop().await;

    let line = std::fs::read_to_string(&seen).unwrap();
    let request: PluginRequest<'_> = serde_json::from_str(line.trim_end()).unwrap();
    assert_eq!(request.kind, "new");
    // The event is embedded raw: byte-identical to the canonical JSON.
    assert_eq!(request.event.get(), ev.json());
    assert!(request.received_at >= before && request.received_at <= now());
    assert_eq!(request.source_type, "IP4");
    assert_eq!(request.source_info, "127.0.0.1");
}

#[tokio::test]
async fn write_policy_does_not_block_shutdown() {
    let (_dir, plugin) = write_plugin(&loop_plugin(
        r#"printf '{"id":"%s","action":"accept"}\n' "$id""#,
    ));
    let relay = Relay::start_with(policy_config(&plugin, 10)).await;
    let mut ws = relay.connect().await;
    let ev = common::event(&key(7), 1, now(), &json!([]), "hi");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    // `stop` joins `serve()`; a stuck policy task would hang this.
    tokio::time::timeout(T, relay.stop()).await.unwrap();
}

// Config hot-reload tests: `relay.reload(config)` is what the binary
// sends down the channel on SIGHUP. Each reload also bumps
// `relay.info.name`, so the NIP-11 document is the deterministic
// "reload applied" marker for the tests below.

/// Poll `check` until it holds or ~5 s pass (reload is applied by a
/// background task).
async fn wait_until<F, Fut>(mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..100 {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// `relay.info.name` as served by NIP-11 right now.
async fn nip11_name(addr: std::net::SocketAddr) -> String {
    nip11_body(&http_get(addr, "/").await)["name"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A base config with the marker `name` set, so `wait_until` can
/// detect that this exact reload was applied.
fn reload_config(marker: &str) -> nosfry::config::Config {
    let mut config = common::config();
    config.relay.info.name = String::from(marker);
    config
}

#[tokio::test]
async fn reload_updates_nip11() {
    let relay = Relay::start().await;
    assert_eq!(nip11_name(relay.addr).await, "nosfry");
    relay.reload(reload_config("hot reload"));
    assert!(
        wait_until(|| async { nip11_name(relay.addr).await == "hot reload" }).await,
        "NIP-11 never picked up the reload"
    );
    relay.stop().await;
}

#[tokio::test]
async fn reload_enables_policy_on_existing_connection() {
    let (_dir, plugin) = write_plugin(&loop_plugin(
        r#"printf '{"id":"%s","action":"reject","msg":"blocked: nope"}\n' "$id""#,
    ));
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;

    let ev = common::event(&key(7), 1, now(), &json!([]), "before");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);

    // Enable the rejecting plugin: the next event on THIS already-open
    // connection is refused.
    let mut config = reload_config("policy on");
    config.relay.write_policy.plugin = plugin.clone();
    relay.reload(config);
    assert!(wait_until(|| async { nip11_name(relay.addr).await == "policy on" }).await);
    let ev = common::event(&key(7), 1, now(), &json!([]), "during");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(
        recv_ok(&mut ws, &ev).await,
        json!(["OK", ev.id().to_string(), false, "blocked: nope"])
    );

    // Disable it again: the same connection accepts right away.
    relay.reload(reload_config("policy off"));
    assert!(wait_until(|| async { nip11_name(relay.addr).await == "policy off" }).await);
    let ev = common::event(&key(7), 1, now(), &json!([]), "after");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    relay.stop().await;
}

#[tokio::test]
async fn reload_lowers_per_ip_cap() {
    let mut config = common::config();
    config.relay.max_connections_per_ip = 5;
    let relay = Relay::start_with(config).await;
    let mut first = relay.connect().await;
    let _second = relay.connect().await;

    let mut config = reload_config("cap lowered");
    config.relay.max_connections_per_ip = 2;
    relay.reload(config);
    assert!(wait_until(|| async { nip11_name(relay.addr).await == "cap lowered" }).await);

    // The next upgrade is refused; connections already above the
    // lowered cap stay open and usable.
    let status = upgrade_status(relay.addr).await;
    assert!(status.contains("429"), "{status}");
    let ev = common::event(&key(7), 1, now(), &json!([]), "still alive");
    send_text(&mut first, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut first, &ev).await[2], true);
    relay.stop().await;
}

#[tokio::test]
async fn reload_rate_limits_apply_to_new_connections() {
    // `common::config()` disables the buckets; a reload enables a
    // strict one. The existing connection keeps its unlimited
    // session; a fresh connection is limited.
    let relay = Relay::start().await;
    let mut old_ws = relay.connect().await;

    let mut config = reload_config("limits on");
    config.relay.rate_limits = nosfry_core::limits::RateLimits {
        events_per_second: 1,
        events_burst: 1,
        reqs_per_second: 0,
        reqs_burst: 0,
        ip_events_per_second: 0,
        ip_events_burst: 0,
        ip_reqs_per_second: 0,
        ip_reqs_burst: 0,
    };
    relay.reload(config);
    assert!(wait_until(|| async { nip11_name(relay.addr).await == "limits on" }).await);

    for content in ["a", "b", "c"] {
        let ev = common::event(&key(7), 1, now(), &json!([]), content);
        send_text(&mut old_ws, &event_wire(&ev)).await;
        assert_eq!(recv_ok(&mut old_ws, &ev).await[2], true, "{content}");
    }

    let mut new_ws = relay.connect().await;
    let ev = common::event(&key(8), 1, now(), &json!([]), "first");
    send_text(&mut new_ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut new_ws, &ev).await[2], true);
    let ev = common::event(&key(8), 1, now(), &json!([]), "second");
    send_text(&mut new_ws, &event_wire(&ev)).await;
    assert_eq!(
        recv_ok(&mut new_ws, &ev).await,
        json!(["OK", ev.id().to_string(), false, "rate-limited: slow down"])
    );
    relay.stop().await;
}

#[tokio::test]
async fn reload_port_change_is_ignored() {
    let relay = Relay::start().await;
    let mut config = reload_config("port changed");
    config.relay.port = 1;
    relay.reload(config);
    assert!(wait_until(|| async { nip11_name(relay.addr).await == "port changed" }).await);
    // Restart-only fields are kept: the relay still serves on the
    // original port.
    let mut ws = relay.connect().await;
    let ev = common::event(&key(7), 1, now(), &json!([]), "hi");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    relay.stop().await;
}

/// A reload whose merged config fails validation is rejected as a
/// whole: no field — not the NIP-11 name, not the connection caps —
/// is half-applied.
#[tokio::test]
async fn invalid_auth_reload_rejects_everything() {
    let mut config = common::config();
    config.relay.max_connections_per_ip = 2;
    let relay = Relay::start_with(config).await;

    let mut bad = reload_config("must not apply");
    bad.relay.max_connections_per_ip = 1;
    bad.relay.service_url = "http://bad".into();
    relay.reload(bad);
    // Let the reload task consume (and reject) it. The name stays the
    // startup value, and the lowered cap never applies: both checks
    // must run before the sentinel reload below — a valid reload
    // would set the caps again and hide a half-applied `1`.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(nip11_name(relay.addr).await, "nosfry");
    let _first = relay.connect().await;
    let _second = relay.connect().await;

    // The channel kept moving: a valid reload applies afterwards.
    relay.reload(reload_config("sentinel"));
    assert!(wait_until(|| async { nip11_name(relay.addr).await == "sentinel" }).await);
    relay.stop().await;
}

/// `auto_ping_seconds = 0` would panic every connection task; a
/// reload to 0 fails merged-config validation, so nothing applies and
/// the running configuration keeps serving (a later valid reload
/// still lands).
#[tokio::test]
async fn zero_auto_ping_reload_is_rejected() {
    let relay = Relay::start().await;
    let mut bad = reload_config("must not apply");
    bad.relay.auto_ping_seconds = 0;
    relay.reload(bad);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(nip11_name(relay.addr).await, "nosfry");
    relay.reload(reload_config("sentinel"));
    assert!(wait_until(|| async { nip11_name(relay.addr).await == "sentinel" }).await);
    relay.stop().await;
}

/// The binary re-reads its config file on SIGHUP: a broken file logs
/// an error and keeps the running configuration, a fixed one applies.
#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_config_and_ignores_broken() {
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    // Grab a free port for the spawned relay.
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg_path = dir.path().join("nosfry.toml");
    let write_config = |name: &str| {
        std::fs::write(
            &cfg_path,
            format!(
                "[db]\npath = {:?}\n[relay]\nport = {port}\n\
                 [relay.info]\nname = \"{name}\"\n",
                dir.path().join("db")
            ),
        )
        .unwrap();
    };
    write_config("before");
    let err_log = dir.path().join("stderr.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nosfry"))
        .args(["relay", "--config"])
        .arg(&cfg_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&err_log).unwrap()))
        .spawn()
        .unwrap();
    let sighup = |child: &std::process::Child| {
        let status = Command::new("kill")
            .args(["-HUP", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    };
    let up = wait_until(|| async { tokio::net::TcpStream::connect(addr).await.is_ok() }).await;
    assert!(up, "spawned relay never listened");

    // A broken config is logged and ignored.
    std::fs::write(&cfg_path, "not = [valid\n").unwrap();
    sighup(&child);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_ok(),
        "relay died on a broken reload"
    );
    let log = std::fs::read_to_string(&err_log).unwrap();
    assert!(log.contains("config reload failed"), "{log}");
    assert_eq!(nip11_name(addr).await, "before");

    // A fixed config applies on the next SIGHUP.
    write_config("after");
    sighup(&child);
    let applied = wait_until(|| async { nip11_name(addr).await == "after" }).await;
    drop(child.kill());
    drop(child.wait());
    assert!(applied, "SIGHUP never applied the fixed config");
}

/// `["AUTH", <signed 22242>]` answering `challenge` for `relay_url`.
fn auth_wire(keypair: &secp256k1::Keypair, challenge: &str, relay_url: &str) -> String {
    let ev = common::event(
        keypair,
        22_242,
        now(),
        &json!([["challenge", challenge], ["relay", relay_url]]),
        "",
    );
    format!("[\"AUTH\",{}]", ev.json())
}

/// Relay config with NIP-42 enabled.
fn auth_config() -> nosfry::config::Config {
    let mut config = common::config();
    config.relay.service_url = "wss://relay.example.com".into();
    config
}

#[tokio::test]
async fn nip11_lists_42_only_with_auth_service_url() {
    let relay = Relay::start_with(auth_config()).await;
    let text = http_get(relay.addr, "/").await;
    let doc = nip11_body(&text);
    assert_eq!(
        doc["supported_nips"],
        json!([1, 9, 11, 40, 42, 45, 62, 70, 77])
    );
    relay.stop().await;
}

#[tokio::test]
async fn auth_dm_flow_restricts_reads_to_involved() {
    let relay = Relay::start_with(auth_config()).await;
    let url = "wss://relay.example.com";
    // Two stored DMs: key1->key2 and key3->key4.
    let pk2 = faster_hex::hex_string(&key(2).x_only_public_key().0.to_byte_array());
    let pk4 = faster_hex::hex_string(&key(4).x_only_public_key().0.to_byte_array());
    let dm12 = common::event(&key(1), 4, now(), &json!([["p", pk2]]), "for 2");
    let dm34 = common::event(&key(3), 4, now(), &json!([["p", pk4]]), "for 4");
    let id12 = dm12.id().to_string();
    let id34 = dm34.id().to_string();
    let mut pub_ws = relay.connect().await;
    for ev in [&dm12, &dm34] {
        send_text(&mut pub_ws, &event_wire(ev)).await;
        assert_eq!(recv_ok(&mut pub_ws, ev).await[2], true);
    }

    // Unauthenticated REQ for restricted kinds: challenge + CLOSED.
    let mut ws_a = relay.connect().await;
    send_text(&mut ws_a, &req_wire("sub", "{\"kinds\":[4]}")).await;
    let auth = json(&recv_text(&mut ws_a, T).await);
    assert_eq!(auth[0], "AUTH", "{auth}");
    let challenge = auth[1].as_str().unwrap().to_owned();
    let closed = json(&recv_text(&mut ws_a, T).await);
    assert_eq!(closed[0], "CLOSED");
    assert_eq!(
        closed[2],
        "auth-required: requested filter requires authentication"
    );

    // AUTH as key2, then the same REQ returns only DMs involving key2.
    send_text(&mut ws_a, &auth_wire(&key(2), &challenge, url)).await;
    let ok = json(&recv_text(&mut ws_a, T).await);
    assert_eq!(ok[2], true, "{ok}");
    let got = req_ids(&mut ws_a, "sub", "{\"kinds\":[4]}").await;
    assert_eq!(got, vec![id12.clone()], "{got:?}");

    // A third party authed as key3 sees only their own DM.
    let mut ws_b = relay.connect().await;
    send_text(&mut ws_b, &req_wire("probe", "{\"kinds\":[4]}")).await;
    let auth = json(&recv_text(&mut ws_b, T).await);
    let challenge_b = auth[1].as_str().unwrap().to_owned();
    drop(json(&recv_text(&mut ws_b, T).await)); // CLOSED
    send_text(&mut ws_b, &auth_wire(&key(3), &challenge_b, url)).await;
    assert_eq!(json(&recv_text(&mut ws_b, T).await)[2], true);
    let got = req_ids(&mut ws_b, "sub", "{\"kinds\":[4]}").await;
    assert_eq!(got, vec![id34], "{got:?}");

    // A live DM to key2 reaches ws_a's subscription but not ws_b's.
    // OK on the publisher means the batch is already queued at every
    // shard, so ws_b's barrier EOSE proves the probe ran.
    let dm2 = common::event(&key(1), 4, now(), &json!([["p", pk2]]), "live");
    send_text(&mut pub_ws, &event_wire(&dm2)).await;
    assert_eq!(recv_ok(&mut pub_ws, &dm2).await[2], true);
    send_text(&mut ws_b, &req_wire("barrier", "{\"kinds\":[1]}")).await;
    let mut ws_b_events = Vec::new();
    loop {
        let frame = json(&recv_text(&mut ws_b, T).await);
        match frame[0].as_str().unwrap() {
            "EVENT" => ws_b_events.push(frame),
            "EOSE" if frame[1] == "barrier" => break,
            _ => {}
        }
    }
    assert!(
        ws_b_events.is_empty(),
        "uninvolved conn got {ws_b_events:?}"
    );
    let live = json(&recv_text(&mut ws_a, T).await);
    assert_eq!(live[0], "EVENT");
    assert_eq!(live[1], "sub");
    assert_eq!(live[2]["id"], dm2.id().to_string());

    relay.stop().await;
}

#[tokio::test]
async fn protected_event_requires_auth() {
    let relay = Relay::start_with(auth_config()).await;
    let url = "wss://relay.example.com";
    let mut ws = relay.connect().await;
    let protected = common::event(&key(7), 1, now(), &json!([["-"]]), "secret");
    send_text(&mut ws, &event_wire(&protected)).await;
    let auth = json(&recv_text(&mut ws, T).await);
    assert_eq!(auth[0], "AUTH", "{auth}");
    let challenge = auth[1].as_str().unwrap().to_owned();
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[2], false);
    assert_eq!(ok[3], "auth-required: event marked as protected");
    // Authenticate as the author, then the same event is accepted.
    send_text(&mut ws, &auth_wire(&key(7), &challenge, url)).await;
    assert_eq!(json(&recv_text(&mut ws, T).await)[2], true);
    send_text(&mut ws, &event_wire(&protected)).await;
    assert_eq!(recv_ok(&mut ws, &protected).await[2], true);
    let got = req_ids(&mut ws, "s", "{}").await;
    assert_eq!(got, vec![protected.id().to_string()]);
    relay.stop().await;
}

#[tokio::test]
async fn protected_event_blocked_without_auth_service() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let protected = common::event(&key(7), 1, now(), &json!([["-"]]), "secret");
    send_text(&mut ws, &event_wire(&protected)).await;
    let ok = recv_ok(&mut ws, &protected).await;
    assert_eq!(ok[2], false);
    assert_eq!(ok[3], "blocked: event marked as protected");
    relay.stop().await;
}

#[tokio::test]
async fn write_policy_receives_authed_pubkey() {
    let out_file = tempfile::tempdir().unwrap();
    let out_path = out_file.path().join("req.jsonl");
    let (_dir, plugin) = write_plugin(&format!(
        "while IFS= read -r line; do printf '%s\\n' \"$line\" >> {}; printf '{{\"id\":\"%s\",\"action\":\"accept\"}}\\n' \"$(printf '%s' \"$line\" | sed -n 's/.*\"event\":{{\"id\":\"\\([0-9a-f]\\{{64\\}}\\)\".*/\\1/p')\"; done",
        out_path.display()
    ));
    let mut config = policy_config(&plugin, 10);
    config.relay.service_url = "wss://relay.example.com".into();
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;
    // Trigger the challenge with a restricted REQ, then AUTH.
    send_text(&mut ws, &req_wire("x", "{\"kinds\":[4]}")).await;
    let auth = json(&recv_text(&mut ws, T).await);
    let challenge = auth[1].as_str().unwrap().to_owned();
    drop(json(&recv_text(&mut ws, T).await));
    send_text(
        &mut ws,
        &auth_wire(&key(5), &challenge, "wss://relay.example.com"),
    )
    .await;
    assert_eq!(json(&recv_text(&mut ws, T).await)[2], true);
    let ev = common::event(&key(5), 1, now(), &json!([]), "authed publish");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    relay.stop().await;
    let lines = std::fs::read_to_string(&out_path).unwrap();
    let request: Value = serde_json::from_str(lines.trim()).unwrap();
    assert_eq!(
        request["authed"],
        faster_hex::hex_string(&key(5).x_only_public_key().0.to_byte_array())
    );
}

#[tokio::test]
async fn restricted_kinds_stored_but_never_served_by_default() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    // Fully restricted REQ: refused outright, no AUTH (disabled).
    send_text(&mut ws, &req_wire("sub", "{\"kinds\":[4]}")).await;
    let closed = json(&recv_text(&mut ws, T).await);
    assert_eq!(closed[0], "CLOSED");
    assert_eq!(closed[2], "restricted: requested kinds are not served");
    // A kind-4 event is still stored.
    let dm = common::event(&key(8), 4, now(), &json!([]), "dm");
    send_text(&mut ws, &event_wire(&dm)).await;
    assert_eq!(recv_ok(&mut ws, &dm).await[2], true);
    let note = common::event(&key(8), 1, now(), &json!([]), "note");
    send_text(&mut ws, &event_wire(&note)).await;
    assert_eq!(recv_ok(&mut ws, &note).await[2], true);
    // A mixed REQ serves kind 1 but hides the kind 4.
    let got = req_ids(&mut ws, "m", "{\"kinds\":[1,4]}").await;
    assert_eq!(got, vec![note.id().to_string()], "{got:?}");
    relay.stop().await;
}

/// Send a `COUNT` and read its one `["COUNT",<sub>,{..}]` answer body.
async fn recv_count(ws: &mut yawc::TcpWebSocket, sub: &str) -> Value {
    let frame = json(&recv_text(ws, T).await);
    assert_eq!(frame[0], "COUNT", "{frame}");
    assert_eq!(frame[1], sub, "{frame}");
    frame[2].clone()
}

fn pk_hex(n: u8) -> String {
    faster_hex::hex_string(&key(n).x_only_public_key().0.to_byte_array())
}

#[tokio::test]
async fn count_reports_union_once() {
    let relay = Relay::start().await;
    let mut pub_ws = relay.connect().await;
    // key 11: two kind-1s + one kind-3; key 12: one kind-1.
    let events = [
        common::event(&key(11), 1, now(), &json!([]), "a"),
        common::event(&key(11), 1, now(), &json!([]), "b"),
        common::event(&key(12), 1, now(), &json!([]), "c"),
        common::event(&key(11), 3, now(), &json!([]), "d"),
    ];
    for ev in &events {
        send_text(&mut pub_ws, &event_wire(ev)).await;
        assert_eq!(recv_ok(&mut pub_ws, ev).await[2], true);
    }
    let mut ws = relay.connect().await;
    send_text(&mut ws, &count_wire("c", "{\"kinds\":[1]}")).await;
    let body = recv_count(&mut ws, "c").await;
    assert_eq!(body["count"], 3, "{body}");
    assert!(body.get("approximate").is_none(), "{body}");

    // Overlapping filters count each event once: 3 kind-1s plus key
    // 11's kind-3 — not 3 + 3.
    let filters = format!("{{\"kinds\":[1]}},{{\"authors\":[\"{}\"]}}", pk_hex(11));
    send_text(&mut ws, &count_wire("d", &filters)).await;
    assert_eq!(recv_count(&mut ws, "d").await["count"], 4);

    // A filter `limit` is ignored for COUNT.
    send_text(&mut ws, &count_wire("e", "{\"kinds\":[1],\"limit\":1}")).await;
    assert_eq!(recv_count(&mut ws, "e").await["count"], 3);
    relay.stop().await;
}

#[tokio::test]
async fn count_after_ok_includes_the_event() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let ev = common::event(&key(21), 1, now(), &json!([]), "fresh");
    send_text(&mut ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut ws, &ev).await[2], true);
    // Read-your-writes: the COUNT's snapshot covers the acked write.
    send_text(&mut ws, &count_wire("c", "{\"kinds\":[1]}")).await;
    assert_eq!(recv_count(&mut ws, "c").await["count"], 1);
    relay.stop().await;
}

#[tokio::test]
async fn count_excludes_deleted_and_expired() {
    let relay = Relay::start().await;
    let mut pub_ws = relay.connect().await;
    let k = key(31);
    let gone = common::event(&k, 1, now(), &json!([]), "gone");
    let keep = common::event(&k, 1, now(), &json!([]), "keep");
    let expiring = common::event(
        &k,
        1,
        now(),
        &json!([["expiration", (now() + 2).to_string()]]),
        "exp",
    );
    for ev in [&gone, &keep, &expiring] {
        send_text(&mut pub_ws, &event_wire(ev)).await;
        assert_eq!(recv_ok(&mut pub_ws, ev).await[2], true);
    }
    let deletion = common::event(&k, 5, now(), &json!([["e", gone.id().to_string()]]), "");
    send_text(&mut pub_ws, &event_wire(&deletion)).await;
    assert_eq!(recv_ok(&mut pub_ws, &deletion).await[2], true);

    let mut ws = relay.connect().await;
    send_text(&mut ws, &count_wire("c", "{\"kinds\":[1]}")).await;
    assert_eq!(recv_count(&mut ws, "c").await["count"], 2);

    // Past the expiration the event is hidden even before the sweep.
    tokio::time::sleep(Duration::from_secs(3)).await;
    send_text(&mut ws, &count_wire("d", "{\"kinds\":[1]}")).await;
    assert_eq!(recv_count(&mut ws, "d").await["count"], 1);
    relay.stop().await;
}

#[tokio::test]
async fn count_budget_marks_approximate() {
    let mut config = common::config();
    config.relay.limits.max_filter_limit_count = 10;
    let relay = Relay::start_with(config).await;
    let mut pub_ws = relay.connect().await;
    for i in 0..20u64 {
        let ev = common::event(&key(33), 1, now() + i, &json!([]), &format!("e{i}"));
        send_text(&mut pub_ws, &event_wire(&ev)).await;
        assert_eq!(recv_ok(&mut pub_ws, &ev).await[2], true);
    }
    let mut ws = relay.connect().await;
    send_text(&mut ws, &count_wire("c", "{\"kinds\":[1]}")).await;
    let body = recv_count(&mut ws, "c").await;
    assert_eq!(body["approximate"], true, "{body}");
    let partial = body["count"].as_u64().unwrap();
    assert!(partial <= 20, "{body}");
    relay.stop().await;
}

#[tokio::test]
async fn count_disabled_closes_unsupported() {
    let mut config = common::config();
    config.relay.limits.max_filter_limit_count = 0;
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;
    send_text(&mut ws, &count_wire("c", "{\"kinds\":[1]}")).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame, json!(["CLOSED", "c", "unsupported: COUNT"]));
    relay.stop().await;
}

#[tokio::test]
async fn count_respects_the_read_gate() {
    let relay = Relay::start_with(auth_config()).await;
    let url = "wss://relay.example.com";
    // Two stored DMs plus two public notes.
    let dm12 = common::event(&key(1), 4, now(), &json!([["p", pk_hex(2)]]), "for 2");
    let dm34 = common::event(&key(3), 4, now(), &json!([["p", pk_hex(4)]]), "for 4");
    let note = common::event(&key(5), 1, now(), &json!([]), "n1");
    let note2 = common::event(&key(6), 1, now(), &json!([]), "n2");
    let mut pub_ws = relay.connect().await;
    for ev in [&dm12, &dm34, &note, &note2] {
        send_text(&mut pub_ws, &event_wire(ev)).await;
        assert_eq!(recv_ok(&mut pub_ws, ev).await[2], true);
    }

    // Unauthenticated all-restricted COUNT: challenge + CLOSED.
    let mut ws = relay.connect().await;
    send_text(&mut ws, &count_wire("c", "{\"kinds\":[4]}")).await;
    let auth = json(&recv_text(&mut ws, T).await);
    assert_eq!(auth[0], "AUTH", "{auth}");
    let challenge = auth[1].as_str().unwrap().to_owned();
    let closed = json(&recv_text(&mut ws, T).await);
    assert_eq!(
        closed,
        json!([
            "CLOSED",
            "c",
            "auth-required: requested filter requires authentication"
        ])
    );

    // A mixed count sees only what the requester may read.
    send_text(&mut ws, &count_wire("m", "{}")).await;
    assert_eq!(recv_count(&mut ws, "m").await["count"], 2);

    // Authenticated as key 2, only the involved DM is counted.
    send_text(&mut ws, &auth_wire(&key(2), &challenge, url)).await;
    assert_eq!(json(&recv_text(&mut ws, T).await)[2], true);
    send_text(&mut ws, &count_wire("d", "{\"kinds\":[4]}")).await;
    assert_eq!(recv_count(&mut ws, "d").await["count"], 1);
    relay.stop().await;
}

#[tokio::test]
async fn count_hll_matches_local_sketch() {
    let relay = Relay::start().await;
    let target = pk_hex(2);
    let mut pub_ws = relay.connect().await;
    // Three followers tag key 2 in kind-3 contact lists; a kind-1 with
    // the same tag does not match the filter.
    let mut followers = Vec::new();
    for n in [1u8, 3, 5] {
        let ev = common::event(&key(n), 3, now(), &json!([["p", target]]), "");
        send_text(&mut pub_ws, &event_wire(&ev)).await;
        assert_eq!(recv_ok(&mut pub_ws, &ev).await[2], true);
        followers.push(n);
    }
    let stray = common::event(&key(7), 1, now(), &json!([["p", target]]), "");
    send_text(&mut pub_ws, &event_wire(&stray)).await;
    assert_eq!(recv_ok(&mut pub_ws, &stray).await[2], true);

    let mut ws = relay.connect().await;
    let filters = format!("{{\"#p\":[\"{target}\"],\"kinds\":[3]}}");
    send_text(&mut ws, &count_wire("c", &filters)).await;
    let body = recv_count(&mut ws, "c").await;
    assert_eq!(body["count"], 3, "{body}");

    // The relay's hll equals the sketch built locally over the same
    // pubkeys with nosfry-core's Hll.
    let filter = nosfry_core::filter::Filter::parse(&filters).unwrap();
    let mut hll = nosfry_core::hll::Hll::for_filters(&[filter]).unwrap();
    for n in followers {
        hll.add(&nosfry_core::event::PublicKey(
            key(n).x_only_public_key().0.to_byte_array(),
        ));
    }
    assert_eq!(
        body["hll"].as_str().unwrap(),
        faster_hex::hex_string(hll.registers()),
        "{body}"
    );
    relay.stop().await;
}

#[tokio::test]
async fn count_never_answers_for_a_replaced_id() {
    let relay = Relay::start().await;
    let mut pub_ws = relay.connect().await;
    let ev = common::event(&key(41), 1, now(), &json!([]), "x");
    send_text(&mut pub_ws, &event_wire(&ev)).await;
    assert_eq!(recv_ok(&mut pub_ws, &ev).await[2], true);

    let mut ws = relay.connect().await;
    // The REQ re-uses the id: once it is processed the COUNT's
    // generation is stale and its answer must be dropped. The COUNT
    // may legitimately finish and answer before the REQ arrives, so
    // the invariant is ordering: no COUNT frame after any REQ frame.
    send_text(&mut ws, &count_wire("c", "{}")).await;
    send_text(&mut ws, &req_wire("c", "{\"kinds\":[1]}")).await;
    let mut events = 0usize;
    loop {
        let frame = json(&recv_text(&mut ws, T).await);
        match frame[0].as_str().unwrap() {
            "EVENT" => {
                assert_eq!(frame[1], "c", "{frame}");
                events += 1;
            }
            "EOSE" => break,
            "COUNT" => assert_eq!(events, 0, "stale generation answered: {frame}"),
            other => panic!("unexpected frame {other}"),
        }
    }
    assert_eq!(events, 1);
    relay.stop().await;
}

/// `["NEG-OPEN",sub,filter,"<hex>"]`.
fn neg_open_wire(sub: &str, filter: &str, msg: &[u8]) -> String {
    format!(
        "[\"NEG-OPEN\",\"{sub}\",{filter},\"{}\"]",
        faster_hex::hex_string(msg)
    )
}

/// `["NEG-MSG",sub,"<hex>"]`.
fn neg_msg_wire(sub: &str, msg: &[u8]) -> String {
    format!(
        "[\"NEG-MSG\",\"{sub}\",\"{}\"]",
        faster_hex::hex_string(msg)
    )
}

/// Hex-decode a wire payload.
fn unhex(text: &str) -> Vec<u8> {
    let mut buf = vec![0u8; text.len() / 2];
    faster_hex::hex_decode(text.as_bytes(), &mut buf).unwrap();
    buf
}

/// Run one negentropy session against the relay: `NEG-OPEN` plus
/// `NEG-MSG` rounds until `reconcile_with_ids` finishes. Returns
/// `(have, need)` — the ids the client has that the relay lacks
/// (`have`), and the ids the relay has that the client still needs
/// (`need`).
async fn neg_sync(
    ws: &mut yawc::TcpWebSocket,
    sub: &str,
    filter: &str,
    records: &[(u64, [u8; 32])],
) -> (Vec<String>, Vec<String>) {
    use negentropy::{Id, Negentropy, NegentropyStorageVector};
    let mut storage = NegentropyStorageVector::with_capacity(records.len());
    for (created_at, id) in records {
        storage
            .insert(*created_at, Id::from_byte_array(*id))
            .unwrap();
    }
    storage.seal().unwrap();
    let mut neg = Negentropy::borrowed(&storage, 500_000).unwrap();
    let init = neg.initiate().unwrap();
    send_text(ws, &neg_open_wire(sub, filter, &init)).await;
    let mut have_ids = Vec::new();
    let mut need_ids = Vec::new();
    loop {
        let frame = json(&recv_text(ws, T).await);
        assert_eq!(frame[0], "NEG-MSG", "{frame}");
        assert_eq!(frame[1], sub, "{frame}");
        let reply = unhex(frame[2].as_str().unwrap());
        let next = neg
            .reconcile_with_ids(&reply, &mut have_ids, &mut need_ids)
            .unwrap();
        match next {
            Some(msg) => send_text(ws, &neg_msg_wire(sub, &msg)).await,
            None => break,
        }
    }
    let hexes = |ids: Vec<Id>| -> Vec<String> {
        ids.iter()
            .map(|id| faster_hex::hex_string(id.as_bytes()))
            .collect()
    };
    (hexes(have_ids), hexes(need_ids))
}

/// Publish each event over `pub_ws`, asserting `OK true`.
async fn publish_all(pub_ws: &mut yawc::TcpWebSocket, events: &[std::sync::Arc<Event>]) {
    for ev in events {
        send_text(pub_ws, &event_wire(ev)).await;
        assert_eq!(recv_ok(pub_ws, ev).await[2], true, "{ev:?}");
    }
}

/// Both sides hold records the other lacks: after the rounds `have`
/// equals exactly the relay-only ids and `need` the client-only ones.
#[tokio::test]
async fn neg_sync_reports_true_differences() {
    let relay = Relay::start().await;
    let mut pub_ws = relay.connect().await;
    // Relay: 6 shared + 10 relay-only.
    let mut events = Vec::new();
    for i in 0..16u64 {
        events.push(common::event(
            &key(41),
            1,
            now() + i,
            &json!([]),
            &format!("e{i}"),
        ));
    }
    publish_all(&mut pub_ws, &events).await;
    // Client: the 6 shared + 5 fabricated client-only records.
    let mut client: Vec<(u64, [u8; 32])> = events[..6]
        .iter()
        .map(|e| (e.created_at(), e.id().0))
        .collect();
    for i in 0..5u64 {
        let mut id = [0xabu8; 32];
        id[..8].copy_from_slice(&(i + 1).to_be_bytes());
        client.push((now() + 100 + i, id));
    }
    let mut relay_only: Vec<String> = events[6..].iter().map(|e| e.id().to_string()).collect();
    let mut client_only: Vec<String> = client[6..]
        .iter()
        .map(|(_, id)| faster_hex::hex_string(id))
        .collect();
    let mut ws = relay.connect().await;
    let (mut have, mut need) = neg_sync(&mut ws, "s", "{}", &client).await;
    have.sort_unstable();
    need.sort_unstable();
    relay_only.sort_unstable();
    client_only.sort_unstable();
    assert_eq!(have, client_only, "client-has wrong");
    assert_eq!(need, relay_only, "client-needs wrong");
    relay.stop().await;
}

/// A filter `limit` bounds the synced set like it bounds a REQ.
#[tokio::test]
async fn neg_open_honors_filter_limit() {
    let relay = Relay::start().await;
    let mut pub_ws = relay.connect().await;
    let mut events = Vec::new();
    for i in 0..10u64 {
        events.push(common::event(
            &key(42),
            1,
            now() + i,
            &json!([]),
            &format!("e{i}"),
        ));
    }
    publish_all(&mut pub_ws, &events).await;
    let mut ws = relay.connect().await;
    // Newest-first, like a REQ: the 3 highest created_at.
    let (have, mut need) = neg_sync(&mut ws, "s", "{\"limit\":3}", &[]).await;
    let mut expected: Vec<String> = events[7..].iter().map(|e| e.id().to_string()).collect();
    need.sort_unstable();
    expected.sort_unstable();
    assert_eq!(need, expected, "{need:?}");
    assert_eq!(have, Vec::<String>::new());
    relay.stop().await;
}

/// Over `max_sync_events` the relay answers `blocked:` with the
/// configured cap as the fourth frame element.
#[tokio::test]
async fn neg_over_max_sync_events_is_blocked() {
    let mut config = common::config();
    config.relay.limits.max_sync_events = 2;
    let relay = Relay::start_with(config).await;
    let mut pub_ws = relay.connect().await;
    let mut events = Vec::new();
    for i in 0..5u64 {
        events.push(common::event(
            &key(43),
            1,
            now() + i,
            &json!([]),
            &format!("e{i}"),
        ));
    }
    publish_all(&mut pub_ws, &events).await;
    let mut ws = relay.connect().await;
    // Any initial message reaches the same blocked path.
    send_text(&mut ws, &neg_open_wire("s", "{}", &[0x61])).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(
        frame,
        json!(["NEG-ERR", "s", "blocked: too many query results", 2]),
        "{frame}"
    );
    // The sync is closed: a NEG-MSG answers `closed:`.
    send_text(&mut ws, &neg_msg_wire("s", &[0x61])).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame[2], "closed: unknown subscription", "{frame}");
    relay.stop().await;
}

/// Past the sync-memory budget the answer is `blocked: sync capacity
/// exhausted`.
#[tokio::test]
async fn neg_over_sync_memory_budget_is_blocked() {
    let mut config = common::config();
    // Two records cost 80 bytes; the budget admits only one.
    config.relay.max_sync_memory_bytes = 40;
    let relay = Relay::start_with(config).await;
    let mut pub_ws = relay.connect().await;
    let mut events = Vec::new();
    for i in 0..2u64 {
        events.push(common::event(
            &key(44),
            1,
            now() + i,
            &json!([]),
            &format!("e{i}"),
        ));
    }
    publish_all(&mut pub_ws, &events).await;
    let mut ws = relay.connect().await;
    send_text(&mut ws, &neg_open_wire("s", "{}", &[0x61])).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(
        frame,
        json!(["NEG-ERR", "s", "blocked: sync capacity exhausted"]),
        "{frame}"
    );
    relay.stop().await;
}

/// Restricted kinds are hidden from an unauthenticated sync: DMs are
/// not reported as relay-has.
#[tokio::test]
async fn neg_restricted_kinds_hidden_from_unauthenticated() {
    let relay = Relay::start_with(auth_config()).await;
    let mut pub_ws = relay.connect().await;
    let dm = common::event(&key(1), 4, now(), &json!([["p", pk_hex(2)]]), "dm");
    let note = common::event(&key(5), 1, now(), &json!([]), "n1");
    let note2 = common::event(&key(6), 1, now(), &json!([]), "n2");
    publish_all(
        &mut pub_ws,
        &[
            dm,
            std::sync::Arc::clone(&note),
            std::sync::Arc::clone(&note2),
        ],
    )
    .await;
    let mut ws = relay.connect().await;
    let (have, mut need) = neg_sync(&mut ws, "s", "{}", &[]).await;
    let mut expected: Vec<String> = [&note, &note2].iter().map(|e| e.id().to_string()).collect();
    expected.sort_unstable();
    need.sort_unstable();
    assert_eq!(need, expected, "{need:?}");
    assert_eq!(have, Vec::<String>::new());
    relay.stop().await;
}

/// `NEG-CLOSE` then `NEG-MSG` answers `closed: unknown subscription`.
#[tokio::test]
async fn neg_close_then_msg_is_closed() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    send_text(&mut ws, &neg_open_wire("s", "{}", &[0x61])).await;
    // The initial reconcile answer arrives; the session exists.
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame[0], "NEG-MSG", "{frame}");
    send_text(&mut ws, "[\"NEG-CLOSE\",\"s\"]").await;
    send_text(&mut ws, &neg_msg_wire("s", &[0x61])).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(
        frame,
        json!(["NEG-ERR", "s", "closed: unknown subscription"]),
        "{frame}"
    );
    relay.stop().await;
}

/// Re-opening the same id replaces the sync: the second storage's
/// records drive the answers, not the first's.
#[tokio::test]
async fn neg_reopen_replaces_the_session() {
    let relay = Relay::start().await;
    let mut pub_ws = relay.connect().await;
    let note = common::event(&key(46), 1, now(), &json!([]), "kind1");
    let other = common::event(&key(46), 7, now(), &json!([]), "kind7");
    publish_all(&mut pub_ws, &[note, std::sync::Arc::clone(&other)]).await;
    let mut ws = relay.connect().await;
    send_text(&mut ws, &neg_open_wire("s", "{\"kinds\":[1]}", &[0x61])).await;
    // The first session's answer arrives; re-opening replaces it and
    // `is_current_neg` gates any further stale-generation output.
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame[0], "NEG-MSG", "{frame}");
    let (have, need) = neg_sync(&mut ws, "s", "{\"kinds\":[7]}", &[]).await;
    assert_eq!(need, [other.id().to_string()], "{need:?}");
    assert_eq!(have, Vec::<String>::new());
    relay.stop().await;
}

/// `max_sync_events = 0` refuses `NEG-OPEN` as unsupported.
#[tokio::test]
async fn neg_disabled_is_unsupported() {
    let mut config = common::config();
    config.relay.limits.max_sync_events = 0;
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;
    send_text(&mut ws, &neg_open_wire("s", "{}", &[0x61])).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(
        frame,
        json!(["NEG-ERR", "s", "unsupported: negentropy sync"]),
        "{frame}"
    );
    relay.stop().await;
}

/// A malformed `NEG-MSG` answers `invalid:` and drops the session: a
/// later `NEG-MSG` is `closed:`.
#[tokio::test]
async fn neg_malformed_msg_is_invalid() {
    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    send_text(&mut ws, &neg_open_wire("s", "{}", &[0x61])).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame[0], "NEG-MSG", "{frame}");
    // A version byte outside 0x60-0x6f fails the protocol.
    send_text(&mut ws, &neg_msg_wire("s", &[0x50])).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(
        frame,
        json!(["NEG-ERR", "s", "invalid: malformed negentropy message"]),
        "{frame}"
    );
    send_text(&mut ws, &neg_msg_wire("s", &[0x61])).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame[2], "closed: unknown subscription", "{frame}");
    relay.stop().await;
}

// NIP-62 request to vanish: end-to-end over the wire.

/// A config with a `service_url` so vanish requests can name this
/// relay, and no restricted read kinds so REQs see gift wraps too.
fn vanish_config() -> nosfry::config::Config {
    let mut config = auth_config();
    config.relay.auth.restricted_read_kinds = vec![];
    config
}

/// REQ `{}` until exactly `want` ids are served or the bound expires;
/// the vanish sweep runs on the writer, so the client may observe the
/// pre-sweep set for a few polls.
async fn settled_ids(ws: &mut yawc::TcpWebSocket, sub: &str, want: &mut Vec<String>) {
    want.sort_unstable();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut got = req_ids(ws, sub, "{}").await;
        got.sort_unstable();
        if got == *want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expected {want:?}, still {got:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn nip62_vanish_deletes_covered_events_and_blocks_republish() {
    let relay = Relay::start_with(vanish_config()).await;
    let mut ws = relay.connect().await;
    let (author, other) = (key(60), key(61));
    let t = now();
    // Everything of the author's at or before the request's
    // `created_at` vanishes — notes, replaceables, and addressables —
    // as do gift wraps `p`-tagged to the author in the window.
    let note = common::event(&author, 1, t - 10, &json!([]), "gone");
    let article = common::event(&author, 30023, t - 5, &json!([["d", "x"]]), "gone too");
    let wrap = common::event(&other, 1059, t - 3, &json!([["p", pk_hex(60)]]), "sealed");
    let keep = common::event(&other, 1, t - 4, &json!([]), "untouched");
    for ev in [&note, &article, &wrap, &keep] {
        send_text(&mut ws, &event_wire(ev)).await;
        assert_eq!(recv_ok(&mut ws, ev).await[2], true);
    }
    let vanish = common::event(
        &author,
        62,
        t,
        &json!([["relay", "wss://relay.example.com"]]),
        "bye",
    );
    send_text(&mut ws, &event_wire(&vanish)).await;
    assert_eq!(recv_ok(&mut ws, &vanish).await[2], true);
    let late = common::event(&author, 1, t + 10, &json!([]), "after");
    send_text(&mut ws, &event_wire(&late)).await;
    assert_eq!(recv_ok(&mut ws, &late).await[2], true);

    let mut want = vec![
        vanish.id().to_string(),
        late.id().to_string(),
        keep.id().to_string(),
    ];
    settled_ids(&mut ws, "v", &mut want).await;

    // Republishing a vanished event is refused.
    send_text(&mut ws, &event_wire(&note)).await;
    let ok = recv_ok(&mut ws, &note).await;
    assert_eq!(ok[2], false);
    assert_eq!(ok[3], "blocked: request to vanish", "{ok}");
    relay.stop().await;
}

#[tokio::test]
async fn nip62_vanish_bypasses_write_policy() {
    let (_dir, plugin) = write_plugin(&loop_plugin(
        r#"printf '{"id":"%s","action":"reject","msg":"nope"}\n' "$id""#,
    ));
    let mut config = policy_config(&plugin, 10);
    config.relay.service_url = "wss://relay.example.com".into();
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;
    let author = key(62);
    // The plugin vetoes an ordinary event …
    let note = common::event(&author, 1, now(), &json!([]), "vetoed");
    send_text(&mut ws, &event_wire(&note)).await;
    let ok = recv_ok(&mut ws, &note).await;
    assert_eq!(ok[2], false);
    // … but a request to vanish naming this relay MUST be accepted
    // (NIP-62), while one naming only another relay still goes through
    // the plugin.
    let vanish = common::event(
        &author,
        62,
        now(),
        &json!([["relay", "wss://relay.example.com"]]),
        "bye",
    );
    send_text(&mut ws, &event_wire(&vanish)).await;
    assert_eq!(recv_ok(&mut ws, &vanish).await[2], true);
    let foreign = common::event(
        &author,
        62,
        now() + 1,
        &json!([["relay", "wss://other.example.com"]]),
        "not here",
    );
    send_text(&mut ws, &event_wire(&foreign)).await;
    assert_eq!(recv_ok(&mut ws, &foreign).await[2], false);
    relay.stop().await;
}

/// A NIP-86 management POST; returns `(status, response body)`.
async fn http_post(
    addr: std::net::SocketAddr,
    body: &str,
    auth: Option<&str>,
    content_type: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(auth) = auth {
        request.push_str("Authorization: ");
        request.push_str(auth);
        request.push_str("\r\n");
    }
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(body);
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        body.to_owned(),
    )
}

/// One raw HTTP request; returns `(status, response head, body)`.
/// `request` is the head through the blank line, `body` the bytes
/// that follow it.
async fn http_raw(addr: std::net::SocketAddr, request: &str, body: &str) -> (u16, String, String) {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(format!("{request}{body}").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        head.to_owned(),
        body.to_owned(),
    )
}

/// CORS on the browser-facing surface: the preflight advertises POST
/// and Authorization (the Fetch wildcard never covers
/// `Authorization`), and every NIP-86 answer — 401 and 200 — carries
/// `access-control-allow-origin: *`.
#[tokio::test]
async fn cors_preflight_and_management() {
    let admin = key(9);
    let relay = Relay::start_with(mgmt_config(&admin)).await;

    let (status, head, _) = http_raw(
        relay.addr,
        "OPTIONS / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        "",
    )
    .await;
    assert_eq!(status, 204, "{head}");
    for want in [
        "access-control-allow-origin: *",
        "access-control-allow-methods: GET, POST, OPTIONS",
        "access-control-allow-headers: Authorization, *",
        "access-control-max-age: 86400",
    ] {
        assert!(head.contains(want), "{want} missing: {head}");
    }

    let body = json!({"method": "supportedmethods", "params": []}).to_string();
    let request = |auth: Option<&str>| {
        let mut request = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            nosfry_core::management::CONTENT_TYPE,
            body.len()
        );
        if let Some(auth) = auth {
            request.push_str("Authorization: ");
            request.push_str(auth);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request
    };
    let (status, head, _) = http_raw(relay.addr, &request(None), &body).await;
    assert_eq!(status, 401, "{head}");
    assert!(head.contains("access-control-allow-origin: *"), "{head}");
    let (status, head, _) =
        http_raw(relay.addr, &request(Some(&nip98(&admin, &body))), &body).await;
    assert_eq!(status, 200, "{head}");
    assert!(head.contains("access-control-allow-origin: *"), "{head}");
    relay.stop().await;
}

/// A NIP-98 `Authorization` value over `body` signed by `key`; the
/// `u` tag normalizes to `relay.example.com` — the `service_url`
/// every management test configures.
fn nip98(k: &secp256k1::Keypair, body: &str) -> String {
    let payload = faster_hex::hex_string(&sha2::Sha256::digest(body.as_bytes()));
    let tags = json!([
        ["u", "http://relay.example.com/"],
        ["method", "POST"],
        ["payload", payload],
    ]);
    auth_b64(&common::event(k, 27235, now(), &tags, ""))
}

/// `Nostr <base64>` for an auth event.
fn auth_b64(event: &Event) -> String {
    use base64::Engine as _;
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(event.json())
    )
}

/// An authorized management call; asserts HTTP 200 and returns the
/// `{"result"|"error"}` object.
async fn rpc(
    relay: &Relay,
    key: &secp256k1::Keypair,
    method: &str,
    params: Value,
    headers: &[(&str, &str)],
) -> Value {
    let body = json!({"method": method, "params": params}).to_string();
    let auth = nip98(key, &body);
    let (status, text) = http_post(
        relay.addr,
        &body,
        Some(&auth),
        "application/nostr+json+rpc",
        headers,
    )
    .await;
    assert_eq!(status, 200, "{method}: {text}");
    serde_json::from_str(&text).unwrap()
}

/// Send an event and read its `OK` (live subs may interleave EVENT
/// frames); returns the reply frame.
async fn publish(ws: &mut yawc::TcpWebSocket, event: &Event) -> Value {
    send_text(ws, &event_wire(event)).await;
    loop {
        let frame = json(&recv_text(ws, T).await);
        if frame[0] == "OK" {
            return frame;
        }
    }
}

/// The pubkey hex of a test keypair.
fn pubkey_hex(keypair: &secp256k1::Keypair) -> String {
    keypair.x_only_public_key().0.to_string()
}

/// A relay config with NIP-86 enabled for `admin` and the
/// `relay.example.com` service URL `nip98` signs against.
fn mgmt_config(admin: &secp256k1::Keypair) -> nosfry::config::Config {
    let mut config = common::config();
    config.relay.service_url = "wss://relay.example.com".into();
    config.relay.management.admins = vec![pubkey_hex(admin)];
    config
}

#[tokio::test]
async fn nip86_pubkey_event_and_kind_moderation() {
    let admin = key(9);
    let relay = Relay::start_with(mgmt_config(&admin)).await;
    let mut ws = relay.connect().await;
    let (a, b) = (key(1), key(2));
    let (pk_a, pk_b) = (pubkey_hex(&a), pubkey_hex(&b));

    // `supportedmethods` is exactly the implemented set.
    let res = rpc(&relay, &admin, "supportedmethods", json!([]), &[]).await;
    assert_eq!(
        res["result"],
        json!([
            "allowkind",
            "allowpubkey",
            "banevent",
            "banpubkey",
            "blockip",
            "changerelaydescription",
            "changerelayicon",
            "changerelayname",
            "disallowkind",
            "listallowedkinds",
            "listallowedpubkeys",
            "listbannedevents",
            "listbannedpubkeys",
            "listblockedips",
            "listdisallowedkinds",
            "supportedmethods",
            "unallowpubkey",
            "unbanevent",
            "unbanpubkey",
            "unblockip",
        ])
    );

    let note = common::event(&a, 1, now(), &json!([]), "a1");
    assert_eq!(publish(&mut ws, &note).await[2], true);

    // banpubkey → author blocked (stored and ephemeral); b unaffected.
    let res = rpc(&relay, &admin, "banpubkey", json!([pk_a, "spam"]), &[]).await;
    assert_eq!(res["result"], true);
    let banned = common::event(&a, 1, now(), &json!([]), "a2");
    let ok = publish(&mut ws, &banned).await;
    assert_eq!(
        (ok[2].as_bool(), ok[3].as_str()),
        (Some(false), Some("blocked: pubkey not allowed"))
    );
    let eph = common::event(&a, 20000, now(), &json!([]), "e");
    let ok = publish(&mut ws, &eph).await;
    assert_eq!(ok[3], "blocked: pubkey not allowed");
    let note_b = common::event(&b, 1, now(), &json!([]), "b1");
    assert_eq!(publish(&mut ws, &note_b).await[2], true);
    let res = rpc(&relay, &admin, "listbannedpubkeys", json!([]), &[]).await;
    assert_eq!(res["result"], json!([{ "pubkey": pk_a, "reason": "spam" }]));
    // unbanpubkey → a publishes again.
    rpc(&relay, &admin, "unbanpubkey", json!([pk_a]), &[]).await;
    let freed = common::event(&a, 1, now(), &json!([]), "a3");
    assert_eq!(publish(&mut ws, &freed).await[2], true);

    // Allow-list mode: only listed authors publish.
    rpc(&relay, &admin, "allowpubkey", json!([pk_b, "vip"]), &[]).await;
    let denied = common::event(&a, 1, now(), &json!([]), "a4");
    assert_eq!(
        publish(&mut ws, &denied).await[3],
        "blocked: pubkey not allowed"
    );
    let allowed = common::event(&b, 1, now(), &json!([]), "b2");
    assert_eq!(publish(&mut ws, &allowed).await[2], true);
    let res = rpc(&relay, &admin, "listallowedpubkeys", json!([]), &[]).await;
    assert_eq!(res["result"], json!([{ "pubkey": pk_b, "reason": "vip" }]));
    rpc(&relay, &admin, "unallowpubkey", json!([pk_b]), &[]).await;
    let free = common::event(&a, 1, now(), &json!([]), "a5");
    assert_eq!(publish(&mut ws, &free).await[2], true);

    // banevent: the stored event disappears from REQ and its
    // republish is blocked.
    send_text(
        &mut ws,
        &req_wire("s", &format!("{{\"authors\":[\"{pk_a}\"]}}")),
    )
    .await;
    let mut before = Vec::new();
    loop {
        let frame = json(&recv_text(&mut ws, T).await);
        if frame[0] == "EVENT" {
            before.push(frame[2]["id"].as_str().unwrap().to_owned());
        } else {
            break;
        }
    }
    assert!(before.contains(&note.id().to_string()), "{before:?}");
    let res = rpc(
        &relay,
        &admin,
        "banevent",
        json!([note.id().to_string(), "bad"]),
        &[],
    )
    .await;
    assert_eq!(res["result"], true);
    send_text(
        &mut ws,
        &req_wire("s2", &format!("{{\"authors\":[\"{pk_a}\"]}}")),
    )
    .await;
    let mut after = Vec::new();
    loop {
        let frame = json(&recv_text(&mut ws, T).await);
        if frame[0] == "EVENT" {
            after.push(frame[2]["id"].as_str().unwrap().to_owned());
        } else {
            break;
        }
    }
    assert!(!after.contains(&note.id().to_string()), "{after:?}");
    assert!(after.contains(&freed.id().to_string()));
    let ok = publish(&mut ws, &note).await;
    assert_eq!(
        (ok[2].as_bool(), ok[3].as_str()),
        (Some(false), Some("blocked: event banned"))
    );
    let res = rpc(&relay, &admin, "listbannedevents", json!([]), &[]).await;
    assert_eq!(
        res["result"],
        json!([{ "id": note.id().to_string(), "reason": "bad" }])
    );
    // unbanevent → republish stores again.
    rpc(
        &relay,
        &admin,
        "unbanevent",
        json!([note.id().to_string()]),
        &[],
    )
    .await;
    let ok = publish(&mut ws, &note).await;
    assert_eq!(ok[2], true);

    // disallowkind blocks the kind; allowkind both clears it and
    // switches to allow-list mode.
    let dm = common::event(&a, 4, now(), &json!([["p", pk_b]]), "dm");
    rpc(&relay, &admin, "disallowkind", json!([4]), &[]).await;
    let ok = publish(&mut ws, &dm).await;
    assert_eq!(
        (ok[2].as_bool(), ok[3].as_str()),
        (Some(false), Some("blocked: kind not allowed"))
    );
    let res = rpc(&relay, &admin, "listdisallowedkinds", json!([]), &[]).await;
    assert_eq!(res["result"], json!([4]));
    rpc(&relay, &admin, "allowkind", json!([4]), &[]).await;
    let ok = publish(&mut ws, &dm).await;
    assert_eq!(ok[2], true);
    let res = rpc(&relay, &admin, "listallowedkinds", json!([]), &[]).await;
    assert_eq!(res["result"], json!([4]));
    let off = common::event(&a, 7, now(), &json!([]), "off list");
    let ok = publish(&mut ws, &off).await;
    assert_eq!(ok[3], "blocked: kind not allowed");
    relay.stop().await;
}

/// Bans and disallowed kinds hide already-stored events at read
/// time — REQ and COUNT stop serving them until the entry is lifted.
#[tokio::test]
async fn nip86_moderation_hides_stored_events() {
    let admin = key(9);
    let relay = Relay::start_with(mgmt_config(&admin)).await;
    let mut ws = relay.connect().await;
    let (a, b) = (key(1), key(2));
    let pk_a = pubkey_hex(&a);

    let a1 = common::event(&a, 1, now(), &json!([]), "a1");
    let a2 = common::event(&a, 1, now(), &json!([]), "a2");
    let b1 = common::event(&b, 1, now(), &json!([]), "b1");
    for ev in [&a1, &a2, &b1] {
        assert_eq!(publish(&mut ws, ev).await[2], true);
    }
    let authors_a = format!("{{\"authors\":[\"{pk_a}\"]}}");
    assert_eq!(req_ids(&mut ws, "s", &authors_a).await.len(), 2);
    send_text(&mut ws, &count_wire("c", &authors_a)).await;
    assert_eq!(recv_count(&mut ws, "c").await["count"], 2);

    rpc(&relay, &admin, "banpubkey", json!([pk_a]), &[]).await;
    // Hidden, not deleted: a's stored events vanish from REQ and
    // COUNT; b's note still serves.
    let hidden = req_ids(&mut ws, "s2", &authors_a).await;
    assert!(hidden.is_empty(), "{hidden:?}");
    send_text(&mut ws, &count_wire("c2", &authors_a)).await;
    assert_eq!(recv_count(&mut ws, "c2").await["count"], 0);
    assert_eq!(req_ids(&mut ws, "s3", "{\"kinds\":[1]}").await.len(), 1);

    rpc(&relay, &admin, "unbanpubkey", json!([pk_a]), &[]).await;
    assert_eq!(req_ids(&mut ws, "s4", &authors_a).await.len(), 2);

    // disallowkind hides stored events of the kind; allowkind moves
    // to allow-list mode and serves kind 1 again.
    rpc(&relay, &admin, "disallowkind", json!([1]), &[]).await;
    let hidden = req_ids(&mut ws, "s5", "{\"kinds\":[1]}").await;
    assert!(hidden.is_empty(), "{hidden:?}");
    rpc(&relay, &admin, "allowkind", json!([1]), &[]).await;
    assert_eq!(req_ids(&mut ws, "s6", &authors_a).await.len(), 2);
    relay.stop().await;
}

#[tokio::test]
async fn nip86_ip_block_and_relay_info() {
    let admin = key(9);
    let mut config = mgmt_config(&admin);
    config.relay.real_ip_header = "x-forwarded-for".into();
    let relay = Relay::start_with(config).await;
    // The management caller keeps a distinct apparent IP so blocking
    // the socket peer still allows unblock calls.
    let admin_ip: &[(&str, &str)] = &[("x-forwarded-for", "10.0.0.9")];

    // NIP-86 info ops take precedence in the NIP-11 document.
    assert_eq!(
        rpc(
            &relay,
            &admin,
            "changerelayname",
            json!(["ops relay"]),
            admin_ip
        )
        .await["result"],
        true
    );
    rpc(
        &relay,
        &admin,
        "changerelaydescription",
        json!(["managed"]),
        admin_ip,
    )
    .await;
    rpc(
        &relay,
        &admin,
        "changerelayicon",
        json!(["https://x/i.png"]),
        admin_ip,
    )
    .await;
    let doc = nip11_body(&http_get(relay.addr, "/").await);
    assert_eq!(doc["name"], "ops relay");
    assert_eq!(doc["description"], "managed");
    assert_eq!(doc["icon"], "https://x/i.png");
    assert!(doc["supported_nips"].to_string().contains("86"));

    // blockip: new requests from the peer get 403 — the upgrade and
    // NIP-11/management paths share the same gate — while requests
    // carrying a different real-IP header still work.
    assert_eq!(
        rpc(
            &relay,
            &admin,
            "blockip",
            json!(["127.0.0.1", "scanner"]),
            admin_ip
        )
        .await["result"],
        true
    );
    let res = rpc(&relay, &admin, "listblockedips", json!([]), admin_ip).await;
    assert_eq!(
        res["result"],
        json!([{ "ip": "127.0.0.1", "reason": "scanner" }])
    );
    let upgrade = http_get(relay.addr, "/").await;
    assert!(upgrade.starts_with("HTTP/1.1 403"), "{upgrade}");
    let (status, _) = http_post(
        relay.addr,
        r#"{"method":"supportedmethods","params":[]}"#,
        None,
        "application/nostr+json+rpc",
        &[],
    )
    .await;
    assert_eq!(status, 403);
    // unblockip restores access.
    assert_eq!(
        rpc(&relay, &admin, "unblockip", json!(["127.0.0.1"]), admin_ip).await["result"],
        true
    );
    let doc = nip11_body(&http_get(relay.addr, "/").await);
    assert_eq!(doc["name"], "ops relay");
    relay.stop().await;
}

/// The served NIP-11 `limitation.restricted_writes` follows the
/// allow-lists: every `allow*`/`unallow*` op rebuilds the cached
/// document when the flag flips.
#[tokio::test]
async fn nip11_restricted_writes_follows_allow_lists() {
    let admin = key(9);
    let relay = Relay::start_with(mgmt_config(&admin)).await;
    let pk = pubkey_hex(&key(1));
    let restricted = |doc: &Value| doc["limitation"]["restricted_writes"].as_bool().unwrap();

    assert!(!restricted(&nip11_body(&http_get(relay.addr, "/").await)));
    rpc(&relay, &admin, "allowpubkey", json!([pk, "vip"]), &[]).await;
    assert!(restricted(&nip11_body(&http_get(relay.addr, "/").await)));
    rpc(&relay, &admin, "unallowpubkey", json!([pk]), &[]).await;
    assert!(!restricted(&nip11_body(&http_get(relay.addr, "/").await)));
    relay.stop().await;
}

/// Concurrent management ops commit in order and publish snapshots
/// in commit order: after 50 joined `allowpubkey` calls the hot-path
/// snapshot contains every key — `listallowedpubkeys` sees all of
/// them and the publish gate applies the union.
#[tokio::test]
async fn nip86_concurrent_ops_publish_in_order() {
    let admin = key(9);
    let relay = Relay::start_with(mgmt_config(&admin)).await;
    let pks: Vec<String> = (1..=50).map(|i| pubkey_hex(&key(i))).collect();
    futures_util::future::join_all(
        pks.iter()
            .map(|pk| rpc(&relay, &admin, "allowpubkey", json!([pk]), &[])),
    )
    .await;

    let list = rpc(&relay, &admin, "listallowedpubkeys", json!([]), &[]).await;
    assert_eq!(list["result"].as_array().unwrap().len(), 50, "{list}");

    let mut ws = relay.connect().await;
    let allowed = common::event(&key(1), 1, now(), &json!([]), "vip note");
    let frame = publish(&mut ws, &allowed).await;
    assert_eq!(frame[2], true, "{frame}");
    let intruder = common::event(&key(51), 1, now(), &json!([]), "intruder");
    let frame = publish(&mut ws, &intruder).await;
    assert_eq!(frame[2], false);
    assert!(
        frame[3]
            .as_str()
            .unwrap()
            .starts_with("blocked: pubkey not allowed"),
        "{frame}"
    );
    relay.stop().await;
}

#[tokio::test]
async fn nip86_auth_failures() {
    let admin = key(9);
    let relay = Relay::start_with(mgmt_config(&admin)).await;
    let body = json!({"method": "supportedmethods", "params": []}).to_string();
    let rpc_ct = "application/nostr+json+rpc";

    // Missing/invalid authorization, bad base64.
    assert_eq!(http_post(relay.addr, &body, None, rpc_ct, &[]).await.0, 401);
    assert_eq!(
        http_post(relay.addr, &body, Some("Bearer xyz"), rpc_ct, &[])
            .await
            .0,
        401
    );
    assert_eq!(
        http_post(relay.addr, &body, Some("Nostr !!!"), rpc_ct, &[])
            .await
            .0,
        401
    );

    let check = |auth: String, name: &'static str| {
        let body = body.clone();
        let addr = relay.addr;
        async move {
            let (status, _) = http_post(addr, &body, Some(&auth), rpc_ct, &[]).await;
            assert_eq!(status, 401, "{name}");
        }
    };
    let digest = faster_hex::hex_string(&sha2::Sha256::digest(body.as_bytes()));

    // Wrong kind, stale timestamp, wrong method, missing/wrong
    // payload, wrong `u`, non-admin signer.
    let wrong_kind = common::event(
        &admin,
        1,
        now(),
        &json!([
            ["u", "http://relay.example.com/"],
            ["method", "POST"],
            ["payload", digest]
        ]),
        "",
    );
    check(auth_b64(&wrong_kind), "kind").await;
    let stale = common::event(
        &admin,
        27235,
        now() - 3600,
        &json!([
            ["u", "http://relay.example.com/"],
            ["method", "POST"],
            ["payload", digest]
        ]),
        "",
    );
    check(auth_b64(&stale), "stale").await;
    let get = common::event(
        &admin,
        27235,
        now(),
        &json!([
            ["u", "http://relay.example.com/"],
            ["method", "GET"],
            ["payload", digest]
        ]),
        "",
    );
    check(auth_b64(&get), "method").await;
    let no_payload = common::event(
        &admin,
        27235,
        now(),
        &json!([["u", "http://relay.example.com/"], ["method", "POST"]]),
        "",
    );
    check(auth_b64(&no_payload), "no payload").await;
    let bad_payload = common::event(
        &admin,
        27235,
        now(),
        &json!([
            ["u", "http://relay.example.com/"],
            ["method", "POST"],
            ["payload", "00".repeat(32)]
        ]),
        "",
    );
    check(auth_b64(&bad_payload), "payload").await;
    let wrong_u = common::event(
        &admin,
        27235,
        now(),
        &json!([
            ["u", "http://other.example.com/"],
            ["method", "POST"],
            ["payload", digest]
        ]),
        "",
    );
    check(auth_b64(&wrong_u), "u").await;
    let stranger = nip98(&key(8), &body);
    check(stranger, "non-admin").await;
    // Bad signature: corrupt the last nibble of `sig`.
    let mut doc = json(
        common::event(
            &admin,
            27235,
            now(),
            &json!([
                ["u", "http://relay.example.com/"],
                ["method", "POST"],
                ["payload", digest]
            ]),
            "",
        )
        .json(),
    );
    let sig = doc["sig"].as_str().unwrap().to_owned();
    let flipped = if sig.ends_with('0') { '1' } else { '0' };
    doc["sig"] = json!(format!("{}{}", &sig[..sig.len() - 1], flipped));
    check(auth_b64_str(&doc.to_string()), "signature").await;

    // Valid auth proves the wiring (the failures above are not a
    // generic reject).
    let (status, _) = http_post(relay.addr, &body, Some(&nip98(&admin, &body)), rpc_ct, &[]).await;
    assert_eq!(status, 200);

    // Unknown method → 200 with `{"error"}`, bad params likewise.
    let res = rpc(&relay, &admin, "frobnicate", json!([]), &[]).await;
    assert_eq!(res["error"], "unsupported method: frobnicate");
    let res = rpc(&relay, &admin, "banpubkey", json!(["not-hex"]), &[]).await;
    assert!(res["error"].as_str().unwrap().starts_with("invalid params"));

    // Oversized body → 413 (route layer, before auth).
    let big = "x".repeat(70_000);
    assert_eq!(http_post(relay.addr, &big, None, rpc_ct, &[]).await.0, 413);

    // Wrong content type falls through to the pre-NIP-86 behavior.
    assert_eq!(
        http_post(relay.addr, &body, None, "application/json", &[])
            .await
            .0,
        405
    );
    relay.stop().await;
}

/// `Nostr <base64>` for a raw event JSON string (possibly tampered).
fn auth_b64_str(event_json: &str) -> String {
    use base64::Engine as _;
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(event_json)
    )
}

#[tokio::test]
async fn nip86_absent_without_admins() {
    let relay = Relay::start().await;
    let body = json!({"method": "supportedmethods", "params": []}).to_string();
    let (status, _) = http_post(relay.addr, &body, None, "application/nostr+json+rpc", &[]).await;
    assert_eq!(status, 405);
    let doc = nip11_body(&http_get(relay.addr, "/").await);
    assert!(!doc["supported_nips"].to_string().contains("86"));
    relay.stop().await;
}

/// `[relay.filter_validation]`: a REQ violating the rules answers
/// `CLOSED blocked:` and registers nothing — the same id still opens
/// a valid subscription afterwards.
#[tokio::test]
async fn filter_validation_refuses_req() {
    let mut config = common::config();
    config.relay.filter_validation.enabled = true;
    let relay = Relay::start_with(config).await;
    let mut ws = relay.connect().await;

    send_text(&mut ws, "[\"REQ\",\"s\",{},{},{},{}]").await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(
        frame,
        json!(["CLOSED", "s", "blocked: invalid number of filters: 4"]),
        "{frame}"
    );
    send_text(&mut ws, &req_wire("s", "{\"kinds\":[1]}")).await;
    let frame = json(&recv_text(&mut ws, T).await);
    assert_eq!(frame, json!(["EOSE", "s"]), "{frame}");
    relay.stop().await;
}

/// A `MakeWriter` collecting formatted log lines into a shared buffer.
#[derive(Clone)]
struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A rejected EVENT produces a `nosfry::ingest` DEBUG line carrying
/// the OK-false frame. The relay logs on spawned tasks, so the
/// capture needs a global subscriber (a scoped thread-local default
/// would miss them); only this test installs one.
#[tokio::test]
async fn ingest_logs_rejected_ok() {
    let sink = LogSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
    let dispatch: tracing::Dispatch = tracing_subscriber::fmt()
        .with_env_filter("nosfry::ingest=debug")
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish()
        .into();
    tracing::dispatcher::set_global_default(dispatch)
        .expect("no other test installs a global subscriber");

    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    let ev = common::event(&key(13), 1, now(), &json!([]), "bad");
    let mut doc = json(ev.json());
    doc["sig"] = json!("00".repeat(64));
    send_text(
        &mut ws,
        &format!("[\"EVENT\",{}]", serde_json::to_string(&doc).unwrap()),
    )
    .await;
    let ok = json(&recv_text(&mut ws, T).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], false);
    let id = doc["id"].as_str().unwrap().to_owned();

    // The ingest line is emitted just after the OK frame is sent.
    let want = format!("[\"OK\",\"{id}\",false");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let logged = {
            let buf = sink
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let text = String::from_utf8_lossy(&buf).into_owned();
            drop(buf);
            text.contains("nosfry::ingest") && text.contains(&want)
        };
        if logged {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no ingest line containing {want}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    relay.stop().await;
}

/// A superseded kind-62 is answered `duplicate: have a newer version`
/// and never replaces the stored newest request.
#[tokio::test]
async fn nip62_older_vanish_request_is_duplicate() {
    let relay = Relay::start_with(vanish_config()).await;
    let mut ws = relay.connect().await;
    let author = key(60);
    let tag = json!([["relay", "wss://relay.example.com"]]);
    let newer = common::event(&author, 62, now(), &tag, "new");
    let older = common::event(&author, 62, now() - 10, &tag, "old");
    assert_eq!(publish(&mut ws, &newer).await[2], true);
    let ok = publish(&mut ws, &older).await;
    assert_eq!(
        (ok[2].as_bool(), ok[3].as_str()),
        (Some(false), Some("duplicate: have a newer version"))
    );
    relay.stop().await;
}

/// A superseded request to vanish is still honored: the newer stored
/// request naming another relay is bookkeeping only (NIP-62 MUST).
#[tokio::test]
async fn nip62_superseded_vanish_request_is_still_honored() {
    let relay = Relay::start_with(vanish_config()).await;
    let mut ws = relay.connect().await;
    let author = key(60);
    let note = common::event(&author, 1, now(), &json!([]), "note");
    publish(&mut ws, &note).await;
    // A newer request naming another relay stores fine (bookkeeping).
    let foreign = common::event(
        &author,
        62,
        now() + 100,
        &json!([["relay", "wss://other.example"]]),
        "",
    );
    let foreign_id = foreign.id().to_string();
    assert_eq!(publish(&mut ws, &foreign).await[2], true);
    // The older request naming this relay is superseded but honored.
    let honored = common::event(
        &author,
        62,
        now(),
        &json!([["relay", "wss://relay.example.com"]]),
        "",
    );
    let ok = publish(&mut ws, &honored).await;
    assert_eq!(
        (ok[2].as_bool(), ok[3].as_str()),
        (Some(false), Some("duplicate: have a newer version"))
    );
    // The covered note is swept despite the superseded write.
    let mut want = vec![foreign_id];
    settled_ids(&mut ws, "s", &mut want).await;
    relay.stop().await;
}
