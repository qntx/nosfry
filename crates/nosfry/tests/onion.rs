//! Embedded onion listener end-to-end over the real Tor network.
//! Ignored by default — it bootstraps Arti and polls the service's
//! reachability for up to five minutes:
//!
//! ```sh
//! cargo test -p nosfry --features onion --test onion -- --ignored --nocapture
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::print_stderr,
    unused_crate_dependencies,
    reason = "tests may panic on failure paths; deps cover every test binary"
)]

mod common;

use std::time::{Duration, Instant};

use futures_util::{SinkExt as _, StreamExt as _};
use nosfry::config::{Listen, ListenAddress};
use nosfry_core::sign;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

/// `tempdir` roots are `0755` on Unix: the relay's state-dir check
/// and Arti's fs-mistrust both demand `0700`.
#[cfg(unix)]
fn tighten(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// No permission model to tighten off-Unix.
#[cfg(not(unix))]
fn tighten(_: &std::path::Path) {}

/// One HTTP GET over clearnet TCP, returning the raw response text.
async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

/// Read an HTTP response's head (`\r\n\r\n` boundary) off a Tor
/// stream; a terminating read error once the head is complete is
/// tolerated — Tor streams report close differently than TCP.
async fn read_head(io: &mut (impl AsyncReadExt + Unpin), deadline: Instant) -> String {
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        assert!(Instant::now() < deadline, "timed out awaiting a response");
        match io.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => head.extend_from_slice(&buf[..n]),
            Err(err) if head.windows(4).any(|w| w == b"\r\n\r\n") => {
                eprintln!("read after head ended with {err}; accepting");
                break;
            }
            Err(err) => panic!("stream read failed: {err}"),
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// The next text frame's payload, skipping pings and pongs.
async fn ws_text<S>(ws: &mut yawc::WebSocket<S>) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let frame = ws.next().await.unwrap();
        if frame.opcode() == yawc::OpCode::Text {
            return std::str::from_utf8(frame.payload()).unwrap().to_owned();
        }
    }
}

/// A WebSocket round-trip over a second Tor stream: NIP-42 AUTH
/// naming the onion URL, a publish, then a REQ returning the event.
async fn ws_roundtrip(
    io: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    url: &str,
    deadline: Instant,
) {
    let mut ws = yawc::WebSocket::handshake(url.parse().unwrap(), io, yawc::Options::default())
        .await
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Trigger the AUTH challenge with a restricted REQ, then answer
    // it with a relay tag naming the onion URL.
    ws.send(yawc::Frame::text(
        "[\"REQ\",\"probe\",{\"kinds\":[4]}]".to_owned(),
    ))
    .await
    .unwrap();
    let challenge = loop {
        let value: serde_json::Value = serde_json::from_str(&ws_text(&mut ws).await).unwrap();
        if value[0] == "AUTH" {
            break value[1].as_str().unwrap().to_owned();
        }
    };
    let auth = sign::event(
        &sign::key(1),
        22_242,
        now,
        &serde_json::json!([["challenge", challenge], ["relay", url]]),
        "",
    );
    ws.send(yawc::Frame::text(format!("[\"AUTH\",{}]", auth.json())))
        .await
        .unwrap();
    let note = sign::event(&sign::key(1), 1, now, &serde_json::json!([]), "over tor");
    let note_id = note.id().to_string();
    ws.send(yawc::Frame::text(format!("[\"EVENT\",{}]", note.json())))
        .await
        .unwrap();
    // Wait for this publish's OK — the AUTH one may arrive first — or
    // the REQ can beat the writer.
    loop {
        let text = ws_text(&mut ws).await;
        if !text.starts_with("[\"OK\"") {
            continue;
        }
        assert!(text.contains("true"), "{text}");
        if text.contains(&note_id) {
            break;
        }
    }
    ws.send(yawc::Frame::text("[\"REQ\",\"s\",{}]".to_owned()))
        .await
        .unwrap();
    let mut saw_event = false;
    while Instant::now() < deadline {
        let text = ws_text(&mut ws).await;
        saw_event |= text.starts_with("[\"EVENT\"");
        if text.starts_with("[\"EOSE\"") {
            break;
        }
    }
    assert!(saw_event, "REQ returned no stored event");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the Tor network: cargo test -p nosfry --features onion --test onion -- --ignored --nocapture"]
async fn onion_listener_end_to_end() {
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();

    // A TCP listener plus one embedded onion service, no
    // `service_url` — the derived onion URL becomes canonical and
    // AUTH is on.
    let mut config = common::config();
    config.db.path = db.path().to_path_buf();
    config.relay.listen = vec![
        common::tcp_listen(),
        Listen {
            address: ListenAddress::Onion("e2e".to_owned()),
            profile: "default".to_owned(),
            real_ip_header: String::new(),
        },
    ];
    config.relay.onion.state_dir = dir.path().to_path_buf();
    tighten(dir.path());

    let url = nosfry::onion::addresses(&config).unwrap()[0].clone();
    let host = url.strip_prefix("ws://").unwrap().to_owned();
    eprintln!("onion url: {url}");

    let listeners = nosfry::bind(&config).await.unwrap();
    let addr = listeners[0].local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let (_reload_tx, reload_rx) = tokio::sync::watch::channel(config.clone());
    // The run uses a fresh `state_dir`: cold relay identity, cold
    // descriptor publication.
    eprintln!("RELAY_STATE=cold");
    let serve_started = Instant::now();
    let serve = tokio::spawn(nosfry::serve(
        config.clone(),
        listeners,
        async {
            stop_rx.await.ok();
        },
        reload_rx,
    ));

    // The clearnet listener answers immediately — Tor bootstrap must
    // not block it.
    let head = http_get(addr, "/").await;
    assert!(head.contains("application/nostr+json"), "{head}");

    // A client-side Arti in its own state dir connects to the
    // service; publishing can take minutes on a cold descriptor.
    let client_dir = tempfile::tempdir().unwrap();
    tighten(client_dir.path());
    std::fs::create_dir_all(client_dir.path().join("state")).unwrap();
    std::fs::create_dir_all(client_dir.path().join("cache")).unwrap();
    tighten(&client_dir.path().join("state"));
    tighten(&client_dir.path().join("cache"));
    let client_cfg = arti_client::config::TorClientConfigBuilder::from_directories(
        client_dir.path().join("state"),
        client_dir.path().join("cache"),
    )
    .build()
    .unwrap();
    let client_started = Instant::now();
    let client = arti_client::TorClient::builder()
        .config(client_cfg)
        .create_bootstrapped()
        .await
        .unwrap();
    eprintln!(
        "CLIENT_BOOTSTRAP_SECS={}",
        client_started.elapsed().as_secs()
    );

    let deadline = Instant::now() + Duration::from_secs(300);
    let mut stream = loop {
        match client.connect((host.as_str(), 80u16)).await {
            Ok(stream) => break stream,
            Err(err) => {
                assert!(
                    Instant::now() < deadline,
                    "onion unreachable after {}s since serve: {err}",
                    serve_started.elapsed().as_secs()
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    eprintln!(
        "ONION_REACHABLE_SECS_SINCE_SERVE={}",
        serve_started.elapsed().as_secs()
    );

    // NIP-11 over the onion stream.
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let onion_head = read_head(&mut stream, deadline).await;
    assert!(onion_head.starts_with("HTTP/1.1 200"), "{onion_head}");
    assert!(
        onion_head.contains("application/nostr+json"),
        "{onion_head}"
    );
    drop(stream);

    let io = client.connect((host.as_str(), 80u16)).await.unwrap();
    ws_roundtrip(io, &url, deadline).await;
    eprintln!(
        "ONION_WS_SECS_SINCE_SERVE={}",
        serve_started.elapsed().as_secs()
    );

    // Shutdown, then re-derive the address from the same state dir:
    // the identity is stable.
    drop(stop_tx);
    serve.await.unwrap().unwrap();
    let again = nosfry::onion::addresses(&config).unwrap();
    assert_eq!(again[0], url);
    eprintln!("TOTAL_SECS={}", started.elapsed().as_secs());
}
