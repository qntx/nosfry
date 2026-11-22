//! Connection-log attribution: every line a connection emits carries
//! its `conn{id peer}` span, and refusals log the peer before the
//! span exists. Own test binary so a global subscriber is safe;
//! tests serialize on `LOCK` and each asserts only on the log slice
//! appended during its own scenario.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    unused_crate_dependencies,
    reason = "tests may panic on failure paths; deps cover every test binary"
)]

mod common;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use common::{Relay, default_profile};

/// Both tests share the one global subscriber; `LOCK` serializes them
/// so their log windows never interleave.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

/// `MakeWriter` appending every formatted line to `BUF`.
#[derive(Clone)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

/// Install the subscriber once and hand out the shared buffer.
fn log_buf() -> &'static Arc<Mutex<Vec<u8>>> {
    BUF.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        tracing_subscriber::fmt()
            .with_env_filter("info,nosfry::conn=debug,nosfry::inbound=trace")
            .with_writer(BufWriter(Arc::clone(&buf)))
            .with_ansi(false)
            .init();
        buf
    })
}

/// Poll until `pred` holds for the text appended since `start`, or
/// panic after ~5 s. Returns the matching slice.
async fn wait_for(buf: &Mutex<Vec<u8>>, start: usize, pred: impl Fn(&str) -> bool) -> String {
    for _ in 0..500 {
        {
            let text = String::from_utf8(buf.lock().unwrap()[start..].to_vec()).unwrap();
            if pred(&text) {
                return text;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let text = String::from_utf8(buf.lock().unwrap()[start..].to_vec()).unwrap();
    panic!("timed out waiting for the log; got:\n{text}");
}

/// A connection's open, inbound, and closed lines all carry its
/// `conn{id peer}` span with one id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_lines_carry_the_conn_span() {
    let _g = LOCK.lock().await;
    let buf = log_buf();
    let start = buf.lock().unwrap().len();

    let relay = Relay::start().await;
    let mut ws = relay.connect().await;
    common::send_text(&mut ws, "[\"NOPE\"]").await;
    common::send_text(&mut ws, "[\"REQ\",\"s\",{\"limit\":1}]").await;
    let _eose = common::recv_text(&mut ws, Duration::from_secs(5)).await;
    drop(ws);

    let text = wait_for(buf, start, |t| {
        t.contains("connection open") && t.contains("connection closed")
    })
    .await;

    let open = text
        .lines()
        .find(|l| l.contains("connection open"))
        .unwrap();
    let id = open
        .split("conn{id=")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_else(|| panic!("connection open lacks conn{{id}}: {open}"));
    let span = format!("conn{{id={id} peer=127.0.0.1}}");
    assert!(
        open.contains(&span),
        "open line should carry {span}: {open}"
    );

    let closed = text
        .lines()
        .find(|l| l.contains("connection closed"))
        .unwrap();
    assert!(
        closed.contains(&span) && closed.contains("reason=") && closed.contains("duration_ms="),
        "closed line should carry {span}, a reason and duration_ms: {closed}"
    );

    for line in text
        .lines()
        .filter(|l| l.contains("nosfry::conn:") || l.contains("nosfry::inbound:"))
    {
        assert!(
            line.contains(&span),
            "every conn/inbound line should carry {span}: {line}"
        );
    }

    relay.stop().await;
}

/// A connection refused by the cap logs `peer` even though the `conn`
/// span does not exist yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cap_refusal_logs_the_peer() {
    let _g = LOCK.lock().await;
    let buf = log_buf();
    let start = buf.lock().unwrap().len();

    let mut config = common::config();
    default_profile(&mut config).max_connections_per_peer = 1;
    let relay = Relay::start_with(config).await;
    let _ws = relay.connect().await;
    let url = format!("ws://{}/", relay.addr);
    let refused = yawc::WebSocket::connect(url.parse().unwrap()).await;
    assert!(refused.is_err(), "second connection must be refused");

    let text = wait_for(buf, start, |t| t.contains("connection cap reached")).await;
    let line = text
        .lines()
        .find(|l| l.contains("connection cap reached"))
        .unwrap();
    assert!(
        line.contains("peer=127.0.0.1"),
        "cap refusal should name the peer: {line}"
    );

    relay.stop().await;
}

/// A unix listener trusting `real_ip_header` warns once per minute
/// when requests lack or mangle it; the client-controlled header
/// value never reaches the log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_ip_fallback_warns_once_without_the_value() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _g = LOCK.lock().await;
    let buf = log_buf();
    let start = buf.lock().unwrap().len();

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("relay.sock");
    let mut config = common::config();
    config.relay.listen = vec![common::unix_listen(&sock)];
    config.relay.listen[0].real_ip_header = "x-real-ip".to_owned();
    let relay = Relay::start_with(config).await;

    // Two requests that cannot resolve a real IP: the first warns,
    // the second is throttled inside the minute.
    for extra in ["", "x-real-ip: not-an-ip-198.51.100.7\r\n"] {
        let mut io = tokio::net::UnixStream::connect(&sock).await.unwrap();
        io.write_all(format!("GET / HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            io.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
    }
    // Give the second request's (suppressed) warning decision time to
    // land in the buffer before counting.
    let _ = wait_for(buf, start, |t| {
        t.contains("real_ip_header missing or unparsable")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let text = String::from_utf8(buf.lock().unwrap()[start..].to_vec()).unwrap();
    let warns: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("real_ip_header missing or unparsable"))
        .collect();
    assert_eq!(warns.len(), 1, "warn once per listener: {text}");
    assert!(
        warns[0].contains("x-real-ip") && warns[0].contains("unix:"),
        "warn names the header and listener: {}",
        warns[0]
    );
    assert!(
        !text.contains("198.51.100.7"),
        "client-controlled value must never be logged: {text}"
    );

    relay.stop().await;
}
