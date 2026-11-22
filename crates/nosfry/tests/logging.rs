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
        closed.contains(&span) && closed.contains("reason="),
        "closed line should carry {span} and a reason: {closed}"
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
