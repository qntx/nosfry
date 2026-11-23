//! `nosfry sync` over Tor end-to-end: the peer is reachable only
//! through its embedded onion service. Ignored by default — it
//! bootstraps two Arti clients and a fresh onion service can need
//! minutes to publish its descriptor:
//!
//! ```sh
//! cargo test -p nosfry --features onion --test onion_sync -- --ignored --nocapture
//! ```
//!
//! Every relay runs as the real `nosfry` binary: each process owns
//! its LMDB env and Arti state lock exactly like production. Peer B's
//! relay keeps running during the sync, so the sync process's Arti
//! takes the shared `[relay.onion] state_dir` read-only — the path an
//! operator hits running `nosfry sync` next to a live relay.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::print_stderr,
    clippy::too_many_lines,
    unused_crate_dependencies,
    reason = "tests may panic on failure paths; deps cover every test binary"
)]

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::json;

/// The `nosfry` binary under test.
const BIN: &str = env!("CARGO_BIN_EXE_nosfry");
/// Small LMDB map so several processes share the machine's memory.
const MAP_SIZE: usize = 1 << 30;
/// Retry budget for the sync: a fresh onion service takes minutes to
/// upload its descriptor, and every attempt is a full `sync` run.
const BUDGET: Duration = Duration::from_secs(360);
/// Pause between failed sync attempts.
const RETRY: Duration = Duration::from_secs(15);

/// `tempdir` roots are `0755` on Unix: the relay's state-dir check
/// and Arti's fs-mistrust both demand `0700`.
fn tighten(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// A state dir Arti's fs-mistrust accepts, created `0700`.
fn state_dir(root: &Path) -> PathBuf {
    let dir = root.join("onion-state");
    std::fs::create_dir(&dir).unwrap();
    tighten(&dir);
    dir
}

/// Write a `nosfry.toml`: db path, the given `[[relay.listen]]`
/// addresses, and `[relay.onion] state_dir`.
fn write_config(dir: &Path, db: &Path, listeners: &[&str], state: &Path) -> PathBuf {
    let mut text = format!(
        "[db]\npath = {:?}\nmap_size = {MAP_SIZE}\n",
        db.display().to_string()
    );
    for addr in listeners {
        write!(
            text,
            "[[relay.listen]]\naddress = \"{addr}\"\nprofile = \"default\"\nreal_ip_header = \"\"\n"
        )
        .unwrap();
    }
    write!(
        text,
        "[relay.onion]\nstate_dir = {:?}\n",
        state.display().to_string()
    )
    .unwrap();
    let path = dir.join("nosfry.toml");
    std::fs::write(&path, text).unwrap();
    path
}

/// `n` signed kind-1 events under key `key_n`, JSONL on disk for
/// `nosfry import`.
fn corpus(path: &Path, n: usize, key_n: u8) -> BTreeSet<String> {
    let base = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 30_000;
    let mut text = String::new();
    let mut ids = BTreeSet::new();
    for i in 0..n {
        let event = common::event(
            &common::key(key_n),
            1,
            base + i as u64,
            &json!([]),
            &format!("onion sync {key_n}/{i}"),
        );
        ids.insert(event.id().to_string());
        writeln!(text, "{}", event.json()).unwrap();
    }
    std::fs::write(path, text).unwrap();
    ids
}

/// The `nosfry` binary, `--config` first, piped stderr so retries
/// can quote the tail.
fn nosfry(config: &Path, args: &[&str]) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(BIN);
    cmd.arg("--config").arg(config).args(args);
    cmd
}

/// `nosfry relay` stderr goes to a log file.
fn spawn_relay(config: &Path, err_log: &Path) -> tokio::process::Child {
    nosfry(config, &["relay"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(err_log).unwrap()))
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

/// Import `corpus` (JSONL) into the store `config` points at.
async fn import(config: &Path, corpus: &Path) {
    let output = nosfry(config, &["import"])
        .stdin(Stdio::from(std::fs::File::open(corpus).unwrap()))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "import {} failed: {}",
        corpus.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `nosfry onion address`'s single URL line.
async fn onion_address(config: &Path) -> String {
    let output = nosfry(config, &["onion", "address"])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "onion address failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let url = stdout.trim();
    assert!(
        stdout.lines().count() == 1
            && url
                .strip_prefix("ws://")
                .and_then(|host| host.strip_suffix(".onion"))
                .is_some_and(|label| label.len() == 56),
        "unexpected onion address output: {stdout:?}"
    );
    url.to_owned()
}

/// `--events-only` export ids of every stored event.
async fn exported_ids(config: &Path) -> BTreeSet<String> {
    let output = nosfry(config, &["export", "--events-only"])
        .output()
        .await
        .unwrap();
    assert!(output.status.success(), "export failed");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// SIGTERM `child` and require a clean exit.
async fn stop(child: tokio::process::Child, name: &str) {
    let killed = std::process::Command::new("kill")
        .args(["-TERM", &child.id().unwrap().to_string()])
        .status()
        .unwrap();
    assert!(killed.success(), "kill -TERM {name} failed");
    let status = child.wait_with_output().await.unwrap().status;
    assert!(status.success(), "{name} exited {status} on SIGTERM");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the Tor network: cargo test -p nosfry --features onion --test onion_sync -- --ignored --nocapture"]
async fn sync_over_onion() {
    let started = Instant::now();
    let root = tempfile::tempdir().unwrap();
    tighten(root.path());
    let dir_a = root.path().join("a");
    let dir_b = root.path().join("b");
    std::fs::create_dir(&dir_a).unwrap();
    std::fs::create_dir(&dir_b).unwrap();
    tighten(&dir_a);
    tighten(&dir_b);

    // A is reachable only over its onion service: the sole listener.
    let cfg_a = write_config(&dir_a, &dir_a.join("db"), &["onion:a"], &state_dir(&dir_a));
    // B has the usual TCP+onion pair; its running relay holds the
    // Arti lock the sync process then shares read-only.
    let cfg_b = write_config(
        &dir_b,
        &dir_b.join("db"),
        &["127.0.0.1:0", "onion:b"],
        &state_dir(&dir_b),
    );

    let corpus_a = root.path().join("a.jsonl");
    let corpus_b = root.path().join("b.jsonl");
    let ids_a = corpus(&corpus_a, 500, 1);
    let ids_b = corpus(&corpus_b, 200, 2);
    import(&cfg_a, &corpus_a).await;
    import(&cfg_b, &corpus_b).await;

    // The address is stable before A starts: the key lives on disk.
    let url_a = onion_address(&cfg_a).await;
    eprintln!("A's onion URL: {url_a}");

    let relay_a = spawn_relay(&cfg_a, &dir_a.join("relay.log"));
    let relay_b = spawn_relay(&cfg_b, &dir_b.join("relay.log"));
    // Relay B's Arti takes the state lock when its bootstrap starts,
    // which logs progress; only then is the sync the second process.
    let log_b = dir_b.join("relay.log");
    while !std::fs::read_to_string(&log_b)
        .unwrap_or_default()
        .contains("tor bootstrap")
    {
        assert!(
            started.elapsed() < BUDGET,
            "relay B never started its Tor bootstrap"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eprintln!("relay B bootstrapping after {:?}", started.elapsed());

    // Fresh descriptors take minutes to reach the HSDirs; retry the
    // whole sync until one run exits 0 or the budget is spent.
    let args = ["sync", url_a.as_str(), "--dir", "both", "--timeout", "120"];
    let mut attempt = 0u32;
    let mut read_only = false;
    let sync_done = loop {
        attempt += 1;
        let t = Instant::now();
        let output = nosfry(&cfg_b, &args)
            .env("RUST_LOG", "info")
            .output()
            .await
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        // arti-client logs this when relay B already holds the state
        // lock: the shared-state path this test exists for.
        for line in stderr.lines().filter(|l| l.contains("read-only mode")) {
            eprintln!("    sync: {line}");
            read_only = true;
        }
        eprintln!(
            "attempt {attempt}: {} in {:?}; stderr tail: {}",
            output.status,
            t.elapsed(),
            stderr
                .lines()
                .rev()
                .take(3)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n    ")
        );
        if output.status.success() {
            break t.elapsed();
        }
        assert!(
            started.elapsed() < BUDGET,
            "sync did not succeed within {BUDGET:?}; last stderr: {stderr}\nrelay A log:\n{}",
            std::fs::read_to_string(dir_a.join("relay.log")).unwrap_or_default()
        );
        tokio::time::sleep(RETRY).await;
    };
    eprintln!(
        "A reachable after {:?}; sync took {sync_done:?} over {attempt} attempt(s); \
         shared Arti state read-only: {read_only}",
        started.elapsed()
    );
    assert!(
        read_only,
        "the sync never ran with relay B holding the shared Arti state lock"
    );

    stop(relay_a, "relay A").await;
    stop(relay_b, "relay B").await;

    let want: BTreeSet<String> = ids_a.union(&ids_b).cloned().collect();
    let got_a = exported_ids(&cfg_a).await;
    let got_b = exported_ids(&cfg_b).await;
    assert_eq!(got_a.len(), 700);
    assert_eq!(got_b.len(), 700);
    assert_eq!(got_a, want, "A's store diverged");
    assert_eq!(got_b, want, "B's store diverged");
    assert!(ids_b.is_subset(&got_a), "A never received B's 200 events");
}
