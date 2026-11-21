//! Administration commands: import/export/scan/compact over a store.

#![allow(
    unused_crate_dependencies,
    reason = "each test binary uses a subset of the workspace dependencies"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "each file is a single integration test"
)]
#![allow(
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may panic"
)]

mod common;

use std::io::{Cursor, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{event, key};
use nosfry::admin::{AdminError, ImportStats, delete, export, import, scan};
use nosfry_core::event::{Event, EventLimits};
use nosfry_core::filter::Filter;
use nosfry_core::store::WriteOutcome;
use nosfry_lmdb::{Store, StoreOptions};
use serde_json::json;

const MAX_LINE: usize = 4096;

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    (dir, store)
}

/// Canonical JSON line of an event Arc.
fn line(event: &Event) -> String {
    event.json().to_owned()
}

/// A line whose signature does not verify (zeros).
fn bad_sig_line() -> String {
    let mut line = line(&event(&key(9), 1, 100, &json!([]), "bad-sig"));
    // `..."sig":"<128 hex>"}`: zero the signature out.
    line.truncate(line.len() - 130);
    line.push_str(&"0".repeat(128));
    line.push_str("\"}");
    line
}

fn export_bytes(store: &Store) -> Vec<u8> {
    let mut out = Vec::new();
    export(store, 0, u64::MAX, false, false, &mut out).unwrap();
    out
}

#[test]
fn import_mixed_corpus_stats() {
    let (_dir, store) = store();
    let k = key(1);
    let good = [
        line(&event(&k, 1, 100, &json!([]), "n1")),
        line(&event(&k, 1, 200, &json!([]), "n2")),
        line(&event(&k, 1, 300, &json!([]), "n3")),
        line(&event(&k, 6, 300, &json!([]), "repost")),
        line(&event(&k, 0, 500, &json!([]), "newer")),
        line(&event(&k, 0, 400, &json!([]), "older")),
        line(&event(&k, 25000, 300, &json!([]), "ephemeral")),
        // Far outside any relay time window: imports must still accept.
        line(&event(&k, 1, 1_000, &json!([]), "ancient")),
    ];
    let corpus = [
        good[0].clone(),
        good[1].clone(),
        String::new(),
        good[2].clone(),
        good[3].clone(),
        good[4].clone(),
        good[5].clone(),
        good[6].clone(),
        good[7].clone(),
        bad_sig_line(),
        "{\"id\":\"broken\"".to_owned(),
        "x".repeat(MAX_LINE + 100),
    ]
    .join("\n");

    let stats = import(
        &store,
        &EventLimits::default(),
        None,
        MAX_LINE,
        Cursor::new(corpus),
        true,
        false,
    )
    .unwrap();

    assert_eq!(
        stats,
        ImportStats {
            processed: 11,
            added: 6,
            duplicates: 0,
            superseded: 1,
            ephemeral: 1,
            blocked: 0,
            state: 0,
            rejected: 3,
        }
    );

    let mut out = Vec::new();
    let count = export(&store, 0, u64::MAX, false, false, &mut out).unwrap();
    assert_eq!(count, 6);
    let exported = String::from_utf8(out).unwrap();
    for expected in &good[0..5] {
        assert!(exported.contains(expected), "missing {expected}");
    }
    assert!(exported.contains(&good[7]), "ancient event stored");
    assert!(
        !exported.contains(&good[5]),
        "superseded replaceable not stored"
    );
    assert!(!exported.contains(&good[6]), "ephemeral not stored");
}

#[test]
fn export_import_export_is_byte_identical() {
    let (_dir_a, a) = store();
    let k = key(2);
    let events: Vec<_> = (0..50u64)
        .map(|i| {
            let kind = match i % 4 {
                0 => 1,
                1 => 2,
                2 => 6,
                _ => 7,
            };
            event(&k, kind, 1_000 + i, &json!([]), &format!("e{i}"))
        })
        .collect();
    a.write(&events, None).unwrap();
    let dump = export_bytes(&a);

    let (_dir_b, b) = store();
    let stats = import(
        &b,
        &EventLimits::default(),
        None,
        MAX_LINE,
        Cursor::new(&dump),
        false,
        false,
    )
    .unwrap();
    assert_eq!(stats.added, 50);
    assert_eq!(stats.rejected, 0);
    assert_eq!(export_bytes(&b), dump);
}

#[test]
fn reimport_reports_all_duplicates() {
    let (_dir, a) = store();
    let k = key(3);
    let events: Vec<_> = (0..10u64)
        .map(|i| event(&k, 1, 1_000 + i, &json!([]), &format!("e{i}")))
        .collect();
    a.write(&events, None).unwrap();
    let dump = export_bytes(&a);

    let stats = import(
        &a,
        &EventLimits::default(),
        None,
        MAX_LINE,
        Cursor::new(&dump),
        false,
        false,
    )
    .unwrap();
    assert_eq!(stats.added, 0);
    assert_eq!(stats.duplicates, 10);
    assert_eq!(stats.processed, 10);
}

#[test]
fn scan_filters_limits_and_counts() {
    let (_dir, store) = store();
    let k = key(4);
    let notes: Vec<_> = (0..600u64)
        .map(|i| event(&k, 1, 10_000 + i, &json!([]), &format!("n{i}")))
        .collect();
    let reposts: Vec<_> = (0..50u64)
        .map(|i| event(&k, 7, 10_000 + i, &json!([]), &format!("r{i}")))
        .collect();
    store.write(&notes, None).unwrap();
    store.write(&reposts, None).unwrap();

    let mut limited_out = Vec::new();
    let limited = scan(
        &store,
        Filter::parse("{\"kinds\":[1],\"limit\":3}").unwrap(),
        false,
        &mut limited_out,
    )
    .unwrap();
    assert_eq!(limited, 3);
    let lines: Vec<&str> = std::str::from_utf8(&limited_out).unwrap().lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], notes[599].json(), "newest first");
    assert_eq!(lines[2], notes[597].json());

    let mut all_out = Vec::new();
    let all = scan(
        &store,
        Filter::parse("{\"kinds\":[1]}").unwrap(),
        false,
        &mut all_out,
    )
    .unwrap();
    assert_eq!(all, 600, "no relay max_filter_limit cap");
    assert_eq!(std::str::from_utf8(&all_out).unwrap().lines().count(), 600);

    let mut count_out = Vec::new();
    let counted = scan(
        &store,
        Filter::parse("{\"kinds\":[1,7]}").unwrap(),
        true,
        &mut count_out,
    )
    .unwrap();
    assert_eq!(counted, 650);
    assert!(count_out.is_empty(), "count mode writes no events");
}

/// A writer that starts failing after `budget` bytes.
struct FailAfter {
    budget: usize,
}

impl Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.budget == 0 {
            return Err(std::io::Error::other("synthetic"));
        }
        let n = self.budget.min(buf.len());
        self.budget -= n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn scan_propagates_write_error_on_final_step() {
    let (_dir, store) = store();
    let k = key(6);
    store
        .write(&[event(&k, 1, 100, &json!([]), "x")], None)
        .unwrap();
    // The whole result fits in one step, so the write error lands in
    // the same `step` that returns `Progress::Done`.
    let mut out = FailAfter { budget: 4 };
    let err = scan(
        &store,
        Filter::parse("{\"kinds\":[1]}").unwrap(),
        false,
        &mut out,
    )
    .unwrap_err();
    assert!(matches!(err, AdminError::Io(_)), "expected Io, got {err}");
}

#[test]
fn delete_removes_matches_and_dry_run_counts() {
    let (_dir, store) = store();
    let k = key(7);
    let notes: Vec<_> = (0..5u64)
        .map(|i| event(&k, 1, 100 + i, &json!([]), &format!("n{i}")))
        .collect();
    let repost = event(&k, 7, 200, &json!([]), "r");
    store.write(&notes, None).unwrap();
    store.write(&[repost], None).unwrap();

    // Dry run counts without touching the store.
    let filter = || Filter::parse("{\"kinds\":[1]}").unwrap();
    assert_eq!(delete(&store, filter(), true).unwrap(), 5);
    let mut out = Vec::new();
    assert_eq!(
        export(&store, 0, u64::MAX, false, false, &mut out).unwrap(),
        6
    );

    // The real run deletes only the matches; deleting again finds none.
    assert_eq!(delete(&store, filter(), false).unwrap(), 5);
    let mut after = Vec::new();
    assert_eq!(
        export(&store, 0, u64::MAX, false, false, &mut after).unwrap(),
        1
    );
    assert_eq!(delete(&store, filter(), false).unwrap(), 0);
}

#[test]
fn delete_covers_expired_events() {
    let (_dir, store) = store();
    let k = key(8);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expired = event(
        &k,
        1,
        now - 200,
        &json!([["expiration", (now - 100).to_string()]]),
        "stale",
    );
    store.write(&[expired], None).unwrap();
    // The admin delete scans with now = 0, so expired events match.
    assert_eq!(
        delete(&store, Filter::parse("{\"kinds\":[1]}").unwrap(), false).unwrap(),
        1
    );
}

#[test]
fn import_counts_blocked_events() {
    let (_dir, store) = store();
    let k = key(10);
    let target = event(&k, 1, 100, &json!([]), "gone");
    let kind5 = event(&k, 5, 200, &json!([["e", format!("{}", target.id())]]), "");
    // The target's line appears again after its deletion request:
    // the re-import is blocked.
    let corpus = [line(&target), line(&kind5), line(&target)].join("\n");
    let stats = import(
        &store,
        &EventLimits::default(),
        None,
        MAX_LINE,
        Cursor::new(corpus),
        false,
        false,
    )
    .unwrap();
    assert_eq!(
        stats,
        ImportStats {
            processed: 3,
            added: 2,
            duplicates: 0,
            superseded: 0,
            ephemeral: 0,
            blocked: 1,
            state: 0,
            rejected: 0,
        }
    );
}

/// The `delete` leg of the CLI end-to-end: `--dry-run` counts, the real
/// run prints the deleted count and leaves the rest.
fn cli_delete_steps(bin: &str, config: &Path) {
    let dry = Command::new(bin)
        .args([
            "--config",
            config.to_str().unwrap(),
            "delete",
            "--dry-run",
            "{\"kinds\":[7]}",
        ])
        .output()
        .unwrap();
    assert!(
        dry.status.success(),
        "delete --dry-run: {}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert_eq!(
        String::from_utf8(dry.stdout).unwrap(),
        "1\n",
        "dry-run count"
    );

    let del = Command::new(bin)
        .args([
            "--config",
            config.to_str().unwrap(),
            "delete",
            "{\"kinds\":[7]}",
        ])
        .output()
        .unwrap();
    assert!(
        del.status.success(),
        "delete: {}",
        String::from_utf8_lossy(&del.stderr)
    );
    assert_eq!(
        String::from_utf8(del.stdout).unwrap(),
        "1\n",
        "deleted count"
    );

    let after = Command::new(bin)
        .args([
            "scan",
            "--count",
            "{}",
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(after.stdout).unwrap(),
        "2\n",
        "remaining events"
    );
}

#[test]
fn cli_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_nosfry");
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    let config = dir.path().join("nosfry.toml");
    std::fs::write(&config, format!("[db]\npath = \"{}\"\n", db.display())).unwrap();

    let k = key(5);
    let events = [
        line(&event(&k, 1, 100, &json!([]), "one")),
        line(&event(&k, 1, 200, &json!([]), "two")),
        line(&event(&k, 7, 300, &json!([]), "three")),
    ];
    let input_path = dir.path().join("in.jsonl");
    std::fs::write(&input_path, format!("{}\n", events.join("\n"))).unwrap();

    let import_out = Command::new(bin)
        .args(["--config", config.to_str().unwrap(), "import"])
        .stdin(Stdio::from(std::fs::File::open(&input_path).unwrap()))
        .output()
        .unwrap();
    assert!(
        import_out.status.success(),
        "import: {}",
        String::from_utf8_lossy(&import_out.stderr)
    );
    assert!(import_out.stdout.is_empty(), "import stdout must be empty");
    assert!(!import_out.stderr.is_empty(), "logs go to stderr");

    let export_out = Command::new(bin)
        .args(["--config", config.to_str().unwrap(), "export"])
        .output()
        .unwrap();
    assert!(
        export_out.status.success(),
        "export: {}",
        String::from_utf8_lossy(&export_out.stderr)
    );
    let stdout = String::from_utf8(export_out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "stdout is exactly the stored JSON lines: {stdout}"
    );
    for line in &lines {
        let json: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(json["id"].is_string());
    }
    assert_eq!(stdout, format!("{}\n", events.join("\n")));
    assert!(
        String::from_utf8_lossy(&export_out.stderr).contains("export done"),
        "logs go to stderr"
    );

    let scan_out = Command::new(bin)
        .args([
            "scan",
            "--count",
            "{\"kinds\":[1]}",
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        scan_out.status.success(),
        "scan: {}",
        String::from_utf8_lossy(&scan_out.stderr)
    );
    assert_eq!(String::from_utf8(scan_out.stdout).unwrap(), "2\n");

    let dest = dir.path().join("compact.mdb");
    let compact_out = Command::new(bin)
        .args([
            "--config",
            config.to_str().unwrap(),
            "compact",
            dest.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        compact_out.status.success(),
        "compact: {}",
        String::from_utf8_lossy(&compact_out.stderr)
    );
    assert!(dest.is_file());

    cli_delete_steps(bin, &config);

    let empty = dir.path().join("empty.toml");
    std::fs::write(
        &empty,
        format!("[db]\npath = \"{}\"\n", dir.path().join("no-db").display()),
    )
    .unwrap();
    let nodb_out = Command::new(bin)
        .args(["--config", empty.to_str().unwrap(), "export"])
        .output()
        .unwrap();
    assert!(!nodb_out.status.success());
    assert!(
        String::from_utf8_lossy(&nodb_out.stderr).contains("no database"),
        "stderr: {}",
        String::from_utf8_lossy(&nodb_out.stderr)
    );
}

/// A line whose id does not match its content (valid signature).
fn bad_id_line() -> String {
    let mut line = line(&event(&key(9), 1, 100, &json!([]), "bad-id"));
    // `{"id":"<64 hex>"`: flip the first nibble.
    let first = line.as_bytes()[7] as char;
    line.replace_range(7..8, if first == '0' { "1" } else { "0" });
    line
}

#[test]
fn import_no_verify_accepts_bad_sig_rejects_bad_id() {
    let (_dir, st) = store();
    let good = line(&event(&key(6), 1, 100, &json!([]), "ok"));
    let corpus = [good, bad_sig_line(), bad_id_line()].join("\n");
    let stats = import(
        &st,
        &EventLimits::default(),
        None,
        MAX_LINE,
        Cursor::new(corpus),
        false,
        true,
    )
    .unwrap();
    assert_eq!(stats.processed, 3);
    assert_eq!(stats.added, 2, "bad sig stored, good stored");
    assert_eq!(stats.rejected, 1, "the wrong id is still rejected");

    // Without --no-verify the same corrupted signature is rejected.
    let (_dir2, store2) = store();
    let verified = import(
        &store2,
        &EventLimits::default(),
        None,
        MAX_LINE,
        Cursor::new(bad_sig_line()),
        false,
        false,
    )
    .unwrap();
    assert_eq!(verified.added, 0);
    assert_eq!(verified.rejected, 1);
}

/// Run the CLI `delete` with extra args against `config`; returns the
/// finished process output.
fn cli_delete(bin: &str, config: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(bin);
    command.args(["--config", config.to_str().unwrap(), "delete"]);
    command.args(args);
    command.output().unwrap()
}

/// `scan --count {}` output as a number.
fn cli_count(bin: &str, config: &Path) -> u64 {
    let out = Command::new(bin)
        .args([
            "scan",
            "--count",
            "{}",
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[test]
fn cli_delete_age_and_selection() {
    let bin = env!("CARGO_BIN_EXE_nosfry");
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    let config = dir.path().join("nosfry.toml");
    std::fs::write(&config, format!("[db]\npath = \"{}\"\n", db.display())).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let store = Store::open(&db, &StoreOptions::default()).unwrap();
        let k = key(12);
        store
            .write(
                &[
                    event(&k, 1, now - 10_000, &json!([]), "old-1"),
                    event(&k, 7, now - 10_000, &json!([]), "old-7"),
                    event(&k, 1, now - 30_000, &json!([]), "older-1"),
                    event(&k, 1, now, &json!([]), "new-1"),
                ],
                None,
            )
            .unwrap();
    }

    // clap requires at least one of --age / FILTER: bare `delete`
    // and `delete --dry-run` both fail -- a selection is required,
    // flags alone never suffice.
    for args in [&[][..], &["--dry-run"][..]] {
        let bare = cli_delete(bin, &config, args);
        assert!(
            !bare.status.success(),
            "delete {args:?} must be rejected: {}",
            String::from_utf8_lossy(&bare.stderr)
        );
        assert!(
            String::from_utf8_lossy(&bare.stderr).contains("required"),
            "stderr: {}",
            String::from_utf8_lossy(&bare.stderr)
        );
    }
    assert_eq!(cli_count(bin, &config), 4, "nothing deleted");

    // --dry-run combines with either selection form.
    for args in [
        &["--dry-run", "--age", "5000"][..],
        &["--dry-run", "{\"kinds\":[1]}"][..],
    ] {
        let dry = cli_delete(bin, &config, args);
        assert!(
            dry.status.success(),
            "delete {args:?}: {}",
            String::from_utf8_lossy(&dry.stderr)
        );
    }
    assert_eq!(cli_count(bin, &config), 4, "dry runs delete nothing");

    // Dry run with --age counts the three old events, deletes nothing.
    let dry = cli_delete(bin, &config, &["--age", "5000", "--dry-run"]);
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert_eq!(String::from_utf8(dry.stdout).unwrap(), "3\n");
    assert_eq!(cli_count(bin, &config), 4);

    // Filter until (now-20000) is earlier than the age cutoff
    // (now-5000): only older-1 matches.
    let until = format!("{{\"kinds\":[1],\"until\":{}}}", now - 20_000);
    let out = cli_delete(bin, &config, &["--age", "5000", &until]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "1\n",
        "until = min wins"
    );

    // Filter until later than the cutoff: the age bound applies,
    // deleting old-1 (the only remaining old kind-1).
    let later = format!("{{\"kinds\":[1],\"until\":{}}}", now + 100_000);
    let later_out = cli_delete(bin, &config, &["--age", "5000", &later]);
    assert!(later_out.status.success());
    assert_eq!(String::from_utf8(later_out.stdout).unwrap(), "1\n");

    // Age only: deletes old-7 regardless of kind; only new-1 remains.
    let age_only = cli_delete(bin, &config, &["--age", "5000"]);
    assert!(age_only.status.success());
    assert_eq!(String::from_utf8(age_only.stdout).unwrap(), "1\n");
    assert_eq!(cli_count(bin, &config), 1);
}

#[test]
fn cli_import_no_verify() {
    let bin = env!("CARGO_BIN_EXE_nosfry");
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    let config = dir.path().join("nosfry.toml");
    std::fs::write(&config, format!("[db]\npath = \"{}\"\n", db.display())).unwrap();

    // A corrupted signature is accepted under --no-verify; a wrong id
    // is still rejected.
    let input_path = dir.path().join("in.jsonl");
    std::fs::write(
        &input_path,
        format!("{}\n{}\n", bad_sig_line(), bad_id_line()),
    )
    .unwrap();
    let import_out = Command::new(bin)
        .args([
            "--config",
            config.to_str().unwrap(),
            "import",
            "--no-verify",
        ])
        .stdin(Stdio::from(std::fs::File::open(&input_path).unwrap()))
        .output()
        .unwrap();
    assert!(
        import_out.status.success(),
        "{}",
        String::from_utf8_lossy(&import_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&import_out.stderr).contains("added: 1"),
        "only the bad-sig line stored, stderr: {}",
        String::from_utf8_lossy(&import_out.stderr)
    );

    let exported = Command::new(bin)
        .args(["--config", config.to_str().unwrap(), "export"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(exported.stdout).unwrap().lines().count(),
        1
    );

    // The default path still rejects the corrupted signature.
    let db2 = dir.path().join("db2");
    let config2 = dir.path().join("nosfry2.toml");
    std::fs::write(&config2, format!("[db]\npath = \"{}\"\n", db2.display())).unwrap();
    std::fs::write(&input_path, format!("{}\n", bad_sig_line())).unwrap();
    let verified = Command::new(bin)
        .args(["--config", config2.to_str().unwrap(), "import"])
        .stdin(Stdio::from(std::fs::File::open(&input_path).unwrap()))
        .output()
        .unwrap();
    assert!(verified.status.success());
    assert!(
        String::from_utf8_lossy(&verified.stderr).contains("rejected: 1"),
        "stderr: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

/// A line over `max_line` is rejected without buffering: the line
/// after it is still parsed at the right boundary.
#[test]
fn import_overlong_line_is_rejected_and_skipped() {
    let (_dir, store) = store();
    let first = line(&event(&key(1), 1, 100, &json!([]), "first"));
    let giant = "x".repeat(1 << 20);
    let second = line(&event(&key(1), 1, 200, &json!([]), "second"));
    let corpus = format!("{first}\n{giant}\n{second}\n");
    let stats = import(
        &store,
        &EventLimits::default(),
        None,
        64 * 1024,
        Cursor::new(corpus),
        false,
        false,
    )
    .unwrap();
    assert_eq!(stats.processed, 3);
    assert_eq!(stats.added, 2);
    assert_eq!(stats.rejected, 1);
    // The event after the long line imported intact.
    let mut ids = Vec::new();
    store
        .export(0, u64::MAX, false, &mut |json| {
            ids.push(json.to_owned());
            Ok(())
        })
        .unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().any(|j| j.contains("\"second\"")), "{ids:?}");
}

/// Pubkey of a test `Keypair` as the `PublicKey` newtype.
fn pubkey(keypair: &secp256k1::Keypair) -> nosfry_core::event::PublicKey {
    nosfry_core::event::PublicKey(keypair.x_only_public_key().0.to_byte_array())
}

/// A store holding every kind of persisted management state, plus the
/// events deletion/vanish behavior keys on. Returns it alongside the
/// fixtures the round-trip assertions need.
struct Fixture {
    store: Store,
    _dir: tempfile::TempDir,
    banned_author_ev: std::sync::Arc<Event>,
    allowed_ev: std::sync::Arc<Event>,
    banned_ev: std::sync::Arc<Event>,
    deleted_ev: std::sync::Arc<Event>,
    deleted_wrap: std::sync::Arc<Event>,
    vanished_ev: std::sync::Arc<Event>,
}

fn managed_store() -> Fixture {
    let (dir, store) = store();
    let banned = key(20);
    let q = key(21);
    let allowed = key(22);
    let v = key(23);
    let w = key(24);
    let r = key(25);

    let banned_author_ev = event(&banned, 1, 100, &json!([]), "p");
    let deleted_ev = event(&q, 1, 100, &json!([]), "q-target");
    // Banned id authored by the allow-listed key: the `banevent`
    // entry — not the allow list — is what refuses it.
    let banned_ev = event(&allowed, 1, 300, &json!([]), "banned");
    let allowed_ev = event(&allowed, 1, 100, &json!([]), "allowed");
    let vanished_ev = event(&v, 1, 50, &json!([]), "v-old");
    let deleted_wrap = event(
        &w,
        1059,
        90,
        &json!([["p", format!("{}", pubkey(&r))]]),
        "wrap",
    );
    store
        .write(
            &[
                banned_author_ev.clone(),
                deleted_ev.clone(),
                banned_ev.clone(),
                allowed_ev.clone(),
                vanished_ev.clone(),
                deleted_wrap.clone(),
            ],
            None,
        )
        .unwrap();
    // NIP-09 carriers: Q deletes its note, the wrap's recipient
    // deletes the wrap (NIP-59).
    let del_q = event(
        &q,
        5,
        110,
        &json!([["e", format!("{}", deleted_ev.id())]]),
        "",
    );
    let del_wrap = event(
        &r,
        5,
        95,
        &json!([["e", format!("{}", deleted_wrap.id())], ["k", "1059"]]),
        "",
    );
    store.write(&[del_q, del_wrap], None).unwrap();
    // A vanish point whose kind-62 carrier is then deleted — the
    // point must still export.
    let vanish = event(&v, 62, 200, &json!([["relay", "ALL_RELAYS"]]), "");
    let written = store.write(&[vanish], None).unwrap();
    let seq = match written.outcomes[0] {
        WriteOutcome::Stored { seq } => seq,
        ref other => panic!("vanish request stored: {other:?}"),
    };
    while store.vanish_step(10_000).unwrap().more {}
    assert_eq!(store.delete(&[seq]).unwrap(), 1);

    use nosfry_core::moderation::{InfoField, ModOp};
    let pubkey = |k: &secp256k1::Keypair| {
        nosfry_core::event::PublicKey(k.x_only_public_key().0.to_byte_array())
    };
    store
        .moderate(ModOp::BanPubkey {
            pubkey: pubkey(&banned),
            reason: Some("spam".to_owned()),
        })
        .unwrap();
    store
        .moderate(ModOp::AllowPubkey {
            pubkey: pubkey(&allowed),
            reason: None,
        })
        .unwrap();
    store
        .moderate(ModOp::BanEvent {
            id: banned_ev.id(),
            reason: Some("illegal".to_owned()),
        })
        .unwrap();
    store.moderate(ModOp::DisallowKind { kind: 7 }).unwrap();
    store
        .moderate(ModOp::BlockIp {
            ip: "192.0.2.1".parse().unwrap(),
            reason: None,
        })
        .unwrap();
    store
        .moderate(ModOp::SetInfo {
            field: InfoField::Name,
            value: "test relay".to_owned(),
        })
        .unwrap();
    // An empty-string override is a real entry and must round-trip.
    store
        .moderate(ModOp::SetInfo {
            field: InfoField::Icon,
            value: String::new(),
        })
        .unwrap();
    Fixture {
        store,
        _dir: dir,
        banned_author_ev,
        allowed_ev,
        banned_ev,
        deleted_ev,
        deleted_wrap,
        vanished_ev,
    }
}

/// Export → import carries the full management state in one stream:
/// moderation snapshot, vanish points, deletion blocks — and the
/// imported store behaves identically.
#[test]
fn export_import_carries_management_state() {
    let f = managed_store();
    let dump = export_bytes(&f.store);
    assert!(
        String::from_utf8_lossy(&dump).contains("{\"nosfry_state\":1,"),
        "export lacks state lines"
    );

    let (_dir_b, b) = store();
    let stats = import(
        &b,
        &EventLimits::default(),
        None,
        MAX_LINE,
        Cursor::new(&dump),
        false,
        false,
    )
    .unwrap();
    // 7 management entries (2 pubkeys, 1 event, 1 kind, 1 ip, 2 info
    // fields) plus 1 vanish point.
    assert_eq!(stats.state, 8, "{stats:?}");

    assert_eq!(b.moderation().unwrap(), f.store.moderation().unwrap());
    assert_eq!(b.vanish_points().unwrap(), f.store.vanish_points().unwrap());
    assert_eq!(
        export_bytes(&b),
        dump,
        "a second export must be byte-identical"
    );

    // The imported store behaves like the source: the banned author's
    // stored events stay stored but a moderated scan hides them.
    use nosfry_lmdb::{Progress, Scan};
    let gate = nosfry_core::auth::ReadGate::default()
        .with_moderation(std::sync::Arc::new(b.moderation().unwrap()));
    let mut emitted = Vec::new();
    let mut scan = Scan::new(
        std::sync::Arc::from([Filter::parse("{}").unwrap()]),
        gate,
        b.snapshot().unwrap(),
        u64::MAX,
        0,
    );
    loop {
        let progress = scan
            .step(&b, Duration::from_secs(1), &mut |_seq, json| {
                emitted.push(json.to_owned());
            })
            .unwrap();
        if progress == Progress::Done {
            break;
        }
    }
    let banned_id = format!("\"id\":\"{}\"", f.banned_author_ev.id());
    assert!(
        !emitted.iter().any(|json| json.contains(&banned_id)),
        "banned author's event visible: {emitted:?}"
    );
    let allowed_id = format!("\"id\":\"{}\"", f.allowed_ev.id());
    assert!(
        emitted.iter().any(|json| json.contains(&allowed_id)),
        "allowed author's event hidden: {emitted:?}"
    );

    // Rebuilt deletion blocks refuse the rewrites, the imported
    // vanish point refuses the old event, and the banned id stays
    // refused by moderation.
    let outcomes = |events: &[std::sync::Arc<Event>]| b.write(events, None).unwrap().outcomes;
    assert_eq!(
        outcomes(&[f.deleted_ev.clone()]).as_slice(),
        [WriteOutcome::Deleted]
    );
    assert_eq!(
        outcomes(&[f.deleted_wrap.clone()]).as_slice(),
        [WriteOutcome::Deleted]
    );
    assert_eq!(
        outcomes(&[f.vanished_ev.clone()]).as_slice(),
        [WriteOutcome::Vanished]
    );
    assert_eq!(
        b.moderation().unwrap().blocked_reason(&f.banned_ev),
        Some("blocked: event banned")
    );
}

/// `--events-only` emits no state lines; a stream containing them
/// (default export) still round-trips.
#[test]
fn export_events_only_omits_state_lines() {
    let f = managed_store();
    let mut out = Vec::new();
    export(&f.store, 0, u64::MAX, false, true, &mut out).unwrap();
    assert!(
        !String::from_utf8_lossy(&out).contains("nosfry_state"),
        "events-only export has state lines"
    );
}

/// A malformed, unknown-version, or out-of-vocabulary state line is a
/// hard error naming the line — never a silent drop.
#[test]
fn import_refuses_bad_state_lines() {
    let good = line(&event(&key(30), 1, 100, &json!([]), "ok"));
    for (bad_line, needle) in [
        (
            "{\"nosfry_state\":2,\"method\":\"banpubkey\",\"params\":[]}",
            "version 2",
        ),
        (
            "{\"nosfry_state\":1,\"method\":\"listbannedpubkeys\",\"params\":[]}",
            "listbannedpubkeys",
        ),
        (
            "{\"nosfry_state\":1,\"method\":\"unbanpubkey\",\"params\":[]}",
            "unbanpubkey",
        ),
        (
            "{\"nosfry_state\":1,\"method\":\"vanish\",\"params\":[]}",
            "params[0]",
        ),
        ("{\"nosfry_state\":", "malformed"),
    ] {
        let (_dir, b) = store();
        let corpus = format!("{good}\n{bad_line}\n{good}");
        let err = import(
            &b,
            &EventLimits::default(),
            None,
            MAX_LINE,
            Cursor::new(corpus),
            false,
            false,
        )
        .unwrap_err();
        match &err {
            AdminError::State { line, reason } => {
                assert_eq!(*line, 2, "{err}");
                assert!(reason.contains(needle), "{err}");
            }
            other => panic!("expected AdminError::State, got {other}"),
        }
    }
}
