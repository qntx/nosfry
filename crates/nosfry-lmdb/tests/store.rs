//! Store semantics: write outcomes, scans, snapshot bounds, persistence.

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
    reason = "tests may panic; the format-mismatch fixture opens LMDB directly"
)]

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use nosfry_core::event::Event;
use nosfry_core::filter::Filter;
use nosfry_core::sign::{event, key};
use nosfry_core::store::WriteOutcome;
use nosfry_lmdb::{FORMAT_VERSION, Progress, Scan, Store, StoreError, StoreOptions};
use serde_json::json;

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    (dir, store)
}

/// Run a scan to completion, collecting every emitted JSON string.
/// `now = 0` disables the NIP-40 cutoff; pass a real `now` where
/// expiry visibility is under test.
fn collect_now(store: &Store, filters: Arc<[Filter]>, snapshot: u64, now: u64) -> Vec<String> {
    let mut scan = Scan::new(
        filters,
        nosfry_core::auth::ReadGate::default(),
        snapshot,
        500,
        now,
    );
    let out = RefCell::new(Vec::new());
    loop {
        let progress = scan
            .step(store, Duration::ZERO, &mut |_seq, json| {
                out.borrow_mut().push(json.to_owned());
            })
            .unwrap();
        if progress == Progress::Done {
            break;
        }
    }
    out.into_inner()
}

/// `collect_now` with the expiry cutoff disabled.
fn collect(store: &Store, filters: Arc<[Filter]>, snapshot: u64) -> Vec<String> {
    collect_now(store, filters, snapshot, 0)
}

/// `collect_now` in record mode: `(created_at, id)` per emitted match.
fn collect_records(store: &Store, filters: Arc<[Filter]>, snapshot: u64) -> Vec<(u64, String)> {
    let mut scan = Scan::new(
        filters,
        nosfry_core::auth::ReadGate::default(),
        snapshot,
        500,
        0,
    );
    let out = RefCell::new(Vec::new());
    loop {
        let progress = scan
            .step_records(store, Duration::ZERO, &mut |created_at, id| {
                out.borrow_mut().push((created_at, id.to_string()));
            })
            .unwrap();
        if progress == Progress::Done {
            break;
        }
    }
    out.into_inner()
}

#[test]
fn write_and_scan_all() {
    let (_dir, store) = store();
    let k = key(1);
    let e1 = event(&k, 1, 100, &json!([]), "a");
    let e2 = event(&k, 1, 200, &json!([]), "b");
    let out = store
        .write(&[Arc::clone(&e1), Arc::clone(&e2)], None)
        .unwrap();
    assert_eq!(
        out.outcomes,
        vec![
            WriteOutcome::Stored { seq: 1 },
            WriteOutcome::Stored { seq: 2 }
        ]
    );
    assert_eq!(store.snapshot().unwrap(), 2);
    let got = collect(&store, Arc::from([Filter::parse("{}").unwrap()]), 2);
    assert_eq!(got, vec![e2.json().to_owned(), e1.json().to_owned()]);
}

#[test]
fn duplicate_and_ephemeral() {
    let (_dir, store) = store();
    let k = key(1);
    let e = event(&k, 1, 100, &json!([]), "a");
    let eph = event(&k, 20_001, 100, &json!([]), "gone");
    let out = store
        .write(&[Arc::clone(&e), Arc::clone(&e), eph], None)
        .unwrap();
    assert_eq!(
        out.outcomes,
        vec![
            WriteOutcome::Stored { seq: 1 },
            WriteOutcome::Duplicate,
            WriteOutcome::Ephemeral
        ]
    );
    assert_eq!(store.snapshot().unwrap(), 1);
}

#[test]
fn replaceable_supersedes() {
    let (_dir, store) = store();
    let k = key(1);
    let old = event(&k, 0, 100, &json!([]), "old");
    let new = event(&k, 0, 200, &json!([]), "new");
    let stale = event(&k, 0, 50, &json!([]), "stale");
    let out = store
        .write(&[Arc::clone(&old), Arc::clone(&new), stale], None)
        .unwrap();
    assert_eq!(
        out.outcomes,
        vec![
            WriteOutcome::Stored { seq: 1 },
            WriteOutcome::Stored { seq: 2 },
            WriteOutcome::Superseded
        ]
    );
    assert_eq!(store.snapshot().unwrap(), 2);
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"kinds\":[0]}").unwrap()]),
        2,
    );
    assert_eq!(got, vec![new.json().to_owned()]);
    let _ = old;
}

#[test]
fn replaceable_two_versions_one_batch() {
    let (_dir, store) = store();
    let k = key(1);
    // Older first: v2 must evict v1 inside the single write txn.
    let v1 = event(&k, 3, 100, &json!([]), "v1");
    let v2 = event(&k, 3, 300, &json!([]), "v2");
    let out = store.write(&[v1, Arc::clone(&v2)], None).unwrap();
    assert_eq!(
        out.outcomes,
        vec![
            WriteOutcome::Stored { seq: 1 },
            WriteOutcome::Stored { seq: 2 }
        ]
    );
    let got = collect(
        &store,
        Arc::from([Filter::parse("{}").unwrap()]),
        store.snapshot().unwrap(),
    );
    assert_eq!(got, vec![v2.json().to_owned()]);
}

#[test]
fn replaceable_tie_lower_id_wins() {
    let (_dir, store) = store();
    let k = key(1);
    // Same created_at: the event with the lower id wins. Craft by trying
    // contents until we find a pair with distinct id ordering.
    let a = event(&k, 0, 100, &json!([]), "tie-a");
    let b = event(&k, 0, 100, &json!([]), "tie-b");
    let (winner, loser) = if a.id() < b.id() { (a, b) } else { (b, a) };
    let out = store.write(&[loser, Arc::clone(&winner)], None).unwrap();
    assert_eq!(
        out.outcomes,
        vec![
            WriteOutcome::Stored { seq: 1 },
            WriteOutcome::Stored { seq: 2 }
        ]
    );
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"kinds\":[0]}").unwrap()]),
        2,
    );
    assert_eq!(got, vec![winner.json().to_owned()]);
}

#[test]
fn addressable_replaces_by_d_tag() {
    let (_dir, store) = store();
    let k = key(1);
    let v1 = event(&k, 30_001, 100, &json!([["d", "article"]]), "v1");
    let v2 = event(&k, 30_001, 200, &json!([["d", "article"]]), "v2");
    let other = event(&k, 30_001, 250, &json!([["d", "other"]]), "other");
    let out = store
        .write(&[v1, Arc::clone(&v2), Arc::clone(&other)], None)
        .unwrap();
    assert_eq!(
        out.outcomes,
        vec![
            WriteOutcome::Stored { seq: 1 },
            WriteOutcome::Stored { seq: 2 },
            WriteOutcome::Stored { seq: 3 }
        ]
    );
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"kinds\":[30001]}").unwrap()]),
        3,
    );
    assert_eq!(got, vec![other.json().to_owned(), v2.json().to_owned()]);
}

#[test]
fn addressable_long_d_replaces() {
    let (_dir, store) = store();
    let k = key(1);
    let long_d = "d".repeat(300);
    let v1 = event(&k, 30_002, 100, &json!([["d", long_d]]), "v1");
    let v2 = event(&k, 30_002, 200, &json!([["d", long_d]]), "v2");
    let out = store.write(&[v1, Arc::clone(&v2)], None).unwrap();
    assert_eq!(
        out.outcomes,
        vec![
            WriteOutcome::Stored { seq: 1 },
            WriteOutcome::Stored { seq: 2 }
        ]
    );
    let got = collect(&store, Arc::from([Filter::parse("{}").unwrap()]), 2);
    assert_eq!(got, vec![v2.json().to_owned()]);
}

#[test]
fn different_authors_do_not_replace() {
    let (_dir, store) = store();
    let a = event(&key(1), 0, 100, &json!([]), "a");
    let b = event(&key(2), 0, 50, &json!([]), "b");
    let out = store
        .write(&[Arc::clone(&a), Arc::clone(&b)], None)
        .unwrap();
    assert_eq!(
        out.outcomes,
        vec![
            WriteOutcome::Stored { seq: 1 },
            WriteOutcome::Stored { seq: 2 }
        ]
    );
    let _ = (a, b);
}

#[test]
fn scan_snapshot_bound() {
    let (_dir, store) = store();
    let k = key(1);
    let e1 = event(&k, 1, 100, &json!([]), "one");
    store.write(&[Arc::clone(&e1)], None).unwrap();
    let snap = store.snapshot().unwrap();
    let e2 = event(&k, 1, 200, &json!([]), "two");
    store.write(&[e2], None).unwrap();
    assert_eq!(store.snapshot().unwrap(), 2);
    let got = collect(&store, Arc::from([Filter::parse("{}").unwrap()]), snap);
    assert_eq!(got, vec![e1.json().to_owned()]);
}

#[test]
fn scan_writes_between_steps_invisible() {
    let (_dir, store) = store();
    let k = key(1);
    // 100 events so a ZERO-budget step stops mid-scan (64-candidate budget).
    let events: Vec<Arc<Event>> = (0..100)
        .map(|i| event(&k, 1, 1_000 + i, &json!([]), "x"))
        .collect();
    store.write(&events, None).unwrap();
    let snap = store.snapshot().unwrap();
    let mut scan = Scan::new(
        Arc::from([Filter::parse("{}").unwrap()]),
        nosfry_core::auth::ReadGate::default(),
        snap,
        500,
        0,
    );
    let out = RefCell::new(Vec::new());
    let p1 = scan
        .step(&store, Duration::ZERO, &mut |_seq, j| {
            out.borrow_mut().push(j.to_owned());
        })
        .unwrap();
    // Write more events between steps — they exceed the snapshot.
    let later: Vec<Arc<Event>> = (0..10)
        .map(|i| event(&k, 1, 9_000 + i, &json!([]), "late"))
        .collect();
    store.write(&later, None).unwrap();
    loop {
        let p = scan
            .step(&store, Duration::ZERO, &mut |_seq, j| {
                out.borrow_mut().push(j.to_owned());
            })
            .unwrap();
        if p == Progress::Done {
            break;
        }
    }
    let _ = p1;
    let got = out.into_inner();
    assert_eq!(got.len(), 100);
    assert!(got.iter().all(|j| !j.contains("late")));
}

#[test]
fn scan_limit_and_ties() {
    let (_dir, store) = store();
    let k = key(1);
    let mut events = Vec::new();
    for i in 0..5u64 {
        events.push(event(&k, 1, 100, &json!([]), &format!("tie{i}")));
    }
    events.push(event(&k, 1, 50, &json!([]), "old"));
    store.write(&events, None).unwrap();
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"limit\":3}").unwrap()]),
        6,
    );
    assert_eq!(got.len(), 3);
}

#[test]
fn scan_addressable_kinds_without_d_unbounded() {
    let (_dir, store) = store();
    let k = key(1);
    let pk = format!("{}", k.x_only_public_key().0);
    let events: Vec<Arc<Event>> = ["a", "b", "c"]
        .iter()
        .map(|d| event(&k, 30_023, 100, &json!([["d", d]]), d))
        .collect();
    store.write(&events, None).unwrap();
    // No `#d` condition: an author+addressable-kind filter has no
    // intrinsic bound, so all live `d` addresses are returned.
    let got = collect(
        &store,
        Arc::from([
            Filter::parse(&format!("{{\"kinds\":[30023],\"authors\":[\"{pk}\"]}}")).unwrap(),
        ]),
        3,
    );
    assert_eq!(got.len(), 3);
    // With `#d` the intrinsic bound is authors*kinds*#d and only the
    // listed addresses match anyway.
    let got_d = collect(
        &store,
        Arc::from([Filter::parse(&format!(
            "{{\"kinds\":[30023],\"authors\":[\"{pk}\"],\"#d\":[\"a\"]}}"
        ))
        .unwrap()]),
        3,
    );
    assert_eq!(got_d, vec![events[0].json().to_owned()]);
}

#[test]
fn scan_records_match_payload_scan() {
    let (_dir, store) = store();
    let k = key(1);
    let events: Vec<Arc<Event>> = (0..10u64)
        .map(|i| event(&k, 1, 100 + i, &json!([["t", "x"]]), &format!("e{i}")))
        .collect();
    store.write(&events, None).unwrap();
    // Two overlapping filters exercise cross-filter dedup in both modes.
    let filters: Arc<[Filter]> = Arc::from([
        Filter::parse("{\"#t\":[\"x\"]}").unwrap(),
        Filter::parse("{\"kinds\":[1]}").unwrap(),
    ]);
    let snap = store.snapshot().unwrap();
    // The payload mode's `(created_at, id)` sequence, parsed back.
    let expected: Vec<(u64, String)> = collect(&store, Arc::clone(&filters), snap)
        .iter()
        .map(|json| {
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            (
                v["created_at"].as_u64().unwrap(),
                v["id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let got = collect_records(&store, filters, snap);
    assert_eq!(got, expected);
}

#[test]
fn scan_cross_filter_dedup() {
    let (_dir, store) = store();
    let k = key(1);
    let e = event(&k, 1, 100, &json!([]), "a");
    store.write(&[Arc::clone(&e)], None).unwrap();
    let id = e.id();
    let hex = format!("{id}");
    let filters: Arc<[Filter]> = Arc::from([
        Filter::parse(&format!("{{\"ids\":[\"{hex}\"]}}")).unwrap(),
        Filter::parse("{}").unwrap(),
    ]);
    let got = collect(&store, filters, 1);
    assert_eq!(got, vec![e.json().to_owned()]);
}

#[test]
fn scan_impossible_filter() {
    let (_dir, store) = store();
    let k = key(1);
    store
        .write(&[event(&k, 1, 100, &json!([]), "a")], None)
        .unwrap();
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"kinds\":[]}").unwrap()]),
        1,
    );
    assert!(got.is_empty(), "expected no emissions");
}

#[test]
fn scan_tag_and_author_indexes() {
    let (_dir, store) = store();
    let k = key(1);
    let tagged = event(&k, 1, 100, &json!([["t", "nostr"]]), "tagged");
    let plain = event(&k, 1, 200, &json!([]), "plain");
    store
        .write(&[Arc::clone(&tagged), Arc::clone(&plain)], None)
        .unwrap();
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"#t\":[\"nostr\"]}").unwrap()]),
        2,
    );
    assert_eq!(got, vec![tagged.json().to_owned()]);
    let pk = format!("{}", tagged.pubkey());
    let got_authors = collect(
        &store,
        Arc::from([Filter::parse(&format!("{{\"authors\":[\"{pk}\"]}}")).unwrap()]),
        2,
    );
    assert_eq!(got_authors.len(), 2); // both events share the author
    assert_eq!(got_authors[0], plain.json());
}

#[test]
fn persistence_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let k = key(1);
    let e1 = event(&k, 1, 100, &json!([]), "one");
    {
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
        store.write(&[Arc::clone(&e1)], None).unwrap();
        assert_eq!(store.snapshot().unwrap(), 1);
    }
    let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    let e2 = event(&k, 1, 200, &json!([]), "two");
    let out = store.write(&[Arc::clone(&e2)], None).unwrap();
    assert_eq!(out.outcomes, vec![WriteOutcome::Stored { seq: 2 }]);
    let got = collect(&store, Arc::from([Filter::parse("{}").unwrap()]), 2);
    assert_eq!(got, vec![e2.json().to_owned(), e1.json().to_owned()]);
}

#[test]
fn format_mismatch_rejected() {
    let dir = tempfile::tempdir().unwrap();
    // Hand-create an env whose meta.format is not 1.
    {
        use heed::types::Bytes;
        use heed::{EnvFlags, EnvOpenOptions};
        let mut options = EnvOpenOptions::new();
        // SAFETY: flag must be set before opening the env.
        unsafe { options.flags(EnvFlags::NO_READ_AHEAD) };
        options.map_size(1 << 20).max_dbs(16);
        // SAFETY: test-scoped env; the dir is private to this test.
        let env = unsafe { options.open(dir.path()).unwrap() };
        let mut wtxn = env.write_txn().unwrap();
        let meta = env
            .create_database::<Bytes, Bytes>(&mut wtxn, Some("meta"))
            .unwrap();
        meta.put(&mut wtxn, b"format", &9u32.to_be_bytes()).unwrap();
        wtxn.commit().unwrap();
    }
    let err = Store::open(dir.path(), &StoreOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        StoreError::FormatMismatch {
            found: 9,
            expected
        } if expected == FORMAT_VERSION
    ));
}

#[test]
fn id_lookup_by_ids_filter() {
    let (_dir, store) = store();
    let k = key(1);
    let a = event(&k, 1, 100, &json!([]), "a");
    let b = event(&k, 1, 200, &json!([]), "b");
    store
        .write(&[Arc::clone(&a), Arc::clone(&b)], None)
        .unwrap();
    let hex = format!("{}", a.id());
    let got = collect(
        &store,
        Arc::from([Filter::parse(&format!("{{\"ids\":[\"{hex}\"]}}")).unwrap()]),
        2,
    );
    assert_eq!(got, vec![a.json().to_owned()]);
}

#[test]
fn scan_emits_first_group_before_step_ends() {
    let (_dir, store) = store();
    let k = key(1);
    let events: Vec<_> = (0..1_000u64)
        .map(|i| event(&k, 1, 1_000 + i, &json!([]), &format!("e{i}")))
        .collect();
    store.write(&events, None).unwrap();
    let snapshot = store.snapshot().unwrap();
    let filters: Arc<[Filter]> =
        Arc::from([Filter::parse("{\"kinds\":[1],\"limit\":500}").unwrap()]);
    let mut scan = Scan::new(
        filters,
        nosfry_core::auth::ReadGate::default(),
        snapshot,
        500,
        0,
    );
    let mut emitted = 0usize;
    // A zero-budget step stops after BUDGET_CHECK_EVERY candidates; a
    // streaming scan has already flushed completed created_at groups.
    let progress = scan
        .step(&store, Duration::ZERO, &mut |_, _| {
            emitted += 1;
        })
        .unwrap();
    assert_eq!(progress, Progress::Pending);
    assert!(emitted > 0, "first step emitted nothing");
}

/// Run an export, collecting every emitted JSON string.
fn export_lines(store: &Store, since: u64, until: u64, reverse: bool) -> Vec<String> {
    let lines = RefCell::new(Vec::new());
    store
        .export(since, until, reverse, &mut |json| {
            lines.borrow_mut().push(json.to_owned());
            Ok(())
        })
        .unwrap();
    lines.into_inner()
}

#[test]
fn export_orders_by_created_at_then_seq() {
    let (_dir, store) = store();
    let k = key(1);
    let e1 = event(&k, 1, 100, &json!([]), "a");
    let e2 = event(&k, 1, 100, &json!([]), "b");
    let e3 = event(&k, 1, 200, &json!([]), "c");
    store
        .write(&[Arc::clone(&e1), Arc::clone(&e2), Arc::clone(&e3)], None)
        .unwrap();

    let asc = export_lines(&store, 0, u64::MAX, false);
    assert_eq!(asc, [e1.json(), e2.json(), e3.json()], "ascending order");

    let desc = export_lines(&store, 0, u64::MAX, true);
    assert_eq!(
        desc,
        [e3.json(), e2.json(), e1.json()],
        "descending order; the created_at tie is seq-descending"
    );
}

#[test]
fn export_bounds_are_inclusive() {
    let (_dir, store) = store();
    let k = key(1);
    let e1 = event(&k, 1, 100, &json!([]), "a");
    let e2 = event(&k, 1, 200, &json!([]), "b");
    let e3 = event(&k, 1, 300, &json!([]), "c");
    store
        .write(&[Arc::clone(&e1), Arc::clone(&e2), Arc::clone(&e3)], None)
        .unwrap();

    let count = RefCell::new(0u64);
    let got = store
        .export(100, 200, false, &mut |json| {
            *count.borrow_mut() += 1;
            assert!(json.contains("\"a\"") || json.contains("\"b\""));
            Ok(())
        })
        .unwrap();
    assert_eq!(got, 2);
    assert_eq!(*count.borrow(), 2);

    assert_eq!(export_lines(&store, 0, 99, false), Vec::<String>::new());
    assert_eq!(
        export_lines(&store, 101, 300, false),
        [e2.json(), e3.json()]
    );
}

#[test]
fn export_propagates_emit_errors() {
    let (_dir, store) = store();
    let k = key(1);
    store
        .write(&[event(&k, 1, 100, &json!([]), "a")], None)
        .unwrap();
    let err = store
        .export(0, u64::MAX, false, &mut |_| {
            Err(std::io::Error::other("synthetic"))
        })
        .unwrap_err();
    assert!(matches!(err, StoreError::Io(e) if e.kind() == std::io::ErrorKind::Other));
}

#[test]
fn compact_to_round_trip() {
    let (_dir, store) = store();
    let k = key(1);
    let events: Vec<_> = (0..10u64)
        .map(|i| event(&k, 1, 100 + i, &json!([]), &format!("e{i}")))
        .collect();
    store.write(&events, None).unwrap();

    let staging = tempfile::tempdir().unwrap();
    let dest = staging.path().join("compact.mdb");
    store.compact_to(&dest).unwrap();
    assert!(dest.is_file(), "compact_to wrote a single file");

    let fresh = tempfile::tempdir().unwrap();
    std::fs::rename(&dest, fresh.path().join("data.mdb")).unwrap();
    let copy = Store::open(fresh.path(), &StoreOptions::default()).unwrap();

    assert_eq!(
        export_lines(&store, 0, u64::MAX, false),
        export_lines(&copy, 0, u64::MAX, false),
        "compacted copy exports identically"
    );
    assert_eq!(
        export_lines(&store, 0, u64::MAX, true),
        export_lines(&copy, 0, u64::MAX, true)
    );
}

#[test]
fn compact_to_refuses_existing_dest() {
    let (_dir, store) = store();
    let dest_dir = tempfile::tempdir().unwrap();
    let dest = dest_dir.path().join("data.mdb");
    std::fs::write(&dest, b"existing").unwrap();

    let err = store.compact_to(&dest).unwrap_err();
    assert!(
        matches!(err, StoreError::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists),
        "expected AlreadyExists, got {err}"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), b"existing", "dest untouched");
}

/// A leftover `<dest>.tmp` — evidence of an interrupted compaction —
/// refuses the run instead of being silently reused or clobbered.
#[test]
fn compact_to_refuses_stale_tmp() {
    let (_dir, store) = store();
    let dest_dir = tempfile::tempdir().unwrap();
    let dest = dest_dir.path().join("data.mdb");
    let tmp = dest_dir.path().join("data.mdb.tmp");
    std::fs::write(&tmp, b"partial").unwrap();

    let err = store.compact_to(&dest).unwrap_err();
    assert!(
        matches!(err, StoreError::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists),
        "expected AlreadyExists for the tmp file, got {err}"
    );
    assert!(!dest.exists(), "dest must not be created");
    assert_eq!(std::fs::read(&tmp).unwrap(), b"partial", "tmp untouched");
}

/// The author's pubkey hex for `a` tag values.
fn pk_hex(keypair: &secp256k1::Keypair) -> String {
    format!("{}", keypair.x_only_public_key().0)
}

#[test]
fn deletion_by_e_removes_target_and_blocks_republish() {
    let (_dir, store) = store();
    let k = key(1);
    let note = event(&k, 1, 100, &json!([]), "gone");
    let kind5 = event(&k, 5, 200, &json!([["e", format!("{}", note.id())]]), "");
    assert_eq!(
        store.write(&[Arc::clone(&note)], None).unwrap().outcomes,
        vec![WriteOutcome::Stored { seq: 1 }]
    );
    let written = store.write(&[Arc::clone(&kind5)], None).unwrap();
    assert_eq!(written.outcomes, vec![WriteOutcome::Stored { seq: 2 }]);
    assert_eq!(written.deleted, vec![1]);
    let got = collect(&store, Arc::from([Filter::parse("{}").unwrap()]), 2);
    assert_eq!(got, vec![kind5.json().to_owned()]);
    // The id stays blocked for this author: republishing is Deleted.
    let again = store.write(&[Arc::clone(&note)], None).unwrap();
    assert_eq!(again.outcomes, vec![WriteOutcome::Deleted]);
    assert_eq!(again.deleted, Vec::<u64>::new());
}

#[test]
fn deletion_kind5_targeting_kind5_has_no_effect() {
    let (_dir, store) = store();
    let k = key(1);
    let first = event(&k, 5, 100, &json!([]), "first");
    let second = event(
        &k,
        5,
        200,
        &json!([["e", format!("{}", first.id())]]),
        "second",
    );
    let written = store
        .write(&[Arc::clone(&first), Arc::clone(&second)], None)
        .unwrap();
    assert_eq!(written.deleted, Vec::<u64>::new());
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"kinds\":[5]}").unwrap()]),
        2,
    );
    assert_eq!(got.len(), 2, "a kind 5 cannot delete a kind 5");
}

#[test]
fn deletion_foreign_author_e_has_no_effect() {
    let (_dir, store) = store();
    let note = event(&key(1), 1, 100, &json!([]), "mine");
    let kind5 = event(
        &key(2),
        5,
        200,
        &json!([["e", format!("{}", note.id())]]),
        "",
    );
    let written = store
        .write(&[Arc::clone(&note), Arc::clone(&kind5)], None)
        .unwrap();
    assert_eq!(written.deleted, Vec::<u64>::new());
    let got = collect(&store, Arc::from([Filter::parse("{}").unwrap()]), 2);
    assert_eq!(got.len(), 2, "a foreign-author e target is ignored");
}

#[test]
fn deletion_by_a_removes_equal_and_older_versions() {
    let (_dir, store) = store();
    let k = key(1);
    let pk = pk_hex(&k);
    let v1 = event(&k, 30_023, 100, &json!([["d", "art"]]), "v1");
    let del = event(&k, 5, 200, &json!([["a", format!("30023:{pk}:art")]]), "");
    let written = store
        .write(&[Arc::clone(&v1), Arc::clone(&del)], None)
        .unwrap();
    assert_eq!(written.outcomes.len(), 2);
    assert_eq!(written.deleted, vec![1]);
    // Equal or older republishing is blocked; a newer version is accepted.
    let v_older = event(&k, 30_023, 50, &json!([["d", "art"]]), "older");
    let v_equal = event(&k, 30_023, 200, &json!([["d", "art"]]), "equal");
    let v_newer = event(&k, 30_023, 250, &json!([["d", "art"]]), "newer");
    let again = store
        .write(
            &[
                Arc::clone(&v1),
                Arc::clone(&v_older),
                Arc::clone(&v_equal),
                Arc::clone(&v_newer),
            ],
            None,
        )
        .unwrap();
    assert_eq!(
        again.outcomes,
        vec![
            WriteOutcome::Deleted,
            WriteOutcome::Deleted,
            WriteOutcome::Deleted,
            WriteOutcome::Stored { seq: 3 }
        ]
    );
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"kinds\":[30023]}").unwrap()]),
        3,
    );
    assert_eq!(got, vec![v_newer.json().to_owned()]);
}

#[test]
fn deletion_by_a_replaceable_uses_empty_d() {
    let (_dir, store) = store();
    let k = key(1);
    let pk = pk_hex(&k);
    let profile = event(&k, 0, 100, &json!([]), "profile");
    let del = event(&k, 5, 200, &json!([["a", format!("0:{pk}:")]]), "");
    let written = store
        .write(&[Arc::clone(&profile), Arc::clone(&del)], None)
        .unwrap();
    assert_eq!(written.deleted, vec![1]);
    assert_eq!(
        store.write(&[Arc::clone(&profile)], None).unwrap().outcomes,
        vec![WriteOutcome::Deleted]
    );
    let newer = event(&k, 0, 300, &json!([]), "new");
    assert_eq!(
        store.write(&[Arc::clone(&newer)], None).unwrap().outcomes,
        vec![WriteOutcome::Stored { seq: 3 }]
    );
}

#[test]
fn deletion_foreign_a_has_no_effect() {
    let (_dir, store) = store();
    let k = key(1);
    let other = pk_hex(&key(2));
    let v1 = event(&k, 30_023, 100, &json!([["d", "art"]]), "v1");
    // The a value names another author's address: not a target.
    let del = event(
        &k,
        5,
        200,
        &json!([["a", format!("30023:{other}:art")]]),
        "",
    );
    let written = store
        .write(&[Arc::clone(&v1), Arc::clone(&del)], None)
        .unwrap();
    assert_eq!(written.deleted, Vec::<u64>::new());
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"kinds\":[30023]}").unwrap()]),
        2,
    );
    assert_eq!(got, vec![v1.json().to_owned()]);
}

/// A `d` longer than 255 bytes never fits the packed record; a delete
/// must still find and remove every index entry. Shared by the `e` and
/// `a` deletion tests.
fn assert_long_d_deletion(store: &Store, del: Arc<Event>) {
    let k = key(1);
    let long_d = "d".repeat(300);
    let v1 = event(&k, 30_002, 100, &json!([["d", long_d]]), "v1");
    let written = store.write(&[Arc::clone(&v1), del], None).unwrap();
    assert_eq!(written.deleted, vec![1], "target must be deleted");
    let blocked = store.write(&[Arc::clone(&v1)], None).unwrap();
    assert_eq!(
        blocked.outcomes,
        vec![WriteOutcome::Deleted],
        "republish must be blocked"
    );
    // A newer version is accepted.
    let v2 = event(&k, 30_002, 250, &json!([["d", long_d]]), "v2");
    let newest = store.write(&[Arc::clone(&v2)], None).unwrap();
    assert_eq!(
        newest.outcomes,
        vec![WriteOutcome::Stored { seq: 3 }],
        "newer version must be stored"
    );
}

#[test]
fn deletion_long_d_by_e() {
    let (_dir, store) = store();
    let k = key(1);
    let v1 = event(&k, 30_002, 100, &json!([["d", "d".repeat(300)]]), "v1");
    let del = event(&k, 5, 200, &json!([["e", format!("{}", v1.id())]]), "");
    assert_long_d_deletion(&store, del);
}

#[test]
fn deletion_long_d_by_a() {
    let (_dir, store) = store();
    let k = key(1);
    let pk = pk_hex(&k);
    let long_d = "d".repeat(300);
    let del = event(
        &k,
        5,
        200,
        &json!([["a", format!("30002:{pk}:{long_d}")]]),
        "",
    );
    assert_long_d_deletion(&store, del);
}

#[test]
fn deletion_block_lifts_when_kind5_is_deleted() {
    let (_dir, store) = store();
    let k = key(1);
    let note = event(&k, 1, 100, &json!([]), "gone");
    let kind5 = event(&k, 5, 200, &json!([["e", format!("{}", note.id())]]), "");
    let written = store
        .write(&[Arc::clone(&note), Arc::clone(&kind5)], None)
        .unwrap();
    assert_eq!(written.deleted, vec![1]);
    assert_eq!(
        store.write(&[Arc::clone(&note)], None).unwrap().outcomes,
        vec![WriteOutcome::Deleted]
    );
    // Deleting the kind 5 itself removes its index rows: republish works.
    assert_eq!(store.delete(&[2]).unwrap(), 1);
    assert_eq!(
        store.write(&[Arc::clone(&note)], None).unwrap().outcomes,
        vec![WriteOutcome::Stored { seq: 3 }]
    );
}

#[test]
fn deleted_reported_within_one_batch() {
    let (_dir, store) = store();
    let k = key(1);
    // An event and its deletion in one batch.
    let note = event(&k, 1, 100, &json!([]), "gone");
    let del = event(&k, 5, 200, &json!([["e", format!("{}", note.id())]]), "");
    let written = store
        .write(&[Arc::clone(&note), Arc::clone(&del)], None)
        .unwrap();
    assert_eq!(
        written.outcomes,
        vec![
            WriteOutcome::Stored { seq: 1 },
            WriteOutcome::Stored { seq: 2 }
        ]
    );
    assert_eq!(written.deleted, vec![1]);
    // A replaceable pair in one batch: the loser lands in `deleted`.
    let v1 = event(&k, 0, 100, &json!([]), "v1");
    let v2 = event(&k, 0, 200, &json!([]), "v2");
    let pair = store.write(&[v1, Arc::clone(&v2)], None).unwrap();
    assert_eq!(pair.deleted, vec![3]);
    let got = collect(
        &store,
        Arc::from([Filter::parse("{\"kinds\":[0]}").unwrap()]),
        4,
    );
    assert_eq!(got, vec![v2.json().to_owned()]);
}

#[test]
fn expire_removes_due_events_and_respects_limit() {
    let (_dir, store) = store();
    let k = key(1);
    let e1 = event(&k, 1, 100, &json!([["expiration", "150"]]), "a");
    let e2 = event(&k, 1, 100, &json!([["expiration", "250"]]), "b");
    let e3 = event(&k, 1, 100, &json!([]), "c");
    store
        .write(&[Arc::clone(&e1), Arc::clone(&e2), Arc::clone(&e3)], None)
        .unwrap();
    // Nothing due yet; limit respected; future events left alone.
    assert_eq!(store.expire(100, 10).unwrap(), 0);
    assert_eq!(store.expire(200, 1).unwrap(), 1);
    assert_eq!(store.expire(200, 10).unwrap(), 0);
    assert_eq!(store.expire(300, 10).unwrap(), 1);
    let got = collect(&store, Arc::from([Filter::parse("{}").unwrap()]), 3);
    assert_eq!(got, vec![e3.json().to_owned()]);
    assert_eq!(
        export_lines(&store, 0, u64::MAX, false),
        vec![e3.json().to_owned()]
    );
}

#[test]
fn scan_hides_expired_and_they_do_not_consume_limits() {
    let (_dir, store) = store();
    let k = key(1);
    let expired = event(&k, 1, 200, &json!([["expiration", "300"]]), "old");
    let live = event(&k, 1, 100, &json!([]), "live");
    let snap = store
        .write(&[Arc::clone(&expired), Arc::clone(&live)], None)
        .map(|_| store.snapshot().unwrap())
        .unwrap();
    // now = 0 disables the cutoff: both visible, newest first.
    let all = collect_now(&store, Arc::from([Filter::parse("{}").unwrap()]), snap, 0);
    assert_eq!(all, vec![expired.json().to_owned(), live.json().to_owned()]);
    // now >= expiration: the expired event is hidden even in storage.
    let at_now = collect_now(&store, Arc::from([Filter::parse("{}").unwrap()]), snap, 400);
    assert_eq!(at_now, vec![live.json().to_owned()]);
    // It does not consume the limit either: newest-first with limit 1
    // still serves the live event, not the expired one.
    let limited = collect_now(
        &store,
        Arc::from([Filter::parse("{\"limit\":1}").unwrap()]),
        snap,
        400,
    );
    assert_eq!(limited, vec![live.json().to_owned()]);
    // Export stays a raw dump: expired events are exported until swept.
    assert_eq!(export_lines(&store, 0, u64::MAX, false).len(), 2);
}

#[test]
fn scan_gate_hides_restricted_and_they_do_not_consume_limits() {
    let (_dir, store) = store();
    let k = key(1);
    let dm = event(&k, 4, 200, &json!([["p", pk_hex(&key(2))]]), "dm");
    let note = event(&k, 1, 100, &json!([]), "note");
    let snap = store
        .write(&[Arc::clone(&dm), Arc::clone(&note)], None)
        .map(|_| store.snapshot().unwrap())
        .unwrap();
    let rules = Arc::new(nosfry_core::auth::AuthRules::new(None, &[4], true));
    let collect_gated = |authed: &[nosfry_core::event::PublicKey], limit: &str| {
        let gate = nosfry_core::auth::ReadGate::new(Arc::clone(&rules), Arc::from(authed));
        let filters = Arc::from([Filter::parse(limit).unwrap()]);
        let mut scan = Scan::new(filters, gate, snap, 500, 0);
        let out = RefCell::new(Vec::new());
        loop {
            let progress = scan
                .step(&store, Duration::ZERO, &mut |_seq, json| {
                    out.borrow_mut().push(json.to_owned());
                })
                .unwrap();
            if progress == Progress::Done {
                break;
            }
        }
        out.into_inner()
    };
    // Unauthenticated: the kind-4 event is hidden and does not count
    // toward `limit` — newest-first with limit 1 still serves the note.
    let hidden = collect_gated(&[], "{}");
    assert_eq!(hidden, vec![note.json().to_owned()]);
    let limited = collect_gated(&[], "{\"limit\":1}");
    assert_eq!(limited, vec![note.json().to_owned()]);
    // The p-tagged recipient sees both.
    let involved = collect_gated(
        &[nosfry_core::event::PublicKey(
            key(2).x_only_public_key().0.to_byte_array(),
        )],
        "{}",
    );
    assert_eq!(involved, vec![dm.json().to_owned(), note.json().to_owned()]);
}

/// The `wss://relay.example.com` service URL for vanish tests.
fn relay_url() -> nosfry_core::url::RelayUrl {
    nosfry_core::url::RelayUrl::parse("wss://relay.example.com").unwrap()
}

/// `Filter` matching every event by `author`.
fn by_author(keypair: &secp256k1::Keypair) -> Arc<[Filter]> {
    let filter = Filter::parse(&format!("{{\"authors\":[\"{}\"]}}", pk_hex(keypair))).unwrap();
    Arc::from([filter])
}

/// Ids a scan by `author` still serves.
fn served_ids(store: &Store, keypair: &secp256k1::Keypair) -> Vec<String> {
    let snapshot = store.snapshot().unwrap();
    collect(store, by_author(keypair), snapshot)
        .iter()
        .map(|json| {
            serde_json::from_str::<serde_json::Value>(json).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn vanish_deletes_authors_events_and_tagged_wraps() {
    let (_dir, store) = store();
    let url = relay_url();
    let (author, other) = (key(1), key(2));
    // The author's own history across kinds, incl. a deletion request,
    // a replaceable, and an addressable event — all at or before the
    // vanish point T = 200.
    let note = event(&author, 1, 100, &json!([]), "note");
    let kind5 = event(&author, 5, 150, &json!([["e", "00".repeat(32)]]), "del");
    let replaceable = event(&author, 0, 120, &json!([]), "meta");
    let addressable = event(&author, 30023, 130, &json!([["d", "a"]]), "post");
    let late = event(&author, 1, 250, &json!([]), "after T");
    // A gift wrap `p`-tagged to the author inside the window, and one
    // `p`-tagged to someone else.
    let wrap_to_author = event(
        &other,
        1059,
        140,
        &json!([["p", pk_hex(&author)]]),
        "sealed",
    );
    let wrap_to_other = event(
        &author,
        1059,
        160,
        &json!([["p", pk_hex(&other)]]),
        "to other",
    );
    let other_note = event(&other, 1, 110, &json!([]), "other's");
    let vanish = event(
        &author,
        62,
        200,
        &json!([["relay", "wss://relay.example.com"]]),
        "bye",
    );
    let written = store
        .write(
            &[
                note,
                kind5,
                replaceable,
                addressable,
                Arc::clone(&late),
                wrap_to_author,
                wrap_to_other,
                Arc::clone(&other_note),
            ],
            Some(&url),
        )
        .unwrap();
    assert!(!written.vanish_pending);
    let vanish_written = store.write(&[Arc::clone(&vanish)], Some(&url)).unwrap();
    assert!(matches!(
        vanish_written.outcomes.as_slice(),
        [WriteOutcome::Stored { .. }]
    ));
    assert!(vanish_written.vanish_pending);
    assert!(store.vanish_pending().unwrap());
    assert!(store.vanish_step(10_000).unwrap().deleted > 0);
    assert!(!store.vanish_pending().unwrap());
    // Only the vanish request itself and the post-T event remain; the
    // wrap to the other author is untouched (its `p` tag points at a
    // pubkey without a vanish point), and the other author's own note
    // survives while the wrap *to* the vanished author is gone.
    assert_eq!(
        served_ids(&store, &author),
        vec![late.id().to_string(), vanish.id().to_string()],
    );
    assert_eq!(
        served_ids(&store, &other),
        vec![other_note.id().to_string()],
    );
}

#[test]
fn vanish_blocks_republish_and_new_writes() {
    let (_dir, store) = store();
    let url = relay_url();
    let (author, other) = (key(1), key(2));
    let old = event(&author, 1, 100, &json!([]), "old");
    store.write(&[Arc::clone(&old)], Some(&url)).unwrap();
    let vanish = event(&author, 62, 200, &json!([["relay", "ALL_RELAYS"]]), "");
    store.write(&[vanish], None).unwrap();
    assert!(store.vanish_step(10_000).unwrap().deleted > 0);
    // Republishing the deleted event, or writing anything at or before
    // T, is refused; a kind-1059 wrap to the vanished author too.
    assert_eq!(
        store.write(&[old], Some(&url)).unwrap().outcomes.as_slice(),
        [WriteOutcome::Vanished]
    );
    let at_t = event(&author, 1, 200, &json!([]), "at T");
    assert_eq!(
        store
            .write(&[at_t], Some(&url))
            .unwrap()
            .outcomes
            .as_slice(),
        [WriteOutcome::Vanished]
    );
    let wrap = event(&other, 1059, 190, &json!([["p", pk_hex(&author)]]), "w");
    assert_eq!(
        store
            .write(&[wrap], Some(&url))
            .unwrap()
            .outcomes
            .as_slice(),
        [WriteOutcome::Vanished]
    );
    // After T stores fine, as does a wrap past T or to someone else.
    let fresh = event(&author, 1, 300, &json!([]), "new");
    assert!(matches!(
        store
            .write(&[fresh], Some(&url))
            .unwrap()
            .outcomes
            .as_slice(),
        [WriteOutcome::Stored { .. }]
    ));
    let wrap_late = event(&other, 1059, 300, &json!([["p", pk_hex(&author)]]), "w2");
    assert!(matches!(
        store
            .write(&[wrap_late], Some(&url))
            .unwrap()
            .outcomes
            .as_slice(),
        [WriteOutcome::Stored { .. }]
    ));
}

#[test]
fn vanish_request_for_another_relay_is_inert() {
    let (_dir, store) = store();
    let url = relay_url();
    let author = key(1);
    let note = event(&author, 1, 100, &json!([]), "kept");
    let vanish = event(
        &author,
        62,
        200,
        &json!([["relay", "wss://other.example.com"]]),
        "",
    );
    let written = store.write(&[note, vanish], Some(&url)).unwrap();
    assert!(!written.vanish_pending);
    assert!(!store.vanish_pending().unwrap());
    assert_eq!(store.vanish_step(10_000).unwrap().deleted, 0);
    // The request is stored and served like any event.
    assert_eq!(served_ids(&store, &author).len(), 2);
}

#[test]
fn all_relays_vanish_applies_without_a_service_url() {
    let (_dir, store) = store();
    let author = key(1);
    let note = event(&author, 1, 100, &json!([]), "gone");
    store.write(&[note], None).unwrap();
    let vanish = event(&author, 62, 200, &json!([["relay", "ALL_RELAYS"]]), "");
    let written = store.write(&[vanish], None).unwrap();
    assert!(written.vanish_pending);
    assert_eq!(store.vanish_step(10_000).unwrap().deleted, 1);
    assert_eq!(served_ids(&store, &author).len(), 1);
}

#[test]
fn kind5_cannot_delete_a_request_to_vanish() {
    let (_dir, store) = store();
    let author = key(1);
    let vanish = event(&author, 62, 100, &json!([["relay", "ALL_RELAYS"]]), "");
    let kind5 = event(
        &author,
        5,
        200,
        &json!([["e", vanish.id().to_string()]]),
        "",
    );
    let written = store.write(&[Arc::clone(&vanish), kind5], None).unwrap();
    assert!(written.vanish_pending);
    // The kind 62 survives the deletion request, and a *different*
    // kind-62 event by the same author is never republish-blocked.
    assert_eq!(store.vanish_step(10_000).unwrap().deleted, 0);
    assert_eq!(served_ids(&store, &author).len(), 2);
    let again = event(&author, 62, 300, &json!([["relay", "ALL_RELAYS"]]), "");
    assert!(matches!(
        store.write(&[again], None).unwrap().outcomes.as_slice(),
        [WriteOutcome::Stored { .. }]
    ));
}

#[test]
fn vanish_step_chunks_and_survives_reopen() {
    let (dir, store) = store();
    let author = key(1);
    let events: Vec<_> = (0..7u64)
        .map(|i| event(&author, 1, 100 + i, &json!([]), &format!("e{i}")))
        .collect();
    store.write(&events, None).unwrap();
    let vanish = event(&author, 62, 500, &json!([["relay", "ALL_RELAYS"]]), "");
    store.write(&[Arc::clone(&vanish)], None).unwrap();
    // A tiny limit drains the backlog across several steps; `more`
    // reports work is still queued.
    let mut total = 0;
    loop {
        let step = store.vanish_step(2).unwrap();
        total += step.deleted;
        assert_eq!(step.more, store.vanish_pending().unwrap());
        if !step.more {
            break;
        }
    }
    assert_eq!(total, 7);
    assert!(!store.vanish_pending().unwrap());
    // Queued work survives a restart: ask for a second vanish point,
    // drop, reopen, drain.
    let more: Vec<_> = (0..3u64)
        .map(|i| event(&author, 1, 600 + i, &json!([]), &format!("f{i}")))
        .collect();
    store.write(&more, None).unwrap();
    let vanish2 = event(&author, 62, 700, &json!([["relay", "ALL_RELAYS"]]), "");
    store.write(&[vanish2], None).unwrap();
    assert!(store.vanish_pending().unwrap());
    drop(store);
    let reopened = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    assert!(reopened.vanish_pending().unwrap());
    assert_eq!(reopened.vanish_step(10_000).unwrap().deleted, 3);
    assert!(!reopened.vanish_pending().unwrap());
}

#[test]
fn vanish_step_examines_mentions_once() {
    let (_dir, store) = store();
    let (author, mentioner) = (key(1), key(3));
    // The vanishing author's own rows plus a large `('p', author)`
    // tag range dominated by non-wrap mentions: every mention is
    // examined once and survives — only wraps are deleted.
    let notes: Vec<_> = (0..3u64)
        .map(|i| event(&author, 1, 100 + i, &json!([]), &format!("n{i}")))
        .collect();
    let mentions: Vec<_> = (0..30u64)
        .map(|i| {
            event(
                &mentioner,
                [1, 7][(i % 2) as usize],
                110 + i,
                &json!([["p", pk_hex(&author)]]),
                &format!("m{i}"),
            )
        })
        .collect();
    let wraps: Vec<_> = (0..2u64)
        .map(|i| {
            event(
                &mentioner,
                1059,
                150 + i,
                &json!([["p", pk_hex(&author)]]),
                &format!("w{i}"),
            )
        })
        .collect();
    let mut batch = notes;
    batch.extend(mentions);
    batch.extend(wraps);
    store.write(&batch, None).unwrap();
    let vanish = event(&author, 62, 500, &json!([["relay", "ALL_RELAYS"]]), "");
    store.write(&[Arc::clone(&vanish)], None).unwrap();
    // 4 author-range rows (3 notes + the kind 62) + 32 tag-range rows
    // = 36 index entries; at most 3 examined per step.
    let mut calls = 0;
    loop {
        calls += 1;
        assert!(calls < 100);
        if !store.vanish_step(3).unwrap().more {
            break;
        }
    }
    // ≈36/3 steps — a restart-per-step walk would need ~36 steps from
    // the re-examined mention prefix alone.
    assert!(calls <= 13, "{calls} steps for 36 index entries");
    // The author's notes and the wraps are gone; every mention
    // survives, as does the request itself.
    assert_eq!(served_ids(&store, &author), vec![vanish.id().to_string()]);
    assert_eq!(served_ids(&store, &mentioner).len(), 30);
}

#[test]
fn vanish_raised_t_covers_rows_past_the_resume() {
    let (_dir, store) = store();
    let (author, other) = (key(1), key(2));
    let notes: Vec<_> = (0..2u64)
        .map(|i| event(&author, 1, 100 + i, &json!([]), &format!("n{i}")))
        .collect();
    let wraps: Vec<_> = (0..5u64)
        .map(|i| {
            event(
                &other,
                1059,
                110 + i,
                &json!([["p", pk_hex(&author)]]),
                &format!("w{i}"),
            )
        })
        .collect();
    let mut batch = notes;
    batch.extend(wraps);
    store.write(&batch, None).unwrap();
    let vanish = event(&author, 62, 200, &json!([["relay", "ALL_RELAYS"]]), "");
    store.write(&[Arc::clone(&vanish)], None).unwrap();
    // One bounded step drains the author range (2 notes + the kind 62)
    // and starts the wraps phase.
    let step = store.vanish_step(4).unwrap();
    assert!(step.more);
    // A newer event past T lands normally, then a second request
    // raises T — restarting the walk so the author range is revisited.
    let later = event(&author, 1, 250, &json!([]), "past T1");
    store.write(&[later], None).unwrap();
    let vanish2 = event(&author, 62, 500, &json!([["relay", "ALL_RELAYS"]]), "");
    store.write(&[Arc::clone(&vanish2)], None).unwrap();
    while store.vanish_step(10_000).unwrap().more {}
    // The event between T1 and T2 vanished with everything else
    // covered; the newer request superseded the older one on store.
    assert_eq!(served_ids(&store, &author), vec![vanish2.id().to_string()],);
}

#[test]
fn vanish_resume_survives_reopen() {
    let (dir, store) = store();
    let (author, mentioner) = (key(1), key(3));
    let note = event(&author, 1, 100, &json!([]), "gone");
    let mentions: Vec<_> = (0..100u64)
        .map(|i| {
            event(
                &mentioner,
                1,
                110 + i,
                &json!([["p", pk_hex(&author)]]),
                &format!("m{i}"),
            )
        })
        .collect();
    let mut batch = vec![note];
    batch.extend(mentions);
    store.write(&batch, None).unwrap();
    let vanish = event(&author, 62, 500, &json!([["relay", "ALL_RELAYS"]]), "");
    store.write(&[Arc::clone(&vanish)], None).unwrap();
    // Examine the author range (note + kind 62) and ~48 mentions
    // across five 10-row steps, then drop and reopen mid-walk.
    let mut calls = 0;
    for _ in 0..5 {
        calls += 1;
        assert!(store.vanish_step(10).unwrap().more);
    }
    drop(store);
    let reopened = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    assert!(reopened.vanish_pending().unwrap());
    while reopened.vanish_step(10).unwrap().more {
        calls += 1;
        assert!(calls < 50);
    }
    // ~102 rows / 10 = 11 calls with the resume position persisted;
    // restarting the tag range after reopen would re-examine the ~48
    // already-seen mentions and take ~16.
    assert!(calls <= 12, "{calls} steps after reopen");
    assert_eq!(
        served_ids(&reopened, &author),
        vec![vanish.id().to_string()]
    );
    assert_eq!(served_ids(&reopened, &mentioner).len(), 100);
}

/// The `PublicKey` of a test keypair (x-only, 32 bytes).
fn pubkey_of(keypair: &secp256k1::Keypair) -> nosfry_core::event::PublicKey {
    nosfry_core::event::PublicKey(keypair.x_only_public_key().0.to_byte_array())
}

#[test]
fn moderation_ops_round_trip() {
    let (_dir, store) = store();
    let (a, b) = (key(1), key(2));
    let (pk_a, pk_b) = (pubkey_of(&a), pubkey_of(&b));

    // Ban with a reason; the ban drops a later-added allow entry and
    // unban leaves an allow entry untouched.
    let mut m = store
        .moderate(nosfry_core::moderation::ModOp::BanPubkey {
            pubkey: pk_a,
            reason: Some("spam".into()),
        })
        .unwrap();
    assert_eq!(m.banned_pubkeys[&pk_a].as_deref(), Some("spam"));
    m = store
        .moderate(nosfry_core::moderation::ModOp::AllowPubkey {
            pubkey: pk_a,
            reason: None,
        })
        .unwrap();
    assert!(m.allowed_pubkeys.contains_key(&pk_a) && m.banned_pubkeys.is_empty());
    m = store
        .moderate(nosfry_core::moderation::ModOp::UnbanPubkey { pubkey: pk_a })
        .unwrap();
    assert!(
        m.allowed_pubkeys.contains_key(&pk_a),
        "unbanpubkey leaves an allow entry"
    );
    m = store
        .moderate(nosfry_core::moderation::ModOp::UnallowPubkey { pubkey: pk_a })
        .unwrap();
    assert!(m.allowed_pubkeys.is_empty());
    store
        .moderate(nosfry_core::moderation::ModOp::BanPubkey {
            pubkey: pk_b,
            reason: None,
        })
        .unwrap();
    m = store
        .moderate(nosfry_core::moderation::ModOp::UnbanPubkey { pubkey: pk_b })
        .unwrap();
    assert!(m.banned_pubkeys.is_empty() && m.allowed_pubkeys.is_empty());

    // allowkind/disallowkind swap the single state byte.
    store
        .moderate(nosfry_core::moderation::ModOp::DisallowKind { kind: 4 })
        .unwrap();
    m = store
        .moderate(nosfry_core::moderation::ModOp::AllowKind { kind: 4 })
        .unwrap();
    assert!(m.allowed_kinds.contains(&4) && !m.disallowed_kinds.contains(&4));
    m = store
        .moderate(nosfry_core::moderation::ModOp::DisallowKind { kind: 4 })
        .unwrap();
    assert!(m.disallowed_kinds.contains(&4) && !m.allowed_kinds.contains(&4));

    // IPs are stored canonical; both families round-trip.
    let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
    store
        .moderate(nosfry_core::moderation::ModOp::BlockIp {
            ip: v6,
            reason: Some("abuse".into()),
        })
        .unwrap();
    m = store
        .moderate(nosfry_core::moderation::ModOp::BlockIp {
            ip: "127.0.0.1".parse().unwrap(),
            reason: None,
        })
        .unwrap();
    assert!(m.ip_blocked(&v6));
    assert!(m.blocked_ips[&"127.0.0.1".parse().unwrap()].is_none());
    m = store
        .moderate(nosfry_core::moderation::ModOp::UnblockIp { ip: v6 })
        .unwrap();
    assert!(!m.ip_blocked(&v6));

    // NIP-11 overrides, including the empty-string override.
    m = store
        .moderate(nosfry_core::moderation::ModOp::SetInfo {
            field: nosfry_core::moderation::InfoField::Name,
            value: "ops".into(),
        })
        .unwrap();
    assert_eq!(m.name.as_deref(), Some("ops"));
    m = store
        .moderate(nosfry_core::moderation::ModOp::SetInfo {
            field: nosfry_core::moderation::InfoField::Description,
            value: String::new(),
        })
        .unwrap();
    assert_eq!(m.description.as_deref(), Some(""));
}

#[test]
fn banevent_deletes_the_stored_event_and_survives_reopen() {
    let (dir, store) = store();
    let author = key(1);
    let note = event(&author, 1, 100, &json!([]), "hi");
    let keep = event(&author, 1, 110, &json!([]), "keep");
    store
        .write(&[Arc::clone(&note), Arc::clone(&keep)], None)
        .unwrap();

    let mut m = store
        .moderate(nosfry_core::moderation::ModOp::BanEvent {
            id: note.id(),
            reason: Some("illegal".into()),
        })
        .unwrap();
    assert_eq!(m.banned_events[&note.id()].as_deref(), Some("illegal"));
    assert_eq!(served_ids(&store, &author), vec![keep.id().to_string()]);
    assert_eq!(m.blocked_reason(&note), Some("blocked: event banned"));
    assert_eq!(m.blocked_reason(&keep), None);
    m = store
        .moderate(nosfry_core::moderation::ModOp::UnbanEvent { id: note.id() })
        .unwrap();
    assert!(m.banned_events.is_empty());

    // The ban (and every other `mod_*` row) persists across reopen.
    store
        .moderate(nosfry_core::moderation::ModOp::BanEvent {
            id: keep.id(),
            reason: None,
        })
        .unwrap();
    drop(store);
    let reopened = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    m = reopened.moderation().unwrap();
    assert!(m.banned_events.contains_key(&keep.id()));
    assert_eq!(served_ids(&reopened, &author), Vec::<String>::new());
}

#[test]
fn blocked_reason_enforces_bans_and_allow_lists() {
    let (_dir, store) = store();
    let (a, b) = (key(1), key(2));
    let pk_of = pubkey_of;
    let note_a = event(&a, 1, 100, &json!([]), "a");
    let note_b = event(&b, 4, 100, &json!([]), "b");

    // Empty snapshot blocks nothing.
    let mut m = store.moderation().unwrap();
    assert_eq!(m.blocked_reason(&note_a), None);

    // Banned author; other authors unaffected.
    m = store
        .moderate(nosfry_core::moderation::ModOp::BanPubkey {
            pubkey: pk_of(&a),
            reason: None,
        })
        .unwrap();
    assert_eq!(
        m.blocked_reason(&note_a),
        Some("blocked: pubkey not allowed")
    );
    assert_eq!(m.blocked_reason(&note_b), None);

    // A non-empty allow list blocks everyone not on it.
    store
        .moderate(nosfry_core::moderation::ModOp::UnbanPubkey { pubkey: pk_of(&a) })
        .unwrap();
    m = store
        .moderate(nosfry_core::moderation::ModOp::AllowPubkey {
            pubkey: pk_of(&b),
            reason: None,
        })
        .unwrap();
    assert_eq!(
        m.blocked_reason(&note_a),
        Some("blocked: pubkey not allowed")
    );
    assert_eq!(m.blocked_reason(&note_b), None);

    // disallowed kind 4; a non-empty allowed-kinds list blocks kinds
    // not on it.
    store
        .moderate(nosfry_core::moderation::ModOp::UnallowPubkey { pubkey: pk_of(&b) })
        .unwrap();
    m = store
        .moderate(nosfry_core::moderation::ModOp::DisallowKind { kind: 4 })
        .unwrap();
    assert_eq!(m.blocked_reason(&note_b), Some("blocked: kind not allowed"));
    assert_eq!(m.blocked_reason(&note_a), None);
    m = store
        .moderate(nosfry_core::moderation::ModOp::AllowKind { kind: 4 })
        .unwrap();
    assert_eq!(m.blocked_reason(&note_b), None, "kind 4 was allowed");
    store
        .moderate(nosfry_core::moderation::ModOp::AllowKind { kind: 1 })
        .unwrap();
    let note_c = event(&a, 7, 100, &json!([]), "c");
    m = store.moderation().unwrap();
    assert_eq!(
        m.blocked_reason(&note_c),
        Some("blocked: kind not allowed"),
        "kind 7 is not on the allow list"
    );
    assert_eq!(m.blocked_reason(&note_a), None);
}

/// NIP-62 bookkeeping: only the author's newest request to vanish is
/// stored; a stored newer one makes the incoming write `Superseded`.
#[test]
fn vanish_request_keeps_only_the_newest() {
    let (_dir, store) = store();
    let url = relay_url();
    let author = key(1);
    let tag = json!([["relay", "wss://relay.example.com"]]);
    let v1 = event(&author, 62, 100, &tag, "v1");
    let v2 = event(&author, 62, 200, &tag, "v2");
    let v3 = event(&author, 62, 150, &tag, "v3");
    let w1 = store.write(&[Arc::clone(&v1)], Some(&url)).unwrap();
    assert_eq!(w1.outcomes, vec![WriteOutcome::Stored { seq: 1 }]);
    let w2 = store.write(&[Arc::clone(&v2)], Some(&url)).unwrap();
    assert_eq!(w2.outcomes, vec![WriteOutcome::Stored { seq: 2 }]);
    let sup = store.write(&[v3], Some(&url)).unwrap();
    assert_eq!(sup.outcomes, vec![WriteOutcome::Superseded]);
    assert_eq!(served_ids(&store, &author), vec![v2.id().to_string()]);
    // The vanish point is still the stored request's T=200: an author
    // event at 150 is blocked.
    let covered = event(&author, 1, 150, &json!([]), "x");
    let van = store.write(&[covered], Some(&url)).unwrap();
    assert_eq!(van.outcomes, vec![WriteOutcome::Vanished]);
    // Equal created_at: the lower id wins.
    let (v4, v5) = (
        event(&author, 62, 300, &tag, "v4"),
        event(&author, 62, 300, &tag, "v5"),
    );
    let (first, second) = if v4.id() < v5.id() {
        (v4, v5)
    } else {
        (v5, v4)
    };
    let w3 = store.write(&[Arc::clone(&first)], Some(&url)).unwrap();
    assert!(matches!(w3.outcomes[0], WriteOutcome::Stored { .. }));
    let tie = store.write(&[second], Some(&url)).unwrap();
    assert_eq!(tie.outcomes, vec![WriteOutcome::Superseded]);
    assert_eq!(served_ids(&store, &author), vec![first.id().to_string()]);
}

/// A superseded kind 62 that names this relay is still honored
/// (NIP-62 MUST): the newer stored request naming another relay is
/// bookkeeping only, while the vanish point still rises.
#[test]
fn vanish_honored_when_superseded_by_foreign_request() {
    let (_dir, store) = store();
    let url = relay_url();
    let author = key(1);
    let note = event(&author, 1, 50, &json!([]), "note");
    store.write(&[note], None).unwrap();
    // Newer request naming another relay: stored, not honored.
    let foreign = event(
        &author,
        62,
        200,
        &json!([["relay", "wss://other.example"]]),
        "",
    );
    let foreign_id = foreign.id().to_string();
    let kept = store.write(&[foreign], Some(&url)).unwrap();
    assert!(matches!(kept.outcomes[0], WriteOutcome::Stored { .. }));
    assert!(!store.vanish_pending().unwrap());
    // Older request naming this relay: superseded at storage yet
    // still honored.
    let honored = event(
        &author,
        62,
        100,
        &json!([["relay", "wss://relay.example.com"]]),
        "",
    );
    let sup = store.write(&[honored], Some(&url)).unwrap();
    assert_eq!(sup.outcomes, vec![WriteOutcome::Superseded]);
    assert!(sup.vanish_pending);
    while store.vanish_step(10_000).unwrap().more {}
    // Only the foreign request remains stored; the covered note is
    // swept and new writes at or before T=100 are refused.
    assert_eq!(served_ids(&store, &author), vec![foreign_id]);
    let blocked = event(&author, 1, 80, &json!([]), "blocked");
    let van = store.write(&[blocked], Some(&url)).unwrap();
    assert_eq!(van.outcomes, vec![WriteOutcome::Vanished]);
}

/// A tag filter with hundreds of values counts an event carrying
/// several covered values exactly once — the cover check searches
/// earlier values, it must not double-count.
#[test]
fn count_many_tag_values_dedups() {
    let (_dir, store) = store();
    let k = key(1);
    let values: Vec<String> = (0..300).map(|i| format!("v{i:03}")).collect();
    let list = values
        .iter()
        .map(|v| format!("\"{v}\""))
        .collect::<Vec<_>>()
        .join(",");
    let filters: Arc<[Filter]> =
        Arc::from([Filter::parse(&format!("{{\"#t\":[{list}]}}")).unwrap()]);
    let two = event(
        &k,
        1,
        100,
        &json!([["t", "v005"], ["t", "v200"]]),
        "two hits",
    );
    let one = event(&k, 1, 110, &json!([["t", "v042"]]), "one hit");
    let miss = event(&k, 1, 120, &json!([["t", "nomatch"]]), "miss");
    store
        .write(&[Arc::clone(&two), Arc::clone(&one), miss], None)
        .unwrap();
    let mut scan = nosfry_lmdb::CountScan::new(
        filters,
        nosfry_core::auth::ReadGate::default(),
        store.snapshot().unwrap(),
        0,
        0,
        None,
    );
    let mut guard = 0usize;
    loop {
        guard += 1;
        assert!(guard < 10_000, "count did not terminate");
        if scan.step(&store, Duration::ZERO).unwrap() == Progress::Done {
            break;
        }
    }
    assert_eq!(scan.result().count, 2);
}
