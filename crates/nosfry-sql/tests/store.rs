//! `SqlStore` unit tests: schema versioning, write outcomes, NIP-09
//! blocks, NIP-40 expiry, and the scan budget.

#![cfg(feature = "rusqlite")]
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
    reason = "tests may panic on failure"
)]

use std::cell::{Cell, RefCell};
use std::ops::ControlFlow;
use std::sync::Arc;

use nosfry_core::auth::ReadGate;
use nosfry_core::event::Event;
use nosfry_core::filter::Filter;
use nosfry_core::sign::{event, key, keys, pubkey_hex};
use nosfry_core::store::{Completion, WriteOutcome};
use nosfry_core::url::RelayNames;
use nosfry_sql::rusqlite::Connection;
use nosfry_sql::{Executor, FORMAT_VERSION, Param, SqlStore, StoreError, Value};
use serde_json::json;

fn store() -> SqlStore<Connection> {
    SqlStore::open(Connection::open_in_memory().unwrap()).unwrap()
}

fn filter(json: &str) -> Filter {
    Filter::parse(json).unwrap()
}

/// A [`Connection`] that counts the index rows its queries stream.
/// Cursor pages select `packed`; payload lookups do not.
#[derive(Debug)]
struct Counting {
    conn: Connection,
    rows: Cell<usize>,
}

impl Counting {
    fn open() -> Self {
        Self {
            conn: Connection::open_in_memory().unwrap(),
            rows: Cell::new(0),
        }
    }

    /// The index rows read since the last call.
    const fn take_index_rows(&self) -> usize {
        self.rows.replace(0)
    }
}

impl Executor for Counting {
    type Error = ::rusqlite::Error;

    fn query(
        &self,
        sql: &str,
        params: &[Param<'_>],
        row: &mut dyn FnMut(Vec<Value>) -> ControlFlow<()>,
    ) -> Result<(), Self::Error> {
        if !sql.contains("packed") {
            return self.conn.query(sql, params, row);
        }
        self.conn.query(sql, params, &mut |values| {
            self.rows.set(self.rows.get() + 1);
            row(values)
        })
    }

    fn execute(&self, sql: &str, params: &[Param<'_>]) -> Result<(), Self::Error> {
        self.conn.execute(sql, params)
    }

    fn transaction<T>(&self, f: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
        self.conn.transaction(f)
    }
}

/// A [`Connection`] that records how many seqs each payload
/// statement binds — `SQL_WINNERS` is the only query selecting
/// `json` without `packed`.
#[derive(Debug)]
struct ChunkCounting {
    conn: Connection,
    sizes: RefCell<Vec<usize>>,
}

impl ChunkCounting {
    fn open() -> Self {
        Self {
            conn: Connection::open_in_memory().unwrap(),
            sizes: RefCell::new(Vec::new()),
        }
    }

    /// The seq count of each payload statement, in call order.
    fn payload_sizes(&self) -> Vec<usize> {
        self.sizes.borrow().clone()
    }
}

impl Executor for ChunkCounting {
    type Error = ::rusqlite::Error;

    fn query(
        &self,
        sql: &str,
        params: &[Param<'_>],
        row: &mut dyn FnMut(Vec<Value>) -> ControlFlow<()>,
    ) -> Result<(), Self::Error> {
        if sql.contains("SELECT seq, json") {
            // `usize::MAX` marks a statement missing its seq list; the
            // assertions below catch it.
            let bound = params
                .first()
                .and_then(|param| match param {
                    Param::Text(list) => serde_json::from_str::<Vec<u64>>(list).ok(),
                    _ => None,
                })
                .map_or(usize::MAX, |v| v.len());
            self.sizes.borrow_mut().push(bound);
        }
        self.conn.query(sql, params, row)
    }

    fn execute(&self, sql: &str, params: &[Param<'_>]) -> Result<(), Self::Error> {
        self.conn.execute(sql, params)
    }

    fn transaction<T>(&self, f: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
        self.conn.transaction(f)
    }
}

/// `MAX(seq)` — the SQL store has no snapshot concept.
fn max_seq<E: Executor>(store: &SqlStore<E>) -> u64 {
    let mut max = 0u64;
    store
        .exec()
        .query("SELECT MAX(seq) FROM events", &[], &mut |row| {
            if let Some(Value::Int(v)) = row.first() {
                max = u64::try_from(*v).unwrap();
            }
            ControlFlow::Continue(())
        })
        .unwrap();
    max
}

fn seqs(store: &SqlStore<Connection>, json: &str, now: u64) -> Vec<u64> {
    let mut seqs = Vec::new();
    store
        .query(
            &[filter(json)],
            &ReadGate::default(),
            now,
            u64::MAX,
            usize::MAX,
            &mut |hit| seqs.push(hit.seq),
        )
        .unwrap();
    seqs
}

#[test]
fn open_stamps_and_verifies_the_format_version() {
    let store = store();
    let mut version = None;
    store
        .exec()
        .query(
            "SELECT value FROM meta WHERE key = 'format'",
            &[],
            &mut |row| {
                if let Some(Value::Int(v)) = row.first() {
                    version = Some(*v);
                }
                ControlFlow::Continue(())
            },
        )
        .unwrap();
    assert_eq!(version, Some(FORMAT_VERSION));

    // An unknown version is refused as corrupt.
    store
        .exec()
        .execute("UPDATE meta SET value = 99 WHERE key = 'format'", &[])
        .unwrap();
    let err = SqlStore::open(store.into_exec()).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)));
}

#[test]
fn write_outcomes_and_scan_order() {
    let store = store();
    let k = key(1);
    let a = event(&k, 1, 100, &json!([]), "a");
    let b = event(&k, 1, 200, &json!([]), "b");
    let c = event(&k, 1, 300, &json!([]), "c");
    let outcomes = store
        .write(
            &[
                Arc::clone(&a),
                Arc::clone(&b),
                Arc::clone(&c),
                Arc::clone(&a),
            ],
            &RelayNames::default(),
        )
        .unwrap()
        .outcomes;
    assert!(matches!(outcomes[0], WriteOutcome::Stored { seq: 1 }));
    assert!(matches!(outcomes[1], WriteOutcome::Stored { seq: 2 }));
    assert!(matches!(outcomes[2], WriteOutcome::Stored { seq: 3 }));
    assert_eq!(outcomes[3], WriteOutcome::Duplicate);

    let mut hits = Vec::new();
    let scan = store
        .query(
            &[filter("{\"kinds\":[1]}")],
            &ReadGate::default(),
            0,
            u64::MAX,
            usize::MAX,
            &mut |hit| hits.push(hit),
        )
        .unwrap();
    assert!(!scan.budget_exhausted);
    let jsons: Vec<&str> = hits.iter().map(|h| h.json.as_ref()).collect();
    assert_eq!(jsons, vec![c.json(), b.json(), a.json()]);
}

#[test]
fn replaceable_supersedes_and_loses() {
    let store = store();
    let k = key(2);
    let old = event(&k, 0, 100, &json!([]), "old");
    let new = event(&k, 0, 200, &json!([]), "new");
    let outcomes = store
        .write(
            &[Arc::clone(&old), Arc::clone(&new)],
            &RelayNames::default(),
        )
        .unwrap()
        .outcomes;
    assert!(matches!(outcomes[1], WriteOutcome::Stored { seq: 2 }));
    // The loser is superseded, not stored.
    let late = store
        .write(&[old], &RelayNames::default())
        .unwrap()
        .outcomes;
    assert_eq!(late[0], WriteOutcome::Superseded);
    // Only the winner serves.
    let mut hits = Vec::new();
    store
        .query(
            &[filter("{\"kinds\":[0]}")],
            &ReadGate::default(),
            0,
            u64::MAX,
            usize::MAX,
            &mut |hit| hits.push(hit),
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].json.as_ref(), new.json());
}

#[test]
fn nip09_blocks_and_deletes() {
    let store = store();
    let k = key(3);
    let victim = event(&k, 1, 100, &json!([]), "victim");
    let kept = event(&k, 1, 200, &json!([]), "kept");
    store
        .write(
            &[Arc::clone(&victim), Arc::clone(&kept)],
            &RelayNames::default(),
        )
        .unwrap();
    let del = event(&k, 5, 300, &json!([["e", format!("{}", victim.id())]]), "");
    let out = store
        .write(&[del], &RelayNames::default())
        .unwrap()
        .outcomes;
    assert!(matches!(out[0], WriteOutcome::Stored { .. }));
    // The victim is gone and stays blocked.
    let mut hits = Vec::new();
    store
        .query(
            &[filter("{\"kinds\":[1]}")],
            &ReadGate::default(),
            0,
            u64::MAX,
            usize::MAX,
            &mut |hit| hits.push(hit),
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].json.as_ref(), kept.json());
    let blocked = store
        .write(&[victim], &RelayNames::default())
        .unwrap()
        .outcomes;
    assert_eq!(blocked[0], WriteOutcome::Deleted);
}

/// `next_expiration` reports the earliest expiring event, `None`
/// when nothing expires.
#[test]
fn next_expiration_tracks_earliest() {
    let store = store();
    let k = key(1);
    assert_eq!(store.next_expiration().unwrap(), None);
    store
        .write(
            &[
                event(&k, 1, 100, &json!([]), "plain"),
                event(&k, 1, 100, &json!([["expiration", "500"]]), "later"),
                event(&k, 1, 100, &json!([["expiration", "150"]]), "soon"),
            ],
            &RelayNames::default(),
        )
        .unwrap();
    assert_eq!(store.next_expiration().unwrap(), Some(150));
    assert_eq!(store.expire(200, 10).unwrap(), 1);
    assert_eq!(store.next_expiration().unwrap(), Some(500));
}

#[test]
fn expire_hides_then_sweeps() {
    let store = store();
    let k = key(4);
    let dying = event(&k, 1, 100, &json!([["expiration", "150"]]), "dying");
    let alive = event(&k, 1, 200, &json!([]), "alive");
    store
        .write(&[dying, alive], &RelayNames::default())
        .unwrap();
    // `now = 0` disables the check; `now = 200` hides the event even
    // before the sweep.
    assert_eq!(seqs(&store, "{\"kinds\":[1]}", 0), vec![2, 1]);
    assert_eq!(seqs(&store, "{\"kinds\":[1]}", 200), vec![2]);
    assert_eq!(store.expire(200, 10).unwrap(), 1);
    assert_eq!(max_seq(&store), 2);
}

#[test]
fn row_budget_bounds_rows_read() {
    let store = SqlStore::open(Counting::open()).unwrap();
    let k = key(5);
    let events: Vec<Arc<Event>> = (0..20u64)
        .map(|i| event(&k, 1, 100 + i, &json!([]), "e"))
        .collect();
    store.write(&events, &RelayNames::default()).unwrap();
    store.exec().take_index_rows();

    let mut hits = Vec::new();
    let scan = store
        .query(
            &[filter("{\"kinds\":[1]}")],
            &ReadGate::default(),
            0,
            u64::MAX,
            5,
            &mut |hit| hits.push(hit),
        )
        .unwrap();
    assert!(scan.budget_exhausted);
    assert!(!hits.is_empty());
    // Results stay newest-first even when truncated by the budget.
    let first = hits.first().unwrap().json.clone();
    assert_eq!(first.as_ref(), events[19].json());
    // `max_rows` bounds rows read: the budget may overshoot by at
    // most the page in flight (here the 16-row first page).
    let read = store.exec().take_index_rows();
    assert!(read <= 5 + 16, "read {read} index rows for a 5-row budget");
}

#[test]
fn first_page_scales_with_the_cursor_count() {
    let store = SqlStore::open(Counting::open()).unwrap();
    let ks = keys();
    let events: Vec<Arc<Event>> = (0..40u64)
        .map(|i| {
            event(
                &ks[usize::try_from(i).unwrap() % 4],
                1,
                100 + i,
                &json!([]),
                "e",
            )
        })
        .collect();
    store.write(&events, &RelayNames::default()).unwrap();
    let authors = (0..4)
        .map(pubkey_hex)
        .map(|pk| format!("\"{pk}\""))
        .collect::<Vec<_>>()
        .join(",");
    store.exec().take_index_rows();
    // limit 4 over 4 author cursors: first pages of 1 row each read
    // about `limit` rows, not 4 × 16.
    let mut hits = Vec::new();
    store
        .query(
            &[filter(&format!("{{\"authors\":[{authors}]}}"))],
            &ReadGate::default(),
            0,
            4,
            usize::MAX,
            &mut |hit| hits.push(hit),
        )
        .unwrap();
    assert_eq!(hits.len(), 4);
    let read = store.exec().take_index_rows();
    assert!(read <= 24, "read {read} index rows for limit 4");
}

/// `count` twin of the LMDB `count_budget_marks_approximate`: the
/// row budget ends the count early with `approximate` and a partial
/// count, never an over-count. A key that drains inside its first
/// page stays exact — the flag marks a scan the budget stopped, not
/// one that merely read over it.
#[test]
fn count_budget_marks_approximate() {
    let store = store();
    let ks = keys();
    let events: Vec<Arc<Event>> = (0..80u64)
        .map(|i| {
            event(
                &ks[usize::try_from(i).unwrap() % 4],
                1,
                100 + i,
                &json!([]),
                "e",
            )
        })
        .collect();
    store.write(&events, &RelayNames::default()).unwrap();
    let authors = (0..4)
        .map(pubkey_hex)
        .map(|pk| format!("\"{pk}\""))
        .collect::<Vec<_>>()
        .join(",");
    let filters = [filter(&format!("{{\"authors\":[{authors}]}}"))];

    let full = store
        .count(&filters, &ReadGate::default(), 0, usize::MAX, None)
        .unwrap();
    assert!(!full.approximate);
    assert_eq!(full.count, events.len() as u64);

    // A 10-row budget lets the first author cursor drain (20 rows in
    // one page) then refuses the next fetch: the answer is
    // approximate and never over-counts.
    let partial = store
        .count(&filters, &ReadGate::default(), 0, 10, None)
        .unwrap();
    assert!(partial.approximate);
    assert!(partial.count <= full.count);
}

/// Payloads are fetched in 64-seq chunks and streamed to the sink
/// in scan order — a REQ never holds more than one chunk.
#[test]
fn payloads_stream_in_64_seq_chunks() {
    let store = SqlStore::open(ChunkCounting::open()).unwrap();
    let k = key(6);
    let events: Vec<Arc<Event>> = (0..150u64)
        .map(|i| event(&k, 1, 100 + i, &json!([]), "e"))
        .collect();
    store.write(&events, &RelayNames::default()).unwrap();

    let mut hits = Vec::new();
    store
        .query(
            &[filter("{\"kinds\":[1]}")],
            &ReadGate::default(),
            0,
            u64::MAX,
            usize::MAX,
            &mut |hit| hits.push(hit),
        )
        .unwrap();
    assert_eq!(hits.len(), 150);
    assert_eq!(store.exec().payload_sizes(), vec![64, 64, 22]);
    // Per-filter newest-first order survives the chunking.
    assert_eq!(hits[0].json.as_ref(), events[149].json());
    assert_eq!(hits[149].json.as_ref(), events[0].json());
}

#[test]
fn int_params_outside_the_js_range_are_rejected() {
    let store = store();
    let mut err = None;
    let result = store
        .exec()
        .query("SELECT ?1", &[Param::Int(i64::MAX)], &mut |_| {
            ControlFlow::Continue(())
        });
    if let Err(e) = result {
        err = Some(e);
    }
    let err = err.unwrap();
    assert!(err.to_string().contains("JavaScript-safe"), "{err}");
}

/// NIP-62 bookkeeping: only the author's newest request to vanish is
/// stored; a stored newer one makes the incoming write `Superseded`.
#[test]
fn vanish_request_keeps_only_the_newest() {
    let store = store();
    let names = RelayNames::parse("wss://relay.example.com", &[]).unwrap();
    let author = key(1);
    let tag = json!([["relay", "wss://relay.example.com"]]);
    let v1 = event(&author, 62, 100, &tag, "v1");
    let v2 = event(&author, 62, 200, &tag, "v2");
    let v3 = event(&author, 62, 150, &tag, "v3");
    assert!(matches!(
        store.write(&[Arc::clone(&v1)], &names).unwrap().outcomes[0],
        WriteOutcome::Stored { .. }
    ));
    assert!(matches!(
        store.write(&[Arc::clone(&v2)], &names).unwrap().outcomes[0],
        WriteOutcome::Stored { .. }
    ));
    let sup = store.write(&[v3], &names).unwrap().outcomes;
    assert_eq!(sup[0], WriteOutcome::Superseded);
    // Only the newest survives; the vanish point stays T=200.
    let mut hits = Vec::new();
    store
        .query(
            &[filter(&format!(
                "{{\"kinds\":[62],\"authors\":[\"{}\"]}}",
                author.x_only_public_key().0
            ))],
            &ReadGate::default(),
            0,
            u64::MAX,
            usize::MAX,
            &mut |hit| hits.push(hit.json.to_string()),
        )
        .unwrap();
    assert_eq!(hits, vec![v2.json()]);
    let covered = event(&author, 1, 150, &json!([]), "x");
    let van = store.write(&[covered], &names).unwrap().outcomes;
    assert_eq!(van[0], WriteOutcome::Vanished);
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
    assert!(matches!(
        store.write(&[Arc::clone(&first)], &names).unwrap().outcomes[0],
        WriteOutcome::Stored { .. }
    ));
    let tie = store.write(&[second], &names).unwrap().outcomes;
    assert_eq!(tie[0], WriteOutcome::Superseded);
    let mut kept = Vec::new();
    store
        .query(
            &[filter(&format!(
                "{{\"kinds\":[62],\"authors\":[\"{}\"]}}",
                author.x_only_public_key().0
            ))],
            &ReadGate::default(),
            0,
            u64::MAX,
            usize::MAX,
            &mut |hit| kept.push(hit.json.to_string()),
        )
        .unwrap();
    assert_eq!(kept, vec![first.json()]);
}

/// A superseded kind 62 that names this relay is still honored
/// (NIP-62 MUST): the newer stored request naming another relay is
/// bookkeeping only, while the vanish point still rises.
#[test]
fn vanish_honored_when_superseded_by_foreign_request() {
    let store = store();
    let names = RelayNames::parse("wss://relay.example.com", &[]).unwrap();
    let author = key(1);
    let note = event(&author, 1, 50, &json!([]), "note");
    store.write(&[note], &RelayNames::default()).unwrap();
    // Newer request naming another relay: stored, not honored.
    let foreign = event(
        &author,
        62,
        200,
        &json!([["relay", "wss://other.example"]]),
        "",
    );
    let stored = store.write(&[Arc::clone(&foreign)], &names).unwrap();
    assert!(matches!(stored.outcomes[0], WriteOutcome::Stored { .. }));
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
    let sup = store.write(&[honored], &names).unwrap();
    assert_eq!(sup.outcomes, vec![WriteOutcome::Superseded]);
    assert!(sup.vanish_pending);
    while store.vanish_step(10_000).unwrap().more {}
    // Only the foreign request remains stored; the covered note is
    // swept and new writes at or before T=100 are refused.
    let mut kept = Vec::new();
    store
        .query(
            &[filter(&format!(
                "{{\"authors\":[\"{}\"]}}",
                author.x_only_public_key().0
            ))],
            &ReadGate::default(),
            0,
            u64::MAX,
            usize::MAX,
            &mut |hit| kept.push(hit.json.to_string()),
        )
        .unwrap();
    assert_eq!(kept, vec![foreign.json()]);
    let blocked = event(&author, 1, 80, &json!([]), "blocked");
    let van = store.write(&[blocked], &names).unwrap();
    assert_eq!(van.outcomes, vec![WriteOutcome::Vanished]);
}

/// A `created_at` tie group is bounded by the limit: 2,000 events at
/// one timestamp still answer only the lowest ids, id-ascending, and
/// an overlapping second filter dedups the same seqs.
#[test]
fn created_at_tie_group_is_bounded() {
    let store = store();
    let k = key(1);
    let events: Vec<Arc<Event>> = (0..2_000u64)
        .map(|i| event(&k, 1, 100, &json!([]), &format!("{i:04}")))
        .collect();
    store.write(&events, &RelayNames::default()).unwrap();
    let mut ids: Vec<String> = events.iter().map(|e| e.id().to_string()).collect();
    ids.sort_unstable();
    let want = ids[..5].to_vec();
    let serve = |filters: &[Filter]| {
        let mut got = Vec::new();
        store
            .query(
                filters,
                &ReadGate::default(),
                0,
                u64::MAX,
                usize::MAX,
                &mut |hit| {
                    got.push(
                        serde_json::from_str::<serde_json::Value>(&hit.json).unwrap()["id"]
                            .as_str()
                            .unwrap()
                            .to_owned(),
                    );
                },
            )
            .unwrap();
        got
    };
    let single = [filter("{\"limit\":5}")];
    assert_eq!(serve(&single), want);
    // The same seqs through an overlapping filter arrive once.
    let pair = [
        filter("{\"limit\":5}"),
        filter("{\"kinds\":[1],\"limit\":5}"),
    ];
    assert_eq!(serve(&pair), want);
}

/// A tag filter with hundreds of values counts an event carrying
/// several covered values exactly once — the cover check searches
/// earlier values, it must not double-count.
#[test]
fn count_many_tag_values_dedups() {
    let store = store();
    let k = key(1);
    let values: Vec<String> = (0..300).map(|i| format!("v{i:03}")).collect();
    let list = values
        .iter()
        .map(|v| format!("\"{v}\""))
        .collect::<Vec<_>>()
        .join(",");
    let filters = [filter(&format!("{{\"#t\":[{list}]}}"))];
    let two = event(
        &k,
        1,
        100,
        &json!([["t", "v005"], ["t", "v200"]]),
        "two hits",
    );
    let one = event(&k, 1, 110, &json!([["t", "v042"]]), "one hit");
    let miss = event(&k, 1, 120, &json!([]), "miss");
    store
        .write(
            &[Arc::clone(&two), Arc::clone(&one), miss],
            &RelayNames::default(),
        )
        .unwrap();
    let result = store
        .count(&filters, &ReadGate::default(), 0, usize::MAX, None)
        .unwrap();
    assert!(!result.approximate);
    assert_eq!(result.count, 2);
}

/// Whether `id` is served by an `ids` scan right now.
fn served_id(store: &SqlStore<Connection>, id: &str) -> usize {
    seqs(store, &format!("{{\"ids\":[\"{id}\"]}}"), 0).len()
}

/// NIP-59: a stored kind-1059 gift wrap is deletable by a kind 5 of
/// any `p`-tagged recipient — including a non-first `p` value —
/// while a third party's kind 5 has no effect and a `p`-tagged
/// event of another kind is never deletable by the recipient. The
/// re-publish block lifts with the carrier kind 5.
#[test]
fn gift_wrap_recipient_deletes() {
    let store = store();
    let w = key(4); // a NIP-59 wrap signs with a random one-off key
    let r = key(1);
    let x = key(3);
    let wrap = event(&w, 1059, 100, &json!([["p", pubkey_hex(0)]]), "wrap");
    let wrap2 = event(
        &w,
        1059,
        101,
        &json!([["p", pubkey_hex(1)], ["p", pubkey_hex(0)]]),
        "wrap2",
    );
    let dm = event(&w, 4, 102, &json!([["p", pubkey_hex(0)]]), "dm");
    let out = store
        .write(
            &[Arc::clone(&wrap), Arc::clone(&wrap2), Arc::clone(&dm)],
            &RelayNames::default(),
        )
        .unwrap();
    assert!(
        out.outcomes
            .iter()
            .all(|o| matches!(o, WriteOutcome::Stored { .. })),
        "{:?}",
        out.outcomes
    );

    // A third party's kind 5 on the wraps deletes nothing.
    let foreign = event(
        &x,
        5,
        200,
        &json!([
            ["e", wrap.id().to_string()],
            ["e", wrap2.id().to_string()],
            ["k", "1059"]
        ]),
        "",
    );
    store.write(&[foreign], &RelayNames::default()).unwrap();
    assert_eq!(served_id(&store, &wrap.id().to_string()), 1);
    assert_eq!(served_id(&store, &wrap2.id().to_string()), 1);

    // The `p` recipient's kind 5 deletes both wraps — `wrap2` via
    // its non-first `p` value — but not the kind-4 DM.
    let del = event(
        &r,
        5,
        201,
        &json!([
            ["e", wrap.id().to_string()],
            ["e", wrap2.id().to_string()],
            ["e", dm.id().to_string()],
            ["k", "1059"],
            ["k", "4"],
            ["expiration", "300"]
        ]),
        "",
    );
    let del_out = store.write(&[del], &RelayNames::default()).unwrap();
    assert!(matches!(del_out.outcomes[0], WriteOutcome::Stored { .. }));
    assert_eq!(
        served_id(&store, &wrap.id().to_string()),
        0,
        "recipient's kind 5 did not delete the wrap"
    );
    assert_eq!(
        served_id(&store, &wrap2.id().to_string()),
        0,
        "non-first `p` recipient did not delete the wrap"
    );
    assert_eq!(
        served_id(&store, &dm.id().to_string()),
        1,
        "a non-1059 `p`-tagged event must survive"
    );

    // The block holds for re-publication until the carrier expires.
    let block_out = store
        .write(&[Arc::clone(&wrap)], &RelayNames::default())
        .unwrap();
    assert_eq!(block_out.outcomes[0], WriteOutcome::Deleted);
    store.expire(300, usize::MAX).unwrap();
    let lift_out = store.write(&[wrap], &RelayNames::default()).unwrap();
    assert!(
        matches!(lift_out.outcomes[0], WriteOutcome::Stored { .. }),
        "{:?}",
        lift_out.outcomes
    );
}

/// NIP-09: kinds 5 and 62 are never deletable, and an ephemeral
/// kind never consults deletion blocks (it is never stored).
#[test]
fn deletion_immune_kinds_and_ephemeral() {
    let store = store();
    let k = key(1);
    let carrier = event(&k, 5, 100, &json!([["e", "00".repeat(32)]]), "del");
    let vanish = event(&k, 62, 100, &json!([]), "vanish");
    let eph = event(&k, 21059, 100, &json!([["p", "00".repeat(32)]]), "eph");
    store
        .write(
            &[Arc::clone(&carrier), Arc::clone(&vanish)],
            &RelayNames::default(),
        )
        .unwrap();
    // A same-author kind 5 targeting the carrier, the request to
    // vanish, and the (never stored) ephemeral id deletes nothing.
    let del = event(
        &k,
        5,
        200,
        &json!([
            ["e", carrier.id().to_string()],
            ["e", vanish.id().to_string()],
            ["e", eph.id().to_string()]
        ]),
        "",
    );
    store.write(&[del], &RelayNames::default()).unwrap();
    assert_eq!(served_id(&store, &carrier.id().to_string()), 1);
    assert_eq!(served_id(&store, &vanish.id().to_string()), 1);
    // The block row exists for the ephemeral id, yet the ephemeral
    // publish is `Ephemeral`, not `Deleted`.
    let out = store.write(&[eph], &RelayNames::default()).unwrap();
    assert_eq!(out.outcomes[0], WriteOutcome::Ephemeral);
}

/// Run `filters` under `gate`, answering the emitted seqs and the
/// scan's NIP-67 [`Completion`].
fn collect_completion(
    store: &SqlStore<Connection>,
    filters: &[&str],
    gate: &ReadGate,
) -> (Vec<u64>, Completion) {
    let filters: Vec<Filter> = filters.iter().map(|f| filter(f)).collect();
    let out = RefCell::new(Vec::new());
    let scan = store
        .query(&filters, gate, 0, u64::MAX, usize::MAX, &mut |hit| {
            out.borrow_mut().push(hit.seq);
        })
        .unwrap();
    (out.into_inner(), scan.completion)
}

/// NIP-67 `finish`: an `ids` lookup that serves every match reports
/// `exhausted` and no `more`.
#[test]
fn scan_completion_ids_lookup_is_exhausted() {
    let store = store();
    let ev = event(&key(1), 1, 100, &json!([]), "x");
    store
        .write(&[Arc::clone(&ev)], &RelayNames::default())
        .unwrap();
    let filter = format!("{{\"ids\":[\"{}\"]}}", ev.id());
    let (emitted, completion) = collect_completion(&store, &[&filter], &ReadGate::default());
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert_eq!(
        completion,
        Completion {
            exhausted: true,
            more: false
        }
    );
}

/// Three stored events under `limit: 2` prove an unsent match: `more`,
/// never `exhausted`.
#[test]
fn scan_completion_limit_cut_reports_more() {
    let store = store();
    let k = key(1);
    let events = [
        event(&k, 1, 100, &json!([]), "a"),
        event(&k, 1, 200, &json!([]), "b"),
        event(&k, 1, 300, &json!([]), "c"),
    ];
    store
        .write(
            &events.iter().map(Arc::clone).collect::<Vec<_>>(),
            &RelayNames::default(),
        )
        .unwrap();
    let (emitted, completion) =
        collect_completion(&store, &["{\"limit\":2}"], &ReadGate::default());
    assert_eq!(emitted.len(), 2, "{emitted:?}");
    assert_eq!(
        completion,
        Completion {
            exhausted: false,
            more: true
        }
    );
}

/// Fewer matches than the limit: the merge ran dry — `exhausted`.
#[test]
fn scan_completion_under_limit_is_exhausted() {
    let store = store();
    let k = key(1);
    let events = [
        event(&k, 1, 100, &json!([]), "a"),
        event(&k, 1, 200, &json!([]), "b"),
    ];
    store
        .write(
            &events.iter().map(Arc::clone).collect::<Vec<_>>(),
            &RelayNames::default(),
        )
        .unwrap();
    let (_, completion) = collect_completion(&store, &["{\"limit\":5}"], &ReadGate::default());
    assert_eq!(
        completion,
        Completion {
            exhausted: true,
            more: false
        }
    );
}

/// The limit reached exactly at the end of the data still ran dry —
/// `exhausted`, no `more`.
#[test]
fn scan_completion_limit_at_end_is_exhausted() {
    let store = store();
    let k = key(1);
    let events = [
        event(&k, 1, 100, &json!([]), "a"),
        event(&k, 1, 200, &json!([]), "b"),
        event(&k, 1, 300, &json!([]), "c"),
    ];
    store
        .write(
            &events.iter().map(Arc::clone).collect::<Vec<_>>(),
            &RelayNames::default(),
        )
        .unwrap();
    let (emitted, completion) =
        collect_completion(&store, &["{\"limit\":3}"], &ReadGate::default());
    assert_eq!(emitted.len(), 3, "{emitted:?}");
    assert_eq!(
        completion,
        Completion {
            exhausted: true,
            more: false
        }
    );
}

/// A hidden (restricted) event beyond the limit is never a `more`
/// witness: the emitted events equal the store without it.
#[test]
fn scan_completion_hidden_event_is_never_a_witness() {
    let rules = Arc::new(nosfry_core::auth::AuthRules::new(
        RelayNames::default(),
        &[4],
        true,
    ));
    let gate = ReadGate::new(rules, Arc::from(&[][..]));
    let k = key(1);
    let v1 = event(&k, 1, 200, &json!([]), "v1");
    let v2 = event(&k, 1, 300, &json!([]), "v2");
    let hidden = event(&k, 4, 100, &json!([]), "hidden");

    let with_hidden = store();
    with_hidden
        .write(
            &[Arc::clone(&v1), Arc::clone(&v2), Arc::clone(&hidden)],
            &RelayNames::default(),
        )
        .unwrap();
    let (emitted_with, completion_with) =
        collect_completion(&with_hidden, &["{\"limit\":2}"], &gate);

    let without_hidden = store();
    without_hidden
        .write(&[v1, v2], &RelayNames::default())
        .unwrap();
    let (emitted_without, completion_without) =
        collect_completion(&without_hidden, &["{\"limit\":2}"], &gate);

    assert_eq!(emitted_with, emitted_without);
    assert!(!completion_with.more, "{completion_with:?}");
    // The hidden head-check candidate is unproven below the cut:
    // the scan can only report the cut, not exhaustion.
    assert!(!completion_with.exhausted, "{completion_with:?}");
    assert_eq!(
        completion_without,
        Completion {
            exhausted: true,
            more: false
        }
    );
}

/// Filter 2's limit-cut witness was already emitted by filter 1:
/// `more` must not fire for an event the client received.
#[test]
fn scan_completion_emitted_witness_is_not_more() {
    let store = store();
    let k = key(1);
    let events = [
        event(&k, 1, 100, &json!([]), "a"),
        event(&k, 1, 200, &json!([]), "b"),
        event(&k, 1, 300, &json!([]), "c"),
    ];
    store
        .write(
            &events.iter().map(Arc::clone).collect::<Vec<_>>(),
            &RelayNames::default(),
        )
        .unwrap();
    let (emitted, completion) = collect_completion(
        &store,
        &["{\"kinds\":[1]}", "{\"kinds\":[1],\"limit\":2}"],
        &ReadGate::default(),
    );
    assert_eq!(emitted.len(), 3, "{emitted:?}");
    // Filter 2 was cut (`exhausted` falls) but its witness is in the
    // emitted union, so `more` does not fire.
    assert_eq!(
        completion,
        Completion {
            exhausted: false,
            more: false
        }
    );
}
