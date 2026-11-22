//! Differential test: `Scan` output vs a naive in-memory model.

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
    clippy::too_many_lines,
    reason = "tests may panic on failure"
)]

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use nosfry_core::auth::ReadGate;
use nosfry_core::event::Event;
use nosfry_core::filter::Filter;
use nosfry_core::hll::Hll;
use nosfry_core::moderation::{ModOp, Moderation};
use nosfry_core::sign::{event, keys};
use nosfry_core::store::WriteOutcome;
use nosfry_core::url::RelayNames;
use nosfry_lmdb::{CountResult, CountScan, Progress, Scan, Store, StoreOptions};
use nosfry_testkit::driver::{Count, StoreDriver, StoreRecords, build_case, check};
use nosfry_testkit::spec::{SERVICE_URL, event_specs_strategy, filter_spec_strategy};
use proptest::prelude::*;
use serde_json::json;

fn store_scan_gated(
    store: &Store,
    filters: Arc<[Filter]>,
    gate: ReadGate,
    snapshot: u64,
    max_limit: u64,
    now: u64,
) -> Vec<String> {
    let mut scan = Scan::new(filters, gate, snapshot, max_limit, now);
    let out = RefCell::new(Vec::new());
    let mut guard = 0usize;
    loop {
        guard += 1;
        assert!(guard < 10_000, "scan did not terminate");
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

/// Run a [`CountScan`] to completion (`0` entry budget = uncapped).
fn store_count(
    store: &Store,
    filters: Arc<[Filter]>,
    gate: ReadGate,
    snapshot: u64,
    budget_entries: u64,
    now: u64,
    hll: Option<Hll>,
) -> CountResult {
    let mut scan = CountScan::new(filters, gate, snapshot, budget_entries, now, hll);
    let mut guard = 0usize;
    loop {
        guard += 1;
        assert!(guard < 100_000, "count scan did not terminate");
        let progress = scan.step(store, Duration::ZERO).unwrap();
        if progress == Progress::Done {
            break;
        }
    }
    scan.result()
}

/// The LMDB store driven through the shared suite.
struct LmdbDriver<'a> {
    store: &'a Store,
}

impl StoreDriver for LmdbDriver<'_> {
    fn write(&mut self, events: &[Arc<Event>]) -> Vec<WriteOutcome> {
        let names = RelayNames::parse(SERVICE_URL, &[]).unwrap();
        self.store.write(events, &names).unwrap().outcomes
    }

    fn snapshot(&mut self) -> u64 {
        self.store.snapshot().unwrap()
    }

    fn scan(
        &mut self,
        filters: Arc<[Filter]>,
        gate: &ReadGate,
        snapshot: u64,
        max_limit: u64,
        now: u64,
    ) -> Vec<String> {
        store_scan_gated(self.store, filters, gate.clone(), snapshot, max_limit, now)
    }

    fn records(
        &mut self,
        filters: Arc<[Filter]>,
        gate: &ReadGate,
        snapshot: u64,
        max_limit: u64,
        now: u64,
    ) -> StoreRecords {
        let mut scan = Scan::new(filters, gate.clone(), snapshot, max_limit, now);
        let out = RefCell::new(Vec::new());
        let mut guard = 0usize;
        loop {
            guard += 1;
            assert!(guard < 10_000, "records scan did not terminate");
            let progress = scan
                .step_records(self.store, Duration::ZERO, &mut |created_at, id| {
                    out.borrow_mut().push((created_at, id));
                })
                .unwrap();
            if progress == Progress::Done {
                break;
            }
        }
        StoreRecords {
            records: out.into_inner(),
            budget_exhausted: false,
        }
    }

    fn count(&mut self, filters: Arc<[Filter]>, gate: &ReadGate, snapshot: u64, now: u64) -> Count {
        let hll = Hll::for_filters(&filters);
        let result = store_count(self.store, filters, gate.clone(), snapshot, 0, now, hll);
        Count {
            count: result.count,
            approximate: result.approximate,
            hll: result.hll,
        }
    }

    fn expire(&mut self, now: u64) {
        self.store.expire(now, usize::MAX).unwrap();
    }

    fn drain_vanish(&mut self) {
        while self.store.vanish_step(3).unwrap().more {}
    }

    fn moderate(&mut self, op: ModOp) -> Moderation {
        self.store.moderate(op).unwrap()
    }
}

/// The shared NIP-86 script replays identically on LMDB.
#[test]
fn moderation_script() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    nosfry_testkit::driver::moderation_check(&mut LmdbDriver { store: &store });
}

/// The shared NIP-09/NIP-59 script replays identically on LMDB.
#[test]
fn deletion_script() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    nosfry_testkit::driver::deletion_check(&mut LmdbDriver { store: &store });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn scan_matches_model(
        specs in event_specs_strategy(),
        batches in proptest::collection::vec(1usize..20, 1..5),
        filter_specs in proptest::collection::vec(filter_spec_strategy(), 1..4),
        max_limit in prop_oneof![Just(3u64), Just(7u64), Just(500u64)],
        now in 0u64..600,
        now2 in 0u64..600,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();

        let case = build_case(&specs, batches, filter_specs, max_limit, now, now2);
        let mut driver = LmdbDriver { store: &store };
        check(&mut driver, &case)?;
    }
}

/// Hitting the entry budget ends the scan early and reports a partial
/// count — never a wrong one.
#[test]
fn count_budget_marks_approximate() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    let events: Vec<Arc<Event>> = (0..40u64)
        .map(|i| {
            event(
                &keys()[usize::try_from(i).unwrap() % 4],
                1,
                1_700_000_000 + i,
                &json!([]),
                &format!("e{i}"),
            )
        })
        .collect();
    store.write(&events, &RelayNames::default()).unwrap();

    let filters: Arc<[Filter]> = Arc::from(vec![Filter::parse("{\"kinds\":[1]}").unwrap()]);
    let snapshot = store.snapshot().unwrap();
    let full = store_count(
        &store,
        Arc::clone(&filters),
        ReadGate::default(),
        snapshot,
        0,
        u64::MAX,
        None,
    );
    assert!(!full.approximate);
    assert_eq!(full.count, events.len() as u64);

    // Fewer index entries than there are matches: the answer is
    // approximate and never over-counts.
    let partial = store_count(
        &store,
        filters,
        ReadGate::default(),
        snapshot,
        10,
        u64::MAX,
        None,
    );
    assert!(partial.approximate);
    assert!(partial.count <= full.count);
}
