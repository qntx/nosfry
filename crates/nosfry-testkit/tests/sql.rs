//! Differential test: `SqlStore::query` output vs the shared
//! in-memory model — the same suite `nosfry-lmdb` runs.

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

use std::ops::ControlFlow;
use std::sync::Arc;

use nosfry_core::auth::ReadGate;
use nosfry_core::event::Event;
use nosfry_core::filter::Filter;
use nosfry_core::hll::Hll;
use nosfry_core::moderation::{ModOp, Moderation};
use nosfry_core::store::WriteOutcome;
use nosfry_core::url::RelayNames;
use nosfry_sql::rusqlite::Connection;
use nosfry_sql::{Executor, SqlStore, Value};
use nosfry_testkit::driver::{Count, StoreDriver, StoreRecords, build_case, check};
use nosfry_testkit::spec::{SERVICE_URL, event_specs_strategy, filter_spec_strategy};
use proptest::prelude::*;

/// The SQL store driven through the shared suite.
struct SqlDriver {
    store: SqlStore<Connection>,
}

impl StoreDriver for SqlDriver {
    fn write(&mut self, events: &[Arc<Event>]) -> Vec<WriteOutcome> {
        let names = RelayNames::parse(SERVICE_URL, &[]).unwrap();
        self.store.write(events, &names).unwrap().outcomes
    }

    fn snapshot(&mut self) -> u64 {
        // The SQL store has no snapshot concept; scans just see
        // current state, so `MAX(seq)` is the driver's bound.
        let mut max = 0u64;
        self.store
            .exec()
            .query("SELECT MAX(seq) FROM events", &[], &mut |row| {
                if let Some(&Value::Int(v)) = row.first() {
                    max = u64::try_from(v).unwrap();
                }
                ControlFlow::Continue(())
            })
            .unwrap();
        max
    }

    fn scan(
        &mut self,
        filters: Arc<[Filter]>,
        gate: &ReadGate,
        _snapshot: u64,
        max_limit: u64,
        now: u64,
    ) -> Vec<String> {
        let mut hits = Vec::new();
        self.store
            .query(&filters, gate, now, max_limit, usize::MAX, &mut |hit| {
                hits.push(hit.json.to_string());
            })
            .unwrap();
        hits
    }

    fn records(
        &mut self,
        filters: Arc<[Filter]>,
        gate: &ReadGate,
        _snapshot: u64,
        max_limit: u64,
        now: u64,
    ) -> StoreRecords {
        let result = self
            .store
            .records(&filters, gate, now, max_limit, usize::MAX)
            .unwrap();
        StoreRecords {
            records: result.records,
            budget_exhausted: result.budget_exhausted,
        }
    }

    fn count(
        &mut self,
        filters: Arc<[Filter]>,
        gate: &ReadGate,
        _snapshot: u64,
        now: u64,
    ) -> Count {
        let result = self
            .store
            .count(&filters, gate, now, usize::MAX, Hll::for_filters(&filters))
            .unwrap();
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

/// The shared NIP-86 script replays identically on SQL.
#[test]
fn moderation_script() {
    let store = SqlStore::open(Connection::open_in_memory().unwrap()).unwrap();
    nosfry_testkit::driver::moderation_check(&mut SqlDriver { store });
}

/// The shared NIP-09/NIP-59 script replays identically on SQL.
#[test]
fn deletion_script() {
    let store = SqlStore::open(Connection::open_in_memory().unwrap()).unwrap();
    nosfry_testkit::driver::deletion_check(&mut SqlDriver { store });
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
        let store = SqlStore::open(Connection::open_in_memory().unwrap()).unwrap();
        let case = build_case(&specs, batches, filter_specs, max_limit, now, now2);
        let mut driver = SqlDriver { store };
        check(&mut driver, &case)?;
    }
}
