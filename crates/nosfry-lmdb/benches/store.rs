//! Criterion bench: 1000-event write batches and a limited kind scan
//! over `100_000` stored events.

#![allow(
    unsafe_code,
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs,
    reason = "bench fixtures may panic; deps cover every bench binary"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use nosfry_core::event::Event;
use nosfry_core::filter::Filter;
use nosfry_core::sign as common;
use nosfry_core::url::RelayNames;
use nosfry_lmdb::{Progress, Scan, Store, StoreOptions};
use serde_json::json;

fn open() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &StoreOptions::default()).unwrap();
    (dir, store)
}

fn events(key: &secp256k1::Keypair, from: u64, n: u64) -> Vec<Arc<Event>> {
    // p tags cycle a pool of 20 pubkeys so multi-value `#p` filters match.
    let keys: Vec<secp256k1::Keypair> = (1..=20u8).map(common::key).collect();
    (from..from + n)
        .map(|i| {
            let pk = keys[usize::try_from(i).unwrap_or_default() % 20]
                .x_only_public_key()
                .0;
            common::event(key, 1, i, &json!([["p", format!("{pk}")]]), "bench")
        })
        .collect()
}

fn emitted_count(store: &Store, filters: &Arc<[Filter]>) -> usize {
    let snapshot = store.snapshot().unwrap();
    let mut scan = Scan::new(
        Arc::clone(filters),
        nosfry_core::auth::ReadGate::default(),
        snapshot,
        500,
        0,
    );
    let mut emitted = 0usize;
    while scan
        .step(store, Duration::from_secs(3_600), &mut |_, _| {
            emitted += 1;
        })
        .unwrap()
        == Progress::Pending
    {}
    emitted
}

fn first_emit(store: &Store, filters: &Arc<[Filter]>) -> Duration {
    let snapshot = store.snapshot().unwrap();
    let mut scan = Scan::new(
        Arc::clone(filters),
        nosfry_core::auth::ReadGate::default(),
        snapshot,
        500,
        0,
    );
    let started = std::time::Instant::now();
    let mut first = None;
    scan.step(store, Duration::from_secs(3_600), &mut |_, _| {
        if first.is_none() {
            first = Some(started.elapsed());
        }
    })
    .unwrap();
    first.unwrap_or_default()
}

fn author_setup() -> (tempfile::TempDir, Store, Arc<[Filter]>) {
    let (dir, store) = open();
    let keys: Vec<secp256k1::Keypair> = (1..=50u8).map(common::key).collect();
    let events: Vec<Arc<Event>> = (0..100_000u64)
        .map(|i| {
            common::event(
                &keys[usize::try_from(i).unwrap_or_default() % 50],
                1,
                i,
                &json!([]),
                "bench",
            )
        })
        .collect();
    for chunk in events.chunks(10_000) {
        store.write(chunk, &RelayNames::default()).unwrap();
    }
    let authors_json = format!(
        "{{\"authors\":[{}],\"limit\":500}}",
        keys.iter()
            .map(|k| format!("\"{}\"", k.x_only_public_key().0))
            .collect::<Vec<_>>()
            .join(",")
    );
    (
        dir,
        store,
        Arc::from([Filter::parse(&authors_json).unwrap()]),
    )
}

fn bench_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("nosfry_lmdb");
    group.sample_size(10);

    // Write batches of 1000 unique events; event generation is untimed.
    let (_dir, store) = open();
    let key = common::key(7);
    let counter = AtomicU64::new(0);
    group.bench_function("write_batch_1000", |b| {
        b.iter_custom(|iters| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iters {
                let base = counter.fetch_add(1_000, Ordering::Relaxed);
                let batch = events(&key, 10_000_000 + base, 1_000);
                let started = std::time::Instant::now();
                store.write(&batch, &RelayNames::default()).unwrap();
                elapsed += started.elapsed();
            }
            elapsed
        });
    });

    // Scan kinds:[1] limit 500 over 100k stored events.
    let (_dir2, store2) = open();
    for chunk in events(&key, 0, 100_000).chunks(10_000) {
        store2.write(chunk, &RelayNames::default()).unwrap();
    }
    let filters: Arc<[Filter]> =
        Arc::from([Filter::parse("{\"kinds\":[1],\"limit\":500}").unwrap()]);
    group.bench_function("scan_kinds1_limit500_100k", |b| {
        b.iter(|| emitted_count(&store2, &filters));
    });

    // Scan a 20-value `#p` filter over the same 100k corpus.
    let pks: Vec<String> = (1..=20u8)
        .map(|n| format!("{}", common::key(n).x_only_public_key().0))
        .collect();
    let p_json = format!(
        "{{\"#p\":[{}],\"limit\":500}}",
        pks.iter()
            .map(|pk| format!("\"{pk}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    let p_filters: Arc<[Filter]> = Arc::from([Filter::parse(&p_json).unwrap()]);
    group.bench_function("scan_tagp20_limit500_100k", |b| {
        b.iter(|| emitted_count(&store2, &p_filters));
    });

    // Scan a 50-value `authors` filter over 100k events spread across
    // those authors.
    let (_dir3, store3, author_filters) = author_setup();
    group.bench_function("scan_authors50_limit500_100k", |b| {
        b.iter(|| emitted_count(&store3, &author_filters));
    });
    // Time from step start until the emit callback first fires.
    group.bench_function("scan_first_emit_kinds1_limit500_100k", |b| {
        b.iter_custom(|iters| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iters {
                elapsed += first_emit(&store2, &filters);
            }
            elapsed
        });
    });
    group.finish();
}

criterion_group!(benches, bench_store);
criterion_main!(benches);
