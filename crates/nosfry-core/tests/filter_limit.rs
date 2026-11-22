//! `vectors/filter-limit.json` runner.

#![allow(
    unused_crate_dependencies,
    reason = "each test binary uses a subset of the workspace dependencies"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "each file is a single vector runner or property test"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "vector fixtures may panic on failure"
)]
#![allow(
    clippy::shadow_unrelated,
    reason = "the loop variables intentionally shadow per-case bindings"
)]

mod common;

use nosfry_core::filter::Filter;
use serde::Deserialize;

/// `(filter JSON substring, why)` — oracle SDK cases the relay resolves
/// differently.
const DIVERGENCES: &[(&str, &str)] = &[(
    "\"#d\":[]",
    "empty `#` value lists make the filter impossible (NIP-01 MUST), so the      intrinsic limit is 0 rather than unbounded",
)];

/// `(filter JSON substring, why)` — oracle SDK cases the relay rejects
/// outright rather than resolving.
const REJECTIONS: &[(&str, &str)] = &[
    (
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "NIP-01 01.md: `ids`/`authors`/`#e`/`#p` values must be exact lowercase hex",
    ),
    (
        "90A80DB6EB294B9EAB0B4E8DDFA3EFE7263458CE2D07566DF4E6C58868FEEF23",
        "NIP-01 01.md: `ids`/`authors`/`#e`/`#p` values must be exact lowercase hex",
    ),
];

#[derive(Deserialize)]
struct Case {
    filter: serde_json::Value,
    limit: Option<u64>,
}

#[test]
fn filter_limit() {
    let cases = common::cases::<Case>("filter-limit.json");
    assert_eq!(cases.len(), 22, "vector count drift");
    let mut divergent = 0usize;
    for (i, case) in cases.iter().enumerate() {
        let filter_json = serde_json::to_string(&case.filter).expect("filter json");
        if let Some((_, why)) = REJECTIONS.iter().find(|(pat, _)| filter_json.contains(pat)) {
            divergent += 1;
            assert!(
                Filter::parse(&filter_json).is_err(),
                "case {i}: expected relay rejection ({why})"
            );
            continue;
        }
        let filter = Filter::parse(&filter_json)
            .unwrap_or_else(|e| panic!("case {i}: filter parse: {e} ({filter_json})"));
        if DIVERGENCES.iter().any(|(pat, _)| filter_json.contains(pat)) {
            divergent += 1;
            assert!(
                filter.is_impossible() && filter.intrinsic_limit() == Some(0),
                "case {i}: {filter_json}"
            );
            continue;
        }
        assert_eq!(
            filter.intrinsic_limit(),
            case.limit,
            "case {i}: {filter_json}"
        );
    }
    assert_eq!(divergent, 3, "divergence count drift");
}
