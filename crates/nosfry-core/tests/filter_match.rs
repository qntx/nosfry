//! `vectors/filter-match.json` runner: events go through
//! `PackedEvent::build` (their ids/signatures are fake).

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

use nosfry_core::event::{EventId, PublicKey};
use nosfry_core::filter::Filter;
use nosfry_core::kind::Kind;
use nosfry_core::packed::PackedEvent;
use serde::{Deserialize, Serialize};

/// `(filter JSON substring, why)` — cases the relay rejects where the
/// SDK canonicalizes silently.
const DIVERGENCES: &[(&str, &str)] = &[
    (
        "\"#custom\"",
        "relay policy (strfry): unknown filter keys are rejected, not ignored",
    ),
    (
        "\"#missing\"",
        "relay policy (strfry): unknown filter keys are rejected, not ignored",
    ),
    (
        "\"#1\"",
        "relay policy (strfry): `#` keys must be exactly one ASCII letter",
    ),
    (
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "NIP-01 01.md: `ids`/`authors`/`#e`/`#p` values must be exact lowercase hex",
    ),
    (
        "90A80DB6EB294B9EAB0B4E8DDFA3EFE7263458CE2D07566DF4E6C58868FEEF23",
        "NIP-01 01.md: `ids`/`authors`/`#e`/`#p` values must be exact lowercase hex",
    ),
    (
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "NIP-01 01.md: `ids`/`authors`/`#e`/`#p` values must be exact lowercase hex",
    ),
];

#[derive(Deserialize)]
struct Case {
    filter: serde_json::Value,
    event: WireEvent,
    matches: bool,
}

#[derive(Deserialize, Serialize)]
struct WireEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
}

#[test]
fn filter_match() {
    let cases = common::cases::<Case>("filter-match.json");
    assert_eq!(cases.len(), 36, "vector count drift");
    let mut divergent = 0usize;
    for (i, case) in cases.iter().enumerate() {
        let filter_json = serde_json::to_string(&case.filter).expect("filter json");
        if let Some((_, why)) = DIVERGENCES
            .iter()
            .find(|(pat, _)| filter_json.contains(pat))
        {
            divergent += 1;
            assert!(
                Filter::parse(&filter_json).is_err(),
                "case {i}: expected relay rejection ({why})"
            );
            continue;
        }
        let filter = Filter::parse(&filter_json)
            .unwrap_or_else(|e| panic!("case {i}: filter parse: {e} ({filter_json})"));
        let id = EventId::from_hex(&case.event.id).expect("event id hex");
        let pubkey = PublicKey::from_hex(&case.event.pubkey).expect("event pubkey hex");
        let packed = PackedEvent::build(
            &id,
            &pubkey,
            case.event.created_at,
            Kind(case.event.kind),
            0,
            &case.event.tags,
        );
        assert_eq!(
            filter.matches(packed.packed()),
            case.matches,
            "case {i}: {filter_json} vs {}",
            serde_json::to_string(&case.event).unwrap_or_default()
        );
    }
    assert_eq!(divergent, 9, "divergence count drift");
}
