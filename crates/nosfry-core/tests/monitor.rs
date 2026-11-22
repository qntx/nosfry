//! Live monitor read gating (NIP-42 restricted kinds).

#![allow(
    unused_crate_dependencies,
    reason = "each test binary uses a subset of the workspace dependencies"
)]
#![allow(
    clippy::tests_outside_test_module,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code may panic on failure"
)]

use std::sync::Arc;

use nosfry_core::auth::{AuthRules, ReadGate};
use nosfry_core::event::{EventId, PublicKey};
use nosfry_core::filter::Filter;
use nosfry_core::kind::Kind;
use nosfry_core::message::SubId;
use nosfry_core::monitor::Monitors;
use nosfry_core::packed::PackedEvent;
use nosfry_core::session::SubKey;
use nosfry_core::url::RelayNames;

#[test]
fn restricted_event_reaches_only_involved_authed_subs() {
    let rules = Arc::new(AuthRules::new(
        RelayNames::parse("wss://relay.example.com", &[]).unwrap(),
        nosfry_core::access::AccessRules::compile(&nosfry_core::access::AccessConfig {
            rules: vec![nosfry_core::access::RuleConfig {
                kinds: Some(vec![4]),
                read: vec![
                    nosfry_core::access::Reader::Author,
                    nosfry_core::access::Reader::Recipient,
                ],
                write: nosfry_core::access::Writer::Open,
            }],
            anonymous_kinds: Vec::new(),
        })
        .unwrap(),
    ));
    let filters: Arc<[Filter]> = Arc::from(vec![Filter::parse("{\"kinds\":[4]}").unwrap()]);
    let mut monitors = Monitors::<u8>::new();
    // conn 1: unauthenticated; conn 2: authed but uninvolved;
    // conn 3: authed p-tag recipient; conn 4: authed author.
    let authed =
        |keys: &[[u8; 32]]| -> Arc<[PublicKey]> { keys.iter().map(|pk| PublicKey(*pk)).collect() };
    for (conn, keys) in [
        (1, vec![]),
        (2, vec![[9u8; 32]]),
        (3, vec![[7u8; 32]]),
        (4, vec![[1u8; 32]]),
    ] {
        monitors.insert(
            conn,
            SubKey {
                id: SubId::parse("s").unwrap(),
                generation: 1,
            },
            Arc::clone(&filters),
            ReadGate::new(Arc::clone(&rules), authed(&keys)),
        );
    }
    let dm = PackedEvent::build(
        &EventId([5; 32]),
        &PublicKey([1; 32]),
        1_700_000_000,
        Kind(4),
        0,
        &[["p".to_owned(), faster_hex::hex_string(&[7u8; 32])]],
    );
    let mut hits = Vec::new();
    monitors.matches(dm.packed(), &mut hits);
    let mut conns: Vec<u8> = hits.iter().map(|(conn, _)| *conn).collect();
    conns.sort_unstable();
    assert_eq!(conns, [3, 4]);
}
