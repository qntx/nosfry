//! Generated event and filter specs: strategies that favor
//! overlapping ids, authors, tags and time windows so the
//! differential suite exercises every cursor shape.

use std::sync::Arc;

use nosfry_core::event::Event;
use nosfry_core::sign::{event, keys, pubkey_hex};
use proptest::prelude::*;
use serde_json::json;

/// The relay URL the suite writes with — also the `relay` tag
/// value [`TagSpec::RelayService`] emits.
pub const SERVICE_URL: &str = "wss://relay.example.com";

/// One tag of a generated event, resolved against the case's id
/// corpus and key pool at build time.
#[derive(Debug, Clone)]
pub enum TagSpec {
    /// `e` reference into the corpus ids.
    E(usize),
    /// `p` reference into the key pool.
    P(usize),
    /// `t` string tag.
    T(String),
    /// `d` string tag.
    D(String),
    /// `a` value of an earlier spec's kind/author/d.
    A(usize),
    /// `a` value with a foreign pubkey.
    AForeign(usize),
    /// Malformed `a` value.
    ABad(String),
    /// NIP-62 `relay` tag holding `ALL_RELAYS`.
    RelayAll,
    /// `relay` tag naming [`SERVICE_URL`] — honored.
    RelayService,
    /// `relay` tag naming a foreign relay — never honored.
    RelayForeign,
}

/// One generated event before signing.
#[derive(Debug, Clone)]
pub struct EventSpec {
    /// Index into the shared key pool.
    pub key: usize,
    /// Event kind.
    pub kind: u16,
    /// `created_at` seconds.
    pub created_at: u64,
    /// Tag specs resolved at build time.
    pub tags: Vec<TagSpec>,
    /// Event content.
    pub content: String,
    /// NIP-40 `expiration`, when the spec carries one.
    pub expiration: Option<u64>,
}

/// One generated filter; `Mixed` merges two specs' JSON maps.
#[derive(Debug, Clone)]
pub enum FilterSpec {
    /// No conditions.
    Any,
    /// `kinds` list.
    Kinds(Vec<u16>),
    /// `authors` pool references.
    Authors(Vec<usize>),
    /// `authors` and `kinds` together.
    AuthorsKinds(Vec<usize>, Vec<u16>),
    /// `ids` corpus references.
    Ids(Vec<usize>),
    /// `#e` corpus references.
    TagE(Vec<usize>),
    /// `#p` pool references.
    TagP(Vec<usize>),
    /// `#<letter>` string values.
    TagStr(u8, Vec<String>),
    /// `since`/`until` window.
    Range(Option<u64>, Option<u64>),
    /// `limit`.
    Limit(u64),
    /// An empty `kinds` list.
    EmptyKinds,
    /// An empty tag list.
    EmptyTag,
    /// Merge two specs into one filter.
    Mixed(Box<Self>, Box<Self>),
}

/// The `a` value of spec `i` — its kind, an (optionally foreign)
/// author, and its first `d` value, matching `Event::address`.
fn a_value(i: usize, foreign: bool, specs: &[EventSpec]) -> String {
    let s = &specs[i % specs.len().max(1)];
    let key = if foreign { (s.key + 1) % 4 } else { s.key };
    let d = s
        .tags
        .iter()
        .find_map(|t| match t {
            TagSpec::D(d) => Some(d.as_str()),
            _ => None,
        })
        .unwrap_or("");
    format!("{}:{}:{d}", s.kind, pubkey_hex(key))
}

fn tag_json(tag: &TagSpec, ids: &[String], specs: &[EventSpec]) -> serde_json::Value {
    match tag {
        TagSpec::E(i) => json!(["e", ids[i % ids.len().max(1)]]),
        TagSpec::P(i) => json!(["p", pubkey_hex(i % 4)]),
        TagSpec::T(s) => json!(["t", s]),
        TagSpec::D(s) => json!(["d", s]),
        TagSpec::A(i) => json!(["a", a_value(*i, false, specs)]),
        TagSpec::AForeign(i) => json!(["a", a_value(*i, true, specs)]),
        TagSpec::ABad(s) => json!(["a", s]),
        TagSpec::RelayAll => json!(["relay", "ALL_RELAYS"]),
        TagSpec::RelayService => json!(["relay", SERVICE_URL]),
        TagSpec::RelayForeign => json!(["relay", "wss://foreign.example.com"]),
    }
}

/// Sign the event a spec describes; `ids` resolves `e` references,
/// `specs` resolves `a` references.
#[must_use]
pub(crate) fn build_event(spec: &EventSpec, ids: &[String], specs: &[EventSpec]) -> Arc<Event> {
    let mut tags: Vec<serde_json::Value> =
        spec.tags.iter().map(|t| tag_json(t, ids, specs)).collect();
    if let Some(exp) = spec.expiration {
        tags.push(json!(["expiration", exp.to_string()]));
    }
    event(
        &keys()[spec.key % 4],
        spec.kind,
        spec.created_at,
        &json!(tags),
        &spec.content,
    )
}

/// The JSON map a filter spec describes; `ids` resolves id
/// references.
#[must_use]
pub fn filter_json(
    spec: &FilterSpec,
    ids: &[String],
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    let mut merge = |s: &FilterSpec| map.extend(filter_json(s, ids));
    match spec {
        FilterSpec::Any => {}
        FilterSpec::Kinds(kinds) => {
            map.insert("kinds".into(), json!(kinds));
        }
        FilterSpec::Authors(ks) => {
            map.insert(
                "authors".into(),
                json!(ks.iter().map(|k| pubkey_hex(k % 4)).collect::<Vec<_>>()),
            );
        }
        FilterSpec::AuthorsKinds(ks, kinds) => {
            map.insert(
                "authors".into(),
                json!(ks.iter().map(|k| pubkey_hex(k % 4)).collect::<Vec<_>>()),
            );
            map.insert("kinds".into(), json!(kinds));
        }
        FilterSpec::Ids(is) => {
            map.insert(
                "ids".into(),
                json!(
                    is.iter()
                        .map(|i| ids[i % ids.len().max(1)].clone())
                        .collect::<Vec<_>>()
                ),
            );
        }
        FilterSpec::TagE(is) => {
            map.insert(
                "#e".into(),
                json!(
                    is.iter()
                        .map(|i| ids[i % ids.len().max(1)].clone())
                        .collect::<Vec<_>>()
                ),
            );
        }
        FilterSpec::TagP(is) => {
            map.insert(
                "#p".into(),
                json!(is.iter().map(|i| pubkey_hex(i % 4)).collect::<Vec<_>>()),
            );
        }
        FilterSpec::TagStr(name, vals) => {
            map.insert(format!("#{}", *name as char), json!(vals));
        }
        FilterSpec::Range(since, until) => {
            if let Some(s) = since {
                map.insert("since".into(), json!(s));
            }
            if let Some(u) = until {
                map.insert("until".into(), json!(u));
            }
        }
        FilterSpec::Limit(n) => {
            map.insert("limit".into(), json!(n));
        }
        FilterSpec::EmptyKinds => {
            map.insert("kinds".into(), json!([]));
        }
        FilterSpec::EmptyTag => {
            map.insert("#t".into(), json!([]));
        }
        FilterSpec::Mixed(a, b) => {
            merge(a);
            merge(b);
        }
    }
    map
}

/// Tag-spec generation: `e`/`p` references, `t`/`d` strings and `a`
/// values (valid, foreign, malformed).
pub fn tag_strategy() -> impl Strategy<Value = TagSpec> {
    prop_oneof![
        2 => (0usize..8).prop_map(TagSpec::E),
        2 => (0usize..4).prop_map(TagSpec::P),
        4 => prop_oneof![
            Just("a".to_owned()),
            Just("b".to_owned()),
            Just("nostr".to_owned()),
            Just("x".repeat(300)),
        ].prop_map(TagSpec::T),
        3 => prop_oneof![
            Just("d1".to_owned()),
            Just("d2".to_owned()),
            Just("long".repeat(80)),
        ].prop_map(TagSpec::D),
        2 => (0usize..40).prop_map(TagSpec::A),
        1 => (0usize..40).prop_map(TagSpec::AForeign),
        1 => prop_oneof![
            Just("garbage".to_owned()),
            Just("1:xyz:d".to_owned()),
            Just("abc::d".to_owned()),
            Just("70000:00:d".to_owned()),
            Just("1:".to_owned()),
        ].prop_map(TagSpec::ABad),
        2 => prop_oneof![
            Just(TagSpec::RelayAll),
            Just(TagSpec::RelayService),
            Just(TagSpec::RelayForeign),
        ],
    ]
}

/// Event-spec generation across regular, replaceable, addressable,
/// kind-5 and expiring events.
pub fn event_spec_strategy() -> impl Strategy<Value = EventSpec> {
    (
        0usize..4,
        prop_oneof![
            4 => Just(1u16),
            2 => Just(0u16),
            1 => Just(3u16),
            1 => Just(20_001u16),
            3 => Just(30_001u16),
            1 => Just(30_002u16),
            2 => Just(5u16),
            1 => Just(62u16),
            1 => Just(1059u16),
        ],
        0u64..30,
        proptest::collection::vec(tag_strategy(), 0..4),
        proptest::collection::vec(0u8..8, 1..6),
        prop_oneof![3 => Just(None), 1 => (100u64..400).prop_map(Some)],
    )
        .prop_map(|(key, kind, created_at, mut tags, content, expiration)| {
            // A kind-62 spec always carries a `relay` tag so the
            // vanish paths actually fire, rotating which URL it
            // names; a kind-1059 wrap always `p`-tags a pool key.
            if kind == 62
                && !tags.iter().any(|t| {
                    matches!(
                        t,
                        TagSpec::RelayAll | TagSpec::RelayService | TagSpec::RelayForeign
                    )
                })
            {
                tags.push(match (key + usize::try_from(created_at).unwrap_or(0)) % 3 {
                    0 => TagSpec::RelayAll,
                    1 => TagSpec::RelayService,
                    _ => TagSpec::RelayForeign,
                });
            }
            if kind == 1059 && !tags.iter().any(|t| matches!(t, TagSpec::P(_))) {
                tags.push(TagSpec::P(key + 1));
            }
            EventSpec {
                key,
                kind,
                created_at,
                tags,
                content: content.iter().map(|b| char::from(b'a' + b)).collect(),
                expiration,
            }
        })
}

/// Event-spec vectors that cover NIP-59 recipient deletion.
///
/// `event_spec_strategy` vectors with the first kind-1059 wrap
/// guaranteed an `e`-deletion kind 5 by its `p` recipient — placed
/// before the wrap half the time (decided by its index parity) so
/// both the delete-stored and the block-on-ingest orderings of
/// NIP-59 fire.
pub fn event_specs_strategy() -> impl Strategy<Value = Vec<EventSpec>> {
    proptest::collection::vec(event_spec_strategy(), 1..40).prop_map(|mut specs| {
        let Some(wrap) = specs.iter().position(|spec| spec.kind == 1059) else {
            return specs;
        };
        let recipient = specs[wrap]
            .tags
            .iter()
            .find_map(|tag| match tag {
                TagSpec::P(i) => Some(*i % 4),
                _ => None,
            })
            .unwrap_or_else(|| (specs[wrap].key + 1) % 4);
        // Insert before or after the wrap; `E(target)` resolves
        // against the final `ids` list, so the target index accounts
        // for the shift the insertion itself causes.
        let (pos, target) = if wrap % 2 == 0 {
            (wrap, wrap + 1)
        } else {
            (wrap + 1, wrap)
        };
        let created_at = specs[wrap].created_at + 1;
        specs.insert(
            pos,
            EventSpec {
                key: recipient,
                kind: 5,
                created_at,
                tags: vec![TagSpec::E(target)],
                content: "wrap deletion".to_owned(),
                expiration: None,
            },
        );
        specs
    })
}

/// Filter-spec generation covering every cursor shape plus empty
/// lists and merged conditions.
pub fn filter_spec_strategy() -> impl Strategy<Value = FilterSpec> {
    let leaf = prop_oneof![
        3 => Just(FilterSpec::Any),
        3 => proptest::collection::vec(
            prop_oneof![Just(1u16), Just(0u16), Just(30_001u16), Just(20_001u16), Just(7u16)],
            1..3,
        ).prop_map(FilterSpec::Kinds),
        2 => proptest::collection::vec(0usize..4, 1..3).prop_map(FilterSpec::Authors),
        2 => (
            proptest::collection::vec(0usize..4, 1..3),
            proptest::collection::vec(prop_oneof![Just(1u16), Just(30_001u16)], 1..3),
        ).prop_map(|(a, k)| FilterSpec::AuthorsKinds(a, k)),
        2 => proptest::collection::vec(0usize..8, 1..4).prop_map(FilterSpec::Ids),
        2 => proptest::collection::vec(0usize..8, 1..3).prop_map(FilterSpec::TagE),
        2 => proptest::collection::vec(0usize..4, 1..3).prop_map(FilterSpec::TagP),
        2 => (
            prop_oneof![Just(b't'), Just(b'd')],
            proptest::collection::vec(
                prop_oneof![
                    Just("a".to_owned()),
                    Just("b".to_owned()),
                    Just("nostr".to_owned()),
                    Just("zzz".to_owned()),
                ],
                1..3,
            ),
        ).prop_map(|(n, v)| FilterSpec::TagStr(n, v)),
        2 => (
            proptest::option::of(0u64..20),
            proptest::option::of(10u64..40),
        ).prop_map(|(s, u)| FilterSpec::Range(s, u)),
        2 => (0u64..8).prop_map(FilterSpec::Limit),
        1 => Just(FilterSpec::EmptyKinds),
        1 => Just(FilterSpec::EmptyTag),
    ];
    leaf.prop_recursive(2, 8, 3, |inner| {
        (inner.clone(), inner).prop_map(|(a, b)| FilterSpec::Mixed(Box::new(a), Box::new(b)))
    })
}
