//! `vectors/message-client.json` runner.
//!
//! `error` cases must fail to parse; `encoded` cases must parse and
//! re-encode to the canonical wire form (rebuilt from the public accessors
//! by `common::message_wire`); bare `raw` cases must parse. The
//! serde/strfry-vs-JSON.parse divergences below are the only permitted
//! deviations, each pinned to a raw substring.

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

use nosfry_core::message::{
    ClientMessage, EoseHints, SubId, closed_frame, count_frame, eose_frame, event_frame,
};
use nosfry_core::store::Completion;
use serde::Deserialize;

/// `(raw substring, why)` — each pattern identifies exactly one case.
const DIVERGENCES: &[(&str, &str)] = &[
    (
        "\"kinds\":[9],\"kinds\":[1]",
        "duplicate `kinds` key and float `1e2`: serde rejects, JSON.parse \
         takes the last value",
    ),
    (
        "\"since\":\"x\",\"since\":5",
        "duplicate `since` key: serde rejects, JSON.parse takes the last value",
    ),
    (
        "\"kinds\":[{}],\"kinds\":[7]",
        "duplicate `kinds` key: serde rejects, JSON.parse takes the last value",
    ),
    (
        "\"ids\":[123],\"ids\"",
        "duplicate `ids` key: serde rejects, JSON.parse takes the last value",
    ),
    (
        "\"limit\":null,\"limit\":3",
        "duplicate `limit` key: serde rejects, JSON.parse takes the last value",
    ),
    (
        "1e3",
        "float spellings `1e3`/`2.0`/`-0`: serde rejects, JSON.parse accepts",
    ),
    (
        "9007199254740991.0",
        "float spelling: serde rejects, JSON.parse accepts",
    ),
    (
        "\"foo\":1",
        "relay policy (strfry): unknown filter keys are rejected, not ignored",
    ),
    (
        "\"#custom\"",
        "relay policy (strfry): unknown filter keys are rejected, not ignored",
    ),
    (
        "9007199254740992",
        "values >= 2^53 accepted as u64 where the SDK rejects them",
    ),
];

#[derive(Deserialize)]
struct Case {
    raw: String,
    encoded: Option<String>,
    error: Option<String>,
}

#[test]
fn message_client() {
    let cases = common::cases::<Case>("message-client.json");
    assert_eq!(cases.len(), 92, "vector count drift");
    let mut divergent = 0usize;
    for (i, case) in cases.iter().enumerate() {
        let outcome = ClientMessage::parse(&case.raw);
        let divergence = DIVERGENCES.iter().find(|(pat, _)| case.raw.contains(pat));
        if case.error.is_some() {
            if let Some((_, why)) = divergence {
                assert!(
                    outcome.is_ok(),
                    "case {i}: oracle expects an error but nosfry accepts ({why})"
                );
                divergent += 1;
            } else {
                assert!(
                    outcome.is_err(),
                    "case {i} ({}): expected error, got {:?}",
                    case.raw,
                    outcome.map(common::message_wire)
                );
            }
            continue;
        }
        match outcome {
            Ok(message) => {
                assert!(
                    divergence.is_none(),
                    "case {i}: parsed yet listed as divergent",
                );
                if let Some(encoded) = &case.encoded {
                    assert_eq!(
                        &common::message_wire(message),
                        encoded,
                        "case {i}: {}",
                        case.raw
                    );
                }
            }
            Err(e) => {
                if divergence.is_some() {
                    divergent += 1;
                    continue;
                }
                panic!("case {i} ({}): expected success, got {e}", case.raw);
            }
        }
    }
    assert_eq!(divergent, DIVERGENCES.len(), "divergence count drift");
}

/// Escaped JSON strings are legal subscription ids: they parse to the
/// unescaped value, and every emitted frame re-escapes them correctly.
#[test]
fn escaped_subscription_ids() {
    let message = ClientMessage::parse("[\"REQ\",\"a\\\"b\",{}]").expect("REQ parses");
    let ClientMessage::Req { sub_id, .. } = message else {
        panic!("expected REQ")
    };
    assert_eq!(sub_id.as_str(), "a\"b");

    let message = ClientMessage::parse("[\"CLOSE\",\"\\u00e9\"]").expect("CLOSE parses");
    let ClientMessage::Close { sub_id } = message else {
        panic!("expected CLOSE")
    };
    assert_eq!(sub_id.as_str(), "é");

    // The echoed frames carry the id as a properly escaped JSON string.
    let quoted = SubId::parse("a\"b").expect("sub id");
    for frame in [
        eose_frame(&quoted, EoseHints::default()),
        closed_frame(&quoted, "closed: test"),
        event_frame(&quoted, "{}"),
    ] {
        let items: Vec<serde_json::Value> =
            serde_json::from_str(&frame).expect("frame is valid JSON");
        assert_eq!(
            items.get(1).and_then(|v| v.as_str()),
            Some("a\"b"),
            "frame {frame} re-escapes the id"
        );
    }
    assert_eq!(
        eose_frame(&sub_id, EoseHints::default()),
        "[\"EOSE\",\"é\"]"
    );
}

/// `eose_frame` NIP-67 wire shapes: no hints keeps the two-element
/// frame; `"auth"` comes first, then `"finish"` or `"more"`.
#[test]
fn eose_frame_hints() {
    let sub = SubId::parse("s").expect("sub id");
    let cases: &[(EoseHints, &str)] = &[
        (EoseHints::default(), r#"["EOSE","s"]"#),
        (
            EoseHints {
                auth: true,
                finish: false,
                more: false,
            },
            r#"["EOSE","s",["auth"]]"#,
        ),
        (
            EoseHints {
                auth: false,
                finish: true,
                more: false,
            },
            r#"["EOSE","s",["finish"]]"#,
        ),
        (
            EoseHints {
                auth: false,
                finish: false,
                more: true,
            },
            r#"["EOSE","s",["more"]]"#,
        ),
        (
            EoseHints {
                auth: true,
                finish: true,
                more: false,
            },
            r#"["EOSE","s",["auth","finish"]]"#,
        ),
        (
            EoseHints {
                auth: true,
                finish: false,
                more: true,
            },
            r#"["EOSE","s",["auth","more"]]"#,
        ),
        (
            EoseHints {
                auth: false,
                finish: true,
                more: true,
            },
            r#"["EOSE","s",["finish"]]"#,
        ),
        (
            EoseHints {
                auth: true,
                finish: true,
                more: true,
            },
            r#"["EOSE","s",["auth","finish"]]"#,
        ),
    ];
    for (hints, expected) in cases {
        let frame = eose_frame(&sub, *hints);
        assert_eq!(&frame, expected, "hints {hints:?}");
        let parsed: serde_json::Value = serde_json::from_str(&frame).expect("frame is valid JSON");
        assert_eq!(parsed[0], "EOSE", "{frame}");
    }
}

/// `EoseHints::new`: `finish` follows `exhausted`, `more` needs a
/// witness and is never emitted alongside `finish`.
#[test]
fn eose_hints_new() {
    let nothing = Completion::default();
    assert_eq!(EoseHints::new(nothing, false), EoseHints::default());
    let exhausted = Completion {
        exhausted: true,
        more: false,
    };
    assert_eq!(
        EoseHints::new(exhausted, false),
        EoseHints {
            finish: true,
            ..EoseHints::default()
        }
    );
    // An exhausted scan never also reports `more`.
    let both = Completion {
        exhausted: true,
        more: true,
    };
    assert_eq!(
        EoseHints::new(both, true),
        EoseHints {
            auth: true,
            finish: true,
            more: false,
        }
    );
    let cut = Completion {
        exhausted: false,
        more: true,
    };
    assert_eq!(
        EoseHints::new(cut, false),
        EoseHints {
            more: true,
            ..EoseHints::default()
        }
    );
    // A cut with no witness reports nothing.
    let silent = Completion {
        exhausted: false,
        more: false,
    };
    assert_eq!(EoseHints::new(silent, false), EoseHints::default());
    assert_eq!(
        EoseHints::new(silent, true),
        EoseHints {
            auth: true,
            ..EoseHints::default()
        }
    );
}

/// `count_frame` wire shapes: bare count, approximate flag, and the
/// 512-char hll field, each only when asked.
#[test]
fn count_frame_shapes() {
    let sub = SubId::parse("c").expect("sub id");
    assert_eq!(
        count_frame(&sub, 42, false, None),
        r#"["COUNT","c",{"count":42}]"#
    );
    assert_eq!(
        count_frame(&sub, 7, true, None),
        r#"["COUNT","c",{"count":7,"approximate":true}]"#
    );
    let registers = [0xabu8; 256];
    let frame = count_frame(&sub, 0, false, Some(&registers));
    let body: serde_json::Value = serde_json::from_str(&frame).expect("valid JSON");
    assert_eq!(body[0], "COUNT");
    assert_eq!(body[1], "c");
    assert_eq!(body[2]["count"], 0);
    assert!(body[2].get("approximate").is_none());
    let hll = body[2]["hll"].as_str().expect("hll hex");
    assert_eq!(hll.len(), 512);
    assert!(hll.bytes().all(|b| b == b'a' || b == b'b'));
    // All flags at once.
    let body: serde_json::Value =
        serde_json::from_str(&count_frame(&sub, 1, true, Some(&registers))).expect("valid JSON");
    assert_eq!(body[2]["approximate"], true);
    assert_eq!(body[2]["hll"].as_str().expect("hll").len(), 512);
}
