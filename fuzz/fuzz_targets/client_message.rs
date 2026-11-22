#![no_main]

//! Feed newline-separated frames into ONE `Session` and assert the
//! protocol invariants on every emitted `Command`.

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use nosfry_core::auth::AuthRules;
use nosfry_core::event::EventLimits;
use nosfry_core::limits::{AddressBuckets, Limits, RateLimits, ReqLimits};
use nosfry_core::message::ClientMessage;
use nosfry_core::session::{Command, Session};
use serde_json::Value;

fn limits() -> Arc<Limits> {
    Arc::new(Limits {
        event: EventLimits::default(),
        req: ReqLimits {
            max_req_filter_size: 3,
            max_subs_per_connection: 4,
            max_tags_per_filter: 3,
            ..ReqLimits::default()
        },
        rate: RateLimits {
            events_per_second: 5,
            events_burst: 10,
            reqs_per_second: 5,
            reqs_burst: 10,
            ip_events_per_second: 0,
            ip_events_burst: 0,
            ip_reqs_per_second: 0,
            ip_reqs_burst: 0,
        },
        auth: Arc::new(AuthRules::new(
            nosfry_core::url::RelayNames::parse("wss://fuzz.example", &[]).unwrap(),
            nosfry_core::access::AccessRules::compile(&nosfry_core::access::AccessConfig {
                rules: vec![nosfry_core::access::RuleConfig {
                    kinds: Some(vec![4, 1059]),
                    read: vec![
                        nosfry_core::access::Reader::Author,
                        nosfry_core::access::Reader::Recipient,
                    ],
                    write: nosfry_core::access::Writer::Open,
                }],
                anonymous_kinds: Vec::new(),
            })
            .unwrap(),
        )),
    })
}

fuzz_target!(|data: &[u8]| {
    let mut session = Session::new(
        limits(),
        "fuzzchallenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    );
    let mut out = Vec::new();
    let mut last_generation = 0;
    for (i, chunk) in data.split(|b| *b == b'\n').enumerate() {
        let Ok(text) = std::str::from_utf8(chunk) else {
            continue;
        };
        let _ = ClientMessage::parse(text);
        out.clear();
        let _ = session.on_text(1_700_000_000_000 + i as u64 * 250, text, &mut out);
        for command in &out {
            match command {
                Command::Send { verb, text } => {
                    let frame: Value =
                        serde_json::from_str(text).expect("frame must parse as JSON");
                    let array = frame.as_array().expect("frame must be a JSON array");
                    assert_eq!(
                        array.first().and_then(Value::as_str),
                        Some(verb.as_str()),
                        "frame verb mismatch: {text}"
                    );
                }
                Command::Subscribe { sub, .. } | Command::Count { sub, .. } => {
                    assert!(sub.generation > last_generation);
                    last_generation = sub.generation;
                    assert!(session.is_current(sub), "stale Subscribe {sub:?}");
                }
                Command::NegOpen { sub, .. } => {
                    assert!(sub.generation > last_generation);
                    last_generation = sub.generation;
                    assert!(session.is_current_neg(sub), "stale NegOpen {sub:?}");
                }
                Command::NegMsg { sub, .. } => {
                    assert!(session.is_current_neg(sub), "stale NegMsg {sub:?}");
                }
                Command::Publish { .. }
                | Command::Unsubscribe { .. }
                | Command::NegClose { .. } => {}
            }
        }
    }
});
