#![no_main]

//! Drive one `Session` through a bounded sequence of structured and
//! raw frames: emitted frames stay parseable, the sub/neg counts
//! never exceed the configured caps.

use std::sync::Arc;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use nosfry_core::auth::AuthRules;
use nosfry_core::event::EventLimits;
use nosfry_core::limits::{AddressBuckets, Limits, RateLimits, ReqLimits};
use nosfry_core::message::{ClientMessage, SubId};
use nosfry_core::session::{Command, Session};
use serde_json::Value;
use std::collections::HashSet;

const VERBS: [&str; 8] = [
    "EVENT", "REQ", "CLOSE", "COUNT", "AUTH", "NEG-OPEN", "NEG-MSG", "NEG-CLOSE",
];
const OUT_VERBS: [&str; 9] = [
    "OK", "EOSE", "EVENT", "COUNT", "CLOSED", "NOTICE", "AUTH", "NEG-MSG", "NEG-ERR",
];

#[derive(Arbitrary, Debug)]
struct Step {
    /// Raw arbitrary text when set, structured frame otherwise.
    raw: bool,
    /// Client verb index for the structured path.
    verb: u8,
    /// Subscription id material.
    sub: String,
    /// Filter/object material.
    payload: String,
    /// `now_ms` advance in milliseconds.
    dt: u16,
}

fn limits() -> Arc<Limits> {
    Arc::new(Limits {
        event: EventLimits::default(),
        req: ReqLimits {
            max_req_filter_size: 4,
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
            Some(nosfry_core::url::RelayUrl::parse("wss://fuzz.example").unwrap()),
            &[4, 1059],
            true,
        )),
    })
}

fn frame(step: &Step) -> String {
    if step.raw {
        return step.payload.clone();
    }
    let verb = VERBS[step.verb as usize % VERBS.len()];
    let sub: String = step.sub.chars().take(64).collect();
    match verb {
        "REQ" | "COUNT" => {
            format!("[\"{verb}\",\"{sub}\",{{\"kinds\":[1]}},{{\"authors\":[\"{}\"]}}]", "a".repeat(64))
        }
        "NEG-OPEN" => format!("[\"{verb}\",\"{sub}\",{{\"kinds\":[1]}},\"aa\"]"),
        "EVENT" | "AUTH" => {
            format!("[\"{verb}\",{{\"id\":\"{}\",\"pubkey\":\"{}\",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"{}\",\"sig\":\"{}\"}}]",
                "b".repeat(64), "c".repeat(64), step.payload.replace('"', "x"), "d".repeat(128))
        }
        _ => format!("[\"{verb}\",\"{sub}\"]"),
    }
}

fuzz_target!(|steps: Vec<Step>| {
    let mut session = Session::new(
        limits(),
        "fuzzchallenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    );
    let mut out = Vec::new();
    let mut now = 1_700_000_000_000u64;
    let mut subs: HashSet<SubId> = HashSet::new();
    let mut negs: HashSet<SubId> = HashSet::new();
    for step in steps.iter().take(64) {
        now = now.saturating_add(u64::from(step.dt));
        let text = frame(step);
        let _ = ClientMessage::parse(&text);
        out.clear();
        let _ = session.on_text(now, &text, &mut out);
        for command in &out {
            match command {
                Command::Send { verb, text } => {
                    let frame: Value =
                        serde_json::from_str(text).expect("frame must parse as JSON");
                    let array = frame.as_array().expect("frame must be a JSON array");
                    let first = array.first().and_then(Value::as_str);
                    assert_eq!(first, Some(verb.as_str()), "frame verb mismatch: {text}");
                    assert!(OUT_VERBS.contains(&first.unwrap_or("")), "{text}");
                }
                Command::Subscribe { sub, .. } | Command::Count { sub, .. } => {
                    subs.insert(sub.id.clone());
                    assert!(subs.len() <= 4, "subs cap exceeded");
                }
                Command::NegOpen { sub, .. } => {
                    negs.insert(sub.id.clone());
                    assert!(negs.len() <= 4, "neg cap exceeded");
                }
                Command::Unsubscribe { sub_id } => {
                    subs.remove(sub_id);
                }
                Command::NegClose { sub_id } => {
                    negs.remove(sub_id);
                }
                _ => {}
            }
        }
    }
});
