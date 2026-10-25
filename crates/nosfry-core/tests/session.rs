//! Session state machine branch coverage (sans-IO).

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

use std::fmt::Write as _;
use std::sync::Arc;

use nosfry_core::event::{PublicKey, event_id, serialize_for_id};
use nosfry_core::kind::Kind;
use nosfry_core::limits::{AddressBuckets, Limits};
use nosfry_core::message::{ClientVerb, SubId};
use nosfry_core::session::{Command, Received, Session, SubKey};
use nosfry_core::url::RelayUrl;
use secp256k1::Keypair;
use secp256k1::schnorr;

fn session() -> Session {
    Session::new(
        Arc::new(Limits::default()),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    )
}

fn feed(session: &mut Session, now: u64, text: &str) -> Vec<Command> {
    feed_ms(session, now * 1000, text)
}

/// `feed` at millisecond resolution, for the rate-limit tests.
fn feed_ms(session: &mut Session, now_ms: u64, text: &str) -> Vec<Command> {
    receive(session, now_ms, text).0
}

/// `feed` plus the returned [`Received`].
fn receive(session: &mut Session, now_ms: u64, text: &str) -> (Vec<Command>, Received) {
    let mut out = Vec::new();
    let received = session.on_text(now_ms, text, &mut out);
    (out, received)
}

fn event_json(created_at: u64, kind: u16, content: &str) -> String {
    let keypair = Keypair::from_secret_bytes([9u8; 32]).expect("secret key");
    let pubkey = PublicKey(keypair.x_only_public_key().0.to_byte_array());
    let preimage = serialize_for_id(&pubkey, created_at, Kind(kind), &[], content);
    let id = event_id(preimage.as_bytes());
    let sig = schnorr::sign_no_aux_rand(&id.0, &keypair);
    let mut sig_hex = String::with_capacity(128);
    for b in sig.to_byte_array() {
        write!(sig_hex, "{b:02x}").expect("write");
    }
    format!(
        "{{\"id\":\"{id}\",\"pubkey\":\"{pubkey}\",\"created_at\":{created_at},\
         \"kind\":{kind},\"tags\":[],\"content\":\"{content}\",\"sig\":\"{sig_hex}\"}}"
    )
}

fn signed_event(created_at: u64, kind: u16, content: &str) -> String {
    format!("[\"EVENT\",{}]", event_json(created_at, kind, content))
}

/// A signed event carrying arbitrary tags (raw JSON tag array).
fn signed_event_tags(created_at: u64, kind: u16, tags: &str, content: &str) -> String {
    let keypair = Keypair::from_secret_bytes([9u8; 32]).expect("secret key");
    let pubkey = PublicKey(keypair.x_only_public_key().0.to_byte_array());
    let tags_v: Vec<Vec<String>> = serde_json::from_str(tags).expect("tags json");
    let preimage = serialize_for_id(&pubkey, created_at, Kind(kind), &tags_v, content);
    let id = event_id(preimage.as_bytes());
    let sig = schnorr::sign_no_aux_rand(&id.0, &keypair);
    let mut sig_hex = String::with_capacity(128);
    for b in sig.to_byte_array() {
        write!(sig_hex, "{b:02x}").expect("write");
    }
    let content_json = serde_json::to_string(content).expect("content");
    format!(
        "[\"EVENT\",{{\"id\":\"{id}\",\"pubkey\":\"{pubkey}\",\"created_at\":{created_at},\
         \"kind\":{kind},\"tags\":{tags},\"content\":{content_json},\"sig\":\"{sig_hex}\"}}]"
    )
}

fn sends(cmds: &[Command]) -> Vec<&str> {
    cmds.iter()
        .filter_map(|c| match c {
            Command::Send { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn garbage_produces_notice() {
    let mut s = session();
    let out = feed(&mut s, 1, "not json");
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(
        frames[0].starts_with("[\"NOTICE\",\"invalid:"),
        "{}",
        frames[0]
    );
}

#[test]
fn req_subscribes_and_is_current() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{\"kinds\":[1]}]");
    assert_eq!(out.len(), 1);
    let Command::Subscribe { sub, filters, .. } = &out[0] else {
        panic!("expected Subscribe, got {out:?}");
    };
    assert_eq!(sub.id.as_str(), "a");
    assert_eq!(sub.generation, 1);
    assert_eq!(filters.len(), 1);
    assert!(s.is_current(sub));
}

#[test]
fn req_replace_unsubscribes_then_subscribes_new_generation() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{}]");
    let Command::Subscribe { sub: first, .. } = &out[0] else {
        panic!("expected Subscribe");
    };
    let out = feed(&mut s, 2, "[\"REQ\",\"a\",{\"kinds\":[2]}]");
    assert_eq!(out.len(), 2);
    let Command::Unsubscribe { sub_id } = &out[0] else {
        panic!("expected Unsubscribe first, got {:?}", out[0]);
    };
    assert_eq!(sub_id.as_str(), "a");
    let Command::Subscribe { sub: second, .. } = &out[1] else {
        panic!("expected Subscribe second");
    };
    assert_eq!(second.id.as_str(), "a");
    assert_ne!(first.generation, second.generation);
    assert!(!s.is_current(first));
    assert!(s.is_current(second));
}

#[test]
fn req_over_cap_closes() {
    let limits = Limits {
        req: nosfry_core::limits::ReqLimits {
            max_subs_per_connection: 1,
            ..nosfry_core::limits::ReqLimits::default()
        },
        ..Limits::default()
    };
    let mut s = Session::new(
        Arc::new(limits),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    );
    feed(&mut s, 1, "[\"REQ\",\"a\",{}]");
    let out = feed(&mut s, 2, "[\"REQ\",\"b\",{}]");
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(
        frames[0].contains("\"CLOSED\"") && frames[0].contains("too many open subscriptions"),
        "{}",
        frames[0]
    );
    // Replacing the still-open sub stays allowed.
    let out = feed(&mut s, 3, "[\"REQ\",\"a\",{}]");
    assert!(matches!(out.last(), Some(Command::Subscribe { .. })));
}

#[test]
fn req_too_many_filters_closes() {
    let mut s = session();
    let mut text = String::from("[\"REQ\",\"a\"");
    for _ in 0..=200 {
        text.push_str(",{}");
    }
    text.push(']');
    let out = feed(&mut s, 1, &text);
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(frames[0].contains("\"CLOSED\""), "{}", frames[0]);
}

#[test]
fn req_too_many_tag_filters_closes() {
    let mut s = session();
    let out = feed(
        &mut s,
        1,
        "[\"REQ\",\"a\",{\"#a\":[\"x\"],\"#b\":[\"x\"],\"#c\":[\"x\"],\"#d\":[\"x\"]}]",
    );
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(frames[0].contains("\"CLOSED\""), "{}", frames[0]);
}

#[test]
fn req_bad_filter_closes_with_reason() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{\"kinds\":\"x\"}]");
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(
        frames[0].starts_with("[\"CLOSED\",\"a\",\"invalid:"),
        "{}",
        frames[0]
    );
}

#[test]
fn close_removes_and_ignores_unknown() {
    let mut s = session();
    feed(&mut s, 1, "[\"REQ\",\"a\",{}]");
    let out = feed(&mut s, 2, "[\"CLOSE\",\"a\"]");
    assert!(matches!(out.as_slice(), [Command::Unsubscribe { .. }]));
    let out = feed(&mut s, 3, "[\"CLOSE\",\"a\"]");
    assert!(out.is_empty());
    let out = feed(&mut s, 4, "[\"CLOSE\",\"never\"]");
    assert!(out.is_empty());
}

#[test]
fn auth_neg_are_unsupported() {
    let mut s = session();
    let auth = format!("[\"AUTH\",{}]", event_json(1, 22_242, "auth"));
    let out = feed(&mut s, 1, &auth);
    assert!(
        sends(&out)[0].contains("unsupported: authentication is disabled"),
        "{out:?}"
    );
    // NEG-OPEN succeeds (the sync is supported); NEG-MSG on an
    // unknown id is `closed:`; NEG-CLOSE on an unknown id is silent.
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    assert!(
        matches!(out.as_slice(), [Command::NegOpen { .. }]),
        "{out:?}"
    );
    let out = feed(&mut s, 1, "[\"NEG-MSG\",\"m\",\"aabb\"]");
    assert!(
        sends(&out)[0].starts_with("[\"NEG-ERR\",\"m\",\"closed:"),
        "{out:?}"
    );
    let out = feed(&mut s, 1, "[\"NEG-CLOSE\",\"x\"]");
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn event_publishes_when_valid() {
    let mut s = session();
    let out = feed(&mut s, 1_700_000_000, &signed_event(1_700_000_000, 1, "gm"));
    assert!(matches!(out.as_slice(), [Command::Publish { .. }]));
}

#[test]
fn event_future_created_at_rejected() {
    let mut s = session();
    let now = 1_700_000_000u64;
    let out = feed(&mut s, now, &signed_event(now + 901, 1, "gm"));
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(
        frames[0].contains(",false,") && frames[0].contains("invalid:"),
        "{}",
        frames[0]
    );
}

#[test]
fn event_ancient_created_at_rejected() {
    let mut s = session();
    let now = 1_700_000_000u64;
    let out = feed(&mut s, now, &signed_event(now - 94_608_001, 1, "gm"));
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(frames[0].contains(",false,"), "{}", frames[0]);
}

#[test]
fn ephemeral_event_past_window_rejected() {
    let mut s = session();
    let now = 1_700_000_000u64;
    let out = feed(&mut s, now, &signed_event(now - 61, 20_000, "gm"));
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(frames[0].contains(",false,"), "{}", frames[0]);
    // Same age on a regular kind passes the ephemeral window.
    let out = feed(&mut s, now, &signed_event(now - 61, 1, "gm"));
    assert!(matches!(out.as_slice(), [Command::Publish { .. }]));
}

#[test]
fn event_bad_signature_rejected() {
    let mut s = session();
    let text = signed_event(1_700_000_000, 1, "gm");
    let tampered = text.replace("\"content\":\"gm\"", "\"content\":\"gn\"");
    let out = feed(&mut s, 1_700_000_000, &tampered);
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(frames[0].contains(",false,"), "{}", frames[0]);
}

#[test]
fn event_malformed_reports_id_or_notice() {
    // Message-level structural failure -> NOTICE (no id extracted).
    let mut s = session();
    let out = feed(&mut s, 1, "[\"EVENT\",{}]");
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(frames[0].starts_with("[\"NOTICE\""), "{}", frames[0]);

    // Limit failure inside `on_event` with a recoverable id -> OK false.
    let limits = Limits {
        event: nosfry_core::event::EventLimits {
            max_num_tags: 0,
            ..nosfry_core::event::EventLimits::default()
        },
        ..Limits::default()
    };
    let mut s = Session::new(
        Arc::new(limits),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    );
    let tagged =
        signed_event(1_700_000_000, 1, "gm").replace("\"tags\":[]", "\"tags\":[[\"t\",\"x\"]]");
    // The event id/signature are stale after tampering, but the limit
    // failure must fire before any hashing so the OK still reports the id.
    let out = feed(&mut s, 1_700_000_000, &tagged);
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(
        frames[0].starts_with("[\"OK\"") && frames[0].contains(",false,"),
        "{}",
        frames[0]
    );
}

#[test]
fn sub_id_emoji_length_counts_chars() {
    let mut s = session();
    let sub = "\u{1f600}".repeat(64);
    let text = format!("[\"REQ\",\"{sub}\",{{}}]");
    let out = feed(&mut s, 1, &text);
    assert!(matches!(out.as_slice(), [Command::Subscribe { .. }]));
    let sub = "\u{1f600}".repeat(65);
    let text = format!("[\"REQ\",\"{sub}\",{{}}]");
    let out = feed(&mut s, 1, &text);
    assert!(sends(&out)[0].starts_with("[\"NOTICE\",\"invalid:"));
}

#[test]
fn close_by_relay_only_removes_current_generation() {
    use SubKey;
    let mut s = session();
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{}]");
    let Command::Subscribe { sub: first, .. } = &out[0] else {
        panic!("expected Subscribe");
    };
    let first = first.clone();
    // Re-REQ bumps the generation; a relay close for the stale key is a no-op.
    feed(&mut s, 2, "[\"REQ\",\"a\",{}]");
    assert!(!s.close_by_relay(&first));
    let current = SubKey {
        id: first.id.clone(),
        generation: first.generation + 1,
    };
    assert!(s.is_current(&current));
    assert!(s.close_by_relay(&current));
    assert!(!s.is_current(&current));
    // Closing an unknown id is also a no-op.
    assert!(!s.close_by_relay(&SubKey {
        id: first.id,
        generation: 99,
    }));
}

#[test]
fn subkey_generation_monotonic() {
    let mut s = session();
    for n in 1..=3u64 {
        let out = feed(&mut s, n, "[\"REQ\",\"a\",{}]");
        let Command::Subscribe { sub, .. } = out.last().expect("subscribe") else {
            panic!("expected Subscribe");
        };
        assert_eq!(sub.generation, n);
    }
}

#[test]
fn expired_event_is_rejected_invalid() {
    let mut s = session();
    let now = 1_700_000_000u64;
    let tags = format!("[[\"expiration\",\"{}\"]]", now - 5);
    let out = feed(&mut s, now, &signed_event_tags(now - 10, 1, &tags, "old"));
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(
        frames[0].contains("\"OK\"") && frames[0].contains("invalid: event has expired"),
        "{}",
        frames[0]
    );

    // Still-valid expiration reaches verification (Publish).
    let tags = format!("[[\"expiration\",\"{}\"]]", now + 100);
    let out = feed(&mut s, now, &signed_event_tags(now, 1, &tags, "fresh"));
    assert!(
        matches!(out.last(), Some(Command::Publish { .. })),
        "{out:?}"
    );
}

/// Session with caller-chosen rate limits over the default `Limits`.
fn session_with_rate(rate: nosfry_core::limits::RateLimits) -> Session {
    Session::new(
        Arc::new(Limits {
            rate,
            ..Limits::default()
        }),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::new(&rate)),
    )
}

#[test]
fn event_burst_exhausts_and_refills() {
    let mut s = session();
    let t = 1_000u64;
    let text = signed_event(1_700_000_000, 1, "gm");
    // The burst of 100 passes; message 101 is rate-limited.
    for _ in 0..100 {
        feed_ms(&mut s, t, &text);
    }
    let out = feed_ms(&mut s, t, &text);
    let frames = sends(&out);
    assert_eq!(frames.len(), 1);
    assert!(
        frames[0].contains("\"OK\"") && frames[0].contains("rate-limited: slow down"),
        "{}",
        frames[0]
    );
    // +1000 ms at 20 events/s refills exactly 20 takes.
    for _ in 0..20 {
        let out = feed_ms(&mut s, t + 1_000, &text);
        assert!(
            !sends(&out).iter().any(|f| f.contains("rate-limited:")),
            "{out:?}"
        );
    }
    let out = feed_ms(&mut s, t + 1_000, &text);
    assert!(
        sends(&out)[0].contains("rate-limited: slow down"),
        "{out:?}"
    );
}

#[test]
fn ephemeral_events_share_the_bucket() {
    let mut s = session();
    let t = 1_000u64;
    let stored = signed_event(1_700_000_000, 1, "gm");
    for _ in 0..100 {
        feed_ms(&mut s, t, &stored);
    }
    let ephemeral = signed_event(1_700_000_000, 20_000, "gm");
    let out = feed_ms(&mut s, t, &ephemeral);
    assert!(
        sends(&out)[0].contains("rate-limited: slow down"),
        "{out:?}"
    );
}

#[test]
fn req_over_limit_is_closed_rate_limited() {
    let mut s = session();
    let t = 1_000u64;
    for _ in 0..100 {
        feed_ms(&mut s, t, "[\"REQ\",\"a\",{}]");
    }
    // The refused re-REQ tears the open subscription down first.
    let out = feed_ms(&mut s, t, "[\"REQ\",\"a\",{}]");
    let frames = sends(&out);
    assert!(
        matches!(
            out.as_slice(),
            [Command::Unsubscribe { .. }, Command::Send { .. }]
        ) && frames[0].contains("rate-limited: slow down"),
        "{out:?}"
    );
    // The subscription is gone: CLOSE is a no-op on an empty bucket.
    let out = feed_ms(&mut s, t, "[\"CLOSE\",\"a\"]");
    assert!(out.is_empty(), "{out:?}");
    // NEG-OPEN shares the REQ bucket, so it is refused too.
    let out = feed_ms(&mut s, t, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    assert!(
        sends(&out)[0].contains("rate-limited: slow down"),
        "{out:?}"
    );
}

#[test]
fn zero_rate_per_second_disables() {
    let rate = nosfry_core::limits::RateLimits {
        events_per_second: 0,
        events_burst: 0,
        reqs_per_second: 0,
        reqs_burst: 0,
        ip_events_per_second: 0,
        ip_events_burst: 0,
        ip_reqs_per_second: 0,
        ip_reqs_burst: 0,
    };
    let mut s = session_with_rate(rate);
    let text = signed_event(1_700_000_000, 1, "gm");
    for _ in 0..200 {
        let out = feed_ms(&mut s, 1_700_000_000_000, &text);
        assert!(
            matches!(out.as_slice(), [Command::Publish { .. }]),
            "{out:?}"
        );
    }
    for _ in 0..200 {
        let out = feed_ms(&mut s, 1_000, "[\"REQ\",\"a\",{}]");
        assert!(
            !sends(&out).iter().any(|f| f.contains("rate-limited:")),
            "{out:?}"
        );
    }
}

/// Every recognized client verb surfaces through `Received.verb`, even
/// when the message fails validation.
#[test]
fn received_verb_covers_every_client_verb() {
    let mut s = session();
    let t = 1_700_000_000_000u64;
    let cases: [(String, ClientVerb); 8] = [
        (signed_event(1_700_000_000, 1, "gm"), ClientVerb::Event),
        ("[\"REQ\",\"a\",{}]".to_owned(), ClientVerb::Req),
        ("[\"CLOSE\",\"a\"]".to_owned(), ClientVerb::Close),
        ("[\"COUNT\",\"a\",{}]".to_owned(), ClientVerb::Count),
        (
            format!("[\"AUTH\",{}]", event_json(1_700_000_000, 1, "gm")),
            ClientVerb::Auth,
        ),
        (
            "[\"NEG-OPEN\",\"a\",{},\"aa\"]".to_owned(),
            ClientVerb::NegOpen,
        ),
        ("[\"NEG-MSG\",\"a\",\"aa\"]".to_owned(), ClientVerb::NegMsg),
        ("[\"NEG-CLOSE\",\"a\"]".to_owned(), ClientVerb::NegClose),
    ];
    for (text, want) in cases {
        let (_, received) = receive(&mut s, t, &text);
        assert_eq!(received.verb, Some(want), "{text}");
        assert!(!received.rate_limited, "{text}");
    }
}

/// Rejected messages still report their verb: parser arity/type errors
/// and session-level rejections alike.
#[test]
fn rejected_messages_still_report_their_verb() {
    let mut s = session();
    for (text, want) in [
        ("[\"EVENT\",\"bad\"]", ClientVerb::Event),
        ("[\"REQ\"]", ClientVerb::Req),
        ("[\"REQ\",\"a\"]", ClientVerb::Req),
        ("[\"CLOSE\",1]", ClientVerb::Close),
        ("[\"NEG-OPEN\",\"a\",{},\"zz\"]", ClientVerb::NegOpen),
    ] {
        let (_, received) = receive(&mut s, 1_000, text);
        assert_eq!(received.verb, Some(want), "{text}");
    }
    // A verified-format event rejected by the session time window.
    let (_, received) = receive(&mut s, 1_000_000, &signed_event(u64::MAX, 1, "x"));
    assert_eq!(received.verb, Some(ClientVerb::Event));
    assert!(
        sends(&receive(&mut s, 1_000_000, &signed_event(u64::MAX, 1, "x")).0)[0]
            .contains("invalid:"),
    );
}

/// Unparseable frames and unknown verbs report `None`.
#[test]
fn unparseable_and_unknown_verbs_report_none() {
    let mut s = session();
    for text in ["not json", "[]", "[1,2]", "[\"BOGUS\",\"x\"]"] {
        let (_, received) = receive(&mut s, 1_000, text);
        assert_eq!(received.verb, None, "{text}");
        assert!(!received.rate_limited, "{text}");
    }
}

/// `rate_limited` flags exactly the messages the buckets refuse.
#[test]
fn rate_limited_flag_marks_refusals() {
    let rate = nosfry_core::limits::RateLimits {
        events_per_second: 1_000,
        events_burst: 1,
        reqs_per_second: 1_000,
        reqs_burst: 1,
        ip_events_per_second: 0,
        ip_events_burst: 0,
        ip_reqs_per_second: 0,
        ip_reqs_burst: 0,
    };
    let mut s = session_with_rate(rate);
    let t = 1_000u64;
    let event = signed_event(1_700_000_000, 1, "gm");
    let (_, received) = receive(&mut s, t, &event);
    assert!(!received.rate_limited);
    let (_, received) = receive(&mut s, t, &event);
    assert!(received.rate_limited);
    assert_eq!(received.verb, Some(ClientVerb::Event));
    let (_, received) = receive(&mut s, t, "[\"REQ\",\"a\",{}]");
    assert!(!received.rate_limited);
    let (_, received) = receive(&mut s, t, "[\"REQ\",\"b\",{}]");
    assert!(received.rate_limited);
    assert_eq!(received.verb, Some(ClientVerb::Req));
    // CLOSE is never charged.
    let (_, received) = receive(&mut s, t, "[\"CLOSE\",\"a\"]");
    assert_eq!(received.verb, Some(ClientVerb::Close));
    assert!(!received.rate_limited);
}

/// Session under auth rules: `url` empty disables AUTH; `kinds` are
/// the restricted read kinds.
fn session_auth(url: &str, kinds: &[u16], involved_only: bool) -> Session {
    let service_url = (!url.is_empty()).then(|| RelayUrl::parse(url).expect("service url"));
    Session::new(
        Arc::new(Limits {
            auth: Arc::new(nosfry_core::auth::AuthRules::new(
                service_url,
                kinds,
                involved_only,
            )),
            ..Limits::default()
        }),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    )
}

/// The pubkey hex of a signing `secret`.
fn pubkey_hex(secret: [u8; 32]) -> String {
    let keypair = Keypair::from_secret_bytes(secret).expect("secret key");
    PublicKey(keypair.x_only_public_key().0.to_byte_array()).to_string()
}

/// Raw signed event JSON with `secret`, `tags` (raw JSON array).
fn signed_event_json(
    secret: [u8; 32],
    created_at: u64,
    kind: u16,
    tags: &str,
    content: &str,
) -> String {
    let keypair = Keypair::from_secret_bytes(secret).expect("secret key");
    let pubkey = PublicKey(keypair.x_only_public_key().0.to_byte_array());
    let tags_v: Vec<Vec<String>> = serde_json::from_str(tags).expect("tags json");
    let preimage = serialize_for_id(&pubkey, created_at, Kind(kind), &tags_v, content);
    let id = event_id(preimage.as_bytes());
    let sig = schnorr::sign_no_aux_rand(&id.0, &keypair);
    let mut sig_hex = String::with_capacity(128);
    for b in sig.to_byte_array() {
        write!(sig_hex, "{b:02x}").expect("write");
    }
    let content_json = serde_json::to_string(content).expect("content");
    format!(
        "{{\"id\":\"{id}\",\"pubkey\":\"{pubkey}\",\"created_at\":{created_at},\
         \"kind\":{kind},\"tags\":{tags},\"content\":{content_json},\"sig\":\"{sig_hex}\"}}"
    )
}

/// A valid `["AUTH",<event>]` frame for `secret` at `created_at`.
fn auth_frame(secret: [u8; 32], created_at: u64) -> String {
    let tags = r#"[["challenge","challenge"],["relay","wss://relay.example.com"]]"#;
    format!(
        "[\"AUTH\",{}]",
        signed_event_json(secret, created_at, 22_242, tags, "")
    )
}

#[test]
fn req_fully_restricted_auth_disabled() {
    let mut s = session_auth("", &[4], true);
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{\"kinds\":[4]}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"CLOSED\",\"a\",\"restricted: requested kinds are not served\"]"],
        "{out:?}"
    );
    assert!(
        !out.iter().any(|c| matches!(c, Command::Subscribe { .. })),
        "{out:?}"
    );
}

#[test]
fn req_fully_restricted_challenges_once() {
    let mut s = session_auth("wss://relay.example.com", &[4, 1059], true);
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{\"kinds\":[4]}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        [
            "[\"AUTH\",\"challenge\"]",
            "[\"CLOSED\",\"a\",\"auth-required: requested filter requires authentication\"]",
        ],
        "{out:?}"
    );
    // The challenge is sent at most once: a second restricted REQ is
    // refused without another AUTH frame.
    let out = feed(&mut s, 1, "[\"REQ\",\"b\",{\"kinds\":[4,1059]}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"CLOSED\",\"b\",\"auth-required: requested filter requires authentication\"]"],
        "{out:?}"
    );
    assert_eq!(s.authenticated().len(), 0);
}

#[test]
fn auth_then_same_req_subscribes() {
    let mut s = session_auth("wss://relay.example.com", &[4], true);
    let out = feed(&mut s, 1_700_000_000, &auth_frame([9; 32], 1_700_000_000));
    let frames = sends(&out);
    assert_eq!(frames.len(), 1, "{out:?}");
    assert!(
        frames[0].starts_with("[\"OK\",\"") && frames[0].ends_with(",true,\"\"]"),
        "{out:?}"
    );
    assert_eq!(s.authenticated().len(), 1);
    let out = feed(&mut s, 1_700_000_000, "[\"REQ\",\"a\",{\"kinds\":[4]}]");
    assert!(
        matches!(out.as_slice(), [Command::Subscribe { .. }]),
        "{out:?}"
    );
}

/// NIP-42 allows ~10 minutes of clock skew either way; the old
/// ephemeral-age rule (60 s) no longer applies to AUTH.
#[test]
fn auth_window_is_symmetric_10_minutes() {
    let mut s = session_auth("wss://relay.example.com", &[4], true);
    let t = 1_700_000_000;
    for (secret, created_at) in [([7u8; 32], t - 300), ([8u8; 32], t + 300)] {
        let out = feed(&mut s, t, &auth_frame(secret, created_at));
        let frames = sends(&out);
        assert_eq!(frames.len(), 1, "{out:?}");
        assert!(
            frames[0].starts_with("[\"OK\",\"") && frames[0].ends_with(",true,\"\"]"),
            "{out:?}"
        );
    }
    assert_eq!(s.authenticated().len(), 2);
}

#[test]
fn auth_failures_report_exact_reasons() {
    let mut s = session_auth("wss://relay.example.com", &[4], true);
    let t = 1_700_000_000u64;
    let fail = |out: &[Command], reason: &str| {
        let frames = sends(out);
        assert_eq!(frames.len(), 1, "{out:?}");
        assert!(
            frames[0].starts_with("[\"OK\",\"")
                && frames[0].contains(&format!(",false,\"{reason}")),
            "{out:?}"
        );
    };
    // Wrong kind.
    let event = signed_event_json(
        [9; 32],
        t,
        1,
        r#"[["challenge","challenge"],["relay","wss://relay.example.com"]]"#,
        "",
    );
    fail(
        &feed(&mut s, t, &format!("[\"AUTH\",{event}]")),
        "invalid: AUTH event must be kind 22242",
    );
    // Stale or future: AUTH has its own symmetric 10-minute window,
    // not the ephemeral-age rules.
    fail(
        &feed(&mut s, t, &auth_frame([9; 32], t - 601)),
        "invalid: created_at is not within 10 minutes of the relay's time",
    );
    fail(
        &feed(&mut s, t, &auth_frame([9; 32], t + 601)),
        "invalid: created_at is not within 10 minutes of the relay's time",
    );
    // Wrong challenge.
    let tags = r#"[["challenge","nope"],["relay","wss://relay.example.com"]]"#;
    fail(
        &feed(
            &mut s,
            t,
            &format!(
                "[\"AUTH\",{}]",
                signed_event_json([9; 32], t, 22_242, tags, "")
            ),
        ),
        "invalid: challenge mismatch",
    );
    // Wrong relay.
    let tags = r#"[["challenge","challenge"],["relay","wss://other.example.com"]]"#;
    fail(
        &feed(
            &mut s,
            t,
            &format!(
                "[\"AUTH\",{}]",
                signed_event_json([9; 32], t, 22_242, tags, "")
            ),
        ),
        "invalid: relay tag mismatch",
    );
    // Bad signature: valid id, corrupted sig.
    let mut bad = auth_frame([9; 32], t);
    let pos = bad.len() - 6;
    bad.replace_range(
        pos..pos + 2,
        if &bad[pos..pos + 2] == "aa" {
            "bb"
        } else {
            "aa"
        },
    );
    fail(&feed(&mut s, t, &bad), "invalid: signature");
}

#[test]
fn auth_relay_tag_normalization() {
    let mut s = session_auth("wss://Relay.Example.com/path?x=1", &[4], true);
    let tags = r#"[["challenge","challenge"],["relay","wss://RELAY.EXAMPLE.COM/other"]]"#;
    let out = feed(
        &mut s,
        1_700_000_000,
        &format!(
            "[\"AUTH\",{}]",
            signed_event_json([9; 32], 1_700_000_000, 22_242, tags, "")
        ),
    );
    assert!(sends(&out)[0].ends_with(",true,\"\"]"), "{out:?}");
}

#[test]
fn auth_multiple_pubkeys_and_cap() {
    let mut s = session_auth("wss://relay.example.com", &[4], true);
    let t = 1_700_000_000u64;
    // Nine distinct keys: the first eight authenticate, the ninth is
    // refused.
    for i in 0..nosfry_core::auth::MAX_AUTHED_PUBKEYS {
        let out = feed(
            &mut s,
            t,
            &auth_frame([u8::try_from(i).unwrap() + 1; 32], t),
        );
        assert!(sends(&out)[0].ends_with(",true,\"\"]"), "{out:?}");
    }
    assert_eq!(s.authenticated().len(), 8);
    let out = feed(&mut s, t, &auth_frame([99; 32], t));
    assert!(
        sends(&out)[0].ends_with("restricted: too many authenticated pubkeys\"]"),
        "{out:?}"
    );
    // A repeat of an already-authed pubkey is idempotent.
    let out = feed(&mut s, t, &auth_frame([1; 32], t));
    assert!(sends(&out)[0].ends_with(",true,\"\"]"), "{out:?}");
    assert_eq!(s.authenticated().len(), 8);
}

#[test]
fn auth_charges_event_bucket() {
    let rate = nosfry_core::limits::RateLimits {
        events_per_second: 1,
        events_burst: 1,
        reqs_per_second: 0,
        reqs_burst: 0,
        ip_events_per_second: 0,
        ip_events_burst: 0,
        ip_reqs_per_second: 0,
        ip_reqs_burst: 0,
    };
    let mut s = Session::new(
        Arc::new(Limits {
            auth: Arc::new(nosfry_core::auth::AuthRules::new(
                Some(RelayUrl::parse("wss://relay.example.com").expect("service url")),
                &[4],
                true,
            )),
            rate,
            ..Limits::default()
        }),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    );
    let t = 1_700_000_000_000u64;
    let out = feed_ms(&mut s, t, &auth_frame([9; 32], 1_700_000_000));
    assert!(sends(&out)[0].ends_with(",true,\"\"]"), "{out:?}");
    let (_, received) = receive(&mut s, t, &auth_frame([10; 32], 1_700_000_000));
    assert!(received.rate_limited);
    assert_eq!(received.verb, Some(ClientVerb::Auth));
}

#[test]
fn event_auth_kind_is_never_published() {
    let mut s = session_auth("wss://relay.example.com", &[4], true);
    let t = 1_700_000_000u64;
    let tags = r#"[["challenge","challenge"],["relay","wss://relay.example.com"]]"#;
    let event = signed_event_json([9; 32], t, 22_242, tags, "");
    let out = feed(&mut s, t, &format!("[\"EVENT\",{event}]"));
    assert!(
        sends(&out)[0].ends_with("invalid: kind 22242 events are only accepted in AUTH\"]"),
        "{out:?}"
    );
}

#[test]
fn protected_event_states() {
    let t = 1_700_000_000u64;
    let protected = |secret: [u8; 32]| {
        format!(
            "[\"EVENT\",{}]",
            signed_event_json(secret, t, 1, "[[\"-\"]]", "for me only")
        )
    };
    // AUTH disabled: outright blocked.
    let mut s = session();
    let out = feed(&mut s, t, &protected([9; 32]));
    assert!(
        sends(&out)[0].ends_with("blocked: event marked as protected\"]"),
        "{out:?}"
    );
    // AUTH enabled, unauthenticated: challenge then auth-required.
    let mut s = session_auth("wss://relay.example.com", &[4], true);
    let out = feed(&mut s, t, &protected([9; 32]));
    let frames = sends(&out);
    assert_eq!(frames[0], "[\"AUTH\",\"challenge\"]");
    assert!(
        frames[1].ends_with("auth-required: event marked as protected\"]"),
        "{out:?}"
    );
    // A second protected event does not re-send the challenge.
    let out = feed(&mut s, t, &protected([8; 32]));
    let frames = sends(&out);
    assert_eq!(frames.len(), 1, "{out:?}");
    // Authenticated as someone else: restricted.
    feed(&mut s, t, &auth_frame([8; 32], t));
    let out = feed(&mut s, t, &protected([9; 32]));
    assert!(
        sends(&out)[0].ends_with("restricted: must be published by the author\"]"),
        "{out:?}"
    );
    // Authenticated as the author: published with `authed = author`.
    feed(&mut s, t, &auth_frame([9; 32], t));
    let out = feed(&mut s, t, &protected([9; 32]));
    let [Command::Publish { authed, .. }] = out.as_slice() else {
        panic!("expected Publish, got {out:?}");
    };
    assert_eq!(
        *authed,
        Some(PublicKey::from_hex(&pubkey_hex([9; 32])).unwrap())
    );
}

#[test]
fn repost_embedding_protected_is_blocked() {
    let mut s = session();
    let t = 1_700_000_000u64;
    let content = "{\"kind\":4,\"tags\":[[\"-\"]]}";
    let out = feed(
        &mut s,
        t,
        &format!(
            "[\"EVENT\",{}]",
            signed_event_json([9; 32], t, 6, "[]", content)
        ),
    );
    assert!(
        sends(&out)[0].ends_with("blocked: reposts can't embed protected events\"]"),
        "{out:?}"
    );
    // A kind-6 repost without the marker is published.
    let out = feed(
        &mut s,
        t,
        &format!(
            "[\"EVENT\",{}]",
            signed_event_json([9; 32], t, 6, "[]", "plain")
        ),
    );
    assert!(
        matches!(out.as_slice(), [Command::Publish { .. }]),
        "{out:?}"
    );
}

#[test]
fn mixed_req_gate_hides_restricted() {
    let mut s = session_auth("wss://relay.example.com", &[4], true);
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{\"kinds\":[1,4]}]");
    let [Command::Subscribe { gate, .. }] = out.as_slice() else {
        panic!("expected Subscribe, got {out:?}");
    };
    let ev = |kind: u16| {
        nosfry_core::packed::PackedEvent::build(
            &nosfry_core::event::EventId([1; 32]),
            &PublicKey([2; 32]),
            0,
            Kind(kind),
            0,
            Vec::<Vec<String>>::new(),
        )
    };
    let note = ev(1);
    let dm = ev(4);
    assert!(gate.allows(note.packed()));
    assert!(!gate.allows(dm.packed()));
}

#[test]
fn refused_re_req_closes_old_subscription() {
    let mut s = session();
    // Open "a", then re-REQ it with a filter that fails parsing.
    feed(&mut s, 1, "[\"REQ\",\"a\",{}]");
    assert!(s.is_current(&SubKey {
        id: SubId::parse("a").unwrap(),
        generation: 1,
    }));
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{\"kinds\":[\"x\"]}]");
    assert!(
        matches!(
            out.as_slice(),
            [Command::Unsubscribe { .. }, Command::Send { .. }]
        ),
        "{out:?}"
    );
    assert!(!s.is_current(&SubKey {
        id: SubId::parse("a").unwrap(),
        generation: 1,
    }));
    // Too many filters: same teardown before CLOSED.
    let mut s = session();
    feed(&mut s, 1, "[\"REQ\",\"a\",{}]");
    let many = format!(
        "[\"REQ\",\"a\",{}]",
        (0..=200).map(|_| "{}").collect::<Vec<_>>().join(",")
    );
    let out = feed(&mut s, 1, &many);
    assert!(
        matches!(
            out.as_slice(),
            [Command::Unsubscribe { .. }, Command::Send { .. }]
        ),
        "{out:?}"
    );
}

#[test]
fn count_disabled_closes_unsupported() {
    let mut s = Session::new(
        Arc::new(Limits {
            req: nosfry_core::limits::ReqLimits {
                max_filter_limit_count: 0,
                ..nosfry_core::limits::ReqLimits::default()
            },
            ..Limits::default()
        }),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    );
    // An open REQ under the same id is torn down by the refusal.
    feed(&mut s, 1, "[\"REQ\",\"c\",{}]");
    let out = feed(&mut s, 2, "[\"COUNT\",\"c\",{}]");
    let frames = sends(&out);
    assert!(
        matches!(
            out.as_slice(),
            [Command::Unsubscribe { .. }, Command::Send { .. }]
        ) && frames[0] == "[\"CLOSED\",\"c\",\"unsupported: COUNT\"]",
        "{out:?}"
    );
}

#[test]
fn count_emits_count_command_with_gate() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"COUNT\",\"c\",{\"kinds\":[1]}]");
    let [Command::Count { sub, filters, gate }] = out.as_slice() else {
        panic!("expected Count, got {out:?}");
    };
    assert_eq!(sub.id.as_str(), "c");
    assert_eq!(sub.generation, 1);
    assert_eq!(filters.len(), 1);
    assert!(s.is_current(sub));
    // The snapshot gate reads like a REQ's: without auth rules it
    // allows everything.
    let note = nosfry_core::packed::PackedEvent::build(
        &nosfry_core::event::EventId([1; 32]),
        &PublicKey([2; 32]),
        0,
        Kind(1),
        0,
        Vec::<Vec<String>>::new(),
    );
    assert!(gate.allows(note.packed()));
}

#[test]
fn count_replaces_open_req_with_new_generation() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{}]");
    let Command::Subscribe { sub: first, .. } = &out[0] else {
        panic!("expected Subscribe");
    };
    let out = feed(&mut s, 2, "[\"COUNT\",\"a\",{\"kinds\":[1]}]");
    let [
        Command::Unsubscribe { .. },
        Command::Count { sub: second, .. },
    ] = out.as_slice()
    else {
        panic!("expected Unsubscribe then Count, got {out:?}");
    };
    assert_eq!(second.id.as_str(), "a");
    assert_ne!(first.generation, second.generation);
    assert!(!s.is_current(first));
    assert!(s.is_current(second));
}

#[test]
fn count_over_limit_is_closed_rate_limited() {
    let mut s = session();
    let t = 1_000u64;
    // The 100-token REQ burst is shared with COUNT.
    for _ in 0..100 {
        feed_ms(&mut s, t, "[\"COUNT\",\"a\",{}]");
    }
    // The refused COUNT tears the open id down first, like a refused
    // re-REQ.
    let (out, received) = receive(&mut s, t, "[\"COUNT\",\"a\",{}]");
    let frames = sends(&out);
    assert!(
        matches!(
            out.as_slice(),
            [Command::Unsubscribe { .. }, Command::Send { .. }]
        ) && frames[0].contains("rate-limited: slow down"),
        "{out:?}"
    );
    assert!(received.rate_limited);
    assert_eq!(received.verb, Some(ClientVerb::Count));
    let out = feed_ms(&mut s, t, "[\"CLOSE\",\"a\"]");
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn count_fully_restricted_unauthenticated() {
    // AUTH enabled: challenge once, then auth-required.
    let mut s = session_auth("wss://relay.example.com", &[4], true);
    let out = feed(&mut s, 1, "[\"COUNT\",\"a\",{\"kinds\":[4]}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        [
            "[\"AUTH\",\"challenge\"]",
            "[\"CLOSED\",\"a\",\"auth-required: requested filter requires authentication\"]",
        ],
        "{out:?}"
    );
    // AUTH disabled: the restricted refusal.
    let mut s = session_auth("", &[4], true);
    let out = feed(&mut s, 1, "[\"COUNT\",\"a\",{\"kinds\":[4]}]");
    assert_eq!(
        sends(&out).as_slice(),
        ["[\"CLOSED\",\"a\",\"restricted: requested kinds are not served\"]"]
    );
}

#[test]
fn authed_count_gate_hides_uninvolved_dms() {
    let mut s = session_auth("wss://relay.example.com", &[4], true);
    let out = feed(&mut s, 1_700_000_000, &auth_frame([9; 32], 1_700_000_000));
    assert!(sends(&out)[0].contains("true"), "{out:?}");
    let out = feed(&mut s, 2, "[\"COUNT\",\"c\",{\"kinds\":[4]}]");
    let [Command::Count { gate, .. }] = out.as_slice() else {
        panic!("expected Count, got {out:?}");
    };
    let authed_pk = pubkey_hex([9; 32]);
    let involved = nosfry_core::packed::PackedEvent::build(
        &nosfry_core::event::EventId([1; 32]),
        &PublicKey([2; 32]),
        0,
        Kind(4),
        0,
        vec![vec!["p".to_owned(), authed_pk]],
    );
    let other = nosfry_core::packed::PackedEvent::build(
        &nosfry_core::event::EventId([3; 32]),
        &PublicKey([4; 32]),
        0,
        Kind(4),
        0,
        Vec::<Vec<String>>::new(),
    );
    assert!(gate.allows(involved.packed()));
    assert!(!gate.allows(other.packed()));
}

/// `NEG-OPEN` emits one `NegOpen` command carrying the one filter,
/// the decoded message, and a read gate.
#[test]
fn neg_open_emits_negopen_command() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{\"kinds\":[1]},\"aabb\"]");
    assert!(
        matches!(
            out.as_slice(),
            [Command::NegOpen {
                sub,
                filters,
                msg,
                ..
            }] if sub.id.as_str() == "n"
                && filters.len() == 1
                && msg.as_ref() == [0xaa, 0xbb]
        ),
        "{out:?}"
    );
}

/// Re-opening a sync id emits `NegClose` for the old generation
/// before the new `NegOpen`; the session tracks the new generation.
#[test]
fn neg_reopen_replaces_session() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    let first = match &out[0] {
        Command::NegOpen { sub, .. } => sub.clone(),
        other => panic!("expected NegOpen, got {other:?}"),
    };
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    assert!(
        matches!(
            out.as_slice(),
            [Command::NegClose { .. }, Command::NegOpen { sub, .. }]
                if sub.generation > first.generation
        ),
        "{out:?}"
    );
    let Command::NegOpen { sub, .. } = &out[1] else {
        unreachable!()
    };
    assert!(s.is_current_neg(sub));
    assert!(!s.is_current_neg(&first));
}

/// `NEG-MSG` on an open id emits `NegMsg` with the current
/// generation; an unknown id answers `closed: unknown subscription`.
#[test]
fn neg_msg_routes_by_id() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    let Command::NegOpen { sub, .. } = &out[0] else {
        unreachable!()
    };
    let generation = sub.generation;
    let out = feed(&mut s, 1, "[\"NEG-MSG\",\"n\",\"ccdd\"]");
    assert!(
        matches!(
            out.as_slice(),
            [Command::NegMsg { sub, msg }]
                if sub.generation == generation && msg.as_ref() == [0xcc, 0xdd]
        ),
        "{out:?}"
    );
    let out = feed(&mut s, 1, "[\"NEG-MSG\",\"m\",\"ccdd\"]");
    assert!(
        sends(&out)[0] == "[\"NEG-ERR\",\"m\",\"closed: unknown subscription\"]",
        "{out:?}"
    );
}

/// `NEG-CLOSE` removes the sync and emits `NegClose` once; a second
/// close is silent.
#[test]
fn neg_close_removes_session() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    let Command::NegOpen { sub, .. } = &out[0] else {
        unreachable!()
    };
    assert!(s.is_current_neg(sub));
    let out = feed(&mut s, 1, "[\"NEG-CLOSE\",\"n\"]");
    assert!(
        matches!(out.as_slice(), [Command::NegClose { .. }]),
        "{out:?}"
    );
    assert!(!s.is_current_neg(sub));
    let out = feed(&mut s, 1, "[\"NEG-CLOSE\",\"n\"]");
    assert!(out.is_empty(), "{out:?}");
    // The closed id answers `closed:` again.
    let out = feed(&mut s, 1, "[\"NEG-MSG\",\"n\",\"ccdd\"]");
    assert!(
        sends(&out)[0] == "[\"NEG-ERR\",\"n\",\"closed: unknown subscription\"]",
        "{out:?}"
    );
}

/// `close_neg_by_relay` removes only the matching generation.
#[test]
fn neg_close_by_relay_matches_generation() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    let Command::NegOpen { sub, .. } = &out[0] else {
        unreachable!()
    };
    let stale = SubKey {
        id: sub.id.clone(),
        generation: sub.generation + 1,
    };
    assert!(!s.close_neg_by_relay(&stale));
    assert!(s.is_current_neg(sub));
    assert!(s.close_neg_by_relay(sub));
    assert!(!s.is_current_neg(sub));
}

/// `max_sync_events = 0` disables sync: `unsupported:` and any sync
/// under the id is torn down.
#[test]
fn neg_disabled_is_unsupported() {
    let mut s = Session::new(
        Arc::new(Limits {
            req: nosfry_core::limits::ReqLimits {
                max_sync_events: 0,
                ..nosfry_core::limits::ReqLimits::default()
            },
            ..Limits::default()
        }),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    );
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    assert!(
        sends(&out)[0] == "[\"NEG-ERR\",\"n\",\"unsupported: negentropy sync\"]",
        "{out:?}"
    );
    assert!(
        !matches!(out[0], Command::NegOpen { .. } | Command::NegClose { .. }) || out.len() == 1
    );
}

/// A refused `NEG-OPEN` on an open sync id emits `NegClose` then
/// the `NEG-ERR`, so the old session does not linger.
#[test]
fn neg_refusal_closes_prior_sync() {
    let mut s = session_with_rate(nosfry_core::limits::RateLimits {
        reqs_per_second: 100,
        reqs_burst: 100,
        ..nosfry_core::limits::RateLimits::default()
    });
    let out = feed_ms(&mut s, 1, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    let Command::NegOpen { sub, .. } = &out[0] else {
        unreachable!()
    };
    assert!(s.is_current_neg(sub));
    let t = 1_000u64;
    for _ in 0..100 {
        feed_ms(&mut s, t, "[\"REQ\",\"r\",{}]");
        feed_ms(&mut s, t, "[\"CLOSE\",\"r\"]");
    }
    // The bucket is empty: the re-open is refused and the old sync
    // torn down first.
    let out = feed_ms(&mut s, t, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    let frames = sends(&out);
    assert!(
        matches!(
            out.as_slice(),
            [Command::NegClose { .. }, Command::Send { .. }]
        ) && frames[0] == "[\"NEG-ERR\",\"n\",\"rate-limited: slow down\"]",
        "{out:?}"
    );
    assert!(!s.is_current_neg(sub));
}

/// A `NEG-OPEN` over `max_tags_per_filter` answers
/// `invalid: filter has too many tag conditions` and drops a sync
/// already open under the id.
#[test]
fn neg_open_over_tag_limit_drops_prior_sync() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{},\"aabb\"]");
    let Command::NegOpen { sub, .. } = &out[0] else {
        unreachable!()
    };
    assert!(s.is_current_neg(sub));
    let many_tags = "{\"#a\":[\"x\"],\"#b\":[\"x\"],\"#c\":[\"x\"],\"#d\":[\"x\"]}";
    let out = feed(
        &mut s,
        1,
        &format!("[\"NEG-OPEN\",\"n\",{many_tags},\"aabb\"]"),
    );
    let frames = sends(&out);
    assert!(
        matches!(
            out.as_slice(),
            [Command::NegClose { .. }, Command::Send { .. }]
        ) && frames[0] == "[\"NEG-ERR\",\"n\",\"invalid: filter has too many tag conditions\"]",
        "{out:?}"
    );
    assert!(!s.is_current_neg(sub));
}

/// A fully restricted `NEG-OPEN` with AUTH disabled answers
/// `restricted:` like a REQ.
#[test]
fn neg_fully_restricted_auth_disabled() {
    let mut s = session_auth("", &[4], true);
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{\"kinds\":[4]},\"aabb\"]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"NEG-ERR\",\"n\",\"restricted: requested kinds are not served\"]"],
        "{out:?}"
    );
    assert!(
        !out.iter().any(|c| matches!(c, Command::NegOpen { .. })),
        "{out:?}"
    );
}

/// A fully restricted unauthenticated `NEG-OPEN` answers
/// `auth-required:` (challenge issued) like a REQ.
#[test]
fn neg_fully_restricted_unauthenticated() {
    let mut s = session_auth("ws://r", &[4], true);
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"n\",{\"kinds\":[4]},\"aabb\"]");
    let frames = sends(&out);
    assert_eq!(frames[0], "[\"AUTH\",\"challenge\"]", "{out:?}");
    assert!(frames[1].contains("auth-required:"), "{out:?}");
    // No sync is open: a follow-up NEG-MSG answers `closed:`.
    let out = feed(&mut s, 1, "[\"NEG-MSG\",\"n\",\"ccdd\"]");
    assert!(
        sends(&out)[0] == "[\"NEG-ERR\",\"n\",\"closed: unknown subscription\"]",
        "{out:?}"
    );
}

/// The sync namespace shares `max_subs_per_connection`: past the cap
/// `NEG-OPEN` answers `error: too many open subscriptions`.
#[test]
fn neg_open_over_sub_cap() {
    let mut s = Session::new(
        Arc::new(Limits {
            req: nosfry_core::limits::ReqLimits {
                max_subs_per_connection: 1,
                ..nosfry_core::limits::ReqLimits::default()
            },
            ..Limits::default()
        }),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    );
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"a\",{},\"aabb\"]");
    assert!(
        matches!(out.as_slice(), [Command::NegOpen { .. }]),
        "{out:?}"
    );
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"b\",{},\"aabb\"]");
    assert!(
        sends(&out)[0].contains("too many open subscriptions"),
        "{out:?}"
    );
}

/// `subs` and `neg` are independent namespaces under the same id:
/// `CLOSE` kills only the REQ, `NEG-CLOSE` only the sync.
#[test]
fn neg_and_req_share_id_not_state() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"REQ\",\"x\",{}]");
    assert!(
        matches!(out.as_slice(), [Command::Subscribe { .. }]),
        "{out:?}"
    );
    let out = feed(&mut s, 1, "[\"NEG-OPEN\",\"x\",{},\"aabb\"]");
    assert!(
        matches!(out.as_slice(), [Command::NegOpen { .. }]),
        "{out:?}"
    );
    // CLOSE removes the REQ; the sync still answers NEG-MSG.
    let out = feed(&mut s, 1, "[\"CLOSE\",\"x\"]");
    assert!(
        matches!(out.as_slice(), [Command::Unsubscribe { .. }]),
        "{out:?}"
    );
    let out = feed(&mut s, 1, "[\"NEG-MSG\",\"x\",\"ccdd\"]");
    assert!(
        matches!(out.as_slice(), [Command::NegMsg { .. }]),
        "{out:?}"
    );
    // NEG-CLOSE removes the sync; a REQ under the id is unaffected.
    let out = feed(&mut s, 1, "[\"REQ\",\"x\",{}]");
    assert!(
        matches!(out.as_slice(), [Command::Subscribe { .. }]),
        "{out:?}"
    );
    let out = feed(&mut s, 1, "[\"NEG-CLOSE\",\"x\"]");
    assert!(
        matches!(out.as_slice(), [Command::NegClose { .. }]),
        "{out:?}"
    );
    let out = feed(&mut s, 1, "[\"NEG-MSG\",\"x\",\"ccdd\"]");
    assert!(
        sends(&out)[0].contains("closed: unknown subscription"),
        "{out:?}"
    );
}

/// A session resumed from persisted state keeps the authenticated
/// pubkeys: a protected event by an authed author publishes without
/// another AUTH, and `challenge_sent` stays set.
#[test]
fn resumed_session_keeps_authed_pubkeys() {
    let t = 1_700_000_000u64;
    let service_url = RelayUrl::parse("wss://relay.example.com").expect("service url");
    let authed: Arc<[PublicKey]> = Arc::from([PublicKey::from_hex(&pubkey_hex([9; 32])).unwrap()]);
    let mut s = Session::resume(
        Arc::new(Limits {
            auth: Arc::new(nosfry_core::auth::AuthRules::new(
                Some(service_url),
                &[4],
                true,
            )),
            ..Limits::default()
        }),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
        true,
        authed,
    );
    assert!(s.challenge_sent());
    assert_eq!(s.authenticated().len(), 1);
    let protected = format!(
        "[\"EVENT\",{}]",
        signed_event_json([9; 32], t, 1, "[[\"-\"]]", "for me only")
    );
    let out = feed(&mut s, t, &protected);
    assert!(
        matches!(out.as_slice(), [Command::Publish { .. }]),
        "{out:?}"
    );
}

/// A resumed session whose challenge was already sent does not send
/// it again.
#[test]
fn resumed_session_does_not_resend_challenge() {
    let service_url = RelayUrl::parse("wss://relay.example.com").expect("service url");
    let mut s = Session::resume(
        Arc::new(Limits {
            auth: Arc::new(nosfry_core::auth::AuthRules::new(
                Some(service_url),
                &[4],
                true,
            )),
            ..Limits::default()
        }),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
        true,
        Arc::from([]),
    );
    let out = feed(&mut s, 1, "[\"REQ\",\"a\",{\"kinds\":[4]}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"CLOSED\",\"a\",\"auth-required: requested filter requires authentication\"]"],
        "{out:?}"
    );
}

/// `CLOSE` of a subscription restored by `resume_sub` emits
/// `Unsubscribe` and drops the generation.
#[test]
fn close_of_resumed_sub_unsubscribes() {
    let mut s = session();
    let key = s.resume_sub(SubId::parse("a").expect("sub id"));
    assert!(s.is_current(&key));
    let out = feed(&mut s, 1, "[\"CLOSE\",\"a\"]");
    assert!(
        matches!(out.as_slice(), [Command::Unsubscribe { .. }]),
        "{out:?}"
    );
    assert!(!s.is_current(&key));
}

/// Session with `[relay.filter_validation]` `config` enabled over the
/// default `Limits`; panics when the config is inconsistent.
fn session_with_filter_validation(config: &nosfry_core::limits::FilterValidationConfig) -> Session {
    let rules = config.limits().expect("rules").expect("enabled");
    Session::new(
        Arc::new(Limits {
            req: nosfry_core::limits::ReqLimits {
                filter_validation: Some(rules),
                ..nosfry_core::limits::ReqLimits::default()
            },
            ..Limits::default()
        }),
        "challenge".to_owned(),
        Arc::new(AddressBuckets::default()),
    )
}

fn validated_session() -> Session {
    session_with_filter_validation(&nosfry_core::limits::FilterValidationConfig {
        enabled: true,
        ..Default::default()
    })
}

/// Filter-count bounds: `min`/`max` exact pass, outside refuses with
/// `blocked: invalid number of filters: N` and drops the sub id.
#[test]
fn filter_validation_filter_count_bounds() {
    let mut s = validated_session();
    // Exactly `max_filters_per_req` passes.
    let out = feed(&mut s, 1, "[\"REQ\",\"ok\",{},{},{}]");
    assert!(
        matches!(out.as_slice(), [Command::Subscribe { .. }]),
        "{out:?}"
    );
    // One over the maximum refuses.
    let out = feed(&mut s, 2, "[\"REQ\",\"over\",{},{},{},{}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"CLOSED\",\"over\",\"blocked: invalid number of filters: 4\"]"],
        "{out:?}"
    );
    // Under the minimum refuses too (min raised for this session).
    let mut s = session_with_filter_validation(&nosfry_core::limits::FilterValidationConfig {
        enabled: true,
        min_filters_per_req: 2,
        ..Default::default()
    });
    let out = feed(&mut s, 3, "[\"REQ\",\"min\",{}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"CLOSED\",\"min\",\"blocked: invalid number of filters: 1\"]"],
        "{out:?}"
    );
}

/// Per-filter kinds bounds: exactly `max_kinds_per_filter` passes,
/// one more answers `blocked: too many kinds in filter: N`.
#[test]
fn filter_validation_kinds_count_bound() {
    let mut s = validated_session();
    let out = feed(&mut s, 1, "[\"REQ\",\"ok\",{\"kinds\":[1,2,3]}]");
    assert!(
        matches!(out.as_slice(), [Command::Subscribe { .. }]),
        "{out:?}"
    );
    let out = feed(&mut s, 2, "[\"REQ\",\"over\",{\"kinds\":[1,2,3,4]}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"CLOSED\",\"over\",\"blocked: too many kinds in filter: 4\"]"],
        "{out:?}"
    );
}

/// A non-empty `allowed_kinds` set refuses unlisted kinds and filters
/// without a `kinds` key (strfry lets those match every kind).
#[test]
fn filter_validation_allowed_kinds() {
    let mut s = session_with_filter_validation(&nosfry_core::limits::FilterValidationConfig {
        enabled: true,
        allowed_kinds: vec![1, 4],
        ..Default::default()
    });
    let out = feed(&mut s, 1, "[\"REQ\",\"ok\",{\"kinds\":[1,4]}]");
    assert!(
        matches!(out.as_slice(), [Command::Subscribe { .. }]),
        "{out:?}"
    );
    let out = feed(&mut s, 2, "[\"REQ\",\"miss\",{\"kinds\":[1,3]}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"CLOSED\",\"miss\",\"blocked: kind not allowed: 3\"]"],
        "{out:?}"
    );
    let out = feed(&mut s, 3, "[\"REQ\",\"none\",{}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"CLOSED\",\"none\",\"blocked: filter must list kinds\"]"],
        "{out:?}"
    );
}

/// `require_author_or_tag` accepts exactly one `authors`, `#p`, or
/// `#e` value and refuses zero or two.
#[test]
fn filter_validation_author_or_tag() {
    let mut s = session_with_filter_validation(&nosfry_core::limits::FilterValidationConfig {
        enabled: true,
        require_author_or_tag: true,
        ..Default::default()
    });
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    for (sub, filter) in [
        ("one_author", format!("{{\"authors\":[\"{a}\"]}}")),
        ("one_p", format!("{{\"#p\":[\"{a}\"]}}")),
        ("one_e", format!("{{\"#e\":[\"{a}\"]}}")),
    ] {
        let out = feed(&mut s, 1, &format!("[\"REQ\",\"{sub}\",{filter}]"));
        assert!(
            matches!(out.as_slice(), [Command::Subscribe { .. }]),
            "{filter}: {out:?}"
        );
    }
    for (sub, filter) in [
        ("two_authors", format!("{{\"authors\":[\"{a}\",\"{b}\"]}}")),
        ("two_p", format!("{{\"#p\":[\"{a}\",\"{b}\"]}}")),
        ("none_of_them", "{\"kinds\":[1]}".to_owned()),
    ] {
        let out = feed(&mut s, 2, &format!("[\"REQ\",\"{sub}\",{filter}]"));
        let frames = sends(&out);
        assert_eq!(
            frames.as_slice(),
            [format!(
                "[\"CLOSED\",\"{sub}\",\"blocked: filter must have exactly one author, p tag, or e tag\"]"
            )],
            "{filter}: {out:?}"
        );
    }
}

/// `COUNT` shares the rules with REQ: the same violation answers the
/// same `CLOSED blocked:` frame.
#[test]
fn filter_validation_applies_to_count() {
    let mut s = validated_session();
    let out = feed(&mut s, 1, "[\"COUNT\",\"c\",{\"kinds\":[1,2,3,4]}]");
    let frames = sends(&out);
    assert_eq!(
        frames.as_slice(),
        ["[\"CLOSED\",\"c\",\"blocked: too many kinds in filter: 4\"]"],
        "{out:?}"
    );
}

/// `NEG-OPEN` is exempt: a filter violating the rules still opens a
/// sync session.
#[test]
fn filter_validation_neg_open_exempt() {
    let mut s = validated_session();
    let out = feed(
        &mut s,
        1,
        "[\"NEG-OPEN\",\"n\",{\"kinds\":[1,2,3,4]},\"aabb\"]",
    );
    assert!(
        matches!(out.as_slice(), [Command::NegOpen { .. }]),
        "{out:?}"
    );
}

/// `enabled = false` (the default) leaves REQ untouched.
#[test]
fn filter_validation_disabled_passes() {
    let mut s = session();
    let out = feed(&mut s, 1, "[\"REQ\",\"s\",{},{},{},{}]");
    assert!(
        matches!(out.as_slice(), [Command::Subscribe { .. }]),
        "{out:?}"
    );
}

/// `FilterValidationConfig::limits` refuses contradictory bounds
/// when enabled, naming the offending key.
#[test]
fn filter_validation_config_bounds() {
    use nosfry_core::limits::FilterValidationConfig;
    assert!(
        FilterValidationConfig::default()
            .limits()
            .unwrap()
            .is_none()
    );
    let zero = FilterValidationConfig {
        enabled: true,
        max_filters_per_req: 0,
        ..Default::default()
    };
    assert_eq!(
        zero.limits().unwrap_err().to_string(),
        "relay.filter_validation.max_filters_per_req must be at least 1"
    );
    let inverted = FilterValidationConfig {
        enabled: true,
        min_filters_per_req: 4,
        ..Default::default()
    };
    assert_eq!(
        inverted.limits().unwrap_err().to_string(),
        "relay.filter_validation.min_filters_per_req must not exceed max_filters_per_req"
    );
    // Disabled sections never fail, even with bad values.
    let disabled = FilterValidationConfig {
        enabled: false,
        min_filters_per_req: 9,
        max_filters_per_req: 0,
        ..Default::default()
    };
    assert!(disabled.limits().unwrap().is_none());
}
