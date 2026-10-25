//! Relay object over the rusqlite executor: protocol flow, delivery,
//! expiry, and hibernation restore.

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
#![allow(
    clippy::let_underscore_must_use,
    clippy::shadow_unrelated,
    clippy::assert_is_empty,
    reason = "tests discard Effects and re-bind short names freely"
)]

use std::cell::RefCell;
use std::ops::ControlFlow;
use std::rc::Rc;

use negentropy::{Id, Negentropy, NegentropyStorageVector};
use nosfry_core::event::PublicKey;
use nosfry_core::filter::Filter;
use nosfry_core::hll::Hll;
use nosfry_core::message::{SubId, count_frame};
use nosfry_core::sign::{event, key};
use nosfry_sql::rusqlite::Connection;
use nosfry_sql::{Executor, Param, SqlStore, StoreError, Value};
use nosfry_worker::{Attachment, Config, Relay, Socket};
use serde_json::json;

const NOW: u64 = 1_700_000_000;

type TestRelay = Relay<Connection, FakeSocket>;

#[derive(Clone, Default)]
struct FakeSocket {
    sent: Rc<RefCell<Vec<String>>>,
    closed: Rc<RefCell<Vec<(u16, String)>>>,
}

impl FakeSocket {
    fn sent(&self) -> Vec<String> {
        self.sent.borrow().clone()
    }

    fn closed(&self) -> Vec<(u16, String)> {
        self.closed.borrow().clone()
    }
}

impl Socket for FakeSocket {
    fn send(&self, text: &str) {
        self.sent.borrow_mut().push(text.to_owned());
    }

    fn close(&self, code: u16, reason: &str) {
        self.closed.borrow_mut().push((code, reason.to_owned()));
    }
}

fn relay(config: &str) -> TestRelay {
    relay_on(Connection::open_in_memory().unwrap(), config, vec![])
}

fn relay_on(exec: Connection, config: &str, sockets: Vec<(FakeSocket, Attachment)>) -> TestRelay {
    relay_with_policy(exec, config, sockets, false)
}

fn relay_with_policy(
    exec: Connection,
    config: &str,
    sockets: Vec<(FakeSocket, Attachment)>,
    policy: bool,
) -> TestRelay {
    Relay::open(
        SqlStore::open(exec).unwrap(),
        Config::parse(config).unwrap(),
        sockets,
        policy,
    )
    .unwrap()
}

fn connect(relay: &mut TestRelay, conn: u64) -> FakeSocket {
    let socket = FakeSocket::default();
    relay
        .accept(socket.clone(), conn, None, format!("challenge-{conn}"))
        .unwrap();
    socket
}

/// `Relay::message` with the `Effects` discarded.
fn msg(relay: &mut TestRelay, conn: u64, text: &str) {
    let _ = relay.message(conn, NOW * 1000, text);
}

/// The hex pubkey of `key(n)` (pool index `n - 1`).
fn pubkey_of(n: u8) -> String {
    format!("{}", key(n).x_only_public_key().0)
}

fn event_frame(event: &nosfry_core::event::Event) -> String {
    format!("[\"EVENT\",{}]", event.json())
}

fn req_frame(sub: &str, filter: &serde_json::Value) -> String {
    format!("[\"REQ\",\"{sub}\",{filter}]")
}

fn count_wire(sub: &str, filter: &serde_json::Value) -> String {
    format!("[\"COUNT\",\"{sub}\",{filter}]")
}

/// The JSON body of the `["COUNT",sub,{..}]` frame.
fn count_body(frames: &[String], sub: &str) -> serde_json::Value {
    let frame = frames
        .iter()
        .find(|f| f.starts_with(&format!("[\"COUNT\",\"{sub}\"")))
        .unwrap_or_else(|| panic!("no COUNT frame for {sub}: {frames:?}"));
    serde_json::from_str::<serde_json::Value>(frame).unwrap()[2].clone()
}

/// `[relay]` + `[relay.management]` with `key(9)` as the admin, at
/// the service URL the NIP-98 `u` tag must name.
fn admin_config() -> String {
    format!(
        "[relay]\nservice_url = \"wss://relay.example.com\"\n\
         [relay.management]\nadmins = [\"{}\"]\n",
        pubkey_of(9)
    )
}

/// `Authorization: Nostr <base64(event)>` — a NIP-98 kind-27235
/// event naming the service URL, `POST`, and the body's SHA-256.
fn nip98(secret: u8, body: &[u8], now: u64) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = faster_hex::hex_string(&sha2::Sha256::digest(body));
    let auth = event(
        &key(secret),
        27_235,
        now,
        &json!([
            ["u", "wss://relay.example.com"],
            ["method", "POST"],
            ["payload", digest],
        ]),
        "",
    );
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(auth.json())
    )
}

/// One management call: sign `body` as `secret` and run
/// `Relay::manage`; returns `(status, parsed body)`.
fn rpc(relay: &mut TestRelay, secret: u8, body: &serde_json::Value) -> (u16, serde_json::Value) {
    let text = body.to_string();
    let managed = relay.manage(
        Some("application/nostr+json+rpc"),
        Some(&nip98(secret, text.as_bytes(), NOW)),
        text.as_bytes(),
        NOW,
    );
    let parsed = serde_json::from_str(&managed.body).unwrap();
    (managed.status, parsed)
}

fn auth_frame(secret: u8, challenge: &str, at: u64) -> String {
    let auth = event(
        &key(secret),
        22_242,
        at,
        &json!([
            ["challenge", challenge],
            ["relay", "wss://relay.example.com"]
        ]),
        "",
    );
    format!("[\"AUTH\",{}]", auth.json())
}

fn ok_frames(frames: &[String]) -> Vec<String> {
    frames
        .iter()
        .filter(|f| f.starts_with("[\"OK\""))
        .cloned()
        .collect()
}

fn event_frames(frames: &[String], sub: &str) -> Vec<String> {
    frames
        .iter()
        .filter(|f| f.starts_with(&format!("[\"EVENT\",\"{sub}\"")))
        .cloned()
        .collect()
}

#[test]
fn publish_ok_and_duplicate() {
    let mut r = relay("");
    let socket = connect(&mut r, 1);
    let e = event(&key(1), 1, NOW, &json!([]), "hi");
    msg(&mut r, 1, &event_frame(&e));
    let frames = ok_frames(&socket.sent());
    assert_eq!(frames.len(), 1, "{:?}", socket.sent());
    assert!(frames[0].ends_with(",true,\"\"]"), "{:?}", socket.sent());
    msg(&mut r, 1, &event_frame(&e));
    let frames = ok_frames(&socket.sent());
    assert_eq!(frames.len(), 2);
    assert!(frames[1].contains("duplicate: have this event"));
}

#[test]
fn req_newest_first_eose_and_limit() {
    let mut r = relay("");
    let publisher = connect(&mut r, 1);
    let reader = connect(&mut r, 2);
    for i in 0..5 {
        let e = event(&key(1), 1, NOW - 10 + i, &json!([]), &format!("m{i}"));
        let _ = r.message(1, NOW * 1000, &event_frame(&e));
    }
    drop(publisher);
    msg(
        &mut r,
        2,
        &req_frame("s", &json!({"kinds": [1], "limit": 3})),
    );
    let frames = reader.sent();
    let hits = event_frames(&frames, "s");
    assert_eq!(hits.len(), 3, "{frames:?}");
    assert!(frames[3].starts_with("[\"EOSE\",\"s\"]"), "{frames:?}");
    assert!(hits[0].contains("m4") && hits[1].contains("m3") && hits[2].contains("m2"));
}

#[test]
fn live_delivery_to_other_and_self() {
    let mut r = relay("");
    let a = connect(&mut r, 1);
    let b = connect(&mut r, 2);
    msg(&mut r, 2, &req_frame("s", &json!({"kinds": [1]})));
    msg(&mut r, 1, &req_frame("t", &json!({"kinds": [1]})));
    let e = event(&key(1), 1, NOW, &json!([]), "live");
    msg(&mut r, 1, &event_frame(&e));
    let b_hits = event_frames(&b.sent(), "s");
    assert_eq!(b_hits.len(), 1, "{:?}", b.sent());
    assert!(b_hits[0].contains("\"live\""));
    // The publisher's own subscription receives it too.
    let a_hits = event_frames(&a.sent(), "t");
    assert_eq!(a_hits.len(), 1, "{:?}", a.sent());
}

#[test]
fn close_stops_delivery() {
    let mut r = relay("");
    connect(&mut r, 1);
    let b = connect(&mut r, 2);
    msg(&mut r, 2, &req_frame("s", &json!({"kinds": [1]})));
    let _ = r.message(2, NOW * 1000, "[\"CLOSE\",\"s\"]");
    let e = event(&key(1), 1, NOW, &json!([]), "gone");
    msg(&mut r, 1, &event_frame(&e));
    assert!(event_frames(&b.sent(), "s").is_empty(), "{:?}", b.sent());
}

#[test]
fn replaceable_event_is_superseded() {
    let mut r = relay("");
    let socket = connect(&mut r, 1);
    let old = event(&key(1), 0, NOW - 100, &json!([]), "old profile");
    let new = event(&key(1), 0, NOW - 50, &json!([]), "new profile");
    msg(&mut r, 1, &event_frame(&old));
    msg(&mut r, 1, &event_frame(&new));
    // The stale version loses.
    msg(&mut r, 1, &event_frame(&old));
    let oks = ok_frames(&socket.sent());
    assert_eq!(oks.len(), 3);
    assert!(
        oks[2].contains("duplicate: have a newer version"),
        "{oks:?}"
    );
    let reader = connect(&mut r, 2);
    msg(&mut r, 2, &req_frame("s", &json!({"kinds": [0]})));
    let hits = event_frames(&reader.sent(), "s");
    assert_eq!(hits.len(), 1);
    assert!(hits[0].contains("new profile"));
}

#[test]
fn deletion_hides_and_blocks_republication() {
    let mut r = relay("");
    let socket = connect(&mut r, 1);
    let victim = event(&key(1), 1, NOW - 100, &json!([]), "victim");
    msg(&mut r, 1, &event_frame(&victim));
    let del = event(
        &key(1),
        5,
        NOW - 50,
        &json!([["e", victim.id().to_string()]]),
        "bye",
    );
    msg(&mut r, 1, &event_frame(&del));
    // The deleted event is gone from scans.
    let reader = connect(&mut r, 2);
    msg(&mut r, 2, &req_frame("s", &json!({"kinds": [1]})));
    assert!(event_frames(&reader.sent(), "s").is_empty());
    // Re-publication is blocked.
    msg(&mut r, 1, &event_frame(&victim));
    let oks = ok_frames(&socket.sent());
    assert!(
        oks.last()
            .unwrap()
            .contains("blocked: deleted by its author"),
        "{oks:?}"
    );
}

#[test]
fn expiry_alarm_and_effects() {
    let mut r = relay("");
    connect(&mut r, 1);
    let soon = event(
        &key(1),
        1,
        NOW,
        &json!([["expiration", (NOW + 150).to_string()]]),
        "soon",
    );
    let later = event(
        &key(2),
        1,
        NOW,
        &json!([["expiration", (NOW + 500).to_string()]]),
        "later",
    );
    let never = event(&key(3), 1, NOW, &json!([]), "never");
    let effects = r.message(1, NOW * 1000, &event_frame(&soon));
    assert_eq!(effects.expiration, Some(NOW + 150));
    msg(&mut r, 1, &event_frame(&later));
    msg(&mut r, 1, &event_frame(&never));
    // Alarm before `soon` expires reports it.
    assert_eq!(r.alarm(NOW + 100).unwrap(), Some(NOW + 150));
    // At NOW + 200 `soon` is gone; `later` is next.
    assert_eq!(r.alarm(NOW + 200).unwrap(), Some(NOW + 500));
    // The sweep removed it for good.
    let reader = connect(&mut r, 2);
    let _ = r.message(
        2,
        (NOW + 600) * 1000,
        &req_frame("s", &json!({"kinds": [1]})),
    );
    let hits = event_frames(&reader.sent(), "s");
    assert_eq!(hits.len(), 1, "{:?}", reader.sent());
    assert!(hits[0].contains("never"));
    // Past everything, the alarm disarms.
    assert_eq!(r.alarm(NOW + 600).unwrap(), None);
}

#[test]
fn auth_challenge_flow() {
    let mut r = relay("[relay]\nservice_url = \"wss://relay.example.com\"\n");
    let socket = connect(&mut r, 1);
    let effects = r.message(1, NOW * 1000, &req_frame("a", &json!({"kinds": [4]})));
    let frames = socket.sent();
    assert_eq!(frames[0], "[\"AUTH\",\"challenge-1\"]", "{frames:?}");
    assert!(frames[1].contains("auth-required:"), "{frames:?}");
    // The sent challenge flips the attachment.
    let attachment = effects.attachment.expect("attachment changed");
    assert!(attachment.challenge_sent);
    assert!(attachment.authed.is_empty());
    // AUTH with the challenge succeeds and grows the authed set.
    let effects = r.message(1, NOW * 1000, &auth_frame(9, "challenge-1", NOW));
    let frames = socket.sent();
    assert!(frames[2].contains(",true,\"\"]"), "{frames:?}");
    let attachment = effects.attachment.expect("authed grew");
    assert_eq!(attachment.authed.len(), 1);
}

#[test]
fn restricted_kind_served_only_to_involved_authed() {
    let mut r = relay("[relay]\nservice_url = \"wss://relay.example.com\"\n");
    connect(&mut r, 1);
    let b = connect(&mut r, 2);
    // Conn 2 authenticates as key(9), then subscribes to kind 4.
    msg(&mut r, 2, &req_frame("x", &json!({"kinds": [4]})));
    msg(&mut r, 2, &auth_frame(9, "challenge-2", NOW));
    msg(&mut r, 2, &req_frame("s", &json!({"kinds": [4]})));
    assert_eq!(b.sent().last().unwrap(), "[\"EOSE\",\"s\"]");
    // A kind-4 p-tagging conn 2's pubkey is delivered; one tagging a
    // stranger is not.
    let me = pubkey_of(9);
    let other = pubkey_of(1);
    let for_me = event(&key(1), 4, NOW, &json!([["p", me]]), "secret for you");
    let for_other = event(&key(1), 4, NOW, &json!([["p", other]]), "not yours");
    msg(&mut r, 1, &event_frame(&for_me));
    msg(&mut r, 1, &event_frame(&for_other));
    let hits = event_frames(&b.sent(), "s");
    assert_eq!(hits.len(), 1, "{:?}", b.sent());
    assert!(hits[0].contains("secret for you"));
}

#[test]
fn protected_event_requires_auth() {
    let mut r = relay("[relay]\nservice_url = \"wss://relay.example.com\"\n");
    let socket = connect(&mut r, 1);
    let protected = event(&key(1), 1, NOW, &json!([["-"]]), "for me only");
    msg(&mut r, 1, &event_frame(&protected));
    let frames = socket.sent();
    assert_eq!(frames[0], "[\"AUTH\",\"challenge-1\"]", "{frames:?}");
    assert!(frames[1].contains("auth-required: event marked as protected"));
}

#[test]
fn oversized_message_closes_1009() {
    let mut r = relay("[relay]\nmax_websocket_payload_size = 64\n");
    let socket = connect(&mut r, 1);
    msg(&mut r, 1, &"x".repeat(100));
    assert_eq!(socket.closed(), vec![(1009, "message too big".to_owned())]);
    // The connection is gone: a following REQ produces nothing.
    msg(&mut r, 1, &req_frame("s", &json!({"kinds": [1]})));
    assert!(socket.sent().is_empty(), "{:?}", socket.sent());
}

#[test]
fn admits_enforces_the_global_cap() {
    let mut r = relay("[relay]\nmax_connections = 1\n");
    assert!(r.admits(None));
    connect(&mut r, 1);
    assert!(!r.admits(None));
    assert!(!r.admits(Some("10.0.0.1".parse().unwrap())));
    r.close(1);
    assert!(r.admits(None));
    // 0 disables the cap.
    let mut r = relay("[relay]\nmax_connections = 0\n");
    connect(&mut r, 1);
    assert!(r.admits(None));
}

#[test]
fn admits_enforces_the_per_ip_cap() {
    let ip = "10.0.0.7".parse().unwrap();
    let mut r = relay("[relay]\nmax_connections_per_ip = 1\n");
    let socket = FakeSocket::default();
    r.accept(socket, 1, Some(ip), "c".into()).unwrap();
    // A second socket from the same address is refused; another
    // address or an address-less connection is fine.
    assert!(!r.admits(Some(ip)));
    assert!(r.admits(Some("10.0.0.8".parse().unwrap())));
    assert!(r.admits(None));
    r.close(1);
    assert!(r.admits(Some(ip)));
    // 0 disables the cap.
    let mut r = relay("[relay]\nmax_connections_per_ip = 0\n");
    let socket = FakeSocket::default();
    r.accept(socket, 1, Some(ip), "c".into()).unwrap();
    assert!(r.admits(Some(ip)));
}

#[test]
fn attachment_stays_under_16_kib() {
    let mut attachment = Attachment {
        conn: 7,
        ip: Some("192.168.1.1".parse().unwrap()),
        challenge: "challenge".to_owned(),
        challenge_sent: true,
        authed: Vec::new(),
    };
    for i in 0..nosfry_core::auth::MAX_AUTHED_PUBKEYS {
        attachment.authed.push(format!("{i:064x}"));
    }
    let bytes = serde_json::to_vec(&attachment).unwrap();
    assert!(bytes.len() < 16 * 1024, "{}", bytes.len());
}

#[test]
fn hibernation_restores_subscriptions() {
    let config = "[relay]\nservice_url = \"wss://relay.example.com\"\n";
    let exec = Connection::open_in_memory().unwrap();
    let a = FakeSocket::default();
    let b = FakeSocket::default();
    let c = FakeSocket::default();
    let (att_a, att_b, att_c);
    {
        let mut r = relay_on(exec, config, vec![]);
        att_a = r.accept(a.clone(), 1, None, "challenge-a".into()).unwrap();
        let mut b_attachment = r.accept(b.clone(), 2, None, "challenge-b".into()).unwrap();
        att_c = r.accept(c.clone(), 3, None, "challenge-c".into()).unwrap();
        // Conn 1 subscribes before AUTH (open kinds plus kind 4, so
        // the REQ is not fully restricted); conn 2 after AUTH. The
        // glue rewrites the socket's attachment each time Effects
        // reports one.
        let _ = r.message(1, NOW * 1000, &req_frame("pre", &json!({"kinds": [1, 4]})));
        let effects = r.message(2, NOW * 1000, &auth_frame(9, "challenge-b", NOW));
        if let Some(attachment) = effects.attachment {
            b_attachment = attachment;
        }
        let _ = r.message(2, NOW * 1000, &req_frame("post", &json!({"kinds": [4]})));
        att_b = b_attachment;
        // Conn 3's row is stranded by the wake below.
        let _ = r.message(3, NOW * 1000, &req_frame("s", &json!({"kinds": [1]})));
        let exec = r.into_store().into_exec();
        // Wake with conn 1 and 2 only; conn 3's socket is gone.
        let mut r = relay_on(exec, config, vec![(a.clone(), att_a), (b.clone(), att_b)]);
        // The wake's restore summary: two live connections, both of
        // their subscriptions, and conn 3's stranded row dropped.
        assert_eq!(r.restored(), (2, 2, 1));
        // A new kind-4 p-tagging conn 2's authed pubkey arrives as
        // before: conn 2's post-AUTH sub sees it, conn 1's pre-AUTH
        // sub does not.
        let me = pubkey_of(9);
        let dm = event(&key(1), 4, NOW + 10, &json!([["p", me]]), "restored dm");
        let _ = r.message(1, NOW * 1000 + 10_000, &event_frame(&dm));
        let post = event_frames(&b.sent(), "post");
        assert_eq!(post.len(), 1, "{:?}", b.sent());
        assert!(post[0].contains("restored dm"));
        assert!(event_frames(&a.sent(), "pre").is_empty(), "{:?}", a.sent());
        // And conn 3's stranded rows were purged on wake.
        let exec = r.into_store().into_exec();
        let mut count = 0u64;
        exec.query("SELECT COUNT(*) FROM subs", &[], &mut |row| {
            if let Some(Value::Int(v)) = row.first() {
                count = u64::try_from(*v).unwrap();
            }
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(count, 2, "one row per live subscription");
    }
    drop((att_c, c));
}

#[test]
fn count_exact_and_union_dedup() {
    let mut r = relay("");
    let socket = connect(&mut r, 1);
    // key(1): two kind-1 + one kind-3; key(2): one kind-1.
    let events = [
        event(&key(1), 1, NOW, &json!([]), "a"),
        event(&key(1), 1, NOW, &json!([]), "b"),
        event(&key(2), 1, NOW, &json!([]), "c"),
        event(&key(1), 3, NOW, &json!([]), "d"),
    ];
    for ev in &events {
        msg(&mut r, 1, &event_frame(ev));
    }
    msg(&mut r, 1, &count_wire("c", &json!({"kinds": [1]})));
    let body = count_body(&socket.sent(), "c");
    assert_eq!(body["count"], 3, "{body}");
    assert!(body.get("approximate").is_none(), "{body}");

    // Overlapping filters count each event once: 3 kind-1s plus
    // key(1)'s kind-3 — not 3 + 3.
    let wire = format!(
        "[\"COUNT\",\"d\",{{\"kinds\":[1]}},{{\"authors\":[\"{}\"]}}]",
        pubkey_of(1)
    );
    msg(&mut r, 1, &wire);
    assert_eq!(count_body(&socket.sent(), "d")["count"], 4);

    // A filter `limit` is ignored for COUNT.
    msg(
        &mut r,
        1,
        &count_wire("e", &json!({"kinds": [1], "limit": 1})),
    );
    assert_eq!(count_body(&socket.sent(), "e")["count"], 3);
}

#[test]
fn count_hll_registers_match_the_core_sketch() {
    let mut r = relay("");
    let socket = connect(&mut r, 1);
    let target = pubkey_of(2);
    // Three followers p-tag key(2); a kind-1 without the tag does not
    // match the filter.
    let mut signers = Vec::new();
    for n in [1u8, 3, 5] {
        let ev = event(&key(n), 3, NOW, &json!([["p", target]]), "");
        msg(&mut r, 1, &event_frame(&ev));
        signers.push(n);
    }
    let stray = event(&key(7), 1, NOW, &json!([]), "");
    msg(&mut r, 1, &event_frame(&stray));

    msg(&mut r, 1, &count_wire("c", &json!({"#p": [target]})));
    // The whole frame equals what `count_frame` builds from the core
    // sketch over the counted authors.
    let filter = Filter::parse(&format!("{{\"#p\":[\"{target}\"]}}")).unwrap();
    let mut hll = Hll::for_filters(std::slice::from_ref(&filter)).unwrap();
    for n in signers {
        hll.add(&PublicKey(key(n).x_only_public_key().0.to_byte_array()));
    }
    let want = count_frame(&SubId::parse("c").unwrap(), 3, false, Some(hll.registers()));
    assert!(socket.sent().contains(&want), "{:?}", socket.sent());
}

#[test]
fn count_restricted_kind_needs_auth() {
    let mut r = relay("[relay]\nservice_url = \"wss://relay.example.com\"\n");
    connect(&mut r, 1);
    let socket = connect(&mut r, 2);
    let for_me = event(&key(5), 4, NOW, &json!([["p", pubkey_of(9)]]), "yours");
    let for_other = event(&key(5), 4, NOW, &json!([["p", pubkey_of(1)]]), "not yours");
    msg(&mut r, 1, &event_frame(&for_me));
    msg(&mut r, 1, &event_frame(&for_other));

    // A fully restricted COUNT is refused like a REQ: challenge plus
    // `auth-required:` CLOSED, nothing counted.
    msg(&mut r, 2, &count_wire("c", &json!({"kinds": [4]})));
    let frames = socket.sent();
    assert!(
        frames.iter().any(|f| f.starts_with("[\"AUTH\"")),
        "{frames:?}"
    );
    let closed = frames
        .iter()
        .find(|f| f.starts_with("[\"CLOSED\",\"c\""))
        .unwrap();
    assert!(closed.contains("auth-required:"), "{closed}");

    // Authenticated as key(9) only the involved DM counts.
    msg(&mut r, 2, &auth_frame(9, "challenge-2", NOW));
    msg(&mut r, 2, &count_wire("d", &json!({"kinds": [4]})));
    assert_eq!(count_body(&socket.sent(), "d")["count"], 1);
}

#[test]
fn count_marks_approximate_at_the_row_budget() {
    let mut r = relay("[worker]\nmax_scan_rows = 3\n");
    let socket = connect(&mut r, 1);
    // Two kind cursors; a 3-row budget lets the first drain inside
    // its page, then refuses the second.
    for i in 0..5u64 {
        let one = event(&key(1), 1, NOW + i, &json!([]), "a");
        let two = event(&key(1), 2, NOW + i, &json!([]), "b");
        msg(&mut r, 1, &event_frame(&one));
        msg(&mut r, 1, &event_frame(&two));
    }
    msg(&mut r, 1, &count_wire("c", &json!({"kinds": [1, 2]})));
    let body = count_body(&socket.sent(), "c");
    assert_eq!(body["approximate"], true, "{body}");
    assert!(body["count"].as_u64().unwrap() <= 10, "{body}");
}

#[test]
fn count_then_req_reuses_the_sub_id() {
    let mut r = relay("");
    let socket = connect(&mut r, 1);
    let ev = event(&key(1), 1, NOW, &json!([]), "hi");
    msg(&mut r, 1, &event_frame(&ev));
    msg(&mut r, 1, &count_wire("s", &json!({"kinds": [1]})));
    assert_eq!(count_body(&socket.sent(), "s")["count"], 1);
    // The COUNT closed the sub relay-side; the id is free for a REQ.
    msg(&mut r, 1, &req_frame("s", &json!({"kinds": [1]})));
    let frames = socket.sent();
    assert_eq!(event_frames(&frames, "s").len(), 1, "{frames:?}");
    assert!(frames.iter().any(|f| f == "[\"EOSE\",\"s\"]"), "{frames:?}");
}

#[test]
fn corrupt_subs_rows_are_purged_not_fatal() {
    let exec = Connection::open_in_memory().unwrap();
    let socket = FakeSocket::default();
    let attachment;
    {
        let mut r = relay_on(exec, "", vec![]);
        attachment = r.accept(socket.clone(), 1, None, "c".into()).unwrap();
        let _ = r.message(1, NOW * 1000, &req_frame("s", &json!({"kinds": [1]})));
        let exec = r.into_store().into_exec();
        // Garbage row for the live connection, plus one for a dead
        // connection.
        exec.execute(
            "INSERT INTO subs (conn, sub_id, filters, authed)
             VALUES (1, 'bad', 'not json', 0), (99, 'x', '[]', 0)",
            &[],
        )
        .unwrap();
        let mut r = relay_on(exec, "", vec![(socket.clone(), attachment)]);
        // The valid subscription still delivers.
        let e = event(&key(1), 1, NOW, &json!([]), "still here");
        let _ = r.message(1, NOW * 1000, &event_frame(&e));
        let hits = event_frames(&socket.sent(), "s");
        assert_eq!(hits.len(), 1, "{:?}", socket.sent());
        let exec = r.into_store().into_exec();
        let mut count = 0u64;
        exec.query("SELECT COUNT(*) FROM subs", &[], &mut |row| {
            if let Some(Value::Int(v)) = row.first() {
                count = u64::try_from(*v).unwrap();
            }
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(count, 1, "only the valid row remains");
    }
}

/// NIP-62: a request to vanish queues the sweep; the alarm deletes
/// the author's older events and `p`-tagged gift wraps, keeps the
/// request itself, and blocks later older publishes.
#[test]
fn request_to_vanish_sweeps_and_keeps_the_request() {
    let mut r = relay("[relay]\nservice_url = \"wss://relay.example.com\"\n");
    let socket = connect(&mut r, 1);
    let old = event(&key(1), 1, NOW - 100, &json!([]), "old");
    let wrap = event(
        &key(2),
        1059,
        NOW - 90,
        &json!([["p", pubkey_of(1)]]),
        "gift",
    );
    msg(&mut r, 1, &event_frame(&old));
    msg(&mut r, 1, &event_frame(&wrap));
    let vanish = event(
        &key(1),
        62,
        NOW,
        &json!([["relay", "wss://relay.example.com"]]),
        "",
    );
    let effects = r.message(1, NOW * 1000, &event_frame(&vanish));
    assert!(effects.vanish, "queued vanish produced no effect");
    assert_eq!(r.next_alarm(50).unwrap(), Some(50));
    // The alarm drains the queue — the loop exercises resumption.
    while r.alarm(NOW).unwrap() == Some(NOW) {}
    assert_eq!(r.next_alarm(50).unwrap(), None);
    // The author's older events are gone; the request remains.
    msg(
        &mut r,
        1,
        &req_frame("a", &json!({"authors": [pubkey_of(1)]})),
    );
    let hits = event_frames(&socket.sent(), "a");
    assert_eq!(hits.len(), 1, "{:?}", socket.sent());
    assert!(hits[0].contains(&format!("{}", vanish.id())), "{hits:?}");
    // The gift wrap `p`-tagged to the author is gone.
    msg(&mut r, 1, &req_frame("w", &json!({"#p": [pubkey_of(1)]})));
    assert!(event_frames(&socket.sent(), "w").is_empty());
    // An equal-or-older publish by the author stays blocked.
    let late = event(&key(1), 1, NOW - 50, &json!([]), "late");
    msg(&mut r, 1, &event_frame(&late));
    assert!(
        socket
            .sent()
            .iter()
            .any(|f| f.contains("blocked: request to vanish")),
        "{:?}",
        socket.sent()
    );
}

/// A kind-62 request naming a foreign relay changes nothing.
#[test]
fn foreign_relay_vanish_request_is_ignored() {
    let mut r = relay("[relay]\nservice_url = \"wss://relay.example.com\"\n");
    let socket = connect(&mut r, 1);
    let old = event(&key(1), 1, NOW - 100, &json!([]), "old");
    msg(&mut r, 1, &event_frame(&old));
    let foreign = event(
        &key(1),
        62,
        NOW,
        &json!([["relay", "wss://foreign.example.com"]]),
        "",
    );
    let effects = r.message(1, NOW * 1000, &event_frame(&foreign));
    assert!(!effects.vanish, "foreign request queued work");
    assert_eq!(r.next_alarm(50).unwrap(), None);
    msg(
        &mut r,
        1,
        &req_frame("s", &json!({"authors": [pubkey_of(1)]})),
    );
    assert_eq!(event_frames(&socket.sent(), "s").len(), 2);
}

/// The NIP-11 document advertises NIP-62.
#[test]
fn nip11_lists_62() {
    let r = relay("");
    let doc: serde_json::Value = serde_json::from_str(&r.nip11()).unwrap();
    let nips = doc["supported_nips"].as_array().unwrap();
    assert!(nips.contains(&json!(62)), "{nips:?}");
}

/// The full NIP-11 field set is served, a configured `supported_nips`
/// replaces the computed list, and a malformed `pubkey`/`self` is
/// rejected at parse.
#[test]
fn nip11_full_fields() {
    const HEX64: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let r = relay(&format!(
        "[relay.info]\n\
         pubkey = \"{HEX64}\"\n\
         contact = \"admin@example.com\"\n\
         banner = \"https://example.com/banner.png\"\n\
         self = \"{HEX64}\"\n\
         terms_of_service = \"https://example.com/terms\"\n\
         privacy_policy = \"https://example.com/privacy\"\n\
         supported_nips = [1, 11]\n"
    ));
    let doc: serde_json::Value = serde_json::from_str(&r.nip11()).unwrap();
    assert_eq!(doc["pubkey"], HEX64);
    assert_eq!(doc["contact"], "admin@example.com");
    assert_eq!(doc["banner"], "https://example.com/banner.png");
    assert_eq!(doc["self"], HEX64);
    assert_eq!(doc["terms_of_service"], "https://example.com/terms");
    assert_eq!(doc["privacy_policy"], "https://example.com/privacy");
    assert_eq!(doc["supported_nips"], json!([1, 11]));

    for key in ["pubkey", "self"] {
        assert!(Config::parse(&format!("[relay.info]\n{key} = \"npub1bad\"\n")).is_err());
    }
}

/// NIP-86: without the RPC content type or a configured admin list the
/// endpoint answers 405, like native.
#[test]
fn management_requires_rpc_and_admins() {
    let mut r = relay(&admin_config());
    let body = br#"{"method":"supportedmethods"}"#;
    let managed = r.manage(Some("text/plain"), None, body, NOW);
    assert_eq!(managed.status, 405);
    let managed = r.manage(None, None, body, NOW);
    assert_eq!(managed.status, 405);
    // Without admins the endpoint does not exist at all.
    let mut r = relay("[relay]\nservice_url = \"wss://relay.example.com\"\n");
    let managed = r.manage(Some("application/nostr+json+rpc"), None, body, NOW);
    assert_eq!(managed.status, 405);
}

/// NIP-98 failures are 401 `{"error":"unauthorized: <reason>"}`; bad
/// bodies are 400 plain text; over the limit is 413.
#[test]
fn management_unauthorized_and_bad_requests() {
    let mut r = relay(&admin_config());
    let body = br#"{"method":"supportedmethods"}"#;
    let managed = r.manage(Some("application/nostr+json+rpc"), None, body, NOW);
    assert_eq!(managed.status, 401);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&managed.body).unwrap()["error"],
        "unauthorized: missing authorization header"
    );
    // A `payload` tag naming another body fails the hash check.
    let other = nip98(9, b"different", NOW);
    let managed = r.manage(Some("application/nostr+json+rpc"), Some(&other), body, NOW);
    assert_eq!(managed.status, 401, "{}", managed.body);
    assert!(
        managed
            .body
            .contains("unauthorized: `payload` tag does not match the body"),
        "{}",
        managed.body
    );
    // A non-admin signature is refused after the crypto passes.
    let (_, body) = rpc(&mut r, 1, &json!({"method": "supportedmethods"}));
    assert_eq!(body["error"], "unauthorized: pubkey is not an admin");
    // Invalid UTF-8 and invalid JSON are 400 with the native wording.
    let managed = r.manage(
        Some("application/nostr+json+rpc"),
        Some(&nip98(9, b"\xff\xfe", NOW)),
        b"\xff\xfe",
        NOW,
    );
    assert_eq!(
        (managed.status, managed.body.as_str()),
        (400, "invalid utf-8")
    );
    let managed = r.manage(
        Some("application/nostr+json+rpc"),
        Some(&nip98(9, b"not json", NOW)),
        b"not json",
        NOW,
    );
    assert_eq!(
        (managed.status, managed.body.as_str()),
        (400, "invalid request json")
    );
    // Over the 64 KiB body limit is 413.
    let big = vec![b' '; nosfry_core::management::BODY_LIMIT + 1];
    let managed = r.manage(Some("application/nostr+json+rpc"), None, &big, NOW);
    assert_eq!(managed.status, 413);
}

/// The pubkey and event method families dispatch and mutate.
#[test]
fn management_pubkey_and_event_methods() {
    let mut r = relay(&admin_config());
    let a = pubkey_of(1);
    let b = pubkey_of(2);
    let note = event(&key(1), 1, NOW, &json!([]), "victim")
        .id()
        .to_string();

    let (_, body) = rpc(&mut r, 9, &json!({"method": "supportedmethods"}));
    assert_eq!(
        body["result"].as_array().unwrap().len(),
        nosfry_core::management::METHODS.len()
    );

    let (_, body) = rpc(
        &mut r,
        9,
        &json!({"method": "banpubkey", "params": [a, "spam"]}),
    );
    assert_eq!(body["result"], true, "{body}");
    let (_, body) = rpc(&mut r, 9, &json!({"method": "listbannedpubkeys"}));
    assert_eq!(
        body["result"],
        json!([{"pubkey": a, "reason": "spam"}]),
        "{body}"
    );
    let (_, body) = rpc(&mut r, 9, &json!({"method": "unbanpubkey", "params": [a]}));
    assert_eq!(body["result"], true, "{body}");

    let (_, body) = rpc(
        &mut r,
        9,
        &json!({"method": "allowpubkey", "params": [b, "vip"]}),
    );
    assert_eq!(body["result"], true, "{body}");
    let (_, body) = rpc(&mut r, 9, &json!({"method": "listallowedpubkeys"}));
    assert_eq!(
        body["result"],
        json!([{"pubkey": b, "reason": "vip"}]),
        "{body}"
    );
    let (_, body) = rpc(
        &mut r,
        9,
        &json!({"method": "unallowpubkey", "params": [b]}),
    );
    assert_eq!(body["result"], true, "{body}");

    let (_, body) = rpc(
        &mut r,
        9,
        &json!({"method": "banevent", "params": [note, "bad"]}),
    );
    assert_eq!(body["result"], true, "{body}");
    let (_, body) = rpc(&mut r, 9, &json!({"method": "listbannedevents"}));
    assert_eq!(
        body["result"],
        json!([{"id": note, "reason": "bad"}]),
        "{body}"
    );
    let (_, body) = rpc(
        &mut r,
        9,
        &json!({"method": "unbanevent", "params": [note]}),
    );
    assert_eq!(body["result"], true, "{body}");
}

/// The kind, IP, and info method families dispatch and mutate, and
/// method/parameter errors answer `{"error": …}` at 200.
#[test]
fn management_kind_ip_and_info_methods() {
    let mut r = relay(&admin_config());

    let (_, body) = rpc(&mut r, 9, &json!({"method": "allowkind", "params": [4]}));
    assert_eq!(body["result"], true, "{body}");
    let (_, body) = rpc(&mut r, 9, &json!({"method": "listallowedkinds"}));
    assert_eq!(body["result"], json!([4]), "{body}");
    let (_, body) = rpc(&mut r, 9, &json!({"method": "disallowkind", "params": [5]}));
    assert_eq!(body["result"], true, "{body}");
    let (_, body) = rpc(&mut r, 9, &json!({"method": "listdisallowedkinds"}));
    assert_eq!(body["result"], json!([5]), "{body}");

    let (_, body) = rpc(
        &mut r,
        9,
        &json!({"method": "blockip", "params": ["192.0.2.1", "abuse"]}),
    );
    assert_eq!(body["result"], true, "{body}");
    let (_, body) = rpc(&mut r, 9, &json!({"method": "listblockedips"}));
    assert_eq!(
        body["result"],
        json!([{"ip": "192.0.2.1", "reason": "abuse"}]),
        "{body}"
    );
    let (_, body) = rpc(
        &mut r,
        9,
        &json!({"method": "unblockip", "params": ["192.0.2.1"]}),
    );
    assert_eq!(body["result"], true, "{body}");

    for method in [
        "changerelayname",
        "changerelaydescription",
        "changerelayicon",
    ] {
        let (_, body) = rpc(&mut r, 9, &json!({"method": method, "params": ["v"]}));
        assert_eq!(body["result"], true, "{body}");
    }

    // Method and parameter errors are `{"error": …}` at 200.
    let (status, body) = rpc(&mut r, 9, &json!({"method": "nosuch"}));
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (200, "unsupported method: nosuch")
    );
    let (_, body) = rpc(&mut r, 9, &json!({"method": "banpubkey", "params": ["zz"]}));
    assert_eq!(
        body["error"], "invalid params: expected a 64-hex pubkey",
        "{body}"
    );
}

/// A banned pubkey's publishes — ephemeral kinds included — answer
/// `OK false` with the native reason; its request to vanish stays
/// exempt.
#[test]
fn management_banpubkey_refuses_publish() {
    let mut r = relay(&admin_config());
    let socket = connect(&mut r, 1);
    rpc(
        &mut r,
        9,
        &json!({"method": "banpubkey", "params": [pubkey_of(1)]}),
    );

    let e = event(&key(1), 1, NOW, &json!([]), "banned");
    msg(&mut r, 1, &event_frame(&e));
    let ephemeral = event(&key(1), 20_000, NOW, &json!([]), "eph");
    msg(&mut r, 1, &event_frame(&ephemeral));
    let oks = ok_frames(&socket.sent());
    assert_eq!(oks.len(), 2, "{oks:?}");
    assert!(
        oks.iter()
            .all(|f| f.contains("blocked: pubkey not allowed")),
        "{oks:?}"
    );
    // A request to vanish is exempt so a banned author can still
    // vanish.
    let vanish = event(
        &key(1),
        62,
        NOW,
        &json!([["relay", "wss://relay.example.com"]]),
        "",
    );
    msg(&mut r, 1, &event_frame(&vanish));
    let oks = ok_frames(&socket.sent());
    assert!(oks.last().unwrap().contains(",true,"), "{oks:?}");
}

/// A banned pubkey's stored events stop answering REQ, and the read
/// gate a subscription carries survives a hibernation restore — the
/// ban keeps hiding the author's frames even for the only kind a
/// banned author may still store (a relay-scoped request to vanish).
#[test]
fn moderation_hides_stored_events_and_restored_subs() {
    let config = admin_config();
    let exec = Connection::open_in_memory().unwrap();
    let a = FakeSocket::default();
    let b = FakeSocket::default();
    let (att_a, att_b);
    {
        let mut r = relay_on(exec, &config, vec![]);
        att_a = r.accept(a.clone(), 1, None, "challenge-a".into()).unwrap();
        att_b = r.accept(b.clone(), 2, None, "challenge-b".into()).unwrap();
        let note = event(&key(1), 1, NOW, &json!([]), "pre-ban note");
        msg(&mut r, 1, &event_frame(&note));
        msg(&mut r, 2, &req_frame("s", &json!({"kinds": [1, 62]})));
        assert_eq!(event_frames(&b.sent(), "s").len(), 1);
        rpc(
            &mut r,
            9,
            &json!({"method": "banpubkey", "params": [pubkey_of(1)]}),
        );
        // The stored note is hidden from new REQs — hidden, not deleted.
        msg(
            &mut r,
            2,
            &req_frame("t", &json!({"authors": [pubkey_of(1)]})),
        );
        assert!(event_frames(&b.sent(), "t").is_empty(), "{:?}", b.sent());
        let exec = r.into_store().into_exec();
        // Simulated hibernation: reopen with the same sockets so the
        // `subs` rows restore under the current moderation snapshot.
        let mut r = relay_on(exec, &config, vec![(a.clone(), att_a), (b.clone(), att_b)]);
        // The vanish request is exempt from the write gate and
        // stored, but the restored subscription's read gate still
        // hides the banned author's frames.
        let vanish = event(
            &key(1),
            62,
            NOW + 1,
            &json!([["relay", "wss://relay.example.com"]]),
            "",
        );
        msg(&mut r, 1, &event_frame(&vanish));
        assert!(
            ok_frames(&a.sent()).last().unwrap().contains(",true,"),
            "{:?}",
            a.sent()
        );
        assert!(
            event_frames(&b.sent(), "s")
                .iter()
                .all(|f| f.contains("pre-ban")),
            "{:?}",
            b.sent()
        );
        // An unbanned author still reaches the restored subscription.
        let ok = event(&key(2), 1, NOW + 2, &json!([]), "b note");
        msg(&mut r, 1, &event_frame(&ok));
        assert!(
            event_frames(&b.sent(), "s")
                .iter()
                .any(|f| f.contains("b note")),
            "{:?}",
            b.sent()
        );
    }
}

/// `banevent` deletes the stored event in the same transaction and
/// blocks its republish.
#[test]
fn management_banevent_deletes_and_blocks() {
    let mut r = relay(&admin_config());
    let socket = connect(&mut r, 1);
    let victim = event(&key(1), 1, NOW, &json!([]), "victim");
    msg(&mut r, 1, &event_frame(&victim));

    rpc(
        &mut r,
        9,
        &json!({"method": "banevent", "params": [victim.id().to_string()]}),
    );
    let reader = connect(&mut r, 2);
    msg(&mut r, 2, &req_frame("s", &json!({"kinds": [1]})));
    assert!(
        event_frames(&reader.sent(), "s").is_empty(),
        "{:?}",
        reader.sent()
    );
    msg(&mut r, 1, &event_frame(&victim));
    assert!(
        socket
            .sent()
            .iter()
            .any(|f| f.contains("blocked: event banned")),
        "{:?}",
        socket.sent()
    );
}

/// The served NIP-11 `limitation.restricted_writes` follows the
/// allow-lists, like native.
#[test]
fn nip11_restricted_writes_follows_allow_lists() {
    let mut r = relay(&admin_config());
    let restricted = |r: &TestRelay| {
        serde_json::from_str::<serde_json::Value>(&r.nip11()).unwrap()["limitation"]
            ["restricted_writes"]
            .as_bool()
            .unwrap()
    };
    assert!(!restricted(&r));
    let (status, _) = rpc(
        &mut r,
        9,
        &json!({"method": "allowpubkey", "params": [pubkey_of(1)]}),
    );
    assert_eq!(status, 200);
    assert!(restricted(&r));
    rpc(
        &mut r,
        9,
        &json!({"method": "unallowpubkey", "params": [pubkey_of(1)]}),
    );
    assert!(!restricted(&r));
}

/// `blockip` flips `ip_blocked` for the glue's 403 gate.
#[test]
fn management_ip_block() {
    let mut r = relay(&admin_config());
    let ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    assert!(!r.ip_blocked(Some(ip)));
    rpc(
        &mut r,
        9,
        &json!({"method": "blockip", "params": ["192.0.2.1"]}),
    );
    assert!(r.ip_blocked(Some(ip)));
    assert!(!r.ip_blocked(Some("198.51.100.1".parse().unwrap())));
    assert!(!r.ip_blocked(None));
    rpc(
        &mut r,
        9,
        &json!({"method": "unblockip", "params": ["192.0.2.1"]}),
    );
    assert!(!r.ip_blocked(Some(ip)));
}

/// NIP-11 lists 86 with admins configured and applies the info
/// overrides.
#[test]
fn management_nip11_overrides_and_86() {
    let mut r = relay(&admin_config());
    let doc: serde_json::Value = serde_json::from_str(&r.nip11()).unwrap();
    assert!(
        doc["supported_nips"]
            .as_array()
            .unwrap()
            .contains(&json!(86))
    );
    rpc(
        &mut r,
        9,
        &json!({"method": "changerelayicon", "params": ["https://mod/icon.png"]}),
    );
    let doc: serde_json::Value = serde_json::from_str(&r.nip11()).unwrap();
    assert_eq!(doc["icon"], "https://mod/icon.png", "{doc}");
    // Without admins there is no 86.
    let r = relay("");
    let doc: serde_json::Value = serde_json::from_str(&r.nip11()).unwrap();
    assert!(
        !doc["supported_nips"]
            .as_array()
            .unwrap()
            .contains(&json!(86))
    );
}

/// The moderation snapshot survives a reopen (it is persisted).
#[test]
fn management_persists_across_reopen() {
    let exec = Connection::open_in_memory().unwrap();
    let config = admin_config();
    let mut r = relay_on(exec, &config, vec![]);
    rpc(
        &mut r,
        9,
        &json!({"method": "banpubkey", "params": [pubkey_of(1)]}),
    );
    rpc(
        &mut r,
        9,
        &json!({"method": "blockip", "params": ["192.0.2.1"]}),
    );
    let exec = r.into_store().into_exec();

    let mut r = relay_on(exec, &config, vec![]);
    let socket = connect(&mut r, 1);
    assert!(r.ip_blocked(Some("192.0.2.1".parse().unwrap())));
    let e = event(&key(1), 1, NOW, &json!([]), "still banned");
    msg(&mut r, 1, &event_frame(&e));
    assert!(
        socket
            .sent()
            .iter()
            .any(|f| f.contains("blocked: pubkey not allowed")),
        "{:?}",
        socket.sent()
    );
}

/// `["NEG-OPEN",sub,{filter},"<hex>"]`.
fn neg_open_wire(sub: &str, filter: &serde_json::Value, msg: &[u8]) -> String {
    format!(
        "[\"NEG-OPEN\",\"{sub}\",{filter},\"{}\"]",
        faster_hex::hex_string(msg)
    )
}

/// `["NEG-MSG",sub,"<hex>"]`.
fn neg_msg_wire(sub: &str, msg: &[u8]) -> String {
    format!(
        "[\"NEG-MSG\",\"{sub}\",\"{}\"]",
        faster_hex::hex_string(msg)
    )
}

/// `["NEG-CLOSE",sub]`.
fn neg_close_wire(sub: &str) -> String {
    format!("[\"NEG-CLOSE\",\"{sub}\"]")
}

/// Hex-decode a wire payload.
fn unhex(text: &str) -> Vec<u8> {
    let mut buf = vec![0u8; text.len() / 2];
    faster_hex::hex_decode(text.as_bytes(), &mut buf).unwrap();
    buf
}

/// A client-side `Negentropy` owning `records`.
fn client_neg(records: &[(u64, [u8; 32])]) -> Negentropy<'static, NegentropyStorageVector> {
    let mut storage = NegentropyStorageVector::with_capacity(records.len());
    for (created_at, id) in records {
        storage
            .insert(*created_at, Id::from_byte_array(*id))
            .unwrap();
    }
    storage.seal().unwrap();
    Negentropy::owned(storage, 500_000).unwrap()
}

/// Frames `socket` received for `sub` since `from`.
fn neg_msgs(socket: &FakeSocket, sub: &str, from: usize) -> Vec<String> {
    socket.sent()[from..]
        .iter()
        .filter(|f| f.starts_with(&format!("[\"NEG-MSG\",\"{sub}\"")))
        .cloned()
        .collect()
}

/// Drive one negentropy session: `NEG-OPEN` then `NEG-MSG` rounds
/// until `reconcile_with_ids` finishes. Returns `(have, need)` — ids
/// the client has that the relay lacks, and ids the relay has that
/// the client still needs.
fn neg_sync(
    relay: &mut TestRelay,
    socket: &FakeSocket,
    conn: u64,
    sub: &str,
    filter: &serde_json::Value,
    records: &[(u64, [u8; 32])],
) -> (Vec<String>, Vec<String>) {
    let mut neg = client_neg(records);
    let init = neg.initiate().unwrap();
    let mut seen = socket.sent().len();
    msg(relay, conn, &neg_open_wire(sub, filter, &init));
    let mut have_ids = Vec::new();
    let mut need_ids = Vec::new();
    loop {
        let msgs = neg_msgs(socket, sub, seen);
        assert_eq!(msgs.len(), 1, "expected one NEG-MSG: {:?}", socket.sent());
        seen = socket.sent().len();
        let frame: serde_json::Value = serde_json::from_str(&msgs[0]).unwrap();
        let reply = unhex(frame[2].as_str().unwrap());
        match neg
            .reconcile_with_ids(&reply, &mut have_ids, &mut need_ids)
            .unwrap()
        {
            Some(next) => msg(relay, conn, &neg_msg_wire(sub, &next)),
            None => break,
        }
    }
    let hexes = |ids: Vec<Id>| -> Vec<String> {
        ids.iter()
            .map(|id| faster_hex::hex_string(id.as_bytes()))
            .collect()
    };
    (hexes(have_ids), hexes(need_ids))
}

/// Both directions converge: `have` is the client-only id, `need`
/// the relay-only one.
#[test]
fn negentropy_reconciles_both_directions() {
    let mut r = relay("");
    let socket = connect(&mut r, 1);
    let shared_a = event(&key(1), 1, NOW + 1, &json!([]), "a");
    let shared_b = event(&key(1), 1, NOW + 2, &json!([]), "b");
    let relay_only = event(&key(2), 1, NOW + 3, &json!([]), "r");
    let client_only = event(&key(3), 1, NOW + 4, &json!([]), "c");
    for ev in [&shared_a, &shared_b, &relay_only] {
        msg(&mut r, 1, &event_frame(ev));
    }
    let (have, need) = neg_sync(
        &mut r,
        &socket,
        1,
        "s",
        &json!({"kinds": [1]}),
        &[
            (shared_a.created_at(), shared_a.id().0),
            (shared_b.created_at(), shared_b.id().0),
            (client_only.created_at(), client_only.id().0),
        ],
    );
    assert_eq!(have, [format!("{}", client_only.id())]);
    assert_eq!(need, [format!("{}", relay_only.id())]);
}

/// Over the effective cap the open is refused `blocked:` with the
/// limit as the fourth element.
#[test]
fn negentropy_over_cap_blocked() {
    let mut r = relay("[relay.limits]\nmax_sync_events = 1\n");
    let socket = connect(&mut r, 1);
    for i in 0..2u64 {
        let ev = event(&key(1), 1, NOW + i, &json!([]), "x");
        msg(&mut r, 1, &event_frame(&ev));
    }
    let mut neg = client_neg(&[]);
    let init = neg.initiate().unwrap();
    msg(&mut r, 1, &neg_open_wire("s", &json!({}), &init));
    assert_eq!(
        socket.sent().last().unwrap(),
        "[\"NEG-ERR\",\"s\",\"blocked: too many query results\",1]"
    );
}

/// An exhausted row budget refuses the same way.
#[test]
fn negentropy_row_budget_blocked() {
    let mut r = relay("[worker]\nmax_scan_rows = 1\n[relay.limits]\nmax_sync_events = 100\n");
    let socket = connect(&mut r, 1);
    for i in 0..2u64 {
        let ev = event(&key(1), 1, NOW + i, &json!([]), "x");
        msg(&mut r, 1, &event_frame(&ev));
    }
    let mut neg = client_neg(&[]);
    let init = neg.initiate().unwrap();
    msg(&mut r, 1, &neg_open_wire("s", &json!({}), &init));
    assert_eq!(
        socket.sent().last().unwrap(),
        "[\"NEG-ERR\",\"s\",\"blocked: too many query results\",1]"
    );
}

/// The sync-memory budget refuses a session it cannot reserve.
#[test]
fn negentropy_memory_budget_refusal() {
    let mut r = relay("[relay]\nmax_sync_memory_bytes = 40\n");
    let socket = connect(&mut r, 1);
    for i in 0..2u64 {
        let ev = event(&key(1), 1, NOW + i, &json!([]), "x");
        msg(&mut r, 1, &event_frame(&ev));
    }
    let mut neg = client_neg(&[]);
    let init = neg.initiate().unwrap();
    msg(&mut r, 1, &neg_open_wire("s", &json!({}), &init));
    assert_eq!(
        socket.sent().last().unwrap(),
        "[\"NEG-ERR\",\"s\",\"blocked: sync capacity exhausted\"]"
    );
}

/// A `NEG-MSG` with no session is refused and a malformed round
/// closes an open session — both with the native wording.
#[test]
fn negentropy_unknown_and_malformed() {
    let mut r = relay("");
    let socket = connect(&mut r, 1);
    let ev = event(&key(1), 1, NOW, &json!([]), "x");
    msg(&mut r, 1, &event_frame(&ev));

    // No session ever opened under "s".
    msg(&mut r, 1, &neg_msg_wire("s", &[0x60]));
    assert!(
        socket
            .sent()
            .contains(&"[\"NEG-ERR\",\"s\",\"closed: unknown subscription\"]".to_owned()),
        "{:?}",
        socket.sent()
    );

    // A malformed initial message refuses the open.
    msg(&mut r, 1, &neg_open_wire("t", &json!({}), &[0xde, 0xad]));
    assert!(
        socket
            .sent()
            .contains(&"[\"NEG-ERR\",\"t\",\"invalid: malformed negentropy message\"]".to_owned()),
        "{:?}",
        socket.sent()
    );

    // A malformed round closes the open session.
    let (have, need) = neg_sync(&mut r, &socket, 1, "u", &json!({}), &[]);
    assert!(have.is_empty() && need.len() == 1, "{have:?} {need:?}");
    let at = socket.sent().len();
    msg(&mut r, 1, &neg_msg_wire("u", &[0xde, 0xad]));
    assert_eq!(
        socket.sent()[at..],
        ["[\"NEG-ERR\",\"u\",\"invalid: malformed negentropy message\"]"]
    );
    msg(&mut r, 1, &neg_msg_wire("u", &[0x60]));
    assert!(
        socket.sent()[at..]
            .contains(&"[\"NEG-ERR\",\"u\",\"closed: unknown subscription\"]".to_owned()),
        "{:?}",
        socket.sent()
    );
}

/// `NEG-CLOSE` releases the reservation: with a budget of one
/// record, a second open only succeeds when the first released.
#[test]
fn negentropy_close_releases_the_reservation() {
    let mut r = relay("[relay]\nmax_sync_memory_bytes = 40\n");
    let socket = connect(&mut r, 1);
    let ev = event(&key(1), 1, NOW, &json!([]), "x");
    msg(&mut r, 1, &event_frame(&ev));
    let (have, need) = neg_sync(&mut r, &socket, 1, "s", &json!({}), &[]);
    assert!(have.is_empty() && need.len() == 1, "{have:?} {need:?}");
    msg(&mut r, 1, &neg_close_wire("s"));
    // The reservation is gone: a second open fits the budget again.
    let (have, need) = neg_sync(&mut r, &socket, 1, "t", &json!({}), &[]);
    assert!(have.is_empty() && need.len() == 1, "{have:?} {need:?}");
}

/// Disconnecting releases the reservation the same way.
#[test]
fn negentropy_disconnect_releases_the_reservation() {
    let mut r = relay("[relay]\nmax_sync_memory_bytes = 40\n");
    let socket = connect(&mut r, 1);
    let ev = event(&key(1), 1, NOW, &json!([]), "x");
    msg(&mut r, 1, &event_frame(&ev));
    let (have, need) = neg_sync(&mut r, &socket, 1, "s", &json!({}), &[]);
    assert!(have.is_empty() && need.len() == 1, "{have:?} {need:?}");
    r.close(1);
    let socket2 = connect(&mut r, 2);
    let (have, need) = neg_sync(&mut r, &socket2, 2, "s", &json!({}), &[]);
    assert!(have.is_empty() && need.len() == 1, "{have:?} {need:?}");
}

/// A session idle 60 s is reaped with `closed: idle timeout` at the
/// head of the next message.
#[test]
fn negentropy_idle_reap() {
    let mut r = relay("");
    let socket = connect(&mut r, 1);
    let ev = event(&key(1), 1, NOW, &json!([]), "x");
    msg(&mut r, 1, &event_frame(&ev));
    let (have, need) = neg_sync(&mut r, &socket, 1, "s", &json!({}), &[]);
    assert!(have.is_empty() && need.len() == 1, "{have:?} {need:?}");
    let at = socket.sent().len();
    // Any later message reaps the idle session first.
    let _ = r.message(1, (NOW + 60) * 1000, "[\"REQ\",\"x\",{\"kinds\":[999]}]");
    assert_eq!(
        socket.sent()[at],
        "[\"NEG-ERR\",\"s\",\"closed: idle timeout\"]"
    );
    // The session is gone: a NEG-MSG answers unknown.
    let _ = r.message(1, (NOW + 61) * 1000, &neg_msg_wire("s", &[0x60]));
    assert!(
        socket.sent()[at..]
            .contains(&"[\"NEG-ERR\",\"s\",\"closed: unknown subscription\"]".to_owned()),
        "{:?}",
        socket.sent()
    );
}

/// A Durable Object wake loses every session: reopening the relay
/// over the same store leaves `NEG-MSG` answering
/// `closed: unknown subscription`.
#[test]
fn negentropy_reopen_loses_sessions() {
    let exec = Connection::open_in_memory().unwrap();
    let socket = FakeSocket::default();
    let attachment;
    {
        let mut r = relay_on(exec, "", vec![]);
        attachment = r
            .accept(socket.clone(), 1, None, "challenge-1".to_owned())
            .unwrap();
        msg(
            &mut r,
            1,
            &event_frame(&event(&key(1), 1, NOW, &json!([]), "x")),
        );
        let (have, need) = neg_sync(&mut r, &socket, 1, "s", &json!({}), &[]);
        assert!(have.is_empty() && need.len() == 1, "{have:?} {need:?}");
        // Reopen over the same store: a fresh isolate lost the
        // in-memory session, and `resume` restored no neg slots.
        let mut r = relay_on(
            r.into_store().into_exec(),
            "",
            vec![(socket.clone(), attachment)],
        );
        msg(&mut r, 1, &neg_msg_wire("s", &[0x60]));
        assert!(
            socket
                .sent()
                .contains(&"[\"NEG-ERR\",\"s\",\"closed: unknown subscription\"]".to_owned()),
            "{:?}",
            socket.sent()
        );
    }
}

/// NIP-11 advertises 77 while sync is enabled and not when
/// `max_sync_events` disables it.
#[test]
fn nip11_lists_77_when_sync_enabled() {
    let r = relay("");
    let info: serde_json::Value = serde_json::from_str(&r.nip11()).unwrap();
    assert!(
        info["supported_nips"]
            .as_array()
            .unwrap()
            .contains(&json!(77))
    );
    let r = relay("[relay.limits]\nmax_sync_events = 0\n");
    let info: serde_json::Value = serde_json::from_str(&r.nip11()).unwrap();
    assert!(
        !info["supported_nips"]
            .as_array()
            .unwrap()
            .contains(&json!(77))
    );
}

/// The write-policy point: a policy-enabled relay pauses a publish
/// into `Effects.policy`, and `decided` finishes it with the native
/// wording. The request line carries the strfry fields.
#[test]
fn policy_accept_writes_and_answers_ok() {
    let exec = Connection::open_in_memory().unwrap();
    let mut r = relay_with_policy(exec, "", vec![], true);
    let socket = connect(&mut r, 1);
    let e = event(&key(1), 1, NOW, &json!([]), "policy-checked");
    let effects = r.message(1, NOW * 1000, &event_frame(&e));
    let check = effects.policy.expect("a policy-enabled relay pauses");
    assert_eq!(check.conn, 1);
    let line: serde_json::Value = serde_json::from_str(&check.line).unwrap();
    assert_eq!(line["type"], "new");
    assert_eq!(line["receivedAt"], NOW);
    assert_eq!(line["event"]["id"], e.id().to_string());
    assert_eq!(line["event"]["content"], "policy-checked");
    assert!(line.get("authed").is_none(), "{line}");
    // Nothing answered or stored yet — the publish is paused.
    assert!(socket.sent().is_empty(), "{:?}", socket.sent());
    let effects = r.decided(
        1,
        &check.event,
        nosfry_core::policy::Decision::Accept,
        NOW * 1000,
    );
    assert!(effects.policy.is_none());
    let oks = ok_frames(&socket.sent());
    assert_eq!(
        oks,
        [format!("[\"OK\",\"{}\",true,\"\"]", e.id())],
        "{oks:?}"
    );
    msg(
        &mut r,
        1,
        &req_frame("s", &json!({"authors": [pubkey_of(1)]})),
    );
    assert!(
        event_frames(&socket.sent(), "s")
            .iter()
            .any(|f| f.contains("policy-checked")),
        "{:?}",
        socket.sent()
    );
}

/// `reject` answers `OK false` with the plugin's message; the event
/// is neither stored nor delivered.
#[test]
fn policy_reject_blocks_the_event() {
    let exec = Connection::open_in_memory().unwrap();
    let mut r = relay_with_policy(exec, "", vec![], true);
    let socket = connect(&mut r, 1);
    let watcher = connect(&mut r, 2);
    msg(&mut r, 2, &req_frame("w", &json!({"kinds": [1]})));
    let e = event(&key(1), 1, NOW, &json!([]), "no");
    let check = r
        .message(1, NOW * 1000, &event_frame(&e))
        .policy
        .expect("a policy-enabled relay pauses");
    let _ = r.decided(
        1,
        &check.event,
        nosfry_core::policy::Decision::Reject("blocked: test policy".into()),
        NOW * 1000,
    );
    let oks = ok_frames(&socket.sent());
    assert_eq!(
        oks,
        [format!(
            "[\"OK\",\"{}\",false,\"blocked: test policy\"]",
            e.id()
        )],
        "{oks:?}"
    );
    assert!(event_frames(&watcher.sent(), "w").is_empty());
    msg(
        &mut r,
        1,
        &req_frame("s", &json!({"authors": [pubkey_of(1)]})),
    );
    assert!(event_frames(&socket.sent(), "s").is_empty());
}

/// An empty `msg` gets the native NIP-01 default.
#[test]
fn policy_reject_empty_msg_gets_the_default() {
    let exec = Connection::open_in_memory().unwrap();
    let mut r = relay_with_policy(exec, "", vec![], true);
    let socket = connect(&mut r, 1);
    let e = event(&key(1), 1, NOW, &json!([]), "empty");
    let check = r
        .message(1, NOW * 1000, &event_frame(&e))
        .policy
        .expect("a policy-enabled relay pauses");
    let _ = r.decided(
        1,
        &check.event,
        nosfry_core::policy::Decision::Reject(String::new()),
        NOW * 1000,
    );
    let oks = ok_frames(&socket.sent());
    assert_eq!(
        oks,
        [format!(
            "[\"OK\",\"{}\",false,\"blocked: rejected by write policy\"]",
            e.id()
        )],
        "{oks:?}"
    );
}

/// `shadowReject` answers `OK true` yet stores and broadcasts
/// nothing.
#[test]
fn policy_shadow_reject_acknowledges_without_storing() {
    let exec = Connection::open_in_memory().unwrap();
    let mut r = relay_with_policy(exec, "", vec![], true);
    let socket = connect(&mut r, 1);
    let watcher = connect(&mut r, 2);
    msg(&mut r, 2, &req_frame("w", &json!({"kinds": [1]})));
    let e = event(&key(1), 1, NOW, &json!([]), "shadowed");
    let check = r
        .message(1, NOW * 1000, &event_frame(&e))
        .policy
        .expect("a policy-enabled relay pauses");
    let _ = r.decided(
        1,
        &check.event,
        nosfry_core::policy::Decision::ShadowReject("shadowed".into()),
        NOW * 1000,
    );
    let oks = ok_frames(&socket.sent());
    assert_eq!(
        oks,
        [format!("[\"OK\",\"{}\",true,\"shadowed\"]", e.id())],
        "{oks:?}"
    );
    assert!(event_frames(&watcher.sent(), "w").is_empty());
    msg(
        &mut r,
        1,
        &req_frame("s", &json!({"authors": [pubkey_of(1)]})),
    );
    assert!(event_frames(&socket.sent(), "s").is_empty());
}

/// NIP-62: a request to vanish naming this relay bypasses the
/// policy, exactly like native.
#[test]
fn policy_does_not_gate_vanish_requests() {
    let exec = Connection::open_in_memory().unwrap();
    let config = "[relay]\nservice_url = \"wss://relay.example.com\"\n";
    let mut r = relay_with_policy(exec, config, vec![], true);
    let socket = connect(&mut r, 1);
    let e = event(
        &key(1),
        62,
        NOW,
        &json!([["relay", "wss://relay.example.com"]]),
        "",
    );
    let effects = r.message(1, NOW * 1000, &event_frame(&e));
    assert!(effects.policy.is_none(), "vanish bypasses the policy");
    let oks = ok_frames(&socket.sent());
    assert_eq!(
        oks,
        [format!("[\"OK\",\"{}\",true,\"\"]", e.id())],
        "{oks:?}"
    );
    assert!(effects.vanish, "the vanish request queues the sweep");
}

/// The NIP-86 gate runs before the policy: a banned author's event
/// is refused without ever reaching the policy point.
#[test]
fn policy_runs_after_moderation() {
    let config = admin_config();
    let exec = Connection::open_in_memory().unwrap();
    let mut r = relay_with_policy(exec, &config, vec![], true);
    let socket = connect(&mut r, 1);
    // Ban key(1) through the management snapshot.
    let (_, body) = rpc(
        &mut r,
        9,
        &json!({"method": "banpubkey", "params": [pubkey_of(1)]}),
    );
    assert_eq!(body["result"], true, "{body}");
    let e = event(&key(1), 1, NOW, &json!([]), "banned");
    let effects = r.message(1, NOW * 1000, &event_frame(&e));
    assert!(effects.policy.is_none(), "moderation wins first");
    let oks = ok_frames(&socket.sent());
    assert_eq!(
        oks,
        [format!(
            "[\"OK\",\"{}\",false,\"blocked: pubkey not allowed\"]",
            e.id()
        )],
        "{oks:?}"
    );
}

/// A verdict that arrives after the publishing connection closed
/// still applies an `Accept`: the event is written and delivered,
/// only the `OK` is skipped.
#[test]
fn policy_accept_survives_a_lost_connection() {
    let exec = Connection::open_in_memory().unwrap();
    let mut r = relay_with_policy(exec, "", vec![], true);
    let socket = connect(&mut r, 1);
    let watcher = connect(&mut r, 2);
    msg(&mut r, 2, &req_frame("w", &json!({"kinds": [1]})));
    let e = event(&key(1), 1, NOW, &json!([]), "late verdict");
    let check = r
        .message(1, NOW * 1000, &event_frame(&e))
        .policy
        .expect("a policy-enabled relay pauses");
    r.close(1);
    let _ = r.decided(
        1,
        &check.event,
        nosfry_core::policy::Decision::Accept,
        NOW * 1000,
    );
    assert!(socket.sent().is_empty(), "no OK on a dead connection");
    let hits = event_frames(&watcher.sent(), "w");
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].contains("late verdict"));
    msg(
        &mut r,
        2,
        &req_frame("s", &json!({"authors": [pubkey_of(1)]})),
    );
    assert!(
        event_frames(&watcher.sent(), "s")
            .iter()
            .any(|f| f.contains("late verdict")),
        "{:?}",
        watcher.sent()
    );
}

/// `[worker] max_subscription_bytes`: a REQ that would push the
/// charged `approx_bytes` total over the budget is refused
/// `blocked:` and registers nothing.
#[test]
fn subscription_byte_budget_refuses_over_capacity() {
    let mut r = relay("[worker]\nmax_subscription_bytes = 1\n");
    let socket = connect(&mut r, 1);
    msg(&mut r, 1, &req_frame("s", &json!({"kinds": [1]})));
    assert_eq!(
        socket.sent().last().unwrap(),
        "[\"CLOSED\",\"s\",\"blocked: subscription capacity exhausted\"]"
    );
    // The sub was never registered: a matching event reaches nobody.
    let ev = event(&key(1), 1, NOW, &json!([]), "x");
    msg(&mut r, 1, &event_frame(&ev));
    assert!(event_frames(&socket.sent(), "s").is_empty());
}

/// CLOSE and connection close release a subscription's charge.
#[test]
fn subscription_byte_budget_releases() {
    // The `approx_bytes` charge of one `{"kinds":[1]}` REQ.
    let bytes = Filter::parse("{\"kinds\":[1]}").unwrap().approx_bytes();
    let config = format!("[worker]\nmax_subscription_bytes = {bytes}\n");
    let mut r = relay(&config);
    let a = connect(&mut r, 1);
    msg(&mut r, 1, &req_frame("s", &json!({"kinds": [1]})));
    msg(&mut r, 1, &req_frame("t", &json!({"kinds": [1]})));
    assert!(
        a.sent()
            .iter()
            .any(|f| f == "[\"CLOSED\",\"t\",\"blocked: subscription capacity exhausted\"]"),
        "{:?}",
        a.sent()
    );
    // CLOSE frees the budget: the same REQ is now admitted.
    msg(&mut r, 1, "[\"CLOSE\",\"s\"]");
    msg(&mut r, 1, &req_frame("t", &json!({"kinds": [1]})));
    assert!(a.sent().iter().any(|f| f == "[\"EOSE\",\"t\"]"));
    // A closed connection frees its whole charge.
    r.close(1);
    let b = connect(&mut r, 2);
    msg(&mut r, 2, &req_frame("u", &json!({"kinds": [1]})));
    msg(&mut r, 2, &req_frame("v", &json!({"kinds": [1]})));
    assert!(b.sent().iter().any(|f| f == "[\"EOSE\",\"u\"]"));
    assert!(
        b.sent()
            .iter()
            .any(|f| f == "[\"CLOSED\",\"v\",\"blocked: subscription capacity exhausted\"]"),
        "{:?}",
        b.sent()
    );
}

/// An executor counting the rows the `subs` restore SELECT streams.
#[derive(Debug)]
struct SubsCounting {
    conn: Connection,
    rows: std::cell::Cell<usize>,
}

impl Executor for SubsCounting {
    type Error = <Connection as Executor>::Error;

    fn query(
        &self,
        sql: &str,
        params: &[Param<'_>],
        row: &mut dyn FnMut(Vec<Value>) -> ControlFlow<()>,
    ) -> Result<(), Self::Error> {
        if sql.starts_with("SELECT conn, sub_id, filters, authed FROM subs") {
            return self.conn.query(sql, params, &mut |values| {
                self.rows.set(self.rows.get() + 1);
                row(values)
            });
        }
        self.conn.query(sql, params, row)
    }

    fn execute(&self, sql: &str, params: &[Param<'_>]) -> Result<(), Self::Error> {
        self.conn.execute(sql, params)
    }

    fn transaction<T>(&self, f: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
        self.conn.transaction(f)
    }
}

/// Dead connections' rows are deleted in one statement before the
/// restore SELECT runs — they never reach the row callback, however
/// corrupt their payload.
#[test]
fn restore_deletes_stale_subs_without_loading_them() {
    let exec = Connection::open_in_memory().unwrap();
    let socket = FakeSocket::default();
    // A dropped relay strands `subs` rows.
    let (att, exec) = {
        let mut r = relay_on(exec, "", vec![]);
        let att = r.accept(socket.clone(), 1, None, "c".into()).unwrap();
        msg(&mut r, 1, &req_frame("s", &json!({"kinds": [1]})));
        (att, r.into_store().into_exec())
    };
    // Two rows for dead connections, one with filters that would
    // fail to decode if it were ever read.
    exec.execute(
        "INSERT INTO subs (conn, sub_id, filters, authed) VALUES (9, 'x', 'not json', 0)",
        &[],
    )
    .unwrap();
    exec.execute(
        "INSERT INTO subs (conn, sub_id, filters, authed) VALUES (8, 'y', '[{\"kinds\":[1]}]', 0)",
        &[],
    )
    .unwrap();

    let counting = SubsCounting {
        conn: exec,
        rows: std::cell::Cell::new(0),
    };
    let r = Relay::open(
        SqlStore::open(counting).unwrap(),
        Config::parse("").unwrap(),
        vec![(socket, att)],
        false,
    )
    .unwrap();
    // Only the live connection's row was ever streamed; both stale
    // rows were deleted by the sweep before it.
    assert_eq!(r.restored(), (1, 1, 2));
    let exec = r.into_store().into_exec();
    assert_eq!(exec.rows.get(), 1, "the SELECT streamed only live rows");
    let mut count = 0u64;
    exec.query("SELECT COUNT(*) FROM subs", &[], &mut |row| {
        if let Some(Value::Int(v)) = row.first() {
            count = u64::try_from(*v).unwrap();
        }
        ControlFlow::Continue(())
    })
    .unwrap();
    assert_eq!(count, 1);
}

/// Restore charges the same `[worker] max_subscription_bytes`
/// budget: rows over it are deleted, not restored.
#[test]
fn restore_honors_the_subscription_byte_budget() {
    let bytes = Filter::parse("{\"kinds\":[1]}").unwrap().approx_bytes();
    let socket = FakeSocket::default();
    let (att, exec) = {
        let mut r = relay("[relay]\nservice_url = \"wss://x\"\n");
        let att = r.accept(socket.clone(), 1, None, "c".into()).unwrap();
        msg(&mut r, 1, &req_frame("a", &json!({"kinds": [1]})));
        msg(&mut r, 1, &req_frame("b", &json!({"kinds": [1]})));
        (att, r.into_store().into_exec())
    };
    // PK order streams "a" before "b"; the budget fits one row.
    let config = format!("[worker]\nmax_subscription_bytes = {bytes}\n");
    let mut r = relay_on(exec, &config, vec![(socket.clone(), att)]);
    let ev = event(&key(1), 1, NOW + 1, &json!([]), "y");
    msg(&mut r, 1, &event_frame(&ev));
    assert_eq!(
        event_frames(&socket.sent(), "a").len(),
        1,
        "{:?}",
        socket.sent()
    );
    assert!(
        event_frames(&socket.sent(), "b").is_empty(),
        "{:?}",
        socket.sent()
    );
    // The over-budget row was deleted, not just skipped.
    let exec = r.into_store().into_exec();
    let mut count = 0u64;
    exec.query("SELECT COUNT(*) FROM subs", &[], &mut |row| {
        if let Some(Value::Int(v)) = row.first() {
            count = u64::try_from(*v).unwrap();
        }
        ControlFlow::Continue(())
    })
    .unwrap();
    assert_eq!(count, 1);
}

/// `[relay.filter_validation]`: a REQ violating the rules answers
/// `CLOSED blocked:` and registers nothing — the same id still opens
/// a valid subscription.
#[test]
fn filter_validation_refuses_req() {
    let mut r = relay("[relay.filter_validation]\nenabled = true\n");
    let socket = connect(&mut r, 1);
    msg(&mut r, 1, "[\"REQ\",\"s\",{},{},{},{}]");
    assert_eq!(
        socket.sent().last().unwrap(),
        "[\"CLOSED\",\"s\",\"blocked: invalid number of filters: 4\"]"
    );
    msg(&mut r, 1, &req_frame("s", &json!({"kinds": [1]})));
    assert!(
        socket.sent().iter().any(|f| f == "[\"EOSE\",\"s\"]"),
        "{:?}",
        socket.sent()
    );
}

/// `Config::parse` refuses contradictory filter-validation bounds
/// when enabled, naming the offending key.
#[test]
fn filter_validation_config_rejects_bad_bounds() {
    for config in [
        "[relay.filter_validation]\nenabled = true\nmax_filters_per_req = 0\n",
        "[relay.filter_validation]\nenabled = true\nmin_filters_per_req = 4\n",
    ] {
        assert!(
            matches!(
                Config::parse(config),
                Err(nosfry_worker::ConfigError::FilterValidation(_))
            ),
            "{config}"
        );
    }
}

/// `AddressKey` groups IPv6 by /64 (native parity): two addresses in
/// one /64 share the per-IP cap and the `ip_*` rate buckets.
#[test]
fn admits_groups_ipv6_by_64() {
    let mut r = relay("[relay]\nmax_connections_per_ip = 1\n");
    let socket = FakeSocket::default();
    r.accept(socket, 1, Some("2001:db8::1".parse().unwrap()), "c".into())
        .unwrap();
    assert!(!r.admits(Some("2001:db8::ffff:abcd".parse().unwrap())));
    assert!(r.admits(Some("2001:db8:0:1::1".parse().unwrap())));
    assert!(r.admits(Some("10.0.0.7".parse().unwrap())));
}

#[test]
fn ip_buckets_are_shared_within_64() {
    let mut r =
        relay("[relay]\n[relay.rate_limits]\nip_events_per_second = 1\nip_events_burst = 1\n");
    let a = FakeSocket::default();
    let b = FakeSocket::default();
    r.accept(a, 1, Some("2001:db8::1".parse().unwrap()), "c".into())
        .unwrap();
    r.accept(
        b.clone(),
        2,
        Some("2001:db8::99".parse().unwrap()),
        "c".into(),
    )
    .unwrap();
    // The first event drains the shared bucket; the other address in
    // the same /64 is refused on the same bucket.
    msg(
        &mut r,
        1,
        &event_frame(&event(&key(1), 1, NOW, &json!([]), "one")),
    );
    msg(
        &mut r,
        2,
        &event_frame(&event(&key(1), 1, NOW + 1, &json!([]), "two")),
    );
    assert!(
        b.sent()
            .iter()
            .any(|f| f.contains("rate-limited: slow down")),
        "{:?}",
        b.sent()
    );
}
