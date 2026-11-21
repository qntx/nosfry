//! Worker TOML configuration: defaults, unknown keys, and the
//! limits the session itself enforces.

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
    clippy::panic,
    clippy::assert_is_empty,
    reason = "tests may panic on failure"
)]

use nosfry_worker::Config;

#[test]
fn defaults() {
    let config = Config::parse("").unwrap();
    assert_eq!(config.relay.max_websocket_payload_size, 131_072);
    assert_eq!(config.relay.max_connections, 5_000);
    assert_eq!(config.relay.max_connections_per_ip, 128);
    assert_eq!(config.worker.max_scan_rows, 100_000);
    assert!(config.relay.service_url.is_empty());
    assert!(config.worker.location_hint.is_empty());
}

/// `relay.max_websocket_payload_size` must carry the largest
/// allowed EVENT frame (`events.max_event_size + 10`) — the same
/// refusal native applies at load and reload.
#[test]
fn payload_must_fit_one_event_frame() {
    let err = Config::parse(
        "[events]\nmax_event_size = 100\n[relay]\nmax_websocket_payload_size = 109\n",
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("relay.max_websocket_payload_size (109) must be at least events.max_event_size + 10 (110)"),
        "{err}"
    );
    Config::parse("[events]\nmax_event_size = 100\n[relay]\nmax_websocket_payload_size = 110\n")
        .expect("boundary pair parses");
}

#[test]
fn unknown_keys_are_rejected() {
    // A native-only key must fail rather than be ignored.
    assert!(Config::parse("[relay]\nbind = \"0.0.0.0\"\n").is_err());
    assert!(Config::parse("[db]\n").is_err());
    assert!(Config::parse("[worker]\nthreads = 4\n").is_err());
}

#[test]
fn limits_pass_sync_and_count_through() {
    let config = Config::parse("").unwrap();
    let limits = config.limits().unwrap();
    let defaults = nosfry_core::limits::ReqLimits::default();
    assert_eq!(
        limits.req.max_filter_limit_count,
        defaults.max_filter_limit_count
    );
    assert_eq!(limits.req.max_sync_events, defaults.max_sync_events);
    assert_eq!(limits.req.max_filter_limit, defaults.max_filter_limit);
    let tuned = Config::parse(
        "[relay.limits]
max_sync_events = 7
",
    )
    .unwrap();
    assert_eq!(tuned.limits().unwrap().req.max_sync_events, 7);
}

#[test]
fn max_scan_rows_must_be_positive() {
    // A zero budget would make every REQ and COUNT return nothing.
    let err = Config::parse("[worker]\nmax_scan_rows = 0\n").unwrap_err();
    assert!(err.to_string().contains("max_scan_rows"), "got: {err}");
    assert!(Config::parse("[worker]\nmax_scan_rows = 1\n").is_ok());
}

#[test]
fn service_url_is_validated() {
    assert!(Config::parse("[relay]\nservice_url = \"http://nope\"\n").is_err());
    let config = Config::parse("[relay]\nservice_url = \"wss://relay.example.com\"\n").unwrap();
    assert!(config.limits().unwrap().auth.enabled());
    // An empty service URL means no AUTH.
    assert!(!Config::parse("").unwrap().limits().unwrap().auth.enabled());
}

#[test]
fn management_admins_are_validated() {
    let err = Config::parse("[relay.management]\nadmins = [\"not-hex\"]\n").unwrap_err();
    assert!(err.to_string().contains("admins"), "got: {err}");
    let admin = nosfry_core::sign::pubkey_hex(0);
    assert!(Config::parse(&format!("[relay.management]\nadmins = [\"{admin}\"]\n")).is_ok());
}
