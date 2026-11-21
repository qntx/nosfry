//! `nosfry` — sans-IO Nostr relay protocol core.
//!
//! Strict NIP-01 ingest (events, filters, client messages), a
//! strfry-style packed index record, the compiled-filter matcher, a
//! per-connection session state machine and the live-subscription inverted
//! index. No async, no I/O, no system clock (time arrives as `now: u64` unix
//! seconds), no randomness; the crate builds for `wasm32-unknown-unknown`.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        unused_crate_dependencies,
        reason = "dev-deps are exercised by integration tests"
    )
)]

mod hex;

pub mod auth;
pub mod deletion;
pub mod event;
pub mod filter;
pub mod hll;
pub mod info;
pub mod kind;
pub mod limits;
pub mod management;
pub mod message;
pub mod moderation;
pub mod monitor;
pub mod packed;
pub mod policy;
pub mod session;
#[cfg(feature = "test-util")]
pub mod sign;
pub mod site;
pub mod state;
pub mod store;
pub mod sync;
pub mod url;
