#![no_main]

//! Relay-side frame parsing: `RelayMessage::parse` over arbitrary
//! UTF-8 text, `PeerLimits::parse` over raw bytes, then the limit
//! helpers on whatever limits parsed.

use libfuzzer_sys::fuzz_target;
use nosfry_core::client::{PeerLimits, RelayMessage, ids_per_req, neg_frame_limit};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = RelayMessage::parse(text);
    }
    if let Some(limits) = PeerLimits::parse(data) {
        assert!(ids_per_req(&limits) >= 1, "ids_per_req must never be 0");
        if let Ok(frame) = neg_frame_limit(limits.max_message_length) {
            assert!(
                (4096..=500_000).contains(&frame),
                "frame limit {frame} outside bounds"
            );
        }
    }
});
