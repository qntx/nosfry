#![no_main]

//! `Filter::parse` then `to_json` must reparse to an equal filter,
//! and `to_json` must be a fixed point (hibernation restore relies
//! on it).

use libfuzzer_sys::fuzz_target;
use nosfry_core::filter::Filter;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(filter) = Filter::parse(text) else {
        return;
    };
    let json = filter.to_json();
    let reparsed = Filter::parse(&json).unwrap_or_else(|e| panic!("reparse failed: {e} ({json})"));
    assert_eq!(filter, reparsed, "roundtrip mismatch ({json})");
    let json2 = reparsed.to_json();
    assert_eq!(json, json2, "to_json is not idempotent");
});
