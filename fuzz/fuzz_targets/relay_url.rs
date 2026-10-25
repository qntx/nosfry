#![no_main]

//! `RelayUrl::parse`/`matches` round-trip: a parsed URL matches its
//! input, and re-parsing its normalized host yields an equal URL.

use libfuzzer_sys::fuzz_target;
use nosfry_core::url::RelayUrl;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(url) = RelayUrl::parse(text) else {
        return;
    };
    assert!(url.matches(text), "parsed URL does not match its input");
    let normalized = format!("wss://{}", url.host());
    let again = RelayUrl::parse(&normalized).expect("normalized host must reparse");
    assert_eq!(url, again, "normalized form not a fixed point");
    assert!(again.matches(url.host()), "normalized URL must match");
});
