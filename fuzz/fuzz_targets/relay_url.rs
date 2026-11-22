#![no_main]

//! `RelayUrl::parse`/`matches` round-trip: a parsed URL matches its
//! input, and re-parsing its normalized host yields an equal URL.
//! The input is then split into a few lines: the first is the
//! canonical service URL, the rest aliases — `RelayNames::parse`
//! output must `matches` every name it accepted.

use libfuzzer_sys::fuzz_target;
use nosfry_core::url::{RelayNames, RelayUrl};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(url) = RelayUrl::parse(text) {
        assert!(url.matches(text), "parsed URL does not match its input");
        let normalized = format!("wss://{}", url.host());
        let again = RelayUrl::parse(&normalized).expect("normalized host must reparse");
        assert_eq!(url, again, "normalized form not a fixed point");
        assert!(again.matches(url.host()), "normalized URL must match");
    }
    let mut lines = text.split('\n').take(5);
    let service_url = lines.next().unwrap_or_default();
    let aliases: Vec<String> = lines.map(str::to_owned).collect();
    let Ok(names) = RelayNames::parse(service_url, &aliases) else {
        return;
    };
    assert_eq!(
        names.canonical().is_some(),
        !names.is_empty(),
        "non-empty names must have a canonical URL"
    );
    for name in std::iter::once(service_url).chain(aliases.iter().map(String::as_str)) {
        if !name.is_empty() {
            assert!(names.matches(name), "names do not match input {name:?}");
        }
    }
});
