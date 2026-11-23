#![no_main]

//! `blossom::range::parse` on an arbitrary `u64` length + header —
//! must never panic, and a `Partial` outcome must name a real slice.

use libfuzzer_sys::fuzz_target;
use nosfry_blossom::range::{self, Range};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let len = u64::from_le_bytes(data[..8].try_into().unwrap_or_default());
    let header = std::str::from_utf8(&data[8..]).ok();
    if let Range::Partial {
        start,
        end_inclusive,
    } = range::parse(header, len)
    {
        assert!(len > 0, "partial range of an empty body");
        assert!(start <= end_inclusive, "{start} > {end_inclusive}");
        assert!(end_inclusive < len, "{end_inclusive} past {len}");
    }
});
