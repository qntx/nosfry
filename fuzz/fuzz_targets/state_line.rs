#![no_main]

//! Parse arbitrary text as a `nosfry_state` export line; a record
//! that parses must re-serialize and re-parse to an equal record.

use libfuzzer_sys::fuzz_target;
use nosfry_core::state::{parse_state_line, state_line};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(Some(record)) = parse_state_line(text) else {
        return;
    };
    let line = state_line(&record).expect("a parsed record always serializes");
    assert_eq!(parse_state_line(&line), Ok(Some(record)), "{line}");
});
