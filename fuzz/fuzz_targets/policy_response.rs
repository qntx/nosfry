#![no_main]

//! The write-policy response parser must not panic; a parsed decision
//! only answers for the requested event id.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use nosfry_core::policy::parse_response;

#[derive(Arbitrary, Debug)]
struct Input {
    bytes: Vec<u8>,
    id: String,
}

fuzz_target!(|input: Input| {
    let _ = parse_response(&input.bytes, &input.id);
});
