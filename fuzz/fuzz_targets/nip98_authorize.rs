#![no_main]

//! `management::authorize` on arbitrary headers/bodies plus a
//! structurally valid `Nostr <base64>` header — no panic.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use nosfry_core::event::PublicKey;
use nosfry_core::event::EventLimits;
use nosfry_core::management::authorize;
use nosfry_core::url::RelayUrl;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Minimal RFC-4648 encoder for fuzz inputs.
fn b64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b))
            << (8 * (3 - chunk.len()));
        for i in 0..4 {
            let idx = ((n >> (18 - 6 * i)) & 63) as usize;
            out.push(if i < chunk.len() + 1 { B64[idx] as char } else { '=' });
        }
    }
    out
}

#[derive(Arbitrary, Debug)]
struct Input {
    header: Option<String>,
    body: Vec<u8>,
    now: u64,
    /// Structured header material.
    ev_id: [u8; 32],
    ev_pubkey: [u8; 32],
    ev_created: u64,
    ev_sig: [u8; 64],
}

fuzz_target!(|input: Input| {
    let url = RelayUrl::parse("wss://fuzz.example").unwrap();
    let admin = PublicKey(input.ev_pubkey);
    // Path A: arbitrary header text.
    let _ = authorize(
        input.header.as_deref(),
        &input.body,
        input.now,
        &EventLimits::default(),
        Some(&url),
        std::slice::from_ref(&admin),
    );
    // Path B: structurally valid `Nostr <base64>` header.
    let json = format!(
        "{{\"id\":\"{}\",\"pubkey\":\"{}\",\"created_at\":{},\"kind\":27235,\"tags\":[[\"u\",\"wss://fuzz.example\"],[\"method\",\"POST\"]],\"content\":\"\",\"sig\":\"{}\"}}",
        faster_hex::hex_string(&input.ev_id),
        faster_hex::hex_string(&input.ev_pubkey),
        input.ev_created,
        faster_hex::hex_string(&input.ev_sig),
    );
    let header = format!("Nostr {}", b64(json.as_bytes()));
    let _ = authorize(
        Some(&header),
        &input.body,
        input.now,
        &EventLimits::default(),
        Some(&url),
        std::slice::from_ref(&admin),
    );
});
