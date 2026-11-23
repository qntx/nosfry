#![no_main]

//! `blossom::auth::authorize` on arbitrary header text for every
//! Verb, with and without an implied blob hash — must never panic.
//! When it succeeds, the token's pubkey must be the decoded event's
//! `pubkey` field (checked independently here).

use libfuzzer_sys::fuzz_target;
use nosfry_blossom::Hash;
use nosfry_blossom::auth::{self, Verb};

/// Decode either base64 alphabet (standard or URL-safe), padded or
/// not; `None` on any non-alphabet byte.
fn b64(input: &str) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for byte in input.trim().bytes() {
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// The event's `pubkey` decoded straight from the header payload —
/// independent of `authorize`'s own path.
fn event_pubkey(header: &str) -> Option<[u8; 32]> {
    let (_, payload) = header.split_once(|c: char| c.is_ascii_whitespace())?;
    let bytes = b64(payload.trim())?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let json: serde_json::Value = serde_json::from_str(text).ok()?;
    let hex = json.get("pubkey")?.as_str()?;
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    faster_hex::hex_decode(hex.as_bytes(), &mut key).ok()?;
    Some(key)
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let fixed = Hash([0x42; 32]);
    for verb in [Verb::Get, Verb::Upload, Verb::List, Verb::Delete] {
        for hash in [None, Some(&fixed)] {
            if let Ok(token) =
                auth::authorize(Some(text), verb, 1_700_000_000, "example.com", hash)
            {
                assert_eq!(
                    token.pubkey.0,
                    event_pubkey(text).expect("authorized token without a pubkey")
                );
            }
        }
    }
});
