//! Hex helpers shared by event and filter validation.
//!
//! Event ids/pubkeys/signatures, `e`/`p` tag values, and filter
//! `ids`/`authors`/`#e`/`#p` values are all exact lowercase hex
//! (NIP-01); [`decode_list`] alone stays case-insensitive for
//! NIP-77 negentropy payloads.

/// `true` when `s` is exactly `len` chars of `[0-9a-f]`.
pub(crate) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `true` when `s` is exactly `len` chars of `[0-9a-fA-F]`.
pub(crate) fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Decode a 64-char lowercase hex string into 32 bytes.
pub(crate) fn decode_32(s: &str) -> Option<[u8; 32]> {
    if !is_lower_hex(s, 64) {
        return None;
    }
    let mut out = [0u8; 32];
    faster_hex::hex_decode(s.as_bytes(), &mut out).ok()?;
    Some(out)
}

/// Decode a 128-char lowercase hex string into 64 bytes.
pub(crate) fn decode_64(s: &str) -> Option<[u8; 64]> {
    if !is_lower_hex(s, 128) {
        return None;
    }
    let mut out = [0u8; 64];
    faster_hex::hex_decode(s.as_bytes(), &mut out).ok()?;
    Some(out)
}

/// Lowercase hex string.
pub(crate) fn encode(bytes: &[u8]) -> String {
    faster_hex::hex_string(bytes)
}

/// Decode a non-empty, even-length hex string of either case into bytes.
pub(crate) fn decode_list(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !is_hex(s, s.len()) {
        return None;
    }
    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).ok()?;
    Some(out)
}
