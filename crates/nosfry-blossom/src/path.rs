//! Request-path parsing: `/<sha256>[.<ext>]`, `/list/<pubkey>`, and
//! the [`struct@Hash`] newtype. No I/O.

use core::fmt;

/// Decode exactly 64 lowercase hex chars into 32 bytes; uppercase
/// and non-hex are rejected (the caller maps that to a 400, like
/// every other malformed hash).
fn decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 32];
    faster_hex::hex_decode(s.as_bytes(), &mut out).ok()?;
    Some(out)
}

/// A 32-byte blob id (SHA-256). `Display` is lowercase hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Parse a 64-char lowercase hex digest; uppercase is rejected.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        decode_32(s).map(Self)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&faster_hex::hex_string(&self.0))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A parsed `/<sha256>[.<ext>]` endpoint path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobPath<'a> {
    /// A well-formed `/<sha256>` or `/<sha256>.<ext>`.
    Blob(Hash, Option<&'a str>),
    /// The segment begins with a hash-shaped (64 ASCII hex digit)
    /// prefix but is malformed — an uppercase digit, a missing or
    /// over-long extension, a stray suffix. The answer is 400.
    Malformed,
    /// Not a blob path at all. The answer is 404.
    Other,
}

/// The `…` in `/<sha256>[.…]` is 1–32 chars of `[A-Za-z0-9._-]`.
fn is_extension(ext: &str) -> bool {
    (1..=32).contains(&ext.len())
        && ext
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Parse one request-path segment as `/<sha256>[.<ext>]`.
#[must_use]
pub fn parse_blob_path(segment: &str) -> BlobPath<'_> {
    let (head, ext) = match segment.split_once('.') {
        Some((head, ext)) => (head, Some(ext)),
        None => (segment, None),
    };
    if head.len() == 64 && head.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Some(hash) = Hash::from_hex(head)
            && ext.is_none_or(is_extension)
        {
            return BlobPath::Blob(hash, ext);
        }
        return BlobPath::Malformed;
    }
    // A longer segment starting with 64 hex digits is a malformed
    // blob path too (`<sha256><junk>`, `<sha256>.<bad ext>`).
    if segment.len() > 64
        && let (first, _) = segment.split_at(64)
        && first.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return BlobPath::Malformed;
    }
    BlobPath::Other
}

/// Parse the `<pubkey>` of `/list/<pubkey>`; the answer on failure is
/// always 400 (the path shape named the list endpoint).
#[must_use]
pub fn parse_list_pubkey(segment: &str) -> Option<Hash> {
    Hash::from_hex(segment)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use super::*;

    const HEX: &str = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";

    /// `Hash::from_hex` takes exactly 64 lowercase hex digits.
    #[test]
    fn hash_from_hex() {
        assert!(Hash::from_hex(HEX).is_some());
        assert!(Hash::from_hex(&HEX.to_ascii_uppercase()).is_none());
        assert_eq!(Hash::from_hex(&HEX[..63]), None);
        assert_eq!(Hash::from_hex(&format!("{HEX}0")), None);
        assert_eq!(Hash::from_hex(&HEX.replace('b', "zz")), None);
        assert!(Hash::from_hex("").is_none());
        assert_eq!(Hash::from_hex(HEX).unwrap().to_string(), HEX);
    }

    /// The path shapes and their classification.
    #[test]
    fn blob_path() {
        let hash = Hash::from_hex(HEX).unwrap();
        assert_eq!(parse_blob_path(HEX), BlobPath::Blob(hash, None));
        assert_eq!(
            parse_blob_path(&format!("{HEX}.png")),
            BlobPath::Blob(hash, Some("png"))
        );
        assert_eq!(
            parse_blob_path(&format!("{HEX}.tar.gz")),
            BlobPath::Blob(hash, Some("tar.gz"))
        );
        // `.` is an allowed extension character, so a double dot
        // parses as extension ".png".
        assert_eq!(
            parse_blob_path(&format!("{HEX}..png")),
            BlobPath::Blob(hash, Some(".png"))
        );
        let long_ext = "x".repeat(32);
        assert_eq!(
            parse_blob_path(&format!("{HEX}.{long_ext}")),
            BlobPath::Blob(hash, Some(long_ext.as_str()))
        );
        // Hex-prefixed but malformed → 400.
        for bad in [
            HEX.to_ascii_uppercase(),
            format!("{HEX}."),
            format!("{HEX}.has space"),
            format!("{HEX}.{}", "x".repeat(33)),
            format!("{HEX}junk"),
            format!("{HEX}.png!"),
        ] {
            assert_eq!(
                parse_blob_path(&bad),
                BlobPath::Malformed,
                "{bad} must be malformed"
            );
        }
        // Not hash-shaped at all → 404.
        for other in [
            "favicon.ico",
            "upload",
            "list",
            "abc",
            &HEX[..63],
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.png",
        ] {
            assert_eq!(
                parse_blob_path(other),
                BlobPath::Other,
                "{other} must be Other"
            );
        }
    }

    /// `/list/<pubkey>` takes 64 lowercase hex and nothing else.
    #[test]
    fn list_pubkey() {
        assert_eq!(parse_list_pubkey(HEX), Hash::from_hex(HEX));
        assert_eq!(parse_list_pubkey(&HEX.to_ascii_uppercase()), None);
        assert_eq!(parse_list_pubkey(&format!("{HEX}.png")), None);
        assert_eq!(parse_list_pubkey("abc"), None);
    }
}
