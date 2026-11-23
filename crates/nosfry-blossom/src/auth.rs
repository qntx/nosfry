//! BUD-11 authorization: the `Authorization: Nostr <base64>`
//! scheme carrying a signed NIP-01 event of kind 24242, and the
//! validation chain a server runs on it.
//!
//! Replay window: a token is usable exactly in
//! `[created_at - CLOCK_SKEW_SECONDS, expiration)`. There is no
//! single-use cache — tokens are reusable by design (client SDKs
//! cache them for their whole validity), and the `t`/`x`/`server`
//! scoping bounds what a leaked token can do. `content` is *not*
//! required to be non-empty: BUD-11's server validation list has no
//! content rule and blossom-client-sdk sends `""` by default.
//!
//! Base64: BUD-11 mandates "Base64 URL-safe without padding", but
//! Amethyst ships padded standard base64 (amethyst#4127) and the
//! spec owner supports loosening it (blossom issue #113, PR #114
//! open as of 2026-11-23) — so both alphabets are accepted, padded
//! or unpadded; a payload mixing the two alphabets still fails.

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::{DecodePaddingMode, Engine};
use nosfry_core::event::{EventLimits, PublicKey, UnverifiedEvent};

use crate::path::Hash;

/// The authorization event kind (BUD-11).
pub const KIND: u16 = 24242;

/// Tolerated client clock lead on `created_at`, in seconds.
pub const CLOCK_SKEW_SECONDS: u64 = 60;

/// Raw `Authorization` header value cap, checked before decoding.
pub const MAX_HEADER_BYTES: usize = 96 * 1024;

/// The `t`-tag verbs the endpoints require. `"media"` (BUD-08) is
/// unsupported: it never matches a [`Verb`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// `GET`/`HEAD /<sha256>` (`t=get`).
    Get,
    /// `PUT /upload`, `PUT /<sha256>`, `HEAD /upload` (`t=upload`).
    Upload,
    /// `GET /list/<pubkey>` (`t=list`).
    List,
    /// `DELETE /<sha256>` (`t=delete`).
    Delete,
}

impl Verb {
    /// The `t` tag value.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Upload => "upload",
            Self::List => "list",
            Self::Delete => "delete",
        }
    }
}

/// A token that passed [`authorize`]: the signer's pubkey plus every
/// *valid* `x` tag hash (malformed `x` values are ignored, never
/// counted).
#[derive(Debug, PartialEq, Eq)]
pub struct Token {
    /// The event's `pubkey` — the identity every check runs against.
    pub pubkey: PublicKey,
    /// The valid 64-lowercase-hex `x` tags.
    hashes: Vec<Hash>,
}

impl Token {
    /// Whether `hash` is covered by a valid `x` tag.
    #[must_use]
    pub fn covers(&self, hash: &Hash) -> bool {
        self.hashes.contains(hash)
    }

    /// Whether the token carries at least one valid `x` tag.
    #[must_use]
    pub const fn has_hashes(&self) -> bool {
        !self.hashes.is_empty()
    }

    /// The first valid `x` tag hash — the client's declared upload
    /// target for `PUT /upload` when neither the path nor
    /// `X-SHA-256` names a hash.
    #[must_use]
    pub fn first(&self) -> Option<Hash> {
        self.hashes.first().copied()
    }
}

/// One authorization failure; the `Display` text is a short
/// human-readable reason served verbatim in `X-Reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No `Authorization` header.
    #[error("missing authorization")]
    Missing,
    /// The scheme is not `Nostr` or credentials are absent.
    #[error("authorization scheme must be Nostr")]
    Scheme,
    /// The raw header value exceeds [`MAX_HEADER_BYTES`].
    #[error("authorization header too large")]
    TooLarge,
    /// The payload is not decodable base64 (either alphabet).
    #[error("invalid base64 in authorization")]
    Base64,
    /// The decoded payload is not UTF-8.
    #[error("authorization event is not utf-8")]
    Utf8,
    /// The decoded text does not parse as a NIP-01 event.
    #[error("invalid authorization event")]
    Invalid,
    /// `kind` is not 24242.
    #[error("authorization event kind must be 24242")]
    Kind,
    /// `created_at` is more than [`CLOCK_SKEW_SECONDS`] ahead.
    #[error("authorization event created_at is in the future")]
    Future,
    /// No `expiration` tag.
    #[error("authorization event has no expiration")]
    NoExpiration,
    /// `expiration` is at or before `now`.
    #[error("authorization event expired")]
    Expired,
    /// No `t` tag matches the endpoint's verb.
    #[error("authorization event verb mismatch")]
    Verb,
    /// `server` tags exist but none names this server's host.
    #[error("authorization event is for a different server")]
    Server,
    /// The endpoint needs an `x` tag and none is valid.
    #[error("authorization event needs an x tag")]
    MissingHash,
    /// `x` tags exist but none covers the blob hash.
    #[error("authorization event does not cover this blob")]
    HashMismatch,
    /// The id hash, canonical form, or BIP-340 signature failed.
    #[error("bad authorization event signature")]
    Signature,
}

impl AuthError {
    /// The bounded `reason` label of `nosfry_blossom_auth_failures_total`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Scheme => "scheme",
            Self::TooLarge => "too_large",
            Self::Base64 => "base64",
            Self::Utf8 => "utf8",
            Self::Invalid => "invalid",
            Self::Kind => "kind",
            Self::Future => "future",
            Self::NoExpiration => "no_expiration",
            Self::Expired => "expired",
            Self::Verb => "verb",
            Self::Server => "server",
            Self::MissingHash => "missing_hash",
            Self::HashMismatch => "hash_mismatch",
            Self::Signature => "signature",
        }
    }

    /// Every variant, for bounded metric render order.
    pub const ALL: [Self; 15] = [
        Self::Missing,
        Self::Scheme,
        Self::TooLarge,
        Self::Base64,
        Self::Utf8,
        Self::Invalid,
        Self::Kind,
        Self::Future,
        Self::NoExpiration,
        Self::Expired,
        Self::Verb,
        Self::Server,
        Self::MissingHash,
        Self::HashMismatch,
        Self::Signature,
    ];
}

/// Base64 engines for both alphabets, each accepting padded or
/// unpadded input.
const STANDARD: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The event's `server` tag values, collected once.
fn server_tags<'s>(event: &'s UnverifiedEvent<'s>) -> Vec<&'s str> {
    event.tag_values("server").collect()
}

/// Authorize one request against a BUD-11 `Authorization` header.
///
/// `header` is the raw `Authorization` value; `verb` the endpoint's
/// required `t`; `now` the unix time; `server` the configured public
/// host (lowercase, no port); `hash` the blob hash the endpoint
/// implies, `None` for `PUT /upload` without `X-SHA-256` (coverage
/// is then checked against the computed hash after the body is
/// hashed). Cheap checks run first, the BIP-340 verify last.
///
/// # Errors
///
/// [`AuthError`]; its `Display` is safe to echo in `X-Reason`.
pub fn authorize(
    header: Option<&str>,
    verb: Verb,
    now: u64,
    server: &str,
    hash: Option<&Hash>,
) -> Result<Token, AuthError> {
    let Some(header) = header else {
        return Err(AuthError::Missing);
    };
    if header.len() > MAX_HEADER_BYTES {
        return Err(AuthError::TooLarge);
    }
    // One ASCII-whitespace split: `Nostr <payload>`.
    let (scheme, payload) = header
        .split_once(|c: char| c.is_ascii_whitespace())
        .map_or((header, ""), |(scheme, rest)| (scheme, rest.trim()));
    if !scheme.eq_ignore_ascii_case("nostr") || payload.is_empty() {
        return Err(AuthError::Scheme);
    }
    // A `-`/`_` marks the URL-safe alphabet; anything else decodes
    // as standard. An engine rejects the other alphabet's digits, so
    // a mixed payload fails either way.
    let engine = if payload.contains(['-', '_']) {
        &URL_SAFE
    } else {
        &STANDARD
    };
    let bytes = engine.decode(payload).map_err(|_| AuthError::Base64)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| AuthError::Utf8)?;
    let event =
        UnverifiedEvent::parse(text, &EventLimits::default()).map_err(|_| AuthError::Invalid)?;
    if event.kind().0 != KIND {
        return Err(AuthError::Kind);
    }
    if event.created_at() > now.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err(AuthError::Future);
    }
    let Some(expiration) = event.expiration() else {
        return Err(AuthError::NoExpiration);
    };
    if expiration <= now {
        return Err(AuthError::Expired);
    }
    if !event.tag_values("t").any(|value| value == verb.as_str()) {
        return Err(AuthError::Verb);
    }
    let servers = server_tags(&event);
    if !servers.is_empty()
        && !servers
            .iter()
            .any(|value| value.eq_ignore_ascii_case(server))
    {
        return Err(AuthError::Server);
    }
    let hashes: Vec<Hash> = event.tag_values("x").filter_map(Hash::from_hex).collect();
    match (hash, verb) {
        (Some(expected), _) => {
            if hashes.is_empty() {
                return Err(AuthError::MissingHash);
            }
            if !hashes.contains(expected) {
                return Err(AuthError::HashMismatch);
            }
        }
        // `PUT /upload` without `X-SHA-256`: an `x` tag must exist;
        // which hash it covers is checked after hashing the body.
        (None, Verb::Upload) => {
            if hashes.is_empty() {
                return Err(AuthError::MissingHash);
            }
        }
        (None, _) => {}
    }
    let pubkey = event.pubkey();
    event
        .verify(&EventLimits::default())
        .map_err(|_| AuthError::Signature)?;
    Ok(Token { pubkey, hashes })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use base64::engine::general_purpose::{STANDARD as PADDED, URL_SAFE_NO_PAD};
    use secp256k1::Keypair;
    use serde_json::{Value, json};

    use super::*;

    const NOW: u64 = 1_700_000_000;
    const HOST: &str = "cdn.example.com";

    /// A signed kind-24242 event JSON with `tags`/`content`, encoded
    /// for the `Authorization` header (`unpadded` URL-safe or padded
    /// standard).
    fn token_json(keypair: &Keypair, created_at: u64, tags: &Value, content: &str) -> String {
        nosfry_core::sign::event(keypair, KIND, created_at, tags, content)
            .json()
            .to_owned()
    }

    fn header_urlsafe(json: &str) -> String {
        format!("Nostr {}", URL_SAFE_NO_PAD.encode(json))
    }

    fn header_standard(json: &str) -> String {
        format!("Nostr {}", PADDED.encode(json))
    }

    /// A minimal upload token for `hash` signed by `keypair`.
    fn upload_token(keypair: &Keypair, hash: &str) -> String {
        token_json(
            keypair,
            NOW - 10,
            &json!([
                ["t", "upload"],
                ["expiration", (NOW + 3600).to_string()],
                ["x", hash]
            ]),
            "Upload Blob",
        )
    }

    const HASH_A: &str = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
    const HASH_B: &str = "a1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";

    fn hash(s: &str) -> Hash {
        Hash::from_hex(s).unwrap()
    }

    /// The happy path: every check passes; both encodings work.
    #[test]
    fn accepts_a_valid_token() {
        let kp = nosfry_core::sign::key(1);
        let json = upload_token(&kp, HASH_A);
        for header in [header_urlsafe(&json), header_standard(&json)] {
            let token =
                authorize(Some(&header), Verb::Upload, NOW, HOST, Some(&hash(HASH_A))).unwrap();
            assert!(token.covers(&hash(HASH_A)));
            assert!(!token.covers(&hash(HASH_B)));
            assert_eq!(token.pubkey.0, kp.x_only_public_key().0.to_byte_array());
        }
        // Mixed alphabets are rejected: `-` selects the URL-safe
        // engine, which then refuses `+`.
        let mixed = format!("{}-+", URL_SAFE_NO_PAD.encode(&json));
        assert_eq!(
            authorize(
                Some(&format!("Nostr {mixed}")),
                Verb::Upload,
                NOW,
                HOST,
                Some(&hash(HASH_A))
            ),
            Err(AuthError::Base64)
        );
        // Whitespace variants still parse.
        let tabbed = format!("Nostr\t{}", URL_SAFE_NO_PAD.encode(&json));
        assert!(authorize(Some(&tabbed), Verb::Upload, NOW, HOST, Some(&hash(HASH_A))).is_ok());
    }

    /// Every [`AuthError`] variant is reachable.
    #[test]
    fn rejects_every_malformation() {
        let kp = nosfry_core::sign::key(2);
        let call = |header: Option<&str>, verb, hash: Option<&Hash>| {
            authorize(header, verb, NOW, HOST, hash)
        };

        assert_eq!(call(None, Verb::Get, None), Err(AuthError::Missing));
        assert_eq!(
            call(Some(&"a".repeat(MAX_HEADER_BYTES + 1)), Verb::Get, None),
            Err(AuthError::TooLarge)
        );
        assert_eq!(
            call(Some("Bearer xyz"), Verb::Get, None),
            Err(AuthError::Scheme)
        );
        assert_eq!(call(Some("Nostr"), Verb::Get, None), Err(AuthError::Scheme));
        assert_eq!(
            call(Some("Nostr  "), Verb::Get, None),
            Err(AuthError::Scheme)
        );
        assert_eq!(
            call(Some("Nostr !!!"), Verb::Get, None),
            Err(AuthError::Base64)
        );
        assert_eq!(
            call(
                Some(&format!("Nostr {}", PADDED.encode(b"\xff\xfe"))),
                Verb::Get,
                None
            ),
            Err(AuthError::Utf8)
        );
        assert_eq!(
            call(
                Some(&format!(
                    "Nostr {}",
                    PADDED.encode(b"{\"not\":\"an event\"}")
                )),
                Verb::Get,
                None
            ),
            Err(AuthError::Invalid)
        );
        // Kind is checked before the signature, so a signed kind-1
        // event fails with Kind even though its id no longer verifies.
        let wrong_kind = token_json(&kp, NOW - 10, &json!([["t", "get"]]), "");
        let wrong_kind = wrong_kind.replace("\"kind\":24242", "\"kind\":1");
        assert_eq!(
            call(Some(&header_urlsafe(&wrong_kind)), Verb::Get, None),
            Err(AuthError::Kind)
        );
    }

    /// Kind, clock, expiration, verb, server, and `x` checks.
    #[expect(
        clippy::too_many_lines,
        reason = "table-style test covering every check"
    )]
    #[test]
    fn validates_each_check() {
        let kp = nosfry_core::sign::key(3);
        let hash_a = hash(HASH_A);
        let signed =
            |created: u64, tags: &Value| header_urlsafe(&token_json(&kp, created, tags, ""));
        let good = signed(
            NOW - 10,
            &json!([
                ["t", "get"],
                ["expiration", (NOW + 10).to_string()],
                ["x", HASH_A]
            ]),
        );
        assert_eq!(
            authorize(Some(&good), Verb::Get, NOW, HOST, Some(&hash_a)).map(|_| ()),
            Ok(())
        );
        // Wrong kind: a real signed kind-1 event.
        let kind1 = nosfry_core::sign::event(&kp, 1, NOW - 10, &json!([]), "")
            .json()
            .to_owned();
        assert_eq!(
            authorize(Some(&header_urlsafe(&kind1)), Verb::Get, NOW, HOST, None),
            Err(AuthError::Kind)
        );
        // Future and boundary: now+60 passes, now+61 fails.
        let future = signed(
            NOW + CLOCK_SKEW_SECONDS + 1,
            &json!([["t", "get"], ["expiration", (NOW + 100).to_string()]]),
        );
        assert_eq!(
            authorize(Some(&future), Verb::Get, NOW, HOST, None),
            Err(AuthError::Future)
        );
        let at_skew = signed(
            NOW + CLOCK_SKEW_SECONDS,
            &json!([["t", "get"], ["expiration", (NOW + 100).to_string()]]),
        );
        assert!(authorize(Some(&at_skew), Verb::Get, NOW, HOST, None).is_ok());
        // No expiration / expired at exactly `now`.
        let no_exp = signed(NOW - 10, &json!([["t", "get"]]));
        assert_eq!(
            authorize(Some(&no_exp), Verb::Get, NOW, HOST, None),
            Err(AuthError::NoExpiration)
        );
        let expired = signed(
            NOW - 10,
            &json!([["t", "get"], ["expiration", NOW.to_string()]]),
        );
        assert_eq!(
            authorize(Some(&expired), Verb::Get, NOW, HOST, None),
            Err(AuthError::Expired)
        );
        // Verb: "delete" token on a "get" endpoint; "media" never matches.
        let wrong_verb = signed(
            NOW - 10,
            &json!([["t", "delete"], ["expiration", (NOW + 10).to_string()]]),
        );
        assert_eq!(
            authorize(Some(&wrong_verb), Verb::Get, NOW, HOST, None),
            Err(AuthError::Verb)
        );
        let media = signed(
            NOW - 10,
            &json!([["t", "media"], ["expiration", (NOW + 10).to_string()]]),
        );
        assert_eq!(
            authorize(Some(&media), Verb::Upload, NOW, HOST, None),
            Err(AuthError::Verb)
        );
        // Server tag: match (case-insensitive) and mismatch.
        let served = signed(
            NOW - 10,
            &json!([
                ["t", "get"],
                ["expiration", (NOW + 10).to_string()],
                ["server", "CDN.EXAMPLE.COM"]
            ]),
        );
        assert!(authorize(Some(&served), Verb::Get, NOW, HOST, None).is_ok());
        let other = signed(
            NOW - 10,
            &json!([
                ["t", "get"],
                ["expiration", (NOW + 10).to_string()],
                ["server", "other.example.com"]
            ]),
        );
        assert_eq!(
            authorize(Some(&other), Verb::Get, NOW, HOST, None),
            Err(AuthError::Server)
        );
        // `x`: missing, mismatched, one of several matching.
        let no_x = signed(
            NOW - 10,
            &json!([["t", "delete"], ["expiration", (NOW + 10).to_string()]]),
        );
        assert_eq!(
            authorize(Some(&no_x), Verb::Delete, NOW, HOST, Some(&hash_a)),
            Err(AuthError::MissingHash)
        );
        let wrong_x = signed(
            NOW - 10,
            &json!([
                ["t", "delete"],
                ["expiration", (NOW + 10).to_string()],
                ["x", HASH_B]
            ]),
        );
        assert_eq!(
            authorize(Some(&wrong_x), Verb::Delete, NOW, HOST, Some(&hash_a)),
            Err(AuthError::HashMismatch)
        );
        let many_x = signed(
            NOW - 10,
            &json!([
                ["t", "delete"],
                ["expiration", (NOW + 10).to_string()],
                ["x", HASH_B],
                ["x", "not-hex"],
                ["x", HASH_A],
            ]),
        );
        assert!(
            authorize(Some(&many_x), Verb::Delete, NOW, HOST, Some(&hash_a)).is_ok(),
            "one valid x among others must cover"
        );
        // Bad signature: flip a sig nibble.
        let mut bad_sig = token_json(
            &kp,
            NOW - 10,
            &json!([["t", "get"], ["expiration", (NOW + 10).to_string()]]),
            "",
        );
        let sig_pos = bad_sig.rfind("sig").unwrap();
        let hex_pos = sig_pos + 7;
        let ch = if bad_sig.as_bytes().get(hex_pos) == Some(&b'0') {
            '1'
        } else {
            '0'
        };
        bad_sig.replace_range(hex_pos..=hex_pos, &ch.to_string());
        assert_eq!(
            authorize(Some(&header_urlsafe(&bad_sig)), Verb::Get, NOW, HOST, None),
            Err(AuthError::Signature)
        );
        // Expiration boundary: now-1 passes.
        let alive = signed(
            NOW - 10,
            &json!([["t", "get"], ["expiration", (NOW + 1).to_string()]]),
        );
        assert!(authorize(Some(&alive), Verb::Get, NOW, HOST, None).is_ok());
    }

    /// `PUT /upload` without `X-SHA-256` needs an `x` tag but any
    /// valid one passes `authorize` (coverage is checked later).
    #[test]
    fn upload_without_known_hash_needs_any_x() {
        let kp = nosfry_core::sign::key(4);
        let signed = |tags: &Value| header_urlsafe(&token_json(&kp, NOW - 10, tags, ""));
        let no_x = signed(&json!([
            ["t", "upload"],
            ["expiration", (NOW + 10).to_string()]
        ]));
        assert_eq!(
            authorize(Some(&no_x), Verb::Upload, NOW, HOST, None),
            Err(AuthError::MissingHash)
        );
        let some_x = signed(&json!([
            ["t", "upload"],
            ["expiration", (NOW + 10).to_string()],
            ["x", HASH_A]
        ]));
        let token = authorize(Some(&some_x), Verb::Upload, NOW, HOST, None).unwrap();
        assert!(token.has_hashes());
        assert!(token.covers(&hash(HASH_A)));
        // A `get` endpoint with no implied hash needs no `x` at all.
        let list_token = signed(&json!([
            ["t", "list"],
            ["expiration", (NOW + 10).to_string()]
        ]));
        assert!(authorize(Some(&list_token), Verb::List, NOW, HOST, None).is_ok());
    }

    /// The label set is stable and unique per variant.
    #[test]
    fn labels_are_bounded() {
        let mut labels: Vec<_> = AuthError::ALL
            .iter()
            .map(|variant| variant.label())
            .collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), AuthError::ALL.len());
        for variant in AuthError::ALL {
            assert!(variant.to_string().is_ascii());
        }
    }
}
