//! Strict NIP-01 event ingest: borrowed parse, hash check, BIP-340 verify,
//! canonical JSON, packed record.

use core::cmp::Ordering;
use core::fmt;
use std::borrow::Cow;

use secp256k1::XOnlyPublicKey;
use secp256k1::schnorr::{self, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::deletion::DeletionTarget;
use crate::hex;
use crate::kind::{Kind, KindClass};
use crate::packed::{PackedEvent, PackedRef};
use crate::url::RelayNames;

/// A 32-byte event id. `Display` is lowercase hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId(pub [u8; 32]);

impl EventId {
    /// Parse a 64-char lowercase hex id.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        hex::decode_32(s).map(Self)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

/// A 32-byte author public key. `Display` is lowercase hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// Parse a 64-char lowercase hex public key.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        hex::decode_32(s).map(Self)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

/// Event acceptance limits: structure plus `created_at` windows, all
/// strfry defaults; unknown keys are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventLimits {
    /// Maximum size of the canonical event JSON, in bytes.
    pub max_event_size: usize,
    /// Maximum number of tags.
    pub max_num_tags: usize,
    /// Maximum size of a single tag element, in bytes.
    pub max_tag_val_size: usize,
    /// Reject events whose `created_at` is more than this far in the future.
    pub reject_events_newer_than_seconds: u64,
    /// Reject events whose `created_at` is older than this many seconds.
    pub reject_events_older_than_seconds: u64,
    /// Reject ephemeral events whose `created_at` is older than this many seconds.
    pub reject_ephemeral_events_older_than_seconds: u64,
}

impl Default for EventLimits {
    fn default() -> Self {
        Self {
            max_event_size: 65_536,
            max_num_tags: 2_000,
            max_tag_val_size: 1_024,
            reject_events_newer_than_seconds: 900,
            reject_events_older_than_seconds: 94_608_000,
            reject_ephemeral_events_older_than_seconds: 60,
        }
    }
}

/// Errors from event parse or verification.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// The input is not a well-formed event object.
    #[error("malformed JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A field has a wrong shape (wrong type or bad hex).
    #[error("field `{0}` must be {1}")]
    Field(&'static str, &'static str),
    /// More tags than [`EventLimits::max_num_tags`].
    #[error("too many tags ({0} > {1})")]
    TooManyTags(usize, usize),
    /// A tag element larger than [`EventLimits::max_tag_val_size`].
    #[error("tag value too large ({0} > {1} bytes)")]
    TagValueTooLarge(usize, usize),
    /// The canonical JSON is larger than [`EventLimits::max_event_size`].
    #[error("event too large ({0} > {1} bytes)")]
    EventTooLarge(usize, usize),
    /// The claimed `id` does not match the serialized event hash.
    #[error("event id does not match computed hash")]
    IdMismatch,
    /// BIP-340 verification failed.
    #[error("signature verification failed")]
    Sig,
    /// The first `expiration` tag lacks an ASCII-decimal `u64` value
    /// of at least 100 (NIP-40).
    #[error("malformed expiration tag")]
    MalformedExpiration,
}

impl EventError {
    /// The NIP-01 machine-readable rejection message (`invalid: ...`).
    #[must_use]
    pub fn reason(&self) -> String {
        format!("invalid: {self}")
    }
}

/// Borrowed, structurally validated but not yet signature-verified event.
#[derive(Debug)]
pub struct UnverifiedEvent<'a> {
    id: EventId,
    pubkey: PublicKey,
    created_at: u64,
    kind: Kind,
    expiration: Option<u64>,
    tags: Vec<Vec<Cow<'a, str>>>,
    content: Cow<'a, str>,
    sig: [u8; 64],
    pubkey_hex: Cow<'a, str>,
    sig_hex: Cow<'a, str>,
}

/// Serde view: all seven fields required, duplicates rejected, unknown keys
/// ignored (they never reach storage).
#[derive(Deserialize)]
struct RawEvent<'a> {
    #[serde(borrow)]
    id: Cow<'a, str>,
    #[serde(borrow)]
    pubkey: Cow<'a, str>,
    created_at: u64,
    kind: u16,
    #[serde(borrow)]
    tags: Vec<Vec<Cow<'a, str>>>,
    #[serde(borrow)]
    content: Cow<'a, str>,
    #[serde(borrow)]
    sig: Cow<'a, str>,
}

impl<'a> UnverifiedEvent<'a> {
    /// Structural parse + limit checks. No hashing happens here.
    ///
    /// # Errors
    ///
    /// [`EventError`] on any malformed field or exceeded limit.
    pub fn parse(json: &'a str, limits: &EventLimits) -> Result<Self, EventError> {
        let ev = Self::parse_structural(json)?;
        ev.check_limits(limits)?;
        Ok(ev)
    }

    /// Structure-only parse without size limits, for re-reading stored
    /// canonical JSON whose configured limits may have changed since the
    /// event was accepted.
    ///
    /// # Errors
    ///
    /// [`EventError`] on any malformed field.
    pub fn parse_structural(json: &'a str) -> Result<Self, EventError> {
        let raw: RawEvent<'a> = serde_json::from_str(json)?;
        let id =
            hex::decode_32(&raw.id).ok_or(EventError::Field("id", "64 lowercase hex chars"))?;
        let pubkey = hex::decode_32(&raw.pubkey)
            .ok_or(EventError::Field("pubkey", "64 lowercase hex chars"))?;
        let sig =
            hex::decode_64(&raw.sig).ok_or(EventError::Field("sig", "128 lowercase hex chars"))?;
        if raw.created_at > 9_007_199_254_740_991 {
            return Err(EventError::Field("created_at", "integer <= 2^53 - 1"));
        }
        let mut expiration = None;
        for tag in &raw.tags {
            let Some(name) = tag.first() else {
                return Err(EventError::Field(
                    "tags",
                    "arrays of non-empty string arrays",
                ));
            };
            if (name.as_ref() == "e" || name.as_ref() == "p")
                && let Some(value) = tag.get(1)
                && !hex::is_lower_hex(value, 64)
            {
                return Err(EventError::Field(
                    "tags",
                    "e/p first values of 64 lowercase hex chars",
                ));
            }
            if name.as_ref() == "expiration" && expiration.is_none() {
                expiration = Some(parse_expiration(tag)?);
            }
        }
        Ok(Self {
            id: EventId(id),
            pubkey: PublicKey(pubkey),
            created_at: raw.created_at,
            kind: Kind(raw.kind),
            expiration,
            tags: raw.tags,
            content: raw.content,
            sig,
            pubkey_hex: raw.pubkey,
            sig_hex: raw.sig,
        })
    }

    /// [`EventLimits::max_num_tags`] and
    /// [`EventLimits::max_tag_val_size`] checks.
    ///
    /// # Errors
    ///
    /// [`EventError::TooManyTags`] or [`EventError::TagValueTooLarge`].
    pub fn check_limits(&self, limits: &EventLimits) -> Result<(), EventError> {
        if self.tags.len() > limits.max_num_tags {
            return Err(EventError::TooManyTags(
                self.tags.len(),
                limits.max_num_tags,
            ));
        }
        for value in self.tags.iter().flatten() {
            if value.len() > limits.max_tag_val_size {
                return Err(EventError::TagValueTooLarge(
                    value.len(),
                    limits.max_tag_val_size,
                ));
            }
        }
        Ok(())
    }

    /// The author public key.
    #[must_use]
    pub const fn pubkey(&self) -> PublicKey {
        self.pubkey
    }

    /// The NIP-40 `expiration` unix time, `None` when absent.
    #[must_use]
    pub const fn expiration(&self) -> Option<u64> {
        self.expiration
    }

    /// The NIP-01 replaceable/addressable storage key derived from
    /// kind, pubkey, and the first `d` tag (empty for replaceable
    /// kinds); `None` for regular and ephemeral kinds.
    #[must_use]
    pub fn address(&self) -> Option<[u8; 32]> {
        match self.kind.class() {
            KindClass::Regular | KindClass::Ephemeral => None,
            KindClass::Replaceable => Some(address_hash(self.kind, &self.pubkey, &[])),
            KindClass::Addressable => {
                let d = self
                    .tags
                    .iter()
                    .find(|tag| tag.first().is_some_and(|name| name.as_ref() == "d"))
                    .and_then(|tag| tag.get(1))
                    .map_or(&[][..], |value| value.as_bytes());
                Some(address_hash(self.kind, &self.pubkey, d))
            }
        }
    }

    /// The NIP-09 deletion targets of a kind-5 event: every `e` id and
    /// every `a` `"<kind>:<author>:<d>"` naming a replaceable or
    /// addressable kind of this author (malformed and foreign-author
    /// values are skipped). Empty for other kinds.
    #[must_use]
    pub fn deletion_targets(&self) -> Vec<DeletionTarget> {
        crate::deletion::targets(self.kind, &self.pubkey, &self.tags)
    }

    /// The `relay` tag values of a kind-62 request to vanish; empty
    /// for other kinds.
    #[must_use]
    pub fn vanish_relays(&self) -> Box<[Box<str>]> {
        if self.kind.0 != 62 {
            return Box::new([]);
        }
        self.tag_values("relay").map(Box::from).collect()
    }

    /// The claimed event id.
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// `created_at` seconds.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Event kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// Whether any tag's first element is exactly `"-"` (the NIP-70
    /// protected marker).
    #[must_use]
    pub fn is_protected(&self) -> bool {
        self.tags
            .iter()
            .any(|tag| tag.first().is_some_and(|name| name.as_ref() == "-"))
    }

    /// Whether a kind-6/16 repost embeds a protected event: the raw
    /// content contains the literal `["-"]` (strfry's substring rule —
    /// the embedded JSON is deliberately not parsed).
    #[must_use]
    pub fn embeds_protected(&self) -> bool {
        matches!(self.kind.0, 6 | 16) && self.content.contains("[\"-\"]")
    }

    /// The second element of every tag named `name`.
    pub fn tag_values<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s str> {
        self.tags.iter().filter_map(move |tag| {
            if tag.first().is_some_and(|n| n.as_ref() == name) {
                tag.get(1).map(AsRef::as_ref)
            } else {
                None
            }
        })
    }

    /// Verify the id hash, build the canonical JSON and check its size,
    /// then verify the BIP-340 signature and build the packed record.
    /// `limits` bounds the canonical JSON size. The size check runs
    /// before the signature check so an oversized event does not pay
    /// for a BIP-340 verification.
    ///
    /// # Errors
    ///
    /// [`EventError::IdMismatch`], [`EventError::EventTooLarge`], or
    /// [`EventError::Sig`].
    pub fn verify(self, limits: &EventLimits) -> Result<Event, EventError> {
        self.verify_impl(limits, true)
    }

    /// [`verify`](Self::verify) skipping only the BIP-340 signature
    /// check: the id hash, canonical size, and every structural/limit
    /// check still run. Only for trusted input such as importing a
    /// dump from a trusted relay — never on network input.
    ///
    /// # Errors
    ///
    /// [`EventError::IdMismatch`] or [`EventError::EventTooLarge`].
    pub fn verify_unsigned(self, limits: &EventLimits) -> Result<Event, EventError> {
        self.verify_impl(limits, false)
    }

    /// [`verify`](Self::verify) with the signature step optional —
    /// `check_sig` false skips only the BIP-340 check.
    fn verify_impl(self, limits: &EventLimits, check_sig: bool) -> Result<Event, EventError> {
        let preimage = id_preimage(
            self.pubkey_hex.as_ref(),
            self.created_at,
            self.kind.0,
            &self.tags,
            self.content.as_ref(),
        );
        let computed: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
        if computed != self.id.0 {
            return Err(EventError::IdMismatch);
        }

        let id_hex = self.id.to_string();
        let json = serde_json::to_string(&CanonicalEvent {
            id: &id_hex,
            pubkey: self.pubkey_hex.as_ref(),
            created_at: self.created_at,
            kind: self.kind.0,
            tags: &self.tags,
            content: self.content.as_ref(),
            sig: self.sig_hex.as_ref(),
        })?;
        if json.len() > limits.max_event_size {
            return Err(EventError::EventTooLarge(json.len(), limits.max_event_size));
        }

        if check_sig {
            let sig = Signature::from_byte_array(self.sig);
            let pubkey =
                XOnlyPublicKey::from_byte_array(self.pubkey.0).map_err(|_| EventError::Sig)?;
            schnorr::verify(&sig, &computed, &pubkey).map_err(|_| EventError::Sig)?;
        }

        let packed = PackedEvent::build(
            &self.id,
            &self.pubkey,
            self.created_at,
            self.kind,
            self.expiration.unwrap_or(0),
            &self.tags,
        );
        Ok(Event {
            packed,
            json: json.into_boxed_str(),
            address: self.address(),
            expiration: self.expiration,
            deletion_targets: self.deletion_targets(),
            vanish_relays: self.vanish_relays(),
        })
    }
}

/// Canonical JSON field order; serde emits fields in declaration order.
#[derive(Serialize)]
struct CanonicalEvent<'a> {
    id: &'a str,
    pubkey: &'a str,
    created_at: u64,
    kind: u16,
    tags: &'a [Vec<Cow<'a, str>>],
    content: &'a str,
    sig: &'a str,
}

/// A fully verified, immutable event. Cheap to wrap in `Arc`.
#[derive(Debug)]
pub struct Event {
    packed: PackedEvent,
    json: Box<str>,
    address: Option<[u8; 32]>,
    expiration: Option<u64>,
    deletion_targets: Vec<DeletionTarget>,
    vanish_relays: Box<[Box<str>]>,
}

impl Event {
    /// Event id.
    #[must_use]
    pub fn id(&self) -> EventId {
        self.packed.packed().id()
    }

    /// Author public key.
    #[must_use]
    pub fn pubkey(&self) -> PublicKey {
        self.packed.packed().pubkey()
    }

    /// `created_at` seconds.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.packed.packed().created_at()
    }

    /// Event kind.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.packed.packed().kind()
    }

    /// Canonical JSON, in fixed field order with `serde_json` string escaping.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.json
    }

    /// Borrowed view over the packed index record.
    #[must_use]
    pub fn packed(&self) -> PackedRef<'_> {
        self.packed.packed()
    }

    /// The fixed-size replaceable/addressable key:
    /// [`address_hash`] over an empty `d` for replaceable kinds, over the
    /// full first `d` value for addressable kinds, `None` otherwise.
    #[must_use]
    pub const fn address(&self) -> Option<[u8; 32]> {
        self.address
    }

    /// The NIP-40 `expiration` unix time, `None` when absent.
    #[must_use]
    pub const fn expiration(&self) -> Option<u64> {
        self.expiration
    }

    /// The NIP-09 deletion targets; empty unless kind 5.
    #[must_use]
    pub fn deletion_targets(&self) -> &[DeletionTarget] {
        &self.deletion_targets
    }

    /// Whether this is a NIP-62 request to vanish that this relay must
    /// honor: a kind 62 whose `relay` tags hold `ALL_RELAYS` or a value
    /// matching any of `names`.
    #[must_use]
    pub fn requests_vanish(&self, names: &RelayNames) -> bool {
        self.vanish_relays
            .iter()
            .any(|value| value.as_ref() == "ALL_RELAYS" || names.matches(value))
    }
}

/// The NIP-01 id preimage `[0, pubkey, created_at, kind, tags, content]`,
/// serialized exactly like `JSON.stringify` (`vectors/event-serialize.json`
/// is the oracle). `pubkey` is the lowercase hex string form.
fn id_preimage<T: Serialize + ?Sized>(
    pubkey: &str,
    created_at: u64,
    kind: u16,
    tags: &T,
    content: &str,
) -> String {
    serde_json::to_string(&(0u8, pubkey, created_at, kind, tags, content)).unwrap_or_default()
}

/// The NIP-01 id preimage, built for an unsigned event.
#[must_use]
pub fn serialize_for_id(
    pubkey: &PublicKey,
    created_at: u64,
    kind: Kind,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    id_preimage(&pubkey.to_string(), created_at, kind.0, tags, content)
}

/// The NIP-01 event id: `SHA-256` of the [`serialize_for_id`] preimage.
#[must_use]
pub fn event_id(preimage: &[u8]) -> EventId {
    EventId(Sha256::digest(preimage).into())
}

/// The storage key for replaceable and addressable events:
/// `SHA-256(kind as u16 big-endian || pubkey || d)`.
#[must_use]
pub fn address_hash(kind: Kind, pubkey: &PublicKey, d: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(kind.0.to_be_bytes());
    hasher.update(pubkey.0);
    hasher.update(d);
    hasher.finalize().into()
}

/// Newest-first ordering: `created_at` descending, then id ascending.
#[must_use]
pub fn cmp_newest_first(a: (u64, &EventId), b: (u64, &EventId)) -> Ordering {
    b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1))
}

/// The NIP-40 `expiration` tag's second element: an ASCII-decimal
/// `u64` of at least 100 (the `0` packed sentinel stays free).
fn parse_expiration(tag: &[Cow<'_, str>]) -> Result<u64, EventError> {
    let Some(value) = tag.get(1) else {
        return Err(EventError::MalformedExpiration);
    };
    let decimal = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    match decimal.then(|| value.parse::<u64>()) {
        Some(Ok(expiration)) if expiration >= 100 => Ok(expiration),
        _ => Err(EventError::MalformedExpiration),
    }
}

/// Whether `new` supersedes `old` as the stored replaceable/addressable
/// event: newer `created_at` wins, and on a tie the lower id wins.
#[must_use]
pub fn supersedes(new: (u64, &EventId), old: (u64, &EventId)) -> bool {
    match new.0.cmp(&old.0) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => new.1 < old.1,
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::Keypair;
    use secp256k1::schnorr;

    use super::*;

    fn sign_json(kind: u16, created_at: u64, tags: &[Vec<String>], content: &str) -> String {
        let keypair = Keypair::from_secret_bytes([7u8; 32]).expect("secret key");
        let pubkey = PublicKey(keypair.x_only_public_key().0.to_byte_array());
        let preimage = serialize_for_id(&pubkey, created_at, Kind(kind), tags, content);
        let id = event_id(preimage.as_bytes());
        let sig = schnorr::sign_no_aux_rand(&id.0, &keypair);
        format!(
            "{{\"id\":\"{id}\",\"pubkey\":\"{pubkey}\",\"created_at\":{created_at},\
             \"kind\":{kind},\"tags\":{},\"content\":{},\"sig\":\"{}\"}}",
            serde_json::to_string(tags).expect("tags"),
            serde_json::to_string(content).expect("content"),
            hex::encode(&sig.to_byte_array()),
        )
    }

    fn sign(kind: u16, created_at: u64, tags: &[Vec<String>], content: &str) -> Event {
        UnverifiedEvent::parse(
            &sign_json(kind, created_at, tags, content),
            &EventLimits::default(),
        )
        .expect("parse")
        .verify(&EventLimits::default())
        .expect("verify")
    }

    fn pubkey() -> PublicKey {
        let keypair = Keypair::from_secret_bytes([7u8; 32]).expect("secret key");
        PublicKey(keypair.x_only_public_key().0.to_byte_array())
    }

    #[test]
    fn replaceable_address_uses_empty_d() {
        let event = sign(0, 1000, &[], "profile");
        assert_eq!(
            event.address(),
            Some(address_hash(Kind(0), &event.pubkey(), &[]))
        );
        let ignored = sign(10_000, 1000, &[vec!["d".into(), "ignored".into()]], "x");
        assert_eq!(
            ignored.address(),
            Some(address_hash(Kind(10_000), &ignored.pubkey(), &[])),
            "replaceable kinds hash an empty d even when a d tag exists"
        );
    }

    #[test]
    fn addressable_address_uses_first_d_value() {
        let event = sign(
            30_023,
            1000,
            &[
                vec!["d".into(), "post".into()],
                vec!["d".into(), "other".into()],
            ],
            "x",
        );
        assert_eq!(
            event.address(),
            Some(address_hash(Kind(30_023), &event.pubkey(), b"post"))
        );
        let no_d = sign(30_023, 1000, &[], "x");
        assert_eq!(
            no_d.address(),
            Some(address_hash(Kind(30_023), &no_d.pubkey(), &[]))
        );
    }

    #[test]
    fn addressable_address_keeps_full_d_beyond_packed_limit() {
        let d = "d".repeat(300);
        let event = sign(30_023, 1000, &[vec!["d".into(), d.clone()]], "x");
        // The 300-byte value is absent from the packed record...
        assert_eq!(event.packed().d_tag(), b"".as_slice());
        // ...but the address still covers all of it.
        assert_eq!(
            event.address(),
            Some(address_hash(Kind(30_023), &event.pubkey(), d.as_bytes()))
        );
    }

    /// An oversized event must be rejected before the BIP-340 check:
    /// the invalid signature would otherwise mask `EventTooLarge`.
    #[test]
    fn oversized_event_fails_size_before_signature() {
        let signed = sign_json(1, 1000, &[], &"x".repeat(70_000));
        let mut value: serde_json::Value = serde_json::from_str(&signed).expect("json");
        *value.get_mut("sig").expect("sig field") = serde_json::json!("00".repeat(64));
        let tampered = serde_json::to_string(&value).expect("json");
        let unverified =
            UnverifiedEvent::parse(&tampered, &EventLimits::default()).expect("structural parse");
        let error = unverified
            .verify(&EventLimits::default())
            .expect_err("oversized");
        assert!(
            matches!(error, EventError::EventTooLarge(..)),
            "expected EventTooLarge before the signature check, got {error}"
        );
    }

    /// `verify_unsigned` skips only the BIP-340 check: a corrupted
    /// signature passes while a wrong id still fails.
    #[test]
    fn verify_unsigned_skips_only_the_signature() {
        let limits = EventLimits::default();
        let signed = sign_json(1, 1000, &[], "x");
        let mut value: serde_json::Value = serde_json::from_str(&signed).expect("json");
        *value.get_mut("sig").expect("sig field") = serde_json::json!("00".repeat(64));
        let tampered = serde_json::to_string(&value).expect("json");

        UnverifiedEvent::parse(&tampered, &limits)
            .expect("structural parse")
            .verify_unsigned(&limits)
            .expect("unsigned verify accepts a corrupted signature");
        let error = UnverifiedEvent::parse(&tampered, &limits)
            .expect("structural parse")
            .verify(&limits)
            .expect_err("verify still rejects it");
        assert!(matches!(error, EventError::Sig), "got {error}");

        let mut doc: serde_json::Value = serde_json::from_str(&signed).expect("json");
        *doc.get_mut("id").expect("id field") = serde_json::json!("11".repeat(32));
        let bad_id = serde_json::to_string(&doc).expect("json");
        let id_error = UnverifiedEvent::parse(&bad_id, &limits)
            .expect("structural parse")
            .verify_unsigned(&limits)
            .expect_err("a wrong id still fails without the sig check");
        assert!(matches!(id_error, EventError::IdMismatch), "got {id_error}");
    }

    #[test]
    fn regular_and_ephemeral_have_no_address() {
        assert_eq!(sign(1, 1000, &[], "gm").address(), None);
        assert_eq!(sign(20_000, 1000, &[], "gm").address(), None);
        assert_eq!(sign(65_535, 1000, &[], "gm").address(), None);
    }

    #[test]
    fn address_hash_layout() {
        let pk = pubkey();
        let hash = address_hash(Kind(30_023), &pk, b"post");
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&30_023u16.to_be_bytes());
        preimage.extend_from_slice(&pk.0);
        preimage.extend_from_slice(b"post");
        assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(&preimage)));
    }

    #[test]
    fn expiration_first_tag_wins_and_packs() {
        let expiration = 1_700_000_000;
        let tags = vec![
            vec!["expiration".into(), expiration.to_string()],
            vec!["expiration".into(), "bogus".into()],
        ];
        let json = sign_json(1, 1000, &tags, "x");
        let unverified = UnverifiedEvent::parse(&json, &EventLimits::default()).expect("parse");
        assert_eq!(unverified.expiration(), Some(expiration));
        let event = unverified.verify(&EventLimits::default()).expect("verify");
        assert_eq!(event.expiration(), Some(expiration));
        assert_eq!(
            event.packed().expiration(),
            expiration,
            "packed header must equal the parsed expiration"
        );
    }

    #[test]
    fn expiration_malformed_rejected() {
        for tags in [
            vec![vec!["expiration".into()]],
            vec![vec!["expiration".into(), "abc".into()]],
            vec![vec!["expiration".into(), "+200".into()]],
            vec![vec!["expiration".into(), "1_000".into()]],
            vec![vec!["expiration".into(), "99".into()]],
            // A malformed first tag is not rescued by a valid second.
            vec![
                vec!["expiration".into(), "bogus".into()],
                vec!["expiration".into(), "1000".into()],
            ],
        ] {
            let error =
                UnverifiedEvent::parse(&sign_json(1, 1000, &tags, "x"), &EventLimits::default())
                    .expect_err("malformed expiration must be rejected");
            assert_eq!(
                error.reason(),
                "invalid: malformed expiration tag",
                "{tags:?}"
            );
        }
        assert_eq!(sign(1, 1000, &[], "x").expiration(), None);
        assert_eq!(sign(1, 1000, &[], "x").packed().expiration(), 0);
    }

    #[test]
    fn deletion_targets_e_and_a_tags() {
        let deleted_id = "ab".repeat(32);
        let other = "cd".repeat(32);
        let pk = pubkey();
        let pk_hex = pk.to_string();
        let tags = vec![
            vec!["e".into(), deleted_id.clone()],
            vec!["e".into(), deleted_id.clone()], // duplicate collapses
            vec!["e".into(), other.clone()],
            vec!["a".into(), format!("30023:{pk_hex}:article")],
            vec!["a".into(), format!("0:{pk_hex}:")], // replaceable, empty d
            vec!["a".into(), format!("30023:{pk_hex}:d:with:colons")],
            // Skipped: foreign author, non-replaceable kind, malformed.
            vec!["a".into(), format!("30023:{}:x", "ef".repeat(32))],
            vec!["a".into(), format!("1:{pk_hex}:x")],
            vec!["a".into(), "not-an-address".into()],
            vec!["a".into(), format!("30023:{pk_hex}")],
            vec!["a".into(), format!("xyz:{pk_hex}:d")],
        ];
        let json = sign_json(5, 1000, &tags, "del");
        let unverified = UnverifiedEvent::parse(&json, &EventLimits::default()).expect("parse");
        let mut want = vec![
            DeletionTarget::Event(EventId::from_hex(&deleted_id).expect("hex")),
            DeletionTarget::Event(EventId::from_hex(&other).expect("hex")),
            DeletionTarget::Address(address_hash(Kind(30_023), &pk, b"article")),
            DeletionTarget::Address(address_hash(Kind(0), &pk, b"")),
            DeletionTarget::Address(address_hash(Kind(30_023), &pk, b"d:with:colons")),
        ];
        want.sort_unstable();
        let targets = unverified.deletion_targets();
        assert_eq!(targets, want);
        let event = unverified.verify(&EventLimits::default()).expect("verify");
        assert_eq!(event.deletion_targets(), targets.as_slice());
    }

    #[test]
    fn deletion_targets_empty_unless_kind_5() {
        let pk = pubkey();
        let tags = vec![
            vec!["e".into(), "ab".repeat(32)],
            vec!["a".into(), format!("30023:{pk}:x")],
        ];
        let json = sign_json(1, 1000, &tags, "x");
        let unverified = UnverifiedEvent::parse(&json, &EventLimits::default()).expect("parse");
        assert_eq!(unverified.deletion_targets(), Vec::<DeletionTarget>::new());
        let event = unverified.verify(&EventLimits::default()).expect("verify");
        assert_eq!(event.deletion_targets(), &[]);
    }

    #[test]
    fn requests_vanish_matches_relay_tags() {
        use crate::url::RelayNames;
        let names = RelayNames::parse(
            "wss://relay.example.com/path",
            &["ws://abc.onion".to_owned()],
        )
        .expect("names");
        let none = RelayNames::default();
        let vanish = |tags: Vec<Vec<String>>| {
            UnverifiedEvent::parse(&sign_json(62, 1000, &tags, "bye"), &EventLimits::default())
                .expect("parse")
                .verify(&EventLimits::default())
                .expect("verify")
        };
        // `ALL_RELAYS` applies even without a configured URL; a
        // matching URL compares under strfry normalization (scheme,
        // path, case dropped).
        assert!(vanish(vec![vec!["relay".into(), "ALL_RELAYS".into()]]).requests_vanish(&none));
        let named = vanish(vec![
            vec!["relay".into(), "wss://other.example.com".into()],
            vec!["relay".into(), "ws://Relay.Example.COM/elsewhere".into()],
        ]);
        assert!(named.requests_vanish(&names));
        assert!(!named.requests_vanish(&none));
        // An alias name honors the request as well.
        let aliased = vanish(vec![vec!["relay".into(), "ws://ABC.ONION".into()]]);
        assert!(aliased.requests_vanish(&names));
        assert!(!aliased.requests_vanish(&none));
        let foreign = vanish(vec![vec!["relay".into(), "wss://other.example.com".into()]]);
        assert!(!foreign.requests_vanish(&names));
        // Not kind 62, or no `relay` tags: never a request.
        assert!(!vanish(vec![]).requests_vanish(&names));
        let note = UnverifiedEvent::parse(
            &sign_json(1, 1000, &[vec!["relay".into(), "ALL_RELAYS".into()]], "x"),
            &EventLimits::default(),
        )
        .expect("parse")
        .verify(&EventLimits::default())
        .expect("verify");
        assert!(!note.requests_vanish(&names));
        assert!(note.vanish_relays.is_empty());
    }
}
