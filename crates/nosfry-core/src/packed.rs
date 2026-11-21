//! strfry-style packed index record: same field order and tag encoding
//! as strfry's `PackedEvent`, but not byte-compatible (strfry uses an
//! 8-byte kind and an 88-byte header).
//!
//! Layout:
//! `[0..32 id][32..64 pubkey][64..72 created_at u64 LE][72..74 kind u16 LE]
//! [74..82 expiration u64 LE, 0 = none][tags...]`, each tag entry
//! `[name u8][len u8][value]`. Only tags with a single ASCII letter name are
//! packed, only their first value, and only when the encoded value fits in
//! 255 bytes — the same rule applies to stored scans and live matching.

use crate::event::{EventId, PublicKey};
use crate::hex;
use crate::kind::Kind;

/// Byte offset where packed tag entries begin.
const HEADER_LEN: usize = 82;

/// An indexed tag value in its packed (normalized) form.
///
/// `e` and `p` values are stored as their 32 raw bytes; every other tag name
/// stores the UTF-8 bytes as-is. Values that cannot be packed (longer than
/// 255 bytes after encoding, or malformed `e`/`p` hex) can never match and
/// are absent both from packed events and compiled filters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TagValueBuf(Box<[u8]>);

impl TagValueBuf {
    /// The packed bytes of this value.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Normalize a tag value into packed form; `None` when it cannot be packed.
///
/// Shared by [`PackedEvent::build`] and filter compilation so both sides
/// normalize identically.
#[must_use]
pub fn encode_tag_value(name: u8, value: &str) -> Option<TagValueBuf> {
    let bytes: Box<[u8]> = if name == b'e' || name == b'p' {
        Box::from(hex::decode_32(value)?)
    } else {
        if value.len() > 255 {
            return None;
        }
        Box::from(value.as_bytes())
    };
    Some(TagValueBuf(bytes))
}

/// An owned packed index record.
#[derive(Debug, Clone)]
pub struct PackedEvent(Box<[u8]>);

impl PackedEvent {
    /// Build the packed record for an event. Tags that cannot be packed are
    /// skipped; `expiration` fills the header (`0` = absent, NIP-40).
    pub fn build<I, T, S>(
        id: &EventId,
        pubkey: &PublicKey,
        created_at: u64,
        kind: Kind,
        expiration: u64,
        tags: I,
    ) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[S]>,
        S: AsRef<str>,
    {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.extend_from_slice(&id.0);
        out.extend_from_slice(&pubkey.0);
        out.extend_from_slice(&created_at.to_le_bytes());
        out.extend_from_slice(&kind.0.to_le_bytes());
        out.extend_from_slice(&expiration.to_le_bytes());

        for tag in tags {
            let els = tag.as_ref();
            let Some(name) = els.first() else {
                continue;
            };
            let name = name.as_ref();
            if name.len() != 1 {
                continue;
            }
            let name = name.as_bytes().first().copied().unwrap_or_default();
            if !name.is_ascii_alphabetic() {
                continue;
            }
            let Some(value) = els.get(1).and_then(|v| encode_tag_value(name, v.as_ref())) else {
                continue;
            };
            out.push(name);
            out.push(u8::try_from(value.as_bytes().len()).unwrap_or(u8::MAX));
            out.extend_from_slice(value.as_bytes());
        }
        Self(out.into_boxed_slice())
    }

    /// The raw record bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrowing view over the record.
    #[must_use]
    pub fn packed(&self) -> PackedRef<'_> {
        PackedRef(&self.0)
    }
}

/// A validated borrowed view over a packed record.
#[derive(Debug, Clone, Copy)]
pub struct PackedRef<'a>(pub(crate) &'a [u8]);

impl<'a> PackedRef<'a> {
    /// Validate the record structure once; `None` on any malformed layout.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        let mut pos = HEADER_LEN;
        while pos < bytes.len() {
            let (name, len) = (bytes.get(pos)?, bytes.get(pos + 1)?);
            if !name.is_ascii_alphabetic() {
                return None;
            }
            pos += 2;
            if pos + usize::from(*len) > bytes.len() {
                return None;
            }
            pos += usize::from(*len);
        }
        Some(Self(bytes))
    }

    /// The raw record bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Event id.
    #[must_use]
    pub fn id(self) -> EventId {
        EventId(self.0.first_chunk::<32>().copied().unwrap_or_default())
    }

    /// Author public key.
    #[must_use]
    pub fn pubkey(self) -> PublicKey {
        PublicKey(
            self.0
                .get(32..64)
                .and_then(|s| <&[u8; 32]>::try_from(s).ok())
                .copied()
                .unwrap_or_default(),
        )
    }

    /// `created_at` seconds.
    #[must_use]
    pub fn created_at(self) -> u64 {
        self.u64_at(64)
    }

    /// Event kind.
    #[must_use]
    pub fn kind(self) -> Kind {
        Kind(
            self.0
                .get(72..74)
                .and_then(|s| <&[u8; 2]>::try_from(s).ok())
                .map_or_default(|s| u16::from_le_bytes(*s)),
        )
    }

    /// NIP-40 `expiration` unix time, `0` when absent.
    #[must_use]
    pub fn expiration(self) -> u64 {
        self.u64_at(74)
    }

    /// Iterate the packed tag index entries `(name, encoded value)`.
    pub fn tags(self) -> impl Iterator<Item = (u8, &'a [u8])> {
        let mut pos = HEADER_LEN;
        core::iter::from_fn(move || {
            let name = *self.0.get(pos)?;
            let len = usize::from(*self.0.get(pos + 1)?);
            let value = self.0.get(pos + 2..pos + 2 + len)?;
            pos += 2 + len;
            Some((name, value))
        })
    }

    /// The first packed `d` value, or empty.
    #[must_use]
    pub fn d_tag(self) -> &'a [u8] {
        self.tags()
            .find(|(name, _)| *name == b'd')
            .map_or(&[][..], |(_, value)| value)
    }

    fn u64_at(self, pos: usize) -> u64 {
        self.0
            .get(pos..pos + 8)
            .and_then(|s| <&[u8; 8]>::try_from(s).ok())
            .map_or_default(|s| u64::from_le_bytes(*s))
    }
}
