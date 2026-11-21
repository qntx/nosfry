//! NIP-09 deletion targets derived from a kind-5 event's tags.

use std::borrow::Cow;

use crate::event::{EventId, PublicKey, address_hash};
use crate::hex;
use crate::kind::{Kind, KindClass};
use crate::packed::PackedRef;

/// One event or address a kind-5 event requests deleted (NIP-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeletionTarget {
    /// An `e` tag's event id.
    Event(EventId),
    /// An `a` tag's address hash ([`address_hash`] of kind ‖ author ‖ `d`).
    Address([u8; 32]),
}

/// Every target of a kind-5 event by `pubkey`: each valid `e` id and
/// each `a` value `"<kind>:<author>:<d>"` whose kind is replaceable or
/// addressable. Malformed and foreign-author values are skipped —
/// NIP-09 only affects the author's own events. The result is sorted
/// and deduplicated; it is empty for non-kind-5 events.
#[must_use]
pub(crate) fn targets(
    kind: Kind,
    pubkey: &PublicKey,
    tags: &[Vec<Cow<'_, str>>],
) -> Vec<DeletionTarget> {
    if kind.0 != 5 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for tag in tags {
        let Some(name) = tag.first() else {
            continue;
        };
        let Some(value) = tag.get(1) else {
            continue;
        };
        let target = match name.as_ref() {
            "e" => EventId::from_hex(value).map(DeletionTarget::Event),
            "a" => address_target(value, pubkey),
            _ => None,
        };
        if let Some(target) = target {
            out.push(target);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Whether `deleter` may `e`-delete the event `packed` is.
///
/// NIP-09 + NIP-59: the deleter's own event, or a kind-1059 gift
/// wrap `p`-tagged to the deleter (the wrap's signing key is random,
/// so NIP-59 lets every recipient delete it). Kinds 5 and 62 are
/// never deletable.
#[must_use]
pub fn deletes(packed: PackedRef<'_>, deleter: &PublicKey) -> bool {
    if matches!(packed.kind().0, 5 | 62) {
        return false;
    }
    packed.pubkey() == *deleter
        || (packed.kind().0 == 1059
            && packed
                .tags()
                .any(|(name, value)| name == b'p' && value == deleter.0.as_slice()))
}

/// The public keys whose kind 5 may `e`-delete or block `packed`.
///
/// The event's author, plus every packed `p` value when the event
/// is a kind-1059 gift wrap (NIP-59). Stores index block rows under
/// each yielded key.
pub fn blockers(packed: PackedRef<'_>) -> impl Iterator<Item = [u8; 32]> + '_ {
    let is_wrap = packed.kind().0 == 1059;
    std::iter::once(packed.pubkey().0).chain(packed.tags().filter_map(move |(name, value)| {
        if is_wrap && name == b'p' {
            <&[u8; 32]>::try_from(value).ok().copied()
        } else {
            None
        }
    }))
}

/// `"<kind>:<pubkey>:<d>"` → address target; `d` is everything after
/// the second colon (empty for replaceable kinds, may contain `:`).
fn address_target(value: &str, author: &PublicKey) -> Option<DeletionTarget> {
    let (kind, rest) = value.split_once(':')?;
    let (target_pubkey, d) = rest.split_once(':')?;
    let kind = kind.parse::<u16>().ok().map(Kind)?;
    if !matches!(
        kind.class(),
        KindClass::Replaceable | KindClass::Addressable
    ) || hex::decode_32(target_pubkey) != Some(author.0)
    {
        return None;
    }
    Some(DeletionTarget::Address(address_hash(
        kind,
        author,
        d.as_bytes(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packed::PackedEvent;

    fn packed(kind: u16, pubkey: u8, p_tags: &[u8]) -> PackedEvent {
        let tags: Vec<Vec<String>> = p_tags
            .iter()
            .map(|p| vec!["p".to_owned(), faster_hex::hex_string(&[*p; 32])])
            .collect();
        PackedEvent::build(
            &EventId([9; 32]),
            &PublicKey([pubkey; 32]),
            0,
            Kind(kind),
            0,
            &tags,
        )
    }

    fn blockers_of(packed: PackedRef<'_>) -> Vec<[u8; 32]> {
        blockers(packed).collect()
    }

    #[test]
    fn deletes_own_event_or_recipient_wrap_only() {
        let author = PublicKey([1; 32]);
        let recipient = PublicKey([2; 32]);
        let third = PublicKey([3; 32]);
        let wrap = packed(1059, 9, &[2, 4]);
        let dm = packed(4, 9, &[2]);
        let note = packed(1, 1, &[]);
        let carrier = packed(5, 1, &[]);
        let vanish = packed(62, 1, &[]);

        assert!(deletes(note.packed(), &author), "own event");
        assert!(!deletes(note.packed(), &recipient), "foreign event");
        assert!(deletes(wrap.packed(), &recipient), "wrap's p recipient");
        assert!(!deletes(wrap.packed(), &third), "uninvolved key");
        assert!(!deletes(wrap.packed(), &author), "author is not a p key");
        assert!(
            !deletes(dm.packed(), &recipient),
            "only kind 1059 is deletable by a p key"
        );
        assert!(!deletes(carrier.packed(), &author), "kind 5 immune");
        assert!(!deletes(vanish.packed(), &author), "kind 62 immune");
    }

    #[test]
    fn blockers_cover_author_and_all_wrap_recipients() {
        let wrap = packed(1059, 9, &[2, 4]);
        assert_eq!(
            blockers_of(wrap.packed()),
            vec![[9; 32], [2; 32], [4; 32]],
            "author plus every packed p value"
        );
        let dm = packed(4, 9, &[2, 4]);
        assert_eq!(blockers_of(dm.packed()), vec![[9; 32]]);
        let note = packed(1, 9, &[]);
        assert_eq!(blockers_of(note.packed()), vec![[9; 32]]);
    }
}
