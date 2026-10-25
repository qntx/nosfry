//! NIP-42 authentication rules and the per-subscription read gate.
//!
//! [`AuthRules`] carries the configured service URL, the restricted
//! read kinds, and the `involved_only` policy. [`ReadGate`] is the
//! snapshot taken at REQ time — the rules plus the connection's
//! authenticated pubkeys — that stored scans and live monitors
//! consult per event.

use std::sync::Arc;

use serde::Deserialize;

use crate::event::PublicKey;
use crate::filter::Filter;
use crate::kind::Kind;
use crate::moderation::Moderation;
use crate::packed::PackedRef;
use crate::url::RelayUrl;

/// The NIP-42 authentication event kind.
pub const AUTH_KIND: Kind = Kind(22242);

/// Maximum distinct pubkeys a connection may authenticate (NIP-42
/// treats every authenticated pubkey as valid for the connection).
pub const MAX_AUTHED_PUBKEYS: usize = 8;

/// `[relay.auth]` — NIP-42 restricted read kinds (strfry
/// `relay.auth.*`; the URL is the relay's `service_url`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Kinds served only to authenticated readers.
    pub restricted_read_kinds: Vec<u16>,
    /// Restricted kinds are served only to authenticated pubkeys
    /// involved in the event (author or `p` tag); `false` serves them
    /// to any authenticated reader.
    pub restrict_read_to_involved: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            restricted_read_kinds: vec![4, 1059],
            restrict_read_to_involved: true,
        }
    }
}

/// Authentication configuration: the relay's own service URL and the
/// read-side restrictions.
///
/// `Default` disables AUTH entirely and restricts nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRules {
    /// The relay's own URL when AUTH is enabled.
    relay: Option<RelayUrl>,
    /// Sorted, deduplicated kinds hidden from unauthorized readers.
    restricted_kinds: Box<[u16]>,
    /// Restricted events are served only to authenticated pubkeys
    /// involved in the event (author or `p` tag).
    involved_only: bool,
}

impl AuthRules {
    /// New rules. `None` disables AUTH (protected events are rejected
    /// outright and restricted kinds are never served).
    #[must_use]
    pub fn new(relay: Option<RelayUrl>, restricted_kinds: &[u16], involved_only: bool) -> Self {
        let mut restricted_kinds = restricted_kinds.to_vec();
        restricted_kinds.sort_unstable();
        restricted_kinds.dedup();
        Self {
            relay,
            restricted_kinds: restricted_kinds.into(),
            involved_only,
        }
    }

    /// The configured service URL (`None` = AUTH disabled).
    #[must_use]
    pub const fn relay(&self) -> Option<&RelayUrl> {
        self.relay.as_ref()
    }

    /// Whether AUTH is enabled (a service URL is configured).
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.relay.is_some()
    }

    /// Whether `kind` is restricted to authorized readers.
    #[must_use]
    pub fn is_restricted(&self, kind: u16) -> bool {
        self.restricted_kinds.binary_search(&kind).is_ok()
    }

    /// Whether a `relay` tag value names the configured service URL.
    pub(crate) fn matches_relay(&self, url: &str) -> bool {
        self.relay.as_ref().is_some_and(|relay| relay.matches(url))
    }

    /// Whether every filter is fully restricted — restricted kinds are
    /// configured, there is at least one filter, and every filter lists
    /// only restricted kinds (strfry `isFilterGroupFullyRestricted`).
    /// An unauthenticated REQ matching this is refused outright.
    pub(crate) fn fully_restricts(&self, filters: &[Filter]) -> bool {
        !self.restricted_kinds.is_empty()
            && !filters.is_empty()
            && filters.iter().all(|filter| {
                filter
                    .kinds()
                    .is_some_and(|kinds| kinds.iter().all(|kind| self.is_restricted(*kind)))
            })
    }
}

/// Per-subscription read visibility: the rules plus the pubkeys the
/// connection had authenticated at REQ time.
///
/// `Default` is an open gate (admin tooling, tests): nothing is
/// restricted and nothing is moderated.
#[derive(Debug, Clone, Default)]
pub struct ReadGate {
    /// Configured rules.
    pub(crate) rules: Arc<AuthRules>,
    /// Pubkeys authenticated on the connection at REQ time.
    pub(crate) authed: Arc<[PublicKey]>,
    /// The NIP-86 moderation snapshot at REQ time; `Default` moderates
    /// nothing.
    pub(crate) moderation: Arc<Moderation>,
}

impl ReadGate {
    /// A gate over `rules` for a connection that authenticated `authed`
    /// pubkeys (REQ-time snapshot).
    #[must_use]
    pub fn new(rules: Arc<AuthRules>, authed: Arc<[PublicKey]>) -> Self {
        Self {
            rules,
            authed,
            ..Self::default()
        }
    }

    /// Attach the NIP-86 moderation snapshot the subscription was
    /// opened under (REQ-time snapshot).
    #[must_use]
    pub fn with_moderation(mut self, moderation: Arc<Moderation>) -> Self {
        self.moderation = moderation;
        self
    }

    /// Whether this subscription may see `ev` (strfry
    /// `shouldSendToSubscriber`): unrestricted kinds always pass; a
    /// restricted kind needs an authenticated pubkey, and under
    /// `involved_only` that pubkey must be the author or a packed `p`
    /// tag value. Either way a moderated event — banned or unlisted
    /// author, banned id, disallowed kind — is never served.
    #[must_use]
    pub fn allows(&self, ev: PackedRef<'_>) -> bool {
        if !self.rules.is_restricted(ev.kind().0) {
            return !self.moderation.hides(ev);
        }
        if self.authed.is_empty() || self.moderation.hides(ev) {
            return false;
        }
        if !self.rules.involved_only {
            return true;
        }
        self.authed.contains(&ev.pubkey())
            || ev.tags().any(|(name, value)| {
                name == b'p'
                    && self
                        .authed
                        .iter()
                        .any(|pubkey| pubkey.0.as_slice() == value)
            })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;

    fn auth_rules(url: &str, kinds: &[u16], involved_only: bool) -> AuthRules {
        let url = if url.is_empty() {
            None
        } else {
            Some(RelayUrl::parse(url).unwrap())
        };
        AuthRules::new(url, kinds, involved_only)
    }

    fn gate(rules: &AuthRules, authed: &[[u8; 32]]) -> ReadGate {
        ReadGate::new(
            Arc::new(rules.clone()),
            authed.iter().map(|pk| PublicKey(*pk)).collect(),
        )
    }

    fn event(kind: u16, pubkey: u8, p_tag: Option<u8>) -> crate::packed::PackedEvent {
        let mut tags: Vec<Vec<String>> = Vec::new();
        if let Some(p) = p_tag {
            tags.push(vec!["p".to_owned(), faster_hex::hex_string(&[p; 32])]);
        }
        crate::packed::PackedEvent::build(
            &crate::event::EventId([9; 32]),
            &PublicKey([pubkey; 32]),
            0,
            Kind(kind),
            0,
            &tags,
        )
    }

    #[test]
    fn service_url_validation() {
        let ok = auth_rules("wss://Relay.Example.com/path?x", &[], false);
        assert!(ok.enabled());
        assert!(ok.matches_relay("wss://relay.example.com"));
        assert!(ok.matches_relay("wss://Relay.Example.com/sub#frag"));
        let disabled = auth_rules("", &[4], true);
        assert!(!disabled.enabled());
        assert!(!disabled.matches_relay("wss://x"));
    }

    #[test]
    fn restricted_kinds_sorted_deduped() {
        let rules = auth_rules("", &[1059, 4, 1059, 4], true);
        assert_eq!(&*rules.restricted_kinds, &[4, 1059]);
        assert!(rules.is_restricted(4));
        assert!(rules.is_restricted(1059));
        assert!(!rules.is_restricted(1));
    }

    #[test]
    fn fully_restricts() {
        let rules = auth_rules("", &[4], true);
        let f = |json: &str| Filter::parse(json).unwrap();
        assert!(rules.fully_restricts(&[f(r#"{"kinds":[4]}"#)]));
        assert!(rules.fully_restricts(&[f(r#"{"kinds":[]}"#)]));
        assert!(!rules.fully_restricts(&[]));
        assert!(!rules.fully_restricts(&[f(r#"{"kinds":[4]}"#), f("{}")]));
        assert!(!rules.fully_restricts(&[f(r#"{"kinds":[4,1]}"#)]));
        assert!(!AuthRules::default().fully_restricts(&[f(r#"{"kinds":[4]}"#)]));
    }

    #[test]
    fn gate_allows() {
        let author = [1u8; 32];
        let tagged = [2u8; 32];
        let other = [3u8; 32];
        let rules = auth_rules("wss://relay.example", &[4], true);
        let dm = event(4, 1, Some(2));
        let note = event(1, 9, None);
        let packed = dm.packed();
        let note_packed = note.packed();

        assert!(gate(&rules, &[]).allows(note_packed), "unrestricted kind");
        assert!(!gate(&rules, &[]).allows(packed), "restricted, unauth");
        assert!(gate(&rules, &[author]).allows(packed), "author");
        assert!(gate(&rules, &[tagged]).allows(packed), "p-tag recipient");
        assert!(!gate(&rules, &[other]).allows(packed), "uninvolved");
        assert!(
            gate(&rules, &[other, tagged]).allows(packed),
            "any of multiple"
        );
        let open = auth_rules("wss://relay.example", &[4], false);
        assert!(
            gate(&open, &[other]).allows(packed),
            "involved_only = false"
        );
    }

    #[test]
    fn gate_hides_moderated_events() {
        use crate::event::EventId;
        use crate::moderation::Moderation;

        let author = [1u8; 32];
        let tagged = [2u8; 32];
        let rules = auth_rules("wss://relay.example", &[4], true);
        let mut moderation = Moderation::default();
        moderation.banned_pubkeys.insert(PublicKey(author), None);
        moderation.disallowed_kinds.insert(7);
        // The shared `event` helper pins id [9;32]; use a distinct
        // one so the banned-id rule is what hides this frame.
        let banned_id = crate::packed::PackedEvent::build(
            &EventId([7; 32]),
            &PublicKey([9; 32]),
            0,
            Kind(1),
            0,
            Vec::<Vec<String>>::new(),
        );
        moderation.banned_events.insert(EventId([7; 32]), None);
        let moderated = gate(&rules, &[tagged]).with_moderation(Arc::new(moderation));

        // An unrestricted note by the banned author is hidden.
        assert!(!moderated.allows(event(1, 1, None).packed()));
        // A disallowed kind is hidden.
        assert!(!moderated.allows(event(7, 9, None).packed()));
        // A banned id is hidden.
        assert!(!moderated.allows(banned_id.packed()));
        // A restricted DM by the banned author stays hidden even for
        // the involved, authenticated reader.
        assert!(!moderated.allows(event(4, 1, Some(2)).packed()));
        // The same frames pass once the moderation snapshot is gone.
        let open = gate(&rules, &[tagged]);
        assert!(open.allows(event(1, 1, None).packed()));
        assert!(open.allows(event(4, 1, Some(2)).packed()));
    }
}
