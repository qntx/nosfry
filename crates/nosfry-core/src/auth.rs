//! NIP-42 authentication rules and the per-subscription read gate.
//!
//! [`AuthRules`] carries the relay names AUTH binds to plus the
//! compiled `[relay.access]` table ([`AccessRules`]). [`ReadGate`] is
//! the snapshot taken at REQ time — the rules, the connection's
//! authenticated pubkeys, and the moderation snapshot — that stored
//! scans and live monitors consult per event.

use std::sync::Arc;

use crate::access::AccessRules;
use crate::event::PublicKey;
use crate::filter::Filter;
use crate::kind::Kind;
use crate::moderation::Moderation;
use crate::packed::PackedRef;
use crate::url::RelayNames;

/// The NIP-42 authentication event kind.
pub const AUTH_KIND: Kind = Kind(22242);

/// Maximum distinct pubkeys a connection may authenticate (NIP-42
/// treats every authenticated pubkey as valid for the connection).
pub const MAX_AUTHED_PUBKEYS: usize = 8;

/// Authentication and access: the relay's own names plus the
/// compiled per-kind rules every decision goes through.
///
/// `Default` disables AUTH entirely and gates nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRules {
    /// The relay's own names when AUTH is enabled — the canonical
    /// `service_url` plus its aliases.
    names: RelayNames,
    /// The compiled `[relay.access]` rules.
    access: AccessRules,
}

impl AuthRules {
    /// New rules. Empty `names` disables AUTH (protected events are
    /// rejected outright and no read rule can be satisfied).
    #[must_use]
    pub const fn new(names: RelayNames, access: AccessRules) -> Self {
        Self { names, access }
    }

    /// The configured names (empty = AUTH disabled).
    #[must_use]
    pub const fn names(&self) -> &RelayNames {
        &self.names
    }

    /// The compiled access rules.
    #[must_use]
    pub const fn access(&self) -> &AccessRules {
        &self.access
    }

    /// Whether AUTH is enabled (a service URL is configured).
    #[must_use]
    pub const fn enabled(&self) -> bool {
        !self.names.is_empty()
    }

    /// Whether the relay guards gift wraps — AUTH enabled and kind
    /// 1059 read-restricted — advertised as NIP-59 in NIP-11.
    #[must_use]
    pub fn guards_gift_wraps(&self) -> bool {
        self.enabled() && self.access.rule(1059).restricts_reads()
    }

    /// Whether a `relay` tag value names one of the configured names.
    pub(crate) fn matches_relay(&self, url: &str) -> bool {
        self.names.matches(url)
    }

    /// Whether this read earns the lazy AUTH challenge: AUTH enabled,
    /// no authenticated pubkey on the connection, and the filters may
    /// match read-restricted kinds. The session sends
    /// `Command::Send(AUTH)` before the operation whenever this holds,
    /// so it is also the NIP-67 `auth` hint's truth condition — it
    /// never inspects stored data.
    pub(crate) fn challenges(&self, authed: &[PublicKey], filters: &[Filter]) -> bool {
        self.enabled() && authed.is_empty() && self.access.may_restrict(filters)
    }

    /// Whether every filter can only match read-restricted kinds —
    /// an unauthenticated REQ matching this is refused outright.
    /// AUTH being disabled does not weaken the check: there is no
    /// reader to serve either way.
    pub(crate) fn fully_restricts(&self, filters: &[Filter]) -> bool {
        self.access.fully_restricts(filters)
    }
}

/// Per-subscription read visibility: the rules plus the pubkeys the
/// connection had authenticated at REQ time.
///
/// `Default` is an open gate (admin tooling, tests): no rules
/// restrict and nothing is moderated.
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

    /// Whether this subscription may see `ev`: the moderation hide
    /// first (bans, disallowed kinds, the allow-list identity), then
    /// the kind's read rule evaluated against the REQ-time
    /// authenticated set.
    #[must_use]
    pub fn allows(&self, ev: PackedRef<'_>) -> bool {
        self.rules
            .access
            .read_allows(ev, &self.authed, &self.moderation)
    }

    /// The NIP-67 `auth` hint for `filters`: true exactly when the
    /// session issued the lazy AUTH challenge for this read — AUTH
    /// enabled, no pubkey authenticated at REQ time, and the filters
    /// may match read-restricted kinds. Data-independent: it never
    /// reveals whether hidden events exist.
    #[must_use]
    pub fn auth_hint(&self, filters: &[Filter]) -> bool {
        self.rules.challenges(&self.authed, filters)
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
    use crate::access::{AccessConfig, Reader, RuleConfig, Writer};

    fn access(kinds: &[u16], read: Vec<Reader>) -> AccessRules {
        AccessRules::compile(&AccessConfig {
            rules: vec![RuleConfig {
                kinds: Some(kinds.to_vec()),
                read,
                write: Writer::Open,
            }],
            anonymous_kinds: Vec::new(),
        })
        .unwrap()
    }

    fn auth_rules(url: &str, access: AccessRules) -> AuthRules {
        AuthRules::new(RelayNames::parse(url, &[]).unwrap(), access)
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
        let ok = auth_rules("wss://Relay.Example.com/path?x", AccessRules::default());
        assert!(ok.enabled());
        assert!(ok.matches_relay("wss://relay.example.com"));
        assert!(ok.matches_relay("wss://Relay.Example.com/sub#frag"));
        let disabled = auth_rules("", access(&[4], vec![Reader::Author]));
        assert!(!disabled.enabled());
        assert!(!disabled.matches_relay("wss://x"));
    }

    /// Every configured name satisfies the `relay`-tag check; an
    /// unrelated name does not.
    #[test]
    fn aliases_match_relay() {
        let names =
            RelayNames::parse("wss://relay.example.com", &["ws://abc.onion".to_owned()]).unwrap();
        let rules = AuthRules::new(names, AccessRules::default());
        assert!(rules.matches_relay("wss://relay.example.com"));
        assert!(rules.matches_relay("ws://ABC.onion"));
        assert!(!rules.matches_relay("wss://unrelated.example.com"));
    }

    #[test]
    fn fully_restricts() {
        let rules = auth_rules("", access(&[4], vec![Reader::Author]));
        let f = |json: &str| Filter::parse(json).unwrap();
        assert!(rules.access.fully_restricts(&[f(r#"{"kinds":[4]}"#)]));
        assert!(rules.access.fully_restricts(&[f(r#"{"kinds":[]}"#)]));
        assert!(!rules.access.fully_restricts(&[]));
        assert!(
            !rules
                .access
                .fully_restricts(&[f(r#"{"kinds":[4]}"#), f("{}")])
        );
        assert!(!rules.access.fully_restricts(&[f(r#"{"kinds":[4,1]}"#)]));
        assert!(!AccessRules::default().fully_restricts(&[f(r#"{"kinds":[4]}"#)]));
    }

    #[test]
    fn may_restrict() {
        let rules = access(&[4, 1059], vec![Reader::Author]);
        let f = |json: &str| Filter::parse(json).unwrap();
        // No `kinds` or a listed restricted kind may match one.
        assert!(rules.may_restrict(&[f(r#"{"kinds":[1,1059]}"#)]));
        assert!(rules.may_restrict(&[f(
            r##"{"#p":["0000000000000000000000000000000000000000000000000000000000000000"]}"##
        )]));
        assert!(rules.may_restrict(&[f("{}")]));
        assert!(rules.may_restrict(&[f(r#"{"kinds":[4]}"#)]));
        // Only public kinds, an impossible filter, and no restricting
        // rule can never match one.
        assert!(!rules.may_restrict(&[f(r#"{"kinds":[1]}"#)]));
        assert!(!rules.may_restrict(&[f(r#"{"kinds":[]}"#)]));
        assert!(!rules.may_restrict(&[]));
        assert!(!AccessRules::default().may_restrict(&[f("{}")]));
    }

    #[test]
    fn gate_allows() {
        let author = [1u8; 32];
        let tagged = [2u8; 32];
        let other = [3u8; 32];
        let rules = auth_rules(
            "wss://relay.example",
            access(&[4], vec![Reader::Author, Reader::Recipient]),
        );
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
        let authed_only = auth_rules(
            "wss://relay.example",
            access(&[4], vec![Reader::Authenticated]),
        );
        assert!(
            gate(&authed_only, &[other]).allows(packed),
            "`authenticated` admits any authed reader"
        );
    }

    #[test]
    fn default_config_restricts_dms_and_wraps() {
        let rules = AccessRules::compile(&AccessConfig::default()).unwrap();
        for kind in [4, 1059, 21059] {
            assert!(rules.rule(kind).restricts_reads(), "kind {kind}");
        }
    }

    #[test]
    fn gate_hides_moderated_events() {
        use crate::event::EventId;

        let author = [1u8; 32];
        let tagged = [2u8; 32];
        let rules = auth_rules(
            "wss://relay.example",
            access(&[4], vec![Reader::Author, Reader::Recipient]),
        );
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
