//! Per-kind access rules — the NIP-42 read/write gate and the
//! allow-list identity both editions share.
//!
//! `[relay.access]` compiles into [`AccessRules`]: a sorted
//! kind→rule table plus at most one catch-all rule (a rule without
//! `kinds`). A kind follows the rule listing it, else the catch-all,
//! else it is open. Resolution is order-independent — the loader
//! refuses a kind listed twice or two catch-all rules.
//!
//! Every access decision lives here: the stored/live read gate
//! ([`AccessRules::read_allows`]), the lazy AUTH challenge predicates
//! (`may_restrict`, `fully_restricts`), the publish-side moderation
//! plus allow-list check ([`AccessRules::write_blocked`]) and
//! NIP-11's `restricted_writes`.

use serde::Deserialize;
use thiserror::Error;

use crate::event::{Event, PublicKey};
use crate::filter::Filter;
use crate::moderation::Moderation;
use crate::packed::PackedRef;

/// `read` principal: authenticated, event author, `p` tag recipient,
/// or a member of the NIP-86 `allowed_pubkeys` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reader {
    /// Any authenticated pubkey.
    Authenticated,
    /// The event's author.
    Author,
    /// Any `p` tag value of the event.
    Recipient,
    /// A pubkey on the gate's moderation allow list — an empty allow
    /// list admits nobody.
    Allowed,
}

/// `read` bit flags on a compiled [`Rule`].
const AUTHENTICATED: u8 = 1;
const AUTHOR: u8 = 2;
const RECIPIENT: u8 = 4;
const ALLOWED: u8 = 8;

impl Reader {
    const fn bit(self) -> u8 {
        match self {
            Self::Authenticated => AUTHENTICATED,
            Self::Author => AUTHOR,
            Self::Recipient => RECIPIENT,
            Self::Allowed => ALLOWED,
        }
    }
}

/// The `read` bitset of one rule: every principal unique, and
/// `authenticated` never combined (it subsumes the others).
fn read_bits(readers: &[Reader]) -> Result<u8, AccessError> {
    let mut read = 0u8;
    for reader in readers {
        let bit = reader.bit();
        if read & bit != 0 {
            return Err(AccessError::DuplicateReader);
        }
        read |= bit;
    }
    if read != AUTHENTICATED && read & AUTHENTICATED != 0 {
        return Err(AccessError::AuthenticatedCombined);
    }
    Ok(read)
}

/// Push `(kind, rule)` for every kind in `list`, refusing a kind
/// another rule already claimed.
fn register(kinds: &mut Vec<(u16, Rule)>, list: &[u16], rule: Rule) -> Result<(), AccessError> {
    for &kind in list {
        if kinds.iter().any(|(k, _)| *k == kind) {
            return Err(AccessError::DuplicateKind(kind));
        }
        kinds.push((kind, rule));
    }
    Ok(())
}

/// `write` rule: open, any authenticated pubkey, or the authenticated
/// event author only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Writer {
    /// Anyone may publish.
    #[default]
    Open,
    /// AUTH first; any authenticated pubkey may publish.
    Authenticated,
    /// AUTH first, as the event's own author.
    Author,
}

/// One `[[relay.access.rules]]` entry. Without `kinds` it is the
/// catch-all every unlisted kind follows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleConfig {
    /// The kinds this rule covers; omitted = the catch-all.
    pub kinds: Option<Vec<u16>>,
    /// Principals that may read; `[]` = open to every reader.
    pub read: Vec<Reader>,
    /// The write gate for these kinds.
    pub write: Writer,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            kinds: None,
            read: Vec::new(),
            write: Writer::Open,
        }
    }
}

/// The stock rule: DMs and both gift-wrap kinds to author or `p`
/// recipient only.
fn default_rules() -> Vec<RuleConfig> {
    vec![RuleConfig {
        kinds: Some(vec![4, 1059, 21059]),
        read: vec![Reader::Author, Reader::Recipient],
        write: Writer::Open,
    }]
}

/// `[relay.access]` — per-kind access rules. `Default` is the DM
/// inbox; `rules = []` disables all gating.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccessConfig {
    /// The rules a kind resolves through; at most one may omit
    /// `kinds` (the catch-all).
    pub rules: Vec<RuleConfig>,
    /// Kinds whose author is not an identity (single-use keys, e.g.
    /// Marmot group messages): exempt from the NIP-86 pubkey allow
    /// list.
    pub anonymous_kinds: Vec<u16>,
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            rules: default_rules(),
            anonymous_kinds: Vec::new(),
        }
    }
}

/// Why a [`AccessConfig`] fails to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AccessError {
    /// A kind listed by more than one rule.
    #[error("kind {0} is listed by more than one rule")]
    DuplicateKind(u16),
    /// More than one rule without `kinds`.
    #[error("more than one rule has no `kinds` list")]
    DuplicateFallback,
    /// A `kinds` list with no entries — omit the key for the
    /// catch-all.
    #[error("a rule's `kinds` list is empty")]
    EmptyKinds,
    /// The same principal twice in one `read` list.
    #[error("`read` lists the same principal twice")]
    DuplicateReader,
    /// `authenticated` is redundant combined with another principal.
    #[error("`authenticated` may not be combined with other read principals")]
    AuthenticatedCombined,
}

/// The rule a kind resolves to: read as a principal bitset (0 =
/// open), write as the [`Writer`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rule {
    /// [`Reader`] bitset; 0 means open to every reader.
    pub(crate) read: u8,
    /// The write gate.
    pub write: Writer,
}

impl Rule {
    /// Whether reads of this kind are gated.
    #[must_use]
    pub const fn restricts_reads(self) -> bool {
        self.read != 0
    }

    /// Whether writes of this kind are gated.
    #[must_use]
    pub const fn restricts_writes(self) -> bool {
        !matches!(self.write, Writer::Open)
    }

    /// Whether this kind is gated on either side.
    #[must_use]
    pub const fn restricts(self) -> bool {
        self.restricts_reads() || self.restricts_writes()
    }
}

/// The compiled rule table — a sorted `kind → rule` map plus the
/// optional catch-all and the sorted anonymous kinds.
///
/// `Default` is fully open: no rules, no anonymous kinds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessRules {
    /// Sorted `(kind, rule)` entries.
    kinds: Box<[(u16, Rule)]>,
    /// The one rule without `kinds`, when configured.
    fallback: Option<Rule>,
    /// Sorted, deduplicated kinds exempt from the pubkey allow list.
    anonymous_kinds: Box<[u16]>,
}

impl AccessRules {
    /// Validate `config` and compile it. The result is
    /// order-independent: explicit kinds always beat the catch-all.
    ///
    /// # Errors
    ///
    /// [`AccessError`] for a kind listed twice, two catch-alls, an
    /// empty `kinds`, a duplicated `read` principal, or
    /// `authenticated` combined with another principal.
    pub fn compile(config: &AccessConfig) -> Result<Self, AccessError> {
        let mut kinds: Vec<(u16, Rule)> = Vec::new();
        let mut fallback = None;
        for rule in &config.rules {
            let compiled = Rule {
                read: read_bits(&rule.read)?,
                write: rule.write,
            };
            match &rule.kinds {
                None if fallback.replace(compiled).is_some() => {
                    return Err(AccessError::DuplicateFallback);
                }
                None => {}
                Some(list) if list.is_empty() => return Err(AccessError::EmptyKinds),
                Some(list) => register(&mut kinds, list, compiled)?,
            }
        }
        kinds.sort_unstable_by_key(|(kind, _)| *kind);
        let mut anonymous_kinds = config.anonymous_kinds.clone();
        anonymous_kinds.sort_unstable();
        anonymous_kinds.dedup();
        Ok(Self {
            kinds: kinds.into(),
            fallback,
            anonymous_kinds: anonymous_kinds.into(),
        })
    }

    /// The rule `kind` follows: its own, the catch-all, or open.
    #[must_use]
    pub fn rule(&self, kind: u16) -> Rule {
        self.kinds
            .binary_search_by_key(&kind, |(k, _)| *k)
            .map_or_else(
                |_| self.fallback.unwrap_or_default(),
                |i| self.kinds.get(i).map_or_else(Rule::default, |(_, r)| *r),
            )
    }

    /// Whether `kind` is exempt from the pubkey allow list.
    fn anonymous(&self, kind: u16) -> bool {
        self.anonymous_kinds.binary_search(&kind).is_ok()
    }

    /// The kinds any rule gates (read or write), plus whether the
    /// catch-all gates — for the startup notice only.
    #[must_use]
    pub fn restricted(&self) -> (Vec<u16>, bool) {
        (
            self.kinds
                .iter()
                .filter(|(_, rule)| rule.restricts())
                .map(|(kind, _)| *kind)
                .collect(),
            self.fallback.is_some_and(Rule::restricts),
        )
    }

    /// Whether any rule gates reads at all.
    fn restricts_any_read(&self) -> bool {
        self.fallback.is_some_and(|rule| rule.read != 0)
            || self.kinds.iter().any(|(_, rule)| rule.read != 0)
    }

    /// Whether any rule gates writes — NIP-11 `restricted_writes`.
    #[must_use]
    pub fn restricts_writes(&self) -> bool {
        self.fallback.is_some_and(|rule| rule.write != Writer::Open)
            || self
                .kinds
                .iter()
                .any(|(_, rule)| rule.write != Writer::Open)
    }

    /// Whether some possible filter can match a read-restricted
    /// kind: a `kinds` filter through its kinds' rules, a kindless
    /// filter through any restricting rule including the catch-all.
    /// Impossible filters never restrict.
    pub(crate) fn may_restrict(&self, filters: &[Filter]) -> bool {
        self.restricts_any_read()
            && filters.iter().any(|filter| {
                !filter.is_impossible()
                    && filter
                        .kinds()
                        .is_none_or(|kinds| kinds.iter().any(|kind| self.rule(*kind).read != 0))
            })
    }

    /// Whether every filter can only match read-restricted kinds: a
    /// `kinds` list where every kind is restricted, or a kindless
    /// filter exactly when the catch-all restricts reads. `{"kinds":[]}`
    /// counts as fully restricted; an empty filter list never does.
    pub(crate) fn fully_restricts(&self, filters: &[Filter]) -> bool {
        self.restricts_any_read()
            && !filters.is_empty()
            && filters.iter().all(|filter| {
                filter.kinds().map_or_else(
                    || self.fallback.is_some_and(|rule| rule.read != 0),
                    |kinds| kinds.iter().all(|kind| self.rule(*kind).read != 0),
                )
            })
    }

    /// The NIP-86 allow-list identity — the single rule the write
    /// check and the read-side hide share so they cannot drift: the
    /// author is allowed, the kind is anonymous, or the event is a
    /// gift wrap (1059/21059) `p`-tagged to an allowed key.
    fn allow_listed(&self, moderation: &Moderation, ev: PackedRef<'_>) -> bool {
        if moderation.allowed_pubkeys.is_empty() {
            return true;
        }
        if moderation.allowed_pubkeys.contains_key(&ev.pubkey()) {
            return true;
        }
        let kind = ev.kind().0;
        self.anonymous(kind)
            || ((kind == 1059 || kind == 21059)
                && ev.tags().any(|(name, value)| {
                    name == b'p'
                        && <[u8; 32]>::try_from(value).is_ok_and(|key| {
                            moderation.allowed_pubkeys.contains_key(&PublicKey(key))
                        })
                }))
    }

    /// The `blocked:` reason `ev` earns from the moderation lists and
    /// the allow-list identity — `None` when clean. Author bans,
    /// banned ids, and kind allow/disallow lists apply to everything
    /// unchanged; the pubkey allow list goes through
    /// [`Self::allow_listed`].
    fn blocked(&self, moderation: &Moderation, ev: PackedRef<'_>) -> Option<&'static str> {
        if moderation.banned_pubkeys.is_empty()
            && moderation.allowed_pubkeys.is_empty()
            && moderation.banned_events.is_empty()
            && moderation.disallowed_kinds.is_empty()
            && moderation.allowed_kinds.is_empty()
        {
            return None;
        }
        if moderation.banned_pubkeys.contains_key(&ev.pubkey())
            || !self.allow_listed(moderation, ev)
        {
            return Some("blocked: pubkey not allowed");
        }
        if moderation.banned_events.contains_key(&ev.id()) {
            return Some("blocked: event banned");
        }
        let kind = ev.kind().0;
        if moderation.disallowed_kinds.contains(&kind)
            || (!moderation.allowed_kinds.is_empty() && !moderation.allowed_kinds.contains(&kind))
        {
            return Some("blocked: kind not allowed");
        }
        None
    }

    /// `blocked` for a publish. The caller exempts AUTH events and
    /// relay-scoped requests to vanish first.
    #[must_use]
    pub fn write_blocked(&self, moderation: &Moderation, event: &Event) -> Option<&'static str> {
        self.blocked(moderation, event.packed())
    }

    /// The one-rule shape tests use most: `kinds` gated to `author`
    /// + `recipient`, every other kind open.
    ///
    /// # Panics
    ///
    /// Never — a single explicit rule always compiles.
    #[cfg(feature = "test-util")]
    #[must_use]
    #[allow(
        clippy::unwrap_used,
        reason = "a single explicit rule cannot fail to compile"
    )]
    pub fn involved(kinds: &[u16]) -> Self {
        Self::compile(&AccessConfig {
            rules: vec![RuleConfig {
                kinds: Some(kinds.to_vec()),
                read: vec![Reader::Author, Reader::Recipient],
                write: Writer::Open,
            }],
            anonymous_kinds: Vec::new(),
        })
        .unwrap()
    }

    /// Whether `ev` is served to a connection that authenticated the
    /// `authed` pubkeys (REQ-time snapshot): the moderation hide
    /// first, then the kind's read rule — open when empty, else any
    /// listed principal satisfied by one authenticated pubkey.
    #[must_use]
    pub fn read_allows(
        &self,
        ev: PackedRef<'_>,
        authed: &[PublicKey],
        moderation: &Moderation,
    ) -> bool {
        if self.blocked(moderation, ev).is_some() {
            return false;
        }
        let rule = self.rule(ev.kind().0);
        if rule.read == 0 {
            return true;
        }
        if authed.is_empty() {
            return false;
        }
        (rule.read & AUTHENTICATED != 0)
            || (rule.read & AUTHOR != 0 && authed.contains(&ev.pubkey()))
            || (rule.read & RECIPIENT != 0
                && ev.tags().any(|(name, value)| {
                    name == b'p' && authed.iter().any(|pk| pk.0.as_slice() == value)
                }))
            || (rule.read & ALLOWED != 0
                && authed
                    .iter()
                    .any(|pk| moderation.allowed_pubkeys.contains_key(pk)))
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
    use crate::event::EventId;
    use crate::kind::Kind;
    use crate::packed::PackedEvent;

    fn compile(rules: Vec<RuleConfig>) -> Result<AccessRules, AccessError> {
        AccessRules::compile(&AccessConfig {
            rules,
            anonymous_kinds: Vec::new(),
        })
    }

    fn rule(kinds: Option<Vec<u16>>, read: Vec<Reader>, write: Writer) -> RuleConfig {
        RuleConfig { kinds, read, write }
    }

    fn event(kind: u16, pubkey: u8, p_tag: Option<u8>) -> PackedEvent {
        let mut tags: Vec<Vec<String>> = Vec::new();
        if let Some(p) = p_tag {
            tags.push(vec!["p".to_owned(), faster_hex::hex_string(&[p; 32])]);
        }
        PackedEvent::build(
            &EventId([9; 32]),
            &PublicKey([pubkey; 32]),
            0,
            Kind(kind),
            0,
            &tags,
        )
    }

    #[test]
    fn validation_rejects_every_misshapen_config() {
        let open = || rule(None, Vec::new(), Writer::Open);
        assert_eq!(
            compile(vec![
                rule(Some(vec![4]), Vec::new(), Writer::Open),
                rule(Some(vec![1, 4]), Vec::new(), Writer::Open),
            ]),
            Err(AccessError::DuplicateKind(4))
        );
        assert_eq!(
            compile(vec![rule(Some(vec![4, 4]), Vec::new(), Writer::Open)]),
            Err(AccessError::DuplicateKind(4))
        );
        assert_eq!(
            compile(vec![open(), open()]),
            Err(AccessError::DuplicateFallback)
        );
        assert_eq!(
            compile(vec![rule(Some(vec![]), Vec::new(), Writer::Open)]),
            Err(AccessError::EmptyKinds)
        );
        assert_eq!(
            compile(vec![rule(
                Some(vec![4]),
                vec![Reader::Author, Reader::Author],
                Writer::Open
            )]),
            Err(AccessError::DuplicateReader)
        );
        assert_eq!(
            compile(vec![rule(
                Some(vec![4]),
                vec![Reader::Authenticated, Reader::Author],
                Writer::Open
            )]),
            Err(AccessError::AuthenticatedCombined)
        );
    }

    #[test]
    fn resolution_explicit_kind_beats_fallback() {
        let rules = compile(vec![
            rule(Some(vec![30078]), vec![Reader::Author], Writer::Author),
            rule(None, vec![Reader::Allowed], Writer::Open),
        ])
        .unwrap();
        assert_eq!(rules.rule(30078).read, AUTHOR);
        assert_eq!(rules.rule(30078).write, Writer::Author);
        assert_eq!(rules.rule(1).read, ALLOWED, "falls to the catch-all");
        assert_eq!(
            compile(Vec::new()).unwrap().rule(4).read,
            0,
            "unlisted is open"
        );
    }

    #[test]
    fn default_config_is_the_dm_inbox() {
        let rules = AccessRules::compile(&AccessConfig::default()).unwrap();
        for kind in [4, 1059, 21059] {
            assert_eq!(rules.rule(kind).read, AUTHOR | RECIPIENT, "kind {kind}");
        }
        assert_eq!(rules.rule(1).read, 0);
        assert_eq!(AccessConfig::default().anonymous_kinds, Vec::<u16>::new());
    }

    #[test]
    fn may_and_fully_restricts() {
        let f = |json: &str| Filter::parse(json).unwrap();
        let rules = compile(vec![rule(
            Some(vec![4]),
            vec![Reader::Author],
            Writer::Open,
        )])
        .unwrap();
        assert!(rules.may_restrict(&[f(r#"{"kinds":[1,4]}"#)]));
        assert!(rules.may_restrict(&[f("{}")]));
        assert!(!rules.may_restrict(&[f(r#"{"kinds":[1]}"#)]));
        assert!(!rules.may_restrict(&[f(r#"{"kinds":[]}"#)]));
        assert!(rules.fully_restricts(&[f(r#"{"kinds":[4]}"#)]));
        assert!(rules.fully_restricts(&[f(r#"{"kinds":[]}"#)]));
        assert!(!rules.fully_restricts(&[f("{}")]), "no catch-all rule");
        assert!(!rules.fully_restricts(&[]));

        // A restricting catch-all fully restricts kindless filters.
        let caught = compile(vec![rule(None, vec![Reader::Allowed], Writer::Open)]).unwrap();
        assert!(caught.fully_restricts(&[f("{}")]));
        assert!(caught.may_restrict(&[f("{}")]));
        // Open rules restrict nothing.
        let open = compile(Vec::new()).unwrap();
        assert!(!open.may_restrict(&[f("{}")]));
        assert!(!open.fully_restricts(&[f(r#"{"kinds":[4]}"#)]));
    }

    #[test]
    fn read_allows_each_principal() {
        let author = PublicKey([1; 32]);
        let tagged = PublicKey([2; 32]);
        let other = PublicKey([3; 32]);
        let rules = compile(vec![rule(
            Some(vec![4]),
            vec![Reader::Author, Reader::Recipient],
            Writer::Open,
        )])
        .unwrap();
        let open = Moderation::default();
        let dm = event(4, 1, Some(2));
        let note = event(1, 9, None);
        assert!(
            rules.read_allows(note.packed(), &[], &open),
            "unlisted kind"
        );
        assert!(
            !rules.read_allows(dm.packed(), &[], &open),
            "unauthenticated"
        );
        assert!(rules.read_allows(dm.packed(), &[author], &open));
        assert!(rules.read_allows(dm.packed(), &[tagged], &open));
        assert!(!rules.read_allows(dm.packed(), &[other], &open));

        let authed_rule = compile(vec![rule(
            Some(vec![4]),
            vec![Reader::Authenticated],
            Writer::Open,
        )])
        .unwrap();
        assert!(authed_rule.read_allows(dm.packed(), &[other], &open));

        let allowed_rule = compile(vec![rule(
            Some(vec![4]),
            vec![Reader::Allowed],
            Writer::Open,
        )])
        .unwrap();
        assert!(
            !allowed_rule.read_allows(dm.packed(), &[other], &open),
            "an empty allow list admits nobody"
        );
        let mut members = Moderation::default();
        members.allowed_pubkeys.insert(other, None);
        members.allowed_pubkeys.insert(author, None);
        assert!(allowed_rule.read_allows(dm.packed(), &[other], &members));
        assert!(!allowed_rule.read_allows(dm.packed(), &[tagged], &members));
    }

    /// The moderation hide covers every list shape: author bans,
    /// banned ids, disallowed kinds, and the non-empty allow lists.
    #[test]
    fn blocked_covers_every_moderated_shape() {
        let rules = compile(Vec::new()).unwrap();
        let mut m = Moderation::default();
        // Fast path: a wholly unmoderated snapshot hides nothing.
        assert!(rules.blocked(&m, event(1, 1, None).packed()).is_none());

        m.banned_pubkeys.insert(PublicKey([1; 32]), None);
        assert!(rules.blocked(&m, event(1, 1, None).packed()).is_some());
        assert!(rules.blocked(&m, event(1, 2, None).packed()).is_none());

        m.banned_pubkeys.clear();
        m.allowed_pubkeys.insert(PublicKey([1; 32]), None);
        assert!(rules.blocked(&m, event(1, 1, None).packed()).is_none());
        assert!(rules.blocked(&m, event(1, 2, None).packed()).is_some());

        m.allowed_pubkeys.clear();
        m.banned_events.insert(EventId([9; 32]), None);
        assert!(rules.blocked(&m, event(1, 1, None).packed()).is_some());

        m.banned_events.clear();
        m.disallowed_kinds.insert(4);
        assert!(rules.blocked(&m, event(4, 2, None).packed()).is_some());
        assert!(rules.blocked(&m, event(1, 2, None).packed()).is_none());

        m.disallowed_kinds.clear();
        m.allowed_kinds.insert(1);
        assert!(rules.blocked(&m, event(1, 2, None).packed()).is_none());
        assert!(rules.blocked(&m, event(4, 2, None).packed()).is_some());
    }

    /// The write check ([`AccessRules::write_blocked`], an [`Event`])
    /// and the read-side hide ([`AccessRules::blocked`], a
    /// [`PackedRef`]) run the same allow-list identity: a wrap to an
    /// allowed recipient passes both, one to a non-member fails both,
    /// an anonymous kind passes iff listed, and a banned author's
    /// wrap stays blocked.
    #[test]
    fn write_and_read_share_the_allow_list_identity() {
        let member = PublicKey([1; 32]);
        let rules = AccessRules::compile(&AccessConfig {
            rules: Vec::new(),
            anonymous_kinds: vec![445],
        })
        .unwrap();
        let mut m = Moderation::default();
        m.allowed_pubkeys.insert(member, None);

        // A signed event and its packed twin so both paths decide on
        // the same identity.
        let verified = |kind: u16, author: u8, ps: &[u8]| {
            let tags: Vec<Vec<String>> = ps
                .iter()
                .map(|p| vec!["p".to_owned(), faster_hex::hex_string(&[*p; 32])])
                .collect();
            let id = crate::event::event_id(
                crate::event::serialize_for_id(&PublicKey([author; 32]), 1, Kind(kind), &tags, "")
                    .as_bytes(),
            );
            let tag_json = serde_json::to_string(&tags).unwrap();
            let json = format!(
                r#"{{"id":"{id}","pubkey":"{}","created_at":1,"kind":{kind},"tags":{tag_json},"content":"","sig":"{}"}}"#,
                PublicKey([author; 32]),
                "ef".repeat(64)
            );
            let event = crate::event::UnverifiedEvent::parse_structural(&json)
                .unwrap()
                .verify_unsigned(&crate::event::EventLimits::default())
                .unwrap();
            let packed = PackedEvent::build(&id, &PublicKey([author; 32]), 1, Kind(kind), 0, &tags);
            (event, packed)
        };
        let agree = |ev: &Event, packed: &PackedEvent| {
            rules.write_blocked(&m, ev).is_some() == rules.blocked(&m, packed.packed()).is_some()
        };
        let (wrap_in, wrap_in_p) = verified(1059, 7, &[1]);
        let (wrap_out, wrap_out_p) = verified(1059, 7, &[2]);
        let (marmot, marmot_p) = verified(445, 7, &[2]);
        let (note, note_p) = verified(1, 7, &[]);
        assert!(agree(&wrap_in, &wrap_in_p), "wrap to a member");
        assert!(agree(&wrap_out, &wrap_out_p), "wrap to a non-member");
        assert!(agree(&marmot, &marmot_p), "anonymous kind");
        assert!(agree(&note, &note_p), "unlisted author");
        assert!(
            rules.write_blocked(&m, &wrap_in).is_none(),
            "member wrap passes"
        );
        assert_eq!(
            rules.write_blocked(&m, &wrap_out),
            Some("blocked: pubkey not allowed"),
            "non-member wrap blocked"
        );
        // Only the last of several `p` tags is allowed — the
        // lookup does not stop at the first miss.
        let (wrap_last, wrap_last_p) = verified(1059, 7, &[2, 3, 1]);
        assert!(agree(&wrap_last, &wrap_last_p));
        assert!(rules.write_blocked(&m, &wrap_last).is_none());
        assert!(
            rules.write_blocked(&m, &marmot).is_none(),
            "445 is anonymous"
        );
        assert_eq!(
            rules.write_blocked(&m, &note),
            Some("blocked: pubkey not allowed"),
            "unlisted author blocked"
        );

        m.banned_pubkeys.insert(PublicKey([7; 32]), None);
        assert_eq!(
            rules.write_blocked(&m, &wrap_in),
            Some("blocked: pubkey not allowed"),
            "a banned author's wrap stays blocked"
        );

        // An unlisted 445 author is blocked when 445 is not anonymous.
        let strict = AccessRules::compile(&AccessConfig::default()).unwrap();
        assert_eq!(
            strict.write_blocked(&m, &marmot),
            Some("blocked: pubkey not allowed"),
        );
    }
}
