//! Strict NIP-01 filter: compiled form and allocation-free matching.
//!
//! Conditions inside a filter are `AND`ed; missing lists are unconstrained;
//! empty `ids`/`authors`/`kinds` lists make the filter impossible (NIP-01).
//! Unknown keys are rejected (`unsupported:`), `search` (NIP-50) is
//! rejected, and `#` keys that are not exactly one ASCII letter are
//! rejected — a relay follows strfry and never silently widens a query.
//! `ids`, `authors`, `#e` and `#p` values are hex — accepted
//! case-insensitively, normalized to lowercase. Empty `#` value lists make
//! the filter impossible like empty `ids`/`authors`/`kinds` (NIP-01).

use std::borrow::Cow;

use serde::Deserialize;
use serde::de::{Deserializer as _, MapAccess, Visitor};
use serde_json::value::RawValue;

use crate::hex;
use crate::kind::Kind;
use crate::packed::{PackedRef, TagValueBuf, encode_tag_value};

/// Ordered `(key, value)` pairs of the raw filter object; duplicates are
/// preserved so [`Filter::compile`] can reject them like JSON.parse cannot.
struct Pairs<'a>(Vec<(Cow<'a, str>, &'a RawValue)>);

struct PairsVisitor;

impl<'de> Visitor<'de> for PairsVisitor {
    type Value = Pairs<'de>;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a filter object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut pairs = Vec::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((key, value)) = map.next_entry::<Cow<'de, str>, &'de RawValue>()? {
            pairs.push((key, value));
        }
        Ok(Pairs(pairs))
    }
}

/// Estimated bytes of one live-subscription index entry — a map
/// slot plus its `Vec` allocation in `monitor::Monitors`. Used by
/// [`Filter::approx_bytes`]; an order-of-magnitude budget unit, not
/// an exact RSS figure.
const INDEX_ENTRY_BYTES: usize = 128;

/// Fields inside a filter are `AND`ed.
#[derive(Debug, Clone, Eq)]
pub struct Filter {
    ids: Option<Box<[[u8; 32]]>>,
    authors: Option<Box<[[u8; 32]]>>,
    kinds: Option<Box<[u16]>>,
    since: Option<u64>,
    until: Option<u64>,
    limit: Option<u64>,
    tags: Box<[(u8, Box<[TagValueBuf]>)]>,
    impossible: bool,
}

impl PartialEq for Filter {
    /// Field-wise equality, except that every impossible filter
    /// compares equal — the canonical shape [`Filter::to_json`]
    /// emits (`{"ids":[]}`) must round-trip to an equal filter, and
    /// `{"kinds":[]}` keeps its fields so read policies like
    /// `fully_restricts` can still inspect them.
    fn eq(&self, other: &Self) -> bool {
        if self.impossible || other.impossible {
            return self.impossible == other.impossible;
        }
        self.ids == other.ids
            && self.authors == other.authors
            && self.kinds == other.kinds
            && self.tags == other.tags
            && self.since == other.since
            && self.until == other.until
            && self.limit == other.limit
    }
}

impl Filter {
    /// Parse a filter object from a JSON string.
    ///
    /// # Errors
    ///
    /// [`FilterError::Invalid`] on malformed values; duplicate keys are
    /// rejected (JSON.parse would take the last one — see the vector
    /// divergences).
    pub fn parse(json: &str) -> Result<Self, FilterError> {
        Self::from_raw(serde_json::from_str::<&RawValue>(json)?)
    }

    /// Parse a filter object from a borrowed raw JSON value.
    ///
    /// # Errors
    ///
    /// Same as [`Filter::parse`].
    pub fn from_raw(raw: &RawValue) -> Result<Self, FilterError> {
        let mut de = serde_json::Deserializer::from_str(raw.get());
        let Pairs(pairs) = de
            .deserialize_map(PairsVisitor)
            .map_err(|e| FilterError::Invalid(format!("filter: {e}")))?;
        de.end()
            .map_err(|e| FilterError::Invalid(format!("filter: {e}")))?;
        Self::compile(&pairs)
    }

    /// The `limit` value, if present.
    #[must_use]
    pub const fn limit(&self) -> Option<u64> {
        self.limit
    }

    /// The `since` value, if present.
    #[must_use]
    pub const fn since(&self) -> Option<u64> {
        self.since
    }

    /// The `until` value, if present.
    #[must_use]
    pub const fn until(&self) -> Option<u64> {
        self.until
    }

    /// A copy with `until` clamped to at most `until` — the earlier
    /// of the filter's own `until` and `until` wins.
    #[must_use]
    pub fn with_until(&self, until: u64) -> Self {
        let mut next = self.clone();
        next.until = Some(next.until.map_or(until, |own| own.min(until)));
        next
    }

    /// Number of `#` conditions.
    #[must_use]
    pub fn tag_filter_count(&self) -> usize {
        self.tags.len()
    }

    /// Whether this filter can never match (empty `ids`/`authors`/`kinds`,
    /// or a `#` condition whose values can never be packed).
    #[must_use]
    pub const fn is_impossible(&self) -> bool {
        self.impossible
    }

    /// Sorted, deduplicated `ids`, if present.
    #[must_use]
    pub fn ids(&self) -> Option<&[[u8; 32]]> {
        self.ids.as_deref()
    }

    /// Sorted, deduplicated `authors`, if present.
    #[must_use]
    pub fn authors(&self) -> Option<&[[u8; 32]]> {
        self.authors.as_deref()
    }

    /// Sorted `kinds`, if present.
    #[must_use]
    pub fn kinds(&self) -> Option<&[u16]> {
        self.kinds.as_deref()
    }

    /// `#` conditions as `(letter, sorted values)`.
    #[must_use]
    pub fn tags(&self) -> &[(u8, Box<[TagValueBuf]>)] {
        &self.tags
    }

    /// An estimate of the filter's compiled size plus the live
    /// monitor index entries a subscription holding it allocates:
    /// each `ids`/`authors` value costs 32 bytes of key plus one
    /// index entry, each kind 2 bytes plus an entry, each `#` value
    /// its packed length plus an entry. A budget unit for the
    /// subscription-byte limits, not exact RSS.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        let hexes = self
            .ids
            .iter()
            .chain(&self.authors)
            .map(|list| list.len())
            .sum::<usize>();
        let mut bytes = size_of::<Self>()
            + hexes * (32 + INDEX_ENTRY_BYTES)
            + self.kinds.as_ref().map_or(0, |kinds| kinds.len()) * (2 + INDEX_ENTRY_BYTES);
        for (_, values) in &self.tags {
            bytes += values
                .iter()
                .map(|value| value.as_bytes().len() + INDEX_ENTRY_BYTES)
                .sum::<usize>();
        }
        bytes
    }

    /// Sorted values of the `#<letter>` condition, if present.
    #[must_use]
    pub fn tag_values(&self, letter: u8) -> Option<&[TagValueBuf]> {
        self.tags
            .iter()
            .find(|(name, _)| *name == letter)
            .map(|(_, values)| &**values)
    }

    /// Intrinsic result bound implied by the filter itself, independent of
    /// any external cap: empty ids/kinds/authors => `0`, deduplicated ids
    /// count, explicit `limit`, or `None` when unbounded
    /// (`vectors/filter-limit.json`).
    ///
    /// The kinds cardinality mirrors nostr-tools `getFilterLimit`
    /// (filter.ts @ `8ffc628`): `authors * kinds` only when every kind
    /// is replaceable (one live event per author+kind); `authors *
    /// kinds * #d` only when every kind is addressable *and* a `#d`
    /// condition is present (one live event per author+kind+d value).
    /// Addressable kinds without `#d`, and kinds mixing classes, are
    /// unbounded — an author may store any number of `d` addresses.
    #[must_use]
    pub fn intrinsic_limit(&self) -> Option<u64> {
        if self.impossible {
            return Some(0);
        }
        let mut bound = self.limit;
        if let Some(ids) = &self.ids {
            bound = Some(bound.map_or(ids.len() as u64, |b| b.min(ids.len() as u64)));
        }
        if let (Some(kinds), Some(authors)) = (&self.kinds, &self.authors)
            && !kinds.is_empty()
            && !authors.is_empty()
            && let Some(card) = self.kinds_cardinality(kinds, authors)
        {
            bound = Some(bound.map_or(card, |b| b.min(card)));
        }
        bound
    }

    /// The author+kind cardinality a filter can hold: `authors *
    /// kinds` when every kind is replaceable, `authors * kinds * #d`
    /// when every kind is addressable and a `#d` condition is present,
    /// else `None`.
    fn kinds_cardinality(&self, kinds: &[u16], authors: &[[u8; 32]]) -> Option<u64> {
        if kinds.iter().all(|k| Kind(*k).is_replaceable()) {
            return Some((kinds.len() as u64).saturating_mul(authors.len() as u64));
        }
        if !kinds.iter().all(|k| Kind(*k).is_addressable()) {
            return None;
        }
        self.tags
            .iter()
            .find(|(name, _)| *name == b'd')
            .filter(|(_, values)| !values.is_empty())
            .map(|(_, values)| {
                (kinds.len() as u64)
                    .saturating_mul(authors.len() as u64)
                    .saturating_mul(values.len() as u64)
            })
    }

    /// Result bound after applying `max` as the external cap.
    #[must_use]
    pub fn effective_limit(&self, max: u64) -> u64 {
        self.intrinsic_limit().unwrap_or(max).min(max)
    }

    /// Canonical JSON: `Filter::parse` of the output produces an equal
    /// filter. An impossible filter serializes as `{"ids":[]}`.
    #[must_use]
    pub fn to_json(&self) -> String {
        if self.impossible {
            return r#"{"ids":[]}"#.to_owned();
        }
        let mut fields = Vec::new();
        if let Some(ids) = &self.ids {
            fields.push(hex_list("ids", ids));
        }
        if let Some(authors) = &self.authors {
            fields.push(hex_list("authors", authors));
        }
        if let Some(kinds) = &self.kinds {
            let values: Vec<String> = kinds.iter().map(u16::to_string).collect();
            fields.push(format!("\"kinds\":[{}]", values.join(",")));
        }
        for (name, values) in &self.tags {
            fields.push(tag_field(*name, values));
        }
        for (key, value) in [
            ("since", self.since),
            ("until", self.until),
            ("limit", self.limit),
        ] {
            if let Some(value) = value {
                fields.push(format!("\"{key}\":{value}"));
            }
        }
        format!("{{{}}}", fields.join(","))
    }

    /// Whether `ev` satisfies every present condition. Allocation-free.
    #[must_use]
    pub fn matches(&self, ev: PackedRef<'_>) -> bool {
        if self.impossible {
            return false;
        }
        if let Some(ids) = &self.ids
            && ids.binary_search(&ev.id().0).is_err()
        {
            return false;
        }
        if let Some(authors) = &self.authors
            && authors.binary_search(&ev.pubkey().0).is_err()
        {
            return false;
        }
        if let Some(kinds) = &self.kinds
            && kinds.binary_search(&ev.kind().0).is_err()
        {
            return false;
        }
        if let Some(since) = self.since
            && ev.created_at() < since
        {
            return false;
        }
        if let Some(until) = self.until
            && ev.created_at() > until
        {
            return false;
        }
        for (name, values) in &self.tags {
            let hit = ev.tags().any(|(n, v)| {
                n == *name && values.binary_search_by(|w| w.as_bytes().cmp(v)).is_ok()
            });
            if !hit {
                return false;
            }
        }
        true
    }

    fn compile(pairs: &[(Cow<'_, str>, &RawValue)]) -> Result<Self, FilterError> {
        let mut filter = Self {
            ids: None,
            authors: None,
            kinds: None,
            since: None,
            until: None,
            limit: None,
            tags: Box::new([]),
            impossible: false,
        };
        let mut tag_conditions: Vec<(u8, Box<[TagValueBuf]>)> = Vec::new();
        for (i, (key, raw)) in pairs.iter().enumerate() {
            let key = key.as_ref();
            if pairs.iter().take(i).any(|(prev, _)| prev.as_ref() == key) {
                return Err(FilterError::Invalid(format!("duplicate key `{key}`")));
            }
            match key {
                "ids" => filter.ids = Some(decode_hex_list(raw, "ids")?),
                "authors" => filter.authors = Some(decode_hex_list(raw, "authors")?),
                "kinds" => {
                    let mut kinds: Vec<u16> = parse_value(raw, "kinds")?;
                    kinds.sort_unstable();
                    kinds.dedup();
                    filter.kinds = Some(kinds.into_boxed_slice());
                }
                "since" => filter.since = Some(parse_value(raw, "since")?),
                "until" => filter.until = Some(parse_value(raw, "until")?),
                "limit" => filter.limit = Some(parse_value(raw, "limit")?),
                "search" => {
                    return Err(FilterError::Unsupported(
                        "search (NIP-50) is not supported".to_owned(),
                    ));
                }
                _ => compile_tag_condition(key, raw, &mut tag_conditions, &mut filter)?,
            }
        }
        if filter.ids.as_ref().is_some_and(|v| v.is_empty())
            || filter.authors.as_ref().is_some_and(|v| v.is_empty())
            || filter.kinds.as_ref().is_some_and(|v| v.is_empty())
        {
            filter.impossible = true;
        }
        tag_conditions.sort_by_key(|(name, _)| *name);
        filter.tags = tag_conditions.into_boxed_slice();
        Ok(filter)
    }
}

/// Compile one `#<letter>` condition. Unknown keys and `#` names that are
/// not exactly one ASCII letter are rejected (strfry relay policy); empty
/// value lists make the filter impossible (NIP-01); values that cannot be
/// packed can never match, so a non-empty list of them is impossible too.
fn compile_tag_condition(
    key: &str,
    raw: &RawValue,
    tag_conditions: &mut Vec<(u8, Box<[TagValueBuf]>)>,
    filter: &mut Filter,
) -> Result<(), FilterError> {
    let Some(name) = key.strip_prefix('#') else {
        return Err(FilterError::Unsupported(format!(
            "unrecognised filter item: {key}"
        )));
    };
    let mut chars = name.chars();
    let letter = chars.next().unwrap_or_default();
    if !letter.is_ascii_alphabetic() || chars.next().is_some() {
        return Err(FilterError::Unsupported(format!(
            "unindexed tag filter: {key}"
        )));
    }
    let values: Vec<Cow<'_, str>> = parse_value(raw, key)?;
    let mut encoded = Vec::with_capacity(values.len());
    for value in &values {
        let value = value.as_ref();
        if letter == 'e' || letter == 'p' {
            // NIP-01: `e`/`p` filter values are exact 64-char
            // lowercase hex (strfry accepts uppercase and `0x` —
            // a documented deviation).
            if hex::decode_32(value).is_none() {
                return Err(FilterError::Invalid(format!(
                    "`{key}` values must be 64 lowercase hex chars"
                )));
            }
        }
        if let Some(buf) = encode_tag_value(letter as u8, value) {
            encoded.push(buf);
        }
    }
    if encoded.is_empty() {
        filter.impossible = true;
        return Ok(());
    }
    encoded.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    encoded.dedup();
    tag_conditions.push((letter as u8, encoded.into_boxed_slice()));
    Ok(())
}

/// `ids`/`authors`: exactly 64 lowercase hex chars, deduplicated.
fn decode_hex_list(raw: &RawValue, key: &str) -> Result<Box<[[u8; 32]]>, FilterError> {
    let values: Vec<Cow<'_, str>> = parse_value(raw, key)?;
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let bytes = hex::decode_32(&value).ok_or_else(|| {
            FilterError::Invalid(format!("`{key}` values must be 64 lowercase hex chars"))
        })?;
        out.push(bytes);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out.into_boxed_slice())
}

fn parse_value<T: for<'de> Deserialize<'de>>(raw: &RawValue, key: &str) -> Result<T, FilterError> {
    serde_json::from_str(raw.get()).map_err(|e| FilterError::Invalid(format!("`{key}`: {e}")))
}

/// Filter validation failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FilterError {
    /// The value could not be parsed as JSON.
    #[error("malformed JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A field was malformed; `invalid:` reason.
    #[error("invalid: {0}")]
    Invalid(String),
    /// A field the relay does not support; `unsupported:` reason.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// `"key":["hex","hex"]"` — the ids/authors list fields.
fn hex_list(key: &str, values: &[[u8; 32]]) -> String {
    let mut field = format!("\"{key}\":[");
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            field.push(',');
        }
        field.push('"');
        field.push_str(&faster_hex::hex_string(value));
        field.push('"');
    }
    field.push(']');
    field
}

/// `"#x":[...]` — e/p values hex-encode their 32 packed bytes; other
/// names carry their original UTF-8 bytes as JSON strings.
fn tag_field(name: u8, values: &[TagValueBuf]) -> String {
    let mut field = format!("\"#{name}\":[", name = name as char);
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            field.push(',');
        }
        if name == b'e' || name == b'p' {
            field.push('"');
            field.push_str(&faster_hex::hex_string(value.as_bytes()));
            field.push('"');
        } else {
            field.push_str(
                &serde_json::to_string(&String::from_utf8_lossy(value.as_bytes()))
                    .unwrap_or_else(|_| "\"\"".to_owned()),
            );
        }
    }
    field.push(']');
    field
}

impl FilterError {
    /// NIP-01 machine-readable reason string; always prefixed.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Json(_) => format!("invalid: {self}"),
            Self::Invalid(_) | Self::Unsupported(_) => self.to_string(),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic"
)]
mod tests {
    use super::*;

    fn encode_32(bytes: &[u8; 32]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::with_capacity(64), |mut out, b| {
            write!(out, "{b:02x}").expect("write");
            out
        })
    }

    #[test]
    fn parses_plain_object() {
        let filter = Filter::parse(r#"{"kinds":[1,3]}"#).expect("parse");
        assert_eq!(filter.kinds(), Some(&[1u16, 3][..]));
        assert!(!filter.is_impossible());
    }

    #[test]
    fn with_until_keeps_the_earlier_bound() {
        let open = Filter::parse(r#"{"kinds":[1]}"#).expect("parse");
        assert_eq!(open.with_until(500).until(), Some(500));

        let later = Filter::parse(r#"{"until":900}"#).expect("parse");
        assert_eq!(later.with_until(500).until(), Some(500));

        let earlier = Filter::parse(r#"{"until":100}"#).expect("parse");
        assert_eq!(earlier.with_until(500).until(), Some(100));
    }

    #[test]
    fn approx_bytes_counts_fields_and_index_entries() {
        let base = size_of::<Filter>();
        let empty = Filter::parse("{}").expect("parse");
        assert_eq!(empty.approx_bytes(), base);

        let id = encode_32(&[0x0A; 32]);
        let filter = Filter::parse(&format!(r#"{{"ids":["{id}"],"authors":["{id}","{id}"]}}"#))
            .expect("parse");
        // Authors dedup to one; ids + authors = 2 hex keys.
        assert_eq!(filter.approx_bytes(), base + 2 * (32 + INDEX_ENTRY_BYTES));

        let kinds = Filter::parse(r#"{"kinds":[1,2,3]}"#).expect("parse");
        assert_eq!(kinds.approx_bytes(), base + 3 * (2 + INDEX_ENTRY_BYTES));

        // `p` values pack to 32 bytes, `t` keeps its UTF-8 bytes.
        let tagged =
            Filter::parse(&format!(r##"{{"#p":["{id}"],"#t":["ab","c"]}}"##)).expect("parse");
        let tags = (32 + INDEX_ENTRY_BYTES) + (2 + INDEX_ENTRY_BYTES) + (1 + INDEX_ENTRY_BYTES);
        assert_eq!(tagged.approx_bytes(), base + tags);
    }

    #[test]
    fn parses_tag_conditions() {
        let filter = Filter::parse(r##"{"#t":["a","b"],"kinds":[1]}"##).expect("parse");
        assert_eq!(filter.tag_filter_count(), 1);
        let [(name, values)] = filter.tags() else {
            panic!("one tag condition");
        };
        assert_eq!(*name, b't');
        let values: Vec<&[u8]> = values.iter().map(TagValueBuf::as_bytes).collect();
        assert_eq!(values, [&b"a"[..], &b"b"[..]]);
    }

    /// NIP-01 (01.md): `ids`/`authors`/`#e`/`#p` values must be exact
    /// 64-char lowercase hex — uppercase, `0x`, and other lengths are
    /// all `invalid:`. Other tag filters stay case-sensitive text.
    #[test]
    fn rejects_non_lowercase_filter_hex() {
        let lower = "ab".repeat(32);
        let upper = "AB".repeat(32);
        let mixed = format!("AB{}", "ab".repeat(31));
        let bad = [
            upper.clone(),
            mixed,
            format!("0x{lower}"),
            format!("0X{lower}"),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
        ];
        for key in ["ids", "authors"] {
            for value in &bad {
                let err = Filter::parse(&format!(r#"{{"{key}":["{value}"]}}"#)).unwrap_err();
                assert!(
                    err.reason().starts_with("invalid:"),
                    "{key} {value}: {}",
                    err.reason()
                );
            }
        }
        for tag in ["e", "p"] {
            for value in &bad {
                let err = Filter::parse(&format!(r##"{{"#{tag}":["{value}"]}}"##)).unwrap_err();
                assert!(
                    err.reason().starts_with("invalid:"),
                    "#{tag} {value}: {}",
                    err.reason()
                );
            }
        }
        // Lowercase hex decodes to bytes; `#t` keeps its case.
        let filter = Filter::parse(&format!(
            r##"{{"ids":["{lower}"],"#e":["{lower}"],"#t":["NOSTR"]}}"##
        ))
        .expect("parse");
        assert_eq!(filter.ids().map(<[_]>::len), Some(1));
        let tags = filter.tags();
        let e_values = tags
            .iter()
            .find(|(name, _)| *name == b'e')
            .map(|(_, values)| values)
            .expect("e condition");
        assert_eq!(
            e_values.first().map(TagValueBuf::as_bytes),
            Some(&[0xAB; 32][..])
        );
        let t_values = tags
            .iter()
            .find(|(name, _)| *name == b't')
            .map(|(_, values)| values)
            .expect("t condition");
        assert_eq!(
            t_values.first().map(TagValueBuf::as_bytes),
            Some(&b"NOSTR"[..])
        );
    }

    #[test]
    fn rejects_duplicate_keys() {
        let err = Filter::parse(r#"{"kinds":[9],"kinds":[1]}"#).expect_err("dup");
        assert!(err.reason().starts_with("invalid:"), "{}", err.reason());
    }

    #[test]
    fn rejects_unknown_keys() {
        for json in [r#"{"foo":1}"#, r#"{"search":"nostr"}"#, r#"{"search":42}"#] {
            let err = Filter::parse(json).expect_err(json);
            assert!(err.reason().starts_with("unsupported:"), "{}", err.reason());
        }
    }

    #[test]
    fn rejects_unindexed_tag_keys() {
        for json in [
            r##"{"#custom":["x"]}"##,
            r##"{"#1":["x"]}"##,
            r##"{"#":["x"]}"##,
        ] {
            let err = Filter::parse(json).expect_err(json);
            assert!(err.reason().starts_with("unsupported:"), "{}", err.reason());
        }
    }

    #[test]
    fn empty_tag_list_is_impossible() {
        let filter = Filter::parse(r##"{"#t":[]}"##).expect("parse");
        assert!(filter.is_impossible());
        assert_eq!(filter.intrinsic_limit(), Some(0));
    }

    #[test]
    fn empty_lists_are_impossible() {
        for json in [r#"{"ids":[]}"#, r#"{"authors":[]}"#, r#"{"kinds":[]}"#] {
            assert!(Filter::parse(json).expect(json).is_impossible(), "{json}");
        }
    }

    #[test]
    fn accepts_u64_beyond_js_safe_range() {
        let filter = Filter::parse(r#"{"since":9007199254740992,"limit":18446744073709551615}"#)
            .expect("parse");
        assert_eq!(filter.since(), Some(9_007_199_254_740_992));
        assert_eq!(filter.limit(), Some(u64::MAX));
    }

    #[test]
    fn to_json_round_trips() {
        let id = encode_32(&[0xAB; 32]);
        let pk = encode_32(&[0xCD; 32]);
        for json in [
            r#"{"kinds":[3,1],"since":5,"until":9,"limit":2}"#,
            &format!(
                r##"{{"ids":["{id}"],"authors":["{pk}"],"#e":["{id}"],"#p":["{pk}"],"#t":["x","y"]}}"##
            ),
            r#"{"ids":[]}"#,
            r##"{"#t":[],"kinds":[1]}"##,
            r"{}",
        ] {
            let filter = Filter::parse(json).expect(json);
            let reparsed = Filter::parse(&filter.to_json()).expect("to_json parses");
            assert_eq!(reparsed, filter, "{json} -> {}", filter.to_json());
        }
    }

    #[test]
    fn to_json_canonical_form() {
        assert_eq!(
            Filter::parse(r#"{"kinds":[3,1]}"#).unwrap().to_json(),
            r#"{"kinds":[1,3]}"#
        );
        assert_eq!(
            Filter::parse(r##"{"#t":[],"kinds":[1]}"##)
                .unwrap()
                .to_json(),
            r#"{"ids":[]}"#
        );
        let filter = Filter::parse(
            r##"{"authors":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"#e":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"##,
        )
        .unwrap();
        assert_eq!(
            filter.to_json(),
            concat!(
                r#"{"authors":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
                r#""bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"#,
                r##""#e":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"##
            )
        );
    }

    #[test]
    fn impossible_filters_are_equal() {
        assert_eq!(
            Filter::parse(r##"{"#t":[],"kinds":[1]}"##).unwrap(),
            Filter::parse(r#"{"ids":[]}"#).unwrap()
        );
    }

    #[test]
    fn every_reason_is_prefixed() {
        let errors = [
            Filter::parse("not json").expect_err("malformed"),
            Filter::parse(r#"{"kinds":"x"}"#).expect_err("invalid"),
            Filter::parse(r#"{"foo":1}"#).expect_err("unsupported"),
        ];
        let prefixes = [
            "duplicate:",
            "pow:",
            "blocked:",
            "rate-limited:",
            "invalid:",
            "restricted:",
            "mute:",
            "error:",
            "auth-required:",
            "unsupported:",
        ];
        for error in &errors {
            let reason = error.reason();
            assert!(
                prefixes.iter().any(|p| reason.starts_with(p)),
                "unprefixed reason: {reason}"
            );
        }
    }
}
