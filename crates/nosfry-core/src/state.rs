//! Versioned management-state lines appended to `nosfry export`.
//!
//! An export is NDJSON event lines — the `strfry export` format,
//! which keeps importing unchanged — followed by one line per
//! persisted NIP-86 entry and NIP-62 vanish point. A state line is a
//! JSON object whose first key is `nosfry_state` (the format
//! [`STATE_VERSION`]), shaped like a NIP-86 request:
//! `{"nosfry_state":1,"method":"banpubkey","params":["<hex>","<reason>"]}`.
//! The nosfry-only `vanish` method carries a vanish point, which can
//! outlive its kind-62 carrier (`nosfry delete`, a `banevent` of the
//! request):
//! `{"nosfry_state":1,"method":"vanish","params":["<pubkey hex>",<T>]}`.
//! NIP-09 tombstones need no state line: the deletion rows belong to
//! their kind-5 carriers, which export as ordinary events and rebuild
//! the blocks on import (deleting a carrier lifts the block by
//! design).
//!
//! Import detects the exact [`STATE_PREFIX`] byte prefix — an event
//! object never starts that way — and refuses unknown versions,
//! read-only methods (`list*`, `supportedmethods`), and undo ops
//! (`un*`): a snapshot holds only applied entries, so such a line can
//! only come from a hand-edited or hostile stream and must abort the
//! import rather than silently drop a ban.

use serde_json::{Value, json};

use crate::event::PublicKey;
use crate::management::{self, Action, Request};
use crate::moderation::{InfoField, ModOp, Moderation};

/// The `nosfry_state` format version this build writes.
pub const STATE_VERSION: u64 = 1;

/// Byte prefix identifying a state line on import.
pub const STATE_PREFIX: &str = r#"{"nosfry_state":"#;

/// The NIP-86 methods a snapshot emits (`vanish` is handled
/// separately). `un*`, `list*`, and `supportedmethods` are refused on
/// import.
const STATE_METHODS: &[&str] = &[
    "allowkind",
    "allowpubkey",
    "banevent",
    "banpubkey",
    "blockip",
    "disallowkind",
    "changerelaydescription",
    "changerelayicon",
    "changerelayname",
];

/// One persisted management fact carried by a state line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateRecord {
    /// A NIP-86 moderation entry (an `allow*`/`ban*`/`disallow*`/
    /// `blockip`/`changerelay*` op — never an `un*` or read-only one).
    Moderate(ModOp),
    /// A NIP-62 vanish point: the author's highest honored request
    /// time.
    Vanish {
        /// The author whose `created_at <= at` events are refused.
        pubkey: PublicKey,
        /// The vanish point `T` (unix seconds).
        at: u64,
    },
}

/// Why a state line was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// Not the documented object shape, or bad params.
    #[error("malformed state line: {0}")]
    Malformed(String),
    /// `nosfry_state` is a version this build does not read.
    #[error("unsupported nosfry_state version {0}")]
    Version(u64),
    /// The method is not part of the snapshot vocabulary (read-only
    /// or `un*` methods are never emitted).
    #[error("state method {0:?} is not part of the export vocabulary")]
    Method(String),
}

/// Serialize the persisted `Moderation` snapshot and every vanish
/// point as state lines.
///
/// One line per entry in deterministic order (groups in emission
/// order, entries sorted inside each group). Re-applying the lines is
/// idempotent, so they are emitted regardless of the export's
/// `since`/`until` window: the two-pass delta upgrade re-applies them
/// safely.
#[must_use]
pub fn state_lines(m: &Moderation, vanish: &[(PublicKey, u64)]) -> Vec<String> {
    let mut records = Vec::new();
    let mut allowed: Vec<_> = m.allowed_pubkeys.iter().collect();
    allowed.sort_by_key(|(key, _)| *key);
    for (pubkey, reason) in allowed {
        records.push(StateRecord::Moderate(ModOp::AllowPubkey {
            pubkey: *pubkey,
            reason: reason.as_deref().map(str::to_owned),
        }));
    }
    let mut banned: Vec<_> = m.banned_pubkeys.iter().collect();
    banned.sort_by_key(|(key, _)| *key);
    for (pubkey, reason) in banned {
        records.push(StateRecord::Moderate(ModOp::BanPubkey {
            pubkey: *pubkey,
            reason: reason.as_deref().map(str::to_owned),
        }));
    }
    let mut events: Vec<_> = m.banned_events.iter().collect();
    events.sort_by_key(|(key, _)| *key);
    for (id, reason) in events {
        records.push(StateRecord::Moderate(ModOp::BanEvent {
            id: *id,
            reason: reason.as_deref().map(str::to_owned),
        }));
    }
    for kind in &m.allowed_kinds {
        records.push(StateRecord::Moderate(ModOp::AllowKind { kind: *kind }));
    }
    for kind in &m.disallowed_kinds {
        records.push(StateRecord::Moderate(ModOp::DisallowKind { kind: *kind }));
    }
    let mut ips: Vec<_> = m.blocked_ips.iter().collect();
    ips.sort_by_key(|(key, _)| *key);
    for (ip, reason) in ips {
        records.push(StateRecord::Moderate(ModOp::BlockIp {
            ip: *ip,
            reason: reason.as_deref().map(str::to_owned),
        }));
    }
    for (field, value) in [
        (InfoField::Name, &m.name),
        (InfoField::Description, &m.description),
        (InfoField::Icon, &m.icon),
    ] {
        // An empty-string override is a real entry and still emits.
        if let Some(value) = value {
            records.push(StateRecord::Moderate(ModOp::SetInfo {
                field,
                value: value.to_string(),
            }));
        }
    }
    let mut points = vanish.to_vec();
    points.sort();
    for (pubkey, at) in points {
        records.push(StateRecord::Vanish { pubkey, at });
    }
    records.iter().filter_map(state_line).collect()
}

/// The `{"nosfry_state":1,…}` line for one record.
///
/// `None` when the op is not part of the snapshot vocabulary (`un*`
/// ops are never emitted). `nosfry_state` stays the first key: import
/// detects the exact byte prefix.
#[must_use]
pub fn state_line(record: &StateRecord) -> Option<String> {
    let (method, params) = match record {
        StateRecord::Vanish { pubkey, at } => ("vanish", json!([pubkey.to_string(), at])),
        StateRecord::Moderate(op) => match op {
            ModOp::BanPubkey { pubkey, reason } => (
                "banpubkey",
                keyed(&json!(pubkey.to_string()), reason.as_deref()),
            ),
            ModOp::AllowPubkey { pubkey, reason } => (
                "allowpubkey",
                keyed(&json!(pubkey.to_string()), reason.as_deref()),
            ),
            ModOp::BanEvent { id, reason } => {
                ("banevent", keyed(&json!(id.to_string()), reason.as_deref()))
            }
            ModOp::AllowKind { kind } => ("allowkind", json!([kind])),
            ModOp::DisallowKind { kind } => ("disallowkind", json!([kind])),
            ModOp::BlockIp { ip, reason } => {
                ("blockip", keyed(&json!(ip.to_string()), reason.as_deref()))
            }
            ModOp::SetInfo { field, value } => (
                match field {
                    InfoField::Name => "changerelayname",
                    InfoField::Description => "changerelaydescription",
                    InfoField::Icon => "changerelayicon",
                },
                json!([value]),
            ),
            ModOp::UnbanPubkey { .. }
            | ModOp::UnallowPubkey { .. }
            | ModOp::UnbanEvent { .. }
            | ModOp::UnblockIp { .. } => return None,
        },
    };
    let params = serde_json::to_string(&params).ok()?;
    Some(format!(
        "{{\"nosfry_state\":{STATE_VERSION},\"method\":\"{method}\",\"params\":{params}}}"
    ))
}

/// `params` for a keyed entry: `[key]` plus `reason` when present.
fn keyed(key: &Value, reason: Option<&str>) -> Value {
    reason.map_or_else(|| json!([key]), |reason| json!([key, reason]))
}

/// Parse one export line into a [`StateRecord`].
///
/// `Ok(None)` when the line lacks [`STATE_PREFIX`] (an ordinary event
/// line), `Ok(Some)` for a valid record, `Err` for a malformed,
/// unknown-version, or out-of-vocabulary state line. Management
/// methods are parsed back into [`ModOp`]s through
/// [`management::action`] — one parser for both transports.
///
/// # Errors
///
/// [`StateError`] naming the problem; import must abort on it rather
/// than silently drop a ban.
pub fn parse_state_line(line: &str) -> Result<Option<StateRecord>, StateError> {
    if !line.starts_with(STATE_PREFIX) {
        return Ok(None);
    }
    let value: Value =
        serde_json::from_str(line).map_err(|err| StateError::Malformed(err.to_string()))?;
    let version = value
        .get("nosfry_state")
        .and_then(Value::as_u64)
        .ok_or_else(|| StateError::Malformed("missing nosfry_state version".to_owned()))?;
    if version != STATE_VERSION {
        return Err(StateError::Version(version));
    }
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| StateError::Malformed("missing method".to_owned()))?;
    let params = value
        .get("params")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if method == "vanish" {
        let pubkey = params
            .first()
            .and_then(Value::as_str)
            .and_then(PublicKey::from_hex)
            .ok_or_else(|| {
                StateError::Malformed("vanish params[0] must be a 64-hex pubkey".to_owned())
            })?;
        let at = params.get(1).and_then(Value::as_u64).ok_or_else(|| {
            StateError::Malformed("vanish params[1] must be a unix time".to_owned())
        })?;
        return Ok(Some(StateRecord::Vanish { pubkey, at }));
    }
    if !STATE_METHODS.contains(&method) {
        return Err(StateError::Method(method.to_owned()));
    }
    match management::action(&Request { method, params }, &Moderation::default()) {
        Ok(Action::Apply(op)) => Ok(Some(StateRecord::Moderate(op))),
        // Unreachable while `STATE_METHODS` holds only mutating
        // methods; keeps the vocabulary honest if a `list*` ever
        // slips in.
        Ok(Action::Respond(_)) => Err(StateError::Method(method.to_owned())),
        Err(reason) => Err(StateError::Malformed(reason)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::event::EventId;

    fn pk(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    /// Every emitted method round-trips through the parser.
    #[test]
    fn state_lines_round_trip() {
        let mut m = Moderation::default();
        m.banned_pubkeys.insert(pk(0x01), Some("spam".into()));
        m.banned_pubkeys.insert(pk(0x02), None);
        m.allowed_pubkeys.insert(pk(0x03), None);
        m.banned_events
            .insert(EventId([0x04; 32]), Some("illegal".into()));
        m.allowed_kinds.insert(3);
        m.disallowed_kinds.insert(7);
        m.blocked_ips
            .insert("192.0.2.1".parse::<IpAddr>().unwrap(), None);
        m.name = Some("test relay".into());
        m.icon = Some("".into());
        let vanish = [(pk(0x09), 1_700_000_000), (pk(0x08), 42)];

        let lines = state_lines(&m, &vanish);
        assert_eq!(lines.len(), 11);
        for line in &lines {
            assert!(line.starts_with(STATE_PREFIX), "{line}");
            let parsed = parse_state_line(line).unwrap().unwrap();
            assert_eq!(&state_line(&parsed).unwrap(), line, "{line}");
        }
        // Deterministic order: groups in emission order, sorted keys
        // inside each group.
        assert_eq!(
            lines,
            [
                format!(
                    "{{\"nosfry_state\":1,\"method\":\"allowpubkey\",\"params\":[\"{}\"]}}",
                    pk(0x03)
                ),
                format!(
                    "{{\"nosfry_state\":1,\"method\":\"banpubkey\",\"params\":[\"{}\",\"spam\"]}}",
                    pk(0x01)
                ),
                format!(
                    "{{\"nosfry_state\":1,\"method\":\"banpubkey\",\"params\":[\"{}\"]}}",
                    pk(0x02)
                ),
                format!(
                    "{{\"nosfry_state\":1,\"method\":\"banevent\",\"params\":[\"{}\",\"illegal\"]}}",
                    EventId([0x04; 32])
                ),
                "{\"nosfry_state\":1,\"method\":\"allowkind\",\"params\":[3]}".to_owned(),
                "{\"nosfry_state\":1,\"method\":\"disallowkind\",\"params\":[7]}".to_owned(),
                "{\"nosfry_state\":1,\"method\":\"blockip\",\"params\":[\"192.0.2.1\"]}".to_owned(),
                "{\"nosfry_state\":1,\"method\":\"changerelayname\",\"params\":[\"test relay\"]}"
                    .to_owned(),
                "{\"nosfry_state\":1,\"method\":\"changerelayicon\",\"params\":[\"\"]}".to_owned(),
                format!(
                    "{{\"nosfry_state\":1,\"method\":\"vanish\",\"params\":[\"{}\",42]}}",
                    pk(0x08)
                ),
                format!(
                    "{{\"nosfry_state\":1,\"method\":\"vanish\",\"params\":[\"{}\",1700000000]}}",
                    pk(0x09)
                ),
            ],
            "{lines:?}"
        );
    }

    /// Event lines and everything else without the prefix pass
    /// through as `None`.
    #[test]
    fn non_state_lines_return_none() {
        assert_eq!(parse_state_line("{\"id\":\"ab\"}").unwrap(), None);
        assert_eq!(parse_state_line(" {\"nosfry_state\":1}").unwrap(), None);
        assert_eq!(parse_state_line("garbage").unwrap(), None);
        assert_eq!(parse_state_line("").unwrap(), None);
    }

    /// Refused lines: unknown version, read-only and `un*` methods,
    /// unknown methods, and malformed params.
    #[test]
    fn refused_state_lines() {
        for (line, expected) in [
            (
                "{\"nosfry_state\":2,\"method\":\"banpubkey\",\"params\":[]}",
                StateError::Version(2),
            ),
            (
                "{\"nosfry_state\":\"1\",\"method\":\"banpubkey\",\"params\":[]}",
                StateError::Malformed("missing nosfry_state version".to_owned()),
            ),
            (
                "{\"nosfry_state\":1,\"method\":\"listbannedpubkeys\",\"params\":[]}",
                StateError::Method("listbannedpubkeys".to_owned()),
            ),
            (
                "{\"nosfry_state\":1,\"method\":\"supportedmethods\",\"params\":[]}",
                StateError::Method("supportedmethods".to_owned()),
            ),
            (
                "{\"nosfry_state\":1,\"method\":\"unbanpubkey\",\"params\":[]}",
                StateError::Method("unbanpubkey".to_owned()),
            ),
            (
                "{\"nosfry_state\":1,\"method\":\"wipe\",\"params\":[]}",
                StateError::Method("wipe".to_owned()),
            ),
            (
                "{\"nosfry_state\":1,\"method\":\"banpubkey\",\"params\":[\"xx\"]}",
                StateError::Malformed("invalid params: expected a 64-hex pubkey".to_owned()),
            ),
            (
                "{\"nosfry_state\":1,\"method\":\"vanish\",\"params\":[]}",
                StateError::Malformed("vanish params[0] must be a 64-hex pubkey".to_owned()),
            ),
        ] {
            assert_eq!(parse_state_line(line), Err(expected), "{line}");
        }
        assert!(matches!(
            parse_state_line("{\"nosfry_state\":"),
            Err(StateError::Malformed(_))
        ));
    }
}
