//! NIP-01 wire messages: client message parsing, relay frame builders.

use core::fmt;
use std::borrow::Cow;
use std::sync::Arc;

use serde_json::value::RawValue;

use crate::event::{EventError, EventId, UnverifiedEvent};
use crate::filter::{Filter, FilterError};
use crate::hex;

/// Maximum subscription id length in chars (NIP-01).
pub const SUB_ID_MAX_CHARS: usize = 64;

/// A validated subscription id (1..=64 Unicode scalar values).
///
/// Stores the original string plus its pre-escaped JSON form behind one
/// `Arc`, so cloning — done per monitor hit, per reader chunk, and per
/// outbound frame — is a refcount bump instead of two allocations.
/// `Eq`/`Hash` compare the original only.
#[derive(Debug, Clone)]
pub struct SubId(Arc<SubIdInner>);

#[derive(Debug)]
struct SubIdInner {
    raw: Box<str>,
    json: Box<str>,
}

impl SubId {
    /// Validate and pre-escape a subscription id.
    ///
    /// # Errors
    ///
    /// [`MessageError::Invalid`] when the id is empty or longer than 64
    /// Unicode scalar values.
    pub fn parse(raw: &str) -> Result<Self, MessageError> {
        let chars = raw.chars().count();
        if chars == 0 || chars > SUB_ID_MAX_CHARS {
            return Err(MessageError::Invalid {
                verb: None,
                message: format!("subscription id must be 1..={SUB_ID_MAX_CHARS} chars"),
            });
        }
        Ok(Self(Arc::new(SubIdInner {
            raw: raw.into(),
            json: json_escape(raw).into(),
        })))
    }

    /// The original string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0.raw
    }

    /// The JSON string literal form (with quotes), inserted verbatim in
    /// frames.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.0.json
    }
}

impl PartialEq for SubId {
    fn eq(&self, other: &Self) -> bool {
        self.0.raw == other.0.raw
    }
}

impl Eq for SubId {}

impl core::hash::Hash for SubId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.raw.hash(state);
    }
}

/// A recognized client→relay verb: the first element of a NIP-01
/// message array. Bounded label set for per-verb metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientVerb {
    /// `["EVENT", <event>]`.
    Event,
    /// `["REQ", <sub>, <filter>+]`.
    Req,
    /// `["CLOSE", <sub>]`.
    Close,
    /// `["COUNT", <sub>, <filter>+]` (NIP-45).
    Count,
    /// `["AUTH", <event>]` (NIP-42).
    Auth,
    /// `["NEG-OPEN", <sub>, <filter>, <hex>]` (NIP-77).
    NegOpen,
    /// `["NEG-MSG", <sub>, <hex>]` (NIP-77).
    NegMsg,
    /// `["NEG-CLOSE", <sub>]` (NIP-77).
    NegClose,
}

impl ClientVerb {
    /// Every verb, for fixed-size per-verb tables.
    pub const ALL: [Self; 8] = [
        Self::Event,
        Self::Req,
        Self::Close,
        Self::Count,
        Self::Auth,
        Self::NegOpen,
        Self::NegMsg,
        Self::NegClose,
    ];

    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Event => "EVENT",
            Self::Req => "REQ",
            Self::Close => "CLOSE",
            Self::Count => "COUNT",
            Self::Auth => "AUTH",
            Self::NegOpen => "NEG-OPEN",
            Self::NegMsg => "NEG-MSG",
            Self::NegClose => "NEG-CLOSE",
        }
    }

    /// The error frame a failed filter message gets: `NEG-ERR` for
    /// NIP-77 verbs, `CLOSED` otherwise.
    pub(crate) const fn is_neg(self) -> bool {
        matches!(self, Self::NegOpen | Self::NegMsg | Self::NegClose)
    }
}

impl std::str::FromStr for ClientVerb {
    type Err = ();

    /// The verb for a wire string; `Err(())` when unrecognized.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match text {
            "EVENT" => Self::Event,
            "REQ" => Self::Req,
            "CLOSE" => Self::Close,
            "COUNT" => Self::Count,
            "AUTH" => Self::Auth,
            "NEG-OPEN" => Self::NegOpen,
            "NEG-MSG" => Self::NegMsg,
            "NEG-CLOSE" => Self::NegClose,
            _ => return Err(()),
        })
    }
}

/// A frame type the relay writes to sockets; bounded label set for
/// per-verb metrics. Only frames the relay can emit today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayVerb {
    /// `["EVENT", <sub>, <event>]`.
    Event,
    /// `["EOSE", <sub>]`.
    Eose,
    /// `["OK", <id>, <accepted>, <message>]`.
    Ok,
    /// `["NOTICE", <message>]`.
    Notice,
    /// `["CLOSED", <sub>, <message>]`.
    Closed,
    /// `["AUTH", "<challenge>"]` (NIP-42).
    Auth,
    /// `["NEG-ERR", <sub>, <message>]`.
    NegErr,
    /// `["COUNT", <sub>, {"count": n}]` (NIP-45).
    Count,
    /// `["NEG-MSG", <sub>, <hex>]` (NIP-77).
    NegMsg,
}

impl RelayVerb {
    /// Every verb, for fixed-size per-verb tables.
    pub const ALL: [Self; 9] = [
        Self::Event,
        Self::Eose,
        Self::Ok,
        Self::Notice,
        Self::Closed,
        Self::Auth,
        Self::NegErr,
        Self::Count,
        Self::NegMsg,
    ];

    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Event => "EVENT",
            Self::Eose => "EOSE",
            Self::Ok => "OK",
            Self::Notice => "NOTICE",
            Self::Closed => "CLOSED",
            Self::Auth => "AUTH",
            Self::NegErr => "NEG-ERR",
            Self::Count => "COUNT",
            Self::NegMsg => "NEG-MSG",
        }
    }
}

/// Errors from client message parsing.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// The input is not a well-formed message.
    #[error("invalid message: {message}")]
    Invalid {
        /// The recognized verb when the failure came after verb
        /// parsing (`None` for malformed JSON or unknown verbs).
        verb: Option<ClientVerb>,
        /// Detail.
        message: String,
    },
    /// The event payload is not a structurally valid event; carries the
    /// best-effort claimed id so the session can answer `OK` when known.
    #[error("invalid event: {source}")]
    Event {
        /// `EVENT` or `AUTH`.
        verb: ClientVerb,
        /// The claimed event id, when the object carried a valid one.
        id: Option<EventId>,
        /// The structural error.
        source: EventError,
    },
    /// A filter inside a `REQ`/`COUNT`/`NEG-OPEN` failed; carries the
    /// subscription id so the session can answer `CLOSED`/`NEG-ERR`.
    #[error("invalid filter: {source}")]
    Filter {
        /// Which verb carried the bad filter (`REQ`, `COUNT`, or
        /// `NEG-OPEN`).
        verb: ClientVerb,
        /// The (already validated) subscription id.
        sub: SubId,
        /// The filter error.
        source: FilterError,
    },
}

impl MessageError {
    /// An `Invalid` without verb context (before the verb is known).
    const fn invalid(message: String) -> Self {
        Self::Invalid {
            verb: None,
            message,
        }
    }

    /// Stamp the recognized verb onto an `Invalid` raised while
    /// parsing that verb's elements.
    fn with_verb(self, verb: ClientVerb) -> Self {
        match self {
            Self::Invalid { message, .. } => Self::Invalid {
                verb: Some(verb),
                message,
            },
            other => other,
        }
    }

    /// The recognized verb of the failed message, if it got that far.
    #[must_use]
    pub const fn verb(&self) -> Option<ClientVerb> {
        match self {
            Self::Invalid { verb, .. } => *verb,
            Self::Event { verb, .. } | Self::Filter { verb, .. } => Some(*verb),
        }
    }

    /// The NIP-01 machine-readable rejection message.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Invalid { message, .. } => format!("invalid: {message}"),
            Self::Event { source, .. } => source.reason(),
            Self::Filter { source, .. } => source.reason(),
        }
    }
}

/// A parsed client→relay message. Event payloads stay borrowed as raw JSON;
/// `REQ`/`COUNT` filters are already compiled.
#[derive(Debug)]
pub enum ClientMessage<'a> {
    /// `["EVENT", <event>]` — structurally parsed, not yet verified.
    Event(UnverifiedEvent<'a>),
    /// `["REQ", <sub>, <filter>+]`.
    Req {
        /// Subscription id.
        sub_id: SubId,
        /// Compiled filters (NIP-01 OR semantics).
        filters: Vec<Filter>,
    },
    /// `["CLOSE", <sub>]`.
    Close {
        /// Subscription id.
        sub_id: SubId,
    },
    /// `["COUNT", <sub>, <filter>+]` (NIP-45).
    Count {
        /// Subscription id.
        sub_id: SubId,
        /// Compiled filters.
        filters: Vec<Filter>,
    },
    /// `["AUTH", <event>]` (NIP-42) — structurally parsed, not verified.
    Auth(UnverifiedEvent<'a>),
    /// `["NEG-OPEN", <sub>, <filter>, <hex>]` (NIP-77).
    NegOpen {
        /// Subscription id.
        sub_id: SubId,
        /// Compiled filter.
        filter: Box<Filter>,
        /// Hex-decoded payload.
        msg: Box<[u8]>,
    },
    /// `["NEG-MSG", <sub>, <hex>]` (NIP-77).
    NegMsg {
        /// Subscription id.
        sub_id: SubId,
        /// Hex-decoded payload.
        msg: Box<[u8]>,
    },
    /// `["NEG-CLOSE", <sub>]` (NIP-77).
    NegClose {
        /// Subscription id.
        sub_id: SubId,
    },
}

impl<'a> ClientMessage<'a> {
    /// The verb this message was written with.
    #[must_use]
    pub const fn verb(&self) -> ClientVerb {
        match self {
            Self::Event(_) => ClientVerb::Event,
            Self::Req { .. } => ClientVerb::Req,
            Self::Close { .. } => ClientVerb::Close,
            Self::Count { .. } => ClientVerb::Count,
            Self::Auth(_) => ClientVerb::Auth,
            Self::NegOpen { .. } => ClientVerb::NegOpen,
            Self::NegMsg { .. } => ClientVerb::NegMsg,
            Self::NegClose { .. } => ClientVerb::NegClose,
        }
    }

    /// Parse a client message frame.
    ///
    /// # Errors
    ///
    /// [`MessageError`] on malformed JSON, arity/type errors, invalid
    /// subscription ids, bad NEG hex, structurally invalid event payloads,
    /// or filter errors (with the sub id attached).
    pub fn parse(text: &'a str) -> Result<Self, MessageError> {
        let items: Vec<&RawValue> = serde_json::from_str(text)
            .map_err(|e| MessageError::invalid(format!("not a JSON array: {e}")))?;
        let verb_str = items
            .first()
            .and_then(|raw| serde_json::from_str::<&str>(raw.get()).ok())
            .ok_or_else(|| MessageError::invalid("expected [verb, ...] array".to_owned()))?;
        let Ok(verb) = verb_str.parse::<ClientVerb>() else {
            return Err(MessageError::invalid(format!("unknown verb `{verb_str}`")));
        };
        let message: Result<Self, MessageError> = match verb {
            ClientVerb::Event => {
                expect_arity(&items, 2, verb)?;
                let event = required(&items, 1, verb)?;
                let unverified = parse_event(event, verb)?;
                Ok(Self::Event(unverified))
            }
            ClientVerb::Req => {
                let sub_id = parse_sub(&items, 1, verb)?;
                expect_min_arity(&items, 3, verb)?;
                let filters = parse_filters(&items, 2, verb, &sub_id)?;
                Ok(Self::Req { sub_id, filters })
            }
            ClientVerb::Close => {
                expect_arity(&items, 2, verb)?;
                let sub_id = parse_sub(&items, 1, verb)?;
                Ok(Self::Close { sub_id })
            }
            ClientVerb::Auth => {
                expect_arity(&items, 2, verb)?;
                let event = required(&items, 1, verb)?;
                let unverified = parse_event(event, verb)?;
                Ok(Self::Auth(unverified))
            }
            ClientVerb::Count => {
                let sub_id = parse_sub(&items, 1, verb)?;
                expect_min_arity(&items, 3, verb)?;
                let filters = parse_filters(&items, 2, verb, &sub_id)?;
                Ok(Self::Count { sub_id, filters })
            }
            ClientVerb::NegOpen => {
                expect_arity(&items, 4, verb)?;
                let sub_id = parse_sub(&items, 1, verb)?;
                let filter = Filter::from_raw(required(&items, 2, verb)?).map_err(|source| {
                    MessageError::Filter {
                        verb,
                        sub: sub_id.clone(),
                        source,
                    }
                })?;
                let msg = parse_neg_hex(items.get(3), verb)?;
                Ok(Self::NegOpen {
                    sub_id,
                    filter: Box::new(filter),
                    msg,
                })
            }
            ClientVerb::NegMsg => {
                expect_arity(&items, 3, verb)?;
                let sub_id = parse_sub(&items, 1, verb)?;
                let msg = parse_neg_hex(items.get(2), verb)?;
                Ok(Self::NegMsg { sub_id, msg })
            }
            ClientVerb::NegClose => {
                expect_arity(&items, 2, verb)?;
                let sub_id = parse_sub(&items, 1, verb)?;
                Ok(Self::NegClose { sub_id })
            }
        };
        message.map_err(|error| error.with_verb(verb))
    }
}

fn parse_event(raw: &RawValue, verb: ClientVerb) -> Result<UnverifiedEvent<'_>, MessageError> {
    UnverifiedEvent::parse_structural(raw.get()).map_err(|source| MessageError::Event {
        verb,
        id: extract_event_id(raw),
        source,
    })
}

/// Best-effort `id` extraction for the rejection frame when structural
/// parse failed.
fn extract_event_id(raw: &RawValue) -> Option<EventId> {
    #[derive(serde::Deserialize)]
    struct OnlyId<'a> {
        #[serde(borrow)]
        id: Option<Cow<'a, str>>,
    }
    let parsed: OnlyId<'_> = serde_json::from_str(raw.get()).ok()?;
    parsed
        .id
        .and_then(|id| hex::decode_32(id.as_ref()))
        .map(EventId)
}

fn required<'a>(
    items: &[&'a RawValue],
    index: usize,
    verb: ClientVerb,
) -> Result<&'a RawValue, MessageError> {
    items
        .get(index)
        .copied()
        .ok_or_else(|| MessageError::Invalid {
            verb: Some(verb),
            message: format!("{} is missing element {index}", verb.as_str()),
        })
}

fn expect_arity(items: &[&RawValue], arity: usize, verb: ClientVerb) -> Result<(), MessageError> {
    if items.len() != arity {
        return Err(MessageError::Invalid {
            verb: Some(verb),
            message: format!("{} takes {} element(s)", verb.as_str(), arity - 1),
        });
    }
    Ok(())
}

fn expect_min_arity(
    items: &[&RawValue],
    arity: usize,
    verb: ClientVerb,
) -> Result<(), MessageError> {
    if items.len() < arity {
        return Err(MessageError::Invalid {
            verb: Some(verb),
            message: format!("{} needs at least {} element(s)", verb.as_str(), arity - 1),
        });
    }
    Ok(())
}

fn parse_sub(items: &[&RawValue], index: usize, verb: ClientVerb) -> Result<SubId, MessageError> {
    // `Cow` so escaped ids ("\u00e9", "a\"b") deserialize too; a borrowed
    // `&str` fails on any escape sequence, although NIP-01 allows any
    // string of 1..=64 chars.
    let raw = items
        .get(index)
        .and_then(|raw| serde_json::from_str::<Cow<'_, str>>(raw.get()).ok())
        .ok_or_else(|| MessageError::Invalid {
            verb: Some(verb),
            message: format!("{} subscription id must be a string", verb.as_str()),
        })?;
    SubId::parse(raw.as_ref())
}

fn parse_filters(
    items: &[&RawValue],
    from: usize,
    verb: ClientVerb,
    sub_id: &SubId,
) -> Result<Vec<Filter>, MessageError> {
    items
        .iter()
        .skip(from)
        .map(|raw| {
            Filter::from_raw(raw).map_err(|source| MessageError::Filter {
                verb,
                sub: sub_id.clone(),
                source,
            })
        })
        .collect()
}

fn parse_neg_hex(raw: Option<&&RawValue>, verb: ClientVerb) -> Result<Box<[u8]>, MessageError> {
    let text = raw
        .and_then(|raw| serde_json::from_str::<&str>(raw.get()).ok())
        .ok_or_else(|| MessageError::Invalid {
            verb: Some(verb),
            message: format!("{} payload must be a hex string", verb.as_str()),
        })?;
    hex::decode_list(text)
        .map(Vec::into_boxed_slice)
        .ok_or_else(|| MessageError::Invalid {
            verb: Some(verb),
            message: format!(
                "{} payload must be non-empty even-length hex",
                verb.as_str()
            ),
        })
}

/// `["EVENT", "<sub>", <json>]` — `json` is inserted verbatim.
#[must_use]
pub fn event_frame(sub: &SubId, json: &str) -> String {
    let mut out = String::with_capacity(12 + sub.json().len() + json.len());
    out.push_str("[\"EVENT\",");
    out.push_str(sub.json());
    out.push(',');
    out.push_str(json);
    out.push(']');
    out
}

/// `["OK", "<id>", <accepted>, "<message>"]`.
#[must_use]
pub fn ok_frame(id: &EventId, accepted: bool, message: &str) -> String {
    let mut out = String::with_capacity(16 + 64 + message.len());
    out.push_str("[\"OK\",\"");
    out.push_str(&id.to_string());
    out.push_str(if accepted { "\",true," } else { "\",false," });
    out.push_str(&json_escape(message));
    out.push(']');
    out
}

/// `["OK", "<id>", <accepted>, "<message>", "<params>"]` — the
/// optional NIP-01 params element, today only the `rate-limited`
/// retry hint: a decimal-millisecond string like `"1000"`.
#[must_use]
pub fn ok_frame_with_params(id: &EventId, accepted: bool, message: &str, params: &str) -> String {
    let mut out = ok_frame(id, accepted, message);
    out.pop();
    out.push(',');
    out.push_str(&json_escape(params));
    out.push(']');
    out
}

/// `["EOSE", "<sub>"]`.
#[must_use]
pub fn eose_frame(sub: &SubId) -> String {
    frame_with_sub("EOSE", sub, "]")
}

/// `["COUNT", "<sub>", {"count": n}]` — the NIP-45 answer.
///
/// `"approximate":true` is added only when the scan hit its entry
/// budget; `"hll":"<512 hex>"` only when the query was eligible for a
/// sketch and one was built.
#[must_use]
pub fn count_frame(sub: &SubId, count: u64, approximate: bool, hll: Option<&[u8; 256]>) -> String {
    let mut out = String::with_capacity(24 + sub.json().len() + hll.map_or(0, |_| 524));
    out.push_str("[\"COUNT\",");
    out.push_str(sub.json());
    out.push_str(",{\"count\":");
    out.push_str(&count.to_string());
    if approximate {
        out.push_str(",\"approximate\":true");
    }
    if let Some(registers) = hll {
        out.push_str(",\"hll\":\"");
        out.push_str(&faster_hex::hex_string(registers));
        out.push('"');
    }
    out.push_str("}]");
    out
}

/// `["CLOSED", "<sub>", "<message>"]`.
#[must_use]
pub fn closed_frame(sub: &SubId, message: &str) -> String {
    let mut out = String::with_capacity(16 + sub.json().len() + message.len());
    out.push_str("[\"CLOSED\",");
    out.push_str(sub.json());
    out.push(',');
    out.push_str(&json_escape(message));
    out.push(']');
    out
}

/// `["CLOSED", "<sub>", "<message>", "<params>"]` — see
/// [`ok_frame_with_params`].
#[must_use]
pub fn closed_frame_with_params(sub: &SubId, message: &str, params: &str) -> String {
    let mut out = closed_frame(sub, message);
    out.pop();
    out.push(',');
    out.push_str(&json_escape(params));
    out.push(']');
    out
}

/// `["NOTICE", "<message>"]`.
#[must_use]
pub fn notice_frame(message: &str) -> String {
    let mut out = String::with_capacity(12 + message.len());
    out.push_str("[\"NOTICE\",");
    out.push_str(&json_escape(message));
    out.push(']');
    out
}

/// `["AUTH","<challenge>"]` — the relay's NIP-42 challenge.
#[must_use]
pub fn auth_frame(challenge: &str) -> String {
    let mut out = String::with_capacity(10 + challenge.len());
    out.push_str("[\"AUTH\",");
    out.push_str(&json_escape(challenge));
    out.push(']');
    out
}

/// `["NEG-ERR", "<sub>", "<message>"]`.
#[must_use]
pub fn neg_err_frame(sub: &SubId, message: &str) -> String {
    let mut out = String::with_capacity(16 + sub.json().len() + message.len());
    out.push_str("[\"NEG-ERR\",");
    out.push_str(sub.json());
    out.push(',');
    out.push_str(&json_escape(message));
    out.push(']');
    out
}

/// `["NEG-ERR", "<sub>", "<message>", <limit>]` — strfry's
/// `blocked:` answer carries the cap as a fourth element.
#[must_use]
pub fn neg_err_frame_with_limit(sub: &SubId, message: &str, limit: u64) -> String {
    let mut out = String::with_capacity(24 + sub.json().len() + message.len());
    out.push_str("[\"NEG-ERR\",");
    out.push_str(sub.json());
    out.push(',');
    out.push_str(&json_escape(message));
    out.push(',');
    out.push_str(&limit.to_string());
    out.push(']');
    out
}

/// `["NEG-MSG", "<sub>", "<hex>"]`.
#[must_use]
pub fn neg_msg_frame(sub: &SubId, hex: &str) -> String {
    let mut out = String::with_capacity(16 + sub.json().len() + hex.len());
    out.push_str("[\"NEG-MSG\",");
    out.push_str(sub.json());
    out.push(',');
    out.push_str(&json_escape(hex));
    out.push(']');
    out
}

fn frame_with_sub(verb: &str, sub: &SubId, tail: &str) -> String {
    let mut out = String::with_capacity(4 + verb.len() + sub.json().len() + tail.len());
    out.push_str("[\"");
    out.push_str(verb);
    out.push_str("\",");
    out.push_str(sub.json());
    out.push_str(tail);
    out
}

fn json_escape(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}

/// The NIP-01 machine-readable message prefixes.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// `duplicate:` — event already stored.
    Duplicate,
    /// `pow:` — insufficient proof of work.
    Pow,
    /// `blocked:` — author or content blocked by policy.
    Blocked,
    /// `rate-limited:` — connection exceeded limits.
    RateLimited,
    /// `invalid:` — malformed or unverifiable input.
    Invalid,
    /// `restricted:` — not allowed on this relay.
    Restricted,
    /// `mute:` — sender is muted.
    Mute,
    /// `error:` — internal error.
    Error,
    /// `auth-required:` — NIP-42 authentication needed.
    AuthRequired,
    /// `unsupported:` — feature not implemented.
    Unsupported,
}

impl Reason {
    /// The `xxx:` prefix.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate:",
            Self::Pow => "pow:",
            Self::Blocked => "blocked:",
            Self::RateLimited => "rate-limited:",
            Self::Invalid => "invalid:",
            Self::Restricted => "restricted:",
            Self::Mute => "mute:",
            Self::Error => "error:",
            Self::AuthRequired => "auth-required:",
            Self::Unsupported => "unsupported:",
        }
    }

    /// `"<prefix> <detail>"`.
    #[must_use]
    pub fn message(self, detail: &str) -> String {
        let mut out = String::with_capacity(self.prefix().len() + 1 + detail.len());
        out.push_str(self.prefix());
        out.push(' ');
        out.push_str(detail);
        out
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}
