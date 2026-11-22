//! Relay→client protocol parsing for `nosfry sync` (sans-IO,
//! fuzzable): the relay-side frames a NIP-01/NIP-77 client consumes,
//! the retry hints inside them, and the NIP-11 limits document.

use serde_json::Value;
use serde_json::value::RawValue;

use crate::event::EventId;

/// Largest NIP-42 challenge signed back into an AUTH event — a peer
/// sending more gets an error, not a signature.
pub const MAX_AUTH_CHALLENGE: usize = 1024;

/// Retry-hint ceiling in milliseconds (5 minutes): a peer asking for
/// a longer wait gets the cap, not its number.
const MAX_RETRY_MS: u64 = 300_000;

/// `supported_nips` entries a NIP-11 document may carry before the
/// rest is dropped.
const MAX_SUPPORTED_NIPS: usize = 256;

/// A relay→client text frame, parsed.
#[derive(Debug)]
#[non_exhaustive]
pub enum RelayMessage<'a> {
    /// `["EVENT", <sub>, <event>]` — the event stays raw JSON.
    Event {
        /// Subscription id.
        sub: &'a str,
        /// Raw event object JSON (canonical or not — the caller
        /// re-validates through `UnverifiedEvent`).
        event: &'a RawValue,
    },
    /// `["OK", <id>, <accepted>, <message>[, <hint>]]`.
    Ok {
        /// The event id answered.
        id: EventId,
        /// Whether the relay stored (or claims to have) the event.
        accepted: bool,
        /// The NIP-01 machine-readable message.
        message: String,
        /// The `rate-limited` retry hint in milliseconds, capped at
        /// `MAX_RETRY_MS`.
        retry_after_ms: Option<u64>,
    },
    /// `["EOSE", <sub>]`.
    Eose {
        /// Subscription id.
        sub: String,
    },
    /// `["CLOSED", <sub>, <message>[, <hint>]]`.
    Closed {
        /// Subscription id.
        sub: String,
        /// The NIP-01 machine-readable message.
        message: String,
        /// The `rate-limited` retry hint in milliseconds, capped at
        /// `MAX_RETRY_MS`.
        retry_after_ms: Option<u64>,
    },
    /// `["NOTICE", <message>]`.
    Notice {
        /// Human-readable relay message.
        message: String,
    },
    /// `["AUTH", <challenge>]` — the NIP-42 challenge.
    Auth {
        /// The challenge to sign into a kind-22242 event.
        challenge: String,
    },
    /// `["NEG-MSG", <sub>, "<hex>"]` — hex-decoded payload (lower-
    /// and uppercase hex both accepted from peers).
    NegMsg {
        /// Subscription id.
        sub: String,
        /// The decoded negentropy message.
        msg: Vec<u8>,
    },
    /// `["NEG-ERR", <sub>, <message>[, <limit>]]`.
    NegErr {
        /// Subscription id.
        sub: String,
        /// The NIP-01 machine-readable message.
        message: String,
        /// strfry's `blocked:` result cap, carried as the fourth
        /// element.
        limit: Option<u64>,
    },
    /// `COUNT` answers and unknown verbs: the caller ignores them.
    Other,
}

/// Why a relay→client frame failed to parse.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayMessageError {
    /// The frame is not a JSON array whose first element is a string
    /// verb.
    #[error("not a relay message")]
    NotAMessage,
    /// A recognized verb whose remaining elements have the wrong
    /// shape; the payload names what failed.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// An AUTH challenge over [`MAX_AUTH_CHALLENGE`] bytes.
    #[error("AUTH challenge over {MAX_AUTH_CHALLENGE} bytes")]
    AuthChallengeTooLarge,
}

impl<'a> RelayMessage<'a> {
    /// Parse one text frame. Unknown and `COUNT` verbs map to
    /// [`RelayMessage::Other`]; malformed frames are an error.
    ///
    /// # Errors
    ///
    /// [`RelayMessageError::NotAMessage`] when the frame is not a JSON
    /// array headed by a string verb, [`RelayMessageError::Malformed`]
    /// when a known verb's elements have the wrong shape, and
    /// [`RelayMessageError::AuthChallengeTooLarge`] past the challenge
    /// bound.
    pub fn parse(text: &'a str) -> Result<Self, RelayMessageError> {
        let elements: Vec<&'a RawValue> =
            serde_json::from_str(text).map_err(|_| RelayMessageError::NotAMessage)?;
        let Some((verb, rest)) = elements.split_first() else {
            return Err(RelayMessageError::NotAMessage);
        };
        let verb: &'a str =
            serde_json::from_str(verb.get()).map_err(|_| RelayMessageError::NotAMessage)?;
        match verb {
            "EVENT" => Self::parse_event(rest),
            "OK" => Self::parse_ok(rest),
            "EOSE" => Self::parse_eose(rest),
            "CLOSED" => Self::parse_closed(rest),
            "NOTICE" => Self::parse_notice(rest),
            "AUTH" => Self::parse_auth(rest),
            "NEG-MSG" => Self::parse_neg_msg(rest),
            "NEG-ERR" => Self::parse_neg_err(rest),
            _ => Ok(RelayMessage::Other),
        }
    }

    fn parse_event(rest: &[&'a RawValue]) -> Result<Self, RelayMessageError> {
        let sub = element::<&'a str>(rest.first(), "EVENT subscription id")?;
        let event = rest
            .get(1)
            .copied()
            .ok_or(RelayMessageError::Malformed("EVENT event"))?;
        Ok(RelayMessage::Event { sub, event })
    }

    fn parse_ok(rest: &[&'a RawValue]) -> Result<Self, RelayMessageError> {
        let id_hex = element::<&'a str>(rest.first(), "OK event id")?;
        let id = EventId::from_hex(id_hex).ok_or(RelayMessageError::Malformed("OK event id"))?;
        let accepted = element::<bool>(rest.get(1), "OK accepted")?;
        let message = element::<String>(rest.get(2), "OK message")?;
        Ok(RelayMessage::Ok {
            id,
            accepted,
            message,
            retry_after_ms: retry_hint(rest.get(3)),
        })
    }

    fn parse_eose(rest: &[&'a RawValue]) -> Result<Self, RelayMessageError> {
        Ok(RelayMessage::Eose {
            sub: element::<String>(rest.first(), "EOSE subscription id")?,
        })
    }

    fn parse_closed(rest: &[&'a RawValue]) -> Result<Self, RelayMessageError> {
        Ok(RelayMessage::Closed {
            sub: element::<String>(rest.first(), "CLOSED subscription id")?,
            message: element::<String>(rest.get(1), "CLOSED message")?,
            retry_after_ms: retry_hint(rest.get(2)),
        })
    }

    fn parse_notice(rest: &[&'a RawValue]) -> Result<Self, RelayMessageError> {
        Ok(RelayMessage::Notice {
            message: element::<String>(rest.first(), "NOTICE message")?,
        })
    }

    fn parse_auth(rest: &[&'a RawValue]) -> Result<Self, RelayMessageError> {
        let challenge = element::<String>(rest.first(), "AUTH challenge")?;
        if challenge.len() > MAX_AUTH_CHALLENGE {
            return Err(RelayMessageError::AuthChallengeTooLarge);
        }
        Ok(RelayMessage::Auth { challenge })
    }

    fn parse_neg_msg(rest: &[&'a RawValue]) -> Result<Self, RelayMessageError> {
        let sub = element::<String>(rest.first(), "NEG-MSG subscription id")?;
        let hex = element::<&'a str>(rest.get(1), "NEG-MSG payload")?;
        let msg =
            crate::hex::decode_list(hex).ok_or(RelayMessageError::Malformed("NEG-MSG payload"))?;
        Ok(RelayMessage::NegMsg { sub, msg })
    }

    fn parse_neg_err(rest: &[&'a RawValue]) -> Result<Self, RelayMessageError> {
        let limit = match rest.get(2) {
            Some(raw) => Some(
                serde_json::from_str::<u64>(raw.get())
                    .map_err(|_| RelayMessageError::Malformed("NEG-ERR limit"))?,
            ),
            None => None,
        };
        Ok(RelayMessage::NegErr {
            sub: element::<String>(rest.first(), "NEG-ERR subscription id")?,
            message: element::<String>(rest.get(1), "NEG-ERR message")?,
            limit,
        })
    }
}

/// Deserialize `raw` (a required element) into `T`; a missing element
/// or wrong type maps to a `Malformed` naming the field.
fn element<'a, T: serde::Deserialize<'a>>(
    raw: Option<&&'a RawValue>,
    what: &'static str,
) -> Result<T, RelayMessageError> {
    let raw = raw.ok_or(RelayMessageError::Malformed(what))?;
    serde_json::from_str(raw.get()).map_err(|_| RelayMessageError::Malformed(what))
}

/// The optional trailing retry hint on `OK`/`CLOSED`: a
/// decimal-millisecond string (what nosfry sends) or a non-negative
/// JSON integer, capped at [`MAX_RETRY_MS`]. Anything else is `None`.
fn retry_hint(raw: Option<&&RawValue>) -> Option<u64> {
    let raw = raw?;
    let ms = serde_json::from_str::<String>(raw.get())
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| serde_json::from_str::<u64>(raw.get()).ok())?;
    Some(ms.min(MAX_RETRY_MS))
}

/// The machine-readable prefix of a NIP-01 message.
///
/// The text before the first `':'` (`"rate-limited"`, `"blocked"`,
/// `"auth-required"`, `"closed"`, `"error"`, `"restricted"`,
/// `"invalid"`, `"duplicate"`, …). Messages without a colon are
/// their own prefix.
#[must_use]
pub fn reason_prefix(message: &str) -> &str {
    message.split_once(':').map_or(message, |(head, _)| head)
}

/// The slice of a peer's NIP-11 document `nosfry sync` uses, each
/// field independently lenient.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PeerLimits {
    /// `limitation.max_message_length` (`None` when absent, not a
    /// number, or `0`).
    pub max_message_length: Option<u64>,
    /// `limitation.max_limit` (`None` when absent, not a number, or
    /// `0`).
    pub max_limit: Option<u64>,
    /// `supported_nips` (capped at 256 entries).
    pub supported_nips: Option<Vec<u64>>,
    /// `limitation.auth_required`.
    pub auth_required: Option<bool>,
}

impl PeerLimits {
    /// Parse a NIP-11 document; `None` when `bytes` is not a JSON
    /// object. Fields of the wrong type fall back to `None` and `0`
    /// counts as unset — a peer may advertise partial limits.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let doc: serde_json::Map<String, Value> = serde_json::from_slice(bytes).ok()?;
        let limitation = doc.get("limitation").and_then(Value::as_object);
        let positive = |value: Option<&Value>| value.and_then(Value::as_u64).filter(|&n| n > 0);
        Some(Self {
            max_message_length: positive(limitation.and_then(|l| l.get("max_message_length"))),
            max_limit: positive(limitation.and_then(|l| l.get("max_limit"))),
            supported_nips: doc
                .get("supported_nips")
                .and_then(Value::as_array)
                .map(|nips| {
                    nips.iter()
                        .filter_map(Value::as_u64)
                        .take(MAX_SUPPORTED_NIPS)
                        .collect()
                }),
            auth_required: limitation
                .and_then(|l| l.get("auth_required"))
                .and_then(Value::as_bool),
        })
    }
}

/// A peer's `max_message_length` leaves less than negentropy's
/// 4,096-byte minimum for a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("peer's max_message_length leaves a {0}-byte negentropy frame (< 4096)")]
pub struct FrameTooSmall(pub u64);

/// The negentropy frame limit to offer the peer.
///
/// `(max_message_length - 256) / 2` (hex doubles the payload), capped
/// at 500,000. Without a document, 60,000 — strfry's frame size,
/// which fits a 128 KiB peer.
///
/// # Errors
///
/// [`FrameTooSmall`] when the advertised limit leaves less than the
/// negentropy protocol's 4,096-byte minimum.
pub fn neg_frame_limit(max_message_length: Option<u64>) -> Result<u64, FrameTooSmall> {
    let Some(max) = max_message_length else {
        return Ok(60_000);
    };
    let limit = (max.saturating_sub(256) / 2).min(500_000);
    if limit < 4_096 {
        return Err(FrameTooSmall(limit));
    }
    Ok(limit)
}

/// How many ids one `REQ {"ids":[…]}` batch asks for.
///
/// The smallest of 500, the peer's `max_limit`, and what fits its
/// `max_message_length` (67 bytes per `"<64-hex>",` element, 128 bytes
/// of frame headroom), at least 1.
#[must_use]
pub fn ids_per_req(limits: &PeerLimits) -> usize {
    let by_limit = limits
        .max_limit
        .map_or(500, |max| usize::try_from(max).unwrap_or(usize::MAX));
    let by_frame = limits.max_message_length.map_or(500, |max| {
        usize::try_from(max.saturating_sub(128) / 67).unwrap_or(usize::MAX)
    });
    by_limit.min(by_frame).clamp(1, 500)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;

    fn event() -> String {
        let json = serde_json::json!({"id": "ab".repeat(32), "content": "hi"});
        format!("[\"EVENT\",\"s1\",{json}]")
    }

    #[test]
    fn event_borrows_the_raw_json() {
        let text = event();
        let RelayMessage::Event { sub, event } = RelayMessage::parse(&text).unwrap() else {
            panic!("not an EVENT");
        };
        assert_eq!(sub, "s1");
        assert!(event.get().contains("\"content\":\"hi\""));
    }

    #[test]
    fn ok_parses_hint_string_and_number() {
        let id = "ab".repeat(32);
        let RelayMessage::Ok {
            id: parsed,
            accepted,
            message,
            retry_after_ms,
        } = RelayMessage::parse(&format!(
            "[\"OK\",\"{id}\",false,\"rate-limited: slow down\",\"1500\"]"
        ))
        .unwrap()
        else {
            panic!("not an OK");
        };
        assert_eq!(parsed.0, [0xab; 32]);
        assert!(!accepted);
        assert_eq!(message, "rate-limited: slow down");
        assert_eq!(retry_after_ms, Some(1_500));
        // A JSON integer hint works the same way.
        assert_eq!(
            ok_hint(&format!("[\"OK\",\"{id}\",true,\"\",250]")),
            Some(250)
        );
        // No hint at all.
        assert_eq!(ok_hint(&format!("[\"OK\",\"{id}\",true,\"\"]")), None);
    }

    /// The `retry_after_ms` of a parsed `OK` frame (test helper).
    fn ok_hint(frame: &str) -> Option<u64> {
        let RelayMessage::Ok { retry_after_ms, .. } = RelayMessage::parse(frame).unwrap() else {
            panic!("not an OK");
        };
        retry_after_ms
    }

    #[test]
    fn hint_is_capped_and_garbage_ignored() {
        let id = "ab".repeat(32);
        assert_eq!(
            ok_hint(&format!("[\"OK\",\"{id}\",false,\"m\",\"999999999\"]")),
            Some(MAX_RETRY_MS)
        );
        // A negative number, a float, a non-decimal string: no hint.
        for hint in ["-5", "1.5", "\"soon\"", "true"] {
            assert_eq!(
                ok_hint(&format!("[\"OK\",\"{id}\",false,\"m\",{hint}]")),
                None,
                "{hint}"
            );
        }
    }

    #[test]
    fn closed_parses_hint() {
        let RelayMessage::Closed {
            sub,
            message,
            retry_after_ms,
        } = RelayMessage::parse("[\"CLOSED\",\"s\",\"rate-limited: too many\",\"2000\"]").unwrap()
        else {
            panic!("not a CLOSED");
        };
        assert_eq!(sub, "s");
        assert_eq!(message, "rate-limited: too many");
        assert_eq!(retry_after_ms, Some(2_000));
    }

    #[test]
    fn eose_notice_auth() {
        assert!(matches!(
            RelayMessage::parse("[\"EOSE\",\"x\"]").unwrap(),
            RelayMessage::Eose { sub } if sub == "x"
        ));
        assert!(matches!(
            RelayMessage::parse("[\"NOTICE\",\"hi there\"]").unwrap(),
            RelayMessage::Notice { message } if message == "hi there"
        ));
        let RelayMessage::Auth { challenge } =
            RelayMessage::parse("[\"AUTH\",\"deadbeef\"]").unwrap()
        else {
            panic!("not an AUTH");
        };
        assert_eq!(challenge, "deadbeef");
        // Over the bound the challenge is an error, not a signature.
        let big = format!("[\"AUTH\",\"{}\"]", "a".repeat(MAX_AUTH_CHALLENGE + 1));
        assert!(matches!(
            RelayMessage::parse(&big),
            Err(RelayMessageError::AuthChallengeTooLarge)
        ));
        let ok_size = format!("[\"AUTH\",\"{}\"]", "a".repeat(MAX_AUTH_CHALLENGE));
        assert!(RelayMessage::parse(&ok_size).is_ok());
    }

    #[test]
    fn neg_msg_decodes_both_hex_cases() {
        let RelayMessage::NegMsg { sub, msg } =
            RelayMessage::parse("[\"NEG-MSG\",\"n1\",\"60aB\"]").unwrap()
        else {
            panic!("not a NEG-MSG");
        };
        assert_eq!(sub, "n1");
        assert_eq!(msg, vec![0x60, 0xab]);
        // Odd length and non-hex both refuse.
        assert!(matches!(
            RelayMessage::parse("[\"NEG-MSG\",\"n1\",\"abc\"]"),
            Err(RelayMessageError::Malformed(_))
        ));
        assert!(matches!(
            RelayMessage::parse("[\"NEG-MSG\",\"n1\",\"zz\"]"),
            Err(RelayMessageError::Malformed(_))
        ));
        assert!(matches!(
            RelayMessage::parse("[\"NEG-MSG\",\"n1\",\"\"]"),
            Err(RelayMessageError::Malformed(_))
        ));
    }

    #[test]
    fn neg_err_reads_the_limit_element() {
        let RelayMessage::NegErr {
            sub,
            message,
            limit,
        } = RelayMessage::parse("[\"NEG-ERR\",\"n\",\"blocked: too many query results\",20]")
            .unwrap()
        else {
            panic!("not a NEG-ERR");
        };
        assert_eq!(sub, "n");
        assert_eq!(message, "blocked: too many query results");
        assert_eq!(limit, Some(20));
        let RelayMessage::NegErr { limit: none, .. } =
            RelayMessage::parse("[\"NEG-ERR\",\"n\",\"closed: unknown subscription\"]").unwrap()
        else {
            panic!("not a NEG-ERR");
        };
        assert_eq!(none, None);
        // A non-numeric limit is malformed.
        assert!(matches!(
            RelayMessage::parse("[\"NEG-ERR\",\"n\",\"blocked: x\",\"20\"]"),
            Err(RelayMessageError::Malformed(_))
        ));
    }

    #[test]
    fn other_and_malformed() {
        assert!(matches!(
            RelayMessage::parse("[\"COUNT\",\"s\",{\"count\":3}]").unwrap(),
            RelayMessage::Other
        ));
        assert!(matches!(
            RelayMessage::parse("[\"WOOF\",\"s\"]").unwrap(),
            RelayMessage::Other
        ));
        for text in [
            "not json",
            "{}",
            "[]",
            "[1,2]",
            "[\"EVENT\"]",
            "[\"EVENT\",\"s\"]",
            "[\"OK\",\"zz\",true,\"\"]",
            "[\"EOSE\"]",
            "[\"CLOSED\",\"s\"]",
            "[\"AUTH\"]",
            "[\"NEG-MSG\",\"n\"]",
        ] {
            assert!(RelayMessage::parse(text).is_err(), "{text} should fail");
        }
    }

    #[test]
    fn reason_prefix_splits_on_first_colon() {
        assert_eq!(reason_prefix("blocked: too many query results"), "blocked");
        assert_eq!(reason_prefix("rate-limited: slow down"), "rate-limited");
        assert_eq!(
            reason_prefix("auth-required: we only serve"),
            "auth-required"
        );
        assert_eq!(reason_prefix("duplicate: have a newer"), "duplicate");
        assert_eq!(reason_prefix("no colon here"), "no colon here");
        assert_eq!(reason_prefix(""), "");
    }

    #[test]
    fn peer_limits_lenient_per_field() {
        let doc = br#"{"limitation":{"max_message_length":262144,"max_limit":5000,
            "auth_required":true},"supported_nips":[1,11,42,77]}"#;
        let limits = PeerLimits::parse(doc).unwrap();
        assert_eq!(limits.max_message_length, Some(262_144));
        assert_eq!(limits.max_limit, Some(5_000));
        assert_eq!(limits.supported_nips, Some(vec![1, 11, 42, 77]));
        assert_eq!(limits.auth_required, Some(true));

        // Not a JSON object at all.
        assert_eq!(PeerLimits::parse(b"[1,2]"), None);
        assert_eq!(PeerLimits::parse(b"garbage"), None);
        // Empty object: every field lenient-None.
        assert_eq!(PeerLimits::parse(b"{}"), Some(PeerLimits::default()));
        // Wrong types and zeroes are None, not errors.
        let wrong_types = br#"{"limitation":{"max_message_length":"big","max_limit":0,
            "auth_required":"yes"},"supported_nips":"nope"}"#;
        assert_eq!(PeerLimits::parse(wrong_types), Some(PeerLimits::default()));
        // supported_nips keeps only numbers, capped at 256.
        let many_nips = format!(
            "{{\"supported_nips\":[{}]}}",
            (0..400)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            PeerLimits::parse(many_nips.as_bytes())
                .unwrap()
                .supported_nips
                .map(|v| v.len()),
            Some(256)
        );
    }

    #[test]
    fn neg_frame_limit_bounds() {
        assert_eq!(neg_frame_limit(None), Ok(60_000));
        // Hex doubles the payload; overhead subtracted first.
        assert_eq!(neg_frame_limit(Some(131_072)), Ok(65_408));
        // The absolute cap wins.
        assert_eq!(neg_frame_limit(Some(10_000_000)), Ok(500_000));
        // Below negentropy's minimum the peer is refused.
        assert!(neg_frame_limit(Some(8_000)).is_err());
        assert_eq!(neg_frame_limit(Some(8_448)), Ok(4_096));
    }

    #[test]
    fn ids_per_req_bounds() {
        assert_eq!(ids_per_req(&PeerLimits::default()), 500);
        assert_eq!(
            ids_per_req(&PeerLimits {
                max_limit: Some(10),
                ..PeerLimits::default()
            }),
            10
        );
        // (16384 - 128) / 67 = 242.
        assert_eq!(
            ids_per_req(&PeerLimits {
                max_message_length: Some(16_384),
                ..PeerLimits::default()
            }),
            242
        );
        // Never zero.
        assert_eq!(
            ids_per_req(&PeerLimits {
                max_message_length: Some(10),
                max_limit: Some(0),
                ..PeerLimits::default()
            }),
            1
        );
    }
}
