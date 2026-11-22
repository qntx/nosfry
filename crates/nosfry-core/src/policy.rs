//! The strfry-compatible write-policy protocol: the `{"type":"new",…}`
//! request line a policy receives for each verified event and the
//! `{"id","action","msg"}` verdict line it answers with.
//!
//! The request is transport-agnostic JSON — the native edition pipes
//! it through a child process's stdio, the Workers edition POSTs it
//! to a service binding.
//!
//! - Request: `{"type":"new","event":<raw>,"receivedAt":<unix>,`
//!   `"sourceType":"IP4"|"IP6"|"Unix","sourceInfo":"<ip or path>"[,`
//!   `"authed":"<hex pubkey>"]}` — IPv4-mapped IPv6 reports `IP4`
//!   with the v4 address; a unix-socket listener reports `Unix` with
//!   its socket path; `authed` appears only after the connection
//!   authenticated (NIP-42).
//! - Response: `{"id":"<event id>","action":"accept"|"reject"|`
//!   `"shadowReject","msg":"..."}` (`msg` optional). Non-JSON lines
//!   are [`ResponseError::Noise`] so transports that stream lines may
//!   skip them; an id mismatch or unknown action is fatal.

use std::net::IpAddr;

use serde_json::Value;

use crate::event::PublicKey;

/// The policy's verdict on one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Continue the normal path.
    Accept,
    /// `OK false <msg>`; an empty `msg` gets a NIP-01 default at the
    /// caller.
    Reject(String),
    /// `OK true <msg>` without storing or broadcasting.
    ShadowReject(String),
}

/// The strfry input line for one event: minified JSON, the event
/// embedded raw (no re-serialization); `authed` is the hex pubkey the
/// connection authenticated with (NIP-42), omitted when absent.
pub fn request_line(
    event_json: &str,
    received_at: u64,
    source: IpAddr,
    authed: Option<PublicKey>,
) -> String {
    let (source_type, source_info) = source_parts(source);
    let authed = authed.map_or_else(String::new, |pk| {
        format!(",\"authed\":\"{}\"", faster_hex::hex_string(&pk.0))
    });
    format!(
        "{{\"type\":\"new\",\"event\":{event_json},\"receivedAt\":{received_at},\
         \"sourceType\":\"{source_type}\",\"sourceInfo\":\"{source_info}\"{authed}}}"
    )
}

/// `sourceType`/`sourceInfo` for an address: IPv4-mapped IPv6 counts
/// as `IP4` with the v4 address (strfry's `renderIP`).
fn source_parts(ip: IpAddr) -> (&'static str, String) {
    match ip {
        IpAddr::V4(_) => ("IP4", ip.to_string()),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| ("IP6", ip.to_string()), |v4| ("IP4", v4.to_string())),
    }
}

/// The request line for a source with no client address — a
/// unix-socket listener.
///
/// Reports `"sourceType":"Unix"` and the socket path, JSON-escaped —
/// filesystem paths may carry characters a raw interpolation would
/// break.
pub fn request_line_unix(
    event_json: &str,
    received_at: u64,
    source_info: &str,
    authed: Option<PublicKey>,
) -> String {
    let info = serde_json::to_string(source_info).unwrap_or_else(|_| "\"\"".to_owned());
    let authed = authed.map_or_else(String::new, |pk| {
        format!(",\"authed\":\"{}\"", faster_hex::hex_string(&pk.0))
    });
    format!(
        "{{\"type\":\"new\",\"event\":{event_json},\"receivedAt\":{received_at},\
         \"sourceType\":\"Unix\",\"sourceInfo\":{info}{authed}}}"
    )
}

/// Parse one response line; [`ResponseError::Noise`] marks input the
/// transport may skip, [`ResponseError::Fatal`] fails the request.
///
/// # Errors
///
/// [`ResponseError::Noise`] when the bytes are not JSON;
/// [`ResponseError::Fatal`] on an `id` mismatch, a missing or
/// non-string `action`, or an unknown `action`.
pub fn parse_response(bytes: &[u8], expected_id: &str) -> Result<Decision, ResponseError> {
    let Ok(response) = serde_json::from_slice::<Value>(bytes) else {
        return Err(ResponseError::Noise);
    };
    if response.get("id").and_then(Value::as_str) != Some(expected_id) {
        return Err(ResponseError::Fatal(PolicyError::IdMismatch));
    }
    let Some(action) = response.get("action").and_then(Value::as_str) else {
        return Err(ResponseError::Fatal(PolicyError::Malformed));
    };
    let msg = response
        .get("msg")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    match action {
        "accept" => Ok(Decision::Accept),
        "reject" => Ok(Decision::Reject(msg)),
        "shadowReject" => Ok(Decision::ShadowReject(msg)),
        other => Err(ResponseError::Fatal(PolicyError::UnknownAction(
            other.to_owned(),
        ))),
    }
}

/// Ways a policy response can fail the request it answers.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The response's `id` differs from the request's event id.
    #[error("response id mismatch")]
    IdMismatch,
    /// The response lacks a string `id` or `action`.
    #[error("malformed response")]
    Malformed,
    /// The response's `action` is none of the known values.
    #[error("unknown action: {0}")]
    UnknownAction(String),
}

/// Parse-failure severity.
#[derive(Debug)]
pub enum ResponseError {
    /// Not JSON: a streaming transport may skip the line with a
    /// warning (plugins may print noise); a one-shot transport treats
    /// it as any other failure.
    Noise,
    /// Everything else rejects the event.
    Fatal(PolicyError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// A plausible event JSON (field order intentionally
    /// non-alphabetical to prove raw embedding).
    const EVENT_JSON: &str = concat!(
        "{\"id\":\"0000000000000000000000000000000000000000000000000000000000000001\",",
        "\"pubkey\":\"0000000000000000000000000000000000000000000000000000000000000002\",",
        "\"created_at\":1700000000,\"kind\":1,\"tags\":[],\"content\":\"hi\",",
        "\"sig\":\"0000000000000000000000000000000000000000000000000000000000000003\"}",
    );

    /// The request line's wire shape, for assertions.
    #[derive(serde::Deserialize)]
    struct Req<'a> {
        #[serde(rename = "type")]
        kind: String,
        #[serde(borrow)]
        event: &'a serde_json::value::RawValue,
        #[serde(rename = "receivedAt")]
        received_at: u64,
        #[serde(rename = "sourceType")]
        source_type: String,
        #[serde(rename = "sourceInfo")]
        source_info: String,
        authed: Option<String>,
    }

    #[test]
    fn request_line_shape() {
        let line = request_line(
            EVENT_JSON,
            1_700_000_000,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            Some(PublicKey([0xab; 32])),
        );
        let request: Req<'_> = serde_json::from_str(&line).unwrap();
        assert_eq!(request.kind, "new");
        assert_eq!(request.received_at, 1_700_000_000);
        assert_eq!(request.source_type, "IP4");
        assert_eq!(request.source_info, "192.0.2.7");
        assert_eq!(request.authed.as_deref(), Some(&"ab".repeat(32)[..]));
        // The event is embedded raw: byte-identical, not reserialized.
        assert_eq!(request.event.get(), EVENT_JSON);
        // Unauthenticated connections omit the field.
        let anonymous = request_line(
            EVENT_JSON,
            1_700_000_000,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
        );
        assert!(!anonymous.contains("authed"), "{anonymous}");
    }

    #[test]
    fn source_parts_maps_v4_mapped_v6() {
        assert_eq!(
            source_parts("::ffff:192.0.2.9".parse().unwrap()),
            ("IP4", "192.0.2.9".to_owned())
        );
        assert_eq!(
            source_parts("2001:db8::1".parse().unwrap()),
            ("IP6", "2001:db8::1".to_owned())
        );
    }

    /// A unix-socket listener reports `sourceType` `Unix` with the
    /// socket path, escaped as a JSON string.
    #[test]
    fn request_line_unix_shape() {
        let line = request_line_unix(EVENT_JSON, 1_700_000_000, "/run/nosfry/tor.sock", None);
        let request: Req<'_> = serde_json::from_str(&line).unwrap();
        assert_eq!(request.kind, "new");
        assert_eq!(request.received_at, 1_700_000_000);
        assert_eq!(request.source_type, "Unix");
        assert_eq!(request.source_info, "/run/nosfry/tor.sock");
        assert_eq!(request.event.get(), EVENT_JSON);
        // A path with JSON metacharacters still parses.
        let escaped = request_line_unix(EVENT_JSON, 0, "/tmp/a\"b\nsock", None);
        let parsed: Req<'_> = serde_json::from_str(&escaped).unwrap();
        assert_eq!(parsed.source_info, "/tmp/a\"b\nsock");
    }

    #[test]
    fn parse_response_decisions() {
        let id = "a".repeat(64);
        assert_eq!(
            parse_response(
                format!("{{\"id\":\"{id}\",\"action\":\"accept\"}}").as_bytes(),
                &id
            )
            .ok(),
            Some(Decision::Accept)
        );
        assert_eq!(
            parse_response(
                format!("{{\"id\":\"{id}\",\"action\":\"reject\",\"msg\":\"blocked: spam\"}}")
                    .as_bytes(),
                &id
            )
            .ok(),
            Some(Decision::Reject("blocked: spam".to_owned()))
        );
        assert_eq!(
            parse_response(
                format!("{{\"id\":\"{id}\",\"action\":\"reject\"}}").as_bytes(),
                &id
            )
            .ok(),
            Some(Decision::Reject(String::new()))
        );
        assert_eq!(
            parse_response(
                format!("{{\"id\":\"{id}\",\"action\":\"shadowReject\",\"msg\":\"m\"}}").as_bytes(),
                &id
            )
            .ok(),
            Some(Decision::ShadowReject("m".to_owned()))
        );
    }

    #[test]
    fn parse_response_failures() {
        let id = "a".repeat(64);
        // Non-JSON is noise, not an error.
        assert!(matches!(
            parse_response(b"this is plugin noise", &id),
            Err(ResponseError::Noise)
        ));
        assert!(matches!(
            parse_response(
                format!("{{\"id\":\"{}\",\"action\":\"accept\"}}", "b".repeat(64)).as_bytes(),
                &id
            ),
            Err(ResponseError::Fatal(PolicyError::IdMismatch))
        ));
        assert!(matches!(
            parse_response(
                format!("{{\"id\":\"{id}\",\"action\":\"bogus\"}}").as_bytes(),
                &id
            ),
            Err(ResponseError::Fatal(PolicyError::UnknownAction(_)))
        ));
        // Missing action is a malformed response, not noise.
        assert!(matches!(
            parse_response(format!("{{\"id\":\"{id}\"}}").as_bytes(), &id),
            Err(ResponseError::Fatal(PolicyError::Malformed))
        ));
    }
}
