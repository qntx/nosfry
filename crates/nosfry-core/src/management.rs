//! NIP-86 relay management protocol (transport-agnostic).
//!
//! Content type and body limit, the `[relay.management]` config, the
//! NIP-98 [`authorize`] gate, and request dispatch into [`Action`]s.
//! Transports (axum native, Durable Object worker) keep only their
//! HTTP plumbing and the store round-trip.

use std::fmt;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::event::{EventId, EventLimits, PublicKey, UnverifiedEvent};
use crate::moderation::{InfoField, ModOp, Moderation};
use crate::url::RelayNames;

/// The content type a NIP-86 request must carry.
pub const CONTENT_TYPE: &str = "application/nostr+json+rpc";

/// Request body cap in bytes — `413` above.
pub const BODY_LIMIT: usize = 64 * 1024;

/// NIP-98 `created_at` tolerance in seconds.
const AUTH_WINDOW_SECONDS: u64 = 60;

/// The implemented NIP-86 method set (`supportedmethods` result).
pub const METHODS: &[&str] = &[
    "allowkind",
    "allowpubkey",
    "banevent",
    "banpubkey",
    "blockip",
    "changerelaydescription",
    "changerelayicon",
    "changerelayname",
    "disallowkind",
    "listallowedkinds",
    "listallowedpubkeys",
    "listbannedevents",
    "listbannedpubkeys",
    "listblockedips",
    "listdisallowedkinds",
    "supportedmethods",
    "unallowpubkey",
    "unbanevent",
    "unbanpubkey",
    "unblockip",
];

/// `[relay.management]` — the NIP-86 relay management API.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ManagementConfig {
    /// Admin pubkeys (lowercase 64-hex) authorized for `POST /` with
    /// `application/nostr+json+rpc`. The endpoint exists only when
    /// non-empty, and `u`-tag checks need `[relay] service_url`.
    pub admins: Vec<String>,
}

/// A malformed `[relay.management] admins` entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("relay.management.admins: {0}: not a 64-hex pubkey")]
pub struct AdminsError(pub String);

impl ManagementConfig {
    /// The validated admin key set; empty `admins` yields an empty
    /// list.
    ///
    /// # Errors
    ///
    /// [`AdminsError`] on an entry that is not a lowercase 64-hex
    /// pubkey.
    pub fn admin_keys(&self) -> Result<Vec<PublicKey>, AdminsError> {
        self.admins
            .iter()
            .map(|admin| PublicKey::from_hex(admin).ok_or_else(|| AdminsError(admin.clone())))
            .collect()
    }
}

/// A rejected NIP-98 authorization — the `unauthorized: <reason>`
/// tail for the 401 body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No `Authorization` header.
    #[error("missing authorization header")]
    MissingHeader,
    /// A scheme other than `Nostr`.
    #[error("expected the `Nostr` authorization scheme")]
    Scheme,
    /// The payload is not base64.
    #[error("malformed base64 auth event")]
    Base64,
    /// The decoded event is not UTF-8.
    #[error("auth event is not utf-8")]
    Utf8,
    /// The decoded event does not parse under the limits.
    #[error("invalid auth event")]
    Invalid,
    /// Not kind 27235.
    #[error("auth event must be kind 27235")]
    Kind,
    /// `created_at` outside the ±60 s window.
    #[error("stale auth event timestamp")]
    Stale,
    /// A `method` tag other than `POST`.
    #[error("auth event `method` tag must be POST")]
    Method,
    /// No `payload` tag.
    #[error("missing `payload` tag")]
    MissingPayload,
    /// The `payload` tag is not the body's SHA-256.
    #[error("`payload` tag does not match the body")]
    PayloadMismatch,
    /// `[relay] service_url` is unset, so `u` cannot be checked.
    #[error("no service_url configured")]
    NoServiceUrl,
    /// The `u` tag names another relay.
    #[error("`u` tag does not match this relay")]
    UrlMismatch,
    /// The BIP-340 signature is invalid.
    #[error("invalid auth event signature")]
    Signature,
    /// The signer is not in `[relay.management] admins`.
    #[error("pubkey is not an admin")]
    NotAdmin,
}

/// The NIP-86 request envelope.
#[derive(Debug, Deserialize)]
pub struct Request<'a> {
    /// Method name.
    pub method: &'a str,
    /// Positional parameters (`[]` when absent).
    #[serde(default)]
    pub params: Vec<Value>,
}

/// What a parsed request asks of the transport: answer inline, or
/// apply a mutation through the store first.
#[derive(Debug)]
pub enum Action {
    /// Read-only answer — `{"result": value}`.
    Respond(Value),
    /// Mutation — the transport applies the op through the store,
    /// then answers `{"result": true}`.
    Apply(ModOp),
}

/// Dispatch one parsed request.
///
/// # Errors
///
/// The `String` becomes the `{"error": …}` response body at HTTP 200
/// (method-level errors are not HTTP errors).
pub fn action(request: &Request<'_>, m: &Moderation) -> Result<Action, String> {
    let op = match request.method {
        "supportedmethods" => return Ok(Action::Respond(json!(METHODS))),
        "listbannedpubkeys" => {
            return Ok(Action::Respond(listed(m.banned_pubkeys.iter(), "pubkey")));
        }
        "listallowedpubkeys" => {
            return Ok(Action::Respond(listed(m.allowed_pubkeys.iter(), "pubkey")));
        }
        "listbannedevents" => return Ok(Action::Respond(listed(m.banned_events.iter(), "id"))),
        "listblockedips" => return Ok(Action::Respond(listed(m.blocked_ips.iter(), "ip"))),
        "listallowedkinds" => return Ok(Action::Respond(kinds(&m.allowed_kinds))),
        "listdisallowedkinds" => return Ok(Action::Respond(kinds(&m.disallowed_kinds))),
        "banpubkey" => ModOp::BanPubkey {
            pubkey: pubkey_param(&request.params)?,
            reason: reason_param(&request.params),
        },
        "unbanpubkey" => ModOp::UnbanPubkey {
            pubkey: pubkey_param(&request.params)?,
        },
        "allowpubkey" => ModOp::AllowPubkey {
            pubkey: pubkey_param(&request.params)?,
            reason: reason_param(&request.params),
        },
        "unallowpubkey" => ModOp::UnallowPubkey {
            pubkey: pubkey_param(&request.params)?,
        },
        "banevent" => ModOp::BanEvent {
            id: event_id_param(&request.params)?,
            reason: reason_param(&request.params),
        },
        "unbanevent" => ModOp::UnbanEvent {
            id: event_id_param(&request.params)?,
        },
        "allowkind" => ModOp::AllowKind {
            kind: kind_param(&request.params)?,
        },
        "disallowkind" => ModOp::DisallowKind {
            kind: kind_param(&request.params)?,
        },
        "blockip" => ModOp::BlockIp {
            ip: ip_param(&request.params)?,
            reason: reason_param(&request.params),
        },
        "unblockip" => ModOp::UnblockIp {
            ip: ip_param(&request.params)?,
        },
        "changerelayname" => ModOp::SetInfo {
            field: InfoField::Name,
            value: info_param(&request.params)?,
        },
        "changerelaydescription" => ModOp::SetInfo {
            field: InfoField::Description,
            value: info_param(&request.params)?,
        },
        "changerelayicon" => ModOp::SetInfo {
            field: InfoField::Icon,
            value: info_param(&request.params)?,
        },
        other => return Err(format!("unsupported method: {other}")),
    };
    Ok(Action::Apply(op))
}

/// The NIP-98 gate, as NIP-86 requires.
///
/// `kind 27235`, `created_at` within ±60 s of `now`, `method` =
/// `POST`, `payload` = the SHA-256 of the raw `body`, `u` matching
/// any of the relay's `names` host-normalized, pubkey in `admins`,
/// and a valid BIP-340 signature.
///
/// # Errors
///
/// The [`AuthError`] naming which check failed.
pub fn authorize(
    authorization: Option<&str>,
    body: &[u8],
    now: u64,
    events: &EventLimits,
    names: &RelayNames,
    admins: &[PublicKey],
) -> Result<(), AuthError> {
    let Some(value) = authorization else {
        return Err(AuthError::MissingHeader);
    };
    let mut parts = value.splitn(2, ' ');
    if parts
        .next()
        .is_none_or(|s| !s.eq_ignore_ascii_case("Nostr"))
    {
        return Err(AuthError::Scheme);
    }
    let json = BASE64
        .decode(parts.next().unwrap_or_default().trim())
        .map_err(|_| AuthError::Base64)?;
    let text = std::str::from_utf8(&json).map_err(|_| AuthError::Utf8)?;
    let event = UnverifiedEvent::parse(text, events).map_err(|_| AuthError::Invalid)?;
    // Cheap checks first; the BIP-340 verify runs last.
    if u16::from(event.kind()) != 27235 {
        return Err(AuthError::Kind);
    }
    if event.created_at().abs_diff(now) > AUTH_WINDOW_SECONDS {
        return Err(AuthError::Stale);
    }
    if event.tag_values("method").next() != Some("POST") {
        return Err(AuthError::Method);
    }
    let digest = faster_hex::hex_string(&Sha256::digest(body));
    match event.tag_values("payload").next() {
        None => return Err(AuthError::MissingPayload),
        Some(tag) if tag != digest => {
            return Err(AuthError::PayloadMismatch);
        }
        Some(_) => {}
    }
    if names.is_empty() {
        return Err(AuthError::NoServiceUrl);
    }
    if !event
        .tag_values("u")
        .next()
        .is_some_and(|u| names.matches(u))
    {
        return Err(AuthError::UrlMismatch);
    }
    let pubkey = event.pubkey();
    // Verify before the admin check, so an unsigned probe cannot learn
    // which pubkeys are admins from the error.
    event.verify(events).map_err(|_| AuthError::Signature)?;
    if !admins.contains(&pubkey) {
        return Err(AuthError::NotAdmin);
    }
    Ok(())
}

/// Render a `mod_*` map as the NIP-86 `[{field, reason?}]` list,
/// sorted by key for a stable output.
fn listed<'a, K>(rows: impl Iterator<Item = (&'a K, &'a Option<Box<str>>)>, field: &str) -> Value
where
    K: Ord + fmt::Display + 'a,
{
    let mut rows: Vec<_> = rows.collect();
    rows.sort_by(|a, b| a.0.cmp(b.0));
    Value::Array(
        rows.into_iter()
            .map(|(key, reason)| {
                let mut obj = Map::new();
                obj.insert(field.to_owned(), Value::String(key.to_string()));
                if let Some(reason) = reason {
                    obj.insert("reason".to_owned(), Value::String(reason.to_string()));
                }
                Value::Object(obj)
            })
            .collect(),
    )
}

/// Render a kind set as `[kind, …]` (sorted — `BTreeSet` order).
fn kinds(set: &std::collections::BTreeSet<u16>) -> Value {
    Value::Array(set.iter().map(|kind| json!(kind)).collect())
}

/// `params[0]` as a hex pubkey.
fn pubkey_param(params: &[Value]) -> Result<PublicKey, String> {
    params
        .first()
        .and_then(Value::as_str)
        .and_then(PublicKey::from_hex)
        .ok_or_else(|| "invalid params: expected a 64-hex pubkey".to_owned())
}

/// `params[0]` as a hex event id.
fn event_id_param(params: &[Value]) -> Result<EventId, String> {
    params
        .first()
        .and_then(Value::as_str)
        .and_then(EventId::from_hex)
        .ok_or_else(|| "invalid params: expected a 64-hex event id".to_owned())
}

/// `params[0]` as a kind number.
fn kind_param(params: &[Value]) -> Result<u16, String> {
    params
        .first()
        .and_then(Value::as_u64)
        .and_then(|k| u16::try_from(k).ok())
        .ok_or_else(|| "invalid params: expected a kind number".to_owned())
}

/// `params[0]` as an IP address.
fn ip_param(params: &[Value]) -> Result<IpAddr, String> {
    params
        .first()
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "invalid params: expected an IP address".to_owned())
}

/// `params[0]` as a string (info fields).
fn info_param(params: &[Value]) -> Result<String, String> {
    params
        .first()
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "invalid params: expected a string value".to_owned())
}

/// `params[1]` as an optional reason string.
fn reason_param(params: &[Value]) -> Option<String> {
    params.get(1).and_then(Value::as_str).map(str::to_owned)
}
