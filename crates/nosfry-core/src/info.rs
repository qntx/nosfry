//! NIP-11 relay information: the `[relay.info]` configuration and
//! the document builder shared by the native and Workers editions.

use serde::Deserialize;
use serde_json::json;

use crate::hex::is_lower_hex;
use crate::limits::Limits;
use crate::message::SUB_ID_MAX_CHARS;
use crate::moderation::Moderation;

/// `[relay.info]` — NIP-11 document fields.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Info {
    /// Relay name.
    pub name: String,
    /// Plain-text description.
    pub description: String,
    /// Relay operator pubkey (hex).
    pub pubkey: String,
    /// Relay operator contact.
    pub contact: String,
    /// Relay icon URL.
    pub icon: String,
    /// Relay banner URL.
    pub banner: String,
    /// The relay's own pubkey (hex); the TOML key is `self`.
    #[serde(rename = "self")]
    pub self_pubkey: String,
    /// Terms of service URL.
    pub terms_of_service: String,
    /// Privacy policy URL.
    pub privacy_policy: String,
    /// Supported NIP numbers. Absent computes the list from the
    /// enabled features; present replaces it verbatim.
    pub supported_nips: Option<Vec<u16>>,
}

impl Default for Info {
    fn default() -> Self {
        Self {
            name: "nosfry".into(),
            description: String::new(),
            pubkey: String::new(),
            contact: String::new(),
            icon: String::new(),
            banner: String::new(),
            self_pubkey: String::new(),
            terms_of_service: String::new(),
            privacy_policy: String::new(),
            supported_nips: None,
        }
    }
}

impl Info {
    /// The effective relay info: the NIP-86 moderation snapshot's
    /// `name`/`description`/`icon` override the configured values
    /// where set.
    #[must_use]
    pub fn with_overrides(&self, moderation: &Moderation) -> Self {
        let mut info = self.clone();
        if let Some(name) = &moderation.name {
            info.name = name.to_string();
        }
        if let Some(description) = &moderation.description {
            info.description = description.to_string();
        }
        if let Some(icon) = &moderation.icon {
            info.icon = icon.to_string();
        }
        info
    }

    /// `pubkey` and `self` must each be empty or 64 lowercase hex.
    ///
    /// # Errors
    ///
    /// [`InfoError`] naming the offending key.
    pub fn validate(&self) -> Result<(), InfoError> {
        for (key, value) in [("pubkey", &self.pubkey), ("self", &self.self_pubkey)] {
            if !value.is_empty() && !is_lower_hex(value, 64) {
                return Err(InfoError(key));
            }
        }
        Ok(())
    }
}

/// `Info::validate` failure: a `[relay.info]` pubkey that is not
/// 64 lowercase hex. The payload is the offending key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("relay.info.{0} must be 64 lowercase hex chars (convert an npub to hex)")]
pub struct InfoError(pub &'static str);

/// The optional capabilities [`supported_nips`] advertises.
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per optional NIP advertisement"
)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Features {
    /// NIP-45 COUNT enabled.
    pub count: bool,
    /// NIP-77 negentropy sync enabled.
    pub sync: bool,
    /// NIP-42 AUTH configured (`service_url` set).
    pub auth: bool,
    /// NIP-59 gift wraps guarded (AUTH enabled, kind 1059 restricted).
    pub gift_wrap: bool,
    /// NIP-86 management admins configured.
    pub management: bool,
}

/// The sorted `supported_nips` list for `features`: NIP-01, 09, 11,
/// 40, 62, 67, and 70 unconditionally, plus the enabled optionals.
#[must_use]
pub fn supported_nips(features: Features) -> Vec<u16> {
    let mut nips = vec![1, 9, 11, 40, 62, 67, 70];
    if features.count {
        nips.push(45);
    }
    if features.sync {
        nips.push(77);
    }
    if features.gift_wrap {
        nips.push(59);
    }
    if features.auth {
        nips.push(42);
    }
    if features.management {
        nips.push(86);
    }
    nips.sort_unstable();
    nips
}

/// The NIP-11 relay information document.
///
/// `moderation` overrides `name`/`description`/`icon` and its
/// allow-lists set `limitation.restricted_writes`; `info.supported_nips`
/// replaces the list `features` computes when set. `description`,
/// `pubkey`, `contact`, `icon`, `banner`, `self`, `terms_of_service`,
/// and `privacy_policy` are omitted when empty; `name` stays
/// unconditionally.
///
/// NIP-11 (11.md) calls `limitation.max_message_length` the maximum
/// incoming JSON message / WebSocket frame size and says it
/// "effectively limits the maximum size of any event". The value
/// advertised here is `max_payload` capped at the largest allowed
/// EVENT frame (`max_event_size + 10`): clients that read it as the
/// event limit (MDK) get the truth and clients that read it as the
/// frame limit get a safe value.
#[must_use]
pub fn document(
    info: &Info,
    moderation: &Moderation,
    features: Features,
    limits: &Limits,
    max_payload: usize,
) -> String {
    let info = info.with_overrides(moderation);
    let nips = info
        .supported_nips
        .clone()
        .unwrap_or_else(|| supported_nips(features));
    let mut doc = json!({
        "name": info.name.as_str(),
        "supported_nips": nips,
        "software": "https://github.com/qntx/nosfry",
        "version": env!("CARGO_PKG_VERSION"),
        "limitation": {
            "max_message_length": crate::limits::max_message_length(max_payload, &limits.event),
            "max_subscriptions": limits.req.max_subs_per_connection,
            "max_limit": limits.req.max_filter_limit,
            "default_limit": limits.req.max_filter_limit,
            "max_subid_length": SUB_ID_MAX_CHARS,
            "max_event_tags": limits.event.max_num_tags,
            "created_at_lower_limit": limits.event.reject_events_older_than_seconds,
            "created_at_upper_limit": limits.event.reject_events_newer_than_seconds,
            "auth_required": false,
            "restricted_writes": moderation.restricts_writes(),
            "payment_required": false,
        },
    });
    if let Some(map) = doc.as_object_mut() {
        for (key, value) in [
            ("description", info.description.as_str()),
            ("pubkey", info.pubkey.as_str()),
            ("contact", info.contact.as_str()),
            ("icon", info.icon.as_str()),
            ("banner", info.banner.as_str()),
            ("self", info.self_pubkey.as_str()),
            ("terms_of_service", info.terms_of_service.as_str()),
            ("privacy_policy", info.privacy_policy.as_str()),
        ] {
            if !value.is_empty() {
                map.insert(key.to_owned(), json!(value));
            }
        }
    }
    doc.to_string()
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;
    use crate::event::PublicKey;

    const HEX64: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    fn doc(info: &Info, moderation: &Moderation, features: Features) -> serde_json::Value {
        serde_json::from_str(&document(
            info,
            moderation,
            features,
            &Limits::default(),
            1024,
        ))
        .unwrap()
    }

    /// NIP-11 (11.md): `limitation.max_message_length` is the
    /// smaller of the payload cap and the largest allowed EVENT
    /// frame — truthful under either client reading.
    #[test]
    fn limitation_max_message_length_is_truthful() {
        let doc = doc(
            &Info::default(),
            &Moderation::default(),
            Features::default(),
        );
        assert_eq!(doc["limitation"]["max_message_length"], 1_024);
        let big: serde_json::Value = serde_json::from_str(&document(
            &Info::default(),
            &Moderation::default(),
            Features::default(),
            &Limits::default(),
            131_072,
        ))
        .unwrap();
        assert_eq!(big["limitation"]["max_message_length"], 65_546);
    }

    #[test]
    fn empty_fields_are_omitted() {
        let doc = doc(
            &Info::default(),
            &Moderation::default(),
            Features::default(),
        );
        assert_eq!(doc["name"], "nosfry");
        for key in [
            "description",
            "pubkey",
            "contact",
            "icon",
            "banner",
            "self",
            "terms_of_service",
            "privacy_policy",
        ] {
            assert!(doc.get(key).is_none(), "{key} must be omitted when empty");
        }
        assert_eq!(doc["supported_nips"], json!([1, 9, 11, 40, 62, 67, 70]));
    }

    #[test]
    fn new_fields_are_emitted() {
        let info = Info {
            banner: "https://example.com/banner.png".into(),
            self_pubkey: HEX64.into(),
            terms_of_service: "https://example.com/terms".into(),
            privacy_policy: "https://example.com/privacy".into(),
            ..Info::default()
        };
        let doc = doc(&info, &Moderation::default(), Features::default());
        assert_eq!(doc["banner"], "https://example.com/banner.png");
        assert_eq!(doc["self"], HEX64);
        assert_eq!(doc["terms_of_service"], "https://example.com/terms");
        assert_eq!(doc["privacy_policy"], "https://example.com/privacy");
    }

    #[test]
    fn configured_nips_replace_the_computed_list() {
        let info = Info {
            supported_nips: Some(vec![1, 11]),
            ..Info::default()
        };
        let doc = doc(
            &info,
            &Moderation::default(),
            Features {
                count: true,
                sync: true,
                auth: true,
                gift_wrap: true,
                management: true,
            },
        );
        assert_eq!(doc["supported_nips"], json!([1, 11]));
    }

    #[test]
    fn features_compute_the_nip_list() {
        let doc = doc(
            &Info::default(),
            &Moderation::default(),
            Features {
                count: true,
                sync: true,
                auth: true,
                gift_wrap: true,
                management: true,
            },
        );
        assert_eq!(
            doc["supported_nips"],
            json!([1, 9, 11, 40, 42, 45, 59, 62, 67, 70, 77, 86])
        );
    }

    /// NIP-59 advertises only with `gift_wrap`; AUTH alone does not.
    #[test]
    fn gift_wrap_flag_controls_59() {
        let auth_only = doc(
            &Info::default(),
            &Moderation::default(),
            Features {
                auth: true,
                ..Features::default()
            },
        );
        assert_eq!(
            auth_only["supported_nips"],
            json!([1, 9, 11, 40, 42, 62, 67, 70])
        );
        let wraps_only = doc(
            &Info::default(),
            &Moderation::default(),
            Features {
                gift_wrap: true,
                ..Features::default()
            },
        );
        assert_eq!(
            wraps_only["supported_nips"],
            json!([1, 9, 11, 40, 59, 62, 67, 70])
        );
    }

    #[test]
    fn allow_lists_set_restricted_writes() {
        let writes = |moderation: &Moderation| {
            doc(&Info::default(), moderation, Features::default())["limitation"]
                ["restricted_writes"]
                .as_bool()
                .unwrap()
        };
        assert!(!writes(&Moderation::default()));
        let mut moderation = Moderation::default();
        moderation
            .allowed_pubkeys
            .insert(PublicKey::from_hex(HEX64).unwrap(), None);
        assert!(writes(&moderation));
        moderation.allowed_pubkeys.clear();
        moderation.allowed_kinds.insert(1);
        assert!(writes(&moderation));
    }

    #[test]
    fn moderation_overrides_still_apply() {
        let moderation = Moderation {
            name: Some("mod name".into()),
            description: Some("mod description".into()),
            icon: Some("https://example.com/mod.png".into()),
            ..Moderation::default()
        };
        let doc = doc(&Info::default(), &moderation, Features::default());
        assert_eq!(doc["name"], "mod name");
        assert_eq!(doc["description"], "mod description");
        assert_eq!(doc["icon"], "https://example.com/mod.png");
    }

    #[test]
    fn validate_accepts_empty_and_hex() {
        Info::default().validate().unwrap();
        let info = Info {
            pubkey: HEX64.into(),
            self_pubkey: HEX64.into(),
            ..Info::default()
        };
        info.validate().unwrap();
    }

    #[test]
    fn validate_rejects_malformed_pubkeys() {
        for bad in [
            "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqmqqqy",
            &HEX64.to_uppercase(),
            &HEX64[..63],
        ] {
            for key in ["pubkey", "self"] {
                let mut info = Info::default();
                match key {
                    "pubkey" => info.pubkey = bad.to_owned(),
                    _ => info.self_pubkey = bad.to_owned(),
                }
                let err = info.validate().unwrap_err().to_string();
                assert!(
                    err.contains(&format!("relay.info.{key}")),
                    "{bad}: unexpected error {err}"
                );
            }
        }
    }
}
