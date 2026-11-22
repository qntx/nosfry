//! Relay service URLs (`ws://`/`wss://`), normalized like strfry's
//! `normalizeRelayUrl`.

/// The host part of a relay URL: strip through `://`, cut at the
/// first `/`, `?`, or `#` (strfry `normalizeRelayUrl`).
fn normalize(url: &str) -> &str {
    let rest = url.find("://").map_or(url, |pos| &url[pos + 3..]);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    &rest[..end]
}

/// A validated relay URL, kept as its normalized lowercase host.
/// Tag values are compared under the same normalization, so scheme
/// and path differences never matter.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayUrl(Box<str>);

impl RelayUrl {
    /// Parse `url` as a `ws://`/`wss://` URL with a non-empty host.
    ///
    /// # Errors
    ///
    /// [`RelayUrlError`] on a wrong scheme or empty host.
    pub fn parse(url: &str) -> Result<Self, RelayUrlError> {
        if !url.starts_with("ws://") && !url.starts_with("wss://") {
            return Err(RelayUrlError);
        }
        let host = normalize(url).to_ascii_lowercase();
        if host.is_empty() {
            return Err(RelayUrlError);
        }
        Ok(Self(host.into_boxed_str()))
    }

    /// The normalized host, with port when the URL carried one.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.0
    }

    /// Whether `tag_value` normalizes to this relay's host
    /// (NIP-42 `relay` tags, NIP-62 vanish targets).
    #[must_use]
    pub fn matches(&self, tag_value: &str) -> bool {
        normalize(tag_value).eq_ignore_ascii_case(&self.0)
    }
}

/// The URL is not a `ws://`/`wss://` URL with a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("service_url must be a ws:// or wss:// URL with a host")]
pub struct RelayUrlError;

/// Every name the relay answers to: the canonical `service_url`
/// first, then each `service_url_aliases` entry.
///
/// Tag values (the NIP-42 `relay` tag, the NIP-62 vanish `relay`
/// tag, the NIP-98 `u` tag) match against all of them, so a relay
/// reachable under several names honors every one on every listener.
/// NIP-11, the landing page and `NodeInfo` still name the canonical
/// URL only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayNames(Box<[RelayUrl]>);

impl RelayNames {
    /// Parse `service_url` plus `aliases` into the name set; the
    /// canonical URL comes first. Duplicates collapse after
    /// normalization.
    ///
    /// # Errors
    ///
    /// [`RelayNamesError::MissingServiceUrl`] when `service_url` is
    /// empty but `aliases` is not — an alias has no canonical name to
    /// alternate; [`RelayNamesError::Url`] when either value fails
    /// [`RelayUrl::parse`].
    pub fn parse(service_url: &str, aliases: &[String]) -> Result<Self, RelayNamesError> {
        if service_url.is_empty() {
            return if aliases.is_empty() {
                Ok(Self::default())
            } else {
                Err(RelayNamesError::MissingServiceUrl)
            };
        }
        let mut names = vec![RelayUrl::parse(service_url)?];
        for alias in aliases {
            let url = RelayUrl::parse(alias)?;
            if !names.iter().any(|name| name == &url) {
                names.push(url);
            }
        }
        Ok(Self(names.into_boxed_slice()))
    }

    /// The canonical `service_url`, `None` when AUTH is disabled.
    #[must_use]
    pub fn canonical(&self) -> Option<&RelayUrl> {
        self.0.first()
    }

    /// Whether `tag_value` normalizes to any of this relay's names.
    #[must_use]
    pub fn matches(&self, tag_value: &str) -> bool {
        self.0.iter().any(|name| name.matches(tag_value))
    }

    /// No names — `service_url` unset, AUTH disabled.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// [`RelayNames::parse`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayNamesError {
    /// `service_url` or an alias is not a `ws://`/`wss://` URL with a
    /// host.
    #[error(transparent)]
    Url(#[from] RelayUrlError),
    /// `service_url_aliases` is set while `service_url` is empty.
    #[error("service_url_aliases requires service_url")]
    MissingServiceUrl,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_match() {
        let url = RelayUrl::parse("wss://Relay.Example.com/path?x").unwrap();
        assert!(url.matches("wss://relay.example.com"));
        assert!(url.matches("wss://Relay.Example.com/sub#frag"));
        assert!(!url.matches("wss://other.example.com"));
        for bad in ["http://x", "wss://", "relay.example.com", "ws://"] {
            assert!(RelayUrl::parse(bad).is_err(), "{bad} must fail");
        }
    }

    #[test]
    fn names_parse_canonical_and_aliases() {
        let names = RelayNames::parse(
            "wss://Relay.Example.com",
            &[
                "wss://alias.nosfry.test".to_owned(),
                "ws://abc.onion".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(names.canonical().unwrap().host(), "relay.example.com");
        for tag in [
            "wss://relay.example.com",
            "ws://relay.example.com/any/path",
            "http://relay.example.com/",
            "wss://ALIAS.nosfry.test",
            "ws://abc.onion",
        ] {
            assert!(names.matches(tag), "{tag} must match a name");
        }
        assert!(!names.matches("wss://unrelated.example.com"));
        assert!(!names.matches("ALL_RELAYS"));
        assert!(!names.is_empty());

        // Duplicates collapse after normalization.
        let dup = RelayNames::parse(
            "wss://relay.example.com",
            &["wss://RELAY.example.com".to_owned()],
        )
        .unwrap();
        assert_eq!(
            dup.matches("wss://relay.example.com"),
            names.matches("wss://relay.example.com")
        );
    }

    #[test]
    fn names_parse_errors() {
        // An alias needs a canonical name.
        assert!(matches!(
            RelayNames::parse("", &["wss://alias.test".to_owned()]),
            Err(RelayNamesError::MissingServiceUrl)
        ));
        // Empty everything is legal (AUTH disabled).
        assert!(RelayNames::parse("", &[]).unwrap().is_empty());
        assert!(RelayNames::parse("", &[]).unwrap().canonical().is_none());
        // A bad alias fails like a bad service_url.
        assert!(matches!(
            RelayNames::parse("wss://relay.example.com", &["not-a-url".to_owned()]),
            Err(RelayNamesError::Url(_))
        ));
        assert!(matches!(
            RelayNames::parse("http://x", &[]),
            Err(RelayNamesError::Url(_))
        ));
    }
}
