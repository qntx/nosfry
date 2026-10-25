//! The relay's static HTTP surface.
//!
//! The HTML landing page and the `NodeInfo` 2.1 documents, shared by
//! the native and Workers editions. Pure functions over the
//! effective NIP-11 info; every interpolated value is escaped and
//! only `http(s)`/`mailto` URLs ever become `src`/`href` targets.

use serde_json::json;

use crate::info::{self, Features, Info};
use crate::moderation::Moderation;
use crate::url::RelayUrl;

/// The CORS header set on every HTTP answer a browser may read
/// (khatru's policy).
///
/// Applied to the OPTIONS preflight, NIP-11, `NodeInfo`, and all
/// NIP-86 responses on both editions. `POST` in the allowed methods
/// and an explicit `Authorization` in the allowed headers are what
/// make the NIP-86 RPC callable from a browser — the Fetch wildcard
/// never covers `Authorization`.
pub const CORS_HEADERS: [(&str, &str); 4] = [
    ("access-control-allow-origin", "*"),
    ("access-control-allow-methods", "GET, POST, OPTIONS"),
    ("access-control-allow-headers", "Authorization, *"),
    ("access-control-max-age", "86400"),
];

/// Defense-in-depth headers for the HTML landing page.
///
/// The page uses an inline `<style>`, `<img>` icons/banners, and
/// plain `<a>` links; no scripts or forms exist to allow. Not applied
/// to API responses such as the NIP-11 document.
pub const LANDING_HEADERS: [(&str, &str); 3] = [
    (
        "Content-Security-Policy",
        "default-src 'none'; img-src http: https:; style-src 'unsafe-inline'; \
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
];

/// Escape `&`, `<`, `>`, `"`, and `'` — valid for both text nodes
/// and double-quoted attribute values.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// `true` when `url` is an `http(s)://` URL — the only scheme allowed
/// in `src` and `href` besides `mailto:`.
fn is_http(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// `true` when `url` may become a link target: `http(s)` or
/// `mailto:`.
fn is_linkable(url: &str) -> bool {
    is_http(url) || url.starts_with("mailto:")
}

/// `<dt>term</dt><dd>value</dd>` — `value` is already-escaped HTML,
/// `term` is a static label.
fn row(page: &mut String, term: &str, value: &str) {
    page.push_str("<dt>");
    page.push_str(term);
    page.push_str("</dt><dd>");
    page.push_str(value);
    page.push_str("</dd>\n");
}

/// A link when `url` is linkable, escaped text otherwise.
fn maybe_link(url: &str) -> String {
    if is_linkable(url) {
        let url = escape(url);
        format!("<a href=\"{url}\">{url}</a>")
    } else {
        escape(url)
    }
}

const CSS: &str = concat!(
    "body{margin:0;font-family:system-ui,sans-serif;color:#222;}",
    "main{max-width:44rem;margin:2rem auto;padding:0 1rem;}",
    "img.banner{display:block;width:100%;max-height:14rem;object-fit:cover;border-radius:.5rem;}",
    "img.icon{display:block;width:4rem;height:4rem;border-radius:.5rem;margin:1rem 0;}",
    "dl{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1.5rem;}",
    "dt{font-weight:600;}",
    "dd{margin:0;}",
    "code{word-break:break-all;}"
);

/// The relay landing page.
///
/// A self-contained HTML5 document with no JavaScript and no
/// external resources beyond the operator's `icon`/`banner` images.
/// The name, description, and icon follow the same effective info as
/// the NIP-11 document; every interpolated value is escaped.
#[must_use]
pub fn landing_page(
    info: &Info,
    moderation: &Moderation,
    features: Features,
    service_url: &str,
) -> String {
    let info = info.with_overrides(moderation);
    let name = escape(&info.name);
    let mut page = String::with_capacity(2048);
    page.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    page.push_str(
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>",
    );
    page.push_str(&name);
    page.push_str("</title>\n<style>");
    page.push_str(CSS);
    page.push_str("</style>\n</head>\n<body>\n<main>\n<h1>");
    page.push_str(&name);
    page.push_str("</h1>\n");
    if is_http(&info.banner) {
        page.push_str("<img class=\"banner\" src=\"");
        page.push_str(&escape(&info.banner));
        page.push_str("\" alt=\"\">\n");
    }
    if is_http(&info.icon) {
        page.push_str("<img class=\"icon\" src=\"");
        page.push_str(&escape(&info.icon));
        page.push_str("\" alt=\"\">\n");
    }
    for paragraph in info.description.split("\n\n") {
        let paragraph = paragraph.trim();
        if !paragraph.is_empty() {
            page.push_str("<p>");
            page.push_str(&escape(paragraph));
            page.push_str("</p>\n");
        }
    }
    page.push_str("<dl>\n");
    if !service_url.is_empty() {
        row(
            &mut page,
            "Relay URL",
            &format!(
                "<code>{}</code> — connect with a Nostr client",
                escape(service_url)
            ),
        );
    }
    if !info.pubkey.is_empty() {
        row(
            &mut page,
            "Admin pubkey",
            &format!("<code>{}</code>", escape(&info.pubkey)),
        );
    }
    if !info.self_pubkey.is_empty() {
        row(
            &mut page,
            "Relay pubkey",
            &format!("<code>{}</code>", escape(&info.self_pubkey)),
        );
    }
    if !info.contact.is_empty() {
        row(&mut page, "Contact", &maybe_link(&info.contact));
    }
    let nips = info
        .supported_nips
        .clone()
        .unwrap_or_else(|| info::supported_nips(features));
    if !nips.is_empty() {
        let links = nips
            .iter()
            .map(|nip| {
                format!(
                    "<a href=\"https://github.com/nostr-protocol/nips/blob/master/{nip:02}.md\">NIP-{nip:02}</a>"
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        row(&mut page, "Supported NIPs", &links);
    }
    row(
        &mut page,
        "Software",
        &format!(
            "<a href=\"https://github.com/qntx/nosfry\">nosfry</a> {}",
            env!("CARGO_PKG_VERSION")
        ),
    );
    for (term, url) in [
        ("Terms of Service", &info.terms_of_service),
        ("Privacy Policy", &info.privacy_policy),
    ] {
        if !url.is_empty() {
            row(&mut page, term, &maybe_link(url));
        }
    }
    page.push_str("</dl>\n</main>\n</body>\n</html>\n");
    page
}

/// The `NodeInfo` discovery document for `/.well-known/nodeinfo`.
///
/// It points at `/nodeinfo/2.1` on the relay's `http(s)` host: `wss`
/// maps to `https`, `ws` to `http`, and any path is dropped. `None`
/// when `service_url` is empty or invalid — the host is never
/// derived from the request's `Host` header.
#[must_use]
pub fn nodeinfo_links(service_url: &str) -> Option<String> {
    let url = RelayUrl::parse(service_url).ok()?;
    let scheme = if service_url.starts_with("wss://") {
        "https"
    } else {
        "http"
    };
    Some(
        json!({
            "links": [{
                "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                "href": format!("{scheme}://{}/nodeinfo/2.1", url.host()),
            }],
        })
        .to_string(),
    )
}

/// The `NodeInfo` 2.1 document: strfry's document shape with the
/// nosfry identity.
#[must_use]
pub fn nodeinfo() -> String {
    json!({
        "version": "2.1",
        "software": {
            "name": "nosfry",
            "version": env!("CARGO_PKG_VERSION"),
            "repository": "https://github.com/qntx/nosfry",
            "homepage": "https://github.com/qntx/nosfry",
        },
        "protocols": ["nostr"],
        "services": {"inbound": [], "outbound": []},
        "openRegistrations": false,
        "usage": {"users": {}},
        "metadata": {"features": ["nostr_relay"]},
    })
    .to_string()
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

    #[test]
    fn escape_covers_text_and_attributes() {
        assert_eq!(escape("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn landing_escapes_interpolated_values() {
        let info = Info {
            name: "a<b>\"'&".into(),
            description: "<script>alert(1)</script>\n\nsecond".into(),
            ..Info::default()
        };
        let page = landing_page(
            &info,
            &Moderation::default(),
            Features::default(),
            "wss://relay.example.com",
        );
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!page.contains("<script>"));
        assert!(page.contains("<h1>a&lt;b&gt;&quot;&#39;&amp;</h1>"));
        assert!(page.contains("<p>second</p>"));
        assert!(page.contains("<code>wss://relay.example.com</code>"));
    }

    #[test]
    fn landing_never_links_dangerous_schemes() {
        let info = Info {
            icon: "javascript:alert(1)".into(),
            contact: "javascript:alert(1)".into(),
            terms_of_service: "javascript:alert(1)".into(),
            ..Info::default()
        };
        let page = landing_page(&info, &Moderation::default(), Features::default(), "");
        assert!(!page.contains("src=\"javascript"));
        assert!(!page.contains("href=\"javascript"));
        // The raw text stays, escaped.
        assert!(page.contains("javascript:alert(1)"));
    }

    #[test]
    fn landing_links_and_omits_rows() {
        let info = Info {
            pubkey: "aa".repeat(32),
            self_pubkey: "bb".repeat(32),
            contact: "mailto:op@example.com".into(),
            terms_of_service: "https://example.com/terms".into(),
            privacy_policy: "not a url".into(),
            supported_nips: Some(vec![1, 11]),
            ..Info::default()
        };
        let page = landing_page(&info, &Moderation::default(), Features::default(), "");
        assert!(page.contains(
            "<a href=\"https://github.com/nostr-protocol/nips/blob/master/01.md\">NIP-01</a>"
        ));
        assert!(page.contains(
            "<a href=\"https://github.com/nostr-protocol/nips/blob/master/11.md\">NIP-11</a>"
        ));
        assert!(page.contains("href=\"mailto:op@example.com\""));
        assert!(page.contains("href=\"https://example.com/terms\""));
        // A non-URL privacy policy renders as text, not a link.
        assert!(!page.contains("href=\"not a url\""));
        // Empty rows are omitted.
        assert!(!page.contains("Relay URL"));
        assert!(!page.contains("<img"));
    }

    #[test]
    fn nodeinfo_links_derives_http_base() {
        for (url, expect) in [
            (
                "wss://relay.example.com",
                "https://relay.example.com/nodeinfo/2.1",
            ),
            ("ws://127.0.0.1:7777", "http://127.0.0.1:7777/nodeinfo/2.1"),
            (
                "wss://relay.example.com:443/nested/path",
                "https://relay.example.com:443/nodeinfo/2.1",
            ),
        ] {
            let doc: serde_json::Value =
                serde_json::from_str(&nodeinfo_links(url).unwrap()).unwrap();
            assert_eq!(doc["links"][0]["href"], expect, "{url}");
            assert_eq!(
                doc["links"][0]["rel"],
                "http://nodeinfo.diaspora.software/ns/schema/2.1"
            );
        }
        for empty in ["", "http://x", "wss://"] {
            assert!(nodeinfo_links(empty).is_none(), "{empty}");
        }
    }

    #[test]
    fn nodeinfo_document_shape() {
        let doc: serde_json::Value = serde_json::from_str(&nodeinfo()).unwrap();
        assert_eq!(doc["version"], "2.1");
        assert_eq!(doc["software"]["name"], "nosfry");
        assert!(doc["software"]["version"].is_string());
        assert_eq!(
            doc["software"]["repository"],
            "https://github.com/qntx/nosfry"
        );
        assert_eq!(doc["protocols"], json!(["nostr"]));
        assert_eq!(doc["openRegistrations"], false);
        assert_eq!(doc["metadata"]["features"], json!(["nostr_relay"]));
    }
}
