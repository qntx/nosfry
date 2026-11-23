//! Content-Type rules.
//!
//! Normalization, the allow-list match, the type → extension table,
//! and `is_active` — the types a browser may render as a document
//! with script, which get `Content-Disposition: attachment` on the
//! way out.

/// The fallback type when the client sends none (BUD-01/BUD-02
/// `application/octet-stream` default).
pub const OCTET_STREAM: &str = "application/octet-stream";

/// A normalized `type/subtype` is at most this many bytes.
const MAX_TYPE_LEN: usize = 127;

/// A malformed `Content-Type`/`X-Content-Type`; the answer is 400.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid content type")]
pub struct MimeError;

/// RFC 9110 `tchar` (token characters).
const fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Normalize a `Content-Type` header value to `type/subtype`.
///
/// Parameters are dropped, the token trimmed and lowercased; absent
/// or blank means `application/octet-stream`. The result is a
/// `type/subtype` pair of non-empty tchar tokens of at most 127
/// bytes.
///
/// # Errors
///
/// [`MimeError`] on anything else.
pub fn normalize(content_type: Option<&str>) -> Result<String, MimeError> {
    let Some(raw) = content_type else {
        return Ok(OCTET_STREAM.to_owned());
    };
    let base = raw.split(';').next().unwrap_or_default().trim();
    if base.is_empty() {
        return Ok(OCTET_STREAM.to_owned());
    }
    let lower = base.to_ascii_lowercase();
    let valid = lower.len() <= MAX_TYPE_LEN
        && lower.split_once('/').is_some_and(|(ty, sub)| {
            !ty.is_empty()
                && !sub.is_empty()
                && ty.bytes().all(is_tchar)
                && sub.bytes().all(is_tchar)
        });
    if !valid {
        return Err(MimeError);
    }
    Ok(lower)
}

/// Whether `entry` is a well-formed allow-list entry — a lowercase
/// `type/subtype` or `type/*`, as `blossom.mime_types` takes.
#[must_use]
pub fn allow_entry(entry: &str) -> bool {
    entry == entry.to_ascii_lowercase()
        && entry.split_once('/').is_some_and(|(ty, sub)| {
            !ty.is_empty()
                && ty.bytes().all(is_tchar)
                && (sub == "*" || (!sub.is_empty() && sub.bytes().all(is_tchar)))
        })
}

/// Whether `ty` (already normalized) passes `allowed`: an empty
/// list allows everything, `type/*` matches the type, and exact
/// `type/subtype` entries match themselves.
#[must_use]
pub fn allowed(ty: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    allowed.iter().any(|entry| {
        entry.strip_suffix("/*").map_or_else(
            || ty == entry,
            |prefix| {
                ty.len() > prefix.len()
                    && ty.starts_with(prefix)
                    && ty.as_bytes().get(prefix.len()) == Some(&b'/')
            },
        )
    })
}

/// The canonical file extension for a normalized type — the `.<ext>`
/// of descriptor URLs (BUD-02 requires one). Unknown types get
/// `"bin"`.
#[must_use]
pub fn extension(ty: &str) -> &'static str {
    match ty {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/avif" => "avif",
        "image/heic" => "heic",
        "image/svg+xml" => "svg",
        "image/bmp" => "bmp",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "video/quicktime" => "mov",
        "video/x-matroska" => "mkv",
        "audio/mpeg" => "mp3",
        "audio/ogg" => "ogg",
        "audio/opus" => "opus",
        "audio/wav" | "audio/x-wav" => "wav",
        "audio/flac" => "flac",
        "audio/mp4" | "audio/x-m4a" => "m4a",
        "application/pdf" => "pdf",
        "text/plain" => "txt",
        "application/json" => "json",
        "text/html" => "html",
        "text/css" => "css",
        "text/javascript" | "application/javascript" => "js",
        "text/xml" | "application/xml" => "xml",
        "application/zip" => "zip",
        "application/gzip" | "application/x-gzip" => "gz",
        "application/x-tar" => "tar",
        "application/wasm" => "wasm",
        "application/vnd.android.package-archive" => "apk",
        _ => "bin",
    }
}

/// Whether a browser may execute or render `ty` as a document.
///
/// Such blobs are served `Content-Disposition: attachment` so direct
/// navigation downloads them instead of running them with script.
/// (Subresource loads are unaffected: `Content-Disposition` does not
/// apply to `<img>`, and SVG in `<img>` never runs script.)
#[must_use]
pub fn is_active(ty: &str) -> bool {
    let active = matches!(
        ty,
        "text/html"
            | "application/xhtml+xml"
            | "image/svg+xml"
            | "text/xml"
            | "application/xml"
            | "text/xsl"
            | "application/xslt+xml"
            | "text/javascript"
            | "application/javascript"
            | "application/x-javascript"
            | "text/ecmascript"
            | "application/ecmascript"
            | "text/jscript"
            | "application/x-shockwave-flash"
            | "multipart/x-mixed-replace"
            | "text/cache-manifest"
    );
    active
        || ty
            .rsplit_once('/')
            .is_some_and(|(_, sub)| sub.ends_with("+xml"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use super::*;

    /// `normalize`: absent/blank → octet-stream; parameters dropped;
    /// case folded; malformed rejected.
    #[test]
    fn normalize_table() {
        assert_eq!(normalize(None).unwrap(), OCTET_STREAM);
        assert_eq!(normalize(Some("")).unwrap(), OCTET_STREAM);
        assert_eq!(normalize(Some("   ")).unwrap(), OCTET_STREAM);
        assert_eq!(
            normalize(Some("Image/PNG; charset=binary")).unwrap(),
            "image/png"
        );
        assert_eq!(
            normalize(Some("text/html; charset=utf-8")).unwrap(),
            "text/html"
        );
        for bad in [
            "text html",
            "/html",
            "text/",
            "text/ht ml",
            &"x/".repeat(64),
        ] {
            assert!(normalize(Some(bad)).is_err(), "{bad}");
        }
        // Parameters after `;` are dropped before validating.
        assert_eq!(normalize(Some("a/b;c=d")).unwrap(), "a/b");
        // 127 bytes exactly is allowed, 128 is not.
        let at_max = format!("a/{}", "b".repeat(125));
        assert_eq!(normalize(Some(&at_max)).unwrap().len(), 127);
        assert!(normalize(Some(&format!("a/{}", "b".repeat(126)))).is_err());
    }

    /// `allowed`: empty allows all; `type/*` prefixes; exact entries.
    #[test]
    fn allowed_table() {
        let list = vec!["image/*".to_owned(), "text/plain".to_owned()];
        assert!(allowed("image/png", &list));
        assert!(allowed("text/plain", &list));
        assert!(!allowed("video/mp4", &list));
        assert!(!allowed("text/plainx", &list));
        assert!(!allowed("images/png", &list));
        assert!(allowed("anything/at-all", &[]));
    }

    /// `extension`: table hits and the `bin` fallback.
    #[test]
    fn extension_table() {
        assert_eq!(extension("image/jpeg"), "jpg");
        assert_eq!(extension("video/quicktime"), "mov");
        assert_eq!(extension("audio/mpeg"), "mp3");
        assert_eq!(extension("text/plain"), "txt");
        assert_eq!(extension("application/vnd.android.package-archive"), "apk");
        assert_eq!(extension("application/x-bittorrent"), "bin");
        assert_eq!(extension(OCTET_STREAM), "bin");
    }

    /// `is_active`: document/script types and any `+xml` subtype.
    #[test]
    fn active_table() {
        for ty in [
            "text/html",
            "application/xhtml+xml",
            "image/svg+xml",
            "application/atom+xml",
            "text/javascript",
            "application/xslt+xml",
            "text/cache-manifest",
        ] {
            assert!(is_active(ty), "{ty}");
        }
        for ty in [
            "image/png",
            "application/pdf",
            "text/plain",
            "video/mp4",
            OCTET_STREAM,
        ] {
            assert!(!is_active(ty), "{ty}");
        }
    }
}
