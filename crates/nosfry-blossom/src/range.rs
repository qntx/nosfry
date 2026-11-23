//! Single-range `Range` header parsing (RFC 9110 §14.2).
//!
//! Anything we do not implement — other units, multiple ranges,
//! syntax errors — degrades to [`Range::Full`]: a server MAY ignore
//! the header, and we never emit `multipart/byteranges`.

/// The outcome of parsing a `Range` header against a blob of `len`
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    /// Serve the whole body: no header, or a header we do not honour.
    Full,
    /// Serve `start..=end_inclusive` (both bounds resolved).
    Partial {
        /// First byte to serve.
        start: u64,
        /// Last byte to serve, inclusive; never past `len - 1`.
        end_inclusive: u64,
    },
    /// A syntactically valid range that cannot be satisfied at all —
    /// the answer is 416 with `Content-Range: bytes */len`.
    Unsatisfiable,
}

/// A decimal `u64` of at most 19 ASCII digits (19 digits always fit
/// `u64`, so anything longer degrades to [`Range::Full`]).
fn digits(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 19 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Parse a `Range` header for a blob of `len` bytes.
#[must_use]
pub fn parse(header: Option<&str>, len: u64) -> Range {
    let Some(value) = header else {
        return Range::Full;
    };
    let Some(spec) = value.trim().strip_prefix("bytes") else {
        return Range::Full;
    };
    let Some(spec) = spec.trim_start().strip_prefix('=') else {
        return Range::Full;
    };
    // Multiple ranges (and byte-range-set separators) are ignored.
    let spec = spec.trim();
    if spec.contains(',') {
        return Range::Full;
    }
    let Some(dash) = spec.find('-') else {
        return Range::Full;
    };
    let (first, second) = (spec[..dash].trim(), spec[dash + 1..].trim());
    if first.is_empty() {
        // Suffix form `-n`: the last n bytes.
        let Some(suffix) = digits(second) else {
            return Range::Full;
        };
        if len == 0 || suffix == 0 {
            return Range::Unsatisfiable;
        }
        let start = len.saturating_sub(suffix.min(len));
        return Range::Partial {
            start,
            end_inclusive: len - 1,
        };
    }
    let Some(start) = digits(first) else {
        return Range::Full;
    };
    let end = if second.is_empty() {
        None
    } else {
        let Some(end) = digits(second) else {
            return Range::Full;
        };
        Some(end)
    };
    // `a > b` is invalid, not merely unsatisfiable.
    if end.is_some_and(|end| start > end) {
        return Range::Full;
    }
    if len == 0 {
        return Range::Unsatisfiable;
    }
    let end_inclusive = end.map_or(len - 1, |end| end.min(len - 1));
    if start >= len {
        return Range::Unsatisfiable;
    }
    Range::Partial {
        start,
        end_inclusive,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use super::*;

    /// The parse table: header → outcome for `len = 100`.
    #[test]
    fn parse_table() {
        let cases: &[(&str, Range)] = &[
            // No header.
            ("", Range::Full),
            // Whitespace tolerated around numbers and the dash.
            (
                "bytes=0-99",
                Range::Partial {
                    start: 0,
                    end_inclusive: 99,
                },
            ),
            (
                "bytes = 10 - 19",
                Range::Partial {
                    start: 10,
                    end_inclusive: 19,
                },
            ),
            // `b` clamps to len-1.
            (
                "bytes=50-500",
                Range::Partial {
                    start: 50,
                    end_inclusive: 99,
                },
            ),
            (
                "bytes=0-",
                Range::Partial {
                    start: 0,
                    end_inclusive: 99,
                },
            ),
            (
                "bytes=99-",
                Range::Partial {
                    start: 99,
                    end_inclusive: 99,
                },
            ),
            // Suffix form.
            (
                "bytes=-10",
                Range::Partial {
                    start: 90,
                    end_inclusive: 99,
                },
            ),
            (
                "bytes=-100",
                Range::Partial {
                    start: 0,
                    end_inclusive: 99,
                },
            ),
            (
                "bytes=-500",
                Range::Partial {
                    start: 0,
                    end_inclusive: 99,
                },
            ),
            // Unsatisfiable.
            ("bytes=100-", Range::Unsatisfiable),
            ("bytes=150-160", Range::Unsatisfiable),
            ("bytes=-0", Range::Unsatisfiable),
            // Syntax errors and unsupported shapes → Full.
            ("items=0-10", Range::Full),
            ("bytes", Range::Full),
            ("bytes=", Range::Full),
            ("bytes=0-10,20-30", Range::Full),
            ("bytes=10-5", Range::Full),
            ("bytes=-", Range::Full),
            ("bytes=--10", Range::Full),
            ("bytes=0-1-2", Range::Full),
            ("bytes=a-b", Range::Full),
            ("bytes=99999999999999999999-100", Range::Full),
            ("bytes=0x10-20", Range::Full),
            ("bytes=10-abc", Range::Full),
            ("Bytes=0-10", Range::Full),
        ];
        for (header, want) in cases {
            assert_eq!(parse(Some(header), 100), *want, "{header}");
        }
        assert_eq!(parse(None, 100), Range::Full);
    }

    /// `len == 0` makes every valid range unsatisfiable.
    #[test]
    fn empty_blob() {
        assert_eq!(parse(Some("bytes=0-"), 0), Range::Unsatisfiable);
        assert_eq!(parse(Some("bytes=0-0"), 0), Range::Unsatisfiable);
        assert_eq!(parse(Some("bytes=-1"), 0), Range::Unsatisfiable);
        assert_eq!(parse(None, 0), Range::Full);
        assert_eq!(parse(Some("items=0-1"), 0), Range::Full);
        assert_eq!(parse(Some("bytes=a-b"), 0), Range::Full);
    }

    /// 19 digits always parse; 20 digits degrade to Full.
    #[test]
    fn digit_cap() {
        let nineteen = "9".repeat(19);
        assert_eq!(digits(&nineteen), Some(9_999_999_999_999_999_999));
        assert_eq!(digits(&"9".repeat(20)), None);
        assert_eq!(digits(""), None);
        assert_eq!(digits("12a"), None);
    }
}
