//! Metrics: `nosfry_blossom_*` counters and gauges rendered in
//! Prometheus text format. All label sets are fixed and bounded —
//! never client-controlled.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::auth::AuthError;

/// The route-class label of `requests_total` — assigned by
/// route/method, never from client-controlled path text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// `GET /<sha256>`.
    Get,
    /// `HEAD /<sha256>`.
    Head,
    /// `PUT /upload` or `PUT /<sha256>`.
    Upload,
    /// `HEAD /upload`.
    UploadCheck,
    /// `DELETE /<sha256>`.
    Delete,
    /// `GET /list/<pubkey>`.
    List,
    /// Any `OPTIONS`.
    Options,
    /// Every other request.
    Other,
}

impl Endpoint {
    const ALL: [Self; 8] = [
        Self::Get,
        Self::Head,
        Self::Upload,
        Self::UploadCheck,
        Self::Delete,
        Self::List,
        Self::Options,
        Self::Other,
    ];

    /// The label value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Head => "head",
            Self::Upload => "upload",
            Self::UploadCheck => "upload_check",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Options => "options",
            Self::Other => "other",
        }
    }
}

/// The status-class label of `requests_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// `2xx` (includes 206).
    Ok2xx,
    /// `3xx` (304, redirects).
    Redirect3xx,
    /// `4xx`.
    Client4xx,
    /// `5xx`.
    Server5xx,
}

impl Class {
    const ALL: [Self; 4] = [
        Self::Ok2xx,
        Self::Redirect3xx,
        Self::Client4xx,
        Self::Server5xx,
    ];

    /// The class of a status code.
    #[must_use]
    pub const fn of(status: u16) -> Self {
        match status {
            200..=299 => Self::Ok2xx,
            300..=399 => Self::Redirect3xx,
            400..=499 => Self::Client4xx,
            _ => Self::Server5xx,
        }
    }

    /// The label value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok2xx => "2xx",
            Self::Redirect3xx => "3xx",
            Self::Client4xx => "4xx",
            Self::Server5xx => "5xx",
        }
    }
}

/// The bounded `reason` label of `rejected_total`. Auth failures are
/// tracked on `auth_failures_total` instead; client-input errors get
/// no counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// `upload = "allowed"` refused the pubkey.
    Policy,
    /// The pubkey is banned.
    BannedPubkey,
    /// The blob hash is banned.
    BannedBlob,
    /// Over `max_blob_size`.
    Size,
    /// Outside the MIME allow-list.
    Mime,
    /// Over the pubkey quota.
    Quota,
    /// The global byte cap is reached.
    Full,
    /// A global or per-pubkey upload slot was unavailable.
    Busy,
    /// Body hash/length did not match the declared values.
    HashMismatch,
    /// `Content-Length` absent or unreadable.
    Length,
    /// Upload idle timeout.
    Timeout,
}

impl RejectReason {
    const ALL: [Self; 11] = [
        Self::Policy,
        Self::BannedPubkey,
        Self::BannedBlob,
        Self::Size,
        Self::Mime,
        Self::Quota,
        Self::Full,
        Self::Busy,
        Self::HashMismatch,
        Self::Length,
        Self::Timeout,
    ];

    /// The label value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::BannedPubkey => "banned_pubkey",
            Self::BannedBlob => "banned_blob",
            Self::Size => "size",
            Self::Mime => "mime",
            Self::Quota => "quota",
            Self::Full => "full",
            Self::Busy => "busy",
            Self::HashMismatch => "hash_mismatch",
            Self::Length => "length",
            Self::Timeout => "timeout",
        }
    }
}

/// The `nosfry_blossom_*` counters and gauges.
#[derive(Debug, Default)]
pub struct Metrics {
    requests: [AtomicU64; 32], // Endpoint::ALL × Class::ALL
    auth_failures: [AtomicU64; 15],
    rejected: [AtomicU64; 11],
    upload_bytes: AtomicU64,
    served_bytes: AtomicU64,
    uploads_in_flight: AtomicU64,
}

impl Metrics {
    /// Count one response.
    pub fn request(&self, endpoint: Endpoint, class: Class) {
        let index = Endpoint::ALL
            .iter()
            .position(|entry| *entry == endpoint)
            .unwrap_or(7)
            * 4
            + Class::ALL
                .iter()
                .position(|entry| *entry == class)
                .unwrap_or(3);
        if let Some(cell) = self.requests.get(index) {
            cell.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count one authorization failure.
    pub fn auth_failure(&self, error: AuthError) {
        if let Some(cell) = AuthError::ALL
            .iter()
            .position(|variant| *variant == error)
            .and_then(|index| self.auth_failures.get(index))
        {
            cell.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count one policy/capacity rejection.
    pub fn rejected(&self, reason: RejectReason) {
        if let Some(cell) = RejectReason::ALL
            .iter()
            .position(|variant| *variant == reason)
            .and_then(|index| self.rejected.get(index))
        {
            cell.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Add accepted upload bytes.
    pub fn upload_bytes(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add served blob bytes (range-adjusted).
    pub fn served_bytes(&self, bytes: u64) {
        self.served_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// An upload stream started / ended.
    pub fn in_flight(&self, delta: i64) {
        if delta >= 0 {
            self.uploads_in_flight
                .fetch_add(delta.cast_unsigned(), Ordering::Relaxed);
        } else {
            self.uploads_in_flight
                .fetch_sub(delta.unsigned_abs(), Ordering::Relaxed);
        }
    }

    /// The in-flight count, for tests.
    #[must_use]
    pub fn in_flight_now(&self) -> u64 {
        self.uploads_in_flight.load(Ordering::Relaxed)
    }

    /// Render the whole Blossom metric block. `stored` supplies the
    /// gauges from `info.total` so every scrape sees live values.
    #[must_use]
    pub fn render(&self, stored: &crate::store::Usage) -> String {
        let mut out = String::with_capacity(2048);
        out.push_str(
            "# HELP nosfry_blossom_requests_total Requests by endpoint and status class\n",
        );
        out.push_str("# TYPE nosfry_blossom_requests_total counter\n");
        for (index, cell) in self.requests.iter().enumerate() {
            let (Some(endpoint), Some(class)) = (
                Endpoint::ALL.get(index / Class::ALL.len()),
                Class::ALL.get(index % Class::ALL.len()),
            ) else {
                continue;
            };
            writeln!(
                out,
                "nosfry_blossom_requests_total{{endpoint=\"{}\",class=\"{}\"}} {}",
                endpoint.label(),
                class.label(),
                cell.load(Ordering::Relaxed)
            )
            .ok();
        }
        out.push_str(
            "# HELP nosfry_blossom_auth_failures_total Authorization failures by reason\n",
        );
        out.push_str("# TYPE nosfry_blossom_auth_failures_total counter\n");
        for (index, cell) in self.auth_failures.iter().enumerate() {
            let Some(variant) = AuthError::ALL.get(index) else {
                continue;
            };
            writeln!(
                out,
                "nosfry_blossom_auth_failures_total{{reason=\"{}\"}} {}",
                variant.label(),
                cell.load(Ordering::Relaxed)
            )
            .ok();
        }
        out.push_str("# HELP nosfry_blossom_rejected_total Rejections by reason\n");
        out.push_str("# TYPE nosfry_blossom_rejected_total counter\n");
        for (index, cell) in self.rejected.iter().enumerate() {
            let Some(variant) = RejectReason::ALL.get(index) else {
                continue;
            };
            writeln!(
                out,
                "nosfry_blossom_rejected_total{{reason=\"{}\"}} {}",
                variant.label(),
                cell.load(Ordering::Relaxed)
            )
            .ok();
        }
        writeln!(
            out,
            "# HELP nosfry_blossom_upload_bytes_total Accepted upload bytes\n\
             # TYPE nosfry_blossom_upload_bytes_total counter\n\
             nosfry_blossom_upload_bytes_total {}\n\
             # HELP nosfry_blossom_served_bytes_total Served blob bytes\n\
             # TYPE nosfry_blossom_served_bytes_total counter\n\
             nosfry_blossom_served_bytes_total {}\n\
             # HELP nosfry_blossom_uploads_in_flight Upload streams in flight\n\
             # TYPE nosfry_blossom_uploads_in_flight gauge\n\
             nosfry_blossom_uploads_in_flight {}\n\
             # HELP nosfry_blossom_stored_bytes Stored blob bytes\n\
             # TYPE nosfry_blossom_stored_bytes gauge\n\
             nosfry_blossom_stored_bytes {}\n\
             # HELP nosfry_blossom_stored_blobs Stored blob count\n\
             # TYPE nosfry_blossom_stored_blobs gauge\n\
             nosfry_blossom_stored_blobs {}",
            self.upload_bytes.load(Ordering::Relaxed),
            self.served_bytes.load(Ordering::Relaxed),
            self.uploads_in_flight.load(Ordering::Relaxed),
            stored.bytes,
            stored.blobs,
        )
        .ok();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every label combination renders, including zero cells.
    #[test]
    fn render_shape() {
        let metrics = Metrics::default();
        metrics.request(Endpoint::Get, Class::Ok2xx);
        metrics.request(Endpoint::Upload, Class::Client4xx);
        metrics.auth_failure(AuthError::Expired);
        metrics.rejected(RejectReason::Quota);
        metrics.upload_bytes(10);
        metrics.served_bytes(4);
        metrics.in_flight(1);
        metrics.in_flight(-1);
        let body = metrics.render(&crate::store::Usage {
            bytes: 42,
            blobs: 2,
        });
        assert_eq!(body.matches("nosfry_blossom_requests_total{").count(), 32);
        assert_eq!(
            body.matches("nosfry_blossom_auth_failures_total{").count(),
            15
        );
        assert_eq!(body.matches("nosfry_blossom_rejected_total{").count(), 11);
        assert!(body.contains("endpoint=\"get\",class=\"2xx\"} 1"));
        assert!(body.contains("reason=\"expired\"} 1"));
        assert!(body.contains("reason=\"quota\"} 1"));
        assert!(body.contains("nosfry_blossom_upload_bytes_total 10\n"));
        assert!(body.contains("nosfry_blossom_served_bytes_total 4\n"));
        assert!(body.contains("nosfry_blossom_uploads_in_flight 0\n"));
        assert!(body.contains("nosfry_blossom_stored_bytes 42\n"));
        assert!(body.contains("nosfry_blossom_stored_blobs 2\n"));
        assert_eq!(metrics.in_flight_now(), 0);
        // Every rejection label name the spec fixes is present.
        for label in [
            "policy",
            "banned_pubkey",
            "banned_blob",
            "size",
            "mime",
            "quota",
            "full",
            "busy",
            "hash_mismatch",
            "length",
            "timeout",
        ] {
            assert!(
                body.contains(&format!("reason=\"{label}\"")),
                "missing {label}"
            );
        }
    }
}
