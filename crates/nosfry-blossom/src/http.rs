//! The Blossom HTTP surface: routes, handlers, and the response
//! header/metrics layer, generic over a [`BlobStore`].
//!
//! Routes: `GET|HEAD|PUT|DELETE /<sha256>[.<ext>]`, `PUT|HEAD
//! /upload`, `GET /list/<pubkey>`, and `OPTIONS` on each — every
//! response gets CORS + security headers from the `observe` layer,
//! which also assigns the bounded `endpoint` label, records
//! `requests_total`, and emits the per-request debug log.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Router, middleware};
use futures_util::StreamExt as _;
use nosfry_core::event::PublicKey;
use nosfry_core::moderation::Moderation;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::sync::watch;
use tokio_util::io::ReaderStream;

use crate::auth::{self, Verb};
use crate::metrics::{Class, Endpoint, Metrics, RejectReason};
use crate::mime;
use crate::path::{self, Hash};
use crate::policy::{Policy, Settings, Slot, Slots};
use crate::range::Range;
use crate::store::{
    BlobMeta, BlobStore, Commit, CommitError, ListError, ListQuery, NewBlob, Quota, Removal,
};

const X_SHA256: HeaderName = HeaderName::from_static("x-sha-256");
const X_CONTENT_LENGTH: HeaderName = HeaderName::from_static("x-content-length");
const X_CONTENT_TYPE: HeaderName = HeaderName::from_static("x-content-type");
const X_REASON: HeaderName = HeaderName::from_static("x-reason");
const EXPOSE: HeaderName = HeaderName::from_static("access-control-expose-headers");
const ALLOW_ORIGIN: HeaderName = HeaderName::from_static("access-control-allow-origin");
const ALLOW_METHODS: HeaderName = HeaderName::from_static("access-control-allow-methods");
const ALLOW_HEADERS: HeaderName = HeaderName::from_static("access-control-allow-headers");
const MAX_AGE: HeaderName = HeaderName::from_static("access-control-max-age");
const CSP: HeaderName = HeaderName::from_static("content-security-policy");
const REFERRER: HeaderName = HeaderName::from_static("referrer-policy");
const NOSNIFF: HeaderName = HeaderName::from_static("x-content-type-options");

const CSP_VALUE: &str = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
const EXPOSE_VALUE: &str = "Allow, X-Reason, Content-Length, Content-Range, Accept-Ranges, ETag";
const BLOB_CACHE: &str = "public, max-age=86400, immutable";

/// The unix-time clock; a `fn` field so tests can pin it.
pub type Clock = fn() -> u64;

/// The default clock.
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |dur| dur.as_secs())
}

/// Everything the handlers share.
pub struct Shared<S: BlobStore> {
    /// The blob store.
    pub store: S,
    /// Restart-only service settings.
    pub settings: Settings,
    /// The live policy — `borrow().clone()` once per request.
    pub policy: watch::Receiver<Arc<Policy>>,
    /// Relay moderation state (NIP-86 banned/allowed pubkeys).
    pub moderation: watch::Receiver<Arc<Moderation>>,
    /// Upload-slot semaphores (global + per-pubkey).
    pub slots: Slots,
    /// The `nosfry_blossom_*` metrics.
    pub metrics: Arc<Metrics>,
    /// Unix-time source for auth and upload timestamps.
    pub now: Clock,
    /// Per-chunk idle timeout while streaming uploads.
    pub idle_timeout: Duration,
}

impl<S: BlobStore> Shared<S> {
    /// The moderation state at request start.
    fn moderation(&self) -> Arc<Moderation> {
        self.moderation.borrow().clone()
    }

    /// The live policy at request start.
    fn policy(&self) -> Arc<Policy> {
        self.policy.borrow().clone()
    }
}

impl<S: BlobStore> std::fmt::Debug for Shared<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

/// The Blossom router for `nosfry::serve`.
pub fn router<S: BlobStore>(shared: Arc<Shared<S>>) -> Router {
    Router::new()
        .route(
            "/upload",
            put(upload).head(upload_check).options(options_upload),
        )
        .route(
            "/{key}",
            get(get_blob)
                .head(head_blob)
                .put(upload_at)
                .delete(delete_blob)
                .options(options_blob),
        )
        .route_layer(DefaultBodyLimit::disable())
        .route("/list/{pubkey}", get(list_blobs).options(options_list))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(Arc::clone(&shared), observe))
        .with_state(shared)
}

/// The `endpoint` label from method + path shape — never from
/// client-controlled text beyond "does it parse".
fn classify(method: &axum::http::Method, path_str: &str) -> Endpoint {
    if method == axum::http::Method::OPTIONS {
        return Endpoint::Options;
    }
    let tail = path_str.strip_prefix('/').unwrap_or(path_str);
    match method.as_str() {
        "PUT" => Endpoint::Upload,
        "DELETE" => Endpoint::Delete,
        "GET" if tail.starts_with("list/") => Endpoint::List,
        "GET" if matches!(path::parse_blob_path(tail), path::BlobPath::Blob(..)) => Endpoint::Get,
        "HEAD" if tail == "upload" => Endpoint::UploadCheck,
        "HEAD" if matches!(path::parse_blob_path(tail), path::BlobPath::Blob(..)) => Endpoint::Head,
        _ => Endpoint::Other,
    }
}

/// Per-request observer: classify, time, run, attach the security
/// and CORS headers every response carries, count `requests_total`,
/// and emit the `nosfry::blossom` debug line (status/bytes/elapsed —
/// never URI query, headers, or Authorization).
async fn observe<S: BlobStore>(
    State(shared): State<Arc<Shared<S>>>,
    req: Request,
    next: Next,
) -> Response {
    let endpoint = classify(req.method(), req.uri().path());
    let started = Instant::now();
    let mut res = next.run(req).await;
    let status = res.status().as_u16();
    {
        let headers = res.headers_mut();
        headers.insert(ALLOW_ORIGIN, HeaderValue::from_static("*"));
        headers.insert(NOSNIFF, HeaderValue::from_static("nosniff"));
        headers.insert(CSP, HeaderValue::from_static(CSP_VALUE));
        headers.insert(REFERRER, HeaderValue::from_static("no-referrer"));
        if endpoint != Endpoint::Options {
            headers.insert(EXPOSE, HeaderValue::from_static(EXPOSE_VALUE));
        }
        if status >= 400 {
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
    }
    shared.metrics.request(endpoint, Class::of(status));
    let bytes = res
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    tracing::debug!(
        target: "nosfry::blossom",
        endpoint = endpoint.label(),
        status,
        bytes,
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "blossom request"
    );
    res
}

/// `OPTIONS /<sha256>`: 204 + the fixed CORS preflight headers.
async fn options_blob() -> Response {
    options("GET, HEAD, PUT, DELETE, OPTIONS")
}

/// `OPTIONS /upload`.
async fn options_upload() -> Response {
    options("PUT, HEAD, OPTIONS")
}

/// `OPTIONS /list/<pubkey>`.
async fn options_list() -> Response {
    options("GET, OPTIONS")
}

/// Shared OPTIONS shape.
fn options(methods: &'static str) -> Response {
    let mut res = StatusCode::NO_CONTENT.into_response();
    let headers = res.headers_mut();
    headers.insert(header::ALLOW, HeaderValue::from_static(methods));
    headers.insert(ALLOW_METHODS, HeaderValue::from_static(methods));
    headers.insert(ALLOW_HEADERS, HeaderValue::from_static("Authorization, *"));
    headers.insert(EXPOSE, HeaderValue::from_static("Allow"));
    headers.insert(MAX_AGE, HeaderValue::from_static("86400"));
    res
}

/// A status + short ASCII reason: `X-Reason` plus a text/plain body
/// unless `head` (the layer adds `no-store` for `>= 400`).
fn fail(status: StatusCode, reason: &str, head: bool) -> Response {
    let mut res = Response::new(if head {
        Body::empty()
    } else {
        Body::from(reason.to_owned())
    });
    *res.status_mut() = status;
    let headers = res.headers_mut();
    if let Ok(value) = HeaderValue::from_str(reason) {
        headers.insert(X_REASON, value);
    }
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    res
}

/// `404` for unknown paths and unknown hashes alike.
async fn not_found() -> Response {
    fail(StatusCode::NOT_FOUND, "not found", false)
}

/// `405` — axum attaches the `Allow` header for the route.
async fn method_not_allowed() -> Response {
    fail(StatusCode::METHOD_NOT_ALLOWED, "method not allowed", false)
}

/// Parse a `/{key}` blob path — `/<sha256>[.<ext>]`. `Malformed`
/// answers 400 on every route; `Other` is left to the caller (404 on
/// reads, 400 on `PUT`).
fn blob_key(key: &str) -> Result<Hash, path::BlobPath<'_>> {
    match path::parse_blob_path(key) {
        path::BlobPath::Blob(hash, _) => Ok(hash),
        other => Err(other),
    }
}

/// `GET /<sha256>[.<ext>]` — public read (BUD-01). Ranges,
/// `If-None-Match`/`If-Range`, `Content-Disposition` for active
/// types.
async fn get_blob<S: BlobStore>(
    State(shared): State<Arc<Shared<S>>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    serve_blob(&shared, &key, &headers, false).await
}

/// `HEAD /<sha256>[.<ext>]` — headers only; Range ignored.
async fn head_blob<S: BlobStore>(
    State(shared): State<Arc<Shared<S>>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    serve_blob(&shared, &key, &headers, true).await
}

/// Shared GET/HEAD body.
async fn serve_blob<S: BlobStore>(
    shared: &Shared<S>,
    key: &str,
    headers: &HeaderMap,
    head: bool,
) -> Response {
    let hash = match blob_key(key) {
        Ok(hash) => hash,
        Err(path::BlobPath::Malformed) => {
            return fail(StatusCode::BAD_REQUEST, "malformed blob path", head);
        }
        Err(_) => return fail(StatusCode::NOT_FOUND, "blob not found", head),
    };
    let found = match shared.store.open_blob(&hash).await {
        Ok(found) => found,
        Err(err) => return store_failure(&err, head),
    };
    let Some((meta, mut reader)) = found else {
        return fail(StatusCode::NOT_FOUND, "blob not found", head);
    };
    let etag = format!("\"{hash}\"");
    let matched = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            let weak = format!("W/{etag}");
            value
                .split(',')
                .any(|tag| tag.trim() == etag || tag.trim() == weak || tag.trim() == "*")
        });
    if matched {
        let mut res = Response::new(Body::empty());
        *res.status_mut() = StatusCode::NOT_MODIFIED;
        blob_headers(res.headers_mut(), &meta, &hash, meta.size, None);
        return res;
    }
    // Range: GET only. An `If-Range` that does not match the ETag
    // demotes the request to a full 200 (RFC 9110 §14.3 — weak
    // validators never satisfy the strong comparison).
    let mut requested = Range::Full;
    if !head {
        let fresh = headers
            .get(header::IF_RANGE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v.trim() == etag);
        if fresh {
            let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
            requested = crate::range::parse(range, meta.size);
        }
    }
    let (status, start, len, range_header) = match requested {
        Range::Full => (StatusCode::OK, 0_u64, meta.size, None),
        Range::Partial {
            start,
            end_inclusive,
        } => (
            StatusCode::PARTIAL_CONTENT,
            start,
            end_inclusive - start + 1,
            Some(format!("bytes {start}-{end_inclusive}/{}", meta.size)),
        ),
        Range::Unsatisfiable => {
            let mut res = fail(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "range not satisfiable",
                head,
            );
            if let Ok(value) = HeaderValue::from_str(&format!("bytes */{}", meta.size)) {
                res.headers_mut().insert(header::CONTENT_RANGE, value);
            }
            return res;
        }
    };
    if let Err(err) = reader.seek(std::io::SeekFrom::Start(start)).await {
        return store_failure(&err.into(), head);
    }
    let body = if head {
        Body::empty()
    } else {
        shared.metrics.served_bytes(len);
        Body::from_stream(ReaderStream::new(reader.take(len)))
    };
    let mut res = Response::new(body);
    *res.status_mut() = status;
    blob_headers(
        res.headers_mut(),
        &meta,
        &hash,
        len,
        range_header.as_deref(),
    );
    res
}

/// The headers every 2xx/3xx blob response carries.
fn blob_headers(
    headers: &mut HeaderMap,
    meta: &BlobMeta,
    hash: &Hash,
    len: u64,
    content_range: Option<&str>,
) {
    if let Ok(ty) = HeaderValue::from_str(&meta.mime) {
        headers.insert(header::CONTENT_TYPE, ty);
    }
    if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(value) = HeaderValue::from_str(&format!("\"{hash}\"")) {
        headers.insert(header::ETAG, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(BLOB_CACHE));
    if let Some(range) = content_range
        && let Ok(value) = HeaderValue::from_str(range)
    {
        headers.insert(header::CONTENT_RANGE, value);
    }
    if mime::is_active(&meta.mime) {
        let disposition = format!(
            "attachment; filename=\"{hash}.{}\"",
            mime::extension(&meta.mime)
        );
        if let Ok(value) = HeaderValue::from_str(&disposition) {
            headers.insert(header::CONTENT_DISPOSITION, value);
        }
    }
}

/// One store failure into a 500 with no details for the client.
fn store_failure(err: &crate::store::StoreError, head: bool) -> Response {
    tracing::error!(target: "nosfry::blossom", error = %err, "blob store failed");
    fail(StatusCode::INTERNAL_SERVER_ERROR, "store failure", head)
}

/// Whether the URI carries a `url` query parameter — the BUD-13
/// remote-mirroring fetch is not implemented, so `PUT /<sha256>`
/// refuses it.
fn url_query(uri: &Uri) -> bool {
    uri.query().is_some_and(|query| {
        query
            .split('&')
            .any(|pair| pair.split('=').next() == Some("url"))
    })
}

/// Extract the request `Authorization` value; an undecodable header
/// value is its own auth failure.
fn auth_header(headers: &HeaderMap) -> Result<Option<&str>, auth::AuthError> {
    headers
        .get(header::AUTHORIZATION)
        .map_or(Ok(None), |value| {
            value.to_str().map(Some).map_err(|_| auth::AuthError::Utf8)
        })
}

/// Run `authorize` and map the error into the response.
#[expect(
    clippy::result_large_err,
    reason = "Response is the uniform error channel for handlers"
)]
fn authorize<S: BlobStore>(
    shared: &Shared<S>,
    headers: &HeaderMap,
    verb: Verb,
    hash: Option<&Hash>,
    head: bool,
) -> Result<auth::Token, Response> {
    auth_header(headers)
        .and_then(|header| {
            auth::authorize(
                header,
                verb,
                (shared.now)(),
                &shared.settings.public_host,
                hash,
            )
        })
        .map_err(|err| {
            shared.metrics.auth_failure(err);
            fail(StatusCode::UNAUTHORIZED, &err.to_string(), head)
        })
}

/// The in-flight upload gauge.
struct Flight<'a>(&'a Metrics);

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.in_flight(-1);
    }
}

/// `PUT /upload`.
async fn upload<S: BlobStore>(
    State(shared): State<Arc<Shared<S>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    upload_inner(&shared, None, &uri, &headers, body).await
}

/// `PUT /<sha256>` — the direct path gives the expected hash.
async fn upload_at<S: BlobStore>(
    State(shared): State<Arc<Shared<S>>>,
    Path(key): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Ok(hash) = blob_key(&key) else {
        return fail(StatusCode::BAD_REQUEST, "malformed blob path", false);
    };
    upload_inner(&shared, Some(hash), &uri, &headers, body).await
}

/// The checks `PUT`/`HEAD /upload` share up to the slot acquisition
/// — everything that does not need a body.
struct Prechecked {
    token: auth::Token,
    declared_len: u64,
    ty: String,
    expected: Option<Hash>,
}

/// Steps 1–7 of the upload pipeline: `X-SHA-256`, declared
/// length/type, auth, policy, known-hash ban, size/mime, quota/cap.
/// `None` response means "proceed to slots + stream".
#[expect(
    clippy::result_large_err,
    reason = "Response is the uniform error channel for handlers"
)]
async fn precheck<S: BlobStore>(
    shared: &Shared<S>,
    path_hash: Option<Hash>,
    headers: &HeaderMap,
    length: Option<Result<u64, ()>>,
    ty: Option<String>,
    head: bool,
) -> Result<Prechecked, Response> {
    // 1. X-SHA-256 syntax and agreement with a direct path.
    let declared_hash = match headers.get(X_SHA256) {
        Some(value) => match value.to_str().ok().and_then(Hash::from_hex) {
            Some(hash) => Some(hash),
            None => return Err(fail(StatusCode::BAD_REQUEST, "invalid x-sha-256", head)),
        },
        None => None,
    };
    if let (Some(a), Some(b)) = (path_hash, declared_hash)
        && a != b
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "x-sha-256 does not match path",
            head,
        ));
    }
    let expected = path_hash.or(declared_hash);
    // 2. Declared length and type.
    let declared_len = match length {
        Some(Ok(len)) => len,
        Some(Err(())) => {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "invalid content-length",
                head,
            ));
        }
        None => {
            return Err(fail(
                StatusCode::LENGTH_REQUIRED,
                "content-length required",
                head,
            ));
        }
    };
    let Some(ty) = ty else {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid content type", head));
    };
    // 3. Authorize.
    let token = authorize(shared, headers, Verb::Upload, expected.as_ref(), head)?;
    let policy = shared.policy();
    let moderation = shared.moderation();
    // 4. Pubkey policy / ban.
    if moderation.banned_pubkeys.contains_key(&token.pubkey) {
        shared.metrics.rejected(RejectReason::BannedPubkey);
        return Err(fail(StatusCode::FORBIDDEN, "pubkey is banned", head));
    }
    if !policy.admits(&token.pubkey, &moderation) {
        shared.metrics.rejected(RejectReason::Policy);
        return Err(fail(
            StatusCode::FORBIDDEN,
            "pubkey is not allowed to upload",
            head,
        ));
    }
    // 5. Known-hash ban + advisory usage figures. `PUT /upload`
    // without `X-SHA-256` declares its target in the token's `x`
    // tag; with no hash at all the zero hash still yields the
    // usage/total figures.
    let probe = expected.or_else(|| token.first()).unwrap_or(Hash([0; 32]));
    let precheck = shared
        .store
        .check(&probe, &token.pubkey)
        .await
        .map_err(|err| store_failure(&err, head))?;
    if expected.is_some() && precheck.banned {
        shared.metrics.rejected(RejectReason::BannedBlob);
        return Err(fail(StatusCode::FORBIDDEN, "blob is banned", head));
    }
    // 6. Size / mime allow-list.
    if declared_len > policy.max_blob_size {
        shared.metrics.rejected(RejectReason::Size);
        return Err(fail(StatusCode::PAYLOAD_TOO_LARGE, "blob too large", head));
    }
    if !mime::allowed(&ty, &policy.mime_types) {
        shared.metrics.rejected(RejectReason::Mime);
        return Err(fail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "media type not allowed",
            head,
        ));
    }
    // 7. Quota / global cap (advisory; commit re-checks). A signer
    // who already owns the blob never hits 429/503 here — the
    // commit returns Existed without growing usage.
    if !precheck.owned {
        if precheck.usage.bytes.saturating_add(declared_len) > policy.quota_bytes
            || precheck.usage.blobs.saturating_add(1) > policy.quota_blobs
        {
            shared.metrics.rejected(RejectReason::Quota);
            return Err(fail(StatusCode::TOO_MANY_REQUESTS, "quota exceeded", head));
        }
        if !precheck.exists
            && precheck.total.bytes.saturating_add(declared_len) > policy.max_total_bytes
        {
            shared.metrics.rejected(RejectReason::Full);
            return Err(fail(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage is full",
                head,
            ));
        }
    }
    Ok(Prechecked {
        token,
        declared_len,
        ty,
        expected,
    })
}

/// `PUT /upload` and `PUT /<sha256>`: the full upload pipeline
/// ending in a streaming commit.
async fn upload_inner<S: BlobStore>(
    shared: &Shared<S>,
    path_hash: Option<Hash>,
    uri: &Uri,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    // `?url=` → 400 on `PUT /<sha256>` — BUD-13 remote mirroring is
    // mandatory there and we do not fetch remote URLs. `PUT /upload`
    // ignores query parameters.
    if path_hash.is_some() && url_query(uri) {
        return fail(StatusCode::BAD_REQUEST, "url query is not supported", false);
    }
    let length = headers.get(header::CONTENT_LENGTH).map(|v| {
        v.to_str()
            .map_err(|_| ())
            .and_then(|s| s.parse::<u64>().map_err(|_| ()))
    });
    let ty = mime::normalize(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
    )
    .ok();
    let checked = match precheck(shared, path_hash, headers, length, ty, false).await {
        Ok(checked) => checked,
        Err(res) => return res,
    };
    // 8. Upload slots (global → 503, per-pubkey → 429).
    let _permits = match shared.slots.try_upload(&checked.token.pubkey) {
        Ok(permits) => {
            shared.metrics.in_flight(1);
            permits
        }
        Err(Slot::Global) => {
            shared.metrics.rejected(RejectReason::Busy);
            return fail(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many uploads in progress",
                false,
            );
        }
        Err(Slot::PerKey) => {
            shared.metrics.rejected(RejectReason::Busy);
            return fail(
                StatusCode::TOO_MANY_REQUESTS,
                "too many concurrent uploads",
                false,
            );
        }
    };
    let _flight = Flight(&shared.metrics);
    // 9. Stream into a staging file: hash, count, idle timeout.
    let mut staging = match shared.store.stage().await {
        Ok(staging) => staging,
        Err(err) => return store_failure(&err, false),
    };
    let hash = match stream_body(shared, &mut staging, body, checked.declared_len).await {
        Ok(hash) => hash,
        Err(res) => return res,
    };
    if let Err(err) = shared.store.sync(&mut staging).await {
        return store_failure(&err, false);
    }
    if let Some(expected) = checked.expected
        && hash != expected
    {
        shared.metrics.rejected(RejectReason::HashMismatch);
        return fail(StatusCode::CONFLICT, "hash mismatch", false);
    }
    if checked.token.has_hashes() && !checked.token.covers(&hash) {
        shared.metrics.auth_failure(auth::AuthError::HashMismatch);
        let reason = auth::AuthError::HashMismatch.to_string();
        return fail(StatusCode::UNAUTHORIZED, &reason, false);
    }
    // 10. Commit — authoritative ban/ownership/quota/cap inside the
    // write txn.
    let policy = shared.policy();
    let limits = Quota {
        bytes: policy.quota_bytes,
        blobs: policy.quota_blobs,
        total_bytes: policy.max_total_bytes,
    };
    let blob = NewBlob {
        hash,
        size: checked.declared_len,
        mime: checked.ty.clone(),
        owner: checked.token.pubkey,
        now: (shared.now)(),
    };
    let committed = match shared.store.commit(staging, blob, limits).await {
        Ok(committed) => committed,
        Err(CommitError::Banned) => {
            shared.metrics.rejected(RejectReason::BannedBlob);
            return fail(StatusCode::FORBIDDEN, "blob is banned", false);
        }
        Err(CommitError::Quota) => {
            shared.metrics.rejected(RejectReason::Quota);
            return fail(StatusCode::TOO_MANY_REQUESTS, "quota exceeded", false);
        }
        Err(CommitError::Full) => {
            shared.metrics.rejected(RejectReason::Full);
            return fail(StatusCode::SERVICE_UNAVAILABLE, "storage is full", false);
        }
        Err(CommitError::Store(err)) => return store_failure(&err, false),
    };
    let (meta, status) = match committed {
        Commit::Created(meta) => (meta, StatusCode::CREATED),
        Commit::Existed(meta) => (meta, StatusCode::OK),
    };
    shared.metrics.upload_bytes(checked.declared_len);
    tracing::info!(
        target: "nosfry::blossom",
        sha256 = %meta.hash,
        size = meta.size,
        r#type = %meta.mime,
        owner = %checked.token.pubkey,
        "blob stored"
    );
    descriptor(&shared.settings, &meta, status)
}

/// The BUD-02 descriptor JSON.
fn descriptor(settings: &Settings, meta: &BlobMeta, status: StatusCode) -> Response {
    let url = format!(
        "{}/{}.{}",
        settings.public_url,
        meta.hash,
        mime::extension(&meta.mime)
    );
    let body = serde_json::json!({
        "url": url,
        "sha256": meta.hash.to_string(),
        "size": meta.size,
        "type": meta.mime,
        "uploaded": meta.uploaded,
    });
    let mut res = Response::new(Body::from(body.to_string()));
    *res.status_mut() = status;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res
}

/// The streaming half of step 9 — per-chunk idle timeout, byte
/// count, hash.
#[expect(
    clippy::result_large_err,
    reason = "Response is the uniform error channel for handlers"
)]
async fn stream_body<S: BlobStore>(
    shared: &Shared<S>,
    staging: &mut S::Staging,
    body: Body,
    declared_len: u64,
) -> Result<Hash, Response> {
    let mut stream = body.into_data_stream();
    let mut hasher = Sha256::new();
    let mut received = 0_u64;
    loop {
        let Ok(next) = tokio::time::timeout(shared.idle_timeout, stream.next()).await else {
            shared.metrics.rejected(RejectReason::Timeout);
            return Err(fail(StatusCode::REQUEST_TIMEOUT, "upload timed out", false));
        };
        let Some(chunk) = next else { break };
        let Ok(chunk) = chunk else {
            shared.metrics.rejected(RejectReason::Length);
            return Err(fail(StatusCode::BAD_REQUEST, "could not read body", false));
        };
        received = received.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if received > declared_len {
            shared.metrics.rejected(RejectReason::Length);
            return Err(fail(StatusCode::BAD_REQUEST, "body length mismatch", false));
        }
        hasher.update(&chunk);
        if let Err(err) = staging.write_all(&chunk).await {
            return Err(store_failure(&err.into(), false));
        }
    }
    if received != declared_len {
        shared.metrics.rejected(RejectReason::Length);
        return Err(fail(StatusCode::BAD_REQUEST, "body length mismatch", false));
    }
    let hash: [u8; 32] = hasher.finalize().into();
    Ok(Hash(hash))
}

/// `HEAD /upload` (BUD-06): the same validation without a body.
async fn upload_check<S: BlobStore>(
    State(shared): State<Arc<Shared<S>>>,
    headers: HeaderMap,
) -> Response {
    // BUD-06 requires the X- headers — no Content-Length /
    // Content-Type fallbacks (a HEAD request cannot carry them
    // meaningfully anyway).
    if headers.get(X_SHA256).is_none() {
        return fail(StatusCode::BAD_REQUEST, "x-sha-256 required", true);
    }
    let length = headers.get(X_CONTENT_LENGTH).map(|v| {
        v.to_str()
            .map_err(|_| ())
            .and_then(|s| s.parse::<u64>().map_err(|_| ()))
    });
    let ty = mime::normalize(headers.get(X_CONTENT_TYPE).and_then(|v| v.to_str().ok())).ok();
    match precheck(&shared, None, &headers, length, ty, true).await {
        Ok(checked) => checked,
        Err(res) => return res,
    };
    // Slots: report busy only when the global semaphore is dry —
    // acquiring here would briefly hold a real upload slot.
    if shared.slots.global_dry() {
        shared.metrics.rejected(RejectReason::Busy);
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many uploads in progress",
            true,
        );
    }
    StatusCode::OK.into_response()
}

/// `DELETE /<sha256>` (BUD-02): ownership removal; banned pubkeys
/// may still delete their own blobs.
async fn delete_blob<S: BlobStore>(
    State(shared): State<Arc<Shared<S>>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let hash = match blob_key(&key) {
        Ok(hash) => hash,
        Err(path::BlobPath::Malformed) => {
            return fail(StatusCode::BAD_REQUEST, "malformed blob path", false);
        }
        Err(_) => return fail(StatusCode::NOT_FOUND, "blob not found", false),
    };
    let token = match authorize(&shared, &headers, Verb::Delete, Some(&hash), false) {
        Ok(token) => token,
        Err(res) => return res,
    };
    match shared.store.remove_owner(&hash, &token.pubkey).await {
        Ok(Removal::Removed { last }) => {
            tracing::info!(
                target: "nosfry::blossom",
                sha256 = %hash,
                owner = %token.pubkey,
                last,
                "blob ownership removed"
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Removal::NotOwner) => fail(StatusCode::FORBIDDEN, "not an owner of this blob", false),
        Ok(Removal::NotFound) => fail(StatusCode::NOT_FOUND, "blob not found", false),
        Err(err) => store_failure(&err, false),
    }
}

/// `GET /list/<pubkey>` (BUD-12): descriptors newest-first.
async fn list_blobs<S: BlobStore>(
    State(shared): State<Arc<Shared<S>>>,
    Path(pubkey): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(owner) = PublicKey::from_hex(&pubkey) else {
        return fail(StatusCode::BAD_REQUEST, "malformed pubkey", false);
    };
    let query = match list_query(&uri) {
        Ok(query) => query,
        Err(res) => return res,
    };
    let token = match authorize(&shared, &headers, Verb::List, None, false) {
        Ok(token) => token,
        Err(res) => return res,
    };
    if token.pubkey != owner {
        return fail(StatusCode::FORBIDDEN, "can only list your own blobs", false);
    }
    if shared.moderation().banned_pubkeys.contains_key(&owner) {
        shared.metrics.rejected(RejectReason::BannedPubkey);
        return fail(StatusCode::FORBIDDEN, "pubkey is banned", false);
    }
    let metas = match shared.store.list(&owner, query).await {
        Ok(metas) => metas,
        Err(ListError::BadCursor) => return fail(StatusCode::BAD_REQUEST, "bad cursor", false),
        Err(ListError::Store(err)) => return store_failure(&err, false),
    };
    let settings = &shared.settings;
    let list: Vec<serde_json::Value> = metas
        .iter()
        .map(|meta| {
            serde_json::json!({
                "url": format!("{}/{}.{}", settings.public_url, meta.hash, mime::extension(&meta.mime)),
                "sha256": meta.hash.to_string(),
                "size": meta.size,
                "type": meta.mime,
                "uploaded": meta.uploaded,
            })
        })
        .collect();
    let mut res = Response::new(Body::from(serde_json::Value::Array(list).to_string()));
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res
}

/// The `/list` query params: `cursor` (64 lower hex), `limit`
/// (default 100, clamped to 1000), `since`, `until` (u64). Unknown
/// params are ignored.
#[expect(
    clippy::result_large_err,
    reason = "Response is the uniform error channel for handlers"
)]
fn list_query(uri: &Uri) -> Result<ListQuery, Response> {
    let mut query = ListQuery {
        cursor: None,
        limit: 100,
        since: None,
        until: None,
    };
    let bad = |what: &'static str| -> Result<ListQuery, Response> {
        Err(fail(StatusCode::BAD_REQUEST, what, false))
    };
    for pair in uri.query().unwrap_or("").split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut kv = pair.splitn(2, '=');
        let (key, value) = (kv.next().unwrap_or(""), kv.next().unwrap_or(""));
        match key {
            "cursor" => {
                query.cursor = Some(match Hash::from_hex(value) {
                    Some(hash) => hash,
                    None => return bad("bad cursor"),
                });
            }
            "limit" => match value.parse::<u64>() {
                Ok(n @ 1..) => {
                    query.limit = usize::try_from(n.min(1000)).unwrap_or(1000);
                }
                _ => return bad("bad limit"),
            },
            "since" => match value.parse::<u64>() {
                Ok(at) => query.since = Some(at),
                Err(_) => return bad("bad since"),
            },
            "until" => match value.parse::<u64>() {
                Ok(at) => query.until = Some(at),
                Err(_) => return bad("bad until"),
            },
            _ => {}
        }
    }
    Ok(query)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, header};
    use nosfry_core::event::PublicKey;
    use nosfry_core::moderation::Moderation;
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use tokio::runtime::Runtime;
    use tokio::sync::watch;
    use tower::ServiceExt as _;

    use super::*;
    use crate::store::{NewBlob, Quota};
    use crate::{FsStore, Metrics, Mode, Policy, Settings, Slots};

    const LIMITS: Quota = Quota {
        bytes: u64::MAX,
        blobs: u64::MAX,
        total_bytes: u64::MAX,
    };

    /// Seeded blob lengths — 0 and 1 boundary cases plus mid/large.
    const LENS: &[usize] = &[0, 1, 64, 257, 4096];

    /// The seeded store, router, and blob bytes (kept alive for the
    /// whole property run so every case shares them).
    struct Rig {
        _dir: TempDir,
        router: Router,
        blobs: Vec<(Hash, Vec<u8>)>,
    }

    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    static RIG: OnceLock<Rig> = OnceLock::new();

    fn runtime() -> &'static Runtime {
        RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
        })
    }

    /// Commit each of `bodies` into `store` under a fixed owner.
    async fn seed(store: &FsStore, bodies: &[Vec<u8>]) -> Vec<(Hash, Vec<u8>)> {
        let mut out = Vec::new();
        for body in bodies {
            let mut staging = store.stage().await.unwrap();
            staging.write_all(body).await.unwrap();
            store.sync(&mut staging).await.unwrap();
            let hash = Hash(Sha256::digest(body).into());
            store
                .commit(
                    staging,
                    NewBlob {
                        hash,
                        size: body.len() as u64,
                        mime: "application/octet-stream".to_owned(),
                        owner: PublicKey([9; 32]),
                        now: 0,
                    },
                    LIMITS,
                )
                .await
                .unwrap();
            out.push((hash, body.clone()));
        }
        out
    }

    /// Seed `LENS` blobs into a tempdir `FsStore` and build the real
    /// axum router over it.
    fn rig() -> &'static Rig {
        RIG.get_or_init(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let rt = runtime();
            let store = FsStore::open(dir.path(), Mode::Serve).expect("store");
            let bodies: Vec<Vec<u8>> = LENS
                .iter()
                .map(|len| {
                    (0..*len)
                        .map(|i| u8::try_from(i % 251).unwrap_or_default())
                        .collect()
                })
                .collect();
            let blobs = rt.block_on(seed(&store, &bodies));
            let (_p, policy_rx) = watch::channel(Arc::new(Policy {
                upload_everyone: true,
                admins: Arc::from([]),
                max_blob_size: LIMITS.bytes,
                max_total_bytes: LIMITS.total_bytes,
                quota_bytes: LIMITS.bytes,
                quota_blobs: LIMITS.blobs,
                mime_types: Vec::new(),
            }));
            let (_m, moderation_rx) = watch::channel(Arc::new(Moderation::default()));
            let shared = Arc::new(Shared {
                store,
                settings: Settings {
                    public_url: "http://test".to_owned(),
                    public_host: "test".to_owned(),
                    max_concurrent_uploads: 4,
                },
                policy: policy_rx,
                moderation: moderation_rx,
                slots: Slots::new(4),
                metrics: Arc::new(Metrics::default()),
                now: unix_now,
                idle_timeout: Duration::from_secs(60),
            });
            Rig {
                _dir: dir,
                router: router(shared),
                blobs,
            }
        })
    }

    /// Independent RFC 9110 reference for single-range semantics
    /// (spec §2.2): ignored headers serve 200 full; a valid range
    /// that cannot be satisfied serves 416 `bytes */len`; anything
    /// else serves 206 with the exact slice.
    #[derive(Debug, PartialEq, Eq)]
    enum Reference {
        Ignore,
        Unsatisfiable,
        Slice(u64, u64),
    }

    /// A byte position: ASCII digits, at most 19 of them.
    fn pos(text: &str) -> Option<u64> {
        if text.is_empty() || text.len() > 19 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    }

    fn reference(header: Option<&str>, len: u64) -> Reference {
        let Some(header) = header else {
            return Reference::Ignore;
        };
        // The range-unit must literally be `bytes` — other units are
        // unrecognised and ignored.
        let Some(set) = header.trim().strip_prefix("bytes") else {
            return Reference::Ignore;
        };
        let Some(set) = set.trim_start().strip_prefix('=') else {
            return Reference::Ignore;
        };
        // Only a single byte-range-spec is honoured: anything with
        // the set separator is a multipart request we do not serve.
        let set = set.trim();
        if set.contains(',') {
            return Reference::Ignore;
        }
        let Some(dash) = set.find('-') else {
            return Reference::Ignore;
        };
        let (first, second) = (set[..dash].trim(), set[dash + 1..].trim());
        if first.is_empty() {
            // suffix-byte-range-spec: the last n bytes. `n == 0` is
            // never satisfiable, and an empty body satisfies nothing.
            let Some(n) = pos(second) else {
                return Reference::Ignore;
            };
            if n == 0 || len == 0 {
                return Reference::Unsatisfiable;
            }
            return Reference::Slice(len - n.min(len), len - 1);
        }
        // byte-range-spec: first-byte-pos '-' [last-byte-pos]; a
        // last position before the first is invalid, not merely
        // unsatisfiable — the whole header is ignored.
        let Some(start) = pos(first) else {
            return Reference::Ignore;
        };
        let end = if second.is_empty() {
            None
        } else {
            match pos(second) {
                Some(end) => Some(end),
                None => return Reference::Ignore,
            }
        };
        if end.is_some_and(|end| start > end) || len == 0 || start >= len {
            return if end.is_some_and(|end| start > end) {
                Reference::Ignore
            } else {
                Reference::Unsatisfiable
            };
        }
        Reference::Slice(start, end.map_or(len - 1, |end| end.min(len - 1)))
    }

    /// `If-Range` values relative to the blob's `ETag`.
    #[derive(Debug, Clone, Copy)]
    enum IfRange {
        Absent,
        Exact,
        Weak,
        Other,
    }

    /// Generated `Range` header values: valid forms across and past
    /// every seeded length, whitespace variants, multi-range, other
    /// units, and garbage.
    fn range_header() -> impl Strategy<Value = Option<String>> {
        prop_oneof![
            1 => Just(None),
            3 => (0u64..5000, 0u64..5000).prop_map(|(a, b)| Some(format!("bytes={a}-{b}"))),
            2 => (any::<u64>(), any::<u64>()).prop_map(|(a, b)| Some(format!("bytes={a}-{b}"))),
            2 => (0u64..6000).prop_map(|a| Some(format!("bytes={a}-"))),
            2 => (0u64..6000).prop_map(|n| Some(format!("bytes=-{n}"))),
            1 => (0u64..5000, 0u64..5000).prop_map(|(a, b)| Some(format!("bytes = {a} - {b}"))),
            1 => (0u64..5000).prop_map(|a| Some(format!(" bytes={a}-  "))),
            1 => (0u64..5000, 0u64..5000)
                .prop_map(|(a, b)| Some(format!("bytes={a}-10,{b}-20"))),
            2 => prop_oneof![
                "items=0-10", "bytes", "bytes=", "bytes=a-b", "bytes=--5",
                "bytes=10-20-30", "bytes=0--5", "-", "=", "bytes==0-1", "bytes=0,5",
            ]
            .prop_map(|s| Some((*s).to_owned())),
            1 => ".*".prop_map(Some),
        ]
        // Bytes that cannot appear in an HTTP field value can never
        // reach the router — drop them rather than panic building the
        // request.
        .prop_filter("header-legal value", |v| {
            v.as_ref()
                .is_none_or(|s| s.bytes().all(|b| b == b'\t' || (0x20..=0x7e).contains(&b)))
        })
    }

    fn if_range() -> impl Strategy<Value = IfRange> {
        prop_oneof![
            4 => Just(IfRange::Absent),
            2 => Just(IfRange::Exact),
            1 => Just(IfRange::Weak),
            2 => Just(IfRange::Other),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// `GET /<sha256>` with a generated `Range` (and `If-Range`)
        /// matches the RFC 9110 reference on status, body bytes,
        /// `Content-Length` and `Content-Range` for every blob size.
        #[test]
        fn range_get_matches_reference(
            index in 0..LENS.len(),
            header in range_header(),
            if_range in if_range(),
        ) {
            let rig = rig();
            let (hash, body) = &rig.blobs[index];
            let len = body.len() as u64;
            let etag = format!("\"{hash}\"");
            let mut req = Request::builder().uri(format!("/{hash}"));
            if let Some(value) = &header {
                req = req.header(header::RANGE, value);
            }
            // A matching If-Range honours the Range; weak or wrong
            // validators demote the request to a full GET (§14.3).
            let honored = match if_range {
                IfRange::Absent => true,
                IfRange::Exact => {
                    req = req.header(header::IF_RANGE, &etag);
                    true
                }
                IfRange::Weak => {
                    req = req.header(header::IF_RANGE, format!("W/{etag}"));
                    false
                }
                IfRange::Other => {
                    req = req.header(header::IF_RANGE, "\"0000\"");
                    false
                }
            };
            let res = runtime()
                .block_on(rig.router.clone().oneshot(req.body(Body::empty()).unwrap()))
                .unwrap();
            let status = res.status().as_u16();
            let content_range = res
                .headers()
                .get(header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok().map(str::to_owned));
            let content_length: Option<u64> = res
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()?.parse().ok());
            let bytes = runtime()
                .block_on(axum::body::to_bytes(res.into_body(), usize::MAX))
                .unwrap();
            let want = if honored {
                reference(header.as_deref(), len)
            } else {
                Reference::Ignore
            };
            match want {
                Reference::Ignore => {
                    assert_eq!(status, 200, "{header:?} {if_range:?} len={len}");
                    assert_eq!(bytes.as_ref(), body.as_slice());
                    assert_eq!(content_length, Some(len));
                    assert_eq!(content_range, None);
                }
                Reference::Unsatisfiable => {
                    assert_eq!(status, 416, "{header:?} {if_range:?} len={len}");
                    assert_eq!(content_range.as_deref(), Some(format!("bytes */{len}").as_str()));
                }
                Reference::Slice(start, end) => {
                    assert_eq!(status, 206, "{header:?} {if_range:?} len={len}");
                    let (lo, hi) = (
                        usize::try_from(start).unwrap(),
                        usize::try_from(end).unwrap(),
                    );
                    assert_eq!(bytes.as_ref(), &body[lo..=hi]);
                    assert_eq!(content_length, Some(end - start + 1));
                    assert_eq!(
                        content_range.as_deref(),
                        Some(format!("bytes {start}-{end}/{len}").as_str())
                    );
                }
            }
        }
    }
}
