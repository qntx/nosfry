//! Blossom end-to-end tests: real HTTP/1.1 over TCP against
//! `nosfry::bind` + `nosfry::serve`, covering every endpoint, every
//! authorization failure mode, response headers, ranges and
//! conditionals, upload dedupe and ownership, list paging, upload
//! policy, bans, quotas, and config refusals.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::shadow_unrelated,
    clippy::missing_asserts_for_indexing,
    clippy::too_many_lines,
    unused_crate_dependencies,
    reason = "tests may panic on failure paths; deps cover every test binary; \
     test fns are end-to-end scenario walkthroughs"
)]

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as PADDED, URL_SAFE_NO_PAD};
use common::key;
use nosfry::config::{BlossomListen, Config, ListenAddress, Upload};
use nosfry_blossom::auth::AuthError;
use nosfry_core::sign;
use secp256k1::Keypair;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, watch};

/// The `nosfry` binary under test — `blob` admin commands run in a
/// second process (the LMDB env is never opened twice in-process).
const BIN: &str = env!("CARGO_BIN_EXE_nosfry");

/// The `blossom.public_url` of every test server — a different host
/// than `relay.service_url` where one is set.
const PUBLIC_URL: &str = "http://blobs.example.com";
/// Its host — the value `server` auth tags must name.
const PUBLIC_HOST: &str = "blobs.example.com";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sha256_hex(data: &[u8]) -> String {
    faster_hex::hex_string(&Sha256::digest(data))
}

fn pubkey_hex(k: &Keypair) -> String {
    faster_hex::hex_string(&k.x_only_public_key().0.to_byte_array())
}

/// A `[[blossom.listen]]` on an ephemeral TCP port.
fn blossom_listen() -> BlossomListen {
    BlossomListen {
        address: ListenAddress::Tcp("127.0.0.1:0".parse().unwrap()),
    }
}

/// A working enabled blossom config. `blossom.dir` stays at the
/// default so `Server::start` substitutes its own owned tempdir.
fn blossom_config() -> Config {
    let mut config = common::config();
    config.blossom.enabled = true;
    PUBLIC_URL.clone_into(&mut config.blossom.public_url);
    config.blossom.upload = Upload::Everyone;
    config.blossom.listen = vec![blossom_listen()];
    config
}

/// Same, with `blossom.dir` inside caller-owned `dir` — required when
/// the store must exist or be reachable before the server starts
/// (`dir` must outlive the server).
fn blossom_config_in(dir: &Path) -> Config {
    let mut config = blossom_config();
    config.blossom.dir = dir.join("blobs");
    config
}

/// A running server with relay + blossom listeners.
struct Server {
    /// The blossom listener's bound TCP address.
    addr: SocketAddr,
    /// The relay listener's bound TCP address (management posts).
    relay_addr: SocketAddr,
    /// `[blossom] dir` — for `blob_admin` calls mid-test.
    blob_dir: PathBuf,
    reload_tx: watch::Sender<Config>,
    stop: oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Server {
    async fn start(config: Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config;
        if config.db.path.as_os_str() == "./nosfry-db" {
            config.db.path = dir.path().join("db");
        }
        if config.blossom.dir.as_os_str() == "./nosfry-blobs" {
            config.blossom.dir = dir.path().join("blobs");
        }
        if config.relay.listen == Config::default().relay.listen {
            config.relay.listen = vec![common::tcp_listen()];
        }
        let blob_dir = config.blossom.dir.clone();
        let (tx, rx) = oneshot::channel();
        let (reload_tx, reload_rx) = watch::channel(config.clone());
        let listeners = nosfry::bind(&config).await.unwrap();
        let addr = listeners
            .iter()
            .find(|l| l.service() == nosfry::Service::Blossom)
            .and_then(nosfry::Listener::local_addr)
            .expect("blossom listener bound");
        let relay_addr = listeners
            .iter()
            .find(|l| l.service() == nosfry::Service::Relay)
            .and_then(nosfry::Listener::local_addr)
            .expect("relay listener bound");
        let handle = tokio::spawn(async move {
            nosfry::serve(
                config,
                listeners,
                async {
                    rx.await.ok();
                },
                reload_rx,
            )
            .await
            .unwrap();
        });
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Self {
            addr,
            relay_addr,
            blob_dir,
            reload_tx,
            stop: tx,
            handle,
            _dir: dir,
        }
    }

    async fn start_default() -> Self {
        Self::start(blossom_config()).await
    }

    fn reload(&self, config: Config) {
        self.reload_tx.send(config).unwrap();
    }

    async fn stop(self) {
        self.stop.send(()).ok();
        self.handle.await.ok();
    }
}

/// One HTTP request; returns `(status, head, body)`. Always sends
/// `Connection: close` so `read_to_end` is the full response.
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String, Vec<u8>) {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    tcp.write_all(request.as_bytes()).await.unwrap();
    // The server may answer before draining the body (e.g. an early
    // 413) and its close then resets our write — the response is
    // still readable afterwards.
    tcp.write_all(body).await.ok();
    let mut buf = Vec::new();
    if tcp.read_to_end(&mut buf).await.is_err() {
        assert!(!buf.is_empty(), "connection closed with no response");
    }
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8_lossy(&buf[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, head, buf[split + 4..].to_vec())
}

/// The `Authorization` header value for a signed kind-24242 event:
/// `Nostr <base64url>` (or `Nostr <base64>` padded when `standard`).
fn auth_token(k: &Keypair, kind: u16, created_at: u64, tags: &Value, standard: bool) -> String {
    let event = sign::event(k, kind, created_at, tags, "Blossom auth");
    let json = event.json();
    if standard {
        format!("Nostr {}", PADDED.encode(json))
    } else {
        format!("Nostr {}", URL_SAFE_NO_PAD.encode(json))
    }
}

/// A valid upload-token header for `hash`, both encodings share this
/// shape: `t` + `x` + `server` + `expiration` tags.
fn upload_auth(k: &Keypair, hash: &str) -> String {
    auth_token(
        k,
        24242,
        now().saturating_sub(10),
        &json!([
            ["t", "upload"],
            ["x", hash],
            ["server", PUBLIC_HOST],
            ["expiration", (now() + 3600).to_string()]
        ]),
        false,
    )
}

/// Upload `body` to `addr` as `k` with `content_type`; returns the
/// full response triple.
async fn upload(
    server: &Server,
    k: &Keypair,
    content_type: &str,
    body: &[u8],
) -> (u16, String, Vec<u8>) {
    let hash = sha256_hex(body);
    http(
        server.addr,
        "PUT",
        "/upload",
        &[
            ("Authorization", upload_auth(k, &hash).as_str()),
            ("Content-Type", content_type),
            ("Content-Length", body.len().to_string().as_str()),
        ],
        body,
    )
    .await
}

/// The security/CORS headers every response must carry.
fn assert_standard_headers(head: &str) {
    for want in [
        "access-control-allow-origin: *",
        "access-control-expose-headers:",
        "x-content-type-options: nosniff",
        "content-security-policy:",
        "referrer-policy: no-referrer",
    ] {
        assert!(head.contains(want), "{want} missing: {head}");
    }
}

/// The `X-Reason` value of a response head — `""` when absent.
fn x_reason(head: &str) -> String {
    head.lines()
        .find_map(|line| line.strip_prefix("x-reason:"))
        .map_or_else(String::new, |v| v.trim().to_owned())
}

/// The headers every error response must carry.
fn assert_error_headers(head: &str) {
    for want in [
        "access-control-allow-origin: *",
        "cache-control: no-store",
        "x-reason:",
    ] {
        assert!(head.contains(want), "{want} missing: {head}");
    }
}

/// GET/HEAD, ranges, conditionals, OPTIONS, dedupe, ownership and
/// delete — the whole BUD-01/02/06/12 happy path on one server.
#[tokio::test]
async fn upload_get_range_conditional_list_delete() {
    let server = Server::start_default().await;
    let alice = key(50);
    let bob = key(51);
    let body = b"hello blossom".to_vec();
    let hash = sha256_hex(&body);

    // PUT /upload → 201 + BUD-02 descriptor.
    let (status, head, res_body) = upload(&server, &alice, "image/png", &body).await;
    assert_eq!(status, 201, "{head}");
    assert_standard_headers(&head);
    let descriptor: Value = serde_json::from_slice(&res_body).unwrap();
    assert_eq!(descriptor["sha256"], hash);
    assert_eq!(descriptor["size"], body.len() as u64);
    assert_eq!(descriptor["type"], "image/png");
    assert_eq!(
        descriptor["url"],
        format!("{PUBLIC_URL}/{hash}.png"),
        "descriptor url"
    );

    // Re-upload → 200 dedupe.
    let (status, _, _) = upload(&server, &alice, "image/png", &body).await;
    assert_eq!(status, 200);

    // A second owner adopting the blob → 200.
    let (status, _, _) = upload(&server, &bob, "image/png", &body).await;
    assert_eq!(status, 200);

    // GET /<sha256>.png → 200, content, blob headers.
    let (status, head, res_body) =
        http(server.addr, "GET", &format!("/{hash}.png"), &[], &[]).await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(res_body, body);
    for want in [
        "content-type: image/png",
        &format!("content-length: {}", body.len()),
        "accept-ranges: bytes",
        &format!("etag: \"{hash}\""),
        "cache-control: public, max-age=86400, immutable",
    ] {
        assert!(head.contains(want), "{want} missing: {head}");
    }
    assert!(
        !head.contains("content-disposition"),
        "png must not be attached: {head}"
    );

    // GET without an extension also works.
    let (status, _, res_body) = http(server.addr, "GET", &format!("/{hash}"), &[], &[]).await;
    assert_eq!(status, 200);
    assert_eq!(res_body, body);

    // HEAD → 200, no body.
    let (status, head, res_body) =
        http(server.addr, "HEAD", &format!("/{hash}.png"), &[], &[]).await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(res_body.len(), 0);
    assert!(head.contains(&format!("content-length: {}", body.len())));

    // Range → 206 + Content-Range.
    let (status, head, res_body) = http(
        server.addr,
        "GET",
        &format!("/{hash}"),
        &[("Range", "bytes=0-4")],
        &[],
    )
    .await;
    assert_eq!(status, 206, "{head}");
    assert_eq!(res_body, b"hello");
    assert!(head.contains(&format!("content-range: bytes 0-4/{}", body.len())));

    // Suffix range.
    let (status, _, res_body) = http(
        server.addr,
        "GET",
        &format!("/{hash}"),
        &[("Range", "bytes=-4")],
        &[],
    )
    .await;
    assert_eq!(status, 206);
    assert_eq!(res_body, b"ssom");

    // Unsatisfiable range → 416 + Content-Range */size.
    let (status, head, _) = http(
        server.addr,
        "GET",
        &format!("/{hash}"),
        &[("Range", "bytes=1000-2000")],
        &[],
    )
    .await;
    assert_eq!(status, 416, "{head}");
    assert!(head.contains(&format!("content-range: bytes */{}", body.len())));

    // If-Range honoring: matching etag → range served.
    let (status, _, _) = http(
        server.addr,
        "GET",
        &format!("/{hash}"),
        &[("Range", "bytes=0-1"), ("If-Range", &format!("\"{hash}\""))],
        &[],
    )
    .await;
    assert_eq!(status, 206);
    // Stale etag → full body.
    let (status, _, res_body) = http(
        server.addr,
        "GET",
        &format!("/{hash}"),
        &[("Range", "bytes=0-1"), ("If-Range", "\"deadbeef\"")],
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(res_body, body);

    // If-None-Match → 304.
    let (status, head, res_body) = http(
        server.addr,
        "GET",
        &format!("/{hash}"),
        &[("If-None-Match", &format!("\"{hash}\""))],
        &[],
    )
    .await;
    assert_eq!(status, 304, "{head}");
    assert_eq!(res_body.len(), 0);

    // OPTIONS on the blob path → 204 + full method set.
    let (status, head, _) = http(server.addr, "OPTIONS", &format!("/{hash}"), &[], &[]).await;
    assert_eq!(status, 204, "{head}");
    for want in [
        "allow: GET, HEAD, PUT, DELETE, OPTIONS",
        "access-control-allow-methods: GET, HEAD, PUT, DELETE, OPTIONS",
        "access-control-allow-headers: Authorization, *",
        "access-control-expose-headers: Allow",
        "access-control-max-age: 86400",
    ] {
        assert!(head.contains(want), "{want} missing: {head}");
    }

    // /list/<pubkey> — alice's descriptor, newest-first.
    let list_auth = |k: &Keypair| {
        auth_token(
            k,
            24242,
            now().saturating_sub(10),
            &json!([
                ["t", "list"],
                ["server", PUBLIC_HOST],
                ["expiration", (now() + 3600).to_string()]
            ]),
            false,
        )
    };
    let (status, head, res_body) = http(
        server.addr,
        "GET",
        &format!("/list/{}", pubkey_hex(&alice)),
        &[("Authorization", list_auth(&alice).as_str())],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{head}");
    let list: Value = serde_json::from_slice(&res_body).unwrap();
    let entries = list.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["sha256"], hash);
    assert_eq!(entries[0]["url"], format!("{PUBLIC_URL}/{hash}.png"));

    // Someone else listing alice → 403.
    let (status, _, _) = http(
        server.addr,
        "GET",
        &format!("/list/{}", pubkey_hex(&alice)),
        &[("Authorization", list_auth(&bob).as_str())],
        &[],
    )
    .await;
    assert_eq!(status, 403);

    // DELETE by a non-owner → 403.
    let delete_auth = |k: &Keypair| {
        auth_token(
            k,
            24242,
            now().saturating_sub(10),
            &json!([
                ["t", "delete"],
                ["x", hash],
                ["server", PUBLIC_HOST],
                ["expiration", (now() + 3600).to_string()]
            ]),
            false,
        )
    };
    let carol = key(52);
    let (status, _, _) = http(
        server.addr,
        "DELETE",
        &format!("/{hash}"),
        &[("Authorization", delete_auth(&carol).as_str())],
        &[],
    )
    .await;
    assert_eq!(status, 403);

    // Alice deletes her ownership (204); bob's copy remains → GET 200.
    let (status, _, _) = http(
        server.addr,
        "DELETE",
        &format!("/{hash}"),
        &[("Authorization", delete_auth(&alice).as_str())],
        &[],
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, res_body) = http(server.addr, "GET", &format!("/{hash}"), &[], &[]).await;
    assert_eq!(status, 200);
    assert_eq!(res_body, body);

    // Bob (last owner) deletes → 204, then GET 404.
    let (status, _, _) = http(
        server.addr,
        "DELETE",
        &format!("/{hash}"),
        &[("Authorization", delete_auth(&bob).as_str())],
        &[],
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = http(server.addr, "GET", &format!("/{hash}"), &[], &[]).await;
    assert_eq!(status, 404);

    server.stop().await;
}

/// Every authorization failure mode → 401 + `X-Reason`, on a real
/// upload request.
#[tokio::test]
async fn auth_failure_modes() {
    let server = Server::start_default().await;
    let k = key(53);
    let body = b"auth".to_vec();
    let hash = sha256_hex(&body);
    let expiration = || (now() + 3600).to_string();
    let valid_tags = json!([
        ["t", "upload"],
        ["x", hash],
        ["server", PUBLIC_HOST],
        ["expiration", expiration()]
    ]);

    let cases: Vec<(Option<String>, &'static str, AuthError)> = vec![
        (None, "missing", AuthError::Missing),
        (Some("Bearer xyz".to_owned()), "scheme", AuthError::Scheme),
        (Some("Nostr !!!".to_owned()), "base64", AuthError::Base64),
        (
            Some(format!("Nostr {}", URL_SAFE_NO_PAD.encode(b"\xff\xfe"))),
            "utf8",
            AuthError::Utf8,
        ),
        (
            Some(format!("Nostr {}", URL_SAFE_NO_PAD.encode(b"{not json"))),
            "json",
            AuthError::Invalid,
        ),
        // wrong kind
        (
            Some(auth_token(&k, 1, now(), &valid_tags, false)),
            "kind",
            AuthError::Kind,
        ),
        // created_at in the future
        (
            Some(auth_token(&k, 24242, now() + 300, &valid_tags, false)),
            "future",
            AuthError::Future,
        ),
        // no expiration tag
        (
            Some(auth_token(
                &k,
                24242,
                now(),
                &json!([["t", "upload"], ["x", hash]]),
                false,
            )),
            "no expiration",
            AuthError::NoExpiration,
        ),
        // expired
        (
            Some(auth_token(
                &k,
                24242,
                now().saturating_sub(7200),
                &json!([
                    ["t", "upload"],
                    ["x", hash],
                    ["expiration", (now().saturating_sub(3600)).to_string()]
                ]),
                false,
            )),
            "expired",
            AuthError::Expired,
        ),
        // wrong verb
        (
            Some(auth_token(
                &k,
                24242,
                now(),
                &json!([["t", "get"], ["x", hash], ["expiration", expiration()]]),
                false,
            )),
            "verb",
            AuthError::Verb,
        ),
        // server mismatch
        (
            Some(auth_token(
                &k,
                24242,
                now(),
                &json!([
                    ["t", "upload"],
                    ["x", hash],
                    ["server", "other.example.com"],
                    ["expiration", expiration()]
                ]),
                false,
            )),
            "server",
            AuthError::Server,
        ),
        // missing x (PUT with X-SHA-256 needs coverage)
        (
            Some(auth_token(
                &k,
                24242,
                now(),
                &json!([["t", "upload"], ["expiration", expiration()]]),
                false,
            )),
            "x",
            AuthError::MissingHash,
        ),
        // x does not cover the hash
        (
            Some(auth_token(
                &k,
                24242,
                now(),
                &json!([
                    ["t", "upload"],
                    ["x", sha256_hex(b"other")],
                    ["expiration", expiration()]
                ]),
                false,
            )),
            "x",
            AuthError::HashMismatch,
        ),
    ];
    for (auth, name, err) in cases {
        let mut headers: Vec<(&str, String)> = vec![
            ("Content-Type", "application/octet-stream".to_owned()),
            ("Content-Length", body.len().to_string()),
            ("X-SHA-256", hash.clone()),
        ];
        if let Some(auth) = &auth {
            headers.push(("Authorization", auth.clone()));
        }
        let header_refs: Vec<(&str, &str)> =
            headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let (status, head, _) = http(server.addr, "PUT", "/upload", &header_refs, &body).await;
        assert_eq!(status, 401, "{name}: {head}");
        assert_eq!(x_reason(&head), err.to_string(), "{name}: {head}");
        assert_error_headers(&head);
    }

    // Signature failures: a well-formed kind-24242 event whose `sig`
    // has one hex digit flipped fails BIP-340 verification, and one
    // whose `content` changed after signing mismatches the event
    // `id`. Both map to `Signature`.
    let signed = |tags: &Value| -> Value {
        let event = sign::event(&k, 24242, now(), tags, "Blossom auth");
        serde_json::from_str(event.json()).unwrap()
    };
    let mut bad_sig = signed(&valid_tags);
    let sig = bad_sig["sig"].as_str().unwrap();
    let mut chars: Vec<char> = sig.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    bad_sig["sig"] = json!(chars.iter().collect::<String>());
    let mut bad_id = signed(&valid_tags);
    bad_id["content"] = json!("tampered after signing");
    for (event, name) in [(bad_sig, "bad signature"), (bad_id, "id mismatch")] {
        let token = format!(
            "Nostr {}",
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&event).unwrap())
        );
        let (status, head, _) = http(
            server.addr,
            "PUT",
            "/upload",
            &[
                ("Authorization", token.as_str()),
                ("Content-Type", "application/octet-stream"),
                ("Content-Length", body.len().to_string().as_str()),
                ("X-SHA-256", hash.as_str()),
            ],
            &body,
        )
        .await;
        assert_eq!(status, 401, "{name}: {head}");
        assert_eq!(
            x_reason(&head),
            AuthError::Signature.to_string(),
            "{name}: {head}"
        );
        assert_error_headers(&head);
    }

    // `DELETE /<sha256>`: the same auth chain plus the hash-scoped
    // `MissingHash`/`HashMismatch` checks.
    let delete_cases: Vec<(Option<String>, &'static str, AuthError)> = vec![
        (None, "missing", AuthError::Missing),
        // a `t=upload` token cannot delete
        (Some(upload_auth(&k, &hash)), "verb", AuthError::Verb),
        // `x` names another blob
        (
            Some(auth_token(
                &k,
                24242,
                now(),
                &json!([
                    ["t", "delete"],
                    ["x", sha256_hex(b"other")],
                    ["expiration", expiration()]
                ]),
                false,
            )),
            "x",
            AuthError::HashMismatch,
        ),
        // no `x` at all
        (
            Some(auth_token(
                &k,
                24242,
                now(),
                &json!([["t", "delete"], ["expiration", expiration()]]),
                false,
            )),
            "no x",
            AuthError::MissingHash,
        ),
    ];
    for (auth, name, err) in delete_cases {
        let mut headers: Vec<(&str, String)> = Vec::new();
        if let Some(auth) = &auth {
            headers.push(("Authorization", auth.clone()));
        }
        let header_refs: Vec<(&str, &str)> =
            headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let (status, head, _) = http(
            server.addr,
            "DELETE",
            &format!("/{hash}"),
            &header_refs,
            &[],
        )
        .await;
        assert_eq!(status, 401, "delete {name}: {head}");
        assert_eq!(x_reason(&head), err.to_string(), "delete {name}: {head}");
        assert_error_headers(&head);
    }

    // `GET /list/<pubkey>`: missing and wrong-verb tokens are 401; a
    // valid list token for a *different* pubkey is the ownership 403.
    let owner = pubkey_hex(&k);
    let list_cases: Vec<(Option<String>, &'static str, AuthError)> = vec![
        (None, "missing", AuthError::Missing),
        (Some(upload_auth(&k, &hash)), "verb", AuthError::Verb),
    ];
    for (auth, name, err) in list_cases {
        let mut headers: Vec<(&str, String)> = Vec::new();
        if let Some(auth) = &auth {
            headers.push(("Authorization", auth.clone()));
        }
        let header_refs: Vec<(&str, &str)> =
            headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let (status, head, _) = http(
            server.addr,
            "GET",
            &format!("/list/{owner}"),
            &header_refs,
            &[],
        )
        .await;
        assert_eq!(status, 401, "list {name}: {head}");
        assert_eq!(x_reason(&head), err.to_string(), "list {name}: {head}");
        assert_error_headers(&head);
    }
    let other_list = auth_token(
        &key(55),
        24242,
        now(),
        &json!([["t", "list"], ["expiration", expiration()]]),
        false,
    );
    let (status, head, _) = http(
        server.addr,
        "GET",
        &format!("/list/{owner}"),
        &[("Authorization", other_list.as_str())],
        &[],
    )
    .await;
    assert_eq!(status, 403, "list other pubkey: {head}");
    assert_eq!(x_reason(&head), "can only list your own blobs");

    // `HEAD /upload` (BUD-06 preflight) without auth → 401 Missing —
    // the blossom-client-sdk upload flow depends on it.
    let (status, head, _) = http(
        server.addr,
        "HEAD",
        "/upload",
        &[
            ("X-SHA-256", hash.as_str()),
            ("X-Content-Length", body.len().to_string().as_str()),
            ("X-Content-Type", "application/octet-stream"),
        ],
        &[],
    )
    .await;
    assert_eq!(status, 401, "head upload: {head}");
    assert_eq!(x_reason(&head), AuthError::Missing.to_string());

    // Both encodings accepted: unpadded URL-safe and padded standard.
    let tags = json!([
        ["t", "upload"],
        ["x", sha256_hex(b"std")],
        ["expiration", expiration()]
    ]);
    let body = b"std".to_vec();
    let (status, head, _) = http(
        server.addr,
        "PUT",
        "/upload",
        &[
            (
                "Authorization",
                auth_token(&k, 24242, now(), &tags, true).as_str(),
            ),
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", "3"),
        ],
        &body,
    )
    .await;
    assert_eq!(status, 201, "padded standard base64: {head}");

    server.stop().await;
}

/// Upload-pipeline validation: `url` query, `X-SHA-256`, headers,
/// length, preflight, and body checks.
#[tokio::test]
async fn upload_validation() {
    let server = Server::start_default().await;
    let k = key(54);
    let body = b"data".to_vec();
    let hash = sha256_hex(&body);
    let length = body.len().to_string();

    // `?url=` → 400 on `PUT /<sha256>` (BUD-13 remote mirroring is
    // not implemented); `PUT /upload` ignores query parameters.
    let (status, head, _) = http(
        server.addr,
        "PUT",
        &format!("/{hash}?url=http://x"),
        &[
            ("Authorization", upload_auth(&k, &hash).as_str()),
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", length.as_str()),
        ],
        &body,
    )
    .await;
    assert_eq!(status, 400, "{head}");
    assert_error_headers(&head);
    let (status, head, _) = http(
        server.addr,
        "PUT",
        "/upload?url=x",
        &[
            ("Authorization", upload_auth(&k, &hash).as_str()),
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", length.as_str()),
        ],
        &body,
    )
    .await;
    assert_eq!(status, 201, "{head}");

    // Missing Content-Length → 411.
    {
        let mut tcp = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        let request = format!(
            "PUT /upload HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Authorization: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
            upload_auth(&k, &hash)
        );
        tcp.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tcp.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 411"), "{text}");
    }

    // Malformed Content-Type → 400 (missing defaults to
    // application/octet-stream per mime::normalize).
    let (status, _, _) = http(
        server.addr,
        "PUT",
        "/upload",
        &[
            ("Authorization", upload_auth(&k, &hash).as_str()),
            ("Content-Type", "not-a-mime"),
            ("Content-Length", length.as_str()),
        ],
        &body,
    )
    .await;
    assert_eq!(status, 400);

    // X-SHA-256 vs computed hash → 409.
    let other = sha256_hex(b"other");
    let (status, head, _) = http(
        server.addr,
        "PUT",
        &format!("/{other}"),
        &[
            ("Authorization", upload_auth(&k, &other).as_str()),
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", length.as_str()),
        ],
        &body,
    )
    .await;
    assert_eq!(status, 409, "{head}");

    // Declared length shorter than the body → the server hashes the
    // truncated stream → not covered by the token's `x` tag → 401.
    // (The reverse direction just makes the server wait for bytes
    // that never come.)
    let (status, _, _) = http(
        server.addr,
        "PUT",
        "/upload",
        &[
            ("Authorization", upload_auth(&k, &hash).as_str()),
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", (body.len() - 1).to_string().as_str()),
        ],
        &body,
    )
    .await;
    assert_eq!(status, 401);

    // BUD-06 preflight: valid HEAD /upload → 200 with requirements
    // echo; unauthorized → 401 without a body.
    let (status, head, res_body) = http(
        server.addr,
        "HEAD",
        "/upload",
        &[
            ("Authorization", upload_auth(&k, &hash).as_str()),
            ("X-SHA-256", hash.as_str()),
            ("X-Content-Length", length.as_str()),
            ("X-Content-Type", "application/octet-stream"),
        ],
        &[],
    )
    .await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(res_body.len(), 0);
    let (status, head, res_body) = http(
        server.addr,
        "HEAD",
        "/upload",
        &[
            ("X-SHA-256", hash.as_str()),
            ("X-Content-Length", length.as_str()),
            ("X-Content-Type", "application/octet-stream"),
        ],
        &[],
    )
    .await;
    assert_eq!(status, 401, "{head}");
    assert!(res_body.is_empty(), "HEAD errors carry no body");
    assert!(head.contains("x-reason:"), "{head}");
    // HEAD /upload without X-SHA-256 → 400.
    let (status, _, _) = http(
        server.addr,
        "HEAD",
        "/upload",
        &[
            ("Authorization", upload_auth(&k, &hash).as_str()),
            ("X-Content-Length", length.as_str()),
            ("X-Content-Type", "application/octet-stream"),
        ],
        &[],
    )
    .await;
    assert_eq!(status, 400);
    // Without X-Content-Length → 411; Content-Length is no fallback.
    let (status, _, _) = http(
        server.addr,
        "HEAD",
        "/upload",
        &[
            ("Authorization", upload_auth(&k, &hash).as_str()),
            ("X-SHA-256", hash.as_str()),
            ("X-Content-Type", "application/octet-stream"),
            ("Content-Length", "0"),
        ],
        &[],
    )
    .await;
    assert_eq!(status, 411);

    // PUT /<sha256> (path upload) works too — fresh body so the
    // commit is a real create, not a dedupe.
    let path_body = b"path-data".to_vec();
    let path_hash = sha256_hex(&path_body);
    let (status, head, _) = http(
        server.addr,
        "PUT",
        &format!("/{path_hash}.bin"),
        &[
            ("Authorization", upload_auth(&k, &path_hash).as_str()),
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", path_body.len().to_string().as_str()),
        ],
        &path_body,
    )
    .await;
    assert_eq!(status, 201, "{head}");

    server.stop().await;
}

/// Routing edges: malformed paths, unknown hashes, wrong methods,
/// OPTIONS on every route.
#[tokio::test]
async fn routing_edges() {
    let server = Server::start_default().await;
    let hash = "a".repeat(64);

    for (path, want) in [
        ("/favicon.ico", 404),
        (&format!("/{}x", "a".repeat(64)), 400), // 64-hex + junk → malformed
        (&format!("/{hash}"), 404),              // well-formed, unknown → 404
        ("/upload", 405),                        // GET /upload → 405 (PUT, HEAD, OPTIONS)
    ] {
        let (status, head, _) = http(server.addr, "GET", path, &[], &[]).await;
        assert_eq!(status, want, "GET {path}: {head}");
        assert_error_headers(&head);
    }

    // POST on a blob path → 405 + Allow.
    let (status, head, _) = http(server.addr, "POST", &format!("/{hash}"), &[], &[]).await;
    assert_eq!(status, 405, "{head}");
    assert!(head.contains("allow:"), "{head}");

    // OPTIONS on each route family, even unknown hashes → 204.
    for (path, allow) in [
        (format!("/{hash}"), "GET, HEAD, PUT, DELETE, OPTIONS"),
        ("/upload".to_owned(), "PUT, HEAD, OPTIONS"),
        (format!("/list/{}", "b".repeat(64)), "GET, OPTIONS"),
    ] {
        let (status, head, body) = http(server.addr, "OPTIONS", &path, &[], &[]).await;
        assert_eq!(status, 204, "OPTIONS {path}: {head}");
        assert!(head.contains(&format!("allow: {allow}")), "{path}: {head}");
        assert_eq!(body.len(), 0);
    }

    // An arbitrary unknown path → 404.
    let (status, _, _) = http(server.addr, "GET", "/anything/else", &[], &[]).await;
    assert_eq!(status, 404);

    server.stop().await;
}

/// Active content is attached, inert content is not.
#[tokio::test]
async fn content_disposition() {
    let server = Server::start_default().await;
    let k = key(55);
    for (mime, ext, attached) in [
        ("text/html", "html", true),
        ("image/svg+xml", "svg", true),
        ("image/png", "png", false),
    ] {
        // Distinct bodies → distinct hashes (stored mime wins on
        // re-upload, so one shared body would not exercise the
        // later mime values).
        let body = mime.as_bytes().to_vec();
        let hash = sha256_hex(&body);
        let (status, head, _) = upload(&server, &k, mime, &body).await;
        assert!(status == 201 || status == 200, "{mime}: {head}");
        let (status, head, _) = http(server.addr, "GET", &format!("/{hash}.{ext}"), &[], &[]).await;
        assert_eq!(status, 200, "{mime}: {head}");
        let disposition = head.contains("content-disposition: attachment");
        assert_eq!(disposition, attached, "{mime}: {head}");
    }
    server.stop().await;
}

/// `upload=allowed` admits admins and NIP-86 allowed pubkeys only;
/// `everyone` admits any valid authorization. Banned pubkeys are
/// refused under either mode — driven live through the NIP-86
/// management endpoint.
#[tokio::test]
async fn policy_modes_and_pubkey_bans() {
    let admin = key(56);
    let member = key(57);
    let outsider = key(58);
    let mut config = blossom_config();
    config.blossom.upload = Upload::Allowed;
    config.relay.service_url = "wss://relay.example.com".to_owned();
    config.relay.management.admins = vec![pubkey_hex(&admin)];
    let server = Server::start(config.clone()).await;
    let body = b"policy".to_vec();

    // allowed mode: admin uploads, outsider refused, member refused.
    assert_eq!(upload(&server, &admin, "text/plain", &body).await.0, 201);
    assert_eq!(upload(&server, &outsider, "text/plain", &body).await.0, 403);
    assert_eq!(upload(&server, &member, "text/plain", &body).await.0, 403);

    // NIP-86 `allowpubkey` lets `member` upload.
    let mgmt = |method: &str, params: Value| {
        let body = json!({"method": method, "params": params}).to_string();
        let payload = faster_hex::hex_string(&Sha256::digest(body.as_bytes()));
        let tags = json!([
            ["u", "http://relay.example.com/"],
            ["method", "POST"],
            ["payload", payload]
        ]);
        let auth = format!(
            "Nostr {}",
            PADDED.encode(sign::event(&admin, 27235, now(), &tags, "").json())
        );
        format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/nostr+json+rpc\r\nContent-Length: {}\r\nConnection: close\r\nAuthorization: {auth}\r\n\r\n{body}",
            body.len()
        )
    };
    {
        let mut tcp = tokio::net::TcpStream::connect(server.relay_addr)
            .await
            .unwrap();
        tcp.write_all(mgmt("allowpubkey", json!([pubkey_hex(&member)])).as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        tcp.read_to_end(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));
    }
    for _ in 0..50 {
        if upload(&server, &member, "text/plain", &body).await.0 != 403 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_ne!(upload(&server, &member, "text/plain", &body).await.0, 403);

    // `banpubkey` refuses even an allowed pubkey.
    {
        let mut tcp = tokio::net::TcpStream::connect(server.relay_addr)
            .await
            .unwrap();
        tcp.write_all(mgmt("banpubkey", json!([pubkey_hex(&member)])).as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        tcp.read_to_end(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));
    }
    for _ in 0..50 {
        if upload(&server, &member, "text/plain", &body).await.0 == 403 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(upload(&server, &member, "text/plain", &body).await.0, 403);

    // upload=everyone (live reload) admits any authorized pubkey —
    // banned pubkeys stay refused.
    let mut everyone = config;
    everyone.blossom.upload = Upload::Everyone;
    server.reload(everyone);
    for _ in 0..50 {
        if upload(&server, &outsider, "text/plain", &body).await.0 == 201 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_ne!(upload(&server, &outsider, "text/plain", &body).await.0, 403);
    assert_eq!(upload(&server, &member, "text/plain", &body).await.0, 403);

    server.stop().await;
}

/// A blob banned through the store before startup is unreachable
/// (its content was deleted with the ban) and cannot be re-uploaded.
#[tokio::test]
async fn banned_blob() {
    let dir = tempfile::tempdir().unwrap();
    let config = blossom_config_in(dir.path());
    let k = key(59);
    let body = b"bad".to_vec();
    let hash = sha256_hex(&body);
    let hash_parsed = nosfry::blob_admin::hash(&hash).unwrap();

    // Seed the store, then ban the hash before the server starts.
    {
        let store = nosfry_blossom::FsStore::open(&config.blossom.dir, nosfry_blossom::Mode::Admin)
            .unwrap();
        nosfry::blob_admin::ban(&store, &hash_parsed, "malware").unwrap();
    }

    let server = Server::start(config).await;
    let (status, _, _) = http(server.addr, "GET", &format!("/{hash}"), &[], &[]).await;
    assert_eq!(status, 404);
    // Re-uploading a banned hash → 403.
    let (status, head, _) = upload(&server, &k, "application/octet-stream", &body).await;
    assert_eq!(status, 403, "{head}");
    server.stop().await;
}

/// Quotas, size and media-type limits — all live-reloadable.
#[tokio::test]
async fn limits_quotas_mime() {
    let server = Server::start_default().await;
    let k = key(60);
    let body = b"quota".to_vec();

    // Shrink every live limit through a reload.
    let mut tight = blossom_config();
    tight.blossom.dir = server.blob_dir.clone();
    tight.blossom.max_blob_size = 2;
    tight.blossom.quota_bytes = 1;
    tight.blossom.quota_blobs = 1;
    tight.blossom.mime_types = vec!["image/*".to_owned()];
    server.reload(tight);
    // Over max_blob_size → 413 once the reload lands.
    let mut status = 0;
    for _ in 0..50 {
        status = upload(&server, &k, "image/png", &body).await.0;
        if status == 413 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(status, 413);

    // mime refused → 415 (under the size limit).
    let (status, _, _) = upload(&server, &k, "text/plain", b"ok").await;
    assert_eq!(status, 415);

    // First small image fits; second blob exceeds quota_blobs → 429.
    // A re-upload of the owned blob still passes (Existed, not 429).
    let (status, head, _) = upload(&server, &k, "image/png", b"1").await;
    assert_eq!(status, 201, "{head}");
    let (status, head, _) = upload(&server, &k, "image/png", b"2").await;
    assert_eq!(status, 429, "{head}");
    let (status, head, _) = upload(&server, &k, "image/png", b"1").await;
    assert_eq!(status, 200, "{head}");

    // Restore generous limits; upload succeeds once the reload lands.
    let mut restore = blossom_config();
    restore.blossom.dir = server.blob_dir.clone();
    server.reload(restore);
    let mut status = 0;
    for _ in 0..50 {
        status = upload(&server, &k, "image/png", b"restored").await.0;
        if status == 201 || status == 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(status == 201 || status == 200, "status {status}");

    server.stop().await;
}

/// `nosfry blob` store administration through the real binary — a
/// second process, so the LMDB env is never opened twice in one
/// process. `ban` lands while the relay serves: the blob 404s and
/// a re-upload is refused; `verify` exits 0 on the clean store.
#[tokio::test]
async fn blob_admin_commands() {
    let server = Server::start_default().await;
    let k = key(61);
    let body = b"admin blob".to_vec();
    let hash = sha256_hex(&body);
    assert_eq!(upload(&server, &k, "image/png", &body).await.0, 201);

    // A minimal config pointing `[blossom] dir` at the live store —
    // `blob` needs no enabled flag.
    let dir = server.blob_dir.parent().unwrap().to_path_buf();
    let cfg = dir.join("blob.toml");
    std::fs::write(
        &cfg,
        format!(
            "[db]\npath = \"{}\"\n[blossom]\ndir = \"{}\"\n",
            dir.join("db").display(),
            server.blob_dir.display()
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(BIN)
            .args(args)
            .arg("--config")
            .arg(&cfg)
            .output()
            .unwrap()
    };
    let ok = |args: &[&str]| {
        let out = run(args);
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };

    // list — JSON lines, then `--after` pages past the one blob.
    let out = ok(&["blob", "list"]);
    let lines: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["sha256"], hash);
    assert_eq!(lines[0]["owners"], 1);
    let out = ok(&["blob", "list", "--after", hash.as_str()]);
    assert_eq!(out.stdout.len(), 0);
    let out = ok(&["blob", "list", "--owner", pubkey_hex(&k).as_str()]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 1);

    // stat — meta, owners, file presence.
    let out = ok(&["blob", "stat", hash.as_str()]);
    let stat: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stat["file_present"], true);
    assert_eq!(stat["owners"].as_array().unwrap().len(), 1);

    // ban while the server runs → gone + re-upload refused.
    ok(&["blob", "ban", hash.as_str(), "--reason", "test"]);
    let (status, _, _) = http(server.addr, "GET", &format!("/{hash}"), &[], &[]).await;
    assert_eq!(status, 404);
    assert_eq!(upload(&server, &k, "image/png", &body).await.0, 403);
    // The banned blob is gone — `stat` reports no such blob.
    assert!(!run(&["blob", "stat", hash.as_str()]).status.success());

    // unban → re-upload ok.
    ok(&["blob", "unban", hash.as_str()]);
    assert_eq!(upload(&server, &k, "image/png", &body).await.0, 201);

    // verify → exit 0 and a clean JSON report.
    let out = ok(&["blob", "verify"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["checked"], 1);
    // gc → JSON report.
    let out = ok(&["blob", "gc"]);
    let _: Value = serde_json::from_slice(&out.stdout).unwrap();

    // delete → absent.
    ok(&["blob", "delete", hash.as_str()]);
    let (status, _, _) = http(server.addr, "GET", &format!("/{hash}"), &[], &[]).await;
    assert_eq!(status, 404);
    // delete again → exit 1 (absent).
    assert!(!run(&["blob", "delete", hash.as_str()]).status.success());

    server.stop().await;
}

/// `/list/<pubkey>` paging: since/until/limit/cursor, newest-first.
#[tokio::test]
async fn list_paging() {
    let server = Server::start_default().await;
    let k = key(62);
    let mut hashes = Vec::new();
    for i in 0..4u8 {
        let body = vec![b'a' + i];
        hashes.push(sha256_hex(&body));
        assert_eq!(upload(&server, &k, "text/plain", &body).await.0, 201);
        // Distinct `uploaded` seconds are not guaranteed; order by
        // insertion still applies within one second.
    }
    let auth = |k: &Keypair| {
        auth_token(
            k,
            24242,
            now(),
            &json!([
                ["t", "list"],
                ["server", PUBLIC_HOST],
                ["expiration", (now() + 3600).to_string()]
            ]),
            false,
        )
    };
    let list = async |query: &str| {
        http(
            server.addr,
            "GET",
            &format!("/list/{}{query}", pubkey_hex(&k)),
            &[("Authorization", auth(&k).as_str())],
            &[],
        )
        .await
        .2
    };
    let all = list("").await;
    let entries: Vec<Value> = serde_json::from_slice(&all).unwrap();
    assert_eq!(entries.len(), 4);
    // limit=2 then cursor onto the next page.
    let page1 = list("?limit=2").await;
    let page1: Vec<Value> = serde_json::from_slice(&page1).unwrap();
    assert_eq!(page1.len(), 2);
    let cursor = page1[1]["sha256"].as_str().unwrap();
    let page2 = list(&format!("?limit=2&cursor={cursor}")).await;
    let page2: Vec<Value> = serde_json::from_slice(&page2).unwrap();
    assert_eq!(page2.len(), 2);
    // Pages don't overlap and together cover all four.
    let mut seen: Vec<String> = page1
        .iter()
        .chain(&page2)
        .map(|e| e["sha256"].as_str().unwrap().to_owned())
        .collect();
    seen.sort();
    assert_eq!(seen, {
        let mut sorted = hashes.clone();
        sorted.sort();
        sorted
    });
    // One more page past the end → empty.
    let cursor = page2[1]["sha256"].as_str().unwrap();
    let page3 = list(&format!("?limit=2&cursor={cursor}")).await;
    let page3: Vec<Value> = serde_json::from_slice(&page3).unwrap();
    assert_eq!(page3.len(), 0);
    // A bad cursor → 400; malformed query values → 400.
    let (status, _, _) = http(
        server.addr,
        "GET",
        &format!("/list/{}?cursor=zz", pubkey_hex(&k)),
        &[("Authorization", auth(&k).as_str())],
        &[],
    )
    .await;
    assert_eq!(status, 400);
    let (status, _, _) = http(
        server.addr,
        "GET",
        &format!("/list/{}?limit=abc", pubkey_hex(&k)),
        &[("Authorization", auth(&k).as_str())],
        &[],
    )
    .await;
    assert_eq!(status, 400);
    let (status, _, _) = http(
        server.addr,
        "GET",
        &format!("/list/{}?since=x", pubkey_hex(&k)),
        &[("Authorization", auth(&k).as_str())],
        &[],
    )
    .await;
    assert_eq!(status, 400);

    server.stop().await;
}

/// `/metrics` on the relay port appends the `nosfry_blossom_*` block.
#[tokio::test]
async fn metrics_appended() {
    let mut config = blossom_config();
    config.relay.metrics = true;
    let server = Server::start(config).await;
    upload(&server, &key(63), "text/plain", b"m").await;
    let (status, _, body) = http(server.relay_addr, "GET", "/metrics", &[], &[]).await;
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("nosfry_blossom_requests_total"), "{text}");
    server.stop().await;
}

/// Load-time config refusals for `[blossom]`.
#[test]
fn config_refusals() {
    let cases: Vec<(String, &str)> = vec![
        // Blossom listener sharing the relay address.
        (
            "\
[relay]\nservice_url = \"wss://relay.example.com\"\n\
[[relay.listen]]\naddress = \"127.0.0.1:7777\"\n\
[blossom]\nenabled = true\npublic_url = \"http://blobs.example.com\"\n\
[[blossom.listen]]\naddress = \"127.0.0.1:7777\"\n"
                .to_owned(),
            "shares an address",
        ),
        // public_url host == service_url host.
        (
            "\
[relay]\nservice_url = \"wss://relay.example.com\"\n\
[blossom]\nenabled = true\npublic_url = \"http://relay.example.com:8443\"\n"
                .to_owned(),
            "host",
        ),
        // public_url host == an alias host.
        (
            "\
[relay]\nservice_url = \"wss://relay.example.com\"\n\
service_url_aliases = [\"wss://alt.example.com\"]\n\
[blossom]\nenabled = true\npublic_url = \"https://alt.example.com\"\n"
                .to_owned(),
            "host",
        ),
        // onion: blossom listener.
        (
            "\
[blossom]\nenabled = true\npublic_url = \"http://blobs.example.com\"\n\
[[blossom.listen]]\naddress = \"onion:nosfry\"\n"
                .to_owned(),
            "onion",
        ),
        // enabled without public_url.
        (
            "\
[blossom]\nenabled = true\n"
                .to_owned(),
            "public_url",
        ),
        // enabled without a listener.
        (
            "\
[blossom]\nenabled = true\npublic_url = \"http://blobs.example.com\"\nlisten = []\n"
                .to_owned(),
            "listen",
        ),
        // public_url not http(s).
        (
            "\
[blossom]\nenabled = true\npublic_url = \"ftp://blobs.example.com\"\n"
                .to_owned(),
            "public_url",
        ),
        // zero / inverted numerics.
        ("[blossom]\nmax_blob_size = 0\n".to_owned(), "max_blob_size"),
        (
            "[blossom]\nmax_blob_size = 200\nmax_total_bytes = 100\n".to_owned(),
            "max_total_bytes",
        ),
        (
            "[blossom]\nmax_concurrent_uploads = 0\n".to_owned(),
            "max_concurrent_uploads",
        ),
        (
            "[blossom]\nmax_concurrent_uploads = 5000\n".to_owned(),
            "max_concurrent_uploads",
        ),
        (
            "[blossom]\nmax_connections = 0\n".to_owned(),
            "max_connections",
        ),
        // bad mime entries.
        (
            "[blossom]\nmime_types = [\"IMAGE/PNG\"]\n".to_owned(),
            "mime_types",
        ),
        (
            "[blossom]\nmime_types = [\"not-a-mime\"]\n".to_owned(),
            "mime_types",
        ),
        // duplicate blossom listeners.
        (
            "\
[[blossom.listen]]\naddress = \"127.0.0.1:7778\"\n\
[[blossom.listen]]\naddress = \"127.0.0.1:7778\"\n"
                .to_owned(),
            "duplicate",
        ),
    ];
    for (text, needle) in cases {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &text).unwrap();
        let err = Config::load(file.path()).unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "expected {needle:?} in {err} for {text:?}"
        );
    }

    // A valid enabled config loads.
    let ok = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        ok.path(),
        "\
[relay]\nservice_url = \"wss://relay.example.com\"\n\
[blossom]\nenabled = true\npublic_url = \"http://blobs.example.com\"\n\
[[blossom.listen]]\naddress = \"127.0.0.1:7778\"\n",
    )
    .unwrap();
    assert!(Config::load(ok.path()).is_ok());
}
