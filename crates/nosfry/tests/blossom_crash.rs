//! Blossom crash-recovery tests against the real `nosfry` binary.
//!
//! `kill -9` exercises the blob commit protocol: a staged upload is
//! never acknowledged before its file and rows commit, an ownership
//! delete is never acknowledged before its rows commit, and the OS
//! page cache survives the kill. After each kill the store is opened
//! `Mode::Admin` in-process (the dead process no longer holds the
//! env): `verify` must be clean, every provably-owned hash must be
//! owned, every provably-deleted one must not be, and every file
//! under `blobs/` must hash to its name.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::shadow_unrelated,
    clippy::excessive_nesting,
    clippy::too_many_lines,
    unused_crate_dependencies,
    reason = "tests may panic on failure paths; deps cover every test binary"
)]

mod common;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::key;
use nosfry_blossom::{BlobStore, FsStore, Hash, ListQuery, Mode};
use nosfry_core::event::PublicKey;
use nosfry_core::sign;
use secp256k1::Keypair;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BIN: &str = env!("CARGO_BIN_EXE_nosfry");

/// Minimal deterministic PRNG (xorshift64*, same as crash.rs).
struct Rng(u64);

impl Rng {
    const fn cycle(cycle: usize) -> Self {
        Self(0x9E37_79B9_7F4A_7C15 ^ (cycle as u64).wrapping_mul(0x2545_F491_4F6C_DD1D))
    }

    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11
    }

    const fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }

    /// Fill `buf` with the keystream — deterministic, cheap.
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            for (slot, byte) in chunk.iter_mut().zip(self.next().to_le_bytes()) {
                *slot = byte;
            }
        }
    }
}

/// A free TCP port for a spawned relay.
fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Relay + blossom config: `upload = "everyone"` and quotas small
/// enough that a busy cycle provably hits them (429s are simply not
/// "acknowledged" for the post-crash invariant).
fn write_config(dir: &Path, relay_port: u16, blob_port: u16) -> PathBuf {
    let path = dir.join("nosfry.toml");
    std::fs::write(
        &path,
        format!(
            "[db]\npath = \"{}\"\n\
             [relay]\nnofiles = 0\n\
             [[relay.listen]]\naddress = \"127.0.0.1:{relay_port}\"\n\
             [blossom]\nenabled = true\n\
             public_url = \"http://127.0.0.1:{blob_port}\"\n\
             dir = \"{}\"\n\
             upload = \"everyone\"\n\
             max_blob_size = 4194304\n\
             max_total_bytes = 1073741824\n\
             quota_bytes = 16777216\n\
             quota_blobs = 24\n\
             [[blossom.listen]]\naddress = \"127.0.0.1:{blob_port}\"\n",
            dir.join("db").display(),
            dir.join("blobs").display()
        ),
    )
    .unwrap();
    path
}

fn stderr_log(path: &Path) -> Stdio {
    Stdio::from(std::fs::File::create(path).unwrap())
}

/// `nosfry relay --config <cfg>`, stderr to a log file.
fn spawn_relay(cfg: &Path, err_log: &Path) -> Child {
    Command::new(BIN)
        .args(["relay", "--config"])
        .arg(cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_log(err_log))
        .spawn()
        .unwrap()
}

/// Wait until the blossom listener answers HTTP. A bare connect is
/// not the readiness edge: `bind` has the socket listening (kernel
/// backlog completes the handshake) while `serve` still opens the
/// store — the accept loops start only after `Mode::Serve` has swept
/// `tmp/`, which a completed response proves.
async fn wait_for_http(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if http(addr, "GET", "/", &[], &[]).await.is_some() {
            return;
        }
        assert!(Instant::now() < deadline, "relay never served on {addr}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A signed kind-24242 token for `verb` covering `hash`; the `server`
/// tag names the blossom `public_url` host.
fn auth(kp: &Keypair, verb: &str, hash: &Hash) -> String {
    let event = sign::event(
        kp,
        24242,
        now().saturating_sub(10),
        &json!([
            ["t", verb],
            ["x", hash.to_string()],
            ["server", "127.0.0.1"],
            ["expiration", (now() + 3600).to_string()]
        ]),
        "Blossom auth",
    );
    format!("Nostr {}", URL_SAFE_NO_PAD.encode(event.json()))
}

/// The `list` variant of [`auth`]: no `x` tag.
fn list_auth(kp: &Keypair) -> String {
    let event = sign::event(
        kp,
        24242,
        now().saturating_sub(10),
        &json!([
            ["t", "list"],
            ["server", "127.0.0.1"],
            ["expiration", (now() + 3600).to_string()]
        ]),
        "Blossom auth",
    );
    format!("Nostr {}", URL_SAFE_NO_PAD.encode(event.json()))
}

/// This client's blobs currently owned on the server
/// (`GET /list/<pubkey>`): seeds `owned` so a saturated quota has
/// delete candidates from the cycle's first op. `None` on any
/// failure — the caller starts empty.
async fn list_owned(addr: SocketAddr, kp: &Keypair) -> Option<Vec<Hash>> {
    let pubkey = PublicKey(kp.x_only_public_key().0.to_byte_array());
    let auth = list_auth(kp);
    let (status, _, body) = http(
        addr,
        "GET",
        &format!("/list/{pubkey}"),
        &[("Authorization", auth.as_str())],
        &[],
    )
    .await?;
    if status != 200 {
        return None;
    }
    let list: serde_json::Value = serde_json::from_slice(&body).ok()?;
    Some(
        list.as_array()?
            .iter()
            .filter_map(|entry| entry["sha256"].as_str().and_then(Hash::from_hex))
            .collect(),
    )
}

/// One HTTP request; `(status, head, body)` or `None` when the
/// connection died before a response head arrived — the request may
/// or may not have committed server-side.
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Option<(u16, String, Vec<u8>)> {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    tcp.write_all(request.as_bytes()).await.ok()?;
    // An early rejection closes the socket mid-write; the response
    // is still readable.
    tcp.write_all(body).await.ok();
    let mut buf = Vec::new();
    if tcp.read_to_end(&mut buf).await.is_err() && buf.is_empty() {
        return None;
    }
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some((status, head, buf[split + 4..].to_vec()))
}

/// Deterministic shared-content bodies (identical across cycles so
/// dedupe/second-owner paths are exercised every cycle).
fn shared_body(n: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + n * 7) % 251).unwrap_or_default())
        .collect()
}

/// A fresh PRNG body of `0..2 MiB`.
fn fresh_body(rng: &mut Rng) -> Vec<u8> {
    let mut body = vec![0; usize::try_from(rng.range(0, 2 * 1024 * 1024)).unwrap()];
    rng.fill(&mut body);
    body
}

/// Per-client record of one crash cycle.
#[derive(Default)]
struct ClientStats {
    /// hash → last acknowledged outcome (`true` owned, `false`
    /// deleted). Each client's ops are sequential, so the last ack
    /// per hash is provable.
    state: HashMap<Hash, bool>,
    /// hashes whose last op's response was lost — outcome ambiguous
    /// either way.
    in_flight: HashSet<Hash>,
    uploads_acked: usize,
    deletes_acked: usize,
}

/// Upload/delete mix until the connection dies or the cap hits:
/// uploads whenever possible (1/3 shared pool, else fresh 0..2
/// MiB), deletes otherwise — 1/5 at random, or forced by a 429:
/// under quota pressure the next op frees a slot instead of
/// locking the client into all-429 uploads. Delete candidates are
/// this client's acknowledged blobs plus whatever this pubkey
/// already owns on the server (`list_owned` seeds them); a seeded
/// hash never enters `stats.state`, so it stays unprovable until
/// this client's own op on it is acknowledged.
async fn client_loop(
    addr: SocketAddr,
    kp: Keypair,
    mut rng: Rng,
    shared: &[Vec<u8>],
    acked: &AtomicUsize,
) -> ClientStats {
    let mut stats = ClientStats::default();
    let mut owned: Vec<Hash> = list_owned(addr, &kp).await.unwrap_or_default();
    let mut must_delete = false;
    for _ in 0..600 {
        if !owned.is_empty() && (must_delete || rng.next().is_multiple_of(5)) {
            must_delete = false;
            let idx = usize::try_from(rng.range(0, owned.len() as u64)).unwrap();
            let hash = owned[idx];
            let auth = auth(&kp, "delete", &hash);
            match http(
                addr,
                "DELETE",
                &format!("/{hash}"),
                &[("Authorization", auth.as_str())],
                &[],
            )
            .await
            {
                Some((204, _, _)) => {
                    stats.state.insert(hash, false);
                    stats.in_flight.remove(&hash);
                    stats.deletes_acked += 1;
                    owned.swap_remove(idx);
                }
                // A same-pubkey sibling deleted it first: no ack of
                // ours, nothing provable — stop offering it.
                Some((404, _, _)) => {
                    owned.swap_remove(idx);
                }
                Some(_) => {}
                None => {
                    stats.in_flight.insert(hash);
                    break;
                }
            }
        } else {
            let body = if rng.next().is_multiple_of(3) {
                shared[usize::try_from(rng.range(0, shared.len() as u64)).unwrap()].clone()
            } else {
                fresh_body(&mut rng)
            };
            let hash = Hash(Sha256::digest(&body).into());
            let auth = auth(&kp, "upload", &hash);
            let path = if rng.next().is_multiple_of(2) {
                "/upload".to_owned()
            } else {
                format!("/{hash}")
            };
            let length = body.len().to_string();
            match http(
                addr,
                "PUT",
                &path,
                &[
                    ("Authorization", auth.as_str()),
                    ("Content-Type", "application/octet-stream"),
                    ("Content-Length", length.as_str()),
                ],
                &body,
            )
            .await
            {
                Some((status, _, _)) if status == 200 || status == 201 => {
                    stats.state.insert(hash, true);
                    stats.in_flight.remove(&hash);
                    stats.uploads_acked += 1;
                    acked.fetch_add(1, Ordering::Relaxed);
                    owned.push(hash);
                }
                // Quota: the next op frees a slot instead of
                // uploading into another 429.
                Some((429, _, _)) => {
                    must_delete = true;
                }
                Some(_) => {}
                None => {
                    stats.in_flight.insert(hash);
                    break;
                }
            }
        }
    }
    stats
}

/// Per `(owner, hash)` merged view of provable end-state.
#[derive(Default)]
struct Rec {
    /// Cycle the latest record came from — earlier cycles are
    /// superseded by any newer record for the key.
    cycle: usize,
    /// Provable outcomes observed in `cycle` (`{true}` owned,
    /// `{false}` deleted; both → conflicting clients, ambiguous).
    states: HashSet<bool>,
    /// An op whose response was lost in `cycle` — either outcome is
    /// legitimate.
    ambiguous: bool,
}

/// Merge one client's per-cycle record for `owner` into `global`.
fn merge(global: &mut HashMap<(u8, Hash), Rec>, cycle: usize, owner: u8, stats: &ClientStats) {
    for (hash, owned) in &stats.state {
        let rec = global.entry((owner, *hash)).or_default();
        if rec.cycle < cycle {
            *rec = Rec::default();
        }
        if rec.cycle <= cycle {
            rec.cycle = cycle;
            rec.states.insert(*owned);
        }
    }
    for hash in &stats.in_flight {
        let rec = global.entry((owner, *hash)).or_default();
        if rec.cycle < cycle {
            *rec = Rec::default();
        }
        if rec.cycle <= cycle {
            rec.cycle = cycle;
            rec.ambiguous = true;
        }
    }
}

/// Every file under `blobs/` must hash to its basename — orphans are
/// allowed, partial files never.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Collect every file under `blobs/` recursively.
fn assert_files_hash_to_names(blobs: &Path) {
    let mut files = Vec::new();
    walk(blobs, &mut files);
    for file in &files {
        let digest = Hash(Sha256::digest(std::fs::read(file).unwrap()).into());
        assert_eq!(
            digest.to_string().as_str(),
            file.file_name().unwrap().to_str().unwrap(),
            "partial blob file {}",
            file.display()
        );
    }
}

/// Open the dead server's store `Mode::Admin` and check every
/// invariant: `verify` clean, provable ownerships present/absent,
/// and every blob file hashing to its name.
async fn check_store(
    blob_dir: &Path,
    global: &HashMap<(u8, Hash), Rec>,
    owners: &[(u8, PublicKey)],
    cycle: usize,
) {
    let store = FsStore::open(blob_dir, Mode::Admin).unwrap();
    let report = store.verify(|_| {}).unwrap();
    assert!(
        report.bad_hash.is_empty()
            && report.missing.is_empty()
            && report.accounting_errors.is_empty(),
        "cycle {cycle}: verify dirty: {report:?}"
    );
    for (owner, pubkey) in owners {
        let owned: HashSet<Hash> = store
            .list(
                pubkey,
                ListQuery {
                    limit: usize::MAX,
                    ..ListQuery::default()
                },
            )
            .await
            .unwrap()
            .into_iter()
            .map(|meta| meta.hash)
            .collect();
        for ((o, hash), rec) in global {
            if o != owner || rec.ambiguous || rec.states.len() != 1 {
                continue;
            }
            if *rec.states.iter().next().unwrap() {
                assert!(
                    owned.contains(hash),
                    "cycle {cycle}: acknowledged upload {hash} of owner {owner} is gone"
                );
            } else {
                assert!(
                    !owned.contains(hash),
                    "cycle {cycle}: acknowledged delete {hash} of owner {owner} still owned"
                );
            }
        }
    }
    drop(store);
    assert_files_hash_to_names(&blob_dir.join("blobs"));
}

/// kill -9 the relay mid-upload repeatedly: nothing the relay
/// acknowledged may be lost or half-written. `NOSFRY_CRASH_CYCLES`
/// overrides the default of 6 cycles (raise for long runs).
#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn kill9_loses_no_acknowledged_blob() {
    let cycles: usize = std::env::var("NOSFRY_CRASH_CYCLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    let dir = tempfile::tempdir().unwrap();
    let blob_dir = dir.path().join("blobs");
    let relay_port = free_port();
    let blob_port = free_port();
    let cfg = write_config(dir.path(), relay_port, blob_port);
    let addr: SocketAddr = format!("127.0.0.1:{blob_port}").parse().unwrap();
    // ~4 pubkeys shared between 8 clients: blobs get shared owners.
    let keys: Vec<Keypair> = (1..=4).map(key).collect();
    let owners: Vec<(u8, PublicKey)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            (
                u8::try_from(i).unwrap(),
                PublicKey(k.x_only_public_key().0.to_byte_array()),
            )
        })
        .collect();
    let shared: Vec<Vec<u8>> = [0, 101, 4096, 65_536, 524_288, 1_048_576]
        .iter()
        .enumerate()
        .map(|(n, len)| shared_body(n, *len))
        .collect();

    // Cumulative provable states across all cycles.
    let mut global: HashMap<(u8, Hash), Rec> = HashMap::new();

    for cycle in 0..cycles {
        let mut rng = Rng::cycle(cycle);
        let mut child = spawn_relay(&cfg, &dir.path().join(format!("relay-{cycle}.err")));
        wait_for_http(addr).await;
        // `Mode::Serve` sweeps tmp/ on open — before it serves.
        if cycle > 0 {
            let tmp = blob_dir.join("tmp");
            assert!(
                std::fs::read_dir(&tmp).is_ok_and(|mut it| it.next().is_none()),
                "cycle {cycle}: tmp/ not swept: {}",
                std::fs::read_dir(&tmp)
                    .unwrap()
                    .filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }

        let cycle_acks = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for index in 0..8_usize {
            let kp = keys[index % keys.len()];
            let shared = shared.clone();
            let client_rng = Rng(rng.next());
            let acks = Arc::clone(&cycle_acks);
            handles.push(tokio::spawn(async move {
                client_loop(addr, kp, client_rng, &shared, &acks).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(rng.range(300, 1500))).await;
        // The kill waits for ≥ 20 acknowledged uploads so a cycle is
        // never vacuous.
        let floor = Instant::now() + Duration::from_secs(10);
        while cycle_acks.load(Ordering::Relaxed) < 20 && Instant::now() < floor {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        child.kill().unwrap();
        child.wait().unwrap();

        let mut cycle_acked = 0_usize;
        for (index, handle) in handles.into_iter().enumerate() {
            let stats = tokio::time::timeout(Duration::from_secs(15), handle)
                .await
                .expect("client never ended")
                .unwrap();
            cycle_acked += stats.uploads_acked;
            merge(
                &mut global,
                cycle,
                u8::try_from(index % keys.len()).unwrap(),
                &stats,
            );
        }
        assert!(
            cycle_acked >= 20,
            "cycle {cycle} was vacuous: {cycle_acked} acknowledged uploads"
        );
        // The process is dead: opening the same env in-process is
        // safe (no double-open). Verify before the next spawn.
        check_store(&blob_dir, &global, &owners, cycle).await;
        let (provably_owned, provably_gone, ambiguous) =
            global.values().fold((0, 0, 0), |(o, g, a), rec| {
                if rec.ambiguous || rec.states.len() != 1 {
                    (o, g, a + 1)
                } else if rec.states.contains(&true) {
                    (o + 1, g, a)
                } else {
                    (o, g + 1, a)
                }
            });
        eprintln!(
            "cycle {cycle}: {cycle_acked} acked uploads; provable owned={provably_owned} \
             deleted={provably_gone} ambiguous={ambiguous}"
        );
    }
}
