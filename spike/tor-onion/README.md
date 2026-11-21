# Spike A: nosfry as a Tor onion service (in-process Arti)

Throwaway research spike: embed the real `nosfry` relay and serve it both
on plain TCP and as a v3 onion service hosted in-process with Arti
(`arti-client` + `tor-hsservice` 0.48.0, tokio runtime, rustls/ring).

Not part of the root workspace (`[workspace]` is empty). Shares
`CARGO_TARGET_DIR=spike/target` with the other spike. Nothing under
`crates/`, the root `Cargo.toml`, or `deny.toml` is modified.

## Layout

- `src/lib.rs` — the shared serving path, generic over the accepted byte
  stream. Identical wiring to `nosfry::spawn_connection` / `accept_loop`:
  hyper `http1::Builder` + `TowerToHyperService` + `.with_upgrades()` +
  `ConnectInfo(SocketAddr)` in request extensions (the router 500s
  without it), 10 s header-read timeout, `TCP_NODELAY`/keepalive tuning.
- `src/bin/baseline.rs` — TCP-only relay (feature `tor` off).
- `src/bin/onion_relay.rs` — TCP + Arti onion service in one process,
  one shared `Server`/router.
- `src/bin/onion_client.rs` — Arti client: NIP-11 GET, WS publish + REQ
  by id, `--probe` retry loop, `--hold N` open connections for RSS.
- `relay.toml` — minimal nosfry config (127.0.0.1:17890, sqlite db).
- `results/` — raw logs for every run and measurement below.

## Dependency versions (from Cargo.lock, `=` pins in Cargo.toml)

| crate | version | published | MSRV (rust-version) |
|---|---|---|---|
| arti-client | 0.48.0 | 2026-11-04 | 1.92 |
| tor-hsservice | 0.48.0 | 2026-11-04 | 1.92 |
| tor-proto | 0.48.0 | 2026-11-04 | 1.92 |
| tor-cell / tor-rtcompat | 0.48.0 | 2026-11-04 | 1.92 |
| rustls | 0.23.46 | — | — |
| tokio-tungstenite | 0.30.0 | — | — |
| ring | 0.17.14 | — | — |

Cargo.lock: 570 packages total (`grep -c '^name = ' Cargo.lock`).

Features used on `arti-client` (default-features = false):
`tokio`, `rustls`, `onion-service-service`, `onion-service-client`.
No `__is_experimental` features are needed. `onion-service-client` is
required even for the client side — without it `connect()` fails with
`operation not supported because Arti feature disabled: Rejecting .onion
address; feature onion-service-client not compiled in` (verbatim, see
`results/run1-client.log`).

## Arti quirks found (all verified in source + live runs)

1. **rustls `CryptoProvider` panic.** `arti-client/rustls` pulls
   `rustls` (renamed `rustls-dont-use` in tor-rtcompat) with
   `default-features = false` — *no* crypto provider. Bootstrap panics:
   `Could not automatically determine the process-level CryptoProvider`.
   Fix: the application must add `rustls` itself with exactly one
   provider (`default-features = false, features = ["ring","std","tls12","logging"]`)
   and call `rustls::crypto::ring::default_provider().install_default()`.
2. **`write_all` does not flush.** `tor_proto::client::stream::DataWriter`
   buffers writes into relay cells (~498 B payload); a partial cell is
   only emitted on `flush()`. An HTTP request written with `write_all`
   alone never reaches the service — hyper times out after the 10 s
   header deadline (`read header from client timeout` in
   `results/run3-relay.log`). `client_async`/tungstenite flushes after
   every frame, so the WS path is unaffected; the raw NIP-11 GET needed
   an explicit `stream.flush().await`.
3. **Clean close surfaces as `END cell with reason MISC` error, not EOF.**
   When the service's accepted `DataStream` is dropped, arti's reactor
   sends END with `CloseStreamBehavior::default() = SendEnd(End::new_misc())`
   (`tor-proto/src/stream.rs`). The client's `DataReader` maps only
   `EndReason::DONE` to `Ok(0)`; any other reason becomes
   `Error::EndReceived` (`tor-proto/src/client/stream/data.rs`). There is
   no public API to change the drop reason (only `close_pending` for
   *unaccepted* requests sends DONE). Client code must therefore read to
   the *protocol* boundary (Content-Length / WS close) and treat a
   trailing END-any-reason as EOF — `read_to_end` is unusable.
4. **First connects often get `END MISC`.** A fresh client's first
   `connect()` to a just-published service commonly fails a few times
   (`results/run*-client.log`); retrying every 2 s for ~5–10 s always
   succeeded. Likely stale intro-point entries while the new descriptor
   propagates.

## Onion key persistence (what operators must back up)

- `launch_onion_service` with a `TorClientConfigBuilder::from_directories`
  persistent state dir stores keys under
  `state/keystore/hss/<nickname>/`:
  - `ks_hs_id.ed25519_expanded_private` — **the service identity key**
    (the .onion address derives from it; 456 B, expanded ed25519 private
    key format),
  - `ks_hs_blind_id+*.ed25519_expanded_private`,
    `ks_hs_desc_sign+*.ed25519_private` — per-period blinded/descriptor
    keys (regenerated),
  - `ipts/*` — intro-point keys, `state/hss/<nickname>/` — intro-point
    and replay-log state.
- Restarting with the same `--state-dir` reuses the identity
  (`tor_hsservice: Using existing identity for service nosfry`) →
  identical `.onion`. Verified across **3 restarts**, all runs printed
  `z6wfl72s6jjy25hosj2nrpjzkdxpspjwegsmurwxpjq5kwhbts43t4ad.onion`
  (see `results/run1/2/3/4-relay.log`).

## Synthetic ConnectInfo and limiter collapse

Every onion stream is served with `ConnectInfo(127.0.0.1:0)` — the real
peer is an anonymous rendezvous circuit with nothing to report (we log
"onion stream accepted (peer is a rendezvous circuit)"). Consequences in
`crates/nosfry/src/limiter.rs`:

- `max_connections_per_ip`: **all** onion clients share the single
  `127.0.0.1` bucket — one aggregate cap for every Tor user.
- Per-address rate-limit buckets: all onion traffic rates against
  localhost as one identity.
- Any IP-based blocklist/allowlist is vacuous for onion peers; the real
  discriminator would have to be the client AUTH key instead of IP.

## Commands

```bash
export CARGO_TARGET_DIR=$PWD/../target

cargo build --release --bin baseline                    # feature off
cargo build --release --features tor --bin onion_relay --bin onion_client

../target/release/onion_relay --config relay.toml --state-dir state-relay
../target/release/onion_client <addr>.onion --state-dir state-client [--probe] [--hold N]
```

## Measurements

Machine context (see `results/uptime-*.txt` for every sample):
10-core M-series Mac shared by many agents; load averages ranged
**~67 to ~793** during this session (single-user 6-day uptime).
All timings below are wall-clock on that loaded box.

| measurement | values | notes |
|---|---|---|
| Arti bootstrap, cold state | 9.795 s (relay r1), 11.144 s + 9.039 s (client) | results/run1 |
| Arti bootstrap, warm state | 0.685 / 0.769 / 0.768 / 4.161 / 0.889 / 0.955 / 0.987 / 0.922 / 0.976 / 1.227 s | median ≈ 0.94 s; dir cached |
| launch → status Running | 9.669 / 46.419 / 7.302 / 20.474 s | run2 slowest: uploaded descriptors for two time periods (8/8 HSDirs each) |
| launch → first WS handshake (client pre-bootstrapped, 2 s poll) | ≈ 9.6–10.1 s | client `first_ws_handshake_secs=9.609` started ~0.4 s after launch marker |
| publish → `OK` RTT over onion | run4: p50 654.2 ms, max 727.8 (12 samples) · run5: p50 638.9, max 900.0 (12) | typical ~6-hop onion RTT |
| NIP-11 over onion | `HTTP/1.1 200 OK`, full doc | results/run4-client.log |
| publish + REQ by id | `OK true`, `EVENT`, `EOSE` | event ids in logs |
| relay RSS | 18 336 KB idle w/ service → 19 040 KB with 20 open onion conns (+704 KB) → 18 704 KB after release | `ps -o rss=` |
| baseline idle RSS | 4 320 KB | feature-off binary, `results/rss-baseline.txt` — Arti adds ~14 MB idle |
| binary size (release, stripped) | baseline 4 069 184 B (fresh/cold build; earlier shared-target artifact was 4 168 720) · onion_client 9 253 056 (8.8 MiB) · onion_relay 12 137 152 cold / 11 627 184 earlier shared-target | root profile: cu=1, thin-lto, panic=abort, strip |
| cold release build (`/usr/bin/time -l`, fresh target dir each, `results/cold-build.txt`) | baseline: **93.55 s real / 183.00 user / 16.82 sys** (load 32→26) · tor on, `onion_relay` only: **324.82 s real / 570.31 user / 50.90 sys** (load 26→27) | user+sys ≈ 200 s vs 621 s CPU — tor ≈ 3.1× baseline |
| earlier warm/loaded builds | feature `tor` on (both bins): **43 m 08 s** wall at load ~120–150 · baseline fresh target: **3 m 22.7 s** at load ~96–124 | `results/uptime-baseline-build.txt`; kept for context — not comparable to the cold runs above |
| dependency count (`cargo tree -e normal --prefix none --no-dedupe \| sort -u \| wc -l`) | tor on: **445** · off: **171** | second, deduped command gives same numbers |
| MSRV | arti crates `rust-version = "1.92"` | spike sets rust-version 1.92; workspace toolchain is 1.99 |

### `cargo deny check` (with the repo's `deny.toml`, verbatim output in `results/deny.txt`)

`advisories FAILED, bans FAILED, licenses FAILED, sources ok`.

- advisories: `RUSTSEC-2026-0542` humantime unmaintained (tor-keymgr,
  tor-log-ratelim, tor-netdir, tor-netdoc); `RUSTSEC-2026-0459`
  `libsqlite3-sys` bundled-SQLite CVE-2026-119375 (tor-netdoc,
  tor-persist, tor-protover, tor-rtcompat); `paste` unmaintained;
  `RUSTSEC-2023-0071` rsa Marvin timing attack.
- bans: `error[wildcard]` — the two mandated `nosfry`/`nosfry-core`
  path deps count as wildcard-version deps; inherent to the spike.
- licenses: `async_executors` (Unlicense, via tor-proto) and
  `xxhash-rust` (BSL-1.0, via tor-hsservice → growable-bloom-filter)
  rejected by the repo policy; plus the spike crate itself was
  unlicensed until `license = "MIT OR Apache-2.0"` was added.
- sources: ok. ~45 duplicate-version warnings (expected noise when
  mixing arti 0.48 + the workspace's own dep set).

## Failure log (verbatim)

- `rustls-0.23.46 ... Could not automatically determine the
  process-level CryptoProvider` → fixed by adding `rustls` + `ring` and
  `install_default()`.
- `error: onion connect — tor: operation not supported because Arti
  feature disabled: Rejecting .onion address; feature
  onion-service-client not compiled in` → added the feature.
- `error: Received an END cell with reason MISC` ×4 client runs → root
  causes: (a) early connects raced descriptor propagation (transient,
  probe retries), (b) writes never flushed (`write_all` without
  `flush`), (c) clean close = END(MISC) not EOF.
- `error: read header from client timeout` (relay side) — same root
  cause as (b).

## Processes

Started/stopped during the spike (all confirmed dead at write-up):

| pid | what |
|---|---|
| 81949 | onion_relay run1 (killed) |
| 99490 | onion_relay run2 (killed) |
| 18015 | onion_relay run3 (killed) |
| 29536 | onion_relay run4 (killed) |
| 30352 | onion_client --hold 20 (killed) |
| several | onion_client probe/RTT runs (exit on their own) |

Scratch state under `state-relay/`, `state-client/` (Arti consensus,
guard state, service keys) — left for review, safe to delete.
