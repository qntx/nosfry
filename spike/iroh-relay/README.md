# spike/iroh-relay — nosfry over iroh (QUIC) listener and TCP gateway

Throwaway research spike. Standalone Cargo package (own `Cargo.lock`,
`[workspace]` table — NOT part of the root workspace). Depends on the
real `nosfry` by path and serves every accepted byte stream through the
exact same hyper/axum path as `nosfry`'s TCP listener
(`hyper::server::conn::http1` + `TowerToHyperService` +
`.with_upgrades()` + `ConnectInfo<SocketAddr>` extension).

Two designs evaluated:

- **(i) `iroh_relay_node`** — an iroh endpoint inside the relay process,
  ALPN `nosfry/http1`. Each bidirectional QUIC stream carries one plain
  HTTP/1.1 connection (WebSocket upgrade, NIP-11 GET, NIP-86 all
  unchanged). One process serves TCP + iroh on the same `Server`.
- **(ii) `iroh_gateway`** — a TCP front-end that keeps one cached QUIC
  connection to the node and opens one bi stream per accepted TCP
  connection, copying bytes both ways with proper half-close
  (`tokio::io::copy_bidirectional`). Unmodified Nostr clients just point
  at `ws://127.0.0.1:<gw-port>`.

`iroh_client` is a native iroh dialer for timing: endpoint bind →
connect → WS handshake → publish→OK.

## Identity / limits caveat (same as spike/tor-onion)

Non-TCP streams get a synthetic `ConnectInfo(127.0.0.1:0)` because
nosfry's router requires a `SocketAddr`. Consequence: every iroh client
shares the `127.0.0.1` bucket of `max_connections_per_ip` and the
per-address rate buckets in `crates/nosfry/src/limiter.rs`. The real
remote endpoint id is logged per connection (`CONN open remote=…`) so
identity is not lost — but the per-IP limiter sees them all as one peer.
A production integration would need a peer-identity abstraction (node id
→ limiter key) rather than a socket address.

## Files

```text
spike/iroh-relay/
├── Cargo.toml / Cargo.lock        standalone package, feature `iroh`
├── relay.toml                     nosfry config (TCP :17891, db ./db)
├── conf-gw.toml / conf-tcp.toml   conformance configs (service_url = gateway / TCP)
├── src/lib.rs                     shared hyper serving path + QUIC stream adapter + iroh helpers
├── src/bin/
│   ├── baseline.rs                TCP-only relay, feature OFF
│   ├── iroh_relay_node.rs         TCP + iroh endpoint, persistent key, ALPN nosfry/http1
│   ├── iroh_gateway.rs            TCP→iroh bi-stream forwarder, cached upstream conn
│   └── iroh_client.rs             native dialer: connect/handshake/publish timings
└── results/                       raw logs and measurements
```

## Locked versions (Cargo.lock)

| crate | version | notes |
|---|---|---|
| iroh | 1.4.1 | `=1.4.1` (1.4.2/1.5.0 published 2026-11-19, outside the 7-day window) |
| iroh-base / iroh-dns / iroh-relay | 1.4.1 | pinned to keep the 1.4.x line (iroh's internal reqs are caret) |
| noq / noq-proto / noq-udp | 1.4.0 | iroh 1.4.1's QUIC stack (there is no noq 1.4.1) |
| tokio-tungstenite | 0.30.0 | client WS handshake |

The local test relay is the `iroh-relay` crate's own binary built with
its `server` feature, installed with:

```bash
CARGO_TARGET_DIR=spike/target/srv \
cargo install iroh-relay --version "=1.4.1" --features server --locked \
    --root spike/target/srv-root
spike/target/srv-root/bin/iroh-relay --dev          # plain-HTTP dev mode, port 3340
```

## Key APIs used (iroh 1.4.1)

- Endpoint: `Endpoint::builder(presets::N0).secret_key(k).alpns([ALPN]).bind()`
- Custom relay only: `.relay_mode(RelayMode::custom([url]))`
- **Relay-only** (the flag the evaluation asked for): **`.clear_ip_transports()`** —
  removes all IP transports so only relay paths exist.
- **No relay at all** (force direct): `.relay_mode(RelayMode::Disabled)` —
  added as `--no-relay` on client/gateway for the forced-direct tests.
- Path inspection: `conn.paths()` → each path `remote=…`, `is_ip()` /
  `is_relay()`, `is_selected()`. Logged per connect as
  `PATH i remote=<addr> kind=<ip|relay> selected=<bool>`.
- Identity: `iroh::SecretKey` persisted as 32 raw bytes, mode 0600.
- Tickets: `ticket:<hex>` = hex of the `EndpointAddr` serde-JSON; plain
  z32 endpoint ids also parse (resolved via pkarr/DNS discovery).

## Results

Machine load context: shared 10-core box, load averages ranged
~37–190 during these runs (see `results/uptime-*.txt`). All numbers are
wall-clock on a heavily loaded host; treat absolute values as upper
bounds.

### Connection path and timings (iroh_client, `--reps 5`)

| path | connect ms | WS handshake ms | publish→OK RTT | evidence |
|---|---|---|---|---|
| **direct loopback** (`--no-relay`, ticket `127.0.0.1:<port>`) | 0.7–7.4 | 0.4–1.3 | p50 4.9–14.9 ms, max 9.5–24.5 ms | `client-forced-direct.log`; `PATH remote=ip:127.0.0.1 kind=ip selected=true` |
| **direct, LAN IP** (`--no-relay`, ticket `192.168.31.22:<port>`) | **timed out** (30 s) | — | — | macOS Application Firewall drops inbound UDP, see below |
| **default mode** (n0 ticket with relay+IP addrs) | 1326–1476 (3/6 runs timed out entirely) | ~700 | — | `client-direct.log`; **always picked `kind=relay` euc1**, never an IP path |
| **local iroh-relay --dev** (`--relay-only --relay-url http://127.0.0.1:3340`) | 0.7–27.8 | ~1–5 | p50 8.8–10.8 ms, max 52–60 ms | `client-localrelay.log`; all paths `kind=relay http://127.0.0.1:3340` |
| **n0 public relay** (`--relay-only`, default map) | 520–1390 (first ~1.1–1.4 s) | 520–760 | p50 522–525 ms, max 541–571 ms | `client-n0relay.log`; relay `euc1-1.relay.n0.iroh.link` |
| **Q.local → n0 relay** (cross-machine, remote binary) | 631–703 warm, 1801 cold | 750–800 | p50 692 ms, max 717 ms | `client-qlocal-relay.log`; relay `use1-1` |

Notes:

- Direct path **does work and is very fast** when reachable: total
  connect+handshake ≈ 1–7 ms on loopback, indistinguishable from raw TCP.
- **Inbound UDP is blocked on this host by the macOS Application
  Firewall** (`socketfilterfw --getglobalstate` → `State = 1`; unsigned
  spike binaries are silently dropped). Both this machine and Q.local
  have it enabled. Consequences measured:
  - dialing the node's LAN IP `192.168.31.22:port` from the SAME machine
    timed out with `--no-relay`; dialing `127.0.0.1:port` connected in
    ~1 ms.
  - Q.local (`192.168.31.228`, same /24, ping 8.7 ms) also timed out
    direct to this host but connected fine through the n0 public relay
    (~690 ms RTT). So on these Macs, iroh effectively always lands on a
    relay path unless the firewall is opened — the "direct" benefit here
    is loopback-only.
  - In default mode (relay + IP addrs both advertised) iroh always
    selected the relay path; it never even showed an established IP path
    in `conn.paths()`. With a reachable direct addr the first connects
    still went through relay — path selection favours whatever
    establishes first.
- Relay-only via a LOCAL iroh-relay adds almost nothing over direct
  (p50 ~9–11 ms vs ~5–7 ms) — the relay is a WebSocket on loopback.
- Public-relay mode costs ~0.5 s per connection and ~0.5 s per
  publish→OK round trip from this host (nearest n0 relay selected was
  `euc1`/`use1`, i.e. WAN RTT × 2 inside the relay path).

### Conformance (crates/nosfry-conformance/run.sh remote, 30 tests)

Same node process, three access paths — all green:

| path | result |
|---|---|
| plain TCP `ws://127.0.0.1:17891` (control) | 30 passed / 0 failed (3.13 s) |
| gateway → direct QUIC stream (`ws://127.0.0.1:17892`) | 30 passed / 0 failed (3.13 s) |
| gateway → local iroh-relay relay-only (`ws://127.0.0.1:17892`) | 30 passed / 0 failed (3.13 s) |

The node's config used the conformance `profile.toml` plus the
`[db]`/`[relay]`/`[relay.write_policy]` stanza `run.sh native` appends,
with `service_url` set to the gateway URL for the gateway runs (AUTH
relay-tag matching includes the port — `crates/nosfry-core/src/url.rs`).

### Fanout benchmark (bench/nosfry-bench, release, `--pid` = node)

50 broadcast subscribers, 600 events at 20 events/s (30 s, 30 000
expected deliveries). Load ~105–131 during the runs.

| path | delivered | latency p50 | latency p99 | latency max | node CPU (30 s) | gateway CPU |
|---|---|---|---|---|---|---|
| TCP → node | 30 000 / 30 000 | 8.2 ms | 48.4 ms | 86.6 ms | 1.02 s | — |
| GW → direct QUIC | 30 000 / 30 000 | 8.8 ms | 21.7 ms | 72.7 ms | 1.68 s | ~1.02 s |
| GW → local relay | 30 000 / 30 000 | 8.9 ms | 62.0 ms | — | 1.44 s | ~0.77 s |

Full JSON in `results/fanout-*.txt`. The gateway costs ~0.5 ms of median
delivery latency and roughly one CPU-second per 30 k proxied events on
this loaded box — i.e. byte-copying is measurable in CPU, not in
delivery latency at this rate.

### Idle RSS / binary size / build

| binary | size (bytes) | idle RSS |
|---|---|---|
| `baseline` (TCP only, feature OFF) | 4 069 184 | 4 256 KB |
| `iroh_relay_node` (TCP + iroh) | 11 635 680 (cold build identical) | 20 160–20 208 KB |
| `iroh_gateway` | 9 002 896 | — |
| `iroh_client` | 10 427 968 | — |

iroh endpoint adds ~16 MB RSS and ~7.6 MB binary over the TCP-only
baseline. The iroh-relay test-server binary (server feature, installed
to `spike/target/srv-root`) is not part of the spike crate.

Build times: cold release build of `iroh_relay_node` with `--features
iroh` into a fresh target dir (`/usr/bin/time -l`,
`results/cold-build.txt`): **487.95 s real / 482.98 user / 30.90 sys**
(load 26→57, peak cargo RSS 1.14 GB). For comparison on the same
day/machine the tor-onion spike's cold builds were: feature-off
baseline 93.55 s real / 183.00 user / 16.82 sys; `tor` feature-on
`onion_relay` 324.82 s real / 570.31 user / 50.90 sys — i.e. iroh costs
≈ 314 s of extra CPU over the same baseline, tor ≈ 421 s.
Earlier warm/loaded runs (not comparable): first feature-on build
9 m 38.5 s wall at load 41–96; `baseline` 1 m 33 s; incremental ~20 s.

### Dependencies

`cargo tree -e normal` unique crate count (see `results/deps.txt`):

- feature OFF (baseline): **171**
- feature ON (`--features iroh`): **317** (+146)

### cargo deny

`cargo deny --config ../../deny.toml --manifest-path Cargo.toml check`
(cargo-deny 0.20.2; the `--config` flag is global and must precede the
`check` subcommand):

```text
advisories FAILED, bans FAILED, licenses FAILED, sources ok
```

(full output: `results/deny.txt`)

- advisories: `chrono` unmaintained RUSTSEC-2026-0543 (via
  `wmi`←`netwatch`←`iroh` — Windows-only path, present in the macOS lock
  anyway) and `paste` unmaintained RUSTSEC-2024-0436.
- licenses: `async_io_stream`, `pharos`, `ws_stream_wasm` (Unlicense,
  all via `iroh-relay`'s wasm WebSocket client) are not in the root
  allow-list; the spike package itself needed an explicit
  `license = "MIT OR Apache-2.0"` (added after this run).
- bans: duplicate crates (`thiserror` 1+2, `hashbrown`, `base64`, …),
  wildcard `nosfry`/`nosfry-core` path deps.
- sources ok.

### MSRV

`iroh`/`iroh-base`/`iroh-dns`/`iroh-relay` 1.4.1 declare
`rust-version = "1.91"`; `noq` 1.4.0 declares 1.88 (`results/msrv.txt`).
The spike crate declares `rust-version = "1.91"`.

## dumbpipe 0.40.2 as an alternative gateway (investigated, not used)

Source: `~/.cargo/registry/src/…/dumbpipe-0.40.2`.

- ALPN is `b"DUMBPIPEV0"` (`dumbpipe::ALPN`).
- In its default mode the CLI writes a `dumbpipe::HANDSHAKE` prologue on
  every accepted connection before piping bytes. With a **custom ALPN**
  (`--custom-alpn`) it does NOT write the handshake — byte-for-byte
  proxying is then the caller's protocol.
- Conclusion: dumbpipe *can* transparently forward a custom-ALPN iroh
  stream to TCP (design ii) since the remote side just sees the stream
  bytes — but it always terminates one QUIC stream per TCP conn the same
  way our 60-line gateway does, gives no control over endpoint
  persistence/tickets output, and ships a full CLI surface we don't
  need. The spike gateway is already trivial; dumbpipe adds a dep for no
  capability we lack. Not used.

## Exact commands (reproduce)

```bash
export CARGO_TARGET_DIR=/Users/xu/Desktop/qntx/nosfry-wt/p2p/spike/target

# build
cd spike/iroh-relay
cargo build --release --features iroh \
    --bin iroh_relay_node --bin iroh_gateway --bin iroh_client
cargo build --release --bin baseline

# node (TCP :17891 + iroh, persistent key)
../target/release/iroh_relay_node --config relay.toml --key node-key.secret
# node relay-only via local dev relay
../target/release/iroh_relay_node --config relay.toml --key node-key.secret \
    --relay-only --relay-url http://127.0.0.1:3340

# gateway direct (design ii)
../target/release/iroh_gateway 'ticket:<hex>' --listen 127.0.0.1:17892 --no-relay
# gateway via local relay
../target/release/iroh_gateway 'ticket:<hex>' --listen 127.0.0.1:17892 \
    --relay-only --relay-url http://127.0.0.1:3340

# native client
../target/release/iroh_client 'ticket:<hex>' --no-relay --reps 5 --samples 12
../target/release/iroh_client 'ticket:<hex>' --relay-only --relay-url http://127.0.0.1:3340

# local test relay
../target/srv-root/bin/iroh-relay --dev     # :3340

# conformance
NOSFRY_URL=ws://127.0.0.1:17892 ../../crates/nosfry-conformance/run.sh remote

# fanout
../target/bench/release/nosfry-bench fanout --url ws://127.0.0.1:17892 \
    --subs 50 --events 600 --rate 20 --pid <node-pid> --label gw-direct
```

## Deviations / failures

- **LAN direct path impossible on this host** (macOS Application
  Firewall enabled, no sudo to open): cross-machine direct between
  Q.local and this host could not be established; verified blocked UDP
  with `--no-relay` timing out both same-host (LAN IP) and remote
  (Q.local → `192.168.31.22`). Loopback direct verified instead.
- Default-mode connects timed out on 3/6 runs (n0 relay reachability
  under heavy load); relay-only runs succeeded 10/10.
- Q.local runs used the prebuilt release binaries over SSH
  (`/tmp/nosfry-spike`, deleted afterwards) instead of a remote build —
  zero remote build artifacts.
- The `Endpoint dropped without calling Endpoint::close` ERROR line on
  client exit is an iroh internal warning (the spike exits after the
  last rep); harmless.
- First curl to the gateway raced upstream connect and returned empty;
  retry served NIP-11. The gateway does not queue until the upstream
  handshake finishes — a production gateway would wait/retry.
- Negentropy sync binary: not implemented (out of time); conformance
  suite already exercises NEG over all three paths
  (`negentropy_converges_and_closes` passed on each).

## Processes started & stopped

| process | purpose | stopped |
|---|---|---|
| `iroh_relay_node` (several PIDs) | node for all experiments | yes (kill) |
| `iroh_gateway` (several PIDs) | gateway for conformance/fanout | yes (kill) |
| `iroh_client` (many) | timing runs | exits itself |
| `iroh-relay --dev` (PID 36209) | local test relay :3340 | yes (kill) |
| `baseline` | idle RSS measure | yes (kill) |
| `nosfry-bench fanout` ×3 | benchmark | exits itself |
| `cargo test -p nosfry-conformance` ×3 | suite | exits itself |
| Q.local `/tmp/nosfry-spike` | remote binaries | deleted |
