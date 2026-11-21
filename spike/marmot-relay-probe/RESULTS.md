# nosfry × Marmot relay compatibility — spike results

Black-box evidence for how nosfry (native and Workers editions) handles
Marmot/MLS-over-Nostr traffic: White Noise `wn`/`wnd` interop scenarios
plus a standalone protocol probe. No nosfry production code was changed.

## Versions

| component | value |
| --- | --- |
| nosfry commit | `0d1b786065626df57146768041a30a05217af1f8` (branch `research/blossom-marmot`) |
| nosfry version | `0.3.0` |
| rustc / cargo | `rustc 1.99.0 (b940084d7 2026-09-28)` / `cargo 1.99.0`; interop suite pinned to `1.99.1` via its `rust-toolchain.toml` |
| marmot repo | `4080d8c91e326b5f53a525596173c612d1d44d5d` (private `--shared` clone under `3rdparty/marmot`) |
| marmot spec pin | `f825024f7eb92157d12a0b8985bc6c5db5531d6d` |
| wn / wnd | `wn 0.17.0`, built from `marmot-protocol/mdk` rev `4df811aea99269b437a6023be9446a5141e93cbe` (tag `v0.17.0`) via `cargo install --locked --root 3rdparty/wn wn-cli` (build took 127m under shared-machine load) |
| wrangler | `4.150.0` via `npx`; `worker-build 0.8.7`; node `v26.13.1` |
| strfry | not run — no binary on this host (`which strfry` empty); the only copy lives inside the Linux bench image (`bench/linux/strfry-pinned.sh` execs `/bench/strfry-1.1.3/strfry` under `taskset`) and no bench image is present (`docker images` clean) |

## Build

```sh
cd /Users/xu/Desktop/qntx/nosfry-wt/blossom-marmot
cargo build --release -p nosfry
```

Artifact: `target/release/nosfry`, 4,286,976 bytes (2026-11-22 00:07 local).
`nosfry --version` → `nosfry 0.3.0`.

## Commands used

Interop (per run, from `3rdparty/marmot/crates/interop`):

```sh
WN_BIN=<repo>/3rdparty/wn/bin/wn \
WND_BIN=<repo>/3rdparty/wn/bin/wnd \
INTEROP_RELAY_URL=ws://127.0.0.1:<port> \   # unset for run A (in-process relay)
cargo test --release -- --ignored --test-threads=1 --nocapture
```

Relay launch (per config, from the repo root):

```sh
RUST_LOG=info,nosfry::ingest=debug \
  ./target/release/nosfry relay --config spike/marmot-relay-probe/configs/<cfg>.toml
```

Workers edition (from `crates/nosfry-worker`):

```sh
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" \
npx --yes wrangler@4.150.0 dev --local --port <port> \
  --persist-to /tmp/nosfry-marmot/<dir> \
  --var "NOSFRY_CONFIG:$(cat <cfg>.toml)"
```

Probe:

```sh
spike/marmot-relay-probe/target/release/marmot-relay-probe \
  ws://127.0.0.1:<port> [--auth] [--only P1,P9] --out logs/<name>.json
```

## Harness patch (interop → external relay + NIP-42)

`interop-external-relay.patch` (also applied in the ignored
`3rdparty/marmot` clone; the canonical `/Users/xu/Desktop/qntx/marmot`
checkout was not touched). Changes:

- `crates/interop/tests/support/mod.rs`: when `INTEROP_RELAY_URL` is set,
  `rig()` skips `LocalRelay` and the NIP-11 front and hands that URL to
  the client, `wnd` and mk-core sessions. `Rig.relay` became
  `Option<LocalRelay>`; `authed_clients: Mutex<HashMap<String, Client>>`
  caches per-pubkey `nostr_sdk::Client`s built with `SignerAuthenticator`
  so restricted reads are retried after NIP-42; `fetch_welcomes` now
  takes the recipient `&LocalSigner` and fetches through the
  authenticated client; a `fetch_on` helper shares the fetch logic.
- `crates/interop/tests/wn.rs`, `tests/bridge.rs`: `rig.relay.shutdown()`
  calls guarded by `if let Some(relay)`; welcome fetches pass the signer.
- `crates/mk-core/src/testing.rs`: `LocalSigner::keys()` getter so the
  rig can build `SignerAuthenticator` from the same `Keys`.

Reason for the AUTH half of the patch: with `service_url` set, nosfry
lazily challenges restricted-kind REQs (`CLOSED auth-required` + `AUTH`
frame); without answering, welcome fetches get nothing.

## Interop scenario matrix

Scenarios 1–6 live in `tests/wn.rs`, scenario 7 in `tests/bridge.rs`.

| run | relay | config | S1 | S2 | S3 | S4 | S5 | S6 | S7 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A | in-process `LocalRelay` + NIP-11 front | upstream defaults | PASS 14.1s | PASS 13.7s | PASS 27.4s | PASS 22.7s | PASS 17.9s | PASS 18.0s | PASS 16.4s |
| B | nosfry native | `native-default.toml` (`service_url` unset) | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| C | nosfry native | `native-auth.toml` (AUTH on) | PASS 28.3s | PASS 26.7s | FAIL | PASS 34.9s | PASS 13.3s | PASS 14.4s | PASS 39.1s |
| D | nosfry native | `native-auth-ratelimit.toml` (C + rate limits only) | PASS 22.3s | PASS 16.3s | PASS 23.2s | PASS 24.6s | PASS 15.1s | PASS 13.7s | PASS 18.3s |
| E | nosfry-worker (wrangler dev --local) | `worker-auth.toml` | PASS 7.2s | PASS 8.3s | FAIL | PASS 17.6s | PASS 7.7s | PASS 7.5s | PASS 7.3s |
| E′ | nosfry-worker | `worker-auth-raised.toml` | PASS 19.3s | PASS 25.5s | PASS 54.7s | PASS 47.9s | PASS 27.8s | PASS 24.4s | PASS 19.2s |

Run B failure — all scenarios die at welcome delivery (`timeout waiting
for wn invite appears` / `timeout waiting for welcome join`). Relay log
(578 identical lines):

```
DEBUG nosfry::ingest: sent conn=8 frame=["CLOSED","marmot:inbox:1845c6ec…","restricted: requested kinds are not served"]
```

`restricted_read_kinds` defaults to `[4, 1059]`; with `service_url` empty
the `AuthRules` gate is disabled so gift wraps are stored but never
served — every publish got `OK true` (63 of them, zero `OK false`).

Run C/E failure — only scenario 3. `s3: mk sent 475 in 2.9s` (~164 ev/s
on one connection) hit `events_per_second = 20`, `events_burst = 100`;
nosfry answered 317 × `OK false` and `wnd` saw only 183/500 events
(158 mk + 25 wn; the wait timed out at `last: 158`):

```
DEBUG nosfry::ingest: sent conn=37 frame=["OK","67d13488…",false,"rate-limited: slow down"]
```

Run D isolated the fix: same config as C plus **rate limits only**
(`max_filter_limit` left at the default 500 — `wnd`'s `limit`-based
history sweep still works because the advertised `max_limit` is only a
page size). Zero `rate-limited` frames in the D relay log; S3 ingested
500/500. E′ confirms the same on the Workers edition.

## Probe matrix

`spike/marmot-relay-probe` (own workspace, own `Cargo.lock`; deps all
published well before 2026-11-14): `secp256k1 0.33.1`, `sha2 0.11.1`,
`serde_json 1.0.154`, `tokio 1.54`, `yawc 0.5.0`, `futures-util 0.3.34`,
`faster-hex 1.0.0`, `getrandom 0.4.3`, `base64 0.23.1`. Full JSON per
run in `logs/probe-*.json`.

| probe | native default (7801) | native AUTH (7802) | worker AUTH (7811) | native AUTH+2 MiB (7804) | worker AUTH+2 MiB (7813) |
| --- | --- | --- | --- | --- | --- |
| P1 nips | `[1,9,11,40,45,62,70,77]` | `[1,9,11,40,42,45,62,70,77]` | same | same (+42) | same |
| P1 max_limit / max_msg | 500 / 131072 | 500 / 131072 | 500 / 131072 | 500 / 2097168 | 500 / 2097168 |
| P2a 200 back-to-back | 100 ok / 100 `rate-limited` | 100 / 100 | 103 / 97 | — | — |
| P2b 200 @ 50/s | 189 ok / 11 | 188 / 12 | 189 / 11 | — | — |
| P3 order/limits | created_at desc, id asc; repeat identical; `limit:100` → newest 100; `since=T` inclusive | identical | identical | — | — |
| P4 live | 100/100, arrival order (not canonical) | same | same | — | — |
| P5 unauth 1059 REQ | `CLOSED "restricted: requested kinds are not served"` | `AUTH` frame + `CLOSED "auth-required: requested filter requires authentication"` | same as native AUTH | — | — |
| P5 AUTH recipient / stranger | n/a (no auth) | 1 event / 0 events | 1 / 0 | — | — |
| P5 mixed REQ (restricted+open) | only kind-445 served, no CLOSED | same | same | — | — |
| P6 30443 slot | newer wins; tie → lower id; late higher-id → `OK false "duplicate: have a newer version"`; `a`+`k` slot delete empties slot; republish ok; `e`+`k` deletes one | identical | identical | — | — |
| P7 10002/10050 | replaceable, newest served | same | same | — | — |
| P8 expiration | expired → `OK false "invalid: event has expired"`; +3 s stored+served; gone after 6 s | same | same | — | — |
| P9 ≤64 KiB | `OK true` | `OK true` | `OK true` | `OK true` | `OK true` |
| P9 70 KiB / 120 KiB | `OK false "invalid: event too large (71669 > 65536 bytes)"` | same | same | `OK true` | `OK true` |
| P9 200 KiB | connection closed, **no OK** | same | same | `OK true` | `OK true` |
| P9 ~2.0 MB / 2 MiB | send failed (conn dead) | send failed | no response (closed) | `OK true` both kinds | `OK true` both kinds |

### P9 size-ladder detail (wire bytes → outcome)

| serialized EVENT frame | native/worker default | 2 MiB config |
| --- | --- | --- |
| ~61,440 B | `OK true` | `OK true` |
| ~71,680 B | `OK false invalid: event too large (> 65536 bytes)` | `OK true` |
| ~122,880 B | `OK false invalid: event too large` | `OK true` |
| ~204,800 B | connection dropped silently (exceeds `max_websocket_payload_size` 131072 — no OK, no NOTICE) | `OK true` |
| ~2,000,000 B | connection dropped | `OK true` |
| ~2,097,152 B | connection dropped | `OK true` |

The two limits act at different layers: `events.max_event_size`
(65,536 default) produces a graceful `OK false`; oversized WS frames hit
`max_websocket_payload_size` (131,072 default) and the relay just
closes the connection — a client sees "no response", not a rejection
reason. Payload cap boundary measured: the check is on raw frame bytes
with `len > max` rejected — cap 2,097,152 accepted a 2,097,151-byte
frame and reset a 2,097,154-byte one. The `["EVENT",` envelope adds 10
bytes, so the smallest `max_websocket_payload_size` that admits any
2 MiB event is **max_event_size + 10 = 2,097,162**; configs here use
2,097,168 for a few bytes of slack. No max-size validation errors at
startup on either edition (both boot clean, NIP-11 then advertises
`max_message_length: 2097168`).

Workers edition at 2 MiB: zero errors in the wrangler log — the
Durable-Object SQLite store accepted the rows; no row/string-size limit
encountered.

## NIP-01 ordering text (github.com/nostr-protocol/nips 01.md)

- L101: "In case of replaceable events with the same timestamp, the
  event with the lowest id (first in lexical order) should be retained,
  and the other discarded."
- L145: "In short, an event matches a filter if
  `since <= created_at <= until` holds."
- L151: "When `limit: n` is present it is assumed that the events
  returned in the initial query will be the last `n` events ordered by
  the `created_at`. Newer events should appear first, and in the case of
  ties the event with the lowest id (first in lexical order) should be
  first."

nosfry matches all three (P3, P6).

## Minimal config for Marmot traffic

```toml
[relay]
service_url = "wss://<your-relay-host>"   # enables NIP-42; without it
                                         # kind 1059 is stored but
                                         # never served (welcome loss)

[relay.rate_limits]
events_per_second    = 200    # defaults 20/s burst 100 kill group
events_burst         = 1000   # bursts: scenario 3 needed >164 ev/s
ip_events_per_second = 2000   # same for the shared-IP dimension
ip_events_burst      = 10000
# reqs_* only needed if REQ bursts matter; raised alongside here.

# Marmot spec (transports/nostr.md, rev 162c61b): relays SHOULD accept
# ≥ 2 MiB serialized events (gift-wrapped Welcomes carry the ratchet
# tree; 64 KiB caps a Welcome at ~56 members).
[events]
max_event_size = 2097152

[relay]
max_websocket_payload_size = 2097168  # smallest that fits is
                                      # max_event_size + 10 (EVENT
                                      # envelope); see P9 boundary
```

Not needed: `max_filter_limit` raise (default 500 is a page size, `wnd`
sweeps fine); `restricted_read_kinds` unchanged (1059 stays restricted —
that is what you want: served only to authenticated involved keys).

## Surprising / noteworthy findings

1. AUTH is off by default and silently breaks welcomes: kind 1059 is
   `restricted_read_kinds` by default, so a stock nosfry stores gift
   wraps but never serves them — Marmot groups look like they deliver
   nothing. One `service_url` line fixes it (lazy NIP-42: only
   restricted REQs get challenged).
2. `restrict_read_to_involved` (default on) means a stranger
   authenticated key still gets zero 1059s — exactly the privacy the
   spec wants, verified live (P5).
3. Mixed-filter REQ: `{"kinds":[1059],…} + {"kinds":[445],…}` serves
   only the unrestricted half — no CLOSED. A client that bundles filter
   sets must notice the missing half itself.
4. Oversized frames die silently: >`max_websocket_payload_size` → TCP
   close with no OK/NOTICE, while 64 KiB < event ≤ payload gets a clean
   `invalid: event too large`. Clients debugging "welcome lost" against
   a default relay see a disconnect, not a reason.
5. Live EVENT delivery is arrival order, not canonical order — fine per
   NIP-01 (only the initial-query order is specified), but a client
   asserting created_at-desc on live traffic would misjudge the relay.
6. `duplicate: have a newer version` on the losing same-timestamp
   KeyPackage publish — correct NIP-01 tie-breaking (lower id wins), and
   it is an `OK false`, so a client that treats OK=false as "retry"
   would loop forever on a lost tie.
7. The in-process `LocalRelay` harness itself runs raised limits
   (`max_reqs 500`, `notes_per_minute` 1e6, `max_filter_limit` 10000) —
   the stock nosfry defaults are much tighter; the B/C failures are
   genuine default-config behavior, not test-harness artifacts.
8. The Workers edition is behavior-identical across every probe
   (AUTH gating, replaceable/tie semantics, expiration, size ladder,
   rate-limit wording) — the conformance claims hold for Marmot shapes.

## Raw logs / artifacts

All under `spike/marmot-relay-probe/logs/`:

- `interop-A-baseline.log`, `interop-B-native-default.log`,
  `interop-C-native-auth.log`, `interop-D-native-ratelimit.log`,
  `interop-D1-ratelimit-s3.log`, `interop-E-worker-auth.log`,
  `interop-E-raised-s3.log`, `interop-E-worker-raised.log` — cargo test
  stdout incl. `SCENARIO-n PASS`/panic lines.
- `nosfry-B-default.log` (interop B **and** the default-config probe —
  both ran against the same instance/port), `nosfry-C-auth.log`
  (interop C + auth probe + P8/P9 frames), `nosfry-D-raised.log`,
  `nosfry-D1-ratelimit.log`, `nosfry-2mib.log`,
  `nosfry-2mib-boundary.log` — `RUST_LOG=info,nosfry::ingest=debug`
  frame-level relay logs (every OK/CLOSED sent).
- `worker-E-auth.log`, `worker-E-raised.log`, `worker-probe-auth.log`,
  `worker-probe-2mib.log` — wrangler output (worker logs HTTP upgrades
  only; per-frame evidence for the worker is client-captured in the
  probe JSON — the worker emits no per-frame logging).
- `probe-{native-default,native-auth,native-2mib,native-2mib-boundary,worker-auth,worker-2mib}.json`
  — full structured probe output; `.log` siblings hold stdout.
- `crates/interop/target/wn-logs/` inside the clone held only empty
  `wnd.{out,err}.log` stubs (0 bytes) — nothing to archive.

Build artifacts kept for reruns:

- `target/` (nosfry workspace): 710 MB
- `3rdparty/wn-target/`: 1.7 GB; `3rdparty/wn/`: 122 MB
- `3rdparty/marmot/`: 675 MB (incl. interop `target/` 669 MB)
- `spike/marmot-relay-probe/target/`: 257 MB
- `crates/nosfry-worker/build/` wasm pkg + wrangler persist dirs under
  `/tmp/nosfry-marmot/` (ephemeral)
