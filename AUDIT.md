# Security audit scope and code guide

Commit under review: 1ca44e7b25254ee9a732136b13a8014977006b37

## Purpose and deliverables

This document scopes a security and correctness audit of nosfry, a Nostr
relay with two editions: a native server on LMDB, and a Cloudflare Workers
edition on Durable Object SQLite. Both share one sans-I/O protocol core. The
engagement covers:

- the protocol core;
- both storage engines;
- both server shells;
- the administration CLI;
- the black-box conformance suite;
- the build, release, and container pipeline that produces published
  artifacts.

A relay is a public, unauthenticated, long-lived network service that stores
and serves other people's data. Correctness failures are therefore in scope
alongside classic vulnerabilities:

- a lost acknowledged write;
- an event served to a reader who must not see it;
- an event delivered twice or not at all;
- a deletion that does not hold.

We ask for:

- **Findings.** Each with a severity rating (Critical / High / Medium / Low /
  Informational), the affected files and lines, the root cause, and a proof of
  concept or a concrete exploit or failure scenario where possible.
- **Property assessment.** For every property claimed below: verified,
  violated, or partially holds, with evidence.
- **Protocol assessment.** Divergences from the NIP texts and from strfry
  1.1.3 that are not listed under "Known limitations and accepted risks" or in
  the compatibility table.
- **Fix review** of the remediations we propose in response to findings.

## System overview

The workspace produces three published crates, one container image, release
binaries, and one Workers bundle:

- `crates/nosfry-core` (published). Sans-I/O protocol core:
  - strict NIP-01 parsing, the id hash, and BIP-340 verification;
  - the filter compiler and matcher;
  - the per-connection `Session` state machine;
  - the live-subscription index (`Monitors`);
  - NIP-11, NIP-42, NIP-45, NIP-77, NIP-86, and NIP-98 logic;
  - the strfry write-policy wire format;
  - the HTML landing page and `NodeInfo`.

  It has no async code, no I/O, no clock (time arrives as `now`), and no
  randomness. It builds for `wasm32-unknown-unknown` and is
  `#![forbid(unsafe_code)]`.
- `crates/nosfry-lmdb` (published). The native event store on LMDB through
  `heed`: writes, deletion, expiration, vanish, NIP-86 moderation tables,
  time-sliced scans (`Scan`), counts (`CountScan`), and negentropy storage
  sealing. Its only `unsafe` is the two `heed` calls in `Store::open`.
- `crates/nosfry` (published, binary `nosfry`). The native relay:
  - an axum HTTP surface, with WebSockets via `yawc` and permessage-deflate;
  - one Tokio task per connection;
  - one writer thread, M monitor-shard threads, and N reader threads;
  - SIGHUP reload, NIP-86 management, the write-policy plugin bridge,
    Prometheus metrics, and the administration CLI (`import`, `export`,
    `scan`, `delete`, `compact`).
- `crates/nosfry-sql` (internal). The SQL event store for the Workers
  edition. It runs on any synchronous `Executor`: Durable Object `SqlStorage`
  in production, `rusqlite` in tests. Write and scan semantics are specified
  to equal `nosfry-lmdb`. `#![forbid(unsafe_code)]`.
- `crates/nosfry-worker` (internal, deployed as a Worker). One Durable Object
  (`RelayObject`, instance name `relay`) owns every connection through the
  hibernation WebSocket API. Per-socket attachments and a `subs` table survive
  eviction. A `POLICY` service binding replaces the plugin process. The
  host-testable logic lives in `relay.rs`; `glue.rs` is the workers-rs shell.
  `#![forbid(unsafe_code)]`.
- `crates/nosfry-testkit` (internal, tests only). A model-based differential
  driver over both stores.
- `crates/nosfry-conformance` (internal, tests only). A black-box protocol
  suite run against both editions (`run.sh native|worker`).
- `bench/nosfry-bench`, `bench/r7`. The load generator and benchmark
  orchestrator. They are out of scope except as reproduction tools.

Layering is one-directional:

- `nosfry-core` is the leaf.
- `nosfry-lmdb` and `nosfry-sql` depend on it.
- `nosfry` composes core and LMDB; `nosfry-worker` composes core and SQL.
- No store depends on a shell, and the core depends on no store; the
  `nosfry-core::store` module holds only shared write-outcome types.

Trust boundaries:

1. **Internet ↔ HTTP surface** (`crates/nosfry/src/http.rs`,
   `crates/nosfry-worker/src/glue.rs`). This covers WebSocket upgrades, NIP-11
   and the landing page (`GET /`), `NodeInfo`, the NIP-86 RPC (`POST /`), CORS
   preflight, and `/metrics` when enabled.
2. **Client ↔ `Session`.** Every WebSocket text frame is untrusted input
   (`crates/nosfry-core/src/session.rs`).
3. **Connection task ↔ writer / shard / reader threads.** These are bounded
   in-process channels (`crates/nosfry/src/channels.rs`). They are trusted, but
   their bounds and ordering are security properties.
4. **Relay ↔ write-policy plugin.** A child process (`/bin/sh -c <plugin>`)
   speaking JSON lines on stdio (`crates/nosfry/src/policy.rs`), or a Workers
   service binding over HTTP. The plugin is operator-supplied and trusted to
   decide; it is not trusted to be well-formed, timely, or alive.
5. **Relay ↔ storage.** LMDB files on local disk, or Durable Object SQLite.
   The database is trusted at rest, but crash consistency and the scan/live
   boundary are in scope.
6. **Reverse proxy ↔ relay.** The proxy terminates TLS. `relay.real_ip_header`
   transfers trust for the client address to the proxy.
7. **Operator ↔ configuration and CLI.** `nosfry.toml`, SIGHUP reloads,
   `import --no-verify`, `delete`, and `compact` are trusted, but must fail
   closed on invalid input.
8. **Cloudflare runtime ↔ Durable Object.** Hibernation, eviction,
   `CF-Connecting-IP`, and platform limits (CPU time, SQL statement limits,
   attachment size).

## Assets

- **Acknowledged events.** An event answered `["OK", id, true, …]` must
  survive a crash, unless the answer carried the `duplicate:` prefix.
- **Read confidentiality of restricted kinds.** NIP-42 `restricted_read_kinds`
  (DMs and NIP-59 gift wraps by default, kinds 4 and 1059) and
  `restrict_read_to_involved` must be served only
  to authorized readers, by both stored scans and live delivery.
- **Deletion and vanish guarantees.**
  - A NIP-09 deletion by the author removes the targets and blocks their
    re-publication.
  - A NIP-62 request to vanish removes the author's history up to its
    `created_at` and blocks older re-publication.
  - NIP-86 bans block new writes and hide matching stored content at
    read time; `banevent` deletes the stored event.
- **Integrity of stored events.** Only events with a valid id and a valid
  BIP-340 signature enter storage through the network path.
- **Admin authority.** Only configured `[relay.management] admins` may issue
  NIP-86 calls.
- **Availability.** Process memory, file descriptors, CPU, disk, LMDB readers,
  and the writer's commit pipeline must stay bounded under hostile load from
  any single client, any single address, or the aggregate.
- **Operator data.** The database files, logs (no secrets or event content at
  default levels), and metrics (bounded label sets).
- **Release artifacts.** crates.io packages, GitHub release binaries and
  checksums, and the multi-arch GHCR image.

## Adversary model

- **Anonymous WebSocket client.**
  - May send any byte sequence: invalid UTF-8, oversized frames, compressed
    bombs, malformed JSON, protocol-valid but adversarial filters (huge lists,
    many tags, deep time ranges), REQ/CLOSE churn, slow reads, and never-read
    connections.
  - May open many connections and try to exhaust shared budgets.
  - Must not crash or wedge the relay, read restricted content, corrupt
    storage, or degrade other clients beyond its fair share as defined by the
    limits below.
- **Authenticated (NIP-42) client.** Has all of the above, plus valid AUTH
  events. Must not:
  - read restricted kinds it is not entitled to;
  - publish NIP-70 protected events for a pubkey it did not authenticate;
  - carry authentication to another connection, or across a hibernation
    restore of a different socket.
- **Malicious event author.** Crafts signed events to hit edge cases:
  - replaceable and addressable races (equal `created_at`, id tie-break);
  - deletions of others' events and deletions by `a` tag across time;
  - expiration in the past, at `now`, or overflowing;
  - kind 62 with crafted relay tags;
  - protected events embedded in reposts;
  - oversized tag values that fall out of packing;
  - non-canonical JSON that hashes differently.

  Must not delete or replace another author's events, revive deleted or
  vanished events, or bypass expiration.
- **Malicious NIP-86 caller.** Replays, forges, or tampers with NIP-98 headers
  and bodies, or probes for admin pubkeys. Must not execute a method without a
  fresh, body-bound, signed authorization from an admin. Replay inside the
  60 s window is an accepted risk (below).
- **Spoofed client address.** Sends `X-Forwarded-For` or another
  `real_ip_header` value directly. Must not change its accounted address when
  the header is not configured. When the header is configured, only its last
  value counts.
- **Malicious or broken write-policy plugin.** May hang, crash, flood stdout,
  answer for the wrong id, or emit huge lines. Must not stall other
  connections indefinitely, crash the relay, or accept an event it did not
  approve.
- **Network attacker.** TLS is assumed at the proxy. The relay does no
  certificate handling.
- **Crash and power loss.** `kill -9`, OOM kill, or power loss at any instant,
  including mid-commit, mid-sweep, and mid-import. The store must reopen
  consistent, with every acknowledged event present.
- **Out of scope.** A malicious operator, a compromised host or Cloudflare
  account, a malicious upstream crate (dependency selection and pinning are in
  scope), and side channels against secp256k1 verification.

## Security properties claimed

Each property names the enforcing code. Line references are approximate;
identifiers are authoritative.

- **P1 — Verified ingest.**
  - Every network event is parsed strictly (`UnverifiedEvent::parse`: all
    seven fields required, duplicates rejected, lowercase hex, `created_at`
    ≤ 2^53 − 1, `e`/`p` first values 64-hex; unknown keys are ignored and
    never reach storage) and size- and structure-checked
    (`check_limits`: `max_event_size`, `max_num_tags`, `max_tag_val_size`).
  - It is time-checked (`Session::check_time`: future, past, ephemeral age,
    expired).
  - Only then is it verified (`UnverifiedEvent::verify`): the id is recomputed
    over the canonical NIP-01 preimage (`id_preimage`) and the BIP-340
    signature checked with `secp256k1`.
  - Only a verified `Event` reaches the writer.
  - `verify_unsigned` (skips only the signature) is reachable solely from the
    operator CLI `import --no-verify`.
  - Files: `crates/nosfry-core/src/event.rs`, `session.rs`, `message.rs`.
- **P2 — Durable acknowledgement.**
  - `OK true` is sent only after the write transaction holding the event has
    committed. The writer commits a batch, enqueues it on every shard, and only
    then pushes each request's `OK` (`writer::write_batch`).
  - LMDB opens with default durability: no `NO_SYNC`, `NO_META_SYNC`, or
    `MAP_ASYNC` (`Store::open`).
  - In the Workers edition, `SqlStore::write` runs inside
    `Executor::transaction` (`DoSql::transaction`, which calls
    `transactionSync`) before the relay answers.
  - Files: `crates/nosfry/src/writer.rs`, `crates/nosfry-lmdb/src/lib.rs`,
    `crates/nosfry-worker/src/glue.rs`, `relay.rs`.
- **P3 — Exactly-once delivery across the scan/live boundary.**
  - Each subscription's shard takes the snapshot `S`, the highest committed
    seq it has received, in the same ordered inbox as committed batches.
  - The stored scan skips seq above `S` in every time slice.
  - Live matches buffer (`PendingSub`, `PENDING_CAP`) until `EOSE`, and only
    seq above `S` is delivered.
  - Seqs are persistent and never reused (`meta/next_seq`).
  - A subscription whose buffer overflows is closed, never silently gapped.
  - Files: `crates/nosfry/src/shard.rs`, `reader.rs`,
    `crates/nosfry-lmdb/src/scan.rs`; the Workers equivalent is in
    `crates/nosfry-worker/src/relay.rs`.
- **P4 — Read gate.**
  - A `ReadGate` snapshot is taken at REQ time from `AuthRules`, the
    connection's authenticated pubkeys, and the current NIP-86
    `Moderation` snapshot.
  - It filters stored scans, counts, negentropy storage, and live delivery
    alike: restricted kinds are served only to involved, authenticated
    readers, and events moderated by NIP-86 — banned or unlisted pubkeys
    and kinds, banned ids — are hidden until the entry is lifted.
  - With `service_url` empty, restricted kinds are stored but never served.
  - A Workers restore rebuilds the gate from the persisted REQ-time count of
    authenticated pubkeys.
  - Files: `crates/nosfry-core/src/auth.rs`, `monitor.rs`, `session.rs`;
    `crates/nosfry-lmdb/src/scan.rs`, `count.rs`;
    `crates/nosfry-sql/src/scan.rs`; `crates/nosfry-worker/src/relay.rs`.
- **P5 — NIP-42 authentication.**
  - AUTH requires kind 22242 and the connection's own challenge. The shell
    generates each challenge with fresh per-connection randomness (16 bytes
    from `getrandom` natively) and passes it to `Session::new`; the core
    never generates randomness.
  - It requires a `relay` tag matching `service_url` (`RelayUrl::matches`,
    normalized like strfry), a `created_at` within ±600 s of the
    relay's time (NIP-42's ~10 minutes, a dedicated symmetric window
    not the ephemeral-age rule), and a valid signature.
  - AUTH events are never stored or broadcast. A kind 22242 sent as EVENT is
    rejected.
  - Files: `crates/nosfry-core/src/session.rs` (`on_auth`), `url.rs`.
- **P6 — NIP-70 protected events.**
  - A protected (`["-"]`) event is rejected when AUTH is disabled.
  - It is answered `auth-required:` (with a challenge) when the connection is
    unauthenticated, and accepted only when its author is among the
    connection's authenticated pubkeys.
  - Reposts embedding a protected event are rejected (`embeds_protected`).
  - File: `crates/nosfry-core/src/session.rs` (`on_event`).
- **P7 — Deletion (NIP-09).**
  - A kind 5 deletes only targets whose author equals the kind-5 author: `e`
    tags by id, and `a` tags by address up to the kind-5 `created_at`.
  - It blocks re-publication of those targets through `ix_deletion` /
    `ix_replace_deletion` rows owned by the kind-5 event, so deleting the
    kind 5 lifts the block.
  - The SQL store implements the same rules.
  - Files: `crates/nosfry-core/src/deletion.rs`,
    `crates/nosfry-lmdb/src/lib.rs`, `crates/nosfry-sql/src/store.rs`.
- **P8 — Replaceable and addressable semantics.**
  - Kinds `0`, `3`, and `10000..20000` are replaceable per `(pubkey, kind)`;
    `30000..40000` are addressable per `(pubkey, kind, first d)`; everything
    else below `40000` is regular, except ephemeral `20000..30000`
    (`Kind::is_replaceable` and siblings).
  - The newest `created_at` wins, and on a tie the lowest id wins.
  - An older version is answered `duplicate: have a newer version` and is
    neither stored nor broadcast.
  - The winner replaces its predecessor in one transaction.
  - Kind 41 is regular, per NIP-01 (strfry and nostr-rs-relay treat it as
    replaceable).
  - Files: `crates/nosfry-core/src/kind.rs`, `event.rs` (`address`),
    `crates/nosfry-lmdb/src/lib.rs` (`ix_replace`),
    `crates/nosfry-sql/src/store.rs`.
- **P9 — Expiration (NIP-40).**
  - Expired events are rejected at ingest. Stored scans and counts hide any
    event with `expiration <= now` even before it is swept.
  - Live delivery happens at commit time and does not re-check expiration.
  - Background sweeps delete expired events in bounded steps that interleave
    with publishes: `EXPIRE_CAP` natively, 10,000 per Workers alarm.
  - Files: `crates/nosfry-core/src/session.rs`, `packed.rs` (expiration
    field), `crates/nosfry-lmdb/src/lib.rs`, `scan.rs`,
    `crates/nosfry/src/writer.rs`, `crates/nosfry-sql/src/store.rs`, `scan.rs`.
- **P10 — Request to vanish (NIP-62).**
  - A kind 62 is honored only when a `relay` tag is `ALL_RELAYS` or matches
    `service_url` (`Event::requests_vanish`).
  - It records the vanish point `T` as the maximum over requests (`ix_vanish`),
    blocks the author's events with `created_at <= T`, and drains history in
    bounded, resumable steps (`vanish_pending`, `vanish_step`, `VANISH_CAP`)
    that survive restarts.
  - Only the newest kind 62 per author is stored (NIP-62 bookkeeping);
    an older incoming one is `duplicate: have a newer version`.
  - Files: `crates/nosfry-core/src/event.rs`, `crates/nosfry-lmdb/src/lib.rs`,
    `crates/nosfry/src/writer.rs`, `crates/nosfry-sql/src/store.rs`.
- **P11 — NIP-86 management authorization.**
  - `POST /` with `application/nostr+json+rpc` and a body of at most
    `BODY_LIMIT` (64 KiB) requires a NIP-98 `Authorization: Nostr` event
    (`management::authorize`) with all of:
    - kind 27235;
    - `created_at` within ±60 s;
    - `method` = `POST`;
    - `payload` = SHA-256 of the exact body;
    - `u` matching `service_url`;
    - a valid signature, checked before the admin lookup so errors do not
      reveal admins;
    - a signer in `admins`.
  - With `admins` empty, or without the RPC content type, `POST /` answers
    405.
  - Writes go through the single writer, and the moderation snapshot is
    published in commit order.
  - Files: `crates/nosfry-core/src/management.rs`, `moderation.rs`;
    `crates/nosfry/src/management.rs`, `writer.rs` (`moderate`);
    `crates/nosfry-worker/src/glue.rs` (`manage`).
- **P12 — Write-policy isolation.**
  - The plugin receives only verified events, through a bounded queue
    (`QUEUE`), served strictly in order.
  - Each request has a deadline (`timeout_seconds`) that also bounds noise
    lines, and response lines are capped (`MAX_RESPONSE`).
  - Any failure kills the child (`kill_on_drop`) and rejects the event
    `error: internal error`. An id mismatch or unknown action is an error.
  - Backpressure falls only on the publishing connection.
  - `shadowReject` answers `OK true` without storing or broadcasting.
  - A configured plugin without `/bin/sh` refuses to start
    (`Config::plugin_needs_shell`).
  - Files: `crates/nosfry/src/policy.rs`, `crates/nosfry-core/src/policy.rs`,
    `crates/nosfry/src/config.rs`; Workers `run_policy` in `glue.rs`.
- **P13 — Bounded resources.** Every queue, buffer, scan, and per-connection
  set is bounded (defaults in parentheses):
  - **Frames and messages.**
    - Inbound frame or message size `max_websocket_payload_size` (128 KiB),
      including the inflated size of a compressed message (yawc).
    - HTTP header read timeout `HEADER_READ_TIMEOUT` (10 s).
    - NIP-86 body `BODY_LIMIT` (64 KiB).
  - **Event size.** `max_event_size` (64 KiB), `max_num_tags` (2,000),
    `max_tag_val_size` (1,024 B).
  - **REQ shape.**
    - Filters per REQ `max_req_filter_size` (200), subscriptions per
      connection `max_subs_per_connection` (200), `#` conditions per filter
      `max_tags_per_filter` (3).
    - Stored results per filter `max_filter_limit` (500).
    - COUNT entries examined `max_filter_limit_count` (1,000,000, then
      `approximate`).
    - NEG-OPEN records `max_sync_events` (1,000,000), and NEG frames
      `NEG_FRAME_LIMIT`.
  - **Rate limits.**
    - Per-connection EVENT and REQ token buckets (20/s, burst 100).
    - Per-address buckets (100/s, burst 500), shared by every connection of
      one address.
    - COUNT and negentropy messages spend REQ tokens.
  - **Connections.** `max_connections`, and `max_connections_per_ip` (128;
    IPv6 counted per /64).
  - **Pending outbound.**
    - Per connection `max_pending_outbound_bytes` (32 MiB, then close).
    - Process-wide `max_pending_outbound_bytes_total` (1 GiB, scans pause).
  - **Process-wide memory.** `max_sync_memory_bytes` (1 GiB),
    `max_subscription_bytes_total` (1 GiB; REQ refused
    `blocked: subscription capacity exhausted`). Sync memory is
    charged in 1,024-record steps while a `NEG-OPEN` collects
    records, not only once the session seals; a refused charge stops
    the scan with `blocked: sync capacity exhausted`.
  - **Inter-thread queues and buffers.**
    - Writer and shard queues (`WRITER_QUEUE`, `SHARD_QUEUE`, 4,096,
      backpressure rather than drop).
    - Pending-subscription buffer `PENDING_CAP` (4,096, then `CLOSED`).
    - Reader chunks (`CHUNK_FRAMES`, `CHUNK_BYTES`) and the scan time slice
      `query_timeslice_budget_microseconds` (10 ms).
    - Idle negentropy sessions expire (`NEG_IDLE`, 60 s).
  - **Workers.** The connection cap (5,000), the sync memory budget, the
    subscription budget, the scan row budget (`max_scan_rows`), and the
    JavaScript exact-integer bound (`JS_MAX`) on every SQL integer.
  - **Hash maps.** Hot-path maps use foldhash with randomized seeding, for
    HashDoS resistance.
- **P14 — Fail-closed configuration.**
  - Every config section is `deny_unknown_fields`.
  - Invalid values fail `Config::load` or are refused by a SIGHUP reload
    without side effects (`reload_once`). This covers `service_url`, admin
    keys, info fields, filter validation, `auto_ping_seconds = 0`, and a
    plugin without a shell.
  - Restart-only fields are listed and ignored on reload, with a warning
    (`Config::reloadable_from`).
  - Existing connections keep their WebSocket options.
- **P15 — Client address accounting.**
  - The client address is the socket peer unless `real_ip_header` is set.
    When set, the header's last comma-separated value is used; a missing or
    unparsable value falls back to the peer (`http::client_ip`).
  - The same address drives the per-IP cap, the per-address buckets, the
    NIP-86 IP block list, and the policy's `sourceInfo`.
  - Workers uses `CF-Connecting-IP`.
  - The NIP-86 IP block applies to new requests only.
- **P16 — Safe HTTP surface.**
  - The landing page escapes every interpolated value and emits only
    `http(s)`/`mailto` URLs as `src`/`href` targets (`site.rs`). It
    carries `Content-Security-Policy` (`default-src 'none'`, `img-src`
    http/https, inline `style-src`, `base-uri`/`form-action`/
    `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, and
    `Referrer-Policy: no-referrer` (`site::LANDING_HEADERS`), in both
    editions; API responses send none of them.
  - NIP-11 and NIP-86 send the shared CORS headers (`site::CORS_HEADERS`);
    `/metrics` sends none and exists only when enabled.
  - Metrics labels are fixed enums or `u16` kinds (`metrics.rs`).
- **P17 — Edition parity.** For the same configuration and input, the native
  and Workers editions produce the same OK/CLOSED/NOTICE prefixes, the same
  stored set, and the same scan order and dedup. This is enforced by the shared
  core, `nosfry-testkit` (model-based differential over both stores), and
  `nosfry-conformance` (black-box, both editions).
- **P18 — Crash consistency.**
  - The store reopens after `kill -9` at any point with every acknowledged
    event present, the index consistent with `events` and `payloads`, and
    vanish and expiry work resumable.
  - Tests: `crates/nosfry/tests/crash.rs`, `NOSFRY_CRASH_CYCLES`; the round 7
    W8 benchmark found 0 of 228,187 acknowledged events missing over 50
    `kill -9` cycles.
- **P19 — Hibernation correctness (Workers).**
  - After eviction, the constructor rebuilds every `Session` (`Session::resume`)
    and the `Monitors` index from the socket attachments and the `subs` table.
  - It drops rows of connections that no longer exist.
  - Subscriptions keep receiving matching events exactly once, and NIP-42
    state survives.
  - Rate-limit buckets restart full, and negentropy sessions end with
    `NEG-ERR closed:`.
  - Files: `crates/nosfry-worker/src/relay.rs`, `glue.rs`.

## Scope

In scope:

- `crates/nosfry-core/src`, `crates/nosfry-lmdb/src`,
  `crates/nosfry-sql/src`, `crates/nosfry/src`, `crates/nosfry-worker/src`
- Configuration surface: `nosfry.example.toml`, `docker/nosfry.toml`,
  `crates/nosfry-worker/wrangler.toml`
- Build and release:
  - `.github/workflows/{ci,container,publish,release,fuzz,dependabot}.yml`;
  - the reusable workflows they call at `qntx/workflows@v2` (the caller side
    and the permissions granted);
  - `Dockerfile`, `.dockerignore`, `rust-toolchain.toml`.
- Dependency set: `Cargo.toml`, `Cargo.lock`, `deny.toml`
- Fuzz targets: `fuzz/fuzz_targets` (coverage adequacy)

Out of scope:

- `yawc`, `heed`/LMDB, `secp256k1`, `negentropy`, `workers-rs` internals.
  Our use of them is in scope: options, invariants, and error paths.
- `crates/nosfry-testkit`, `crates/nosfry-conformance`, `bench/`, and tests,
  except as evidence for claimed properties
- The reverse proxy, TLS termination, and host hardening
- The `docs/` tree (local only, not published)

## Priority areas

Ranked by risk:

1. **Ingest and verification.** `event.rs` (`parse`, `check_limits`,
   `id_preimage`, `verify_impl`), `message.rs`, `session.rs` (`on_event`,
   `on_auth`). Check strictness, canonical serialization, limit order,
   integer edges, and NIP-70.
2. **Read gate and restricted kinds.** `auth.rs`, plus the gate application in
   `scan.rs`, `count.rs`, the negentropy seal paths, `monitor.rs`, and the
   SQL scan. Check every serving path, including COUNT, NEG, live delivery,
   and Workers restore.
3. **Storage semantics.** `nosfry-lmdb/src/lib.rs` (write path,
   replace/delete/vanish/expire, index maintenance, `next_seq`) and
   `nosfry-sql/src/store.rs`. Check transactional integrity, deletion and
   vanish guarantees, crash consistency, and LMDB/SQL parity.
4. **Delivery pipeline.** `writer.rs`, `shard.rs`, `reader.rs`,
   `connection.rs`, `channels.rs`. Check exactly-once delivery,
   backpressure, ordering (read-your-writes before `EOSE`), shutdown and
   drain, slow consumers, and the cost of `PENDING_CAP` and outbound budgets.
5. **Resource exhaustion.** Look for every allocation driven by a peer:
   - filters, including approx-bytes accounting versus real memory;
   - subscriptions, COUNT, NEG sessions and their frames;
   - compression state, outbound queues, and parse-failure NOTICE floods;
   - connection churn and per-address bucket maps.
6. **NIP-86 and NIP-98.** `management.rs` (core and native), `moderation.rs`,
   Workers `manage`. Check authorization, body binding, replay, method
   semantics, and ban side effects.
7. **Write-policy bridge.** `policy.rs` (native, core) and Workers
   `run_policy`. Check timeouts, child lifecycle, ordering, and malformed
   output.
8. **Workers edition.** `relay.rs`, `glue.rs`, `config.rs`. Check hibernation
   restore, attachment trust, single-object serialization, alarms,
   `transactionSync` use, platform limits, and `CF-Connecting-IP`.
9. **HTTP surface and configuration.** `http.rs`, `site.rs`, `info.rs`,
   `config.rs`, `lib.rs` (reload), `limiter.rs`, `metrics.rs`.
10. **Supply chain and release.** Workflows, reusable-workflow pinning, the
    container base and build, `cargo-deny` policy, and the exact pins
    (`negentropy`, `worker`, `wasm-bindgen`).

## Known limitations and accepted risks

- **Unauthenticated metrics.** `/metrics` has no authentication. It is off by
  default; keep it behind a proxy or firewall.
- **NIP-98 replay.** A captured NIP-86 request can be replayed within the
  ±60 s window. The payload hash binds it to the identical body, and there is
  no replay cache. Serve the relay over TLS.
- **Trusted address header.** `real_ip_header` trusts the header's last value.
  It must only be set behind a proxy that sets or appends it.
- **No HTTP rate limit.** HTTP routes have no request-rate limit of their own.
  A NIP-86 request that passes the cheap checks costs one signature
  verification. Rate-limit HTTP at the proxy.
- **Workers: one object.** One Durable Object serializes every connection,
  write, and scan on a single isolate. Capacity is that of one object, and
  there is no sharding.
- **Workers: idle socket close.** Cloudflare closes WebSockets idle for about
  100 s (close code 1006 seen by the object). The runtime has no server-side
  ping and browsers cannot send pings, so idle browser subscriptions reconnect.
  Decision pending: document it, or add an alarm-driven heartbeat.
- **Workers: state lost on wake.** Rate-limit buckets restart full after a
  hibernation wake. In-flight negentropy sessions end with `NEG-ERR closed:`.
- **Workers: policy ordering.** Workers write-policy checks on different
  connections interleave while a fetch is in flight. A service-bound policy
  must not rely on ordering; the native plugin is strictly serial.
- **Approximate COUNT.** COUNT is approximate (`"approximate": true`) once it
  examines `max_filter_limit_count` index entries. HyperLogLog follows
  go-nostr's `nip45/hyperloglog`.
- **Unverified import.** `import --no-verify` trusts its input's signatures.
  It is an operator-only path for re-importing a trusted export.
- **Disk full.** A full LMDB map (`map_size`) fails writes as
  `error: internal error`. There is no automatic growth.
- **Kind 41 is regular.** NIP-01 says so. strfry 1.1.3 and nostr-rs-relay
  0.10.0 treat it as replaceable per author, so the same event stream stores
  more kind-41 events on nosfry.
- **Authenticated pubkey cap.** NIP-42 says every correctly signed AUTH
  pubkey MUST be treated as authenticated; per connection the relay caps
  them at `MAX_AUTHED_PUBKEYS` (8) and answers a ninth `restricted:`
  (bounded per-connection state).
- **Client-controlled metrics series.** `nostr_events_total{kind}` is
  counted before moderation and policy, so clients control its series
  count, bounded at 65,536 kinds. `/metrics` is off by default and must
  stay behind a proxy.
- **Per-connection memory.** The baseline is about 11 KiB per idle connection,
  plain or with pooled deflate, against about 1 KiB for strfry without
  compression. The broadcast CPU per delivery is about 2.4× strfry's (round 7,
  P6 and P7).
- **Writer stalls under overload.** Under sustained open-loop ingest at or
  above 4,500 events/s on the benchmark VM, single commits of 1,024 events
  took 1.1–12.4 s, and OK tail latency grew to seconds (round 7 W1). This is
  under investigation. strfry runs with an effective `MDB_NOMETASYNC`, one
  fsync fewer per commit.
- **NIP-50 rejected.** NIP-50 `search` is rejected (`unsupported:`), and
  filter keys beyond NIP-01 are rejected rather than ignored.
- **Filter validation off.** `[relay.filter_validation]` defaults to disabled,
  matching strfry.
- **Ephemeral events escape a vanish.** Ephemeral events skip storage, so a
  vanished author's ephemeral events with `created_at <= T` are still
  broadcast live. The window is narrow: vanish points satisfy
  `T <= now + 900 s` while ephemeral events are generally `now - 60 s` or
  newer.
- **CI reusable workflows float.** The workflows reference the moving
  `qntx/workflows@v2` tag rather than a commit SHA. The repository is
  organization-owned and the referenced workflows are ours; third-party
  actions are SHA-pinned.

## Prior internal review

Earlier internal rounds covered:

- A NIP audit against the current texts (01, 09, 11, 40, 42, 45, 62, 70, 77,
  86, 98) and a strfry 1.1.3 parity review. Roughly 20 deliberate deviations
  are documented, each with its NIP basis.
- NIP-11 completeness (all strfry fields, `limitation`, `retention`, fees),
  the HTML landing page, `NodeInfo`, `filterValidation`, TCP keepalive, and
  management-method parameters.
- CORS for NIP-86 browser clients: preflight `POST`, explicit
  `Authorization` in allowed headers, and CORS on management responses.
- `auto_ping_seconds = 0` panicked in `tokio::time::interval`. It is now
  rejected at load and on reload.
- A distroless image with a configured plugin and no `/bin/sh` now refuses to
  start.
- The unbounded subscription memory is now bounded:
  `max_subscription_bytes_total`, released on every removal, replacement, and
  overflow path, with the `nosfry_subscription_bytes` metric.
- yawc 0.5.0 integration, with upstream issue #60 and PRs #61 and #63:
  - pooled no-context-takeover deflate by default;
  - a 128 B compression threshold;
  - 2 KiB buffers;
  - bounded inflated payloads (yawc #56).
- Soak runs:
  - 72 h, stopped at 47.3 h, on `dfaf455`: zero errors, anonymous RSS slope
    +0.02 MiB/h;
  - 24 h on 0.3.0 (round 7 W7): zero errors, +0.05 MiB/h.
- Round 7 benchmark audit (#55, #64, #65):
  - the W2/W5 runs were voided after an empty-database harness defect;
  - W8 showed zero acknowledged-event loss over 50 `kill -9` cycles;
  - strfry's kind-41 and `replaced:` behaviors were characterized.
- Workers acceptance on a real deployment:
  - 30/30 conformance;
  - hibernation restore of 152 subscriptions with exactly-once delivery
    (1,500/1,500);
  - NIP-42 state survived the restore;
  - no exceptions or CPU-limit errors.

No external audit has been performed.

## Build, test and reproduce

```bash
npx --yes @taplo/cli@0.7.0 fmt --check
cargo +nightly fmt --all -- --check
cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" \
    cargo check -p nosfry-core -p nosfry-sql -p nosfry-worker --target wasm32-unknown-unknown
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" \
    cargo clippy -p nosfry-worker --target wasm32-unknown-unknown -- -D warnings

# black-box protocol suite against both editions
crates/nosfry-conformance/run.sh native
crates/nosfry-conformance/run.sh worker      # worker-build 0.8.7, Node, wrangler 4.150.0

# crash recovery: kill -9 cycles
NOSFRY_CRASH_CYCLES=60 cargo test -p nosfry --test crash

# fuzzing (nightly + cargo-fuzz); targets: client_message, event_roundtrip,
# filter_parse, monitor_differential, packed_record
cargo +nightly fuzz run <target> -- -max_total_time=60

# run locally
cargo run --release -p nosfry -- relay --config nosfry.example.toml
(cd crates/nosfry-worker && npx --yes wrangler@4.150.0 dev --local)
```

Load, soak and durability reproduction: `bench/README.md` (round 7:
`bench/r7/run.py`, `bench/r7/analyze.py`).

## Code guide

### Directory map

- `crates/nosfry-core/src/`
  - `event.rs`: `UnverifiedEvent`, `Event`, `EventLimits`, the id preimage,
    `address`, `requests_vanish`, `embeds_protected`, `is_protected`.
  - `kind.rs`: `Kind`, `KindClass`.
  - `filter.rs`: `Filter`, its compiled form and matcher, `approx_bytes`.
  - `message.rs`: client message parsing (`ClientMessage`), relay frame
    builders, `SubId`, and `Reason` prefixes.
  - `session.rs`: the per-connection state machine (`Session`, `Command`,
    `Received`, `Session::resume`).
  - `monitor.rs`: the live index (`Monitors`).
  - `limits.rs`: `Limits`, `ReqLimits`, `RateLimits`, `AddressBuckets`,
    `TokenBucket`, `FilterValidation`.
  - `auth.rs`: `AuthConfig`, `AuthRules`, `ReadGate`.
  - `deletion.rs`: NIP-09 targets.
  - `packed.rs`: the packed index record.
  - `sync.rs`: the negentropy round and limits.
  - `hll.rs`: NIP-45 HyperLogLog.
  - `info.rs`: NIP-11.
  - `site.rs`: landing page, `NodeInfo`, `CORS_HEADERS`.
  - `management.rs`: NIP-86 dispatch and NIP-98 `authorize`.
  - `moderation.rs`: `ModOp`, `Moderation`.
  - `policy.rs`: strfry policy wire format.
  - `url.rs`: `RelayUrl`.
  - `store.rs`: write outcomes.
  - `sign.rs`: test and tooling signers.
- `crates/nosfry-lmdb/src/`
  - `lib.rs`: `Store`, `StoreOptions`, the write path, deletion, vanish,
    expiry, moderation tables, and the layout table in the module docs.
  - `scan.rs`: `Scan`.
  - `count.rs`: `CountScan`.
- `crates/nosfry-sql/src/`
  - `store.rs`: schema, writes, expiry.
  - `scan.rs`: paged cursors, k-way merge, row budget.
  - `exec.rs`: the `Executor` trait.
  - `rusqlite.rs`: the `Executor` with workerd statement limits.
- `crates/nosfry/src/`
  - `lib.rs`: server wiring, thread topology, `Live`, the reload loop, the
    accept loop.
  - `http.rs`: router, upgrade, `client_ip`, NIP-11 and landing.
  - `connection.rs`: the per-connection task and batching.
  - `writer.rs`: group commit, sweeps, broadcast.
  - `shard.rs`: the monitor shard and pending subscriptions.
  - `reader.rs`: scans, COUNT, negentropy.
  - `channels.rs`: message types.
  - `limiter.rs`: connection caps and per-address buckets.
  - `policy.rs`: plugin bridge.
  - `management.rs`: NIP-86 transport.
  - `metrics.rs`: Prometheus.
  - `config.rs`: TOML, defaults, reload rules.
  - `admin.rs`: CLI commands.
  - `main.rs`: CLI entry.
- `crates/nosfry-worker/src/`
  - `relay.rs`: the host-testable relay object (`Relay`, `Socket`, `Effects`,
    the `subs` schema, restore).
  - `glue.rs`: the Durable Object shell (`fetch`, `upgrade`, `manage`,
    WebSocket handlers, `alarm`, `DoSql`, `run_policy`).
  - `config.rs`: the `NOSFRY_CONFIG` document.

### Native thread and channel topology

| Component        | Count                            | Owns                                                       | Talks to                                                 |
| ---------------- | -------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------- |
| Tokio runtime    | 1 (multi-thread)                 | HTTP, upgrades, one task per connection, plugin I/O        | writer (`WRITER_QUEUE`), its shard (`SHARD_QUEUE`)       |
| Writer thread    | 1                                | the only LMDB write transaction, `next_seq`, sweeps        | every shard (committed batches), connection outbound     |
| Monitor shards   | `relay.threads.monitors` (3)     | `Monitors`, `PendingSub`s, snapshot `S`, outbound queues   | readers (scan control), connections (frames)             |
| Reader threads   | `relay.threads.readers` (3)      | read transactions, time-sliced `Scan`/`CountScan`, NEG     | shards (results, `EOSE`), connections (frames)           |

LMDB is touched only by the writer and the readers.

### Flow walkthroughs

#### Connection accept and upgrade (native)

1. The accept loop (`lib.rs`) applies `HEADER_READ_TIMEOUT` and optional
   `SO_KEEPALIVE`.
2. `http::root` handles the request:
   1. `ip_blocked` (NIP-86 IP list on `client_ip`) answers 403.
   2. An upgrade request goes to `websocket`.
   3. Otherwise `Accept: application/nostr+json` returns NIP-11 with CORS.
   4. Anything else gets the landing page.
3. `websocket` takes one config snapshot, then:
   1. `upgrade_options`: payload cap, 2 KiB buffers, deflate (pooled or
      sliding).
   2. `limiter.try_acquire(ip)` charges the global and per-IP caps before the
      upgrade; failure answers 429.
   3. The connection task is spawned with the address's shared buckets.

#### Publish (EVENT)

1. `connection.rs` passes the text to `Session::receive`, which:
   1. parses the message (`ClientMessage::parse`);
   2. charges the connection and address EVENT buckets (`rate-limited:`);
   3. runs `on_event`: `check_limits`, `check_time`, the AUTH-kind refusal,
      `embeds_protected`, the NIP-70 gate, then `verify`, which emits
      `Command::Publish`.
2. The connection (`connection.rs`) checks moderation (banned pubkey, event,
   or kind, ephemeral events included; a request to vanish for this relay is
   exempt) and then the write-policy plugin when configured (`policy.rs`).
3. It hands the request to the writer (`WRITER_QUEUE`).
4. `writer::run` drains up to `BATCH_CAP` (1,024) requests and calls
   `write_batch`:
   1. one LMDB transaction (`Store::write`) applies dedup, deletion and vanish
      blocks, replace, deletion targets, and expiry rows;
   2. the transaction commits;
   3. `enqueue_batch` queues the batch on every shard (`blocking_send`),
      minus seqs deleted in the same transaction;
   4. each `OK` is pushed onto its connection's outbound queue.
5. Ephemeral events skip the writer. After moderation and policy, the
   connection fans them out to every shard (`ShardMsg::Ephemeral`) without a
   seq.

#### Subscribe (REQ) and the scan/live handoff

1. `Session::on_req` checks the filter count, the subscription cap, filter
   validation, and the subscription byte budget, then takes the `ReadGate`
   snapshot and emits `Subscribe`.
2. The connection registers with its shard. The shard records snapshot `S`
   and buffers live matches in `PendingSub` (≤ `PENDING_CAP`).
3. A reader runs `Scan` in time slices (`query_timeslice_budget_microseconds`):
   - per filter, newest first, capped at `limit`/`max_filter_limit`;
   - read gate and expiry applied;
   - seq above `S` skipped;
   - chunks of at most `CHUNK_FRAMES`/`CHUNK_BYTES`, pausing while the
     process-wide outbound budget is exceeded.
4. At `EOSE` the shard flushes the buffered seq above `S` and switches the
   subscription to live.
5. CLOSE, a replaced sub id, or disconnect releases the monitor entries and
   the subscription byte charge.

#### COUNT (NIP-45)

`Session::on_count` charges REQ tokens and passes `CountScan` to a reader:

- the same cursors as `Scan`, with no payload fetch;
- the first filter wins and the first cursor wins (no hash set);
- the read gate is applied;
- the scan stops at `max_filter_limit_count` entries and reports
  `approximate`;
- HLL registers are added for single-tag single-filter queries (`hll.rs`).

#### Negentropy (NIP-77)

1. `NEG-OPEN` charges REQ tokens. A reader seals the filter's records (read
   gate applied) into negentropy storage, refusing past `max_sync_events` and
   charging `max_sync_memory_bytes` at `SYNC_RECORD_BYTES` per record.
2. `NEG-MSG` rounds run in `sync.rs`, with frames bounded by
   `NEG_FRAME_LIMIT`.
3. Idle sessions close after `NEG_IDLE`, and the storage is released on every
   exit path.

#### AUTH (NIP-42)

1. The shell creates the challenge when the connection opens (`getrandom`);
   the session sends it once (`issue_challenge`, `challenge_sent`).
2. `Session::on_auth` checks: authentication enabled, kind 22242, time window,
   challenge, `relay` tag (`RelayUrl::matches`), then the signature.
3. On success the pubkey is added to `authed`. Later REQs snapshot it into
   their `ReadGate`; existing subscriptions keep the gate they were created
   with.

#### Deletion, expiration, vanish

- **Deletion.** A kind 5's `deletion_targets` are applied in its write
  transaction, author-matched, with block rows owned by the kind 5.
- **Expiration.** An `ix_expiration` row is written with the event. The writer
  runs `Expire` sweeps capped at `EXPIRE_CAP` that interleave with publishes.
  Scans check expiry against `now`.
- **Vanish.** `record_vanish` stores `T = max(T, created_at)` and queues
  `vanish_pending`. The writer drains through `vanish_step(VANISH_CAP)`, which
  resumes after a restart. `vanish_blocked` refuses older events.

#### NIP-86 management

1. `POST /` passes through the axum body limit (`BODY_LIMIT`), `ip_blocked`,
   the content type, and `management::authorize`.
2. The request is dispatched to `Action`:
   - reads answer from the moderation snapshot;
   - writes go to the writer (`writer::moderate`), which commits and
     publishes the rebuilt snapshot before replying;
   - `changerelay*` methods rebuild NIP-11 and the landing page.
3. Workers: `RelayObject::manage` checks the body size, then `Relay::manage`
   runs the same core dispatch. Its store writes go through
   `Executor::transaction`, which is `transactionSync` in production.

#### Write policy

- **Native.** `Policy::new` spawns the `run` task. Each request goes
  `try_serve`: lazy spawn (restarted when the plugin path's mtime changes),
  write the request line, read lines until the matching id or the deadline
  (noise skipped, at most `MAX_RESPONSE` per line). Any error kills the child
  and rejects the event.
- **Workers.** `run_policy` POSTs the same request line to `POLICY`,
  `policy_response` parses the reply, and `decide` finishes the publish.

#### Reload (SIGHUP)

1. `reload_loop` receives the new config, and `reload_once` validates it
   completely before any side effect.
2. `reloadable_from` restores and warns about restart-only fields.
3. A new `Live` is published (limits, NIP-11, landing, policy). Connection
   caps are updated; existing connections keep their snapshot.

#### Workers request and hibernation lifecycle

1. The entry `fetch` (`glue.rs`) serves `/.well-known/nodeinfo` and
   `/nodeinfo/2.1` directly. Everything else on `/` goes to the single object
   `get_by_name("relay")`, with an optional location hint.
2. `RelayObject::fetch`:
   1. `CF-Connecting-IP` is checked against the IP block list.
   2. An upgrade goes to `upgrade`: cap check, `accept_web_socket`, and an
      attachment.
   3. `POST` goes to `manage`.
   4. Anything else gets NIP-11 or landing.
3. `websocket_message` feeds `Relay` (`Session`, `Monitors`, `SqlStore`).
   `Effects` carry sends, closes, and the alarm schedule. Each open
   subscription is a `subs` row.
4. After eviction, `RelayObject::new` restores sessions and monitors from the
   attachments and `subs`, and drops orphan rows.
5. `alarm` (`Relay::alarm`) runs one expiry sweep and one vanish step
   (10,000 rows each) and schedules the next wake (`next_alarm`). Idle
   negentropy sessions are reaped after `NEG_IDLE_MS`.

### Validation helper index

- `UnverifiedEvent::parse` / `check_limits` / `verify` (`event.rs`): strict
  parse, structural limits, id and signature.
- `Session::check_time` (`session.rs`): `created_at` windows and expiration.
- `Filter::parse` / `Filter::matches` / `Filter::is_impossible` /
  `Filter::approx_bytes` (`filter.rs`).
- `FilterValidation::violation` (`limits.rs`): the strfry `filterValidation`
  rules.
- `ReadGate` (`auth.rs`): the per-event read decision.
- `RelayUrl::parse` / `RelayUrl::matches` (`url.rs`): AUTH `relay`, the
  NIP-62 `relay` tag, and the NIP-98 `u` tag.
- `management::authorize` (`management.rs`): the NIP-98 gate.
- `deletion::targets` (`deletion.rs`): author-bound NIP-09 targets.
- `Event::requests_vanish` (`event.rs`): the NIP-62 relay match.
- `http::client_ip`, `ConnectionLimiter::try_acquire` (`http.rs`,
  `limiter.rs`).
- `Config::load` / `Config::limits` / `Config::reloadable_from`
  (`config.rs`).
- `policy::Response` parsing (`crates/nosfry-core/src/policy.rs`): id match
  and action set.

### Storage layout

The LMDB layout (databases, keys, and values) is the table in the
`crates/nosfry-lmdb/src/lib.rs` module documentation; all integers are
big-endian. The SQL schema is in `crates/nosfry-sql/src/store.rs`. Every
integer bound into SQL stays at or below `2^53 − 1`.
