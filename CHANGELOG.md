# Changelog

All notable changes to `nosfry` are documented in this file.

The format is based on [Keep a Changelog]; this project follows
[Semantic Versioning].

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Changed

- Only the newest kind-62 request to vanish per author is stored
  (NIP-62 bookkeeping); an older or equal-dated incoming request is
  answered `duplicate: have a newer version` instead of accumulating.
- COUNT's tag-cover check binary-searches the sorted earlier values
  instead of scanning them against every packed tag.

### Fixed

- A scan crossing one `created_at` shared by many events no longer
  buffers the whole tie group: it keeps only `limit - taken`
  smallest ids, bounded per filter.
- An in-progress `NEG-OPEN` scan now charges `max_sync_memory_bytes`
  while it collects records and is refused with `blocked: sync
  capacity exhausted` instead of running unbudgeted until the
  session seals.
- NIP-86 bans and allow/disallow lists now hide matching stored
  events at read time: a REQ, COUNT, or NEG-OPEN taken after a
  `banpubkey`, `disallowkind`, or allow-list change no longer serves
  the moderated events, and the entries hide again after a Workers
  hibernation restore. `banevent` still deletes the stored event.

## [0.3.0] - 2026-10-23

### Added

- A `restored <conns> connections, <subs> subscriptions (<n> rows
dropped)` line in the Workers edition's log whenever the Durable
  Object is constructed, proving a hibernation wake restored the
  still-attached sockets and subscriptions.

### Changed

- yawc 0.5.0 on the native edition: lazy deflate state, a shared
  `DeflatePool` for no-context-takeover connections, and exact socket
  buffer capacities.
- `[relay.compression] sliding_window` now defaults to `false`: both
  directions negotiate no context takeover and deflate state comes
  from a server-wide pool, so an idle connection costs a few KiB
  instead of ~370 KiB. The price, against the sliding window: 18-52%
  more bytes and about 25% more CPU per compressed message (1,000
  subscribers: 26 MB relay RSS against 217 MB, 11.2 against 9.0 us
  of CPU per delivery; strfry: 235 MB, 11.7 us). `true` keeps strfry's
  behaviour for relays bound by bandwidth or CPU rather than
  connection count.
- Socket read and write buffers start at 2 KiB each (was 8 KiB);
  they still grow for large frames and shrink back afterwards.
- Outbound messages under 128 bytes go out uncompressed: every reply
  type (OK, EOSE, CLOSED, NOTICE, AUTH, COUNT) is shorter and gains
  nothing, while every event message is longer.

## [0.2.0] - 2026-10-22

### Added

- strfry `enableTcpKeepalive` parity on the native edition:
  `[relay] tcp_keepalive` sets `SO_KEEPALIVE` with OS default
  timings on each accepted socket. Reloadable on SIGHUP for new
  connections; a failed `setsockopt` warns and the connection
  proceeds, as strfry does.
- strfry's logging switches as tracing targets (native):
  `nosfry::ingest` (DEBUG) logs every relay-sent `OK` frame — accept
  and reject — plus relay-sent `CLOSED` frames;
  `nosfry::inbound` (TRACE) logs every inbound text message;
  `nosfry::scan` (DEBUG) logs each finished stored REQ scan (filters,
  events sent, elapsed microseconds) and COUNT (count, index entries
  examined). Disabled levels cost nothing measurable; no config keys
  — select with `RUST_LOG`, e.g.
  `RUST_LOG=info,nosfry::ingest=debug`.
- `nosfry delete --age <SECONDS>` bounds the deletion by
  `created_at` (`until = now - SECONDS`, the earlier of that and the
  filter's own `until`); FILTER is now optional but at least one of
  `--age`/FILTER is required, so nothing can delete the whole
  database by accident.
- `nosfry import --no-verify` skips only the BIP-340 signature
  check (trusted input such as a dump from a trusted relay); the id
  hash, canonical size, and every structural/limit check still run.
  Backed by `UnverifiedEvent::verify_unsigned`, which shares one
  implementation with `verify`.
- `[relay] max_subscription_bytes_total` (default 1 GiB, `0`
  unlimited, restart-only): a process-wide budget for live
  subscriptions on the native edition. Every REQ is charged the
  `Filter::approx_bytes` sum of its filters — an estimate of the
  compiled filters plus their monitor index entries — and a REQ
  that would cross the budget answers `CLOSED blocked:
subscription capacity exhausted`; `CLOSE`, disconnects, and
  relay-side closes release the charge. New gauge
  `nosfry_subscription_bytes` reports the shared total, and the
  soak harness asserts it drains to zero once every connection
  is closed. The Workers `[worker] max_subscription_bytes` now
  charges the same `approx_bytes` estimate instead of the
  persisted filters-JSON length.
- strfry `relay.filterValidation` parity on both editions: a
  `[relay.filter_validation]` section limits REQ/COUNT filters by
  count (`min_filters_per_req`/`max_filters_per_req`), kinds per
  filter (`max_kinds_per_filter`), an `allowed_kinds` set (a filter
  without `kinds` is refused when the set is non-empty — strfry lets
  it match every kind), and `require_author_or_tag` (exactly one
  `authors`, `#p`, or `#e` value). Violations answer `CLOSED
blocked:`; `NEG-OPEN` is exempt. Reloads on SIGHUP for new
  connections.
- strfry's HTTP surface on both editions: `GET /` without
  `Accept: application/nostr+json` answers a self-contained HTML
  landing page (name, icon/banner, description, relay URL, admin
  and relay pubkeys, contact, supported NIPs, terms of service,
  privacy policy — every interpolated value escaped), and
  `/.well-known/nodeinfo` plus `/nodeinfo/2.1` serve NodeInfo
  discovery and the 2.1 document. The discovery link derives from
  `[relay] service_url`, never the `Host` header; the Workers
  edition answers both at the entry Worker and now 404s every
  other path without waking the relay object.
- The full NIP-11 field set on `[relay.info]`: `banner`, `self` (the
  relay's own pubkey), `terms_of_service`, `privacy_policy`, and
  `supported_nips` (when present it replaces the computed list
  verbatim, like strfry `info.nips`). `pubkey` and `self` are
  validated at load: anything but 64 lowercase hex — an npub,
  uppercase, or a wrong length — rejects the configuration.
  `limitation.restricted_writes` now reports whether the NIP-86
  allow-lists refuse unlisted writes. The document is built by
  `nosfry_core::info::document`, shared by both editions.
- A Cloudflare Workers edition (`nosfry-worker`): the relay runs as
  a hibernatable Durable Object over `ctx.storage.sql`, with the
  same NIP-01/09/11/40/42/45/62/70/77/86 coverage as the native
  edition. WebSocket hibernation persists attachments and a `subs`
  table restores subscriptions on wake. Publishes can be gated by a
  strfry write-policy through an optional `POLICY` service binding
  (the request line is `POST`ed and the `reject`/`shadowReject`
  verdicts behave identically). `nosfry-sql` is a portable store
  over a minimal executor trait with a rusqlite adapter, and the
  conformance suite runs the same cases against both editions.
  Workers-specific keys: `[worker] location_hint`,
  `[worker] max_scan_rows` (per-REQ index-row budget, default
  100,000), and `[worker] max_subscription_bytes` (live-subscription
  byte budget, default 32 MiB, `0` unlimited); the Workers defaults
  for `[relay] max_connections` (5,000) and `[relay]
max_sync_memory_bytes` (32 MiB) are tighter than native's.
- NIP-86 relay management API over NIP-98 auth: `POST /` with
  `application/nostr+json+rpc` answers `{"result"|"error"}` JSON for
  pubkey/event/kind bans and allow-lists, IP blocks, and NIP-11
  name/description/icon overrides. Enabled by `[relay.management]
admins`; every call must carry a valid kind-27235 auth event from a
  configured admin (the `u` tag is matched against `[relay]
service_url` host-normalized, `payload` must hash the body).
  Moderation state persists in the store (format 4) and is enforced
  from an in-memory snapshot: publishes get `blocked:` `OK`s (AUTH
  and relay-scoped vanish requests exempt), `banevent` deletes the
  stored event atomically, and blocked IPs get 403 on new requests.
- NIP-62 request to vanish: a kind-62 event whose `relay` tags name
  `[relay] service_url` or hold `ALL_RELAYS` (honored even without a
  configured URL) records a vanish point at its `created_at`, deletes
  the author's events at or before it (every kind except 62 itself,
  which can never be deleted or blocked) and `p`-tagged kind-1059
  gift wraps in the window, and queues a persistent backlog the
  writer drains 10,000 events per step — resuming after a restart.
  Republishing vanished events is refused with
  `blocked: request to vanish`, and requests bypass the
  write-policy plugin as the NIP requires. NIP-11 advertises 62.
  The store's `write` takes the relay URL, bumps the on-disk format
  to 3, and `vanish_step`/`vanish_pending` drive the sweep.
- NIP-45 `COUNT`: `["COUNT", <sub>, <filters>…]` counts the stored
  events the filters would return and answers with one
  `["COUNT",<sub>,{"count":n}]` frame. COUNTs share the REQ rate
  buckets, subscription slots, and filter validation; a filter's
  `limit` is ignored and restricted kinds are counted only for
  readers allowed to see them. `relay.limits.max_filter_limit_count`
  (default 1,000,000, `0` disables COUNT) caps the index entries one
  COUNT may examine; reaching it ends the scan early and the answer
  carries `"approximate": true` rather than strfry's `limited`.
  Single-tag-condition queries also get `"hll"`, the 256-register
  HyperLogLog sketch of the counted authors (NIP-45 offset rule).
  NIP-11 advertises 45 while COUNT is enabled.

- NIP-77 negentropy sync: `NEG-OPEN`/`NEG-MSG`/`NEG-CLOSE` run a
  record-mode scan (matching, limits, ordering, dedup, read-gate, and
  expiration identical to a REQ, without fetching payloads) and keep
  a sealed `NegentropyStorageVector` per session for reconciliation.
  Syncs have their own subscription-id namespace, share the REQ rate
  buckets and the `max_subs_per_connection` cap, and idle sessions
  are reaped after 60 s (`closed: idle timeout`).
  `relay.limits.max_sync_events` (default 1,000,000, `0` disables
  sync) bounds the records per sync — `blocked: too many query
results` with the cap as the fourth `NEG-ERR` element — and
  `[relay] max_sync_memory_bytes` (default 1 GiB, `0` unlimited) is
  the process-wide budget for sealed storages at 40 bytes per
  record. Both are restart-only; NIP-11 advertises 77 while sync is
  enabled. The `nosfry_sync_memory_bytes` gauge reports the reserved
  bytes.

- `[relay] nofiles` (default 1,000,000, `0` disables): the binary raises
  its soft open-file limit at startup, capped by the hard limit, so
  systemd/containerd's 1024 default no longer caps connection count.
  Failures warn and do not abort startup.
- NIP-09 event deletion: kind-5 `e` tags delete the author's own events
  by id and `a` tags delete the author's own replaceable/addressable
  events at an address (versions with `created_at` not newer than the
  deletion request). Republishing a deleted event or address is
  rejected with `blocked: deleted by its author`; deleting the kind 5
  itself lifts the block. Deleting a deletion request has no effect.
- NIP-40 event expiration: the first `expiration` tag is validated at
  ingest (missing, non-decimal, or sub-100 values are rejected) and an
  already-expired event is refused with `invalid: event has expired`.
  Stored events are hidden from every `REQ` at their timestamp and
  swept by the writer on a 10-second timer.
- `Store::delete` (delete by seq) and `Store::expire` (sweep expired
  events, capped per call) in `nosfry-lmdb`; `WriteOutcome::Deleted`
  reports a blocked republish.
- `nosfry delete [--dry-run] <filter-json>` deletes every stored event
  matching a `REQ` filter (including already-expired ones) and prints
  the count; `ImportStats` gains a `blocked` field for blocked imports.
- Multi-arch container image published to `ghcr.io/qntx/nosfry` on tag
  pushes: distroless non-root runtime, `NOSFRY_CONFIG` pointing at a
  bundled config with `/data` as the database volume.
- taplo formatting for every TOML file (`.taplo.toml`, aligned `=`),
  checked in CI.
- Administration commands on the `nosfry` binary: `export` writes every
  stored event as JSON lines ordered by `created_at` (with `--since`,
  `--until`, and `--reverse`), `import` verifies and stores event JSON
  lines from stdin in 10 000-event batches without a `created_at`
  time-window check (`--show-rejected` logs each rejected line), `scan`
  runs a `REQ` filter over the whole database in newest-first order
  (with `--count`), and `compact` copies the database to a compacted
  file. Read-only commands fail with `no database at <path>` when the
  database does not exist.
- `Store::export` (snapshot-consistent chronological streaming via
  `ix_time`) and `Store::compact_to` (compacted environment copy) in
  `nosfry-lmdb`.
- `nosfry::admin`, the library API behind the administration commands.
- Per-connection token-bucket rate limits (`[relay.rate_limits]`,
  20 events/s and 20 REQs/s with a burst of 100 each; a `*_per_second`
  of 0 disables that bucket). Over-limit EVENTs are answered `OK false
rate-limited: slow down`, over-limit REQs `CLOSED rate-limited: slow
down`; CLOSE is never charged.
- Shared per-client-address rate limits (`ip_events_per_second`,
  `ip_events_burst`, `ip_reqs_per_second`, `ip_reqs_burst`; defaults
  100/s burst 500, a `*_per_second` of 0 disables the bucket). Every
  connection of one client address — IPv4 per address, IPv6 per /64 —
  draws from the same buckets, and a message is refused when either
  the connection bucket or the shared address bucket is empty, closing
  the `max_connections_per_ip × per-connection-rate` bypass.
- `[relay] max_pending_outbound_bytes_total` (default 1 GiB, `0`
  disables, restart-only): a process-wide budget on the sum of every
  connection's pending outbound bytes. Over budget, stored scans pause
  only on connections already more than one chunk behind; caught-up
  readers keep scanning and live deliveries are unaffected. New gauge
  `nosfry_outbound_pending_bytes` reports the shared total.
- `nosfry_store_errors_total{op}` counter (`write`, `expire`, `scan`)
  for failed store operations.
- Connection caps: `[relay] max_connections` (default 0 = unlimited)
  and `max_connections_per_ip` (default 128) refuse over-cap upgrades
  with `429 Too Many Requests`. IPv4 counts per address, IPv4-mapped
  IPv6 folds to IPv4, other IPv6 groups per /64 prefix.
- Optional Prometheus metrics: `[relay] metrics = true` serves
  unauthenticated `GET /metrics` on the relay port in the text
  exposition format — `nostr_client_messages_total{verb}`,
  `nostr_relay_messages_total{verb}`, `nostr_events_total{kind}`,
  `nosfry_connections`, `nosfry_connections_rejected_total`, and
  `nosfry_rate_limited_total{verb}`, all on fixed label sets from
  lock-free counters.
- NIP-42 authentication (`[relay.auth]`): with `service_url` set, the
  relay challenges a connection lazily — once, the first time it REQs
  a fully restricted filter or publishes a protected event — and a
  valid kind-22242 AUTH event authenticates its pubkey. Up to 8
  distinct pubkeys authenticate per connection (strfry allows one).
- NIP-70 protected events: a `["-"]` tag makes the event rejectable —
  `blocked: event marked as protected` when AUTH is disabled,
  `auth-required:` (with the challenge) when the connection has not
  authenticated, `restricted: must be published by the author` when
  authenticated as a different key. Kind-6/16 reposts whose content
  embeds `["-"]` are blocked outright.
- Restricted read kinds: `restricted_read_kinds` (default `[4, 1059]`)
  are hidden from unauthenticated clients and, with
  `restrict_read_to_involved = true`, from authenticated clients not
  involved as author or `p`-tagged recipient. A REQ whose filters are
  all restricted is refused (`auth-required:` / `restricted:`); mixed
  REQs subscribe and the per-subscription `ReadGate` hides restricted
  events in both stored scans and the live monitor — hidden events
  never consume `limit`.
- The write-policy plugin request gains `authed`, the hex pubkey the
  connection authenticated with (omitted when absent), matching
  strfry's plugin field.
- `[relay.write_policy]`: a strfry-compatible write-policy plugin
  (`plugin`, `timeout_seconds` = 10). Each verified event is sent to
  `/bin/sh -c <plugin>` as one JSON line carrying the raw event, the
  receive time, and the client's IP (`IP4`/`IP6`); the plugin answers
  `accept`, `reject`, or `shadowReject`. A plugin configured as a bare
  path reloads when its mtime changes; any failure rejects the event
  with `error: internal error` and restarts the process for the next
  event. `nosfry import` does not invoke the plugin.
- Configuration hot reload (unix): SIGHUP makes the binary re-read its
  config file and apply it live — a parse error is logged and the
  running configuration is kept. Session limits and connection options
  apply to new connections and new publishes; `max_connections` /
  `max_connections_per_ip` and the write-policy plugin take effect for
  every connection at once. Restart-only keys (`[db]`, `relay.bind`,
  `relay.port`, `relay.nofiles`, `relay.metrics`, `relay.threads`,
  `relay.query_timeslice_budget_microseconds`,
  `relay.limits.max_filter_limit`) keep their startup values and are
  logged as ignored.
- The writer thread logs a warning when a store commit, the shard
  enqueue, or an expiry sweep takes over one second — a stall there
  delays every publisher's `OK` while read queries keep completing.

### Changed

- Shared protocol code moved into `nosfry-core` for the Workers
  edition: `moderation` (the NIP-86 snapshot and ops),
  `management` (the RPC authorization and dispatch), `policy`
  (the strfry write-policy request/response protocol), `sync`
  (the negentropy reconcile helpers), `info` (the NIP-11 document),
  and `auth`'s `AuthConfig`; `nosfry_core::sign` is now behind the
  `test-util` feature.

- `WriteOutcome` moved from `nosfry-lmdb` to `nosfry_core::store`,
  with the `OK` reply mapping as `WriteOutcome::ok_reply`, so every
  event store shares one outcome type.

- `service_url` moved from `[relay.auth]` to `[relay]` (the URL is
  also the NIP-62 vanish target, independent of AUTH); the error is
  `ServerError::ServiceUrl`. `nosfry_core`'s `AuthRules::new` takes a
  typed `Option<RelayUrl>` and `AuthRulesError` is gone.

- `Session::on_text` takes the current unix time in **milliseconds**
  (previously seconds), needed for millisecond-accurate rate buckets,
  and returns `Received { verb, rate_limited }` — the recognized client
  verb even when the message fails validation. `Command::Send` is now
  `Send { verb, text }` carrying the relay frame type.
- `MessageError` variants carry the recognized `ClientVerb`
  (`MessageError::verb()`), and `FilterVerb` is superseded by
  `ClientVerb`.
- `client_ip` returns `IpAddr` (the peer is mandatory now) and
  `ConnectionLimiter::try_acquire` takes `IpAddr` instead of
  `Option<IpAddr>`; a missing `ConnectInfo` in the HTTP handler is an
  internal error (500).
- A write-policy `reject` with an empty or absent `msg` answers
  `blocked: rejected by write policy` instead of strfry's bare empty
  message, because NIP-01 expects a prefixed rejection reason.
- `nosfry::serve` takes a `watch::Receiver<Config>` reload channel; the
  binary sends each config loaded on SIGHUP. Server state readers now
  go through `watch::Receiver<Arc<Live>>` instead of `Arc<Config>` —
  `ConnectionLimiter`'s caps are atomics, and `client_ip` /
  `try_acquire` already take the mandatory `IpAddr`.
- The LMDB format version is now 2 (three new lifecycle databases);
  databases created by 0.1.0 cannot be opened. Since 0.1.0 had no
  `export`, a 0.1.0 database must be re-imported from its source.
- `Store::write` returns `Written { outcomes, deleted }`, listing every
  seq removed inside the same transaction, instead of the bare outcome
  list.
- `Scan::new` takes a `now` argument (an event expiring at or before it
  is hidden and never counted) and its emit callback receives
  `(seq, json)`.
- **BREAKING:** kinds 4 and 1059 are no longer served to
  unauthenticated clients by default (`restricted_read_kinds`); set
  `restricted_read_kinds = []` to keep serving them openly.
- **BREAKING (API):** `Session::new` takes the client address's
  shared `Arc<AddressBuckets>` as a third argument. `Outbound`
  (crate-internal) now carries a shared process-wide pending-byte
  counter.
- **BREAKING (API):** `Session::new` takes the per-connection
  challenge; `Command::Publish` is `{ event, authed }` and
  `Command::Subscribe` carries a `ReadGate`; `Scan::new` and
  `Monitors::insert` take the gate; `Limits` is no longer `Copy`
  (new `auth` field); `Config::limits` is now fallible
  (`ServerError::ServiceUrl` on an invalid `relay.service_url`).
- `--config` is a global flag on the `nosfry` binary: it works before
  or after the subcommand, not just on `relay`.
- All logs go to stderr (previously stdout), keeping stdout clean for
  `export` and `scan` output.
- `ServerError::Serve` is renamed to `ServerError::Shutdown`: it now
  wraps the `JoinError` of the worker-shutdown task (it previously
  wrapped `std::io::Error`).
- `relay.compression.enabled` now defaults to `true` (strfry parity):
  yawc 0.4.4 bounds the inflated size of a compressed message by
  `max_websocket_payload_size`, so permessage-deflate is safe to
  negotiate. `sliding_window` stays enabled.

### Fixed

- NIP-86 is callable from browsers on both editions: the CORS
  preflight now allows `POST` and names `Authorization` explicitly
  (the Fetch wildcard never covers it), `Access-Control-Max-Age`
  caches the preflight for a day, and every management response —
  200, 400, 401, 405 — carries the allow-origin header. The header
  set lives in `nosfry_core::site::CORS_HEADERS`, shared with the
  Workers edition.
- `[relay] auto_ping_seconds = 0` is refused at load and on reload
  (`config: relay.auto_ping_seconds must be at least 1`): tokio's
  `interval` panics on a zero period and the interval doubles as the
  write deadline — unlike strfry, 0 cannot mean "no pings". A broken
  reload keeps the running configuration.
- A configured `relay.write_policy.plugin` is refused at load when
  `/bin/sh` does not exist: plugins spawn via `sh -c` like strfry,
  and the distroless runtime image has no shell — every publish
  would have been rejected `error: internal error`.

- Frames still queued when a connection ended (slow consumer, socket
  error, stall, shutdown) kept their bytes charged to the
  process-wide outbound budget forever: `nosfry_outbound_pending_bytes`
  grew without bound and, past `max_pending_outbound_bytes_total`,
  paused the scans of every connection. The queue's receiving end now
  releases all still-queued bytes when it is dropped.
- A reader process killed while holding a read transaction left its
  slot in `lock.mdb` permanently, so LMDB kept that reader's pages
  pinned and `data.mdb` grew without bound. `Store::open` now runs
  `mdb_reader_check` on startup and the relay's 10-second expiry sweep
  reaps stale readers on every tick.
- `nosfry compact` could leave a plausible-looking partial database at
  the destination path when killed mid-copy. It now writes to
  `<dest>.tmp`, fsyncs it, publishes by hard-linking to the final
  name, and fsyncs the directory; a leftover `.tmp` file makes the
  next run fail instead of clobbering it.
- Protected events (`["-"]` tag) were accepted although NIP-70
  requires rejecting them by default; kind-6/16 reposts embedding a
  protected event are now blocked too.
- A refused re-REQ (over the filter/tag/subscription limits,
  rate-limited, or a filter parse error) for an already-open
  subscription id now closes the old subscription before the `CLOSED`,
  so it no longer keeps delivering under an id the client was told is
  closed.
- `Filter::intrinsic_limit` bounded an `authors` + addressable-`kinds`
  filter without a `#d` condition to `authors * kinds`, so
  `{"kinds":[30023],"authors":[pk]}` served one article of fifty. It
  now follows nostr-tools `getFilterLimit`: the `authors * kinds` bound
  applies only when every kind is replaceable, `authors * kinds * #d`
  only when every kind is addressable and `#d` is present, and mixed or
  `#d`-less filters are unbounded.

### Security

- Upgraded to yawc 0.4.4: the inflated size of a permessage-deflate
  message is now bounded by `max_websocket_payload_size`, so a small
  compressed frame can no longer deliver an oversized payload
  (yawc#55, fixed upstream in infinitefield/yawc#56).
- `real_ip_header` now trusts the _last_ comma-separated value parsed
  as an `IpAddr` (the entry written by the proxy in front), falling
  back to the socket peer on missing or unparsable values — the first
  value is client-controlled.
- The HTTP listener now enforces a 10-second request-header read
  deadline (`axum::serve` installed no timer, so slowloris connections
  were held indefinitely) via an explicit hyper HTTP/1 accept loop
  with graceful shutdown.
- Inbound pings now flush their pong under the normal write deadline:
  a stalled pong write ends the connection instead of letting yawc's
  `obligated_sends` queue grow.
- Reader scans alternate between new and resumed queues, so a sustained
  stream of new `REQ`s can no longer starve long-running scans.

## [0.1.0] - 2026-10-19

### Added

- `nosfry-core`, the sans-IO protocol core. It has no async, no I/O, no clock,
  and no randomness, uses `forbid(unsafe_code)`, and builds cleanly for
  `wasm32-unknown-unknown`.
  - `event`: a strict NIP-01 ingest pipeline.
    - Parsing borrows from the input, requires all seven fields, and
      rejects duplicate keys, non-lowercase hex, and malformed `e`/`p`
      tags.
    - `EventLimits` sets the size, tag, and `created_at` window limits,
      with strfry's defaults.
    - `verify` checks the id hash, then the canonical JSON size, then
      the BIP-340 signature.
    - The result is an immutable `Event` with canonical JSON, a packed
      record, and the replaceable/addressable `address_hash`.
  - `packed`: a strfry-style index record with the same field order and
    tag encoding, but not byte-compatible with strfry.
  - `filter`: a compiled `Filter` with allocation-free matching.
    - Duplicate keys are rejected.
    - Unknown keys, `search`, and non-letter `#` keys are answered with
      `unsupported:`.
    - Hex values are accepted in any case and normalized.
    - An empty list makes the filter impossible.
  - `message`: an `Arc`-backed `SubId` that accepts any string of 1 to 64
    characters, including JSON escapes. Also exact-arity client message
    parsing and relay frame builders.
  - `limits`: `Limits { event, req }`.
  - `session`: a per-connection state machine with subscription
    generations.
  - `monitor`: the live-subscription inverted index, with O(1) removal.
- `nosfry-lmdb`, a synchronous LMDB event store.
  - The on-disk format is versioned, and sequence numbers persist and are
    never reused.
  - Each batch is written in one transaction. Replaceable and addressable
    events are evicted by `supersedes`.
  - Commits are fully durable: LMDB's meta page is synced before the
    write returns.
  - `Scan` runs time-sliced, snapshot-bounded index scans. Each step keeps
    one live iterator per cursor and streams results per completed
    `created_at` group, with cross-filter deduplication.
- `nosfry`, the native relay crate and binary.
  - **Threads:** one writer (group commits), M monitor shards (live index,
    snapshot authority, and scan control for their connections), and N
    readers, with exactly-once historical and live delivery.
  - **`OK` frames** are pushed by the writer straight onto the
    connection's outbound queue, after the batch is queued on every
    shard, so a `REQ` sent after `OK` always snapshots the event. Scan
    results arrive in chunks, and the first frame of each scan is sent
    alone.
  - **Backpressure:**
    - every connection has an outbound byte budget, and scans pause
      above a high-water mark;
    - slow consumers are closed with 1008;
    - every socket write is bounded;
    - half-open connections are closed after two ping intervals.
  - **Sockets:** `TCP_NODELAY` on every accepted socket. Queued frames are
    batched into one flush. permessage-deflate runs at level 1, with an
    optional sliding window.
  - **HTTP:** NIP-11 is served from a document serialized once, with
    empty optional fields omitted. Also CORS preflight and
    `real_ip_header`.
  - **Shutdown:** connections are tracked and get a 10-second deadline;
    the writer commits its last batch before worker threads join.
  - **Configuration:** TOML with strfry's section layout and defaults.
    Unknown keys are rejected. `nosfry.example.toml` lists every key;
    `NOSFRY_CONFIG` selects the file.
- Benchmark tooling under `bench/`:
  - the `nosfry-bench` harness for live fan-out latency, memory per
    connection, and relay CPU;
  - a Linux container recipe with relay and harness CPU pinning;
  - relayBench and nosfry-bench drivers;
  - the `aggregate.py` summary script.

[Unreleased]: https://github.com/qntx/nosfry/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/qntx/nosfry/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/qntx/nosfry/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/qntx/nosfry/releases/tag/v0.1.0
