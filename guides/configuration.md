# Configuration reference

nosfry reads one TOML file: `--config <path>`, else `$NOSFRY_CONFIG`, else
`./nosfry.toml`. Every section rejects unknown keys, and invalid or
contradictory values stop the relay at startup with a `config:` error.
`SIGHUP` reloads the file without a restart; a file that fails to load is
logged and the running configuration stays.

[`nosfry.example.toml`](../nosfry.example.toml) lists every key with its default
and parses to exactly the built-in defaults. The tables below list the same
keys; a test (`crates/nosfry/tests/docs.rs`) fails when a key or a default here
differs from that file.

In the **Reload** column, _restart_ means the key keeps its startup value until
the next start (a reload logs it as ignored), _new_ means a reload applies to
connections opened afterwards, and _live_ means it applies at once.

## Reference

<!-- feat/bounded-server (the max_connections default, the
pending-subscription budget) and fix/protocol-round1 change keys here:
the docs test fails until these tables match nosfry.example.toml. -->

### `[db]`

| Key                | Default          | Reload  | Meaning                                                                                                                                                   |
| ------------------ | ---------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `db.path`          | `"./nosfry-db"`  | restart | LMDB environment directory (`data.mdb`, `lock.mdb`).                                                                                                      |
| `db.map_size`      | `10995116277760` | restart | Map size in bytes (10 TiB). Address space only; the file grows as data is written and never shrinks.                                                      |
| `db.max_readers`   | `256`            | restart | Maximum concurrent read transactions, across the relay and administration commands.                                                                       |
| `db.no_read_ahead` | `false`          | restart | `MDB_NORDAHEAD`. Leave off: it cuts query throughput about 10x. On btrfs with a database larger than RAM, lower the filesystem's `read_ahead_kb` instead. |

### `[events]`

| Key                                                 | Default    | Reload | Meaning                                       |
| --------------------------------------------------- | ---------- | ------ | --------------------------------------------- |
| `events.max_event_size`                             | `65536`    | new    | Maximum canonical event size in bytes.        |
| `events.reject_events_newer_than_seconds`           | `900`      | new    | Refuse events this far in the future.         |
| `events.reject_events_older_than_seconds`           | `94608000` | new    | Refuse events this far in the past (3 years). |
| `events.reject_ephemeral_events_older_than_seconds` | `60`       | new    | Refuse ephemeral events this far in the past. |
| `events.max_num_tags`                               | `2000`     | new    | Maximum tags per event.                       |
| `events.max_tag_val_size`                           | `1024`     | new    | Maximum tag value size in bytes.              |

### `[relay]`

| Key                                         | Default       | Reload  | Meaning                                                                                                                     |
| ------------------------------------------- | ------------- | ------- | --------------------------------------------------------------------------------------------------------------------------- |
| `relay.bind`                                | `"127.0.0.1"` | restart | Listen address.                                                                                                             |
| `relay.port`                                | `7777`        | restart | Listen port.                                                                                                                |
| `relay.service_url`                         | `""`          | new     | The relay's public `ws://` or `wss://` URL. Required for NIP-42 AUTH, NIP-62 requests naming this relay, and NIP-86.        |
| `relay.nofiles`                             | `1000000`     | restart | Raise the soft open-file limit to this value at startup, capped by the hard limit; `0` leaves it unchanged.                 |
| `relay.real_ip_header`                      | `""`          | new     | Header carrying the client address; its last comma-separated value is trusted. Only behind a proxy that sets or appends it. |
| `relay.max_websocket_payload_size`          | `131072`      | new     | Maximum inbound WebSocket message in bytes, after inflation.                                                                |
| `relay.auto_ping_seconds`                   | `55`          | new     | WebSocket ping interval; at least 1. It also bounds socket writes and idle closes.                                          |
| `relay.tcp_keepalive`                       | `false`       | new     | Set `SO_KEEPALIVE` on accepted sockets.                                                                                     |
| `relay.max_pending_outbound_bytes`          | `33554432`    | new     | Queued outbound bytes above which one connection is closed (1008).                                                          |
| `relay.max_pending_outbound_bytes_total`    | `1073741824`  | restart | Process-wide queued outbound bytes; over it, scans pause for connections that are behind. `0` is unlimited.                 |
| `relay.max_sync_memory_bytes`               | `1073741824`  | restart | Process-wide negentropy budget, 40 bytes per record. `0` is unlimited.                                                      |
| `relay.max_subscription_bytes_total`        | `1073741824`  | restart | Process-wide estimated memory of live subscriptions. `0` is unlimited.                                                      |
| `relay.max_connections`                     | `0`           | live    | Maximum WebSocket connections. `0` is unlimited: set it on a public relay.                                                  |
| `relay.max_connections_per_ip`              | `128`         | live    | Maximum WebSocket connections per client address (IPv6 per /64). `0` is unlimited.                                          |
| `relay.metrics`                             | `false`       | restart | Serve unauthenticated `GET /metrics` (Prometheus) on the relay port.                                                        |
| `relay.query_timeslice_budget_microseconds` | `10000`       | restart | Time slice of one stored scan before it yields to the next.                                                                 |

### `[relay.limits]`

| Key                                    | Default   | Reload  | Meaning                                                                                    |
| -------------------------------------- | --------- | ------- | ------------------------------------------------------------------------------------------ |
| `relay.limits.max_req_filter_size`     | `200`     | new     | Maximum filters per `REQ`.                                                                 |
| `relay.limits.max_subs_per_connection` | `200`     | new     | Maximum open subscriptions per connection.                                                 |
| `relay.limits.max_filter_limit`        | `500`     | restart | Cap on a filter's `limit` for stored scans.                                                |
| `relay.limits.max_filter_limit_count`  | `1000000` | restart | Index entries one `COUNT` may examine before answering approximately; `0` disables NIP-45. |
| `relay.limits.max_sync_events`         | `1000000` | restart | Records one negentropy sync may hold; `0` disables NIP-77.                                 |
| `relay.limits.max_tags_per_filter`     | `3`       | new     | Maximum `#x` conditions per filter.                                                        |

### `[relay.filter_validation]`

| Key                                             | Default | Reload | Meaning                                                                        |
| ----------------------------------------------- | ------- | ------ | ------------------------------------------------------------------------------ |
| `relay.filter_validation.enabled`               | `false` | new    | Refuse `REQ` and `COUNT` filters that break the rules below (strfry parity).   |
| `relay.filter_validation.max_filters_per_req`   | `3`     | new    | Filters allowed in one request.                                                |
| `relay.filter_validation.min_filters_per_req`   | `1`     | new    | Filters required in one request.                                               |
| `relay.filter_validation.max_kinds_per_filter`  | `3`     | new    | Kinds allowed per filter.                                                      |
| `relay.filter_validation.allowed_kinds`         | `[]`    | new    | Kinds a filter may list; empty allows all. When set, a filter must list kinds. |
| `relay.filter_validation.require_author_or_tag` | `false` | new    | Each filter must pin exactly one author, or one `#p` or `#e` value.            |

### `[relay.rate_limits]`

| Key                                      | Default | Reload | Meaning                                                    |
| ---------------------------------------- | ------- | ------ | ---------------------------------------------------------- |
| `relay.rate_limits.events_per_second`    | `20`    | new    | EVENT refill rate per connection; `0` disables the bucket. |
| `relay.rate_limits.events_burst`         | `100`   | new    | EVENT burst per connection.                                |
| `relay.rate_limits.reqs_per_second`      | `20`    | new    | REQ, COUNT and NEG-OPEN refill rate per connection.        |
| `relay.rate_limits.reqs_burst`           | `100`   | new    | REQ burst per connection.                                  |
| `relay.rate_limits.ip_events_per_second` | `100`   | new    | EVENT refill rate shared by one client address.            |
| `relay.rate_limits.ip_events_burst`      | `500`   | new    | EVENT burst shared by one client address.                  |
| `relay.rate_limits.ip_reqs_per_second`   | `100`   | new    | REQ refill rate shared by one client address.              |
| `relay.rate_limits.ip_reqs_burst`        | `500`   | new    | REQ burst shared by one client address.                    |

### `[relay.write_policy]`

| Key                                  | Default | Reload | Meaning                                                                                 |
| ------------------------------------ | ------- | ------ | --------------------------------------------------------------------------------------- |
| `relay.write_policy.plugin`          | `""`    | live   | strfry-compatible plugin command, run with `/bin/sh -c`; empty disables it.             |
| `relay.write_policy.timeout_seconds` | `10`    | live   | Seconds the plugin has to answer before the event is rejected and the plugin restarted. |

### `[relay.auth]`

| Key                                    | Default     | Reload | Meaning                                                                      |
| -------------------------------------- | ----------- | ------ | ---------------------------------------------------------------------------- |
| `relay.auth.restricted_read_kinds`     | `[4, 1059]` | new    | Kinds served only to authenticated readers (direct messages and gift wraps). |
| `relay.auth.restrict_read_to_involved` | `true`      | new    | Serve restricted kinds only to the author or a `p`-tagged pubkey.            |

### `[relay.management]`

| Key                       | Default | Reload | Meaning                                                                   |
| ------------------------- | ------- | ------ | ------------------------------------------------------------------------- |
| `relay.management.admins` | `[]`    | live   | Hex pubkeys allowed to call the NIP-86 API; empty turns the endpoint off. |

### `[relay.threads]`

| Key                      | Default | Reload  | Meaning                          |
| ------------------------ | ------- | ------- | -------------------------------- |
| `relay.threads.readers`  | `3`     | restart | Stored-scan reader threads.      |
| `relay.threads.monitors` | `3`     | restart | Live-subscription shard threads. |

### `[relay.compression]`

| Key                                | Default | Reload | Meaning                                                                   |
| ---------------------------------- | ------- | ------ | ------------------------------------------------------------------------- |
| `relay.compression.enabled`        | `true`  | new    | Negotiate permessage-deflate.                                             |
| `relay.compression.sliding_window` | `false` | new    | Keep per-connection deflate state (strfry's default, about 370 KiB each). |

### `[relay.info]`

| Key                           | Default    | Reload | Meaning                            |
| ----------------------------- | ---------- | ------ | ---------------------------------- |
| `relay.info.name`             | `"nosfry"` | live   | NIP-11 `name`.                     |
| `relay.info.description`      | `""`       | live   | NIP-11 `description`.              |
| `relay.info.pubkey`           | `""`       | live   | NIP-11 `pubkey`, 64 lowercase hex. |
| `relay.info.contact`          | `""`       | live   | NIP-11 `contact`.                  |
| `relay.info.icon`             | `""`       | live   | NIP-11 `icon` URL.                 |
| `relay.info.banner`           | `""`       | live   | NIP-11 `banner` URL.               |
| `relay.info.self`             | `""`       | live   | NIP-11 `self`, 64 lowercase hex.   |
| `relay.info.terms_of_service` | `""`       | live   | NIP-11 `terms_of_service` URL.     |
| `relay.info.privacy_policy`   | `""`       | live   | NIP-11 `privacy_policy` URL.       |

`relay.info.supported_nips` (unset by default) replaces the computed
`supported_nips` list verbatim; use it when a write-policy plugin implements a
NIP the relay itself does not.

## A minimal public configuration

```toml
[db]
path = "/var/lib/nosfry/db"

[relay]
service_url = "wss://relay.example.com"
real_ip_header = "X-Forwarded-For"
max_connections = 100000

[relay.info]
name = "relay.example.com"
contact = "mailto:admin@example.com"
```

Keep `relay.bind = "127.0.0.1"` and let the reverse proxy
([deployment.md](deployment.md)) terminate TLS and rate-limit HTTP. 100,000
idle connections cost about 0.7 GiB at 7.2 KiB each; size `max_connections`
to the memory you give the relay.

## Behaviour behind the keys

### Limits and abuse resistance

- **Rate limits.** `relay.rate_limits` throttles each connection with EVENT and REQ token buckets (default 20/s, burst 100). An over-limit EVENT gets `OK false rate-limited:` and an over-limit REQ gets `CLOSED rate-limited:`. A `*_per_second` of 0 disables that bucket.
- **Per-address buckets.** The `ip_*` keys add a second pair of buckets shared by every connection of one client address (default 100/s, burst 500 each). A message is refused when either its connection bucket or its address bucket is empty, so 128 connections cannot each spend 20 events per second.
- **Connection caps.** `relay.max_connections` caps all WebSocket connections and `relay.max_connections_per_ip` (default 128) caps them per client address, with IPv6 grouped per /64. An over-cap upgrade is refused with `429 Too Many Requests` before the handshake.
- **Client address.** Behind a proxy, set `relay.real_ip_header`; the last comma-separated value of that header is trusted, because the proxy appends its peer's address.
- **Subscription memory.** `relay.max_subscription_bytes_total` (default 1 GiB, 0 disables, restart-only) bounds the estimated memory of all live subscriptions: the compiled filters plus 128 bytes per indexed value. A REQ past it gets `CLOSED blocked: subscription capacity exhausted`, and `nosfry_subscription_bytes` reports usage.
- **Outbound memory.** `relay.max_pending_outbound_bytes` bounds one connection's queue, and a slow consumer past it is disconnected. `relay.max_pending_outbound_bytes_total` (default 1 GiB, 0 disables, restart-only) bounds the sum across connections. Over budget, scans pause only on connections already more than one chunk behind; caught-up readers keep scanning.

### Filter validation

`[relay.filter_validation]` (off by default) restricts the shape of `REQ` and `COUNT` filters, with strfry's keys and defaults. A request that breaks a rule is answered `CLOSED blocked: <reason>`. `NEG-OPEN` is exempt, as in strfry, so a full sync stays possible.

- `min_filters_per_req` and `max_filters_per_req` (1 and 3) bound the filters per request.
- `max_kinds_per_filter` (3) bounds the kinds per filter.
- `allowed_kinds` (empty allows all) limits which kinds a filter may list. When it is set, a filter without `kinds` is refused too; strfry lets such a filter through, which returns every kind.
- `require_author_or_tag` requires each filter to pin exactly one `authors` value, one `#p` value, or one `#e` value.
- The section reloads on SIGHUP for new connections. Contradictory bounds fail at load and on reload.

### Relay information and HTTP

- `[relay.info]` holds the NIP-11 fields: `name`, `description`, `pubkey`, `self`, `contact`, `icon`, `banner`, `terms_of_service`, and `privacy_policy`.
  - `pubkey` and `self` must be 64 lowercase hex; convert an npub first.
  - `supported_nips` replaces the computed list. Use it when a write-policy plugin implements a NIP the relay itself does not.
- `limitation.restricted_writes` is `true` while a NIP-86 pubkey or kind allow list is non-empty.
- `GET /` from a browser returns an HTML page built from the same fields. Only `http`, `https`, and `mailto` values become links, and every value is escaped.
- `/nodeinfo/2.1` describes the software. `/.well-known/nodeinfo` links to it on the host of `service_url`, and is 404 while `service_url` is unset.

### Logging

Logs go to stderr at `info` (set `RUST_LOG_JSON=1` for JSON). strfry's `relay.logging` switches are `RUST_LOG` targets instead of configuration. They are off by default so a hostile client cannot flood the log:

| strfry                                    | `RUST_LOG` directive    | Output                                                          |
| ----------------------------------------- | ----------------------- | --------------------------------------------------------------- |
| `invalidEvents`                           | `nosfry::ingest=debug`  | every `OK` sent, accepted or rejected, and every relay `CLOSED` |
| `dumpInAll`, `dumpInEvents`, `dumpInReqs` | `nosfry::inbound=trace` | every inbound message                                           |
| `dbScanPerf`                              | `nosfry::scan=debug`    | one line per finished stored scan or `COUNT`, with timings      |

For example: `RUST_LOG=info,nosfry::ingest=debug`.

`[relay] tcp_keepalive = true` (strfry `enableTcpKeepalive`) sets `SO_KEEPALIVE` on new sockets, with the operating system's timers, to detect connections a proxy dropped silently.

### Compression

`[relay.compression]` negotiates permessage-deflate. It is on by default and differs from strfry's default as follows:

- `sliding_window = false` imposes no context takeover in both directions, which RFC 7692 lets a server do. Deflate state is borrowed from one server-wide pool for each message, so a connection costs a few KiB.
- On the real-event corpus this sends 18% (live) to 52% (stored batches) more bytes than `sliding_window = true`, and still about 40% fewer than no compression.
- `sliding_window = true` is strfry's default: every connection keeps its own deflate state, about 370 KiB once a message has been compressed. Choose it only when bandwidth matters more than connection count.
- Messages under 128 bytes always go out uncompressed. These are every reply type, which deflate cannot shrink. Inflated messages are bounded by `max_websocket_payload_size`, like uncompressed ones: a compressed frame that would inflate past it closes the connection.

### Write policy

`[relay.write_policy]` runs a strfry-compatible plugin; plugins written for strfry run unchanged.

- Every verified event is sent to `/bin/sh -c <plugin>` as one JSON line: `{"type":"new","event":…,"receivedAt":…,"sourceType":"IP4"|"IP6","sourceInfo":"<ip>"}`, plus `"authed":"<hex>"` once the connection has authenticated.
- The plugin answers `accept`, `reject`, or `shadowReject`. The event is then stored and broadcast, refused with `OK false`, or acknowledged and silently dropped.
- `timeout_seconds` (default 10) bounds each answer. On a timeout or a plugin error, the event is rejected with `error: internal error` and a fresh plugin process serves the next event.
- A plugin configured as a bare path restarts when the file's mtime changes.

### Authentication and protected events

`[relay] service_url` (empty by default) is the relay's canonical `ws://` or `wss://` address. Clients echo it in the AUTH event's `relay` tag, and NIP-62 requests name it.

- When it is set, NIP-11 lists 42 and the relay challenges lazily: only when a client sends a REQ with a fully restricted filter, or publishes a protected event. A connection may authenticate up to 8 pubkeys.
- `[relay.auth] restricted_read_kinds` (default `[4, 1059]`, direct messages and gift wraps) are served only to authenticated readers. With `restrict_read_to_involved = true` (the default), they are served only to the author or a `p`-tagged recipient.
- A REQ whose filters list only restricted kinds is refused: `CLOSED auth-required:` when AUTH is enabled, `CLOSED restricted:` otherwise. Mixed filters still subscribe but hide restricted events, and hidden events never consume `limit`. Without a `service_url`, direct messages are stored but never served.
- NIP-70 protected events (a `["-"]` tag) are rejected unless AUTH is configured and the author is authenticated. Reposts (kinds 6 and 16) embedding a protected event are always blocked. AUTH events (kind 22242) are never stored or broadcast.

### Request to vanish (NIP-62)

A kind-62 event whose `relay` tags name `service_url`, or hold `ALL_RELAYS` (which applies even without a URL), deletes every event the author published with `created_at` at or before the request. Kind 62 itself is never deleted. Kind-1059 gift wraps p-tagged to the author in that window are deleted too.

- Deletion runs as background sweeps of 10,000 events per step, and it resumes after a restart.
- Republishing a vanished event is refused with `blocked: request to vanish`.
- The request bypasses the write-policy plugin, as NIP-62 requires. A request naming only other relays is stored with no local effect.

### COUNT (NIP-45)

`["COUNT", <sub>, <filters>…]` answers with one frame counting the events the same filters would return, then frees the subscription id.

- COUNT shares the REQ rate buckets, subscription slots, and filter validation. It takes the same snapshot as a REQ, so an event is counted as soon as its `OK` is sent.
- The filter `limit` is ignored, and restricted kinds are counted only for readers allowed to see them.
- `relay.limits.max_filter_limit_count` (default 1,000,000; 0 disables COUNT) caps the index entries one COUNT may examine. Past it, the answer carries `"approximate": true`.
- A request with exactly one filter holding exactly one tag condition of one value also gets `"hll"`: the 256-register HyperLogLog of the counted authors, for client-side follower counts.

### Negentropy (NIP-77)

`NEG-OPEN` runs a negentropy sync against the events one filter would return. The scan matches, limits, gates, and expires exactly like a REQ, but fetches no payloads.

- Syncs have their own subscription namespace, share the REQ rate buckets and the subscription cap, and are closed after 60 s without a `NEG-MSG` (`closed: idle timeout`).
- `relay.limits.max_sync_events` (default 1,000,000; 0 disables) caps the records one sync may hold. Past it, the answer is `blocked: too many query results`, with the cap as a fourth element.
- `relay.max_sync_memory_bytes` (default 1 GiB, 0 unlimited) is a process-wide budget at 40 bytes per record. Past it, opens answer `blocked: sync capacity exhausted`.
