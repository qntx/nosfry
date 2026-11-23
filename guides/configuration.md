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

### `[db]`

| Key                | Default          | Reload  | Meaning                                                                                                                                                   |
| ------------------ | ---------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `db.path`          | `"./nosfry-db"`  | restart | LMDB environment directory (`data.mdb`, `lock.mdb`).                                                                                                      |
| `db.map_size`      | `10995116277760` | restart | Map size in bytes (10 TiB). Address space only; the file grows as data is written and never shrinks.                                                      |
| `db.max_readers`   | `256`            | restart | Maximum concurrent read transactions, across the relay and administration commands.                                                                       |
| `db.no_read_ahead` | `false`          | restart | `MDB_NORDAHEAD`. Leave off: it cuts query throughput about 10x. On btrfs with a database larger than RAM, lower the filesystem's `read_ahead_kb` instead. |

### `[events]`

| Key                                                 | Default    | Reload | Meaning                                                                                               |
| --------------------------------------------------- | ---------- | ------ | ----------------------------------------------------------------------------------------------------- |
| `events.max_event_size`                             | `65536`    | new    | Maximum canonical event size in bytes; `relay.max_websocket_payload_size` must be at least this + 10. |
| `events.reject_events_newer_than_seconds`           | `900`      | new    | Refuse events this far in the future.                                                                 |
| `events.reject_events_older_than_seconds`           | `94608000` | new    | Refuse events this far in the past (3 years).                                                         |
| `events.reject_ephemeral_events_older_than_seconds` | `60`       | new    | Refuse ephemeral events this far in the past.                                                         |
| `events.max_num_tags`                               | `2000`     | new    | Maximum tags per event.                                                                               |
| `events.max_tag_val_size`                           | `1024`     | new    | Maximum tag value size in bytes.                                                                      |

A Marmot-ready 2 MiB profile is `max_event_size = 2097152` with
`max_websocket_payload_size = 2097168`.

### `[relay]`

| Key                                         | Default      | Reload  | Meaning                                                                                                                                                                                                  |
| ------------------------------------------- | ------------ | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `relay.service_url`                         | `""`         | new     | The relay's public `ws://` or `wss://` URL. Required for NIP-42 AUTH, NIP-62 requests naming this relay, and NIP-86. Empty disables AUTH: restricted kinds are then refused on write.                    |
| `relay.nofiles`                             | `1000000`    | restart | Raise the soft open-file limit to this value at startup, capped by the hard limit; `0` leaves it unchanged.                                                                                              |
| `relay.max_websocket_payload_size`          | `131072`     | new     | Maximum inbound WebSocket frame in bytes, after inflation — inclusive, one byte more closes with 1009. Must be at least `events.max_event_size + 10`, or the config is refused at load and reload.       |
| `relay.auto_ping_seconds`                   | `55`         | new     | WebSocket ping interval; at least 1. It also bounds socket writes and idle closes.                                                                                                                       |
| `relay.tcp_keepalive`                       | `false`      | new     | Set `SO_KEEPALIVE` on accepted sockets.                                                                                                                                                                  |
| `relay.max_pending_outbound_bytes`          | `33554432`   | new     | Queued outbound bytes above which one connection is closed (1008). Live matches buffered while a subscription's stored scan runs reserve bytes against it too, so a connection holds at most twice this. |
| `relay.max_pending_outbound_bytes_total`    | `1073741824` | restart | Process-wide queued outbound bytes; over it, scans pause for connections that are behind. `0` is unlimited.                                                                                              |
| `relay.max_sync_memory_bytes`               | `1073741824` | restart | Process-wide negentropy budget, 40 bytes per record. `0` is unlimited.                                                                                                                                   |
| `relay.max_subscription_bytes_total`        | `1073741824` | restart | Process-wide estimated memory of live subscriptions. `0` is unlimited.                                                                                                                                   |
| `relay.metrics`                             | `false`      | restart | Serve unauthenticated `GET /metrics` (Prometheus) on the relay port.                                                                                                                                     |
| `relay.query_timeslice_budget_microseconds` | `10000`      | restart | Time slice of one stored scan before it yields to the next.                                                                                                                                              |

`relay.max_connections` (unset by default, reload: live) caps all WebSocket
connections and is always finite. Unset, it is derived from the soft open-file
limit after `relay.nofiles` raised it: `limit - 64 - limit/8`, which keeps 64
descriptors for the process and one eighth of the limit for sockets the cap
does not count (plain HTTP requests and handshakes in progress) — 874,936 at
the default `nofiles`, 832 under a soft limit of 1,024. An explicit value must
be at least 1 and at most that ceiling: `0` or a larger value stops the relay
at startup with a `config:` error, and a reload carrying one is refused and
keeps the running configuration. The relay logs the effective cap at startup
(`connection cap max_connections=… soft_nofile=…`). The derived value bounds
descriptors, not memory: on a host with less memory than the descriptors
allow, set it explicitly.

`relay.service_url_aliases` (unset by default, reload: new) lists further
`ws://` or `wss://` URLs the relay answers to — an onion address, an old
domain. A NIP-42 AUTH `relay` tag, a NIP-62 `relay` tag and a NIP-98 `u` tag
may name `service_url` or any alias, compared like `service_url` (scheme,
case and path ignored). Aliases need a `service_url`; NIP-11, the landing page
and NodeInfo name only `service_url`.

### `[[relay.listen]]`

| Key            | Default                                                                      | Reload  | Meaning                                                                          |
| -------------- | ---------------------------------------------------------------------------- | ------- | -------------------------------------------------------------------------------- |
| `relay.listen` | `[{ address = "127.0.0.1:7777", profile = "default", real_ip_header = "" }]` | restart | The sockets the relay accepts connections on: one `[[relay.listen]]` table each. |

Each `[[relay.listen]]` table holds:

- `address` (required): `"<ip>:<port>"`, `"[<ipv6>]:<port>"`,
  `"unix:<absolute path>"` for a Unix-domain socket, or
  `"onion:<nickname>"` for an embedded onion service (needs a build
  with `--features onion`; the nickname is lowercase ASCII
  alphanumerics, `_` and `-`, non-empty, not starting with `-`;
  `real_ip_header` must be empty on an onion listener).
- `profile` (default `"default"`): the `[relay.profiles.<name>]` whose
  connection cap and rate limits apply to this listener's connections.
- `real_ip_header` (default `""`): a header carrying the client address,
  whose last comma-separated value is trusted. Set it only on a listener that
  is reachable only through a proxy that sets or appends it.

At least one listener is required, addresses must be unique, and every
`profile` must exist; the relay refuses to start otherwise. A reload keeps the
running listeners and logs `relay.listen` among the ignored restart-only keys. See
[Listeners and peers](#listeners-and-peers).

### `[relay.onion]`

Settings of the embedded onion service — used by `onion:` listeners
and by `nosfry sync` dialing a `.onion` peer, both of which need a
build with `--features onion`. The derived `ws://<addr>.onion` URLs
act as the relay's name: with an empty `service_url` the first is the
canonical URL, otherwise all are aliases.

| Key                                   | Default           | Reload  | Meaning                                                                                                                                                 |
| ------------------------------------- | ----------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `relay.onion.state_dir`               | `"./nosfry-onion"` | restart | Arti state root (`state/` with the service keystores, `cache/` beneath it). A missing directory is created with mode 0700; an existing one must already be mode 0700. `nosfry sync` shares it for `.onion` peers (read-only next to a running relay). |
| `relay.onion.max_circuits`            | `256`             | restart | Concurrent rendezvous circuits per onion listener, including ones being established; further introductions are dropped.                                   |
| `relay.onion.max_streams_per_circuit` | `128`             | restart | Streams a client may open on one circuit before Arti closes it; a client multiplexes all its connections onto that circuit.   |                                                                                         |
| `relay.onion.intro_rate`              | `0`               | restart | Introduction rate limit announced to the intro points (requests per second); `0` = unset, and then `intro_burst` must be `0` too.                        |
| `relay.onion.intro_burst`             | `0`               | restart | Introduction burst paired with `intro_rate`.                                                                                                            |
| `relay.onion.onion_location`          | `false`           | live    | Advertise the first onion address as `Onion-Location` on NIP-11, the landing page and upgrade responses of non-onion listeners.                           |

### `[relay.limits]`

| Key                                    | Default   | Reload  | Meaning                                                                                                                               |
| -------------------------------------- | --------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `relay.limits.max_req_filter_size`     | `200`     | new     | Maximum filters per `REQ`.                                                                                                            |
| `relay.limits.max_subs_per_connection` | `200`     | new     | Maximum open subscriptions per connection. Twice this many queries (`REQ`, `COUNT`, `NEG-OPEN`) may wait for a reader per connection. |
| `relay.limits.max_filter_limit`        | `500`     | restart | Cap on a filter's `limit` for stored scans.                                                                                           |
| `relay.limits.max_filter_limit_count`  | `1000000` | restart | Index entries one `COUNT` may examine before answering approximately; `0` disables NIP-45.                                            |
| `relay.limits.max_sync_events`         | `1000000` | restart | Records one negentropy sync may hold; `0` disables NIP-77.                                                                            |
| `relay.limits.max_tags_per_filter`     | `3`       | new     | Maximum `#x` conditions per filter.                                                                                                   |

### `[relay.filter_validation]`

| Key                                             | Default | Reload | Meaning                                                                        |
| ----------------------------------------------- | ------- | ------ | ------------------------------------------------------------------------------ |
| `relay.filter_validation.enabled`               | `false` | new    | Refuse `REQ` and `COUNT` filters that break the rules below (strfry parity).   |
| `relay.filter_validation.max_filters_per_req`   | `3`     | new    | Filters allowed in one request.                                                |
| `relay.filter_validation.min_filters_per_req`   | `1`     | new    | Filters required in one request.                                               |
| `relay.filter_validation.max_kinds_per_filter`  | `3`     | new    | Kinds allowed per filter.                                                      |
| `relay.filter_validation.allowed_kinds`         | `[]`    | new    | Kinds a filter may list; empty allows all. When set, a filter must list kinds. |
| `relay.filter_validation.require_author_or_tag` | `false` | new    | Each filter must pin exactly one author, or one `#p` or `#e` value.            |

### `[relay.profiles.<name>]`

A profile holds the per-peer connection cap and the rate limits of the
listeners that name it. `default` always exists; any other name defines a
profile with the same keys and defaults. Listeners that share a profile share
its per-peer accounting. A reload applies profile changes, and a reload that
removes a profile a running listener uses is refused.

| Key                                                       | Default | Reload | Meaning                                                                                                              |
| --------------------------------------------------------- | ------- | ------ | -------------------------------------------------------------------------------------------------------------------- |
| `relay.profiles.default.max_connections_per_peer`         | `128`   | live   | Maximum WebSocket connections per peer: a client address (IPv6 per /64), or a whole unix listener. `0` is unlimited. |
| `relay.profiles.default.rate_limits.events_per_second`    | `20`    | new    | EVENT refill rate per connection; `0` disables the bucket.                                                           |
| `relay.profiles.default.rate_limits.events_burst`         | `100`   | new    | EVENT burst per connection.                                                                                          |
| `relay.profiles.default.rate_limits.reqs_per_second`      | `20`    | new    | REQ, COUNT and NEG-OPEN refill rate per connection.                                                                  |
| `relay.profiles.default.rate_limits.reqs_burst`           | `100`   | new    | REQ burst per connection.                                                                                            |
| `relay.profiles.default.rate_limits.ip_events_per_second` | `100`   | new    | EVENT refill rate shared by one peer.                                                                                |
| `relay.profiles.default.rate_limits.ip_events_burst`      | `500`   | new    | EVENT burst shared by one peer.                                                                                      |
| `relay.profiles.default.rate_limits.ip_reqs_per_second`   | `100`   | new    | REQ refill rate shared by one peer.                                                                                  |
| `relay.profiles.default.rate_limits.ip_reqs_burst`        | `500`   | new    | REQ burst shared by one peer.                                                                                        |

### `[relay.write_policy]`

| Key                                  | Default | Reload | Meaning                                                                                 |
| ------------------------------------ | ------- | ------ | --------------------------------------------------------------------------------------- |
| `relay.write_policy.plugin`          | `""`    | live   | strfry-compatible plugin command, run with `/bin/sh -c`; empty disables it.             |
| `relay.write_policy.timeout_seconds` | `10`    | live   | Seconds the plugin has to answer before the event is rejected and the plugin restarted. |

### `[relay.access]`

| Key                            | Default                                                                          | Reload | Meaning                                                                                                 |
| ------------------------------ | -------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------- |
| `relay.access.anonymous_kinds` | `[]`                                                                             | new    | Kinds whose author is not an identity: exempt from the NIP-86 pubkey allow list (e.g. Marmot kind 445). |
| `relay.access.rules`           | `[{ kinds = [4, 1059, 21059], read = ["author", "recipient"], write = "open" }]` | new    | `[[relay.access.rules]]` entries; `[]` disables all gating. See Access rules below.                     |

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

### `[blossom]`

The Blossom blob server (the `blossom` cargo feature): BUD-01/02/06/11/12/13
blob hosting served on its own `[[blossom.listen]]` addresses, never on the
relay listeners. `public_url` must be an `http://` or `https://` URL whose
host differs from `relay.service_url` and every alias, so uploaded HTML/SVG
can never run in the relay's origin; blobs are advertised as
`<public_url>/<sha256>.<ext>`.

| Key                              | Default                            | Reload  | Meaning                                                                             |
| -------------------------------- | ---------------------------------- | ------- | ----------------------------------------------------------------------------------- |
| `blossom.enabled`                | `false`                            | restart | Serve Blossom on `[[blossom.listen]]`.                                              |
| `blossom.public_url`             | `""`                               | restart | The blob server's public `http(s)://host[:port]` URL — required when enabled.       |
| `blossom.dir`                    | `"./nosfry-blobs"`                 | restart | Blob store directory (blob files, LMDB metadata, `tmp/`, `trash/`).                 |
| `blossom.upload`                 | `"allowed"`                        | live    | Who may upload: `"allowed"` (admins plus NIP-86 allowed pubkeys) or `"everyone"`.   |
| `blossom.max_blob_size`          | `104857600`                        | live    | Maximum blob size in bytes (at least 1, at most `max_total_bytes`).                 |
| `blossom.max_total_bytes`        | `10737418240`                      | live    | Global cap on stored blob bytes (at least 1).                                       |
| `blossom.quota_bytes`            | `1073741824`                       | live    | Per-pubkey stored-byte quota (at least 1).                                          |
| `blossom.quota_blobs`            | `10000`                            | live    | Per-pubkey blob-count quota (at least 1).                                           |
| `blossom.mime_types`             | `[]`                               | live    | Allowed `type/subtype` or `type/*` media types, lowercase; empty allows every type. |
| `blossom.max_concurrent_uploads` | `16`                               | restart | Simultaneous upload streams (`1..=1024`; at most 4 per pubkey).                     |
| `blossom.max_connections`        | `1024`                             | restart | Simultaneous blossom connections; accept waits for a free slot.                     |
| `blossom.listen`                 | `[{ address = "127.0.0.1:7778" }]` | restart | The sockets the blob server accepts on: one `[[blossom.listen]]` table each.        |

### `[[blossom.listen]]`

Each `[[blossom.listen]]` table holds one key:

- `address` (required): `"<ip>:<port>"`, `"[<ipv6>]:<port>"`, or
  `"unix:<absolute path>"` — the same forms as `[[relay.listen]]` except
  `onion:`, which is refused.

Enabled requires at least one listener, addresses must be unique and must
not collide with a `[[relay.listen]]` address. A reload keeps the running
listeners and logs `blossom.listen` among the ignored restart-only keys.

## A minimal public configuration

```toml
[db]
path = "/var/lib/nosfry/db"

[relay]
service_url = "wss://relay.example.com"
max_connections = 100000

[[relay.listen]]
address = "127.0.0.1:7777"
real_ip_header = "X-Forwarded-For"

[relay.info]
name = "relay.example.com"
contact = "mailto:admin@example.com"
```

Keep the listener on `127.0.0.1` (or a unix socket) and let the reverse proxy
([deployment.md](deployment.md)) terminate TLS and rate-limit HTTP. 100,000
idle connections cost about 0.7 GiB at 7.2 KiB each; size `max_connections`
to the memory you give the relay. Left unset it is derived from the open-file
limit (874,936 at the default `nofiles`), which bounds descriptors, not memory.

## Behaviour behind the keys

### Limits and abuse resistance

- **Rate limits.** Each listener profile's `rate_limits` throttles each connection with EVENT and REQ token buckets (default 20/s, burst 100). An over-limit EVENT gets `OK false rate-limited:` and an over-limit REQ gets `CLOSED rate-limited:`, each carrying the NIP-01 retry hint (milliseconds until the bucket refills). A `*_per_second` of 0 disables that bucket. Frames that fail to parse spend REQ tokens too: within the budget each gets a `NOTICE` (an unknown verb is quoted to at most 32 bytes), past it none.
- **Per-peer buckets.** The `ip_*` keys add a second pair of buckets shared by every connection of one peer (default 100/s, burst 500 each). A message is refused when either its connection bucket or its peer bucket is empty, so 128 connections cannot each spend 20 events per second.
- **Connection caps.** `relay.max_connections` (derived from the open-file limit unless set, see [`[relay]`](#relay)) caps all WebSocket connections and a profile's `max_connections_per_peer` (default 128) caps them per peer, with IPv6 grouped per /64. An over-cap upgrade is refused with `429 Too Many Requests` before the handshake.
- **Client address.** Behind a proxy, set the listener's `real_ip_header`; the last comma-separated value of that header is trusted, because the proxy appends its peer's address.
- **Subscription memory.** `relay.max_subscription_bytes_total` (default 1 GiB, 0 disables, restart-only) bounds the estimated memory of all live subscriptions: the compiled filters plus 128 bytes per indexed value. A REQ past it gets `CLOSED blocked: subscription capacity exhausted`, and `nosfry_subscription_bytes` reports usage.
- **Outbound memory.** `relay.max_pending_outbound_bytes` bounds one connection's queue, and a slow consumer past it is disconnected. `relay.max_pending_outbound_bytes_total` (default 1 GiB, 0 disables, restart-only) bounds the sum across connections. Over budget, scans pause only on connections already more than one chunk behind; caught-up readers keep scanning. Live events matched while a subscription's stored scan is still running are buffered against the same two budgets, so one connection holds at most twice `max_pending_outbound_bytes`; a subscription whose buffer no longer fits, or reaches 4,096 events, is closed with `CLOSED error: subscription fell behind` and the connection stays open.
- **Reader admission.** Stored scans (`REQ`, `COUNT`, `NEG-OPEN`) and `NEG-MSG` steps wait for the reader threads in bounded queues: each reader admits at most 4,096 queries, and each connection may have at most twice `max_subs_per_connection` queries waiting (both fixed). A `REQ` or `COUNT` past its connection's bound is answered `CLOSED rate-limited: too many pending queries`, and one that finds the readers saturated `CLOSED rate-limited: relay busy`; a `NEG-OPEN` gets a `NEG-ERR` with the same reason, and a `NEG-MSG` on a saturated reader `NEG-ERR rate-limited: relay busy`. `nosfry_reader_busy_total{msg}` counts the refused work and `nosfry_reader_jobs` the admitted queries.

### Listeners and peers

A profile's connection cap and `ip_*` buckets count per **peer**: the client
address of a TCP connection (IPv4 per address, IPv6 per /64), or the value of
the listener's `real_ip_header`. A unix socket carries no client address, so
without a `real_ip_header` every connection of a unix listener is one peer,
named after the listener (`peer=unix:/run/nosfry/onion.sock` in logs): the
profile's `max_connections_per_peer` and `ip_*` buckets then bind the whole
listener. Such a peer is reported to the write-policy plugin as
`"sourceType":"Unix"` with the socket path as `sourceInfo`, and NIP-86
`blockip` cannot match it.

When a listener has a `real_ip_header` and a request lacks it, or its last
value is not an address, the connection falls back to the transport peer; the
relay warns about it at most once a minute per listener, without logging the
header's value.

The relay creates a unix socket at startup and removes it on shutdown. A socket
file left by a crashed relay is replaced; if another process still serves the
path, the relay refuses to start (`unix socket … already in use`), and any
other file at the path is an error, never removed. The socket's
permissions come from the process umask and its directory: there is no mode
key. [deployment.md](deployment.md#a-unix-socket-instead-of-tcp) has a systemd
setup that lets nginx or tor connect.

```toml
[[relay.listen]]
address = "127.0.0.1:7777"
real_ip_header = "X-Forwarded-For"

[[relay.listen]]
address = "unix:/run/nosfry/onion.sock"
profile = "onion"

[relay.profiles.onion]
max_connections_per_peer = 10000
```

### Filter validation

Whatever this section does, filter `ids`, `authors`, `#e` and `#p` values must each be 64 lowercase hex characters — anything else is refused with `invalid:` (`CLOSED` for REQ and COUNT, `NEG-ERR` for NEG-OPEN). `[relay.filter_validation]` (off by default) then restricts the shape of `REQ` and `COUNT` filters, with strfry's keys and defaults. A request that breaks a rule is answered `CLOSED blocked: <reason>`. `NEG-OPEN` is exempt, as in strfry, so a full sync stays possible.

- `min_filters_per_req` and `max_filters_per_req` (1 and 3) bound the filters per request.
- `max_kinds_per_filter` (3) bounds the kinds per filter.
- `allowed_kinds` (empty allows all) limits which kinds a filter may list. When it is set, a filter without `kinds` is refused too; strfry lets such a filter through, which returns every kind.
- `require_author_or_tag` requires each filter to pin exactly one `authors` value, one `#p` value, or one `#e` value.
- The section reloads on SIGHUP for new connections. Contradictory bounds fail at load and on reload.

### Relay information and HTTP

- `[relay.info]` holds the NIP-11 fields: `name`, `description`, `pubkey`, `self`, `contact`, `icon`, `banner`, `terms_of_service`, and `privacy_policy`.
  - `pubkey` and `self` must be 64 lowercase hex; convert an npub first.
  - `supported_nips` replaces the computed list. Use it when a write-policy plugin implements a NIP the relay itself does not.
- `limitation.max_message_length` is `min(max_websocket_payload_size, max_event_size + 10)` — the largest frame the relay accepts and the largest EVENT frame it can carry.
- `limitation.restricted_writes` is `true` while a NIP-86 pubkey or kind allow list is non-empty.
- `GET /` from a browser returns an HTML page built from the same fields. Only `http`, `https`, and `mailto` values become links, and every value is escaped.
- `/nodeinfo/2.1` describes the software. `/.well-known/nodeinfo` links to it on the host of `service_url`, and is 404 while `service_url` is unset.

### Logging

Logs go to stderr at `info` (set `RUST_LOG_JSON=1` for JSON). strfry's `relay.logging` switches are `RUST_LOG` targets instead of configuration. They are off by default so a hostile client cannot flood the log:

| strfry                                    | `RUST_LOG` directive    | Output                                                                                             |
| ----------------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------- |
| `invalidEvents`                           | `nosfry::ingest=debug`  | every `OK` sent, accepted or rejected, and every relay `CLOSED`                                    |
| `dumpInAll`, `dumpInEvents`, `dumpInReqs` | `nosfry::inbound=trace` | every inbound message                                                                              |
| `dbScanPerf`                              | `nosfry::scan=debug`    | one line per finished stored scan or `COUNT`, with timings                                         |
| —                                         | `nosfry::conn=debug`    | `connection open`, `connection closed reason=… duration_ms=…`, and `connection cap reached peer=…` |

For example: `RUST_LOG=info,nosfry::ingest=debug`.

Every line a WebSocket connection logs sits inside a `conn{id, peer}` span,
where `peer` is the client address after `real_ip_header`, or `unix:<path>` for
a unix listener without one; JSON lines carry it
as `"span":{"name":"conn","id":…,"peer":"…"}`. With
`RUST_LOG=info,nosfry::conn=debug`, a fail2ban filter can match `connection
cap reached peer=<HOST>`.

`[relay] tcp_keepalive = true` (strfry `enableTcpKeepalive`) sets `SO_KEEPALIVE` on new sockets, with the operating system's timers, to detect connections a proxy dropped silently.

### Compression

`[relay.compression]` negotiates permessage-deflate. It is on by default and differs from strfry's default as follows:

- `sliding_window = false` imposes no context takeover in both directions, which RFC 7692 lets a server do. Deflate state is borrowed from one server-wide pool for each message, so a connection costs a few KiB.
- On the real-event corpus this sends 18% (live) to 52% (stored batches) more bytes than `sliding_window = true`, and still about 40% fewer than no compression.
- `sliding_window = true` is strfry's default: every connection keeps its own deflate state, about 370 KiB once a message has been compressed. Choose it only when bandwidth matters more than connection count.
- Messages under 128 bytes always go out uncompressed. These are every reply type, which deflate cannot shrink. Inflated messages are bounded by `max_websocket_payload_size`, like uncompressed ones: a compressed frame that would inflate past it closes the connection.

### Write policy

`[relay.write_policy]` runs a strfry-compatible plugin; plugins written for strfry run unchanged.

- Every verified event is sent to `/bin/sh -c <plugin>` as one JSON line: `{"type":"new","event":…,"receivedAt":…,"sourceType":"IP4"|"IP6"|"Unix","sourceInfo":"<ip or socket path>"}`, plus `"authed":"<hex>"` once the connection has authenticated.
- The plugin answers `accept`, `reject`, or `shadowReject`. The event is then stored and broadcast, refused with `OK false`, or acknowledged and silently dropped.
- `timeout_seconds` (default 10) bounds each answer. On a timeout or a plugin error, the event is rejected with `error: internal error` and a fresh plugin process serves the next event.
- A plugin configured as a bare path restarts when the file's mtime changes.

### Authentication and protected events

`[relay] service_url` (empty by default) is the relay's canonical `ws://` or `wss://` address. Clients echo it in the AUTH event's `relay` tag, and NIP-62 requests name it. `service_url_aliases` adds further names the relay accepts in those tags and in NIP-98 `u` tags.

- When it is set, NIP-11 lists 42 and the relay sends each connection at most one AUTH challenge: when an unauthenticated REQ, COUNT or NEG-OPEN could match a read-gated kind — the request still proceeds, with the gated events hidden — when one publishes a protected event, or when a `write` rule requires it. A connection may authenticate up to 8 pubkeys.
- A REQ whose filters can only match read-gated kinds is refused: `CLOSED auth-required:` when AUTH is enabled, `CLOSED restricted:` otherwise. Mixed filters still subscribe but hide gated events, and hidden events never consume `limit`.
- Without a `service_url`, publishing a gated kind is refused with `restricted:` — the gate needs NIP-42 AUTH, which is disabled. Set `relay.access.rules = []` to accept and serve everything openly.
- A gift wrap (kind 1059) is also deleted by a kind-5 request from the pubkey its `p` tag names, and re-publication stays blocked (NIP-59); NIP-11 lists 59 while AUTH is on and kind 1059 is read-gated.
- NIP-70 protected events (a `["-"]` tag) are rejected unless AUTH is configured and the author is authenticated. Reposts (kinds 6 and 16) embedding a protected event are always blocked. AUTH events (kind 22242) are never stored or broadcast.

### Access rules

`[relay.access]` compiles to a sorted rule table validated at load and at every reload: a kind follows the `[[relay.access.rules]]` entry listing it, else the one entry without `kinds` (the catch-all), else it is open — rule order never matters. The loader refuses a kind listed twice, two catch-alls, an empty `kinds` list, a duplicated `read` principal, and `authenticated` combined with another principal (it is redundant).

Each rule carries two sides. `read` is a set of principals — an event is served when any listed principal is satisfied by a pubkey the connection authenticated: `authenticated` (any), `author` (the event's author), `recipient` (any `p` tag value), `allowed` (a pubkey on the NIP-86 allow list — an empty allow list admits nobody). `read = []` is open to every reader. `write` is one of `open` (the default), `authenticated` (challenge first, any authed pubkey may publish), or `author` (only the event's own author, authenticated). The same rules gate stored scans, live delivery, COUNT, and NEG, so hidden events leak nothing — not through `limit`, `COUNT` answers, NEG sets, or NIP-67 EOSE hints.

`anonymous_kinds` exempts listed kinds from the NIP-86 pubkey allow list: gift wraps (1059/21059) already pass when any `p` tag names an allowed pubkey, but kinds signed by single-use keys (Marmot group messages, kind 445) would otherwise be refused and hidden. Bans, banned ids, and kind allow/disallow lists still apply to anonymous kinds.

#### DM and gift-wrap inbox (default)

```toml
[[relay.access.rules]]
kinds = [4, 1059, 21059]
read  = ["author", "recipient"]
```

#### Private storage (NIP-78 app data, NIP-37 drafts)

Owner-only reads and writes: the event's author must authenticate.

```toml
[[relay.access.rules]]
kinds = [30078, 31234]
read  = ["author"]
write = "author"
```

#### AUTH before write for kind 1059

NIP-59 suggests authenticating senders as a spam defence: a stranger may no longer drop a gift wrap anonymously, at the cost of one AUTH per sender. Listing `[[relay.access.rules]]` replaces the default rule table, so 1059 keeps its read gate and the other DM kinds are re-listed.

```toml
[[relay.access.rules]]
kinds = [1059]
read  = ["author", "recipient"]
write = "authenticated"

[[relay.access.rules]]
kinds = [4, 21059]
read  = ["author", "recipient"]
```

#### Members-only relay with Marmot

A `read = ["allowed"]` catch-all serves members only, while Marmot traffic still flows: kind 445 is carved out of the read gate and exempted from the allow-list identity (its authors are single-use keys, and gift wraps already pass by recipient). The trade-off is that anyone may store kind 445 — bound it with `relay.profiles` rate limits.

```toml
[relay.access]
anonymous_kinds = [445]

[[relay.access.rules]]
kinds = [4, 1059, 21059]
read  = ["author", "recipient"]

[[relay.access.rules]]
kinds = [445]
read  = []

[[relay.access.rules]]
read = ["allowed"]
```

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
