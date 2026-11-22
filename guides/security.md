# Security model and limits

How to report a vulnerability, and which versions get fixes:
[SECURITY.md](../SECURITY.md). This page is the operator's view of what the
relay protects against, which bounds it enforces, and what it leaves to you.

## Trust boundaries

| Party                                           | Trusted with                                  | Notes                                                                                                              |
| ----------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| WebSocket clients                               | nothing                                       | Every message is size- and structure-checked before its signature is verified; every per-connection set is capped. |
| HTTP clients                                    | nothing                                       | NIP-11, the landing page and NodeInfo are cheap but **not rate-limited**: the proxy must limit them.               |
| NIP-86 admins (`relay.management.admins`)       | moderation state and NIP-11 overrides         | Authenticated by NIP-98 with a 60 s window; a captured request can be replayed inside it, so serve over TLS.       |
| The reverse proxy                               | the client address                            | Only when `relay.real_ip_header` is set; the last value of that header is trusted.                                 |
| The write-policy plugin                         | every verified event, and the accept decision | A child process with the relay's privileges and sandbox.                                                           |
| Anyone who reaches `/metrics`                   | traffic counters                              | Unauthenticated; never expose it.                                                                                  |
| Local users who can read the database directory | everything stored                             | LMDB files are not encrypted; the unit's `UMask=0077` and `StateDirectoryMode=0700` keep them private.             |

## Enforced bounds

Defaults in parentheses; each is a key in [configuration.md](configuration.md)
unless marked fixed.

- **Per message:** inbound WebSocket frame after inflation
  (`max_websocket_payload_size`, 128 KiB, inclusive — it must be at least
  `max_event_size + 10`); canonical event size (`max_event_size`, 64
  KiB); tags per event (2,000) and tag value size (1,024 bytes); filter
  `ids`/`authors`/`#e`/`#p` values are strict 64-character lowercase
  hex; `created_at` window (900 s ahead, 3 years back, 60 s for
  ephemeral events).
- **Per connection:** subscriptions (`max_subs_per_connection`, 200); filters
  per `REQ` (200); `#x` conditions per filter (3); queued outbound bytes
  (`max_pending_outbound_bytes`, 32 MiB, then the connection is closed); EVENT
  and REQ token buckets (20/s, burst 100), which frames that fail to parse
  spend too; queries waiting for a reader (twice `max_subs_per_connection`);
  live matches buffered during a stored scan count against
  `max_pending_outbound_bytes`, so a connection holds at most twice it; 8
  authenticated pubkeys (fixed); negentropy sessions close after 60 s idle
  (fixed).
- **Per client address** (IPv4 address, IPv6 /64): connections
  (`max_connections_per_ip`, 128) and shared EVENT and REQ buckets (100/s,
  burst 500).
- **Per process:** WebSocket connections (`max_connections`, derived from
  the open-file limit unless set: 874,936 at the default `nofiles`; `0` is
  refused); queries admitted to each reader (4,096, fixed — past it a query is
  refused with `rate-limited: relay busy`); live-subscription memory, queued
  outbound bytes and negentropy memory (1 GiB each); writer queue (65,536 requests and 64 MiB,
  fixed); stored-scan rows per filter (`max_filter_limit`, 500); `COUNT` index
  entries (1,000,000, then approximate); negentropy records per session
  (1,000,000).
- **Plugin:** one request at a time per event, `timeout_seconds` (10) per
  answer, bounded response lines; a timeout rejects the event and restarts the
  plugin.

## Known gaps

These are open in the current release and are tracked in the audit
(round 1 identifiers):

- Reader capacity is shared, not divided per client: once the readers are
  saturated, queries are refused with `rate-limited: relay busy` instead of
  queued, and enough connections flooding past their rate limits (rate limits
  off, or many addresses) can get other clients' queries refused this way.
- `relay.max_connections` defaults to a descriptor bound derived from the
  open-file limit, not a memory bound; size it to the host.
- HTTP has no request-rate limit (by design; the proxy does it).
- A single panic aborts the whole process (`panic = "abort"`); the supervisor
  restarts it. Fuzzing covers the message, filter, event, NIP-98 and plugin
  decoders.
- The relay has not been independently audited.

## Recommended public profile

On top of the defaults: `max_connections` sized to the host's memory, a reverse
proxy with TLS and HTTP rate limiting ([deployment.md](deployment.md)),
`real_ip_header` set to the header the proxy overwrites, `metrics` scraped from
the host only, the hardened systemd unit, and alerts on
`nosfry_store_errors_total` and `nosfry_reader_busy_total`.
