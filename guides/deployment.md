# Deployment

A public relay is the `nosfry` binary bound to `127.0.0.1`, run by systemd (or
a container runtime), behind a reverse proxy that terminates TLS, rate-limits
HTTP, and passes the client address. nosfry has no TLS of its own.

## Checklist

- [ ] `relay.service_url` is the public `wss://` URL (NIP-42 AUTH, NIP-62 and
      NIP-86 need it).
- [ ] `relay.max_connections` is sized to memory: an idle connection costs
      about 7.2 KiB (100,000 connections, about 0.7 GiB). Unset, it is derived
      from the open-file limit (874,936 at the default `nofiles`), which bounds
      descriptors, not memory.
- [ ] `relay.bind` stays `127.0.0.1`; only the proxy reaches the relay.
- [ ] The proxy rate-limits HTTP, overwrites `X-Forwarded-For`, and the relay
      sets `relay.real_ip_header = "X-Forwarded-For"`.
- [ ] `/metrics` is not reachable from the internet.
- [ ] The open-file hard limit leaves room for `max_connections`: the relay
      refuses to start when `max_connections` exceeds `limit - 64 - limit/8`
      of the soft limit `nofiles` raised it to.
- [ ] The database volume has free space for growth, and alerts watch it
      (see [Disk space](#disk-space)).
- [ ] Backups are scheduled ([administration.md](administration.md#backup-and-restore)).

## systemd

[`contrib/systemd/nosfry.service`](../contrib/systemd/nosfry.service) is a
hardened unit: a dedicated user, a private state directory, a read-only view
of the rest of the file system, no capabilities, and a system-call filter.

```bash
sudo useradd --system --home-dir /var/lib/nosfry --shell /usr/sbin/nologin nosfry
sudo install -d -m 0755 /etc/nosfry
sudo install -m 0644 nosfry.example.toml /etc/nosfry/nosfry.toml
sudo sed -i 's|^path = "./nosfry-db"|path = "/var/lib/nosfry/db"|' /etc/nosfry/nosfry.toml
sudo install -m 0644 contrib/systemd/nosfry.service /etc/systemd/system/nosfry.service
sudo systemctl daemon-reload
sudo systemctl enable --now nosfry
systemctl status nosfry
journalctl -u nosfry -f
```

`systemctl reload nosfry` sends `SIGHUP`, which reloads the configuration
([configuration.md](configuration.md) says which keys need a restart).
`systemctl stop nosfry` sends `SIGTERM`: the relay stops accepting, commits
the writes already queued, and exits 0; the unit allows 60 s for that.
`systemd-analyze security nosfry` scores the sandbox.

The relay is a single process and one panic aborts it (`panic = "abort"`), so
`Restart=on-failure` matters. A write-policy plugin inherits the sandbox: give
it read access to what it needs with `ReadOnlyPaths=`, and drop
`MemoryDenyWriteExecute=` if it runs on a JIT runtime.

## Open files

Every WebSocket is one file descriptor. At startup the relay raises its soft
limit to `relay.nofiles` (1,000,000 by default), capped by the hard limit.
`LimitNOFILE=` in the unit and `--ulimit nofile=` for containers raise the hard
limit; systemd's and containerd's default hard limit is 524,288. The proxy
needs the same headroom, twice over, because it holds two descriptors per
WebSocket: in nginx's main context set `worker_rlimit_nofile 1000000;` and
`events { worker_connections 100000; }` (per worker).

## Reverse proxy and TLS

[`contrib/nginx/nosfry.conf`](../contrib/nginx/nosfry.conf) is a complete
nginx site:

- TLS on 443 with a certificate from your ACME client (for example `certbot
  certonly --webroot -w /var/www/acme -d relay.example.com`), and a redirect
  from port 80 that still serves ACME challenges.
- `limit_req` at 10 requests per second per address, burst 20, answered
  `429`. It covers NIP-11, the landing page, NIP-86 calls and WebSocket
  upgrades. nosfry does not rate-limit HTTP itself, and one NIP-86 request
  with a valid-looking header costs a signature verification.
- WebSocket upgrade headers, and `X-Forwarded-For` set to the client address.
  The relay trusts the **last** value of `real_ip_header`, so the proxy must
  set or append it and nothing in front of the proxy may append after it.
- Read and send timeouts of 120 s, above the relay's 55 s ping interval, so
  idle connections stay open.
- `/metrics` answered 404.

With that site, configure the relay with:

```toml
[relay]
bind = "127.0.0.1"
service_url = "wss://relay.example.com"
real_ip_header = "X-Forwarded-For"
```

Any proxy works if it does the same five things: TLS, WebSocket upgrade, a
client-address header it overwrites, HTTP rate limiting, and a read timeout
above 55 s. Caddy needs the third-party `caddy-ratelimit` module for the rate
limit.

## Container

The [install guide](install.md#container-image) has the `docker run` line. In
production, also:

- keep the database in a named volume or a host directory mounted at `/data`;
- run administration commands inside the relay's container, so they share its
  PID namespace (LMDB tracks readers by PID):
  `docker exec nosfry /nosfry export > dump.jsonl`;
- reload with `docker kill -s HUP nosfry`, and stop with a timeout of at least
  60 s (`--stop-timeout 60`);
- consider `--network host` for many connections, to avoid the bridge NAT.

## Monitoring

`relay.metrics = true` (restart-only) serves `GET /metrics` in Prometheus
format on the relay port. It is unauthenticated: scrape it from the host, and
keep it off the proxy.

| Metric                                 | Type    | Meaning                                                                                                                                                | Alert on                             |
| -------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------ |
| `nosfry_store_errors_total{op}`        | counter | Failed store operations                                                                                                                                | any increase (disk full, I/O errors) |
| `nosfry_connections`                   | gauge   | Live WebSocket connections                                                                                                                             | above 80 % of `max_connections`      |
| `nosfry_connections_rejected_total`    | counter | Refused upgrades (caps)                                                                                                                                | a sustained rate                     |
| `nosfry_outbound_pending_bytes`        | gauge   | Process-wide queued outbound bytes                                                                                                                     | above 50 % of the total budget       |
| `nosfry_subscription_bytes`            | gauge   | Estimated live-subscription memory                                                                                                                     | above 80 % of the budget             |
| `nosfry_sync_memory_bytes`             | gauge   | Memory held by negentropy sessions                                                                                                                     | above 80 % of the budget             |
| `nosfry_reader_jobs`                   | gauge   | Queries admitted to the reader threads and not yet finished                                                                                            | near 4,096 × `threads.readers`       |
| `nosfry_reader_busy_total{msg}`        | counter | Work refused because the readers were saturated (`relay busy`) or a connection had too many queries waiting: `scan`, `conn_scan`, `neg_msg`, `control` | a sustained `scan` rate              |
| `nosfry_rate_limited_total{verb}`      | counter | Rate-limit refusals                                                                                                                                    | informational                        |
| `nostr_client_messages_total{verb}`    | counter | Inbound messages by verb                                                                                                                               | informational                        |
| `nostr_relay_messages_total{verb}`     | counter | Frames written to sockets                                                                                                                              | informational                        |
| `nostr_events_total{kind}`             | counter | Events persisted to the store; at most 256 kinds get an own series, the rest count under `kind="other"`                                                | informational                        |
| `nosfry_event_outcomes_total{outcome}` | counter | Verified publishes by outcome: `stored`, `ephemeral`, `duplicate`, `superseded`, `deleted`, `vanished`, `moderated`, `policy`, `error`                 | a rising `error` outcome             |

A counter that has never moved prints only its `# HELP` and `# TYPE` lines, so
treat a missing series as zero. There are no latency metrics yet, and
`nosfry_reader_jobs` is the only queue-depth gauge; watch the process (RSS,
open descriptors) with node-exporter or the container runtime.

Logs go to stderr (the journal under systemd). The relay warns about commits,
enqueues and sweeps slower than 1 s. Per-message debugging targets are listed
in [configuration.md](configuration.md#logging).

## Disk space

LMDB's file grows as events are written and never shrinks; freed pages are
reused, and `nosfry compact` writes a smaller copy. When the disk fills,
publishes are answered `OK false error: internal error`, reads keep working,
`nosfry_store_errors_total{op="write"}` climbs, and the log gets one ERROR line
per failed transaction (thousands per minute). Writes resume once LMDB can
allocate pages again; no restart is needed. Keep the journal on another
volume, or cap it (`SystemMaxUse=` in `journald.conf`), so the log cannot fill
the same disk.
