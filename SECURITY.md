# Security

nosfry has not been independently audited. [AUDIT.md](AUDIT.md) is the
scope document for an audit and records the internal review rounds.

## Supported versions

Only the latest release receives security fixes. A fix ships as a new patch
release of the native binary, the container image, and the crates; there
are no backports to older minor versions before 1.0. The Workers edition is
a preview and is supported only at the latest commit on `main`.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting:
[open a draft security advisory](https://github.com/qntx/nosfry/security/advisories/new).
Only the maintainers can read it. Do not open a public issue, pull request,
or discussion that describes the problem before a fix is released.

Include the affected version or commit, the edition (native or Workers),
the configuration that matters, and the shortest reproduction you have.
A report is acknowledged in the advisory thread, the fix is developed in a
private fork of that advisory, and the advisory is published, with credit
unless you ask otherwise, when the fixed release is out.

## Threat model and limits

- Every client message is untrusted input. Events are size- and
  structure-checked before their BIP-340 signature is verified.
  Connections, subscriptions, filters, scans and the reader queues,
  negentropy sessions, outbound bytes, and the writer queue are bounded
  by the limits in [`nosfry.example.toml`](nosfry.example.toml).
- Reader queues are bounded too: past a reader's admission limit, or a
  connection's limit of waiting queries, a query is refused with
  `rate-limited:` instead of queued. That capacity is shared, not divided per
  client, so enough connections flooding past their rate limits can get
  other clients' queries refused while the flood lasts.
- `relay.max_connections` is always finite, but its default is derived from
  the open-file limit (874,936 at the default `relay.nofiles`) and bounds
  descriptors, not memory. On a public relay size it to the host, keep
  `max_connections_per_peer` and the rate limits on, and put the relay behind
  a reverse proxy.
- One panic aborts the process (`panic = "abort"`); run the relay under a
  supervisor that restarts it.
- The Prometheus endpoint (`relay.metrics`) is unauthenticated; keep it
  behind a reverse proxy or firewall.
- The NIP-86 management API relies on NIP-98 signatures and a 60-second
  window. A captured request can be replayed inside that window, so serve
  the relay over TLS.
- A listener's `real_ip_header` trusts the header's last comma-separated value.
  Set it only behind a proxy that sets or appends that header; otherwise
  clients choose their own address, and with it their rate-limit and
  connection-cap bucket.
- A unix-socket listener without `real_ip_header` counts all of its
  connections as one peer, and anyone who can connect to the socket uses
  that listener's profile. Its permissions come from the umask and the
  socket's directory; there is no mode key.
- HTTP routes have no request-rate limit of their own. WebSocket messages
  are rate-limited (each listener profile's `rate_limits`), HTTP requests are not; a NIP-86
  request that passes its cheap checks costs one signature verification.
  Put the relay behind a reverse proxy that rate-limits HTTP.
- A write-policy plugin runs as a child process with the relay's
  privileges and sees every verified event. The container image has no
  shell, so it refuses to start with a plugin configured.
