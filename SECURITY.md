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
  Subscriptions, filters, scans, negentropy sessions, outbound bytes,
  and the writer queue are bounded by the limits in
  [`nosfry.example.toml`](nosfry.example.toml).
- Known open resource bounds (audit round 1): the per-reader request
  queues are unbounded (C-14), and `relay.max_connections` defaults to `0`
  (unlimited). On a public relay set `max_connections`, keep
  `max_connections_per_ip` and the rate limits on, and put the relay behind
  a reverse proxy.
- One panic aborts the process (`panic = "abort"`); run the relay under a
  supervisor that restarts it.
- The Prometheus endpoint (`relay.metrics`) is unauthenticated; keep it
  behind a reverse proxy or firewall.
- The NIP-86 management API relies on NIP-98 signatures and a 60-second
  window. A captured request can be replayed inside that window, so serve
  the relay over TLS.
- `relay.real_ip_header` trusts the header's last comma-separated value.
  Set it only behind a proxy that sets or appends that header; otherwise
  clients choose their own address, and with it their rate-limit and
  connection-cap bucket.
- HTTP routes have no request-rate limit of their own. WebSocket messages
  are rate-limited (`relay.rate_limits`), HTTP requests are not; a NIP-86
  request that passes its cheap checks costs one signature verification.
  Put the relay behind a reverse proxy that rate-limits HTTP.
- A write-policy plugin runs as a child process with the relay's
  privileges and sees every verified event. The container image has no
  shell, so it refuses to start with a plugin configured.
