<!-- markdownlint-disable MD033 MD041 -->

# nosfry

A Nostr relay in Rust. It follows strfry's configuration tree, plugin protocol
and export format, stores events in LMDB, and commits every acknowledged event
to disk before it answers `OK`.

There are two editions, both built on one protocol core (`nosfry-core`) and
checked by one black-box conformance suite:

- **Native** (`nosfry`): a single binary for Linux and macOS servers. This is
  the edition to run in production.
- **Workers** (`nosfry-worker`, preview): the same relay as a Cloudflare
  Durable Object on SQLite. It has no upgrade path between schema versions
  yet; see [guides/workers.md](guides/workers.md).

## Quick start

With Docker, on any machine:

```bash
docker run -d --name nosfry -p 127.0.0.1:7777:7777 -v nosfry-data:/data ghcr.io/qntx/nosfry:latest
curl -H 'Accept: application/nostr+json' http://127.0.0.1:7777/
```

The relay now accepts WebSocket clients at `ws://127.0.0.1:7777`, and the
`curl` call prints its NIP-11 document. Stop it with `docker stop nosfry`; the
events stay in the `nosfry-data` volume.

With the release binary (Linux x86_64 or aarch64 with glibc 2.31 or newer, or
macOS on Apple silicon):

```bash
VERSION=0.4.0 TARGET=x86_64-unknown-linux-gnu
curl -fsSLO "https://github.com/qntx/nosfry/releases/download/v$VERSION/nosfry-$VERSION-$TARGET.tar.gz"
curl -fsSLO "https://github.com/qntx/nosfry/releases/download/v$VERSION/nosfry-$VERSION-$TARGET.tar.gz.sha256"
sha256sum -c "nosfry-$VERSION-$TARGET.tar.gz.sha256"
tar xzf "nosfry-$VERSION-$TARGET.tar.gz" && cd "nosfry-$VERSION-$TARGET"
cp nosfry.example.toml nosfry.toml
./nosfry relay
```

The Linux binaries of 0.3.0 and earlier need glibc 2.38 or newer and do not
start on Debian 12 or Ubuntu 22.04; use 0.4.0 or later. `cargo install nosfry
--locked` builds from source with Rust 1.99 or newer.

Before you open the relay to the internet, read
[guides/deployment.md](guides/deployment.md): put it behind a reverse proxy
with TLS and HTTP rate limiting, set `relay.service_url`, and size
`relay.max_connections` to the host's memory (unset, it is derived from the
open-file limit).

## Supported NIPs

Each NIP below is listed in the relay's NIP-11 `supported_nips` exactly when
the condition holds; `relay.info.supported_nips` replaces the list verbatim.
A test (`crates/nosfry/tests/docs.rs`) checks this table against the list the
code computes.

| NIP                                                            | Feature                    | Advertised                                                                        |
| -------------------------------------------------------------- | -------------------------- | --------------------------------------------------------------------------------- |
| [01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Basic protocol             | always                                                                            |
| [09](https://github.com/nostr-protocol/nips/blob/master/09.md) | Event deletion requests    | always                                                                            |
| [11](https://github.com/nostr-protocol/nips/blob/master/11.md) | Relay information document | always                                                                            |
| [40](https://github.com/nostr-protocol/nips/blob/master/40.md) | Expiration timestamp       | always                                                                            |
| [42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Authentication of clients  | when `relay.service_url` is set                                                   |
| [45](https://github.com/nostr-protocol/nips/blob/master/45.md) | Event counts (with HLL)    | when `max_filter_limit_count` is not 0                                            |
| [59](https://github.com/nostr-protocol/nips/blob/master/59.md) | Gift wrap deletion         | when `relay.service_url` is set and `relay.access` gates kind 1059 reads |
| [62](https://github.com/nostr-protocol/nips/blob/master/62.md) | Request to vanish          | always                                                                            |
| [67](https://github.com/nostr-protocol/nips/blob/master/67.md) | EOSE completeness hints    | always                                                                            |
| [70](https://github.com/nostr-protocol/nips/blob/master/70.md) | Protected events           | always                                                                            |
| [77](https://github.com/nostr-protocol/nips/blob/master/77.md) | Negentropy syncing         | when `max_sync_events` is not 0                                                   |
| [86](https://github.com/nostr-protocol/nips/blob/master/86.md) | Relay management API       | when `relay.management.admins` is set                                             |

NIP-98 authorizes the NIP-86 calls. strfry's write-policy plugins and
`strfry export` dumps work unchanged ([guides/administration.md](guides/administration.md)),
and `nosfry sync` reconciles with any NIP-77 relay, strfry included, in
either direction ([guides/sync.md](guides/sync.md)).

## Blossom media

The native binary can also serve [Blossom](https://github.com/hzrd149/blossom)
blobs for the relay's members, on its own listener and hostname so uploaded
files never run in the relay's origin. Off by default; see
[guides/blossom.md](guides/blossom.md).

| BUD | Feature                                         | Status                                 |
| --- | ----------------------------------------------- | -------------------------------------- |
| 01  | Blob retrieval, ranges, `OPTIONS` discovery     | when `blossom.enabled`                 |
| 02  | `PUT /upload`                                   | when `blossom.enabled`                 |
| 06  | `HEAD /upload` preflight                        | when `blossom.enabled`                 |
| 11  | Kind 24242 authorization (both base64 forms)    | when `blossom.enabled`                 |
| 12  | List (own blobs only) and delete                | when `blossom.enabled`                 |
| 13  | `PUT /<sha256>` upload                          | when `blossom.enabled`; no mirroring   |
| 04  | Mirroring                                       | not implemented                        |
| 05  | Media optimisation                              | not implemented                        |
| 07  | Payments                                        | not implemented                        |

## Performance

Measured against strfry 1.1.3 on one Linux aarch64 VM, with the relay pinned to
four cores, in benchmark round 7 and its follow-ups
([bench/reports/round-7.md](bench/reports/round-7.md), `main` at `2898125`). In
short: faster than strfry on reads and latency, at parity on durable writes up
to 3,000 events/s, heavier per idle connection.

- Faster: warm queries on an 8.35M-event database (p50 2.42 vs 4.39 ms at 8
  connections, 1.26x throughput at 64), queries with permessage-deflate (1.8 to
  3.8x throughput), live delivery to 5,000 subscribers (p50 21 vs 93 ms), and
  CPU per acknowledged write (0.35 to 0.43x).
- At parity: ingest into a fresh database (5,673 vs 4,480 events/s in one
  round, no significant difference in the repeat) and sustained ingest at
  3,000 events/s into an 18.7 GB database larger than RAM.
- Slower or heavier: strfry also sustains 3,500 events/s into that database and
  nosfry does not; a cold-cache query at 64 connections has a higher p50 (54.8
  vs 38.4 ms); an idle plain connection costs 7.23 vs 1.00 KiB (7.31 vs 109
  KiB with permessage-deflate); a live delivery costs 9.33 vs 3.68 µs of CPU.

## Documentation

- [guides/](guides/README.md): install, configuration reference, deployment,
  administration, sync with other relays, Blossom media, Tor, Workers, a test
  relay for local development and CI, and the security model and limits.
- [`nosfry.example.toml`](nosfry.example.toml): every configuration key with its
  default.
- [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md) (how to report a
  vulnerability), [CONTRIBUTING.md](CONTRIBUTING.md) (development and the
  local gate), [AUDIT.md](AUDIT.md) (audit scope).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
