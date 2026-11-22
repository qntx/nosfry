---
name: nosfry
description: >-
  High-performance Nostr relay in Rust for bare-metal servers and Cloudflare
  Workers. Use when the user asks to run, configure, or operate a Nostr
  relay; export/import/scan/delete stored events; compact the database; tune
  rate limits, filter validation, NIP-42 read auth, the NIP-86 management
  API, limits, or relay info; or run the Workers edition with worker-build
  and wrangler.
---

# nosfry — Nostr relay in Rust

`nosfry` is a single binary relay. Same engine runs on bare metal (LMDB)
and Cloudflare Workers (Durable Objects + SQLite).

## Install

```sh
curl -fsSL https://sh.qntx.org/nosfry | sh   # prebuilt binary via sh.qntx.org
cargo install nosfry --locked              # from crates.io
```

## CLI

```text
nosfry [--config <CONFIG>] <COMMAND>
```

`--config` defaults to `nosfry.toml`; env `NOSFRY_CONFIG` overrides.
`-h/--help` and `-V/--version` are global.

| Command | Purpose |
| ------- | ------- |
| `relay` | Run the relay |
| `export` | Export all events as JSON lines, oldest first |
| `import` | Import event JSON lines from stdin |
| `scan <FILTER>` | Emit stored events matching a REQ filter (JSON), newest first |
| `delete [FILTER]` | Delete events matching a REQ filter and/or `--age` (one required) |
| `compact <DEST>` | Write a compacted copy of the database to a new file |

Flags (verbatim from `--help`):

- `export`: `--since <SINCE>` (unix ts, default 0), `--until <UNTIL>` (default u64::MAX), `--reverse` (newest first)
- `import`: `--show-rejected` (log each rejected line with its reason), `--no-verify` (skips only the BIP-340 signature check; id hash, size, structural and limit checks still run — trusted input only)
- `scan`: positional `<FILTER>` JSON e.g. `'{"kinds":[1]}'`; `--count` prints only the match count
- `delete`: `[FILTER]` JSON; `--dry-run` counts without deleting; `--age <SECONDS>` deletes events with `created_at` older than `now - SECONDS` (with FILTER the earlier `until` wins)
- `compact`: positional `<DEST>` — destination file must not exist

## Configuration (`nosfry.toml`)

Every key is documented in `nosfry.example.toml`; sections are
`[db]`, `[events]`, `[relay]`, `[[relay.listen]]`, `[relay.limits]`,
`[relay.filter_validation]`, `[relay.profiles.<name>]` (with
`.rate_limits`), `[relay.write_policy]`,
`[relay.auth]`, `[relay.management]`, `[relay.threads]`,
`[relay.compression]`, `[relay.info]`. `[db]`, `[[relay.listen]]` and
`[relay.threads]` are restart-only.

Essentials:

```toml
[db]
path = "./nosfry-db"

[relay]
service_url = "wss://relay.example.com"   # canonical URL; empty disables AUTH
metrics = true                            # GET /metrics, unauthenticated (restart-only)

[[relay.listen]]
address = "127.0.0.1:7777"                # or "unix:/run/nosfry/relay.sock"

[relay.management]
admins = ["<64-char hex pubkey>"]         # NIP-86 management API, NIP-98 auth
```

Notable knobs: `[events]` caps `max_event_size`, event age windows and tag
limits; `[relay.filter_validation]` (`enabled`, `allowed_kinds`,
`require_author_or_tag`) constrains REQ shapes; a listener's
`[relay.profiles.<name>]` sets `max_connections_per_peer` and, under
`.rate_limits`, per-connection and per-peer (`ip_*`) event/REQ token buckets; `[relay.write_policy].plugin` loads an
external write-policy plugin with `timeout_seconds`;
`[relay.auth].restricted_read_kinds` / `restrict_read_to_involved` gate
reads on NIP-42 auth; `[relay.compression]` (`enabled`, `sliding_window`)
controls permessage-deflate; `[relay.info]` feeds the NIP-11 document
(`name`, `description`, `pubkey`, `contact`, `icon`, `banner`, `self`,
`terms_of_service`, `privacy_policy`).

## Operational checks

```sh
nosfry --config nosfry.toml relay            # run it
curl -s http://127.0.0.1:7777/ -H 'Accept: application/nostr+json'   # NIP-11 doc
curl -s http://127.0.0.1:7777/metrics        # when [relay] metrics = true
nosfry scan '{"kinds":[1]}' --count          # stored kind-1 count
nosfry export > dump.jsonl                   # full backup, oldest first
nosfry import < dump.jsonl                   # restore (add --no-verify only for trusted dumps)
nosfry delete '{"kinds":[2]}' --dry-run      # preview deletion
nosfry compact nosfry-db-compacted           # offline compaction to a new file
```

## Cloudflare Workers edition

`crates/nosfry-worker` builds the same relay as a Workers bundle: a
`RelayObject` Durable Object (SQLite storage class, migration tag `v1`)
bound as `RELAY`. Build with `worker-build --release` — the workspace
release profile keeps `target_features` un-stripped
(`CARGO_PROFILE_RELEASE_STRIP=false`) and needs a wasm32-capable clang via
`CC_wasm32_unknown_unknown` (e.g. `$(brew --prefix llvm)/bin/clang`).
Local run: `npx --yes wrangler@4.150.0 dev --local` from the crate dir;
`crates/nosfry-conformance/run.sh worker` runs the black-box conformance
suite against it (needs `worker-build` 0.8.7 and Node).
