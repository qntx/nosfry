# A test relay for local development and CI

A client's integration tests want a real relay that starts in milliseconds,
holds a known set of events, and can be reset between runs. nosfry does this
with its normal binary: a pinned release, `import` to seed it once, and a
copy of the seeded database to reset it.

## Pin the binary

Pin both the version and the archive's SHA-256, so CI never runs a binary
you have not chosen. The hashes are in each release's `SHA256SUMS`.

```bash
VERSION=0.4.0
TARGET=x86_64-unknown-linux-gnu          # aarch64-unknown-linux-gnu, aarch64-apple-darwin
SHA256=<the archive's hash from SHA256SUMS>
curl -fsSLO "https://github.com/qntx/nosfry/releases/download/v$VERSION/nosfry-$VERSION-$TARGET.tar.gz"
echo "$SHA256  nosfry-$VERSION-$TARGET.tar.gz" | sha256sum -c -   # macOS: shasum -a 256 -c -
tar xzf "nosfry-$VERSION-$TARGET.tar.gz"
NOSFRY="$PWD/nosfry-$VERSION-$TARGET/nosfry"
```

## Configure it for tests

```toml
# test-relay.toml
[db]
path = "./test-relay-db"

[relay]
# Turns on NIP-42 AUTH, so tests can read direct messages and gift wraps.
service_url = "ws://127.0.0.1:7777"

[[relay.listen]]
address = "127.0.0.1:7777"

# Tests publish in bursts; the per-connection and per-peer buckets
# would answer "rate-limited:" and make them flaky.
[relay.profiles.default.rate_limits]
events_per_second = 0
reqs_per_second = 0
ip_events_per_second = 0
ip_reqs_per_second = 0
```

Add `[relay.management] admins = ["<test key hex>"]` to test NIP-86 calls.

## Seed once, reset by copying

Seed the database from JSON lines (one event per line, the format of `nosfry
export` and `strfry export`), then keep a compacted copy as the pristine
state:

```bash
"$NOSFRY" --config test-relay.toml import < fixtures.jsonl
"$NOSFRY" --config test-relay.toml compact pristine.mdb
```

`import` checks every signature and every structural limit, but not the
`created_at` window or the restricted-kind refusal, so fixtures of any age
load — direct messages and gift wraps included, with or without AUTH
configured. Events with an `expiration` tag in the past are stored but never
served.

Before each test run, with the relay stopped, replace the database with the
pristine copy and start it:

```bash
rm -rf test-relay-db && mkdir test-relay-db
cp pristine.mdb test-relay-db/data.mdb
"$NOSFRY" --config test-relay.toml relay &
RELAY_PID=$!
until curl -fsS -o /dev/null http://127.0.0.1:7777/; do sleep 0.05; done
# ... run the tests against ws://127.0.0.1:7777 ...
kill -TERM "$RELAY_PID"; wait "$RELAY_PID"
```

The copy is the whole reset: there is no state outside `data.mdb` (LMDB
recreates `lock.mdb`). On file systems with copy-on-write clones the copy is
instant: `cp -c` on APFS (macOS), `cp --reflink=auto` on btrfs and XFS. Never
replace the files of a running relay.

For tests that must not share state, run one relay per test with its own
`[db] path` and `port`; a fresh relay on an empty database is ready in tens
of milliseconds.

## What the test relay is not

It is the production relay with production semantics: signatures are always
checked on publish, every NIP-01 rule applies, and an `OK true` means the event
is on disk. There is no in-memory mode, no clock control and no endpoint to
inject events without signatures. Keep a fixture relay of your own for those.
