# A test relay for local development and CI

A client's integration tests want a real relay that starts in milliseconds,
holds a known set of events, and can be reset between runs. nosfry does this
with its normal binary: a pinned release, `import` to seed it once, and a
copy of the seeded database to reset it.

For one-off runs, [`contrib/test-relay/nosfry-test-relay.sh`](../contrib/test-relay/nosfry-test-relay.sh)
wraps the whole recipe — temp dir, config, optional seed, readiness probe,
deterministic cleanup — into one command:

```bash
contrib/test-relay/nosfry-test-relay.sh \
    --port N [--bin PATH] [--seed FILE.jsonl] [--config-extra FILE]
```

It prints `NOSFRY_URL=ws://127.0.0.1:<port>` (plus `NOSFRY_RELAY_PID` and
`NOSFRY_TMPDIR` for the harness) once the relay is ready, then holds the
relay open until it is signaled. `--bin` defaults to `$NOSFRY_BIN`, then
`nosfry` on `$PATH`; `--port` is required (see "Port allocation"); `--config-extra`
appends TOML to the generated config (the `[relay.access]`,
`[relay.management]` or `[relay.info]` additions below). The sections
below explain what it does so a harness can either call it or
re-implement the pieces it needs.

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

## A fixed local config

```toml
# test-relay.toml
[db]
path = "./test-relay-db"

[relay]
# The URL clients dial, verbatim. Setting it turns NIP-42 AUTH on, so
# direct-message, gift-wrap and NIP-70 protected-event flows are
# testable. It must equal what the client signs in its AUTH `relay`
# tag — a mismatch is refused `invalid: relay tag mismatch`.
service_url = "ws://127.0.0.1:7777"

[[relay.listen]]
address = "127.0.0.1:7777"

# Parallel test workers share the 127.0.0.1 peer: 0 lifts the
# simultaneous-connection cap.
[relay.profiles.default]
max_connections_per_peer = 0

# Tests publish in bursts; the per-connection and per-peer buckets
# would answer "rate-limited:" and make them flaky.
[relay.profiles.default.rate_limits]
events_per_second = 0
reqs_per_second = 0
ip_events_per_second = 0
ip_reqs_per_second = 0
```

Every key matters:

- **`service_url`** enables AUTH. Without it the relay refuses writes to
  AUTH-gated kinds outright and never challenges reads, so DM inboxes and
  NIP-70 protected events are untestable.
- **`[relay.access]`** defaults keep kind 4/1059/21059 (direct messages and
  gift wraps) readable only by their authenticated author or `p` recipient —
  the realistic posture. A suite that needs open DM reads can open
  everything with `rules = []`:

  ```toml
  [relay.access]
  rules = []
  ```
- **`[relay.management] admins = ["<test key hex>"]`** enables the NIP-86
  management API (bans, allow lists) for the listed test key.
- **NIP-11 is always served** on the same port, with
  `curl -fsS -H 'Accept: application/nostr+json' http://127.0.0.1:7777/` —
  it is also the cheapest readiness probe (below).
- **Marmot clients**: use [`contrib/marmot/nosfry.toml`](../contrib/marmot/nosfry.toml)
  instead, rewriting `service_url`, the `[[relay.listen]]` address and
  `[db] path` to your port and temp dir (see [marmot.md](marmot.md)). Its
  2 MiB event cap and White-Noise-sized rate limits are the profile a
  group/inbox relay actually ships.

## Ephemeral data dir

One `mktemp -d` per relay instance; the config lives wherever you keep it —
everything the relay writes is under `[db] path`:

```bash
dir="$(mktemp -d)"
# config has: path = "$dir/db"
```

Nothing else needs cleanup: delete the dir and the relay state is gone.

## Port allocation

Two ways, one honest constraint.

- **The listener accepts `127.0.0.1:0`** and the relay logs the bound
  address at startup: `INFO nosfry: listening address=127.0.0.1:54682`.
  Reading that line is the race-free way to let the kernel allocate a
  port.
- **But `service_url` must equal the URL clients dial** before the
  config is written — NIP-42 verifies the AUTH event's `relay` tag
  against it, and the config is read once at startup. With `service_url
  = "ws://127.0.0.1:0"` every AUTH is refused, so a suite that needs
  AUTH cannot use kernel allocation; it must own the port itself
  (a fixed port per lane, or the worker index times a stride).
- **Probe-then-bind is racy**: a socket bound to `:0`, closed, and
  rebound by nosfry loses the port to any parallel process in between.
  Do not do it in CI.

The contrib script therefore takes `--port N` and refuses to pick one.

## Readiness probe

Poll the NIP-11 document instead of sleeping:

```bash
until curl -fsS -H 'Accept: application/nostr+json' \
    http://127.0.0.1:7777/ -o /dev/null; do
  sleep 0.05
done
```

Ready means the listener accepts connections and the store is open —
the first WebSocket frame after that gets a normal answer. Bound the
loop (~30 s) and fail with the relay log tail when it expires or the
relay exits early. On a shared machine another process may already
answer on that port, so also wait for this relay's own
`listening address=127.0.0.1:<port>` log line, as the contrib script
does.

## Seed once, reset by copying

Seed the database from JSON lines (one event per line, the format of `nosfry
export` and `strfry export`), then keep a compacted copy as the pristine
state:

```bash
"$NOSFRY" --config test-relay.toml import < fixtures.jsonl
"$NOSFRY" --config test-relay.toml compact pristine.mdb
```

`import` checks every signature and every structural limit, but not the
`created_at` window or the write gate, so fixtures of any age load —
direct messages and gift wraps included, with or without AUTH
configured. Events with an `expiration` tag in the past are stored but
never served. That is also the only way to load fixtures older than
`created_at_lower_limit`: a live publish of them is refused `invalid:`.

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
`[db] path` and port; a fresh relay on an empty database is ready in tens
of milliseconds.

## Deterministic cleanup

SIGTERM is the graceful stop: the relay finishes in-flight writes and
exits 0. Give it a bounded wait, escalate to SIGKILL, then remove the
dir:

```bash
kill -TERM "$RELAY_PID"
for _ in $(seq 1 100); do
  kill -0 "$RELAY_PID" 2>/dev/null || break
  sleep 0.05
done
kill -KILL "$RELAY_PID" 2>/dev/null || true
rm -rf "$dir"
```

Wrap the harness in a `trap ... EXIT` so a failed test cleans up the
same way. Never kill by port (`pkill -f`, `lsof -i:$port`) — it kills a
stale process or a neighbour's.

## No external network

In this config the relay makes no outbound connections: it listens, it
serves, it writes LMDB. The only code path that can reach off-host is
`[relay.write_policy] plugin` (an operator-supplied `/bin/sh -c`
command, empty here), so the suite is hermetic by construction.

## In CI

A GitHub Actions sequence — generic, no secrets:

```yaml
- name: Fetch nosfry
  run: |
    curl -fsSLO "https://github.com/qntx/nosfry/releases/download/v$VERSION/nosfry-$VERSION-x86_64-unknown-linux-gnu.tar.gz"
    echo "$SHA256  nosfry-$VERSION-x86_64-unknown-linux-gnu.tar.gz" | sha256sum -c -
    tar xzf "nosfry-$VERSION-x86_64-unknown-linux-gnu.tar.gz"
- name: Test relay
  run: |
    ./contrib/test-relay/nosfry-test-relay.sh \
      --bin "nosfry-$VERSION-x86_64-unknown-linux-gnu/nosfry" \
      --port 7777 --seed fixtures.jsonl > relay.env &
    echo $! > relay-script.pid
    for _ in $(seq 1 100); do grep -q NOSFRY_URL relay.env 2>/dev/null && break; sleep 0.1; done
    cat relay.env >> "$GITHUB_ENV"
- name: Tests
  run: cargo test -- --test-threads=1
  env:
    NOSFRY_URL: ${{ env.NOSFRY_URL }}
- name: Stop the relay
  if: always()
  run: kill -TERM "$(cat relay-script.pid)" || true
```

## Client checklist — what a real relay shows

Findings from running a client's (Meowl's) end-to-end suite and probes
against nosfry instead of its in-memory fixture relay:

- **`limit` is capped**: `limitation.max_limit` (500 here) bounds how
  many events a filter returns; bigger asks truncate silently per
  NIP-01. Page with `until`, or take the NIP-67 hint: `["EOSE",<sub>,
  ["more"]]` means a stored match remains, `["finish"]` means the sweep
  is complete.
- **`COUNT` is charged to the REQ bucket**: one COUNT per note in a
  feed hits strfry-default rate limits fast. Batch, pace, or honour
  the `rate-limited:` retry hint — the element after the message
  (`["OK",<id>,false,<msg>,"<ms>"]`, `["CLOSED",<sub>,<msg>,"<ms>"]`)
  is the milliseconds until the bucket refills.
- **`CLOSED` beats the timeout**: a refused query answers
  `["CLOSED",<sub>,"<prefix>: <reason>"]` instead of `EOSE`. A client
  that only resolves on EOSE hangs to the timeout; fail fast on the
  reason instead.
- **NIP-11 changes client paths**: clients that branch on
  `supported_nips`/`limitation` (COUNT vs event path, AUTH decisions)
  take different code on a real relay than on a fixture with no NIP-11.
  Fetch the document and test both paths.
- **Restricted kinds need AUTH**: an `auth-required:` CLOSED or a
  NIP-67 `auth` EOSE hint means the filter could match gated kinds;
  DM/gift-wrap reads serve only the authenticated author or `p`
  recipient.
- **Strict validation**: filter values must be lowercase 64-hex, an
  unknown filter key refuses the whole REQ, and publishes outside the
  `created_at` window are `invalid:` — fixtures older than the window
  must be **imported**, not published.
- **Multi-filter REQs are ordered per filter**, not globally sorted —
  do not assume a single interleaved order.

## What the test relay is not

It is the production relay with production semantics: signatures are always
checked on publish, every NIP-01 rule applies, and an `OK true` means the event
is on disk. There is no in-memory mode, no clock control and no endpoint to
inject events without signatures. Keep a fixture relay of your own for those.
