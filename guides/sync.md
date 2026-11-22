# Sync with another relay

`nosfry sync` reconciles the local database with a remote relay over
NIP-77 (negentropy) and transfers only the events one side lacks. It works
against any relay that serves NIP-77: another nosfry, strfry 1.x, or any
other implementation. Use it to mirror a relay, back one up, backfill a
personal relay from public ones, or run strfry and nosfry side by side
during a migration.

```bash
nosfry sync <relay-url> [--filter <json>] [--dir down|up|both]
            [--since <unix>] [--until <unix>]
            [--auth-key-file <path>] [--allow-private] [--timeout <seconds>]
```

Like the other administration commands it opens the database named by
`--config` directly, writes logs to stderr, and can run while the relay
serves (see [Running next to the relay](#running-next-to-the-relay)).

## Examples

Mirror everything a relay has into the local database (the default
direction is `down`):

```bash
nosfry --config /etc/nosfry/nosfry.toml sync wss://relay.example.com
```

Backfill a personal relay with your own notes, reactions and profile from
the last year:

```bash
nosfry sync wss://relay.example.com \
  --filter '{"authors":["<your hex pubkey>"]}' \
  --since "$(date -d '1 year ago' +%s)"
```

Two-way sync between two relays you run, for example nosfry next to strfry
during a migration (run it from the nosfry host, then switch DNS once both
sides agree):

```bash
nosfry sync wss://old-relay.example.com --dir both
```

Push the local database to a backup relay:

```bash
nosfry sync wss://backup.example.com --dir up
```

Run it on a schedule with a systemd timer or cron; the command is
idempotent, so a rerun after any failure picks up where the last one
stopped.

## Options

- `--filter <json>`: one NIP-01 filter selecting the events to sync
  (NIP-77 reconciles a single filter). `limit` and `search` are refused
  because they make the set partial. Default: every event.
- `--dir down|up|both`: `down` downloads what the remote has and the local
  database lacks, `up` uploads the reverse, `both` does both. Default:
  `down`.
- `--since`, `--until`: unix-time bounds, intersected with the filter's own
  `since` and `until`. The default range ends at now plus
  `events.reject_events_newer_than_seconds`.
- `--auth-key-file <path>`: the secret key used when the remote asks for
  NIP-42 authentication (see [Authentication](#authentication)).
- `--allow-private`: permit loopback and private addresses (see
  [Which URLs are accepted](#which-urls-are-accepted)).
- `--timeout <seconds>`: how long to wait for any reply the remote owes
  before giving up. Default: 60.

## Exit codes

| Code | Meaning                                                                                                                                                                                                                    |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | Complete: every difference was transferred, or refused by a rule that a rerun would apply again (validation, moderation, the write-policy plugin, the remote's `OK false`, superseded or deleted events, skipped uploads). |
| 3    | Partial: the run finished, but some transfers failed for reasons that may pass on a rerun (rate limits that outlasted the retries, `error:` answers, events the remote announced but did not deliver).                      |
| 1    | Failed: bad arguments or URL, the connection failed or dropped, the remote stopped answering, does not support NIP-77 or refused it, authentication was required without a key or was refused, or a store error.           |
| 2    | Usage error (unknown flag or missing argument).                                                                                                                                                                            |

The final log line, `sync done`, carries the counters: events reconciled
on each side, downloaded, uploaded, duplicates, refused locally and
remotely, skipped, and failed.

## What gets transferred

- **Downloads** pass the same checks as an `EVENT` from a client: event
  limits, the signature (never skipped), the future `created_at` bound,
  expiration, NIP-86 bans and allow lists (re-read during the run, so bans
  made through the running relay apply), and the write-policy plugin, which
  sees `"sourceType":"Sync"` with the remote URL as `sourceInfo`, as with
  strfry. Deletions, replaceable events and NIP-62 requests to vanish are
  applied by the store exactly as for published events. Unlike client
  ingest, there is no lower `created_at` bound, so history of any age
  syncs.
- Downloads refuse NIP-70 protected events (only their author may publish
  them), kind 22242, ephemeral events, and everything the local
  `[relay.access]` write gate refuses an unauthenticated writer: gated
  kinds while AUTH is disabled locally, and any kind whose `write` rule
  is `authenticated` or `author` — the sync peer is never an
  authenticated author.
- **Uploads** are the stored events matching the filter, minus events
  hidden by NIP-86 and expired events. Protected events and events a
  non-open `read` rule hides from an unauthenticated reader are never
  uploaded: the remote authenticates as neither author nor recipient, so
  a catch-all `read` rule uploads nothing at all. Events larger than the
  remote's NIP-11 `max_message_length` are skipped.
- Events a rule refuses come back on every run (for example a remote
  holding an older version of a replaceable event); they are counted, not
  retried.

## Limits and large syncs

- Memory stays bounded whatever the size of either database: the time
  range is reconciled in windows of at most 100,000 local events, and a
  window that turns up more than 100,000 differences is transferred and
  split. A remote that refuses a large set (`blocked: too many query
  results`, strfry's and nosfry's `max_sync_events`) gets smaller windows
  the same way.
- The remote's NIP-11 document sets the frame sizes: negentropy messages
  fit its `max_message_length` (60,000 bytes when it publishes none, which
  fits strfry's default), download batches respect its `max_limit`, and at
  most 32 uploads await their `OK` at a time.
- `rate-limited:` answers are retried after the remote's retry hint, or
  with backoff from 1 to 30 seconds, up to 8 times per item.
- An interrupted run loses at most the batch in flight. There is no cursor
  to manage: the next run reconciles again, which costs one round trip per
  window that already agrees, and transfers only what is still missing.
- There is no fallback to plain `REQ` for relays without NIP-77: relays cap
  `REQ` results, so such a copy could neither be bounded nor known to be
  complete. The command exits 1 and says so.

## Running next to the relay

The command writes through LMDB like `import`, in transactions of at most
500 events, so the running relay's writer waits at most one such commit.
Synced events are stored and returned by new `REQ`s at once, but the
running relay does not broadcast them to subscriptions that are already
open. Run it as the relay's user (`sudo -u nosfry nosfry --config ...
sync ...`), and inside the relay's container for the image (`docker exec`),
because LMDB tracks readers per process.

## Authentication

When the remote sends a NIP-42 challenge, the command authenticates with
the key in `--auth-key-file`: a file holding the 64-character hex secret
key, readable only by its owner (`chmod 600`; a file that group or others
can read is refused). The key never appears in the command line, the
environment, or the logs; the logs name only its public key.

```bash
install -m 600 /dev/null /etc/nosfry/sync.key
printf '%s\n' "<64 hex characters>" > /etc/nosfry/sync.key
nosfry sync wss://private.example.com --auth-key-file /etc/nosfry/sync.key
```

Without a key, a remote that requires authentication ends the run with
exit code 1. Events the remote serves only to authenticated readers (for
example direct messages addressed to the key) are synced only with the key.

## Which URLs are accepted

- Only `ws://` and `wss://`. `wss://` verifies the certificate against the
  Mozilla root store bundled in the binary.
- No user name or password in the URL; use NIP-42 for authentication.
- `.onion` addresses are refused: there is no Tor dialer yet, and a
  clearnet lookup would leak the address.
- Every address the name resolves to must be publicly routable. Loopback
  (`127.0.0.1`, `::1`, `localhost`), private (RFC 1918, `fc00::/7`),
  shared (`100.64.0.0/10`) and link-local addresses need
  `--allow-private`, for example to sync two relays on one host or one
  network. Unspecified and multicast addresses are always refused. The
  connection goes to the addresses that were checked, not to a second
  lookup.
