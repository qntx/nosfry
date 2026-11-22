# Administration

The `nosfry` binary is also the administration tool. The commands open the
same LMDB database as the relay and are safe to run while it serves: LMDB
allows many readers and one writer across processes. Run them as the relay's
user (`sudo -u nosfry nosfry --config /etc/nosfry/nosfry.toml ...` under the
systemd unit), and inside the relay's container for the image.

## Commands

`--config` is a global flag, so `nosfry --config nosfry.toml <command>` and `nosfry <command> --config nosfry.toml` are equivalent. All commands write logs to stderr; event output goes to stdout.

```bash
nosfry export [--since <unix>] [--until <unix>] [--reverse] [--events-only] > dump.jsonl
nosfry import [--show-rejected] [--no-verify] < dump.jsonl
nosfry scan '{"kinds":[1],"limit":10}' [--count]
nosfry delete [--dry-run] [--age <seconds>] ['{"kinds":[1]}']
nosfry compact <dest-file>
```

- `export` writes every stored event as one JSON line, ordered by `created_at` (newest first with `--reverse`), over a consistent snapshot. The event lines are followed by `{"nosfry_state":1,…}` lines carrying the persisted NIP-86 state (bans, allow/disallow lists, blocked IPs, NIP-11 overrides) and the NIP-62 vanish points, emitted regardless of `--since`/`--until`. `--events-only` skips them, for piping into strfry or another relay.
- `import` verifies each line's signature and stores verified events in batches. Malformed, oversized, or invalid lines are rejected and counted. A `nosfry_state` line is applied as it arrives; a malformed one, an unknown version, or a method outside the export vocabulary (read-only `list*` and `un*` ops are never exported) aborts the import.
  - Unlike relay ingest, there is no `created_at` time-window check, so archives of any age import cleanly.
  - Events imported while the relay is running are stored and queryable, but are not broadcast to live subscriptions.
  - Import bypasses the write-policy plugin, NIP-86 moderation, and the restricted-kind refusal (a dump's direct messages and gift wraps import without AUTH configured); it is an operator tool.
  - `--no-verify` skips only the signature check, for dumps from a relay you trust (for example `strfry export | nosfry import --no-verify`). The id hash, the size limit, and every structural check still run. The summary log records that signatures were not verified.
- `scan` runs a `REQ` filter over the whole database in newest-first order; `--count` prints only the number of matches.
- `delete` removes every stored event matching a `REQ` filter and prints the deleted count; `--dry-run` prints the count without deleting. Already-expired events still match the filter.
  - `--age <seconds>` keeps only events older than that, by `created_at`. Combined with a filter, the earlier `until` wins. A cron job running `nosfry delete --age 7776000 '{"kinds":[1]}'` keeps 90 days of notes.
  - A filter or `--age` is required, so `delete` alone never selects everything.
- `compact` writes a compacted copy of the database to a new file and refuses to overwrite an existing one.

`export`, `scan`, `delete`, and `compact` fail with `no database at <path>` when `<db.path>/data.mdb` does not exist. `import` creates the database, as `relay` does.

## Management API (NIP-86)

`POST /` with `Content-Type: application/nostr+json+rpc` is enabled when `[relay.management] admins` lists at least one pubkey.

- Browser admin tools can call the API: every answer carries CORS headers that allow `POST` and the `Authorization` header.
- Every call needs a NIP-98 `Authorization: Nostr <base64(event)>` header: a kind-27235 event no older than 60 s, with `method` = `POST`, a `payload` tag hashing the raw body, a `u` tag matching `service_url`, and an admin's signature. Anything else is answered 401. A captured request can be replayed within those 60 s; every method is idempotent, and TLS is assumed.
- Methods:
  - `supportedmethods`;
  - pubkeys: `banpubkey`, `unbanpubkey`, `listbannedpubkeys`, `allowpubkey`, `unallowpubkey`, `listallowedpubkeys`;
  - events: `banevent`, `unbanevent`, `listbannedevents`;
  - kinds: `allowkind`, `disallowkind`, `listallowedkinds`, `listdisallowedkinds`;
  - IP addresses: `blockip`, `unblockip`, `listblockedips`;
  - NIP-11 fields: `changerelayname`, `changerelaydescription`, `changerelayicon`.
- State persists in the database and is enforced from an in-memory snapshot:
  - banned authors, banned events, and disallowed kinds are refused at publish with `blocked:`, while AUTH and NIP-62 requests stay exempt;
  - stored events of banned authors, of disallowed kinds, and outside a non-empty allow list are hidden from every `REQ`, `COUNT` and `NEG-OPEN`; they stay in the database and reappear when the entry is removed;
  - `banevent` deletes the stored event;
  - blocked addresses get 403 on new requests;
  - the NIP-11 overrides take precedence over the configuration.

## Backup and restore

There are two kinds of backup, and they carry different things:

|                                                                 | `nosfry compact <file>`                          | `nosfry export`                                                   |
| --------------------------------------------------------------- | ------------------------------------------------ | ----------------------------------------------------------------- |
| What                                                            | a consistent physical copy of the whole database | every stored event as JSON lines, then `nosfry_state` state lines |
| NIP-86 state (bans, allow lists, blocked IPs, NIP-11 overrides) | included                                         | included as state lines; an import re-applies them                |
| NIP-62 vanish points                                            | included                                         | included as state lines; the sweeps re-run on import              |
| Restores into                                                   | the same on-disk format version only             | any nosfry version, and strfry with `--events-only`               |
| Size                                                            | compacted (free pages dropped)                   | larger, compresses well                                           |

A nightly physical backup:

```bash
sudo -u nosfry nosfry --config /etc/nosfry/nosfry.toml compact /var/lib/nosfry/backup-$(date +%F).mdb
```

`compact` refuses to overwrite an existing file. To restore, stop the relay and
put the copy in place as `data.mdb` of an empty database directory:

```bash
sudo systemctl stop nosfry
sudo -u nosfry mv /var/lib/nosfry/db /var/lib/nosfry/db.old
sudo -u nosfry mkdir /var/lib/nosfry/db
sudo -u nosfry cp /var/lib/nosfry/backup-2026-11-22.mdb /var/lib/nosfry/db/data.mdb
sudo systemctl start nosfry
```

A logical backup with `export` is what you keep across format versions and
what you hand to another relay:

```bash
sudo -u nosfry nosfry --config /etc/nosfry/nosfry.toml export | gzip > events-$(date +%F).jsonl.gz
```

## Upgrading

The database records its on-disk format version, and a binary refuses to open
a database of another version (`format version mismatch: found X, expected
Y`). The format has been 4 since 0.2.0, so upgrading from 0.2.x or 0.3.x to
0.4.0 is: replace the binary, restart. The CHANGELOG states every format
change at the top of the release that makes it. nosfry never migrates a
database in place; a format change is upgraded by export and import, with the
old relay serving until the switch:

```bash
# 1. While the old relay serves: copy everything up to now.
T=$(date +%s)
nosfry-old --config /etc/nosfry/nosfry.toml export > dump.jsonl
nosfry-new --config new.toml import < dump.jsonl        # new.toml: [db] path = "/var/lib/nosfry/db.new"
# 2. Stop the old relay and copy what arrived since step 1.
sudo systemctl stop nosfry
nosfry-old --config /etc/nosfry/nosfry.toml export --since "$T" | nosfry-new --config new.toml import
# 3. Switch the database directory and the binary, then start.
```

Events already present are answered as duplicates, so the overlap of the two
passes is harmless, and the downtime is the second pass only. `--since`
selects by `created_at`, not by arrival: an event published between the two
passes with a `created_at` before `T` (the relay accepts events up to
`events.reject_events_older_than_seconds` old) is missed. When that matters,
run the second pass without `--since`, at the cost of a longer downtime.

The `nosfry_state` lines carry the NIP-86 state and vanish points over — a
0.4.0 exporter writes them on every pass and re-applying them is idempotent.
An older binary's export (0.3.x and earlier, and strfry's) has no state lines,
so that path still loses the NIP-86 state: record it before the upgrade
(`listbannedpubkeys`, `listallowedpubkeys`, `listbannedevents`,
`listallowedkinds`, `listdisallowedkinds`, `listblockedips`) and apply it
again on the new relay. Until the bans and allow lists are applied again, the
events they hid are served again: moderation hides stored events at read
time without deleting them.

What an export and import does **not** carry over:

- Ephemeral events (never stored) and events a write-policy plugin would now
  reject: `import` bypasses the plugin and NIP-86 checks.
- The configuration file, which you copy yourself.

The Workers edition has no export and no upgrade path yet; see
[workers.md](workers.md).

## Retention

`delete` with `--age` keeps a rolling window. For example, a daily timer that
keeps 90 days of kind-1 notes:

```bash
nosfry --config /etc/nosfry/nosfry.toml delete --age 7776000 '{"kinds":[1]}'
```

Deleted pages are reused for new events; the file only gets smaller through
`compact` and a restore.
