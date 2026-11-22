# Running a Marmot relay

Marmot clients (MDK, White Noise, Meowl) put four shapes on a relay:
kind-445 group messages signed by a fresh key each and carrying one
`h` (group id) tag, kind-1059 gift-wrap Welcomes `p`-tagged to a
recipient, kind-30443 KeyPackages with one `d` slot per device, and
the usual NIP-09 deletions and replaceable relay lists. Three relay
behaviours make this work: AUTH so Welcomes can be served to their
recipient only, events up to 2 MiB so a Welcome to a large group
fits, and rate limits that tolerate a group burst.

A tested profile ships at [`contrib/marmot/nosfry.toml`](../contrib/marmot/nosfry.toml).
Run it like any other config:

```bash
nosfry relay --config contrib/marmot/nosfry.toml
```

## The profile, key by key

`[relay] service_url = "wss://relay.example.com"` turns on NIP-42
AUTH — set the deployed URL. Without it every Welcome is accepted
`OK true` and then never served, because kind 1059 is only readable
by its author or `p`-tagged recipient; the sender is told the
message was delivered and the invitee never sees it.

`[events] max_event_size = 2097152` is the spec's SHOULD for group
and inbox relays: a Welcome wrap is about 3x the MLS Welcome it
carries, so a 64 KiB cap stops groups at roughly 56 members.
`[relay] max_websocket_payload_size = 2097162` is the smallest cap
that carries the largest EVENT frame (`max_event_size + 10`,
measured), and it makes NIP-11's `max_message_length` truthful —
MDK reads that field as the event limit.

`[relay.profiles.default.rate_limits]` is sized for bursts, not
average load: a White Noise scenario publishes 475 group messages
in 2.9 s (~164/s) on one connection, which the stock 20/s burst-100
bucket refuses 317 times. `events_per_second = 100` with
`events_burst = 1000` holds that burst with ~2x headroom;
`reqs_per_second = 50` with `reqs_burst = 500` covers MDK's one
sweep REQ per 100 ms and Meowl's 53 REQ/s peak; the
`ip_*` buckets allow about five such clients behind one NAT. With
these values the White Noise interop suite (MDK v0.18.0) passed all
seven scenarios with no `rate-limited:` refusal. The listener sets
`real_ip_header = "X-Forwarded-For"` because the relay sits behind
the TLS proxy; without it every client shares the proxy's buckets.
`[relay.limits] max_filter_limit` stays at the default 500 — the
interop runs passed with it, and NIP-11 publishes it as `max_limit`,
which MDK uses to prove a sweep is complete.

`[relay.access]` keeps the stock DM/gift-wrap rule spelled out so
kind 1059 stays recipient-only (the NIP-17 inbox contract), and
sets `anonymous_kinds = [445]`: kind-445 authors are single-use
keys that are never identities, so this exempts them from a NIP-86
pubkey allow list if an operator adds one later. It is inert while
no allow list exists. Kind 445 is never read-gated — its `h` tag is
a 256-bit capability already, and an AUTH gate would link accounts
to groups.

`[relay.info]` carries the usual NIP-11 placeholders; set
`privacy_policy` (see below for what the relay can see).

## The Cloudflare Workers edition

The same file becomes `NOSFRY_CONFIG` TOML with these changes (see
[workers.md](workers.md) for the key-name mapping):

- Drop `[db]` and `[[relay.listen]]` — there are no listeners or a
  database path on Workers.
- Drop the `[relay.profiles]` layer: the buckets move to
  `[relay.rate_limits]` with the same key names, and the
  per-address connection cap is `[relay] max_connections_per_ip`
  (default 128).
- Everything else — `service_url`, `max_websocket_payload_size`,
  `[events]`, `[relay.access]`, `[relay.info]` — is identical.

The caveat: a 2 MiB group message fans out to every matching
subscriber, and 2 MiB fan-out on a 128 MB isolate is unmeasured at
scale. The Workers conformance pass covers the sizes; production
capacity behind it is not yet measured.

## What the relay learns

Every 445 reveals its group's routing id (`h`), a single-use
pubkey, a timestamp and a size — never the content. From a
connection the relay sees the client's address and the `#h` values
it subscribes to, which links that client's groups; if the same
connection also authenticates for 1059, it links the account to
those groups. Two things nosfry already does keep this minimal:
addresses, filters and tag values are never logged at `info`
level, and AUTH is lazy — the relay only challenges when a
read-gated kind is actually requested, so pure 445 traffic never
triggers an AUTH. Recommend that clients subscribe to 445 on a
connection that never authenticates (the spec's own guidance for
reading one's own 445s), and publish a `privacy_policy` that says
what you retain.

## A members-only variant

To carry Marmot on a NIP-86 allow-list relay, add the catch-all
`read = ["allowed"]` rule and a `read = []` carve-out for kind 445
on top of `anonymous_kinds = [445]` — wraps addressed to members
pass by recipient, kind 445 stays public, and everything else is
members-only. The full recipe is in
[configuration.md](configuration.md) under "Access rules".

## Sweeps, retention and limits

- NIP-67 `finish` hints on EOSE tell MDK a stored sweep is complete
  and it should not paginate; nosfry sends them when the scan ran
  dry, so a 475-message history arrives in one `limit:500` REQ.
- NIP-77 negentropy works over `#h` filters for set reconciliation.
- There is no TTL on kind 445: group commits never expire because
  members catching up need the history, and application messages
  carry NIP-40 `expiration` when the group enables retention —
  nosfry honours it (expired events are refused on write and hidden
  on read). `nosfry delete --age` exists for operators who accept
  cutting group history.

## Verifying a deployment

NIP-11 should advertise `limitation.max_message_length = 2097162`,
`max_limit = 500`, and `supported_nips` covering 42 (AUTH), 59
(gift wraps), 67 (EOSE hints) and 77 (negentropy):

```bash
curl -sH 'Accept: application/nostr+json' https://your-relay/ | jq .limitation
```

The conformance suite's fourth pass runs the Marmot cases —
2 MiB Welcome delivery, the 475-message burst with zero
`rate-limited` frames, KeyPackage slot semantics, expiration,
unauthenticated 445 reads — against a relay started from the
shipped profile itself:

```bash
crates/nosfry-conformance/run.sh native   # pass 4 uses contrib/marmot/nosfry.toml
crates/nosfry-conformance/run.sh worker
```
