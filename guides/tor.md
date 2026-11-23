# Tor onion service

A relay is reachable as an onion service two ways. This page first
describes putting C tor in front of it with a `HiddenService` in `torrc`
and that setup's limits, then the embedded Arti mode that needs no
separate tor process.

## Setup

On the relay host, with the Debian `tor` package, point the hidden service at
a unix socket of the relay:

```text
# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/nosfry/
HiddenServicePort 80 unix:/run/nosfry/onion.sock
```

```bash
sudo systemctl restart tor
sudo cat /var/lib/tor/nosfry/hostname
```

`hostname` holds the relay's address, for example `exampleabc.onion` (the real
one is 56 characters). Clients connect to `ws://exampleabc.onion`. Tor encrypts
the connection end to end and the address is the service's key, so no TLS is
needed. Back up `/var/lib/tor/nosfry/`: losing `hs_ed25519_secret_key` loses
the address.

Give the onion service its own listener and profile, and name the onion
address as an alias of the relay:

```toml
[relay]
service_url = "wss://relay.example.com"
service_url_aliases = ["ws://exampleabc.onion"]

[[relay.listen]]
address = "127.0.0.1:7777"
real_ip_header = "X-Forwarded-For"

[[relay.listen]]
address = "unix:/run/nosfry/onion.sock"
profile = "onion"

[relay.profiles.onion]
# Every onion client is one peer: this caps all onion connections together.
max_connections_per_peer = 10000

# The per-peer buckets would be one bucket for all onion clients, which one
# client could drain; keep only the per-connection buckets.
[relay.profiles.onion.rate_limits]
ip_events_per_second = 0
ip_reqs_per_second = 0
```

On an onion-only relay, drop the TCP listener and set `service_url` to the
`ws://….onion` address instead of an alias. tor must be able to connect to the
socket: the systemd drop-in in
[deployment.md](deployment.md#a-unix-socket-instead-of-tcp) creates
`/run/nosfry` for the `nosfry` group, and `usermod -aG nosfry debian-tor` adds
tor to it. Debian also confines tor with AppArmor; if tor logs a permission
error for the socket, allow its path in tor's AppArmor profile.

Tor's own defences against introduction floods work as usual and are
recommended for a public onion relay:

```text
HiddenServicePoWDefensesEnabled 1
HiddenServiceEnableIntroDoSDefense 1
HiddenServiceMaxStreams 1000
HiddenServiceMaxStreamsCloseCircuit 1
```

Do **not** set `HiddenServiceExportCircuitID`: nosfry does not parse the PROXY
header it prepends, and every connection would fail.

## Limits of the torrc setup

- **Onion clients have no address.** tor hands the relay a stream, not the
  client's address, so all onion clients are one peer
  (`peer=unix:/run/nosfry/onion.sock` in logs). The onion profile's cap and
  buckets therefore bind all of them together, which is why the profile above
  raises the cap and turns off the shared buckets; the per-connection buckets
  still apply to each connection. The clearnet listener keeps its own profile,
  so onion traffic cannot use up the clearnet per-peer budgets;
  `relay.max_connections` still counts both.
- **One canonical URL.** NIP-11, the landing page and NodeInfo name only
  `service_url`. NIP-42 AUTH, NIP-62 requests and NIP-86 calls accept it and
  every `service_url_aliases` entry, so clients authenticate over either
  address.
- **No anonymity for the operator** when the same relay also serves clearnet:
  the same events, timing and NIP-11 document link the two addresses. Leave
  `relay.info` contact and icon fields empty if that matters.
- NIP-86 `blockip` cannot target onion clients; the write-policy plugin sees
  them as `"sourceType":"Unix"`.

## Embedded mode (`--features onion`)

nosfry can also embed an onion service inside the relay process through
[Arti](https://arti.torproject.org/), the Tor implementation in Rust. It
is an opt-in cargo feature: releases ship it as `-onion` artifacts —
`nosfry-<version>-onion-<target>.tar.gz` archives and
`ghcr.io/qntx/nosfry:<version>-onion` image tags — while the default
artifacts do not include it. To build from source instead:

```bash
cargo install nosfry --locked --features onion
```

An `onion:<nickname>` address in `[[relay.listen]]` is an embedded onion
service; the nickname labels logs and metrics and names the key
directory. Give it its own profile, because every onion client is one
peer (see below):

```toml
[[relay.listen]]
address = "onion:main"
profile = "onion"

[relay.profiles.onion]
max_connections_per_peer = 10000

[relay.onion]
state_dir = "./nosfry-onion"
max_circuits = 256
max_streams_per_circuit = 128
intro_rate = 0
intro_burst = 0
onion_location = false
```

`state_dir` must be a directory only the relay user can read (mode
`0700`); the relay refuses a looser one and says `chmod 700 <path>`.
`max_circuits` bounds concurrent rendezvous circuits per listener — a
circuit holds its slot until the client closes it, so clients holding
idle circuits count against the budget —
`max_streams_per_circuit` the streams Arti allows on each — a client
multiplexes all its connections onto one circuit, so the default is
sized for that and the profile's `max_connections_per_peer` is the
connection bound — and
`intro_rate`/`intro_burst` an optional token bucket sent to the
introduction points (both 0 = unset). `onion_location` adds an
`Onion-Location` header to NIP-11, landing-page and WebSocket-upgrade
responses on the non-onion listeners, so Tor Browser is offered the
onion address; it reloads with SIGHUP. Every other `[relay.onion]` key
is restart-only.

Print the service's address without starting the relay or touching the
network (it creates the key on first run):

```bash
nosfry onion address --config nosfry.toml
# ws://exampleabc.onion
```

The address lives on port 80, so the client URL is
`ws://exampleabc.onion`. The identity key — the address — is

```text
<state_dir>/state/keystore/hss/<nickname>/ks_hs_id.ed25519_expanded_private
```

Back that file up: losing it changes the onion address; everything else
in `state_dir` regenerates. With no `service_url` the first onion URL is
the canonical relay URL, so NIP-42 AUTH names it and NIP-62 and NIP-86
accept it; with a `service_url` every onion URL is an alias.

Clearnet listeners do not wait for Tor: they serve immediately while the
onion listener bootstraps in the background, retrying with a capped
backoff when the Tor network is unreachable. `nosfry_onion_state`,
`nosfry_onion_circuits`, `nosfry_onion_streams_total` and
`nosfry_onion_circuits_rejected_total` report each listener's state,
live circuits, accepted streams and refused circuits.

The write-policy plugin sees onion connections as
`"sourceType":"Onion"` with the listener id (`onion:<nickname>`) as
`sourceInfo`.

### Syncing over Tor

The same feature also lets `nosfry sync` dial a peer's
`ws://<addr>.onion` URL through an embedded Arti client that shares
`[relay.onion] state_dir` with the listeners — next to a running relay
Arti's lock files make it read the shared state and cache without
writing. See `guides/sync.md`.

### Which to choose

|                            | torrc (C tor)            | embedded (Arti)            |
|----------------------------|--------------------------|----------------------------|
| Extra process to run       | yes (`tor`)              | no                         |
| Onion-service PoW          | available                | not wired in               |
| Maturity                   | production               | see below                  |
| Relay binary (macOS arm64) | 6.1 MB stripped          | 14.6 MB stripped           |
| Setup                      | torrc + unix listener    | one listener line          |
| Client IPs                 | hidden from the relay    | hidden from the relay      |
| `sourceType` to the plugin | `Unix`                   | `Onion`                    |

Arti's own documentation disagrees about readiness: `doc/OnionService.md`
(tag `arti-v2.8.0`, "as of February 2024") still says onion services are
"suitable for testing and experimentation only", while Arti MR !3464
(merged 2025-11-13) made the onion-service features stable. Operators who
need C tor's track record or onion PoW should stay on the torrc setup.
