# Tor onion service

nosfry has no Tor support of its own yet. Today a relay is reachable as an
onion service by putting C tor in front of it with a `HiddenService` in
`torrc`. This page describes that setup and its limits.

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
