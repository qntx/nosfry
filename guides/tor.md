# Tor onion service

nosfry has no Tor support of its own yet. Today a relay is reachable as an
onion service by putting C tor in front of it with a `HiddenService` in
`torrc`. This page describes that setup and its limits.

## Setup

On the relay host, with the Debian `tor` package:

```text
# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/nosfry/
HiddenServicePort 80 127.0.0.1:7777
```

```bash
sudo systemctl restart tor
sudo cat /var/lib/tor/nosfry/hostname
```

`hostname` holds the relay's address, for example `abcd…xyz.onion`. Clients
connect to `ws://abcd…xyz.onion`. Tor encrypts the connection end to end and
the address is the service's key, so no TLS is needed. Back up
`/var/lib/tor/nosfry/`: losing `hs_ed25519_secret_key` loses the address.

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

- **Every onion client is `127.0.0.1`.** The per-address limits then apply to
  all Tor users together: `relay.max_connections_per_ip` (128) caps all onion
  connections, and the `ip_*` rate buckets are shared by all of them. On an
  onion-only relay, set `max_connections_per_ip = 0` and the `ip_*_per_second`
  keys to `0`, keep the per-connection buckets, and bound the total with
  `max_connections`. If the same process also serves clearnet clients behind a
  proxy with `real_ip_header`, the clearnet clients keep their own addresses,
  but every onion client still shares the `127.0.0.1` bucket.
- **One relay URL.** `relay.service_url` names one address, and NIP-42 AUTH,
  NIP-62 requests and NIP-86 calls must name it. On an onion-only relay set it
  to the `ws://….onion` address. A relay that serves both clearnet and onion
  clients accepts AUTH only for the URL it is configured with; clients that
  connect over the other address cannot authenticate, so they cannot read
  restricted kinds (direct messages, gift wraps) or publish protected events.
- **No anonymity for the operator** when the same relay also serves clearnet:
  the same events, timing and NIP-11 document link the two addresses. Leave
  `relay.info` contact and icon fields empty if that matters.
- NIP-86 blocks by IP address cannot target onion clients.
