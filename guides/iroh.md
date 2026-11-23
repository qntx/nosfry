# iroh

nosfry can accept connections over [iroh](https://github.com/n0-computer/iroh),
a QUIC transport that dials peers by public key and punches through NATs, with
relay servers as the fallback. A relay with no public IP address becomes
reachable by anyone who holds its iroh endpoint id. It is an opt-in cargo
feature: the published binaries and the container image do not include it.

```bash
cargo install nosfry --locked --features iroh
```

No Nostr client dials iroh today. nosfry therefore ships both ends: the relay
listener, `nosfry sync` for relay-to-relay reconciliation, and `nosfry connect`,
a localhost gateway through which any existing client reaches an iroh-only
relay.

## Which to choose

|                                   | clearnet (TCP + TLS)         | torrc (C tor)            | embedded onion (Arti)     | iroh                                          |
|-----------------------------------|------------------------------|--------------------------|---------------------------|-----------------------------------------------|
| Needs a public IP or port forward | yes                          | no                       | no                        | no                                            |
| Existing clients connect directly | yes                          | Tor-enabled clients      | Tor-enabled clients       | no: through `nosfry connect` on their machine |
| Client IP hidden from the relay   | no                           | yes                      | yes                       | no (direct path); hidden behind a relay       |
| Operator location hidden          | no                           | yes, onion-only          | yes, onion-only           | no                                            |
| Third parties in the path         | none                         | Tor network              | Tor network               | the iroh relay, when no direct path forms     |
| Per-peer limits                   | per IP                       | one peer for all         | one peer for all          | per endpoint id                               |
| Typical latency to `OK`           | network RTT                  | about 650 ms             | about 650 ms              | RTT direct, both legs to the relay otherwise (about 500 ms through n0's EU relay from East Asia) |
| Extra process                     | reverse proxy for TLS        | `tor`                    | none                      | none (plus your own `iroh-relay`, optional)   |
| Build                             | default                      | default                  | `--features onion`        | `--features iroh`                             |

Pick iroh for relays at home or behind CGNAT that you want to sync with other
relays or reach from your own devices. Pick onion when clients must not learn
each other's or the relay's location. Pick clearnet for a public relay.

## The listener

An `iroh:<nickname>` address in `[[relay.listen]]` is an iroh endpoint. The
nickname labels logs and metrics and names the key file. Give it its own
profile:

```toml
[[relay.listen]]
address = "iroh:main"
profile = "iroh"

[relay.profiles.iroh]
# Per remote endpoint id: QUIC authenticates it, so this is a real
# per-peer cap. A `nosfry connect` gateway is one endpoint for all the
# clients behind it.
max_connections_per_peer = 128

[relay.iroh]
state_dir = "./nosfry-iroh"
relay_mode = "n0"            # "n0", "custom" or "disabled"
relay_urls = []              # with relay_mode = "custom"
address_lookup = "n0"        # "n0" or "disabled"
max_connections = 256        # concurrent QUIC connections per listener
max_streams_per_connection = 128
```

Every `[relay.iroh]` key is restart-only; the profile reloads with SIGHUP.
`state_dir` must be a directory only the relay user can read (mode `0700`); the
relay creates it so when missing and refuses a looser one with a
`chmod 700 <path>` hint. The listener's secret key is
`<state_dir>/<nickname>.key` (32 bytes, mode `0600`), created on first start.
**Back it up**: it is the endpoint id. Deleting it gives the listener a new id.

Each QUIC bidirectional stream on ALPN `nosfry/http/1` carries one ordinary
HTTP/1.1 connection, so NIP-11, the WebSocket relay protocol and NIP-86 work
exactly as on TCP.

Print the listener's dial address and relay name without starting the relay
or touching the network (it creates the key on first run):

```bash
nosfry iroh address --config nosfry.toml
# <endpoint-id>	ws://<endpoint-id>.iroh
```

The startup log names the listener by its relay name and logs its full dial
address whenever iroh learns its relay or direct addresses. NIP-11 lists the
endpoint ids under `"iroh"`:

```json
{ "iroh": { "alpn": "nosfry/http/1", "endpoints": ["<endpoint-id>"] } }
```

Served on a TLS clearnet name, that document is the proof that the endpoint
id belongs to that relay.

### Dial addresses

A dial address is `<endpoint-id>[@<hint>,<hint>…]`: the endpoint id in
z-base-32 (52 characters) or hex, optionally followed by `ip:port` socket
addresses or `https://` relay URLs. With the default `address_lookup = "n0"`
the endpoint id alone is enough: the dialer looks up the listener's relay in
n0's DNS. With `relay_mode = "custom"` on both sides, the dialer adds its own
relay URLs as hints, so the id is enough again. With relays disabled, pass the
listener's `ip:port`.

### Relay names and AUTH

There is no standard URL for an iroh endpoint. nosfry names each iroh listener
`ws://<endpoint-id>.iroh` and adds that name to the relay's names
automatically, like the onion URL: with no `service_url` and no onion listener
it is the canonical name (AUTH on), otherwise an alias. NIP-42 AUTH, NIP-62
requests and NIP-98 calls accept it on every listener; `nosfry sync` signs it.

**Standard clients cannot dial this name**: a DNS lookup of it fails (and
tells the resolver the endpoint id). A client that adds an iroh transport can
keep the name in its relay lists and route the `.iroh` suffix itself.

## Clients through `nosfry connect`

`nosfry connect` runs on the client's machine and forwards every local TCP
connection to the relay over its own QUIC stream:

```bash
nosfry connect <dial-address> --listen 127.0.0.1:4869
```

Point any Nostr client at `ws://127.0.0.1:4869`. The gateway connects to the
relay before it accepts anything, keeps one QUIC connection and redials it with
a capped backoff (1 s to 30 s) when it drops, forwards at most
`--max-connections` (default 64) clients at a time, and logs whether the path
is direct or relayed and every change. It refuses a non-loopback `--listen`
address unless `--allow-remote` is given. It reads `[relay.iroh]`
(`relay_mode`, `relay_urls`, `address_lookup`) from `--config` when that file
exists and uses the defaults otherwise; it uses a fresh endpoint key per run.

A client behind the gateway signs NIP-42 AUTH with the URL it connected to,
`ws://127.0.0.1:4869`. For AUTH to work, the relay operator adds that URL to
`service_url_aliases` and the users keep that port:

```toml
[relay]
service_url = "ws://relay.example.com"
service_url_aliases = ["ws://127.0.0.1:4869"]
```

All clients behind one gateway are one peer to the relay (one endpoint id), so
the relay's per-peer cap and buckets bind them together.

## Sync between two relays behind NAT

Each relay runs an iroh listener; either one can run `nosfry sync` against the
other with an `iroh:` peer:

```bash
nosfry sync iroh:<endpoint-id> --dir both --config nosfry.toml
```

The dialer opens one QUIC connection, fetches NIP-11 on one stream and runs the
NIP-77 reconciliation over a WebSocket on another. It authenticates with
`--auth-key-file` as usual and signs the peer's `ws://<endpoint-id>.iroh` name.
`--allow-private` does not apply to iroh peers. Everything in
[sync.md](sync.md) applies unchanged; a cron job or systemd timer on one side
keeps the two relays converged.

## Privacy and trust in n0's infrastructure

The defaults use infrastructure run by number0 (n0), the company behind iroh:

- **Relays** (`relay_mode = "n0"`): four public relay servers carry traffic
  until a direct path forms, and permanently when it cannot. They see both
  endpoints' IP addresses, connection times and traffic volumes, never the
  content: QUIC's TLS runs end to end between the two endpoints. n0 documents
  them as "for development and hobby use", without an SLA or published rate
  limits, and they do throttle: a 100,000-event `nosfry sync` over them ran at
  about 110 events per second, with iroh logging that the relay was
  rate-limiting the endpoint, where the same sync through a self-hosted relay
  took under 8 seconds.
- **Address lookup** (`address_lookup = "n0"`): the listener publishes a signed
  record to n0's DNS server mapping its endpoint id to its home relay URL (iroh
  publishes no IP address there by default), and dialers query it.
- **Direct paths**: once hole punching succeeds, each side learns the other's
  public IP address. There is no way to have iroh's reachability without that.

`relay_mode = "custom"` with your own relay moves the relay's view to you.
`relay_mode = "disabled"` leaves only direct paths: dialers need the listener's
`ip:port`, and two NATed peers cannot connect. `address_lookup = "disabled"`
publishes nothing; dialers then need a relay URL or `ip:port` hint (or a shared
custom relay).

## Self-hosting an iroh relay

`iroh-relay` is n0's stateless relay server. Run the version that matches
nosfry's iroh (1.4.1):

```bash
cargo install iroh-relay --locked --version 1.4.1 --features server
```

Give it a public host with a DNS name, TCP 80/443 and UDP 7842 (QUIC address
discovery, which lets endpoints learn their public address for hole punching).
Without QUIC address discovery an endpoint behind NAT knows only its private
addresses, so two NATed peers stay on the relayed path. QUIC address discovery
needs TLS, and nosfry verifies the relay's certificate against the Mozilla root
store, so the relay needs a publicly trusted certificate (Let's Encrypt below);
a relay with a self-signed or private-CA certificate still relays traffic but
cannot help nosfry punch holes.
A minimal `iroh-relay.toml` with Let's Encrypt (an `iroh-relay`
config, not a nosfry one):

```conf
enable_relay = true
enable_quic_addr_discovery = true

[tls]
cert_mode = "LetsEncrypt"
hostname = "iroh-relay.example.com"
contact = "ops@example.com"
```

```bash
iroh-relay --config-path iroh-relay.toml
```

Point both relays (and every `nosfry connect`) at it:

```toml
[relay.iroh]
relay_mode = "custom"
relay_urls = ["https://iroh-relay.example.com"]
address_lookup = "disabled"
```

nosfry verifies the relay's certificate against the Mozilla root store, so the
relay needs a publicly trusted certificate.

## Limits and abuse

- **Endpoint ids are free.** Anyone can create endpoint ids without limit, so
  the per-endpoint cap and buckets attribute load but do not stop a flood. The
  listener-wide bound is `max_connections`: a connection beyond it is refused
  before the QUIC handshake, so it costs the relay no cryptography; each
  admitted connection carries at most `max_streams_per_connection` streams.
  `relay.max_connections` still bounds WebSockets across all listeners.
- **What an attacker with many ids can do**: fill `max_connections` and deny
  the iroh listener to others. **What they cannot do**: exceed the
  listener-wide bound, the process-wide connection cap or the store's write
  budgets, or affect the other listeners' per-peer budgets.
- NIP-86 `blockip` does not apply to iroh peers. The write-policy plugin sees
  `"sourceType":"Iroh"` with the endpoint id as `sourceInfo`, so a plugin can
  refuse writes from specific endpoints.
- macOS: with the Application Firewall on, a self-built (unsigned) nosfry
  receives no unsolicited inbound UDP, so direct paths to it did not form in
  testing, even on one LAN; relayed paths work. Linux has no such rule.

## Metrics

`nosfry_iroh_connections{listener,path}` counts open QUIC connections by
selected path (`direct` or `relay`), `nosfry_iroh_connections_rejected_total`
connections refused at `max_connections`, `nosfry_iroh_streams_total` accepted
streams, and `nosfry_iroh_relay_connected` whether the listener's home relay
connection is up. `listener` is the nickname.
