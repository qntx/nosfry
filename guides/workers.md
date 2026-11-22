# Workers edition (preview)

The Workers edition runs the same relay core as a Cloudflare Durable Object
with SQLite storage (`crates/nosfry-worker`). It passes the same conformance
suite as the native relay, but it is a **preview**: do not put data you cannot
lose on it yet.

What makes it a preview:

- **No upgrade path.** The object stores a schema version and refuses to start
  on any other; a release that changes the schema strands a deployed relay's
  data, and there is no export endpoint to carry it over.
- **One object is the ceiling.** All connections and storage live in one
  Durable Object (10 GB of SQLite, one thread, 128 MB of memory). Its
  sustained write rate and its connection limit have not been measured.
- **Idle WebSockets close after about 100 s** (see Deploy below).
- `worker` 0.8.7, the workers-rs crate it is built on, depends on chrono,
  which is unmaintained (RUSTSEC-2026-0543); the native relay does not link
  it.

## Toolchain

- Rust with the `wasm32-unknown-unknown` target.
- A clang that targets wasm32, exported as `CC_wasm32_unknown_unknown` (for example `"$(brew --prefix llvm)/bin/clang"`), for libsecp256k1.
- `worker-build` 0.8.7 (`cargo install worker-build --version 0.8.7 --locked`).
- Node and wrangler 4.150.0 (`npx --yes wrangler@4.150.0`).

`crates/nosfry-worker/wrangler.toml` declares the `RELAY` Durable Object binding and its SQLite migration. Its build command keeps the `target_features` section that wasm-bindgen needs.

## Configuration

All configuration lives in one `NOSFRY_CONFIG` variable that holds TOML. It uses the native section and key names where they exist, and rejects unknown keys:

```toml
[relay]
service_url = "wss://relay.example.com"

[relay.info]
name = "my relay"

[relay.management]
admins = ["<hex pubkey>"]

[worker]
location_hint = "weur"
```

Keys that differ from native:

- `[relay] max_connections` defaults to 5,000.
- `[relay] max_sync_memory_bytes` defaults to 32 MiB.
- `[worker] max_scan_rows` (default 100,000) bounds the rows any one scan reads, including COUNT and negentropy.
- `[worker] max_subscription_bytes` (default 32 MiB) bounds the estimated memory (`Filter::approx_bytes`, the native estimate) of every open subscription in the object. A REQ past it answers `blocked: subscription capacity exhausted`.
- `[worker] location_hint` pins the object's region.

## Write policy

An optional `POLICY` service binding enables the write policy. The bound Worker receives the strfry request line as the `POST` body and answers the strfry response JSON. `[relay.write_policy] timeout_seconds` (default 10) bounds each answer.

## Local development

From `crates/nosfry-worker`:

```bash
npx --yes wrangler@4.150.0 dev --local
```

`crates/nosfry-conformance/run.sh worker` builds the Worker, starts it with a fixture policy, and runs the conformance suite against it.

## Deploy

```bash
npx --yes wrangler@4.150.0 deploy
```

A deploy restarts the object and drops its WebSockets; clients reconnect. Cloudflare also closes a WebSocket that carries no data for about 100 s. The Workers runtime cannot send pings, so a client that never sends anything, as browsers do not, reconnects after idle periods; clients that send WebSocket pings stay connected. Stored events, moderation state, and pending vanish sweeps persist in the object's SQLite. Subscriptions end with their sockets.
