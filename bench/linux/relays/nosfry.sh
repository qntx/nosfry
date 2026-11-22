#!/usr/bin/env bash
# nosfry pinned to the relay cores with the round 7 parity config.
# Usage: nosfry.sh <binary> <port> <dir> [variant-toml]
#   The optional variant file is appended to the generated nosfry.toml.
# Env: RELAY_CPUS (default 0-3), DB_DIR (default <dir>/db — an explicit
#      database directory the wrapper uses but never wipes), METRICS
#      (default 0; 1 serves GET /metrics for the soak).
set -euo pipefail
bin="$1"; port="$2"; dir="$3"; variant="${4:-}"
RELAY_CPUS="${RELAY_CPUS:-0-3}"
DB_DIR="${DB_DIR:-$dir/db}"
METRICS="${METRICS:-0}"
if [ -n "$variant" ] && [ ! -f "$variant" ]; then
    echo "nosfry.sh: variant config '$variant' not found" >&2
    exit 1
fi
mkdir -p "$dir" "$DB_DIR"
metrics_line=""
[ "$METRICS" = "1" ] && metrics_line="metrics = true"
cat > "$dir/nosfry.toml" <<CONF
[db]
path = "$DB_DIR"
map_size = 137438953472

[events]
max_event_size = 65536
max_num_tags = 2000
# Parity with strfry: the corpus's created_at window must never clip.
reject_events_newer_than_seconds = 3155760000
reject_events_older_than_seconds = 3155760000

[relay]
$metrics_line
max_websocket_payload_size = 131072

[[relay.listen]]
address = "127.0.0.1:$port"

# Serve restricted read kinds (DMs) like strfry does, so relayBench's
# cross-check compares the same result sets.
[relay.auth]
restricted_read_kinds = []

[relay.limits]
max_sync_events = 2000000

# Benchmarks measure the engine, not the limiter: 50,000 subscribers
# connect from one IP and ingest floods a single connection.
[relay.profiles.default]
max_connections_per_peer = 0

[relay.profiles.default.rate_limits]
events_per_second = 0
events_burst = 0
reqs_per_second = 0
reqs_burst = 0
# Same for the per-address buckets: every benchmark connection shares
# one IP and would otherwise hit the default 500-REQ burst.
ip_events_per_second = 0
ip_events_burst = 0
ip_reqs_per_second = 0
ip_reqs_burst = 0
CONF
# Deliberately no [relay.compression] table above: a variant file may
# add one, and a duplicate table is a TOML error.
if [ -n "$variant" ]; then
    cat "$variant" >> "$dir/nosfry.toml"
fi
exec taskset -c "$RELAY_CPUS" "$bin" relay --config "$dir/nosfry.toml"
