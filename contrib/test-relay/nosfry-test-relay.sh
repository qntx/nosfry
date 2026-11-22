#!/usr/bin/env bash
# Start a pinned nosfry as a local/CI test relay on a throwaway data
# dir, wait for NIP-11 readiness, print the endpoint, then serve until
# signalled. Cleanup is deterministic: TERM the relay, wait, KILL as
# last resort, remove the temp dir. See guides/test-relay.md.
set -euo pipefail

bin="${NOSFRY_BIN:-nosfry}"
port=""
seed=""
extra=""

usage() {
    cat >&2 <<'EOF'
usage: nosfry-test-relay.sh --port N [--bin PATH] [--seed FILE.jsonl] [--config-extra FILE]

  --port N          listener and service_url port on 127.0.0.1 (required:
                    service_url must equal the URL clients dial, so the
                    script cannot safely probe-then-bind one for you)
  --bin PATH        nosfry binary (default: $NOSFRY_BIN or `nosfry` on PATH)
  --seed FILE       JSON-lines event file imported once before start
  --config-extra F  TOML fragment appended to the generated config

Prints NOSFRY_URL, NOSFRY_RELAY_PID and NOSFRY_TMPDIR on stdout, then
stays in the foreground. Send the script SIGINT/SIGTERM to stop the
relay gracefully and remove the temp dir.
EOF
}

while (($#)); do
    case "$1" in
        --bin) bin="$2"; shift 2 ;;
        --port) port="$2"; shift 2 ;;
        --seed) seed="$2"; shift 2 ;;
        --config-extra) extra="$2"; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

if [[ -z "$port" || "$port" =~ [^0-9] || "$port" -lt 1 || "$port" -gt 65535 ]]; then
    echo "nosfry-test-relay: --port N (1-65535) is required" >&2
    usage
    exit 2
fi
command -v curl >/dev/null || {
    echo "nosfry-test-relay: curl is required for the readiness probe" >&2
    exit 2
}

tmpdir_base="${TMPDIR:-/tmp}"
tmpdir="$(mktemp -d "${tmpdir_base%/}/nosfry-test-relay.XXXXXX")"
config="$tmpdir/nosfry.toml"

cat >"$config" <<EOF
[db]
path = "$tmpdir/db"

[relay]
service_url = "ws://127.0.0.1:$port"

[[relay.listen]]
address = "127.0.0.1:$port"

[relay.profiles.default]
max_connections_per_peer = 0

[relay.profiles.default.rate_limits]
events_per_second    = 0
reqs_per_second      = 0
ip_events_per_second = 0
ip_reqs_per_second   = 0
EOF

if [[ -n "$extra" ]]; then
    cat "$extra" >>"$config"
fi

if [[ -n "$seed" ]]; then
    "$bin" --config "$config" import <"$seed"
fi

"$bin" --config "$config" relay >"$tmpdir/relay.log" 2>&1 &
relay_pid=$!

cleanup() {
    trap - INT TERM EXIT
    if kill -0 "$relay_pid" 2>/dev/null; then
        kill -TERM "$relay_pid" 2>/dev/null || true
        for _ in $(seq 1 100); do
            kill -0 "$relay_pid" 2>/dev/null || break
            sleep 0.05
        done
        kill -KILL "$relay_pid" 2>/dev/null || true
    fi
    rm -rf "$tmpdir"
}
trap cleanup INT TERM EXIT

# Ready means this relay logged its listener and answers NIP-11 —
# the log check keeps another process on the same port from passing
# for it.
ready=0
for _ in $(seq 1 600); do
    if ! kill -0 "$relay_pid" 2>/dev/null; then
        echo "nosfry-test-relay: relay exited during startup" >&2
        tail -n 20 "$tmpdir/relay.log" >&2 || true
        exit 1
    fi
    if grep -q "listening.*127\.0\.0\.1:$port" "$tmpdir/relay.log" &&
        curl -fs -H 'Accept: application/nostr+json' \
            "http://127.0.0.1:$port/" -o /dev/null 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.05
done

if [[ "$ready" != 1 ]]; then
    echo "nosfry-test-relay: not ready within 30 s" >&2
    tail -n 20 "$tmpdir/relay.log" >&2 || true
    exit 1
fi

echo "NOSFRY_URL=ws://127.0.0.1:$port"
echo "NOSFRY_RELAY_PID=$relay_pid"
echo "NOSFRY_TMPDIR=$tmpdir"

# Stay in the foreground until the relay exits or we are signalled;
# the EXIT trap then runs cleanup either way.
wait "$relay_pid" || true
