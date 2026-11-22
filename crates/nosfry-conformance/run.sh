#!/usr/bin/env bash
# Run the black-box conformance suite against one edition.
#
#   run.sh native   build nosfry and run it with profile.toml
#   run.sh native-unix
#                   same, but the relay listens on a unix socket and
#                   unix_bridge.py forwards 127.0.0.1:$port to it
#   run.sh worker   build nosfry-worker and run it under wrangler dev
#   run.sh remote   run the suite against an already-running relay;
#                   NOSFRY_URL must be set (e.g. ws:// or wss://host)
#
# Local editions run TWO sequential passes against fresh relays:
#   pass 1 — profile.toml plus an injected service_url (AUTH on;
#            native also gets the write-policy plugin): every test
#            except those named `alt_*`.
#   pass 2 — profile-alt.toml (no service_url, AUTH off, shipped
#            defaults otherwise): only `alt_*` tests. A case named
#            `alt_*` may only assert behavior that holds on a relay
#            started with profile-alt.toml.
# `remote` runs pass 1 only.
set -euo pipefail

edition="${1:?usage: run.sh <native|worker|remote>}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
profile="$here/profile.toml"
profile_alt="$here/profile-alt.toml"
tmpdir="$(mktemp -d)"
server_pid=""
bridge_pid=""
generated_config=""

cleanup() {
    if [ -n "$server_pid" ]; then
        # The server runs in its own process group (see `set -m`
        # below): signal the whole group, so wrangler's node and
        # workerd children die with it instead of outliving the run.
        kill -- "-$server_pid" 2>/dev/null || kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if [ -n "$bridge_pid" ]; then
        kill -- "-$bridge_pid" 2>/dev/null || kill "$bridge_pid" 2>/dev/null || true
        wait "$bridge_pid" 2>/dev/null || true
    fi
    if [ -n "$generated_config" ]; then
        rm -f "$generated_config"
    fi
    rm -rf "$tmpdir"
}
trap cleanup EXIT

stop_server() {
    if [ -n "$bridge_pid" ]; then
        kill -- "-$bridge_pid" 2>/dev/null || kill "$bridge_pid" 2>/dev/null || true
        wait "$bridge_pid" 2>/dev/null || true
        bridge_pid=""
    fi
    if [ -n "$server_pid" ]; then
        kill -- "-$server_pid" 2>/dev/null || kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        server_pid=""
    fi
}

if [ "$edition" = "remote" ]; then
    : "${NOSFRY_URL:?remote mode needs NOSFRY_URL set to a running relay}"
else
    port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
    export NOSFRY_URL="ws://127.0.0.1:$port"
fi

wait_ready() {
    local log="$1"
    for _ in $(seq 1 600); do
        if curl -fsS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; then
            return 0
        fi
        if [ -n "$server_pid" ] && ! kill -0 "$server_pid" 2>/dev/null; then
            echo "server died; log follows" >&2
            cat "$log" >&2 2>/dev/null || true
            return 1
        fi
        sleep 0.5
    done
    echo "server did not become ready; log follows" >&2
    cat "$log" >&2 2>/dev/null || true
    return 1
}

# Start one relay for `pass` ("main" = profile + service_url +
# native write policy; "alt" = profile-alt, no service_url) and wait
# for it to answer HTTP. The build is shared: the second worker
# `wrangler dev` startup is warm, and the two never build or run
# concurrently.
start_server() {
    local pass="$1"
    local server_log="$tmpdir/server-$pass.log"
    case "$edition" in
    native|native-unix)
        local src="$profile"
        [ "$pass" = "alt" ] && src="$profile_alt"
        # The shared profile keeps [relay.rate_limits] for the worker
        # edition; native moved it under the `default` profile.
        sed 's/^\[relay\.rate_limits\]$/[relay.profiles.default.rate_limits]/' \
            "$src" >"$tmpdir/config-$pass.toml"
        # `[[relay.listen]]` is its own table, so it can always be
        # appended — no splice needed when the profile owns `[relay]`.
        local address="127.0.0.1:$port"
        [ "$edition" = "native-unix" ] && address="unix:$tmpdir/relay-$pass.sock"
        cat >>"$tmpdir/config-$pass.toml" <<EOF

[db]
path = "$tmpdir/db-$pass"

[[relay.listen]]
address = "$address"
EOF
        if [ "$pass" = "main" ]; then
            if grep -q '^\[relay\]' "$tmpdir/config-$pass.toml"; then
                # The profile already owns a [relay] table: splice
                # service_url into it — TOML tables may not be
                # declared twice.
                awk -v url="$NOSFRY_URL" '
                    { print }
                    /^\[relay\]$/ {
                        print "service_url = \"" url "\""
                        print "service_url_aliases = [\"wss://alias.nosfry.test\"]"
                    }
                ' "$tmpdir/config-$pass.toml" >"$tmpdir/config-$pass.toml.tmp"
                mv "$tmpdir/config-$pass.toml.tmp" "$tmpdir/config-$pass.toml"
            else
                cat >>"$tmpdir/config-$pass.toml" <<EOF

[relay]
service_url = "$NOSFRY_URL"
service_url_aliases = ["wss://alias.nosfry.test"]
EOF
            fi
            cat >>"$tmpdir/config-$pass.toml" <<EOF

[relay.write_policy]
plugin = "python3 $here/policy/policy.py"
EOF
        fi
        "$root/target/release/nosfry" relay --config "$tmpdir/config-$pass.toml" \
            >"$server_log" 2>&1 &
        server_pid=$!
        if [ "$edition" = "native-unix" ]; then
            python3 "$here/unix_bridge.py" 127.0.0.1 "$port" \
                "$tmpdir/relay-$pass.sock" >"$tmpdir/bridge-$pass.log" 2>&1 &
            bridge_pid=$!
        fi
        ;;
    worker)
        local src="$profile"
        [ "$pass" = "alt" ] && src="$profile_alt"
        cat "$src" >"$tmpdir/config-$pass.toml"
        if [ "$pass" = "main" ]; then
            cat >>"$tmpdir/config-$pass.toml" <<EOF

[relay]
service_url = "$NOSFRY_URL"
service_url_aliases = ["wss://alias.nosfry.test"]
EOF
        fi
        # Give the relay a POLICY service binding without carrying the
        # test-only wiring in the shipped wrangler.toml: copy it beside
        # itself (relative main/build paths keep working) and append the
        # binding the fixture worker provides in the same dev session.
        generated_config="$root/crates/nosfry-worker/.wrangler.conformance.toml"
        cat "$root/crates/nosfry-worker/wrangler.toml" >"$generated_config"
        cat >>"$generated_config" <<'EOF'

# Generated by crates/nosfry-conformance/run.sh; not for deploys.
[[services]]
binding = "POLICY"
service = "nosfry-policy"
EOF
        (
            cd "$root/crates/nosfry-worker"
            # worker-build needs a wasm32-capable clang.
            if [ -z "${CC_wasm32_unknown_unknown:-}" ]; then
                if brew_prefix="$(brew --prefix llvm 2>/dev/null)"; then
                    CC_wasm32_unknown_unknown="$brew_prefix/bin/clang"
                else
                    CC_wasm32_unknown_unknown="clang"
                fi
                export CC_wasm32_unknown_unknown
            fi
            # Persist into the run's temp dir so a stale local store
            # (e.g. an older FORMAT_VERSION) never poisons the suite.
            # The generated config carries the POLICY service binding
            # to the fixture worker; both configs run in one dev session.
            npx --yes wrangler@4.150.0 dev --local --port "$port" \
                -c .wrangler.conformance.toml \
                -c "$here/policy/wrangler.toml" \
                --persist-to "$tmpdir/persist-$pass" \
                --var "NOSFRY_CONFIG:$(cat "$tmpdir/config-$pass.toml")" \
                >"$server_log" 2>&1
        ) &
        server_pid=$!
        ;;
    esac
    wait_ready "$server_log"
}

set -m
case "$edition" in
remote)
    ;;
native|native-unix)
    cargo build --release --manifest-path "$root/Cargo.toml" -p nosfry
    ;;
worker)
    ;;
*)
    echo "usage: run.sh <native|native-unix|worker|remote>" >&2
    exit 2
    ;;
esac

if [ "$edition" = "remote" ]; then
    cd "$root" && cargo test -p nosfry-conformance -- --ignored --test-threads 8 --skip alt_
else
    # Pass 1: the shared profile plus service_url (AUTH on).
    start_server main
    cd "$root" && cargo test -p nosfry-conformance -- --ignored --test-threads 8 --skip alt_
    stop_server

    # Pass 2: profile-alt.toml, AUTH disabled — `alt_*` cases only.
    start_server alt
    cd "$root" && cargo test -p nosfry-conformance -- --ignored --test-threads 8 alt_
    stop_server
fi
set +m
