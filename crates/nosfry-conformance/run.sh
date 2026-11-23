#!/usr/bin/env bash
# Run the black-box conformance suite against one edition.
#
#   run.sh native   build nosfry and run it with profile.toml
#   run.sh native-unix
#                   same, but the relay listens on a unix socket and
#                   unix_bridge.py forwards 127.0.0.1:$port to it
#   run.sh native-iroh
#                   same, but the relay listens on iroh:conformance
#                   (the `iroh` feature) and `nosfry connect` bridges
#                   127.0.0.1:$port to the endpoint
#   run.sh worker   build nosfry-worker and run it under wrangler dev
#   run.sh remote   run the suite against an already-running relay;
#                   NOSFRY_URL must be set (e.g. ws:// or wss://host)
#
# Local editions run THREE sequential passes against fresh relays:
#   pass 1 — profile.toml plus an injected service_url (AUTH on;
#            native also gets the write-policy plugin): every test
#            except those named `alt_*` or `access_*`.
#   pass 2 — profile-alt.toml (no service_url, AUTH off, shipped
#            defaults otherwise): only `alt_*` tests. A case named
#            `alt_*` may only assert behavior that holds on a relay
#            started with profile-alt.toml. On native-iroh AUTH is
#            on — the iroh listener itself is a canonical name — so
#            the two AUTH-off-only cases are skipped.
#   pass 3 — profile-access.toml plus an injected service_url (AUTH
#            on; no write-policy plugin): only `access_*` tests, one
#            at a time — the NIP-86 allow list each case manages is
#            relay-wide. A case named `access_*` may only assert
#            behavior that holds on a relay started with
#            profile-access.toml.
#   pass 4 — contrib/marmot/nosfry.toml, the shipped Marmot profile
#            with service_url/listen/db rewritten for the run (no
#            write-policy plugin): only `marmot_*` tests, one at a
#            time — the per-address rate bucket is shared by every
#            test on 127.0.0.1 and the burst case must stay honest.
# `remote` runs pass 1 only.
set -euo pipefail

edition="${1:?usage: run.sh <native|native-unix|native-iroh|worker|remote>}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
profile="$here/profile.toml"
profile_alt="$here/profile-alt.toml"
profile_access="$here/profile-access.toml"
profile_marmot="$root/contrib/marmot/nosfry.toml"
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

# Render the shipped Marmot profile into a runnable config for this
# run. For native it rewrites `service_url`, the listener address and
# the db path in place; for Workers it does the same `service_url`
# rewrite, drops the `[db]` and `[[relay.listen]]` tables the Workers
# schema does not have, and flattens
# `[relay.profiles.default.rate_limits]` to `[relay.rate_limits]`.
marmot_config() {
    # $1 = edition, $2 = output path, $3 = listener address
    # (`127.0.0.1:$port` or `unix:<path>`).
    python3 - "$1" "$profile_marmot" "$2" "$NOSFRY_URL" "$3" \
        "$tmpdir/db-marmot" <<'PY'
import sys

edition, src, dst, url, address, db = sys.argv[1:7]
worker = edition == "worker"
section, skip = "", False
out = []
for line in open(src):
    s = line.strip()
    if s.startswith("["):
        # `[db] # restart-only`-style headers: stop at the bracket.
        end = s.find("]]") if s.startswith("[[") else s.find("]")
        section = s[: end + (2 if s.startswith("[[") else 1)]
        skip = worker and section in ("[db]", "[[relay.listen]]")
        if skip:
            continue
        if worker and section == "[relay.profiles.default.rate_limits]":
            line = line.replace(
                "[relay.profiles.default.rate_limits]", "[relay.rate_limits]"
            )
        out.append(line)
        continue
    if skip:
        continue
    key = s.split("=", 1)[0].strip()
    # An iroh listener carries no client IP to read a header from.
    if (
        section == "[[relay.listen]]"
        and key == "real_ip_header"
        and address.startswith("iroh:")
    ):
        continue
    if section == "[relay]" and key == "service_url":
        line = f'service_url = "{url}"\n'
    elif section == "[[relay.listen]]" and key == "address":
        line = f'address = "{address}"\n'
    elif section == "[db]" and key == "path":
        line = f'path = "{db}"\n'
    out.append(line)
with open(dst, "w") as f:
    f.write("".join(out))
PY
}

# Start one relay for `pass` ("main" = profile + service_url +
# native write policy; "alt" = profile-alt, no service_url;
# "access" = profile-access + service_url; "marmot" = the shipped
# contrib/marmot profile rewritten for the run) and wait for it to
# answer HTTP. The build is shared: later worker `wrangler dev`
# startups are warm, and the passes never build or run concurrently.
start_server() {
    local pass="$1"
    local server_log="$tmpdir/server-$pass.log"
    case "$edition" in
    native|native-unix|native-iroh)
        local address="127.0.0.1:$port"
        if [ "$pass" = "marmot" ]; then
            # The shipped profile already carries [db] and
            # [[relay.listen]]: rewrite their values, never append.
            [ "$edition" = "native-unix" ] && address="unix:$tmpdir/relay-marmot.sock"
            [ "$edition" = "native-iroh" ] && address="iroh:conformance"
            marmot_config native "$tmpdir/config-marmot.toml" "$address"
        else
            local src="$profile"
            [ "$pass" = "alt" ] && src="$profile_alt"
            [ "$pass" = "access" ] && src="$profile_access"
            # The shared profile keeps [relay.rate_limits] for the worker
            # edition; native moved it under the `default` profile.
            sed 's/^\[relay\.rate_limits\]$/[relay.profiles.default.rate_limits]/' \
                "$src" >"$tmpdir/config-$pass.toml"
            # `[[relay.listen]]` is its own table, so it can always be
            # appended — no splice needed when the profile owns `[relay]`.
            [ "$edition" = "native-unix" ] && address="unix:$tmpdir/relay-$pass.sock"
            [ "$edition" = "native-iroh" ] && address="iroh:conformance"
            cat >>"$tmpdir/config-$pass.toml" <<EOF

[db]
path = "$tmpdir/db-$pass"

[[relay.listen]]
address = "$address"
EOF
        fi
        if [ "$edition" = "native-iroh" ]; then
            # Loopback only: no iroh relays, no address lookup — the
            # dial address carries the bound socket as its hint.
            cat >>"$tmpdir/config-$pass.toml" <<EOF

[relay.iroh]
state_dir = "$tmpdir/iroh-$pass"
relay_mode = "disabled"
address_lookup = "disabled"
EOF
            cat >"$tmpdir/connect-$pass.toml" <<EOF
[relay.iroh]
relay_mode = "disabled"
address_lookup = "disabled"
EOF
        fi
        if [ "$pass" = "main" ] || [ "$pass" = "access" ]; then
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
        fi
        if [ "$pass" = "main" ]; then
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
        if [ "$edition" = "native-iroh" ]; then
            # The supervise task logs `dial=<z32>@<ip:port>,…` once
            # the endpoint's sockets are bound; take the first hint
            # and rewrite its host to loopback.
            local dial=""
            for _ in $(seq 1 150); do
                # tracing's ANSI escapes sit inside the `dial=` field
                # name, so strip them before grepping; `|| true`
                # keeps a no-match grep from tripping `pipefail`.
                dial="$(tr -d '\033' <"$server_log" \
                    | sed -e 's/\[[0-9;]*m//g' \
                    | grep -o 'dial=[^ ]*' | tail -1 | cut -d= -f2- || true)"
                [ -n "$dial" ] && break
                sleep 0.2
            done
            if [ -z "$dial" ]; then
                echo "relay never logged its iroh dial address; log follows" >&2
                cat "$server_log" >&2 || true
                return 1
            fi
            local id="${dial%%@*}"
            local hints="${dial#*@}"
            local first="${hints%%,*}"
            dial="$id@127.0.0.1:${first##*:}"
            "$root/target/release/nosfry" connect "$dial" \
                --listen "127.0.0.1:$port" \
                --config "$tmpdir/connect-$pass.toml" \
                >"$tmpdir/bridge-$pass.log" 2>&1 &
            bridge_pid=$!
        fi
        ;;
    worker)
        if [ "$pass" = "marmot" ]; then
            marmot_config worker "$tmpdir/config-marmot.toml" ""
        else
            local src="$profile"
            [ "$pass" = "alt" ] && src="$profile_alt"
            [ "$pass" = "access" ] && src="$profile_access"
            cat "$src" >"$tmpdir/config-$pass.toml"
        fi
        if [ "$pass" = "main" ] || [ "$pass" = "access" ]; then
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
native|native-unix|native-iroh)
    if [ "$edition" = "native-iroh" ]; then
        cargo build --release --manifest-path "$root/Cargo.toml" -p nosfry --features iroh
    else
        cargo build --release --manifest-path "$root/Cargo.toml" -p nosfry
    fi
    ;;
worker)
    ;;
*)
    echo "usage: run.sh <native|native-unix|native-iroh|worker|remote>" >&2
    exit 2
    ;;
esac

if [ "$edition" = "remote" ]; then
    cd "$root" && cargo test -p nosfry-conformance -- --ignored --test-threads 8 --skip alt_ --skip access_ --skip marmot_
else
    # Pass 1: the shared profile plus service_url (AUTH on).
    start_server main
    cd "$root" && cargo test -p nosfry-conformance -- --ignored --test-threads 8 --skip alt_ --skip access_ --skip marmot_
    stop_server

    # Pass 2: profile-alt.toml, AUTH disabled — `alt_*` cases only.
    # On native-iroh the listener itself names the relay
    # (`ws://<z32>.iroh`), so AUTH is on and the two cases that can
    # only hold with no canonical name are skipped.
    start_server alt
    if [ "$edition" = "native-iroh" ]; then
        cd "$root" && cargo test -p nosfry-conformance -- --ignored --test-threads 8 \
            --skip alt_eose_no_auth_hint_when_auth_disabled \
            --skip alt_restricted_kinds_refused_without_auth alt_
    else
        cd "$root" && cargo test -p nosfry-conformance -- --ignored --test-threads 8 alt_
    fi
    stop_server

    # Pass 3: profile-access.toml, members-only reads — `access_*`
    # cases only, serialized: the NIP-86 allow list is relay-wide.
    start_server access
    cd "$root" && cargo test -p nosfry-conformance -- --ignored --test-threads 1 access_
    stop_server

    # Pass 4: the shipped contrib/marmot profile — `marmot_*` cases
    # only, serialized: every test shares 127.0.0.1's per-address
    # bucket and the burst case must not trip a sibling's tokens.
    start_server marmot
    cd "$root" && cargo test -p nosfry-conformance -- --ignored --test-threads 1 marmot_
    stop_server
fi
set +m
