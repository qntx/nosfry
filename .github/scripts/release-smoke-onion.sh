#!/usr/bin/env bash
# Smoke-test an unpacked onion-variant release archive with no Tor
# network: `nosfry onion address` derives a stable ws://...onion URL
# offline into a mode-0700 state dir, the relay serves NIP-11 on its
# clearnet listener while Arti is still failing to bootstrap, the
# `listening` log line names the same onion URL, and SIGTERM exits
# 0. Release jobs run this under `docker --network none` on Linux;
# on macOS it runs on the host — no network isolation there.
#
#   release-smoke-onion.sh <unpacked archive dir> <expected version>
set -euo pipefail

dir="$(cd "${1:?usage: release-smoke-onion.sh <dir> <version>}" && pwd)"
version="${2:?usage: release-smoke-onion.sh <dir> <version>}"
work="$(mktemp -d)"
pid=""
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$work"' EXIT

"$dir/nosfry" --version | tee "$work/version.txt"
grep -qx "nosfry $version" "$work/version.txt"

# Minimal config: nosfry.example.toml is not reused — it already has a
# [relay.onion] table, which a second appended one would collide with.
cd "$work"
cat >nosfry.toml <<TOML
[db]
path = "$work/db"

[[relay.listen]]
address = "127.0.0.1:7777"

[[relay.listen]]
address = "onion:smoke"

[relay.onion]
state_dir = "$work/onion-state"
TOML

# Derives the key offline and prints one ws:// URL per onion listener.
addr="$("$dir/nosfry" --config nosfry.toml onion address)"
[ "$(printf '%s\n' "$addr" | wc -l | tr -d ' ')" = "1" ]
printf '%s\n' "$addr" | grep -Eqx 'ws://[a-z2-7]{56}\.onion'
# A second run reads the persisted key: the address must not change.
[ "$("$dir/nosfry" --config nosfry.toml onion address)" = "$addr" ]
# `stat -c` is GNU/Linux, `stat -f` BSD/macOS (GNU `stat -f` means
# file-system status and would not fail); the state dir is 0700.
mode="$(stat -c '%a' "$work/onion-state" 2>/dev/null || stat -f '%Lp' "$work/onion-state")"
[ "$mode" = "700" ]

"$dir/nosfry" --config nosfry.toml relay >relay.log 2>&1 &
pid=$!

# Same NIP-11 probe as release-smoke.sh: the clearnet listener serves
# immediately while Tor bootstrap retries with backoff.
nip11() {
    exec 3<>/dev/tcp/127.0.0.1/7777 || return 1
    printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n' >&3
    cat <&3
    exec 3<&-
}

for _ in $(seq 1 100); do
    if body="$(nip11 2>/dev/null)"; then
        break
    fi
    kill -0 "$pid" 2>/dev/null || { cat relay.log; exit 1; }
    sleep 0.1
done
printf '%s\n' "$body" | tail -n 1
printf '%s' "$body" | grep -q '"software":"https://github.com/qntx/nosfry"'
printf '%s' "$body" | grep -q "\"version\":\"$version\""

# `listening` logs each bound listener's Display: the onion one is
# "ws://<addr>.onion (onion:smoke)" — derived at bind time, before
# Arti bootstraps, so it is in the log well before NIP-11 answers.
grep -F "$addr" relay.log

kill -TERM "$pid"
status=0
wait "$pid" || status=$?
pid=""
cat relay.log
[ "$status" -eq 0 ]
echo "onion smoke ok: nosfry $version on $(uname -sm) ($addr)"
