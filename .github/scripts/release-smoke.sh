#!/usr/bin/env bash
# Smoke-test an unpacked release archive on the current system: the
# binary runs, the shipped nosfry.example.toml loads unmodified, the
# relay serves NIP-11 on an empty database, and SIGTERM exits 0.
#
#   release-smoke.sh <unpacked archive dir> <expected version>
set -euo pipefail

dir="$(cd "${1:?usage: release-smoke.sh <dir> <version>}" && pwd)"
version="${2:?usage: release-smoke.sh <dir> <version>}"
work="$(mktemp -d)"
pid=""
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$work"' EXIT

"$dir/nosfry" --version | tee "$work/version.txt"
grep -qx "nosfry $version" "$work/version.txt"

cd "$work"
cp "$dir/nosfry.example.toml" nosfry.toml
"$dir/nosfry" relay >relay.log 2>&1 &
pid=$!

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

kill -TERM "$pid"
status=0
wait "$pid" || status=$?
pid=""
cat relay.log
[ "$status" -eq 0 ]
echo "smoke ok: nosfry $version on $(uname -sm)"
