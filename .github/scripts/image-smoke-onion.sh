#!/usr/bin/env bash
# Smoke-test the onion-variant container image: it reports the
# expected version and runs as the non-root user, `onion address`
# derives a ws://...onion URL offline under `--network none` (the key
# lives under /data, which the image owns as nonroot), the relay
# serves NIP-11 on 0.0.0.0:7777 while Arti cannot bootstrap,
# `docker stop` exits 0, and the `listening` log names an onion URL.
#
#   image-smoke-onion.sh <image> <expected version>
set -euo pipefail

image="${1:?usage: image-smoke-onion.sh <image> <version>}"
version="${2:?usage: image-smoke-onion.sh <image> <version>}"
cid=""
work="$(mktemp -d)"
# The container's nonroot user owns what it wrote under $work/data, so
# the runner may be unable to remove all of it; that must not fail the
# smoke.
trap 'if [ -n "$cid" ]; then docker rm -f "$cid" >/dev/null 2>&1 || true; fi; rm -rf "$work" 2>/dev/null || true' EXIT

docker run --rm "$image" --version | grep -qx "nosfry $version"
[ "$(docker image inspect --format '{{.Config.User}}' "$image")" = "nonroot:nonroot" ]

# One TCP listener and one embedded onion service; both db.path and
# state_dir under /data, which the image's nonroot user can write.
cat >"$work/nosfry.toml" <<'TOML'
[db]
path = "/data/nosfry-db"

[[relay.listen]]
address = "0.0.0.0:7777"

[[relay.listen]]
address = "onion:smoke"

[relay.onion]
state_dir = "/data/onion-state"
TOML
chmod 644 "$work/nosfry.toml"

# No interfaces but loopback: the key and its URL are derived locally.
# /data is bind-mounted from the work dir so the relay run below reuses
# the same key and logs this exact address. It is world-writable for the
# image's nonroot user, with the sticky bit: Arti's fs-mistrust accepts
# a world-writable intermediate directory only when it is sticky.
mkdir "$work/data"
chmod 1777 "$work/data"
addr="$(docker run --rm --network none \
    -v "$work/nosfry.toml:/etc/nosfry/nosfry.toml:ro" \
    -v "$work/data:/data" \
    "$image" onion address)"
printf '%s\n' "$addr" | grep -Eqx 'ws://[a-z2-7]{56}\.onion'

# The host reaches the relay over the default bridge; Arti bootstrap
# failure does not block the clearnet listener.
cid="$(docker run -d -p 127.0.0.1::7777 \
    -v "$work/nosfry.toml:/etc/nosfry/nosfry.toml:ro" \
    -v "$work/data:/data" \
    "$image")"
port="$(docker port "$cid" 7777/tcp | head -n 1 | sed 's/.*://')"
body=""
for _ in $(seq 1 100); do
    if body="$(curl -fsS -H 'Accept: application/nostr+json' "http://127.0.0.1:$port/" 2>/dev/null)"; then
        break
    fi
    sleep 0.2
done
printf '%s\n' "$body"
printf '%s' "$body" | grep -q "\"version\":\"$version\""

docker stop -t 20 "$cid" >/dev/null
[ "$(docker inspect --format '{{.State.ExitCode}}' "$cid")" = 0 ]
docker logs "$cid" 2>&1 | tee "$work/relay.log"
docker rm "$cid" >/dev/null
cid=""

grep -F "$addr" "$work/relay.log"
echo "onion image smoke ok: $image nosfry $version ($addr)"
