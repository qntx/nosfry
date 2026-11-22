#!/usr/bin/env bash
# Smoke-test a built container image: it reports the expected version,
# runs as the non-root user, serves NIP-11 with the bundled
# configuration, stops cleanly on SIGTERM, and refuses to start with a
# write-policy plugin configured, because the distroless image has no
# shell to spawn it with.
#
#   image-smoke.sh <image> <expected version>
set -euo pipefail

image="${1:?usage: image-smoke.sh <image> <version>}"
version="${2:?usage: image-smoke.sh <image> <version>}"
cid=""
work="$(mktemp -d)"
trap 'if [ -n "$cid" ]; then docker rm -f "$cid" >/dev/null 2>&1 || true; fi; rm -rf "$work"' EXIT

docker run --rm "$image" --version | grep -qx "nosfry $version"
[ "$(docker image inspect --format '{{.Config.User}}' "$image")" = "nonroot:nonroot" ]

cid="$(docker run -d -p 127.0.0.1::7777 "$image")"
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
docker logs "$cid" 2>&1 | tail -n 5
docker rm "$cid" >/dev/null
cid=""

cat docker/nosfry.toml - >"$work/plugin.toml" <<'TOML'

[relay.write_policy]
plugin = "/bin/true"
TOML
chmod 644 "$work/plugin.toml"
if out="$(docker run --rm -v "$work/plugin.toml:/etc/nosfry/nosfry.toml:ro" "$image" 2>&1)"; then
    echo "image started with a write-policy plugin and no shell" >&2
    exit 1
fi
printf '%s\n' "$out" | tail -n 3
printf '%s' "$out" | grep -q 'relay.write_policy.plugin needs /bin/sh'
echo "image smoke ok: nosfry $version"
