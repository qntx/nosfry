#!/usr/bin/env bash
# Assert a release variant's Arti linkage on two surfaces:
#
#   - the binary: release binaries are stripped, but dependency panic
#     paths (".../tor-proto-0.48.0/src/...") survive as strings;
#   - the SBOM: the CycloneDX component list names every crate.
#
# A `default` artifact must show no Arti on either surface; an `onion`
# one must show it on both — the positive arm proves the check can
# actually see Arti instead of passing vacuously.
#
#   arti-check.sh <binary> <sbom.cdx.json> <default|onion>
set -euo pipefail

bin="${1:?usage: arti-check.sh <binary> <sbom.json> <default|onion>}"
sbom="${2:?usage: arti-check.sh <binary> <sbom.json> <default|onion>}"
variant="${3:?usage: arti-check.sh <binary> <sbom.json> <default|onion>}"

# `-a` reads the stripped binary as text; `-c` counts matching lines.
# grep exits 1 on zero matches, so keep the count and continue.
paths="$(grep -aEc '(arti-client|tor-[a-z0-9-]+)-[0-9]+\.[0-9]+\.[0-9]+/src/' "$bin" || true)"
components="$(jq '[.components[].name | select(. == "arti-client" or startswith("tor-"))] | length' "$sbom")"

case "$variant" in
    default)
        if [ "$paths" != 0 ]; then
            echo "::error::default binary embeds $paths Arti crate paths" >&2
            exit 1
        fi
        if [ "$components" != 0 ]; then
            jq -r '.components[].name | select(. == "arti-client" or startswith("tor-"))' "$sbom" >&2
            echo "::error::default SBOM lists the Arti crates above" >&2
            exit 1
        fi
        ;;
    onion)
        if [ "$paths" = 0 ]; then
            echo "::error::onion binary embeds no Arti crate paths" >&2
            exit 1
        fi
        if [ "$components" = 0 ]; then
            echo "::error::onion SBOM has no arti-client component" >&2
            exit 1
        fi
        ;;
    *)
        echo "usage: arti-check.sh <binary> <sbom.json> <default|onion>" >&2
        exit 2
        ;;
esac

echo "arti-check ok: $variant ($paths Arti path lines, $components SBOM components)"
