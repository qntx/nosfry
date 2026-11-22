#!/usr/bin/env bash
# Fail when an ELF binary references a glibc symbol version newer than
# the floor, e.g. `glibc-floor.sh target/.../nosfry 2.31`. Runs on the
# build host, before any container proves the binary starts.
set -euo pipefail

bin="${1:?usage: glibc-floor.sh <elf> <floor>}"
floor="${2:?usage: glibc-floor.sh <elf> <floor>}"
newest="$(readelf --version-info --wide "$bin" \
    | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -n 1)"
echo "newest glibc symbol version: ${newest:-none} (floor ${floor})"
[ -n "$newest" ]
[ "$(printf '%s\n%s\n' "$newest" "$floor" | sort -V | tail -n 1)" = "$floor" ]
