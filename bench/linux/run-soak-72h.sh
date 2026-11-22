#!/usr/bin/env bash
# The 72-hour release-candidate soak, the production gate in
# bench/SOAK.md. Runs run-soak.sh at its default (gate) workload for
# 72 h, records the run's provenance before it starts, and writes the
# analyzer's verdict next to the JSONL when it ends.
# Usage: run-soak-72h.sh <nosfry-binary-name> <label>
#   Same container layout as run-soak.sh (bench/README.md). Env:
#   ANALYZER (default /src/nosfry/bench/soak_analyze.py), SOAK_OUT
#   (default /bench/results); DURATION (default 259200 s) and WARMUP
#   (the analyzer's warm-up, default 21600 s) shorten a rehearsal and
#   are recorded in the .meta; every other run-soak.sh knob passes
#   through.
set -euo pipefail

BENCH=/bench
BIN="${1:?usage: run-soak-72h.sh <nosfry-binary-name> <label>}"
LABEL="${2:?usage: run-soak-72h.sh <nosfry-binary-name> <label>}"
OUT="${SOAK_OUT:-$BENCH/results}"
ANALYZER="${ANALYZER:-/src/nosfry/bench/soak_analyze.py}"
META="$OUT/soak-$LABEL.meta"
DURATION="${DURATION:-259200}"
WARMUP="${WARMUP:-21600}"

[ -x "$BENCH/bin/$BIN" ] || { echo "no binary $BENCH/bin/$BIN" >&2; exit 1; }
[ -f "$ANALYZER" ] || { echo "no analyzer at $ANALYZER" >&2; exit 1; }
[ ! -e "$OUT/soak-$LABEL.jsonl" ] || { echo "$OUT/soak-$LABEL.jsonl exists; pick a new label" >&2; exit 1; }
mkdir -p "$OUT"

{
    echo "label: $LABEL"
    echo "started: $(date -u +%FT%TZ)"
    echo "binary: $BENCH/bin/$BIN"
    echo "binary sha256: $(sha256sum "$BENCH/bin/$BIN" | cut -d' ' -f1)"
    echo "version: $("$BENCH/bin/$BIN" --version)"
    echo "harness sha256: $(sha256sum "$BENCH/harness/target/release/nosfry-bench" | cut -d' ' -f1)"
    echo "kernel: $(uname -srm)"
    echo "cpus: $(nproc)"
    echo "memory: $(grep MemTotal /proc/meminfo)"
    echo "duration: $DURATION s, warm-up: $WARMUP s"
    echo "work filesystem: $(df -T "$BENCH/work" 2>/dev/null | tail -n 1)"
    echo "workload: publishers=${PUBLISHERS:-8} rate=${RATE:-200} subscribers=${SUBSCRIBERS:-200} churn=${CHURN_RATE:-10} slow_every=${SLOW_EVERY:-60} neg_every=${NEG_EVERY:-10} vanish_every=${VANISH_EVERY:-60} deflate=${DEFLATE:-0}"
} | tee "$META"

DURATION="$DURATION" SAMPLE="${SAMPLE:-60}" "$BENCH/run-soak.sh" "$BIN" "$LABEL"

echo "ended: $(date -u +%FT%TZ)" >>"$META"
status=0
python3 "$ANALYZER" "$OUT/soak-$LABEL.jsonl" --warmup-secs "$WARMUP" \
    --publishers "${PUBLISHERS:-8}" --subscribers "${SUBSCRIBERS:-200}" \
    | tee "$OUT/soak-$LABEL.verdict" || status=$?
echo "analyzer exit: $status" >>"$META"
# The analyzer also passes a relay killed by SIGTERM; the gate needs a
# clean exit.
rc="$(tail -n 1 "$OUT/soak-$LABEL.jsonl" | python3 -c \
    'import json, sys; r = json.load(sys.stdin); print(r["exit_status"] if r.get("type") == "relay_exit" else "missing")')"
echo "relay exit: $rc" | tee -a "$OUT/soak-$LABEL.verdict" "$META"
[ "$rc" = 0 ] || status=1
exit "$status"
