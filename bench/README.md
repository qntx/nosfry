# Benchmark tooling

Reproducible head-to-head benchmarks of nosfry against strfry. Nothing here
is part of the cargo workspace: `bench/nosfry-bench` is excluded in the root
`Cargo.toml`.

## Harnesses

- **relayBench** (third party, from
  [amethyst](https://github.com/vitorpamplona/amethyst) `relayBench/` at
  commit `9847d0a`; driven by `linux/run-relaybench.sh`).
  - Replays a deterministic corpus: synthetic `--events N --seed S`, or a
    dump via `--corpus`.
  - Measures ingest throughput, `OK` latency, and receipt-to-queryable
    latency.
  - Runs 12 client-shaped queries, reporting time to first event, time to
    `EOSE`, and 8-connection throughput.
  - Cross-checks the result sets of all relays.
  - Its OkHttp client negotiates permessage-deflate.
- **nosfry-bench** (`nosfry-bench/`; driven by `linux/run-nosfry-bench.sh`).
  - `fanout` measures publish-to-delivery latency for every subscriber and
    event pair, with exact delivery accounting and relay CPU.
  - `conns` measures anonymous resident memory per idle subscribed
    connection.
  - `soak` runs a mixed long-running workload against one relay
    (driven by `linux/run-soak.sh`): paced publishers writing a
    deterministic kind mix and awaiting every `OK`, long-lived
    subscribers counting deliveries, short-lived connections churning
    historical REQs and COUNTs, periodically spawned `REQ {}`
    consumers that never read, negentropy sessions ending by
    `NEG-CLOSE`, disconnect and the idle reaper, and vanish rounds
    that publish then ask the relay to delete them. Every
    `--sample-secs` it prints one cumulative JSON line with relay
    RSS, `data.mdb` size, connection, rate-limit,
    `nosfry_outbound_pending_bytes`, `nosfry_sync_memory_bytes` and
    `nosfry_subscription_bytes` metrics, and the workload counters; a
    final `end` line (with `outbound_pending_after_close`,
    `sync_memory_after_close` and `subscription_bytes_after_close`,
    the gauge values once every harness connection is closed) and a
    `relay_exit` line close the JSONL.
  - `gen` builds the D2 synthetic corpus (`--template` a gzipped JSON
    array of real events such as the Amethyst startup dump). The
    corpus is reproducible byte for byte: event `i` is fully
    determined by `--seed` and `i` (`sha256(seed || "ev" || i)` seeds
    a `ChaCha20Rng`), so `--threads` never changes the output.
    Templates keep their kind, tag skeleton and content; events get
    fresh authors drawn Zipf (s = 1.0) over `--authors` generated
    keypairs, a `created_at` spread over a fixed two-year window, and
    BIP-340 signatures with zero auxiliary randomness. Template events
    of ephemeral kinds (20000-29999) are dropped, and so are kinds 5
    (NIP-09 deletion) and 62 (NIP-62 request to vanish): with
    Zipf-drawn authors one popular author's vanish would wipe a large
    share of the corpus and deletions would make stored counts
    relay-dependent. Templates carrying an `expiration` tag or a tag
    element over 1,024 bytes are dropped for the same reason: they
    would expire by ingest time or be rejected by the relays' size
    limits. Every drop reason is counted in the final JSON.
  - The e-pool: the first `P = 100,000` generated ids are the reply
    pool. Pool members carry no `e` tags of their own (a template `e`
    tag degrades to a `p` tag with a Zipf-drawn author); every event
    past `P` rewrites its `e` tags to a uniformly drawn pool id, so
    `#e` thread queries fan out to a real, shared set of parents.
  - Outputs in `--out`: `events.jsonl` (the `--events` prefix),
    `holdout.jsonl` (`--holdout` tail, the ingest driver's input),
    `params.json` (query-driver sidecar: popular and random authors,
    random ids, top `t` values, follow lists, `created_at` range,
    kind counts, `(kind, pubkey, d)` triples and `pool_ids`) and
    `fingerprints.txt` (sha256 of each).
  - `ingest-open` paces `--corpus` events at a fixed `--rate` over
    `--conns` connections for `--duration` seconds; `ingest-closed`
    keeps a `--window` of outstanding events per connection. Both
    report `accepted`, `rejected`, `timeouts`, `late_acks`, send-lag
    and OK-latency histograms, and `valid` when no timeouts occurred.
  - `query` replays the `mix.json` REQ templates against `params.json`
    as closed REQ→EOSE→CLOSE loops; per-query stats land in `--log`
    and the summary reports per-template EOSE latency histograms and
    event counts.
  - `corpus-filter --regular [--skip N] [--first N]` keeps only regular
    kinds (1, 2, 4-44, 1000-9999) and reports scanned/kept/dropped.
  - `neg` runs one NIP-77 session over filter `{}`: the relay must
    hold the first `--base` lines of `--corpus`; the client drops a
    seeded `diff-pct/2` percent of them and adds the same share from
    `--holdout-corpus`, then checks the reconciled `have`/`need`
    against those expected sets and reports `correct`, rounds, wall
    time, and payload vs overhead bytes.
  - `ack-ingest` paces `--corpus` like `ingest-open` with no warm-up
    and appends every accepted id (`duplicate:` included) to `--out`,
    flushed every 100 lines and on exit; a dropped connection flushes
    and exits 0. `ack-check` REQs the file back in `{"ids":[500]}`
    batches and reports `acked`, `found`, `missing` and up to 20
    sample ids; `valid` means the queries ran without errors.
- **aggregate.py**: `python3 bench/aggregate.py <results-dir>` prints the
  median and [min, max] of every metric across repeated runs.
- **soak_analyze.py**: `python3 bench/soak_analyze.py <run.jsonl>
--warmup-secs N` applies the soak criteria (anonymous-memory slope,
  `data.mdb` plateau, connection gauge, zero errors) and exits non-zero
  on a failure. Use a warm-up of at least the 600 s event expiration;
  the 72 h gate run uses 6 h.

## Environment

The scripts run inside the Linux container built from `linux/Dockerfile`:
Ubuntu 24.04, JDK 21, Rust, and strfry's build dependencies. Relays are
pinned to cores 0-3 (`strfry-pinned.sh`, `linux/relays/nosfry.sh`) and harnesses to
cores 4-9, so a 10-core machine is expected. Check `nproc` first; the
scripts do not.

## Setup

Build relayBench on the host (JDK 21), once:

```bash
git clone https://github.com/vitorpamplona/amethyst && cd amethyst
git checkout 9847d0a
./gradlew :relayBench:installDist
```

Start the container, mounting this repository and the amethyst checkout:

```bash
docker build -t nosfry-bench:linux bench/linux
docker volume create nosfry-bench-work
# --init reaps the zombie relay/harness children that a wrapper or a
# killed unit leaves behind; --privileged is needed for drop_caches.
docker run -d --name nosfry-bench --init --privileged \
    --ulimit nofile=1048576:1048576 \
    -v nosfry-bench-work:/bench/work \
    -v "$PWD/results:/bench/results" \
    -v "$PWD:/src/nosfry:ro" \
    -v /path/to/amethyst:/amethyst:ro \
    nosfry-bench:linux sleep infinity
```

Inside the container (`docker exec nosfry-bench bash -lc '...'`):

```bash
# strfry 1.1.3, unpatched
git clone https://github.com/hoytech/strfry /bench/strfry-1.1.3
cd /bench/strfry-1.1.3 && git checkout 1.1.3 && git submodule update --init
make setup-golpe && make -j10

# one nosfry binary per commit under test
mkdir -p /bench/bin && git clone /src/nosfry /bench/nosfry-src
cd /bench/nosfry-src && git checkout <sha> && cargo build --release -p nosfry
cp target/release/nosfry /bench/bin/<name>

# nosfry-bench
cp -r /src/nosfry/bench/nosfry-bench /bench/harness
cd /bench/harness && cargo build --release

# relayBench and its real-event corpus
cp -r /amethyst/relayBench/build/install/relaybench /bench/relaybench
mkdir -p /bench/corpus
cp /amethyst/quartz/src/commonTest/resources/nostr_vitor_startup_data.json.gz /bench/corpus/

# drivers, relay wrappers, and config variants
cp /src/nosfry/bench/linux/*.sh /bench/
cp -r /src/nosfry/bench/linux/variants /bench/variants
```

## Runs

```bash
/bench/run-relaybench.sh <name>...
/bench/run-nosfry-bench.sh /bench/results/nosfry-bench <reps> <name>...
# a name may be bin+variant: /bench/variants/<variant>.toml is appended
# to the generated config and the full label stays in every result
/bench/run-nosfry-bench.sh /bench/results/r6 3 nosfry-020 nosfry-main nosfry-main+sliding
DURATION=1800 SAMPLE=30 /bench/run-soak.sh <name> [label]
```

`run-soak.sh` writes `/bench/results/soak-<label>.jsonl` and the
relay's log lives at `/bench/work/soak-<label>/relay.log`. Defaults:
8 publishers at 200 events/s total, 200 subscribers, 10 churn
connections/s, one slow consumer per minute, one negentropy session
per 10 s, one vanish round per minute; `DURATION` and `SAMPLE`
(seconds between samples) plus every workload knob
(`PUBLISHERS`, `RATE`, `SUBSCRIBERS`, `CHURN_RATE`, `SLOW_EVERY`,
`NEG_EVERY`, `VANISH_EVERY`)
are environment-overridable. `DEFLATE=1` makes every harness
connection negotiate permessage-deflate; `PORT`, `RELAY_CPUS`, and
`HARNESS_CPUS` move the soak off the default port and cores — a soak
can share the box with a benchmark run this way.

Each `<name>` is a binary in `/bench/bin`; strfry always runs alongside.

- `run-relaybench.sh` runs relayBench 3 times on the synthetic corpus
  (100,000 events, seed 1) and twice on the real corpus. It rotates the
  order of the nosfry binaries between runs; strfry always runs first, a
  relayBench limitation.
- `run-nosfry-bench.sh` runs six scenarios: broadcast to 1,000 subscribers
  (plain and deflate), broadcast to 5,000, selective delivery to 2,000, and
  5,000 idle connections (plain and deflate). Each scenario starts against
  a fresh relay and database, and the relay order rotates on every rep.

`linux/relays/nosfry.sh` disables the rate limits and the per-IP connection cap
in the generated config: the scenarios run thousands of subscribers from
one IP and flood ingest over a single connection, and the benchmark
measures the engine, not the limiter.

## Round 7

`r7/run.py` is the orchestrator: Python 3.12, standard library only,
driven entirely by `r7/params.toml` (`tomllib`).

```bash
python3 r7/run.py prep            # corpus-filter + one d2 import per relay
python3 r7/run.py pilot w1        # one short rep per relay
python3 r7/run.py w1              # … w2 w3 w4 w5 w6 w7 w8
python3 r7/run.py status          # units done / valid per workload
python3 r7/run.py --dry-run w4    # print the schedule, start nothing
```

Every measured unit checks no other relay or harness process is
running, records the load average, starts the relay through its
`linux/relays/<relay>.sh` wrapper (`<binary> <port> <dir>
[variant]`, `RELAY_CPUS`/`DB_DIR`/`METRICS` env), waits for the port,
does one warm-up REQ, captures stdout to `rep<k>.json` and stderr to
`rep<k>.log`, stops the relay with TERM then KILL after 10 s, and
copies `relay.log` and the generated config next to the results.
Relay order rotates per rep. Results land at
`/bench/results/r7/<workload>/<scenario>/<relay-label>/` plus
`manifest.jsonl`; `run-meta.json` records the build info, sysctls,
ulimit, affinity masks, and the params content and sha256.

Databases: `prep` imports `events.jsonl` once per relay into
`work/db/<bin>` — the one imported db every read-only unit shares;
there are no snapshots to restore. Workloads that write or need a
clean slate get a scratch dir under `work/db-<wl>/<bin>` (w1/w3/w4
wiped per unit, w7 per rep, w8 wiped once then accumulating across
cycles), and w6 imports `regular.jsonl` into `work/db-w6/<bin>` once
per rep.

Workloads: w1 ingest saturation (closed conns × window, then open
loop at the frozen per-relay `open_rates`); w2 the D2 query mix,
warm and cold (drop_caches), plus D1 relayBench continuity; w3
fanout broadcast and selective; w4 connection scale up to 50,000
(harness binds spread over 127.0.0.2-127.0.0.9 when ports run out);
w5 read-only query and restart-timing reps on the shared db, then
ingest reps on a fresh full copy of the imported db — every unit
replays the same corpus slice so the measured db is identical per
rep (the d2 import itself is timed by `prep`); w6
NIP-77 `neg` over its freshly imported 1M-event db at 0.1/1/10%
diffs; w7 the 24 h soak profile per relay (negentropy and vanish
skipped where unsupported); w8 crash durability: ack-ingest,
kill the relay at a seeded-random 2-20 s, restart, ack-check.

Analysis runs next to the results, inside the container, because it
reads each unit's `relay.log`:

```bash
python3 r7/analyze.py /bench/results/r7 --json summary.json > report.md
uv run --python 3.12 --with scipy --with statsmodels python r7/test_stats.py
```

`analyze.py` takes the last manifest line per unit, so a rerun
replaces the earlier attempt. It prints the eight pre-registered
primary comparisons (exact two-sided Mann–Whitney U, Holm over all
eight, a claim only when the adjusted p < 0.05 and the median intervals
are disjoint), one table per workload and metric with the median and a
distribution-free interval per relay, the W7 soak rows and the W8
durability totals. Every rep is listed; a rep with a flag (timeouts,
rejected events, send lag ≥ 5 ms, an empty result set, missing or
duplicate deliveries, a negentropy set mismatch, a database below its
import count) stays out of the medians and tests and is named under
its workload. strfry answers an older replaceable version with
`replaced:`, which older harness builds counted as a rejection; the
analysis accepts those reps only when the unit's `relay.log` shows no
other kind of rejection. `test_stats.py` checks `stats.py` against
SciPy and statsmodels.

The durability comparison adds a measurement-only build, never shipped,
that opens LMDB with `EnvFlags::NO_META_SYNC` in `Store::open`. This
reproduces the `MDB_NOMETASYNC` strfry effectively runs with: rasgueadb
passes `MDB_CREATE`, the same bit 0x40000, to `mdb_env_open`
(hoytech/strfry#282).

### Round 7b

`r7/params-7b.toml` re-measures the cells touched by #79, #80 and #81:

- W1 closed-c32 and open-4500/5400;
- W2 c8 and c64, plain and deflate;
- W3 broadcast-5000-plain;
- W4 10,000 connections;
- W5.

Every workload value it sets is the Round 7 one. `nosfry-030` runs in the same session as the control, and `[analysis]` points the primaries at the new build.

W2 and W5 reuse the Round 7 imports instead of importing again; the volume has no room for a second pair of 18.7 GB databases. The shared directories are symlinks, and each needs a `prep-imports.jsonl` record so `require_main_dbs` accepts it:

```bash
mkdir -p /bench/work/r7b/db /bench/results/r7b
ln -s /bench/work/r7/db/nosfry-030 /bench/work/r7b/db/nosfry-030
ln -s /bench/work/r7/db/nosfry-030 /bench/work/r7b/db/nosfry-7b
ln -s /bench/work/r7/db/strfry     /bench/work/r7b/db/strfry
# one {"corpus": "d2", "label": ..., "stored": <current count>} line per label
```

nosfry-030 and nosfry-7b share one database (same on-disk format). They must never both ingest into it, so only nosfry-7b and strfry run W5. Round 7 already ingested slices 0, 200k, and 400k, so `w5.skip_base = 600_000` starts the new ones after them. Both databases hold 5 to 7 % more events than during the Round 7 W2 runs, and the report says so.

These W5 ingest cells are void for the read-ahead reason Round 7d explains: they ran with the filesystem bdi read-ahead at 4 MiB and every rep hit the same LMDB page-fault storm.

### Round 7c

`r7/params-7c.toml` has two aims: a 12-rep A/B of W2 q-c64-plain between nosfry-7b and nosfry-030 to settle the possible #80 regression, and a W5 ingest rate sweep (1500/2000/2500) of nosfry-7b vs strfry to find each relay's sustainable rate on the grown databases. Results go to `/bench/results/r7c` and work dirs to `/bench/work/r7c`; the W2/W5 databases are again the Round 7 imports reused through symlinks (`/bench/work/r7c/db/<label>`), like Round 7b. W5 continues the holdout corpus after the Round 7b slices: `w5.skip_base = 1_200_000`, contiguous `rate * ingest_secs` slices per (rep, rate). Its ingest cells are void for the same read-ahead reason as Round 7b's.

### Round 7d

`r7/params-7d.toml` re-measures W5 after the btrfs read-ahead finding: on the bench host, btrfs raises the filesystem bdi read-ahead to at least 4 MiB (`/sys/class/bdi/btrfs-*/read_ahead_kb = 4096`), and with a 21 GB LMDB db bigger than RAM every writer page fault read megabytes — the Round 7/7b/7c W5 ingest collapse was that storm, not the relays. At 128 KiB (the ext4/xfs default) both relays sustain 1500/s with zero timeouts, and queries are unaffected (MDB_NORDAHEAD also fixes ingest but costs ~10x warm query throughput). W1/W3/W4 results stand — they ran on RAM-resident databases — and W2/W5 query cells are unaffected.

Method: fresh D2 imports via `run.py prep` with `params-7d.toml`; `[host] read_ahead_kb = 128` pins the fs bdi read-ahead for prep and for the run, recorded into `run-meta.json` and restored afterwards (also on SIGTERM). Every ingest unit gets a fresh `--reflink=never` copy of the shared import under `work/db-w5/`, dropped caches, and the identical corpus slice (`skip_base = 0`, `ceil(rate * ingest_secs)` lines); a 10 GiB free-space guard aborts before a copy that would not fit. Lineup: `nosfry-7d` = main at `af66802` (Round 7b's writer plus the #81 revert), and strfry; three reps at 1500/2000/2500/3000 events per second.

## Output

- `run-relaybench.sh`: `<out>/<run>/<timestamp>/{report.md,results.json}` and
  `<out>/<run>.log`.
- `run-nosfry-bench.sh`: `<out>/results.jsonl` (one JSON object per scenario,
  relay, and rep) and `<out>/rep<N>-<relay>-<scenario>.log`.
- `python3 bench/aggregate.py results` summarizes both.
