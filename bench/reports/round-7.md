# Round 7: nosfry vs strfry 1.1.3

This report covers Round 7, which compared nosfry 0.3.0 with strfry 1.1.3 and
nostr-rs-relay 0.10.0, and the follow-up rounds 7b to 7e, which measured the
fixes made on `main` afterwards. Each table names the build it measured. Raw
data, per-unit logs and the orchestrator configuration are kept on the bench
host (see [Reproducing](#reproducing)).

## Summary

On a single 10-vCPU Linux VM, current `main` (`2898125`) compares with strfry
1.1.3 as follows:

| area | result | source |
|---|---|---|
| Ingest throughput, fresh db, 32 closed-loop connections | nosfry 5673/s vs 4480/s (+27 %, Holm p = 0.017); Round 7e 5192 vs 4542/s, not significant (p = 0.39) | 7b, 7e |
| Ingest CPU per `OK` | nosfry 0.35-0.43x strfry | 7b, 7e |
| `OK` latency p50, open loop 4500/5400 events/s | nosfry 0.57-0.59x strfry (p <= 0.004) | 7e |
| `OK` latency p99, open loop 4500/5400 events/s | no significant difference (p >= 0.09); strfry's p99 is tighter at 5400/s | 7e |
| Queries on an 8.35M-event db | nosfry p50 0.55x strfry at 8 connections, 1.26x throughput at 64; 1.8-3.8x throughput with permessage-deflate | 7b |
| Broadcast latency to 5000 subscribers | nosfry p50 21 ms vs 93 ms | 7b |
| Broadcast CPU per delivery | **strfry better**: 3.68 us vs nosfry 9.33 us | 7b |
| Memory per idle connection, no compression | **strfry better**: 1.00 KiB vs nosfry 7.23 KiB | 7b |
| Memory per idle connection, permessage-deflate | nosfry 7.31 KiB vs 109 KiB | 7b |
| Sustained ingest into an 18.7 GB db (larger than RAM) | both sustain 3000 events/s with no timeouts and similar latency; **strfry also sustains 3500/s**, nosfry does not | 7e |
| 24 h soak | nosfry and strfry both flat (+0.05 / +0.03 MiB/h RssAnon) | 7 |
| kill -9 durability, 50 cycles | nosfry: 0 acknowledged events missing | 7 |

nosfry does not beat strfry everywhere. It is faster on queries, broadcast
latency, CPU per write and compressed connections. strfry uses less memory per
plain connection, less CPU per broadcast delivery, and keeps up with a higher
sustained write rate once the database no longer fits in RAM.

## Setup

- Host: Apple M4 (16 GiB), macOS 26.5.2, OrbStack Linux VM 7.2.9 aarch64. The
  container sees 10 vCPUs and 12 GiB of memory.
- Pinning: the relay runs on cores 0-3 and the load generator
  (`bench/nosfry-bench`) on cores 4-9. `nofile` is 1,048,576.
- Storage: databases live on a btrfs volume mounted `nodatacow,noatime`.
  Rounds 7d and 7e pin the filesystem read-ahead to 128 KiB (see
  [Large-database ingest](#large-database-ingest-w5)).
- Builds:

| label | commit | notes |
|---|---|---|
| nosfry-030 | `95bccbc` (v0.3.0) | Round 7 baseline |
| nosfry-7b | `036eddc` | #79 writer batching, #80 connection memory, #81 lazy write deadline (later reverted) |
| nosfry-7d | `af66802` | 7b with #81 reverted |
| nosfry-e5, nosfry-7e | `bb2d45b`, `2898125` | #87: each write transaction drains the whole writer inbox (7e is the merge) |
| strfry | 1.1.3 (`16c00df`), unpatched | `g++ 13.3 -O3`, LTO |
| nostr-rs-relay | 0.10.0 (`b5c1f64`) | Round 7 only |

- Corpus: D2, a deterministic synthetic corpus of signed events generated
  from real event templates (the Amethyst startup dump), with Zipf-distributed
  authors. It has an 8.0M-event import file and a 2.0M-event holdout that the
  ingest workloads replay (see `bench/README.md`). Fresh imports stored
  7,842,556 events in nosfry and 7,840,019 in strfry.
- Statistics: each cell is the median and a distribution-free interval of
  95 % or more over valid reps. Comparisons use Mann-Whitney U. Round 7's
  eight primary comparisons are Holm-adjusted, and a difference is claimed only
  when the adjusted p < 0.05 and the two intervals do not overlap. A rep is
  invalid when the harness saw timeouts, errors, send lag of 5 ms or more, or
  harness saturation; `(k/n)` marks a cell with only k valid reps.

## Results

### Write path (W1, fresh database)

Round 7b, 6 reps:

| scenario | nosfry-7b | nosfry-030 | strfry | nosfry-7b/strfry | p |
|---|---|---|---|---|---|
| closed-c32 accepted/s | 5673 [5386, 5731] | 4640 [3856, 5323] | 4480 [4246, 4660] | 1.27 | 0.0022 |
| open-4500 `OK` p99 ms | 1655 [801, 2757] | 26903 [11575, 30605] | 1126 [826, 5546] | 1.47 | 0.39 |
| open-5400 `OK` p99 ms | 4028 [747, 6160] | — (0/6) | 1556 [1313, 1872] | 2.59 | 0.065 |
| open-4500 CPU us per `OK` | 83.1 | 63.0 | 196 | 0.42 | 0.0022 |

Round 7e, current `main`, 6 reps:

| scenario | nosfry-7e | strfry | ratio | p |
|---|---|---|---|---|
| closed-c32 accepted/s | 5192 [3588, 5996] | 4542 [4246, 5005] | 1.14 | 0.39 |
| closed-c32 `OK` p50 ms | 332 [329, 370] | 454 [417, 459] | 0.73 | 0.0022 |
| open-4500 `OK` p50 / p99 ms | 198 / 807 | 347 / 823 | 0.57 / 0.98 | 0.0022 / 0.78 |
| open-5400 `OK` p50 / p99 ms | 346 / 2393 | 584 / 1458 | 0.59 / 1.64 | 0.0043 / 0.093 |
| CPU us per `OK` (closed / 4500 / 5400) | 66.0 / 74.2 / 79.8 | 188 / 194 / 184 | 0.35-0.43 | 0.0022 |

#79 removed the multi-second stalls that 0.3.0 hit at 4500/s and above.
nosfry 0.3.0 kept a 1024-event write transaction and an unbounded inbox; at
open-4500 its p99 was 26.9 s, and at 5400/s it fell behind in every rep. The
fix itself is described under [Fixes](#fixes-made-during-this-round).

### Queries on a large database (W2)

Round 7b, 6 reps. The database holds about 8.35M events, cold cache means
`drop_caches` before each run, and the query mix is `bench/r7/mix.json`.

| scenario | nosfry-7b | strfry | ratio | p |
|---|---|---|---|---|
| c8 plain warm p50 ms | 2.42 | 4.39 | 0.55 | 0.0022 |
| c8 plain warm events/s | 746,968 | 424,467 | 1.76 | 0.0022 |
| c64 plain warm events/s | 677,208 | 538,508 | 1.26 | 0.0022 |
| c64 plain cold p50 ms | 54.8 | 38.4 | 1.43 | 0.0022 |
| c64 plain cold events/s | 189,507 | 205,176 | 0.92 | 0.24 |
| c8 deflate warm events/s | 229,963 | 64,842 | 3.55 | 0.0022 |
| c64 deflate warm events/s | 243,017 | 64,164 (3/6) | 3.79 | 0.024 |

With 64 connections and a cold cache, strfry has the lower median latency
(38 ms vs 55 ms) and throughput is not significantly different. In every warm
and every compressed scenario, nosfry is ahead. A 12-rep A/B in Round 7c
found no regression from #80: c64-plain-warm reached 667k events/s on
nosfry-7b vs 661k on 0.3.0, with a 6:6 paired split.

### Broadcast (W3)

Round 7b, 5000 subscribers at 20 events/s, plain WebSocket:

| metric | nosfry-7b | nosfry-030 | strfry |
|---|---|---|---|
| delivery latency p50 / p99 ms | 21.2 / 34.1 | 21.3 / 34.2 | 93.4 / 182 |
| relay CPU per delivery us | 9.33 | 9.33 | 3.68 |
| relay anon RSS after, MiB | 41.2 | 63.8 | 9.72 |

strfry batches deliveries, which costs latency and saves CPU. nosfry hands
each delivery from a monitor shard to the connection's task. Profiling (E2,
E4) put the remaining cost in the kernel TCP send path and in waking one task
per delivery. Closing the gap would mean cross-connection write batching, and
that would give up part of the latency advantage.

### Idle connections (W4)

Round 7b, 10,000 connections:

| metric | nosfry-7b | nosfry-030 | strfry |
|---|---|---|---|
| KiB per connection, plain | 7.23 | 11.0 | 1.00 |
| KiB per connection, permessage-deflate | 7.31 | 11.1 | 109 |

#80 removed about 3.8 KiB per connection. strfry multiplexes all connections
on one thread with shared buffers, so it stays near 1 KiB. nosfry runs one task
per connection, and its largest remaining fixed costs are the task, the
WebSocket read buffer and per-shard session state.

### Large-database ingest (W5)

W5 replays the holdout at a fixed open-loop rate for 60 s into an 18.7 GB
database, larger than the VM's memory. It then waits up to 30 s for the
remaining `OK`s; a send that never receives one counts as a timeout.

**Rounds 7, 7b and 7c are void for this workload.** btrfs sets its
backing-device read-ahead to at least 4 MiB
(`/sys/class/bdi/btrfs-*/read_ahead_kb = 4096`). Once the database outgrew
the page cache, every LMDB page fault read megabytes: during one 50 s ingest
the nosfry writer read 16-19 GB from disk and spent 64 of its 71 CPU seconds
in the kernel. At 128 KiB, the ext4/xfs default, both relays ingested 1500/s
with no timeouts and query throughput did not change. Setting `MDB_NORDAHEAD`
instead also fixes ingest but cuts warm query throughput about 10x, so the
benchmark pins the filesystem read-ahead (`[host] read_ahead_kb`). The same
advice now appears in `nosfry.example.toml` (#86). Since Round 7d, every
ingest unit also runs on a fresh full copy of the import with the page cache
dropped, so every rep starts from the same database.

Round 7d (nosfry-7d, before #87), 3 reps:

| rate | nosfry-7d valid | strfry valid | `OK` p99 s, nosfry / strfry |
|---|---|---|---|
| 1500/s | 3/3 | 3/3 | 20.6 / 21.7 |
| 2000/s | 3/3 | 3/3 | 20.1 / 23.9 |
| 2500/s | 1/3 | 3/3 | 32.2 / 30.4 |
| 3000/s | 0/3 | 3/3 | — / 31.7 |

nosfry-7d capped each write transaction at 16,384 events. Under backlog,
every commit hit the cap and took 7-11 s, which limited nosfry to about
1800 events/s. strfry commits whatever is queued, 38k-53k events every
13-17 s at 3000/s. On a database larger than RAM, a commit's cost tracks the
number of distinct dirty B-tree pages, and that grows sublinearly with batch
size. #87 removed the cap: a transaction now takes everything in the writer
inbox, which was already bounded at 65,536 requests and 64 MiB of event bytes.

E5, a same-session A/B of #87 against nosfry-7d, 3 reps: at 2500/s and
3000/s, #87 was valid in 6/6 runs (3000/s `OK` p99 27.0-30.0 s) against 0/6
for nosfry-7d. W1 on a fresh database showed no regression (all 18 units
valid, overlapping intervals). Peak anonymous RSS rose from about 433 MiB to
about 635 MiB during the runs; strfry peaked at about 674 MiB.

Round 7e (current `main`), 3 reps:

| rate | nosfry-7e valid | strfry valid | `OK` p50 s, nosfry / strfry | `OK` p99 s, nosfry / strfry | CPU us per `OK`, nosfry / strfry |
|---|---|---|---|---|---|
| 2500/s | 3/3 | 3/3 | 22.4 / 20.2 (p = 0.70) | 31.5 / 28.1 (p = 0.70) | 258 / 430 |
| 3000/s | 3/3 | 3/3 | 20.8 / 20.2 (p = 1.00) | 28.2 / 31.1 (p = 0.70) | 189 / 361 |
| 3500/s | 0/3 (31k-56k timeouts) | 3/3 | — / 23.7 | — / 38.5 | — / 330 |

Both relays are disk-bound at these rates: their `OK` latencies are 20-40 s
because the backlog queues up behind commits. Up to 3000/s the two are
statistically indistinguishable. At 3500/s strfry finished each 210k-event
run within the window, about 2400-2600 events/s end to end. nosfry's commit
time summed to 89-102 s for the same events, about 2100-2350 events/s, so
nosfry writes roughly 10-15 % less efficiently per event on this storage. The
leading hypothesis is index write amplification: nosfry's index entries are
larger, and its time index stores the 32-byte event id, giving about 3x the
leaf pages of strfry's equivalent. This has not been measured yet and is the
next item to investigate.

On SIGTERM, nosfry commits the events already queued before it exits (11-13 s
after a 3500/s run). strfry exits immediately (about 0.05 s) and drops events
it has not yet acknowledged.

### Negentropy sync (W6)

Round 7, nosfry 0.3.0 only. For 1M-event sets at 0.1/1/10 % difference, sync
took 399 / 501 / 1045 ms. Every strfry rep reported a set mismatch of about
246 events, so its cells are invalid. The mismatches are kind-41 events:
strfry treats kind 41 as replaceable, while NIP-01 classifies it as a regular
event.

### Soak and durability (W7, W8; Round 7, nosfry 0.3.0)

| relay | 24 h OKs | deliveries | RssAnon mean / slope | failures |
|---|---|---|---|---|
| nosfry-030 | 17.1M | 202.8M | 28.3 MiB / +0.052 MiB/h | none |
| strfry | 17.1M | 202.6M | 27.2 MiB / +0.031 MiB/h | 2877 negentropy failures |
| nostr-rs-0100 | 16.9M | 200.2M | 2263 MiB / +7.19 MiB/h | 172,801 COUNT failures |

In 50 kill -9 cycles, no event that nosfry 0.3.0 acknowledged was missing
after restart (228,187 acknowledged). strfry and nostr-rs-relay were each
missing 30 acknowledged kind-41 events, replaced by later kind-41 events under
their replaceable-kind-41 rule; these are not storage losses. Median restart
to first `EOSE` was 62-66 ms for all three relays.

## Fixes made during this round

| change | evidence | effect |
|---|---|---|
| #79 write batching, byte-bounded inbox | E1: with 1024-event transactions, synced bytes per event under backlog were nearly twice strfry's | open-4500 p99 26.9 s to 1.66 s; closed throughput +22 % |
| #80 lighter outbound queue, lazy write buffer | E3 heap profile: about 2.4 KiB of channel blocks and a 2 KiB write buffer per idle connection | 11.0 to 7.23 KiB per connection |
| #81 lazy write deadline, reverted in #84 | E2 attributed about 7 % of CPU to timers; Round 7b and E4 showed no change (p = 0.94) | none; reverted to keep the simpler code |
| #85 benchmark read-ahead pin, fresh W5 copies | D1-D4 diagnostics (above) | W5 results now reflect the relays rather than host thrashing |
| #86 `no_read_ahead` guidance | 10x query regression with `MDB_NORDAHEAD` | documentation |
| #87 drain the whole inbox per transaction | Round 7d commit logs (above) | W5 2500/3000/s: 0/6 valid to 6/6 |
| #88 benchmark shutdown handling | a relay still committing on shutdown aborted one Round 7e attempt | harness waits up to 180 s, then SIGKILL |

## Open items

- W5 at 3500/s: measure synced bytes and dirty pages per event for both
  relays at equal batch size, then decide on index layout changes.
- Broadcast CPU per delivery (2.5x strfry) and plain idle memory (7x strfry):
  both follow from nosfry's task-per-connection design, so further work there
  is a trade-off against latency, not a straightforward fix.
- The W1 open-5400 p99 (2.4 s vs 1.5 s) is not significant, but its direction
  is consistent across rounds.

## Validity notes

- Round 7 invalid cells: strfry W6 (kind 41, above); two strfry W2
  c64-deflate-warm reps (one query error each, also seen in 7b).
- Round 7b: nosfry-030 open-5400 0/6 (sender blocked 3.9-31 s); three strfry
  c64-deflate-warm reps (one error each); W5 void.
- An earlier Round 7b attempt stopped when the host disk filled. It is
  archived and not used.
- Round 7e: the first W5 attempt aborted on a 10 s shutdown timeout, and the
  next W1 unit measured the relay left over from it. Both are archived under
  `/bench/results/r7e/aborted/` and were rerun after #88.
- nosfry-7e (`2898125`) and nosfry-e5 (`bb2d45b`) differ only in doc comments.

## Reproducing

The orchestrator is `bench/r7/run.py`, and `bench/r7/params*.toml` holds each
round's parameters (`params.toml` for Round 7, then `params-7b.toml` through
`params-7e.toml`). `bench/README.md` documents the corpus, the workloads and
the per-round deviations. On the bench host:

```bash
python3 bench/r7/run.py --params bench/r7/params-7e.toml --dry-run w5
python3 bench/r7/run.py --params bench/r7/params-7e.toml w5
python3 bench/r7/analyze.py /bench/results/r7e --params bench/r7/params-7e.toml \
    --json summary.json > report.md
```

Raw results, per-unit relay logs and `run-meta.json` (kernel, sysctls,
read-ahead record and build info) are under `/bench/results/{r7,r7b,r7c,r7d,e5,r7e}`
on the bench host.
