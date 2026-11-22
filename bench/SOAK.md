# The 72-hour soak

The production gate of a release candidate: 72 hours of the mixed soak
workload against one relay, judged by criteria fixed before the run. A
release that changes the writer, the readers, the connection path or the
store needs a passing run on its candidate commit. The only long runs so far
are 24 hours on 0.3.0 (round 7, W7) and a 72-hour run on `dfaf455` stopped at
47.3 hours; the writer has changed since (#79, #87).

## Before the run

- [ ] A dedicated Linux host or VM, not shared with other load; the
      container from `bench/linux/Dockerfile` with the layout in
      [README.md](README.md#setup).
- [ ] The candidate binary built from the tagged or candidate commit with
      `cargo build --release --locked -p nosfry`, copied to `/bench/bin/<name>`.
- [ ] The harness built from the same commit (`bench/nosfry-bench`).
- [ ] The database directory (`/bench/work`) on the file system you deploy to
      (the round 7 host used btrfs with `nodatacow,noatime`), with at least
      50 GiB free.
- [ ] Clock synchronized (the harness publishes events with the current time).
- [ ] `ulimit -n` at least 65,536 inside the container.

## Run

```bash
/bench/run-soak-72h.sh <name> rc-<version>
```

It writes, under `/bench/results`:

- `soak-<label>.meta`: label, start and end time, binary and harness SHA-256,
  `nosfry --version`, kernel, CPUs, memory, file system, workload;
- `soak-<label>.jsonl`: one sample per minute (relay RSS and RssAnon,
  `data.mdb` size, connections, outbound, sync and subscription gauges,
  rate-limit counters, workload counters), then the `end` and `relay_exit`
  lines;
- `soak-<label>.verdict`: the analyzer's table and the relay's exit status;

and the relay log at `/bench/work/soak-<label>/relay.log`.

The workload is `run-soak.sh`'s default: 8 publishers at 200 events/s in
total, 200 long-lived subscribers, 10 churn connections/s with historical
`REQ`s and `COUNT`s, a non-reading consumer every 60 s (reaped as a slow
consumer), a negentropy session every 10 s, and a vanish round every 60 s.

## Pass criteria

All of the analyzer's checks (`bench/soak_analyze.py`, 6-hour warm-up) must
pass, and the relay must exit 0. The script exits non-zero otherwise.

| Check         | Pass when                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------- |
| memory        | the least-squares slope of RssAnon after warm-up, projected over 72 h, stays within max(64 MiB, 10 % of its mean)         |
| database      | `data.mdb` in the last third never exceeds the middle third's maximum by more than 5 %                                    |
| connections   | the gauge never exceeds publishers + subscribers + 50 and ends within publishers + subscribers + 20                       |
| errors        | zero harness errors, failed churn queries, `COUNT`s, syncs and vanish rounds, zero subscriber reconnects, every `OK` true |
| outbound      | `nosfry_outbound_pending_bytes` reads 0 once every harness connection is closed                                           |
| sync          | `nosfry_sync_memory_bytes` reads 0 once every harness connection is closed                                                |
| subscriptions | `nosfry_subscription_bytes` reads 0 once every harness connection is closed                                               |
| coverage      | churn queries, `COUNT`s, syncs and vanish rounds each completed at least once                                             |
| exit          | the relay exits 0 on `SIGTERM`; the analyzer also passes death by `SIGTERM`, so the script checks for 0 itself            |

And, checked by hand after the run:

- [ ] `relay.log` has no `ERROR` line and no panic; record every `WARN`
      (slow commit, slow enqueue, slow sweep) with its count.
- [ ] The relay restarts on the soaked database and answers NIP-11, and,
      once its first expiry sweep has run (a minute after the start; the
      soak's notes expire after 600 s), `nosfry export | wc -l` and
      `nosfry scan --count '{}'` agree.
- [ ] Peak RSS, final `data.mdb` size and events stored are recorded in the
      release notes.

A failed check fails the gate: fix the cause and run the full 72 hours again
on the new candidate. Do not shorten a run, change a criterion, or exclude a
window after the run has started.
