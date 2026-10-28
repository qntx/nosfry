#!/usr/bin/env python3
"""Verdict for a `nosfry-bench soak` JSONL run.

Usage: python3 bench/soak_analyze.py <run.jsonl> [--warmup-secs N]
       [--publishers P] [--subscribers S]

Criteria (fixed before any run was analyzed):
- memory: the least-squares slope of anonymous RSS (RssAnon; VmRSS also
  counts touched LMDB map pages, which are reclaimable page cache bounded
  by the database size) after warm-up, projected over 72 h, stays within
  max(64 MiB, 10% of the mean post-warm-up value);
- database: `data.mdb` in the last third of the run never exceeds the
  middle third's maximum by more than 5%;
- connections: the relay gauge never exceeds publishers + subscribers + 50
  and ends within publishers + subscribers + 20 (slow consumers and churn
  are reaped);
- errors: zero harness errors, zero failed churn queries, COUNTs, sync
  sessions and vanish rounds, zero subscriber reconnects, every OK
  accepted, relay exit status 0.
- outbound: once every harness connection is closed, the relay's
  `nosfry_outbound_pending_bytes` gauge reads 0 (no queued bytes stay
  charged to closed connections; added 2026-10-21 before the definitive run).
- sync: once every harness connection is closed, `nosfry_sync_memory_bytes`
  reads 0 (no negentropy reservation outlives its connection; added
  2026-10-21 before the definitive run).
- coverage: churn queries, COUNTs, sync sessions and vanish rounds all
  completed at least once (the run exercised every workload).
"""

import argparse
import json
import sys

MIB = 1024


def slope(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    return 0.0 if den == 0 else sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--warmup-secs", type=float, default=600)
    ap.add_argument("--publishers", type=int, default=8)
    ap.add_argument("--subscribers", type=int, default=200)
    ap.add_argument("--relay-rc", type=int, help="relay exit code when known")
    args = ap.parse_args()

    samples, end, exit_status = [], None, None
    with open(args.path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            rec = json.loads(line)
            kind = rec.get("type")
            if kind == "sample":
                samples.append(rec)
            elif kind == "end":
                end = rec
            elif kind == "relay_exit":
                exit_status = rec["exit_status"]

    post = [s for s in samples if s["t"] >= args.warmup_secs]
    if len(post) < 6:
        sys.exit(f"only {len(post)} post-warm-up samples; need at least 6")
    checks = []

    ts = [s["t"] for s in post]
    # A missing series (e.g. no procfs RssAnon off Linux) is a failed
    # check, not a traceback.
    rss = [v for s in post if (v := s["rss_anon_kib"]) is not None]
    total_rss = [v for s in post if (v := s["rss_kib"]) is not None]
    if rss:
        mean_rss = sum(rss) / len(rss)
        rss_slope_h = slope(ts, rss) * 3600
        projected = rss_slope_h * 72
        budget = max(64 * MIB, 0.10 * mean_rss)
        checks.append((
            "memory",
            abs(projected) <= budget,
            f"anon mean {mean_rss / MIB:.1f} MiB, min {min(rss) / MIB:.1f}, max {max(rss) / MIB:.1f}, "
            f"total RSS max {max(total_rss) / MIB:.1f} MiB, "
            f"slope {rss_slope_h / MIB:+.2f} MiB/h, 72 h projection {projected / MIB:+.1f} MiB "
            f"(budget {budget / MIB:.1f} MiB)",
        ))
    else:
        checks.append(("memory", None, "no rss_anon_kib samples"))

    third = len(post) // 3
    middle = post[third:2 * third]
    last = post[2 * third:]
    db_mid_l = [v for s in middle if (v := s["db_bytes"]) is not None]
    db_last_l = [v for s in last if (v := s["db_bytes"]) is not None]
    if db_mid_l and db_last_l:
        db_mid, db_last = max(db_mid_l), max(db_last_l)
        checks.append((
            "database",
            db_last <= db_mid * 1.05,
            f"middle-third max {db_mid / 2**20:.1f} MiB, last-third max {db_last / 2**20:.1f} MiB, "
            f"final {post[-1]['db_bytes'] / 2**20:.1f} MiB",
        ))
    else:
        checks.append(("database", None, "no db_bytes samples"))

    base = args.publishers + args.subscribers
    conns = [v for s in samples if (v := s["conns"]) is not None]
    final = conns[-1] if conns else None
    checks.append((
        "connections",
        max(conns) <= base + 50 and final <= base + 20 if conns else None,
        f"max {max(conns) if conns else 'n/a'}, final {final}, baseline {base}",
    ))

    counts = end or samples[-1]
    ok = counts.get("ok", {})
    rejected = {k: v for k, v in ok.items() if not k.startswith("true")}
    failures = {
        "errors": counts.get("errors", 0),
        "churn_failed": counts.get("churn_failed", 0),
        "count_failed": counts.get("count_failed", 0),
        "neg_failed": counts.get("neg_failed", 0),
        "vanish_failed": counts.get("vanish_failed", 0),
        "sub_reconnects": counts.get("sub_reconnects", 0),
    }
    def drain_check(name, end_key, sample_key):
        """After-close drain check; n/a when the metric is a
        nosfry-only series absent from every sample."""
        drained = end.get(end_key) if end else None
        absent = all(s.get(sample_key) is None for s in post)
        return (
            name,
            None if absent else drained == 0,
            f"{name} after all connections closed: "
            f"{drained if end else 'run not finished'} bytes, "
            f"last sample {post[-1].get(sample_key)} bytes",
        )

    checks.append(drain_check("outbound", "outbound_pending_after_close", "outbound_pending"))
    checks.append(drain_check("sync", "sync_memory_after_close", "sync_memory"))
    checks.append(drain_check(
        "subscriptions", "subscription_bytes_after_close", "subscription_bytes"))
    ran = {
        "churn": counts.get("churn_done", 0) + counts.get("churn_failed", 0),
        "count": counts.get("count_done", 0) + counts.get("count_failed", 0),
        "neg": counts.get("neg_done", 0) + counts.get("neg_failed", 0)
            + counts.get("neg_unreaped", 0),
        "vanish": counts.get("vanish_done", 0) + counts.get("vanish_failed", 0),
    }
    done = {k: counts.get(f"{k}_done", 0) for k in ran}
    cov_ok = None if not any(ran.values()) else all(
        v == 0 or done[k] > 0 for k, v in ran.items())
    checks.append(("coverage", cov_ok, f"{done} (n/a when no runs: {ran})"))
    checks.append((
        "errors",
        not any(failures.values()) and not rejected,
        f"{failures}, rejected OKs {rejected or 'none'}",
    ))
    rc = args.relay_rc if args.relay_rc is not None else exit_status
    checks.append((
        "exit",
        rc in (0, -15, 143) if rc is not None else None,
        f"relay exit {rc if rc is not None else 'n/a'} "
        f"(0 or SIGTERM -15/143 passes)",
    ))

    print(f"run: {samples[-1]['t'] / 3600:.2f} h, {len(samples)} samples, {len(post)} after "
          f"{args.warmup_secs:.0f} s warm-up")
    print(f"load: {sum(ok.values())} OKs, {counts.get('deliveries', 0)} deliveries, "
          f"{counts.get('churn_done', 0)} churn queries, "
          f"{counts.get('count_done', 0)} COUNTs, "
          f"{counts.get('neg_done', 0)} syncs, "
          f"{counts.get('vanish_done', 0)} vanish rounds, "
          f"{counts.get('slow_spawned', 0)} slow consumers")
    for name, passed, detail in checks:
        mark = "n/a" if passed is None else ("PASS" if passed else "FAIL")
        print(f"{mark} {name}: {detail}")
    sys.exit(0 if all(p is not False for _, p, _ in checks) else 1)


if __name__ == "__main__":
    main()
