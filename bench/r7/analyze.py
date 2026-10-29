#!/usr/bin/env python3
"""Round 7 analysis: raw results -> Markdown tables and the
pre-registered primary comparisons.

Usage: python3 bench/r7/analyze.py <results-dir>
           [--params bench/r7/params.toml] [--json summary.json]

Reads <results-dir>/manifest.jsonl (the last line per unit wins, so a
rerun replaces the earlier attempt) and every unit's rep<k>.json.
Standard library only; the statistics live in stats.py next to this
file. Every rep is reported; a rep with a flag is shown but left out of
the medians and tests, and the flags are listed per point.
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections import defaultdict
from pathlib import Path
from statistics import median

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats  # noqa: E402

NOSFRY, STRFRY = "nosfry-030", "strfry"
LINEUP = (NOSFRY, "nosfry-030+sliding", STRFRY, "nostr-rs-0100")
SEND_LAG_LIMIT_MS = 5.0
SOAK_WARMUP_S = 3600
REPLACED = "Rejected event. replaced:"
REJECTED = "Rejected event."


def last_json(path: Path):
    recs = all_json(path)
    return recs[-1] if recs else None


def all_json(path: Path) -> list:
    return [json.loads(line) for line in path.read_text().splitlines()
            if line.strip().startswith("{")]


def dig(d, path: str):
    for k in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def load_units(root: Path) -> dict:
    """(workload, scenario, label) -> {rep: manifest line}."""
    units: dict = defaultdict(dict)
    for line in (root / "manifest.jsonl").read_text().splitlines():
        if line.strip():
            m = json.loads(line)
            units[(m["workload"], m["scenario"], m["label"])][m["rep"]] = m
    return units


def unit_dir(root: Path, key) -> Path:
    return root.joinpath(*key)


def replaced_check(udir: Path) -> bool | None:
    """True when strfry's relay.log shows only `replaced:` rejections,
    i.e. every `rejected_other` reply was a superseded replaceable
    version (nosfry reports the same case as `duplicate:`). None when
    the log is not available."""
    log = udir / "relay.log"
    if not log.exists():
        return None
    other = 0
    with open(log, errors="replace") as f:
        for line in f:
            if REJECTED in line and REPLACED not in line:
                other += 1
    return other == 0


def ingest_rep(d: dict, superseded_ok: bool | None) -> tuple[dict, list]:
    closed = d["scenario"] == "ingest-closed"
    lat = d["ok_latency_closed" if closed else "ok_latency"]
    oks = (d["accepted"] + d["accepted_duplicate"] + d["rejected_rate_limited"]
           + d["rejected_other"])
    cpu = dig(d, "sampler.relay_cpu_secs")
    m = {"ok_p50_ms": lat["p50_ms"], "ok_p99_ms": lat["p99_ms"], "ok_p999_ms": lat["p999_ms"],
         "relay_cpu_us_per_ok": cpu / oks * 1e6 if cpu and oks else None}
    flags = []
    if closed:
        m["accepted_per_sec"] = d["accepted_per_sec"]
    else:
        m["send_lag_p99_ms"] = d["send_lag"]["p99_ms"]
        if d["send_lag"]["p99_ms"] >= SEND_LAG_LIMIT_MS:
            flags.append(f"send_lag_p99={d['send_lag']['p99_ms']:.1f}ms")
    if d["timeouts"]:
        flags.append(f"timeouts={d['timeouts']}")
    if d["rejected_other"]:
        if superseded_ok is None:
            flags.append(f"rejected={d['rejected_other']}(log unavailable)")
        elif not superseded_ok:
            flags.append(f"rejected={d['rejected_other']}")
    if d["rejected_rate_limited"]:
        flags.append(f"rate_limited={d['rejected_rate_limited']}")
    if d.get("errors") or d.get("conn_errors"):
        flags.append("conn_errors")
    if dig(d, "harness.harness_saturated") is not False:
        flags.append("harness_saturated")
    return m, flags


def query_rep(d: dict) -> tuple[dict, list]:
    m = {"p50_ms": dig(d, "queries.overall.latency.p50_ms"),
         "p99_ms": dig(d, "queries.overall.latency.p99_ms"),
         "events_per_sec": d["events_per_sec"]}
    flags = []
    if not d["events_per_sec"]:
        flags.append("empty_result_set")
    if d.get("errors"):
        flags.append(f"errors={len(d['errors'])}")
    if dig(d, "harness.harness_saturated") is not False:
        flags.append("harness_saturated")
    return m, flags


def fanout_rep(d: dict) -> tuple[dict, list]:
    m = {"latency_p50_ms": d["latency_p50_ms"], "latency_p99_ms": d["latency_p99_ms"],
         "latency_p999_ms": dig(d, "latency_ms.p999"),
         "relay_cpu_us_per_delivery": (d["relay_cpu_secs"] / d["delivered"] * 1e6
                                       if d["delivered"] else None),
         "rss_anon_mib_after": d["relay_rss_anon_kib_after"] / 1024}
    flags = [f"{k}={d[k]}" for k in ("missing", "duplicates", "subs_failed",
                                      "subscriber_errors", "unknown") if d.get(k)]
    if dig(d, "harness.harness_saturated") is not False:
        flags.append("harness_saturated")
    return m, flags


def conns_rep(d: dict) -> tuple[dict, list]:
    m = {"kib_per_conn": d["kib_per_conn"], "setup_secs": d["setup_secs"],
         "relay_cpu_secs_setup": d.get("relay_cpu_secs_setup")}
    flags = [f"{k}={d[k]}" for k in ("failed", "dropped_during_hold") if d.get(k)]
    if d["accepted"] != d["requested"]:
        flags.append(f"accepted={d['accepted']}/{d['requested']}")
    return m, flags


def neg_rep(d: dict) -> tuple[dict, list]:
    m = {"wall_ms": d["wall_ms"], "rounds": d["rounds"],
         "bytes_received": d["payload_bytes_received"] + d["overhead_bytes_received"],
         "bytes_sent": d["payload_bytes_sent"] + d["overhead_bytes_sent"]}
    flags = []
    if not d["correct"]:
        flags.append("set_mismatch(" + ",".join(
            f"{k}={d[k]}" for k in ("unexpected_have", "missing_have",
                                    "unexpected_need", "missing_need") if d[k]) + ")")
    return m, flags


EXTRACT = {"w2": query_rep, "w3": fanout_rep, "w4": conns_rep, "w6": neg_rep}


def w5_rep(scenario: str, path: Path, result: dict,
           superseded_ok: bool | None):
    recs = all_json(path)
    if scenario.startswith("ingest"):
        m, flags = ingest_rep(recs[-1], superseded_ok)
        dc = result.get("db_copy")
        if dc is None:
            flags.append("db_copy_missing")
        elif dc.get("bytes") != dc.get("source_bytes") or dc.get("rc") != 0:
            flags.append(f"db_copy_mismatch(bytes={dc.get('bytes')},"
                         f"source={dc.get('source_bytes')},rc={dc.get('rc')})")
        return m, flags
    m, flags = {}, []
    for name, d in zip(("cold", "warm"), recs, strict=False):
        qm, qf = query_rep(d)
        m.update({f"{name}_{k}": v for k, v in qm.items()})
        flags += [f"{name}:{f}" for f in qf]
    m["restart_ms"] = result.get("restart_ms")
    return m, flags


def collect(root: Path, units: dict) -> dict:
    """key -> list of {rep, metrics, flags}, for w1-w6."""
    out = {}
    for key, reps in sorted(units.items()):
        wl, scenario, _label = key
        if wl in ("w7", "w8") or scenario == "d1":
            continue
        udir = unit_dir(root, key)
        superseded_ok = replaced_check(udir) if wl in ("w1", "w5") else None
        rows = []
        for rep in sorted(reps):
            path = udir / f"rep{rep}.json"
            result = json.loads((udir / f"rep{rep}.result.json").read_text())
            if not path.exists() or not path.read_text().strip():
                rows.append({"rep": rep, "metrics": {}, "flags": ["no_output"]})
                continue
            if wl == "w5":
                m, flags = w5_rep(scenario, path, result, superseded_ok)
            elif wl == "w1":
                m, flags = ingest_rep(last_json(path), superseded_ok)
            else:
                m, flags = EXTRACT[wl](last_json(path))
            if result.get("cmds_rc") and any(result["cmds_rc"]):
                flags.append(f"exit={result['cmds_rc']}")
            rows.append({"rep": rep, "metrics": m, "flags": flags})
        out[key] = rows
    return out


def values(rows: list, metric: str) -> list[float]:
    return [r["metrics"][metric] for r in rows
            if not r["flags"] and r["metrics"].get(metric) is not None]


def fmt(v: float) -> str:
    if v == 0:
        return "0"
    a = abs(v)
    if a >= 100:
        return f"{v:.0f}"
    if a >= 10:
        return f"{v:.1f}"
    return f"{v:.2f}" if a >= 1 else f"{v:.3g}"


def cell(vs: list[float], n_all: int) -> str:
    if not vs:
        return f"— (0/{n_all})"
    s = stats.summarize(vs)
    tail = "" if len(vs) == n_all else f" ({len(vs)}/{n_all})"
    if len(vs) == 1:
        return fmt(s["median"]) + tail
    return f"{fmt(s['median'])} [{fmt(s['ci_lo'])}, {fmt(s['ci_hi'])}]{tail}"


WORKLOAD_METRICS = {
    "w1": ["accepted_per_sec", "ok_p50_ms", "ok_p99_ms", "relay_cpu_us_per_ok"],
    "w2": ["p50_ms", "p99_ms", "events_per_sec"],
    "w3": ["latency_p50_ms", "latency_p99_ms", "relay_cpu_us_per_delivery",
           "rss_anon_mib_after"],
    "w4": ["kib_per_conn", "setup_secs"],
    "w5": ["cold_p50_ms", "warm_p50_ms", "warm_events_per_sec", "restart_ms",
           "ok_p50_ms", "ok_p99_ms", "relay_cpu_us_per_ok"],
    "w6": ["wall_ms", "rounds", "bytes_received"],
}


def scenario_tables(data: dict, summary: dict) -> list[str]:
    out = []
    by_wl: dict = defaultdict(lambda: defaultdict(dict))
    for (wl, scenario, label), rows in data.items():
        by_wl[wl][scenario][label] = rows
    for wl in sorted(by_wl):
        out.append(f"\n## {wl.upper()}\n")
        for metric in WORKLOAD_METRICS[wl]:
            scen = {s: r for s, r in by_wl[wl].items()
                    if any(metric in x["metrics"] for rows in r.values() for x in rows)}
            if not scen:
                continue
            out.append(f"\n### {metric}\n")
            out.append("| scenario | " + " | ".join(LINEUP) + " | nosfry/strfry | p (MWU) |")
            out.append("|---" * (len(LINEUP) + 3) + "|")
            for s in sorted(scen, key=sort_key):
                cols = scen[s]
                cells = [cell(values(cols[relay], metric), len(cols[relay]))
                         if relay in cols else "n/a" for relay in LINEUP]
                a = values(cols.get(NOSFRY, []), metric)
                b = values(cols.get(STRFRY, []), metric)
                ratio = p = "—"
                if len(a) >= 2 and len(b) >= 2:
                    c = stats.compare(a, b)
                    ratio, p = f"{c['ratio']:.2f}", f"{c['p']:.4f}"
                    summary.setdefault("exploratory", []).append(
                        {"workload": wl, "scenario": s, "metric": metric, **c})
                out.append(f"| {s} | " + " | ".join(cells) + f" | {ratio} | {p} |")
        flagged = [(s, relay, r["rep"], r["flags"]) for s, cols in by_wl[wl].items()
                   for relay, rows in cols.items() for r in rows if r["flags"]]
        if flagged:
            out.append(f"\n<details><summary>{len(flagged)} flagged reps</summary>\n")
            for s, relay, rep, flags in sorted(flagged,
                                               key=lambda t: (sort_key(t[0]), t[1], t[2])):
                out.append(f"- {s} / {relay} / rep{rep}: {', '.join(flags)}")
            out.append("\n</details>")
    return out


def sort_key(scenario: str):
    parts = scenario.replace("pct", "").split("-")
    return [(0, float(p)) if p.replace(".", "").isdigit() else (1, p) for p in parts]


# params.toml [primary] metric (a path in the raw result, or a derived
# name) -> the extracted metric it corresponds to.
PRIMARY_METRIC = {
    "accepted_per_sec": "accepted_per_sec",
    "ok_latency.p99_ms": "ok_p99_ms",
    "queries.overall.latency.p50_ms": "p50_ms",
    "events_per_sec": "events_per_sec",
    "latency_p50_ms": "latency_p50_ms",
    "relay_cpu_us_per_delivery": "relay_cpu_us_per_delivery",
    "kib_per_conn": "kib_per_conn",
}


def primary(data: dict, prm: dict, summary: dict) -> list[str]:
    if not prm.get("primary"):
        return []
    rows, pvals = [], {}
    for pid, spec in sorted(prm["primary"].items()):
        metric = PRIMARY_METRIC[spec["metric"]]
        ra = data.get((spec["workload"], spec["scenario"], NOSFRY), [])
        rb = data.get((spec["workload"], spec["scenario"], STRFRY), [])
        a, b = values(ra, metric), values(rb, metric)
        c = stats.compare(a, b) if len(a) >= 2 and len(b) >= 2 else None
        pvals[pid] = c["p"] if c else 1.0
        rows.append((pid, spec, (a, len(ra)), (b, len(rb)), c))
    adj = stats.holm(pvals)
    out = [f"\n## Primary comparisons ({NOSFRY} vs {STRFRY})\n",
           f"Holm over all {len(pvals)}; a point without data enters as p = 1. A difference is "
           "claimed only when the adjusted p < 0.05 and the two median intervals are disjoint.\n",
           "| id | point | nosfry | strfry | ratio | p | Holm p | verdict |",
           "|---|---|---|---|---|---|---|---|"]
    for pid, spec, (a, na), (b, nb), c in rows:
        point = (f"{spec['workload']} {spec['scenario']} {spec['metric']} "
                 f"({spec['better']} is better)")
        if c is None:
            out.append(f"| {pid} | {point} | {cell(a, na)} | {cell(b, nb)} | — | — | — | pending |")
            summary.setdefault("primary", {})[pid] = {"status": "pending"}
            continue
        p_adj, reject = adj[pid]
        verdict = "no claim"
        if reject and c["ci_disjoint"]:
            nos_better = (c["ratio"] > 1) == (spec["better"] == "higher")
            verdict = "nosfry better" if nos_better else "strfry better"
        out.append(f"| {pid} | {point} | {cell(a, na)} | {cell(b, nb)} | "
                   f"{c['ratio']:.2f} | {c['p']:.4f} | {p_adj:.4f} | {verdict} |")
        summary.setdefault("primary", {})[pid] = {**c, "holm_p": p_adj, "verdict": verdict,
                                                  "nosfry": a, "strfry": b}
    return out


def soak(root: Path, units: dict, summary: dict) -> list[str]:
    if not any(key[0] == "w7" for key in units):
        return []
    out = ["\n## W7 soak (24 h per relay)\n",
           f"RSS slope and mean over samples after {SOAK_WARMUP_S} s.\n",
           "| relay | hours | OKs | deliveries | RssAnon mean MiB | slope MiB/h "
           "| failures | relay exit |",
           "|---|---|---|---|---|---|---|---|"]
    for key, reps in sorted(units.items()):
        if key[0] != "w7":
            continue
        udir = unit_dir(root, key)
        for rep in sorted(reps):
            recs = all_json(udir / f"rep{rep}.json")
            result = json.loads((udir / f"rep{rep}.result.json").read_text())
            samples = [r for r in recs if r.get("type") == "sample"]
            end = next((r for r in recs if r.get("type") == "end"), samples[-1])
            post = [s for s in samples if s["t"] >= SOAK_WARMUP_S and s.get("rss_anon_kib")]
            ts, rss = [s["t"] for s in post], [s["rss_anon_kib"] / 1024 for s in post]
            fail = {k: end.get(k, 0) for k in ("errors", "churn_failed", "count_failed",
                                               "neg_failed", "vanish_failed", "sub_reconnects")}
            fail["rejected_oks"] = sum(v for k, v in end.get("ok", {}).items()
                                       if not k.startswith("true"))
            bad = {k: v for k, v in fail.items() if v}
            row = {"hours": end["t"] / 3600, "oks": sum(end.get("ok", {}).values()),
                   "deliveries": end.get("deliveries"), "rss_mean_mib": sum(rss) / len(rss),
                   "rss_slope_mib_h": slope(ts, rss) * 3600, "failures": bad,
                   "relay_rc": result.get("relay_rc")}
            summary.setdefault("w7", {})[key[2]] = row
            out.append(f"| {key[2]} | {row['hours']:.1f} | {row['oks']} | {row['deliveries']} | "
                       f"{row['rss_mean_mib']:.1f} | {row['rss_slope_mib_h']:+.3f} | "
                       f"{bad or 'none'} | {row['relay_rc']} |")
    return out


def slope(xs: list[float], ys: list[float]) -> float:
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    return 0.0 if den == 0 else sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True)) / den


def durability(root: Path, units: dict, summary: dict) -> list[str]:
    if not any(key[0] == "w8" for key in units):
        return []
    out = ["\n## W8 kill -9 durability\n",
           "`missing` is cumulative: acknowledged ids absent after the last restart.\n",
           "| relay | cycles | acked | missing | restart ms median [min, max] |",
           "|---|---|---|---|---|"]
    for key, reps in sorted(units.items()):
        if key[0] != "w8":
            continue
        udir = unit_dir(root, key)
        final = last_json(udir / f"rep{max(reps)}.json")
        restarts = [m["restart_ms"] for m in reps.values() if m.get("restart_ms") is not None]
        row = {"cycles": len(reps), "acked": final["acked"], "missing": final["missing"],
               "missing_sample": final.get("missing_sample", []),
               "restart_ms_median": median(restarts)}
        summary.setdefault("w8", {})[key[2]] = row
        out.append(f"| {key[2]} | {len(reps)} | {final['acked']} | {final['missing']} | "
                   f"{median(restarts):.0f} [{min(restarts):.0f}, {max(restarts):.0f}] |")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results", type=Path)
    ap.add_argument("--params", type=Path, default=Path(__file__).with_name("params.toml"))
    ap.add_argument("--json", type=Path, help="write the machine-readable summary here")
    args = ap.parse_args()
    prm = tomllib.loads(args.params.read_text())
    # The optional [analysis] table overrides the analyzed relay and
    # the table column order; defaults keep today's constants.
    global NOSFRY, LINEUP
    analysis = prm.get("analysis", {})
    NOSFRY = analysis.get("nosfry", NOSFRY)
    LINEUP = tuple(analysis.get("lineup", LINEUP))
    units = load_units(args.results)
    data = collect(args.results, units)
    summary: dict = {}
    lines = [f"# Benchmark results: {args.results.name}\n",
             "Cells: median [distribution-free 95%+ interval] over unflagged reps; "
             "(k/n) when reps were flagged."]
    lines += primary(data, prm, summary)
    lines += scenario_tables(data, summary)
    lines += soak(args.results, units, summary)
    lines += durability(args.results, units, summary)
    print("\n".join(lines))
    if args.json:
        args.json.write_text(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
