#!/usr/bin/env python3
"""Round 7 benchmark orchestrator.

Drives workloads w1-w8 against the relay lineup defined in
params.toml. Every measured unit starts the relay through its
bench/linux/relays wrapper, runs the nosfry-bench harness (or a
composite step list for w5/w8), captures results under
<results>/<workload>/<scenario>/<relay-label>/rep<k>.{json,log} and
appends one line to <results>/manifest.jsonl.

Subcommands: prep, w1..w8, pilot <wN>, status. --dry-run prints the
scheduled units and their commands without starting anything.
"""

import argparse
import contextlib
import hashlib
import json
import math
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import tomllib
from pathlib import Path

# Binary names that must not already be running before a unit.
FOREIGN_PROCS = ("nosfry", "strfry", "nostr-rs", "nosfry-bench", "relaybench")
READY_TIMEOUT_S = 60.0
TERM_GRACE_S = 10.0
RTT_TIMEOUT_S = 15.0
RESTART_POLL_S = 0.05
RESTART_DEADLINE_S = 120.0
LMDB_MAP = 137438953472


def sh(cmd, **kw):
    try:
        return subprocess.run(cmd, text=True, capture_output=True, **kw)
    except FileNotFoundError as e:
        return subprocess.CompletedProcess(cmd, 127, "", str(e))
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(cmd, 124, e.stdout or "",
                                           e.stderr or "")


def sh_out(cmd, **kw):
    """Stripped stdout of `cmd`, or None when it cannot run."""
    r = sh(cmd, **kw)
    return r.stdout.strip() if r.returncode == 0 else None


def loadavg():
    try:
        a, b, c = os.getloadavg()
        return [round(a, 2), round(b, 2), round(c, 2)]
    except OSError:
        return None


def read_memtotal():
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return line.split()[1] + " kB"
    except OSError:
        pass
    return None


def last_json(stdout):
    """Parse the last non-empty stdout line as JSON, else None."""
    for line in reversed(stdout.splitlines()):
        if line.strip():
            try:
                return json.loads(line)
            except ValueError:
                return None
    return None


class Params:
    """params.toml, resolved once."""

    def __init__(self, path):
        self.path = Path(path)
        self.raw = self.path.read_text()
        self.cfg = tomllib.loads(self.raw)
        self.sha256 = hashlib.sha256(self.raw.encode()).hexdigest()

    def p(self, *keys):
        node = self.cfg
        for k in keys:
            node = node[k]
        return node

    def path_of(self, key):
        return Path(self.p("paths", key))

    def reps(self, workload, pilot):
        if pilot:
            return int(self.p("pilot", "reps"))
        w = self.p(workload)
        return int(w["reps"]) if "reps" in w else int(self.p("reps", "default"))


def rotated(relays, rep):
    """Relay order rotates per rep, like run-nosfry-bench.sh."""
    shift = (rep - 1) % len(relays)
    return relays[shift:] + relays[:shift]


def bin_of(label):
    """`nosfry-030+sliding` -> `nosfry-030`: the storage identity."""
    return label.split("+")[0]


def relay_entry(label, prm):
    """Resolve a lineup entry to its wrapper, binary and variant."""
    bin_name = bin_of(label)
    paths = prm.p("paths")
    wrappers = Path(paths["wrappers"])
    if bin_name == "strfry":
        impl, ext = "strfry", ".conf"
        binary, wrapper = Path(paths["strfry_bin"]), wrappers / "strfry.sh"
    elif bin_name.startswith("nostr-rs"):
        impl, ext = "nostr-rs", ".toml"
        binary = Path(paths["bin_dir"]) / bin_name
        wrapper = wrappers / "nostr-rs-relay.sh"
    else:
        impl, ext = "nosfry", ".toml"
        binary = Path(paths["bin_dir"]) / bin_name
        wrapper = wrappers / "nosfry.sh"
    _, _, variant = label.partition("+")
    variant_path = str(Path(paths["variants"]) / f"{variant}{ext}") if variant else ""
    return {"label": label, "impl": impl, "binary": str(binary),
            "wrapper": str(wrapper), "variant": variant_path}


def unit(workload, scenario, label, rep, kind, cmds, db="main",
         cold_cache=False, env=None, note=None):
    return {"workload": workload, "scenario": scenario, "label": label,
            "rep": rep, "kind": kind, "cmds": cmds, "db": db,
            "cold_cache": cold_cache, "env": env or {}, "note": note}


def ws_url(port):
    return f"ws://127.0.0.1:{port}"


def harness_cmd(prm, *args):
    """Harness invocation pinned to the harness cores."""
    return ["taskset", "-c", str(prm.p("cores", "harness")),
            str(prm.path_of("harness")), *args]


def deflate_arg(on):
    return ["--deflate"] if on else []


# ------------------------------------------------------------------
# Unit schedule builders
# ------------------------------------------------------------------

def units_w1(prm, pilot):
    w = prm.p("w1")
    reps = prm.reps("w1", pilot)
    secs = int(prm.p("pilot", "secs")) if pilot else w["closed_secs"]
    warm = int(prm.p("pilot", "warmup")) if pilot else w["warmup_secs"]
    corpus = str(prm.path_of("d2") / "holdout.jsonl")
    port = str(prm.p("net", "port"))
    out = []
    for rep in range(1, reps + 1):
        for label in rotated(w["relays"], rep):
            for c in w["closed_conns"]:
                if pilot and c != max(w["closed_conns"]):
                    continue
                out.append(unit("w1", f"closed-c{c}", label, rep, "harness", [
                    harness_cmd(prm, "ingest-closed", "--url", ws_url(port),
                                "--corpus", corpus, "--conns", str(c),
                                "--window", str(w["window"]),
                                "--duration", str(secs), "--warmup", str(warm),
                                "--label", f"w1-closed-c{c}-r{rep}")],
                    db="fresh"))
            for rate in w["open_rates"].get(label, []):
                scen = f"open-{rate}"
                out.append(unit("w1", scen, label, rep, "harness", [
                    harness_cmd(prm, "ingest-open", "--url", ws_url(port),
                                "--corpus", corpus, "--conns", str(w["open_conns"]),
                                "--rate", str(rate), "--duration", str(w["open_secs"]),
                                "--warmup", str(warm), "--label", f"w1-{scen}-r{rep}")],
                    db="fresh", note={"open_rate": rate}))
    return out


def units_w2(prm, pilot):
    w = prm.p("w2")
    reps = prm.reps("w2", pilot)
    secs = int(prm.p("pilot", "secs")) if pilot else w["secs"]
    warm = int(prm.p("pilot", "warmup")) if pilot else w["warmup"]
    d2 = prm.path_of("d2")
    port = str(prm.p("net", "port"))
    out = []
    for rep in range(1, reps + 1):
        for label in rotated(w["relays"], rep):
            for c in w["conns"]:
                if pilot and c != max(w["conns"]):
                    continue
                for df in w["deflate"]:
                    for cold in (True, False):
                        scen = (f"q-c{c}-{'deflate' if df else 'plain'}-"
                                f"{'cold' if cold else 'warm'}")
                        out.append(unit("w2", scen, label, rep, "harness", [
                            harness_cmd(
                                prm, "query", "--url", ws_url(port),
                                "--params", str(d2 / "params.json"),
                                "--mix", str(prm.path_of("mix")),
                                "--log", "/dev/null", "--conns", str(c),
                                "--duration", str(secs), "--warmup", str(warm),
                                "--seed", str(w["seed"]), *deflate_arg(df),
                                "--label", f"w2-{scen}-r{rep}")],
                            db="main", cold_cache=cold))
        # D1 continuity through relayBench (non-strfry entries only;
        # strfry is already relayBench's built-in baseline).
        for label in rotated(w["relays"], rep):
            if bin_of(label) == "strfry":
                continue
            e = relay_entry(label, prm)
            tpl = f"{e['wrapper']} {e['binary']} {{port}} {{dir}} {e['variant']}".strip()
            for _ in range(1 if pilot else w["d1_reps"]):
                out.append(unit("w2", "d1", label, rep, "relaybench", [[
                    "taskset", "-c", str(prm.p("cores", "harness")),
                    str(prm.path_of("relaybench")),
                    "--strfry-bin", str(prm.path_of("strfry_pinned")),
                    "--relay", f"{label}={tpl}",
                    "--no-sync", "--no-color",
                    "--corpus", str(prm.path_of("d1_corpus"))]],
                    db="main"))
    return out


def units_w3(prm, pilot):
    w = prm.p("w3")
    reps = prm.reps("w3", pilot)
    secs = int(prm.p("pilot", "secs")) if pilot else w["secs"]
    port = str(prm.p("net", "port"))
    out = []
    shapes = ([("broadcast", s) for s in w["broadcast"]]
              + [("selective", s) for s in w["selective"]])
    for rep in range(1, reps + 1):
        for label in rotated(w["relays"], rep):
            for mode, shape in shapes:
                events = int(shape["rate"] * secs)
                for df in w["deflate"]:
                    if df and bin_of(label).startswith("nostr-rs"):
                        continue
                    scen = f"{mode}-{shape['subs']}-{'deflate' if df else 'plain'}"
                    out.append(unit("w3", scen, label, rep, "harness", [
                        harness_cmd(
                            prm, "fanout", "--url", ws_url(port),
                            "--subs", str(shape["subs"]), "--events", str(events),
                            "--rate", str(shape["rate"]), "--mode", mode,
                            "--authors", str(w["authors"]), *deflate_arg(df),
                            "--label", f"w3-{scen}-r{rep}")],
                        db="fresh"))
    return out


def units_w4(prm, pilot):
    w = prm.p("w4")
    reps = prm.reps("w4", pilot)
    hold = int(prm.p("pilot", "hold_secs")) if pilot else w["hold_secs"]
    port = str(prm.p("net", "port"))
    out = []
    for rep in range(1, reps + 1):
        for label in rotated(w["relays"], rep):
            for c in w["conns"]:
                for df in w["deflate"]:
                    if df and bin_of(label).startswith("nostr-rs"):
                        continue
                    scen = f"conns-{c}-{'deflate' if df else 'plain'}"
                    out.append(unit("w4", scen, label, rep, "harness", [
                        harness_cmd(prm, "conns", "--url", ws_url(port),
                                    "--conns", str(c), "--hold-secs", str(hold),
                                    *deflate_arg(df),
                                    "--label", f"w4-{scen}-r{rep}")],
                        db="fresh"))
    return out


def units_w5(prm, pilot):
    w = prm.p("w5")
    reps = prm.reps("w5", pilot)
    qsecs = int(prm.p("pilot", "secs")) if pilot else w["query_secs"]
    qwarm = int(prm.p("pilot", "warmup")) if pilot else w["query_warm"]
    isecs = int(prm.p("pilot", "secs")) if pilot else w["ingest_secs"]
    d2 = prm.path_of("d2")
    corpus = str(d2 / "holdout.jsonl")
    port = str(prm.p("net", "port"))
    rates = w["ingest_rates"]
    skip_base = int(w.get("skip_base", 0))
    query_reps = int(w.get("query_reps", reps))
    out = []
    # Read-only units first, on the shared imported db: cold and warm
    # queries plus a timed restart, per rep.
    for rep in range(1, query_reps + 1):
        for label in rotated(w["relays"], rep):
            def q(cold):
                return harness_cmd(
                    prm, "query", "--url", ws_url(port),
                    "--params", str(d2 / "params.json"),
                    "--mix", str(prm.path_of("mix")), "--log", "/dev/null",
                    "--conns", str(w["conns"]), "--duration", str(qsecs),
                    "--warmup", str(qwarm), "--seed", str(w["seed"]),
                    "--label", f"w5-q-{'cold' if cold else 'warm'}-r{rep}")
            out.append(unit("w5", "query-restart", label, rep, "w5ro",
                            [q(True), q(False)]))
    # Then ingest units on a fresh full copy of the imported db: every
    # unit replays the identical corpus slice (skip_base .. skip_base +
    # ceil(rate * ingest_secs)) into `work/db-w5/<bin>`, so each rep
    # measures ingest into the same on-disk db, not a growing shared
    # one. Rate and relay order still rotate per rep.
    for rep in range(1, reps + 1):
        for rate in rotated(rates, rep):
            lines = math.ceil(rate * isecs)
            for label in rotated(w["relays"], rep):
                out.append(unit("w5", f"ingest-{rate:g}", label, rep, "w5ingest", [
                    harness_cmd(prm, "ingest-open", "--url", ws_url(port),
                                "--corpus", corpus, "--conns", str(w["open_conns"]),
                                "--rate", f"{rate:g}", "--duration", str(isecs),
                                "--warmup", "0", "--skip", str(skip_base),
                                "--label", f"w5-ingest-{rate:g}-r{rep}")],
                    db="copy",
                    note={"ingest_rate": round(rate, 2), "skip": skip_base,
                          "lines": lines}))
    with open(corpus) as f:
        corpus_lines = sum(1 for _ in f)
    need = skip_base + max((math.ceil(r * isecs) for r in rates), default=0)
    if need > corpus_lines:
        sys.exit(f"run.py: w5 ingest slices end at line {need} but "
                 f"{corpus} has only {corpus_lines} lines")
    return out


def units_w6(prm, pilot):
    w = prm.p("w6")
    reps = prm.reps("w6", pilot)
    port = str(prm.p("net", "port"))
    out = []
    for rep in range(1, reps + 1):
        for label in rotated(w["relays"], rep):
            for pct in w["diff"]:
                out.append(unit("w6", f"diff-{pct:g}pct", label, rep, "harness", [
                    harness_cmd(
                        prm, "neg", "--url", ws_url(port),
                        "--corpus", str(prm.path_of("regular")),
                        "--base", str(w["n"]),
                        "--holdout-corpus", str(prm.path_of("holdout_regular")),
                        "--diff-pct", str(pct), "--seed", str(w["seed"]),
                        "--frame-size-limit", str(w["frame_size_limit"]),
                        "--label", f"w6-diff-{pct:g}-r{rep}")],
                    db="import:w6"))
    return out


def units_w7(prm, pilot):
    w = prm.p("w7")
    reps = prm.reps("w7", pilot)
    # The soak's duration lives in [w7] itself — a pilot file sets a
    # few minutes, the real one 24 h; pilot.secs is too short to soak.
    dur = int(w["duration_secs"])
    port = str(prm.p("net", "port"))
    out = []
    for rep in range(1, reps + 1):
        for label in rotated(w["relays"], rep):
            e = relay_entry(label, prm)
            neg_every = w["neg_every_secs"] if e["impl"] in ("nosfry", "strfry") else 0
            vanish_every = w["vanish_every_secs"] if e["impl"] == "nosfry" else 0
            skipped = ([n for n, v in (("negentropy", neg_every), ("vanish", vanish_every))
                        if v == 0])
            metrics = (["--metrics-url", f"http://127.0.0.1:{port}/metrics"]
                       if e["impl"] == "nosfry" else [])
            env = {"METRICS": "1"} if e["impl"] == "nosfry" else {}
            db_path = str(prm.path_of("work") / "db-w7" / bin_of(label))
            out.append(unit("w7", "soak", label, rep, "harness", [
                harness_cmd(
                    prm, "soak", "--url", ws_url(port), *metrics,
                    "--db-dir", db_path,
                    "--duration-secs", str(dur), "--sample-secs", str(w["sample_secs"]),
                    "--publishers", str(w["publishers"]), "--rate", str(w["rate"]),
                    "--subscribers", str(w["subscribers"]),
                    "--churn-rate", str(w["churn_rate"]),
                    "--slow-every-secs", str(w["slow_every_secs"]),
                    "--neg-every-secs", str(neg_every),
                    "--vanish-every-secs", str(vanish_every),
                    "--label", f"w7-soak-r{rep}")],
                db="fresh",
                env=env, note={"skipped": skipped} if skipped else None))
    return out


def units_w8(prm, pilot):
    w = prm.p("w8")
    cycles = prm.reps("w8", pilot) if pilot else int(w["cycles"])
    rng = random.Random(w["seed"])
    # Regular kinds only: a replaceable event may be ACKed and then
    # legitimately superseded by a later corpus event, which is not a
    # lost write.
    corpus = str(prm.path_of("holdout_regular"))
    port = str(prm.p("net", "port"))
    out = []
    for rep in range(1, cycles + 1):
        for label in rotated(w["relays"], rep):
            kill_after = rng.uniform(w["kill_min"], w["kill_max"])
            # One file per relay, appended across cycles: ack-ingest
            # resumes the corpus past the ids it already recorded.
            ids = str(prm.path_of("work") / "ack" / label / "acked.ids")
            out.append(unit("w8", "cycle", label, rep, "w8", [
                harness_cmd(prm, "ack-ingest", "--url", ws_url(port),
                            "--corpus", corpus, "--conns", str(w["conns"]),
                            "--rate", str(w["rate"]), "--out", ids,
                            "--label", f"w8-cycle{rep}"),
                harness_cmd(prm, "ack-check", "--url", ws_url(port), "--ids", ids)],
                db="fresh" if rep == 1 else "reuse",
                note={"kill_after_s": round(kill_after, 2), "ids": ids}))
    return out


BUILDERS = {"w1": units_w1, "w2": units_w2, "w3": units_w3, "w4": units_w4,
            "w5": units_w5, "w6": units_w6, "w7": units_w7, "w8": units_w8}


def schedule(prm, workload, pilot):
    return BUILDERS[workload](prm, pilot)


# ------------------------------------------------------------------
# Process hygiene and relay lifecycle
# ------------------------------------------------------------------

def assert_quiet():
    """No other relay or harness process may be running."""
    out = sh(["ps", "-eo", "pid=,args="])
    bad = []
    for line in out.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid == os.getpid():
            continue
        args = parts[1]
        if "<defunct>" in args:
            continue
        if any(name in args for name in FOREIGN_PROCS) and "run.py" not in args:
            bad.append(line.strip())
    if bad:
        sys.exit("run.py: foreign benchmark processes running, aborting:\n  "
                 + "\n  ".join(bad))


def ra_bdi_file(work):
    """read_ahead_kb of the filesystem bdi holding `work`: btrfs keeps
    it under /sys/fs/btrfs/<uuid>/bdi (raised to 4 MiB at mount),
    other filesystems under the device bdi (parent dir resolves a
    partition to the whole device)."""
    r = sh(["findmnt", "-no", "FSTYPE,UUID,MAJ:MIN", "-T", str(work)])
    parts = r.stdout.split()
    if r.returncode != 0 or not parts:
        return None
    if parts[0] == "btrfs" and len(parts) > 1:
        p = Path(f"/sys/fs/btrfs/{parts[1]}/bdi/read_ahead_kb")
    else:
        p = Path(f"/sys/dev/block/{parts[-1]}/bdi/read_ahead_kb")
        if not p.exists():
            p = Path(f"/sys/dev/block/{parts[-1]}/../bdi/read_ahead_kb").resolve()
    return p


def read_ahead_record(prm):
    """{"path", "original_kb", "applied_kb"} for run-meta; applied_kb
    stays None unless [host] read_ahead_kb is set."""
    p = ra_bdi_file(prm.path_of("work"))
    rec = {"path": str(p) if p else None,
           "original_kb": int(p.read_text().strip())
           if p and p.exists() else None,
           "applied_kb": None}
    target = prm.cfg.get("host", {}).get("read_ahead_kb")
    if target is not None:
        rec["applied_kb"] = int(target)
    return rec


@contextlib.contextmanager
def read_ahead_ctx(prm):
    """Pin the filesystem read_ahead_kb while units run; always yields
    the meta record. With no [host] key this is a no-op that still
    records the resolved path and original value."""
    rec = read_ahead_record(prm)
    target = rec["applied_kb"]
    if target is None:
        yield rec
        return
    path = rec["path"]
    if path is None or not Path(path).exists():
        sys.exit("run.py: [host] read_ahead_kb set but the filesystem "
                 f"bdi file for {prm.path_of('work')} cannot be resolved")
    p = Path(path)
    orig = rec["original_kb"]
    try:
        p.write_text(f"{target}\n")
    except OSError as e:
        sys.exit(f"run.py: cannot write {p}: {e}")

    def _term(signum, frame):
        raise SystemExit(143)

    prev = signal.signal(signal.SIGTERM, _term)
    try:
        yield rec
    finally:
        signal.signal(signal.SIGTERM, prev)
        try:
            p.write_text(f"{orig}\n")
        except OSError as e:
            print(f"run.py: restoring {p} failed: {e}", file=sys.stderr)


def set_sysctls():
    values = {"net.ipv4.ip_local_port_range": "1024 65535",
              "net.ipv4.tcp_tw_reuse": "1"}
    for key, val in values.items():
        r = sh(["sysctl", "-w", f"{key}={val}"])
        if r.returncode != 0:
            print(f"run.py: sysctl {key} failed: {r.stderr.strip()}", file=sys.stderr)
    return values


# Destructive and standalone workloads get a scratch dir under work/
# so they can never wipe or grow the shared imported db in work/db/.
SCRATCH_DBS = {"w1": "db-w1", "w3": "db-w3", "w4": "db-w4",
               "w7": "db-w7", "w8": "db-w8"}


def db_dir(prm, unit):
    """`main` is work/db/<bin>; `import:<name>` and the scratch modes
    live under their own work/db-<x>/<bin>."""
    if unit["db"] == "import:w6":
        base = "db-w6"
    else:
        base = "db-w5" if unit["db"] == "copy" else SCRATCH_DBS.get(
            unit["workload"], "db")
    return prm.path_of("work") / base / bin_of(unit["label"])


def relay_env(prm, unit):
    env = dict(os.environ)
    env["RELAY_CPUS"] = str(prm.p("cores", "relay"))
    env["DB_DIR"] = str(db_dir(prm, unit))
    env.update(unit["env"])
    return env


def start_relay(prm, unit, entry, run_dir):
    run_dir.mkdir(parents=True, exist_ok=True)
    log = open(run_dir / "relay.log", "ab")
    proc = subprocess.Popen(
        [entry["wrapper"], entry["binary"], str(prm.p("net", "port")),
         str(run_dir), entry["variant"]],
        stdout=log, stderr=subprocess.STDOUT, env=relay_env(prm, unit))
    proc._logfile = log
    return proc


def wait_port(port, proc, timeout=READY_TIMEOUT_S):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            if proc.poll() is not None:
                return False
            time.sleep(0.1)
    return False


def rtt_probe(prm):
    """One `{"kinds":[65535],"limit":1}` REQ; True when EOSE arrives."""
    r = sh(harness_cmd(prm, "rtt", "--url", ws_url(prm.p("net", "port")),
                     "--n", "1"), timeout=RTT_TIMEOUT_S)
    v = last_json(r.stdout)
    return r.returncode == 0 and isinstance(v, dict) and v.get("n", 0) >= 1


def stop_relay(proc, sig=signal.SIGTERM):
    if proc.poll() is not None:
        return
    proc.send_signal(sig)
    try:
        proc.wait(timeout=TERM_GRACE_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=TERM_GRACE_S)


def restart_timed(prm, unit, entry, run_dir):
    """Start the relay; measure start -> first REQ->EOSE at 50 ms."""
    proc = start_relay(prm, unit, entry, run_dir)
    t0 = time.monotonic()
    ok = False
    while time.monotonic() - t0 < RESTART_DEADLINE_S:
        if proc.poll() is not None:
            break
        if rtt_probe(prm):
            ok = True
            break
        time.sleep(RESTART_POLL_S)
    ms = (time.monotonic() - t0) * 1000.0 if ok else None
    return proc, ms


def drop_caches():
    subprocess.run(["sync"], check=False)
    try:
        Path("/proc/sys/vm/drop_caches").write_text("3\n")
        return True
    except OSError as e:
        print(f"run.py: drop_caches failed: {e}", file=sys.stderr)
        return False


def prepare_db(prm, unit):
    """`main`/`reuse` leave the db alone, `fresh` wipes the workload's
    scratch dir, `import:w6` imports the regular corpus into its own
    dir once per rep. Returns import stats or None."""
    mode = unit["db"]
    d = db_dir(prm, unit)
    if mode in ("main", "reuse"):
        return None
    if mode == "fresh":
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        return None
    if mode == "import:w6":
        marker = d.parent / f".imported-{bin_of(unit['label'])}-r{unit['rep']}"
        if marker.exists():
            return None
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        entry = relay_entry(unit["label"], prm)
        log_path = d.parent / f"import-w6-{bin_of(unit['label'])}-r{unit['rep']}.log"
        with open(log_path, "wb") as log:
            stats = timed_import(prm, entry, str(d),
                                 prm.path_of("regular"), log)
        marker.touch()
        return {"import": stats}
    if mode == "copy":
        src = prm.path_of("work") / "db" / bin_of(unit["label"])
        src_bytes = du_bytes(src)
        if src_bytes is None:
            sys.exit(f"run.py: db-copy source {src} missing — run `run.py prep`")
        free = shutil.disk_usage(prm.path_of("work")).free
        if free < src_bytes + 10 * (1 << 30):
            sys.exit(f"run.py: {free} bytes free on {prm.path_of('work')}, "
                     f"need {src_bytes} for the db copy plus 10 GiB")
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        t0 = time.monotonic()
        rc = subprocess.call(["cp", "-a", "--reflink=never",
                              str(src) + "/.", str(d)])
        wall = time.monotonic() - t0
        copied = du_bytes(d)
        if rc != 0 or copied != src_bytes:
            shutil.rmtree(d, ignore_errors=True)
            sys.exit(f"run.py: db copy {src} -> {d} failed "
                     f"(rc={rc}, {copied} of {src_bytes} bytes)")
        drop_caches()
        return {"db_copy": {"source": str(src), "source_bytes": src_bytes,
                            "bytes": copied, "wall_secs": round(wall, 2),
                            "rc": rc}}
    sys.exit(f"run.py: unknown db mode {mode}")


def du_bytes(path):
    path = Path(path)
    if not path.exists():
        return None
    r = sh(["du", "-sb", str(path)])
    try:
        return int(r.stdout.split()[0])
    except (ValueError, IndexError):
        return None


def copy_generated(entry, run_dir, unit_dir):
    """relay.log and the generated config go into the unit dir."""
    names = {"nosfry": "nosfry.toml", "strfry": "strfry.conf", "nostr-rs": "config.toml"}
    for f in run_dir.iterdir():
        if f.name in ("relay.log", names[entry["impl"]]):
            shutil.copy2(f, unit_dir / f.name)


PID_CMDS = {"conns", "fanout", "ingest-closed", "ingest-open", "neg",
            "query", "soak"}


def with_pid(cmds, pid):
    """Append the relay pid to sampler-capable harness invocations."""
    out = []
    for argv in cmds:
        if len(argv) > 4 and argv[4] in PID_CMDS:
            argv = [*argv, "--pid", str(pid)]
        out.append(argv)
    return out


def run_cmds(cmds, rep_json, rep_log):
    """Run the unit's commands; stdout -> rep<k>.json, stderr -> rep<k>.log."""
    codes, outputs = [], []
    with open(rep_json, "a") as jf, open(rep_log, "ab") as log:
        for argv in cmds:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=log, text=True)
            stdout, _ = proc.communicate()
            codes.append(proc.returncode)
            jf.write(stdout if stdout.endswith("\n") or not stdout else stdout + "\n")
            outputs.append(last_json(stdout))
    return codes, outputs


# ------------------------------------------------------------------
# Unit runners
# ------------------------------------------------------------------

def run_dir_for(prm, unit, unit_dir):
    rel = unit_dir.relative_to(prm.path_of("results"))
    return prm.path_of("work") / "run" / rel


def run_harness_unit(prm, unit, unit_dir):
    entry = relay_entry(unit["label"], prm)
    run_dir = run_dir_for(prm, unit, unit_dir)
    prep = prepare_db(prm, unit)
    if prep:
        (unit_dir / f"rep{unit['rep']}.import.json").write_text(json.dumps(prep))
    proc = start_relay(prm, unit, entry, run_dir)
    port_up = wait_port(prm.p("net", "port"), proc)
    warm = port_up and rtt_probe(prm)
    cold_done = drop_caches() if unit["cold_cache"] and port_up else False
    rep_json = unit_dir / f"rep{unit['rep']}.json"
    rep_log = unit_dir / f"rep{unit['rep']}.log"
    if port_up:
        codes, outputs = run_cmds(with_pid(unit["cmds"], proc.pid),
                                  rep_json, rep_log)
    else:
        codes, outputs = [-1], []
    stop_relay(proc)
    copy_generated(entry, run_dir, unit_dir)
    valid = port_up and warm and all(c == 0 for c in codes)
    for o in outputs:
        if isinstance(o, dict) and "valid" in o:
            valid = valid and bool(o["valid"])
    return {"cmds_rc": codes, "relay_rc": proc.returncode, "port_up": port_up,
            "warmup_req": warm, "cold_cache": cold_done,
            "db_bytes": du_bytes(db_dir(prm, unit)), "valid": valid}


def run_relaybench_unit(prm, unit, unit_dir):
    out_dir = unit_dir / "relaybench-out"
    rb_work = prm.path_of("work") / "rb" / f"{unit['label']}-r{unit['rep']}"
    argv = [*unit["cmds"][0], "--work", str(rb_work), "--out", str(out_dir)]
    rep_log = unit_dir / f"rep{unit['rep']}.log"
    t0 = time.time()
    with open(rep_log, "wb") as log:
        rc = subprocess.call(argv, stdout=log, stderr=subprocess.STDOUT)
    found = sorted(out_dir.glob("*/results.json"))
    rep_json = unit_dir / f"rep{unit['rep']}.json"
    if found:
        shutil.copy2(found[-1], rep_json)
    return {"cmds_rc": [rc], "wall_secs": round(time.time() - t0, 2),
            "valid": rc == 0 and bool(found)}


def impl_conf(prm, entry, db):
    """Minimal offline config pointing the impl at `db`."""
    conf = prm.path_of("work") / "import" / f"{entry['impl']}-{bin_of(entry['label'])}.conf"
    conf.parent.mkdir(parents=True, exist_ok=True)
    if entry["impl"] == "nosfry":
        conf.write_text(f'[db]\npath = "{db}"\nmap_size = {LMDB_MAP}\n')
    elif entry["impl"] == "strfry":
        conf.write_text(f'db = "{db}"\ndbParams {{\n    mapsize = {LMDB_MAP}\n}}\n')
    return conf


def import_argv(prm, entry, db):
    """The relay's bulk-import command (JSONL on stdin, verify on)."""
    conf = impl_conf(prm, entry, db)
    if entry["impl"] == "nosfry":
        return [entry["binary"], "import", "--config", str(conf)]
    if entry["impl"] == "strfry":
        return [entry["binary"], "--config", str(conf), "import"]
    sys.exit(f"run.py: {entry['label']} has no bulk import path")


def count_events(prm, entry, db):
    """Stored event count of an offline db, or None on failure."""
    conf = impl_conf(prm, entry, db)
    if entry["impl"] == "nosfry":
        r = sh([entry["binary"], "scan", "--config", str(conf),
                "--count", "{}"])
    elif entry["impl"] == "strfry":
        r = sh([entry["binary"], "--config", str(conf),
                "scan", "--count", "{}"])
    else:
        return None
    try:
        return int(r.stdout.strip()) if r.returncode == 0 else None
    except ValueError:
        return None


def prep_records(prm):
    """Latest `corpus == "d2"` prep-imports record per label."""
    out = {}
    log = prm.path_of("results") / "prep-imports.jsonl"
    if log.exists():
        for line in log.read_text().splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("corpus") == "d2":
                out[r.get("label")] = r
    return out


def require_main_dbs(prm, units):
    """Every db="main" unit shares the prep-imported d2 db; refuse to
    run when it is missing or holds less than prep stored."""
    records = prep_records(prm)
    for b in sorted({bin_of(u["label"]) for u in units
                     if u["db"] in ("main", "copy") and u["kind"] != "relaybench"}):
        rec = records.get(b)
        expected = rec["stored"] if rec else None
        db = prm.path_of("work") / "db" / b
        actual = count_events(prm, relay_entry(b, prm), db)
        if expected is None or actual is None or actual < expected:
            sys.exit(f"run.py: shared db for {b} holds {actual} events, "
                     f"prep record expects {expected} — run `run.py prep`")


def timed_import(prm, entry, db, stdin_path, log):
    """Import `stdin_path` into `db` under /usr/bin/time -v."""
    argv = ["/usr/bin/time", "-v", *import_argv(prm, entry, db)]
    t0 = time.monotonic()
    with open(stdin_path, "rb") as fin:
        proc = subprocess.Popen(argv, stdin=fin, stdout=log, stderr=subprocess.PIPE)
        _, stderr = proc.communicate()
    wall = time.monotonic() - t0
    text = stderr.decode(errors="replace")
    user = re.search(r"User time \(seconds\): ([\d.]+)", text)
    syst = re.search(r"System time \(seconds\): ([\d.]+)", text)
    cpu = (float(user.group(1)) + float(syst.group(1))) if user and syst else None
    return {"rc": proc.returncode, "wall_secs": round(wall, 2),
            "cpu_secs": round(cpu, 2) if cpu is not None else None,
            "db_bytes": du_bytes(db)}


def run_w5ro_unit(prm, unit, unit_dir):
    """start -> drop_caches -> cold query -> warm query -> timed restart."""
    entry = relay_entry(unit["label"], prm)
    run_dir = run_dir_for(prm, unit, unit_dir)
    rep_json = unit_dir / f"rep{unit['rep']}.json"
    rep_log = unit_dir / f"rep{unit['rep']}.log"
    phases = []
    ms = None
    prepare_db(prm, unit)
    with open(rep_log, "ab") as log:
        proc = start_relay(prm, unit, entry, run_dir)
        phases.append({"phase": "start",
                       "ok": wait_port(prm.p("net", "port"), proc) and rtt_probe(prm)})
        phases.append({"phase": "cold_cache", "done": drop_caches()})
        with open(rep_json, "a") as jf:
            for name, argv in zip(("query_cold", "query_warm"),
                                  with_pid(unit["cmds"], proc.pid)):
                t0 = time.monotonic()
                p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=log, text=True)
                stdout, _ = p.communicate()
                jf.write(stdout if stdout.endswith("\n") or not stdout else stdout + "\n")
                phases.append({"phase": name, "rc": p.returncode,
                               "wall_secs": round(time.monotonic() - t0, 2)})
        stop_relay(proc)
        proc, ms = restart_timed(prm, unit, entry, run_dir)
        phases.append({"phase": "restart", "restart_ms": ms})
        stop_relay(proc)
        copy_generated(entry, run_dir, unit_dir)
    valid = all(p.get("rc", 0) == 0 for p in phases) and ms is not None
    return {"phases": phases, "restart_ms": ms,
            "db_bytes": du_bytes(db_dir(prm, unit)),
            "cmds_rc": [p["rc"] for p in phases if "rc" in p], "valid": valid}


def run_w5ingest_unit(prm, unit, unit_dir):
    """record the stored count -> start -> ingest-open -> stop."""
    entry = relay_entry(unit["label"], prm)
    db = db_dir(prm, unit)
    run_dir = run_dir_for(prm, unit, unit_dir)
    rep_json = unit_dir / f"rep{unit['rep']}.json"
    rep_log = unit_dir / f"rep{unit['rep']}.log"
    db_copy = (prepare_db(prm, unit) or {}).get("db_copy")
    try:
        proc = start_relay(prm, unit, entry, run_dir)
        port_up = wait_port(prm.p("net", "port"), proc)
        warm = port_up and rtt_probe(prm)
        if port_up:
            codes, outputs = run_cmds(with_pid(unit["cmds"], proc.pid),
                                      rep_json, rep_log)
        else:
            codes, outputs = [-1], []
        stop_relay(proc)
        copy_generated(entry, run_dir, unit_dir)
        db_bytes = du_bytes(db)
    finally:
        if db.exists():
            shutil.rmtree(db)
    valid = port_up and warm and all(c == 0 for c in codes)
    for o in outputs:
        if isinstance(o, dict) and "valid" in o:
            valid = valid and bool(o["valid"])
    return {"cmds_rc": codes, "relay_rc": proc.returncode, "port_up": port_up,
            "warmup_req": warm, "db_copy": db_copy, "db_bytes": db_bytes,
            "valid": valid}


def run_w8_unit(prm, unit, unit_dir):
    """start -> ack-ingest (bg) -> sleep -> KILL -> restart -> ack-check."""
    entry = relay_entry(unit["label"], prm)
    db = db_dir(prm, unit)
    run_dir = run_dir_for(prm, unit, unit_dir)
    rep_json = unit_dir / f"rep{unit['rep']}.json"
    rep_log = unit_dir / f"rep{unit['rep']}.log"
    phases = []
    ms = None
    prepare_db(prm, unit)
    with open(rep_log, "ab") as log:
        proc = start_relay(prm, unit, entry, run_dir)
        phases.append({"phase": "start",
                       "ok": wait_port(prm.p("net", "port"), proc) and rtt_probe(prm)})
        ids_path = Path(unit["note"]["ids"])
        ids_path.parent.mkdir(parents=True, exist_ok=True)
        ingest_out = unit_dir / f"rep{unit['rep']}.ack-ingest.json"
        with open(ingest_out, "w") as fout:
            bg = subprocess.Popen(unit["cmds"][0], stdout=fout, stderr=log)
        time.sleep(unit["note"]["kill_after_s"])
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=TERM_GRACE_S)
        phases.append({"phase": "kill", "kill_after_s": unit["note"]["kill_after_s"],
                       "relay_rc": proc.returncode})
        proc, ms = restart_timed(prm, unit, entry, run_dir)
        phases.append({"phase": "restart", "restart_ms": ms})
        try:
            bg.wait(timeout=120)
        except subprocess.TimeoutExpired:
            bg.kill()
            bg.wait(timeout=TERM_GRACE_S)
        phases.append({"phase": "ack_ingest", "rc": bg.returncode})
        check = subprocess.Popen(unit["cmds"][1], stdout=subprocess.PIPE,
                                 stderr=log, text=True)
        stdout, _ = check.communicate()
        with open(rep_json, "w") as jf:
            jf.write(stdout if stdout.endswith("\n") or not stdout else stdout + "\n")
        phases.append({"phase": "ack_check", "rc": check.returncode})
        stop_relay(proc)
        copy_generated(entry, run_dir, unit_dir)
    valid = bg.returncode == 0 and check.returncode == 0 and ms is not None
    return {"phases": phases, "restart_ms": ms, "db_bytes": du_bytes(db),
            "cmds_rc": [bg.returncode, check.returncode], "valid": valid}


RUNNERS = {"harness": run_harness_unit, "relaybench": run_relaybench_unit,
           "w5ro": run_w5ro_unit, "w5ingest": run_w5ingest_unit,
           "w8": run_w8_unit}


# ------------------------------------------------------------------
# prep / manifest / metadata / status
# ------------------------------------------------------------------

def write_run_meta(prm, read_ahead=None):
    bi = prm.path_of("build_info")
    meta = {
        "build_info": bi.read_text() if bi.exists() else None,
        "uname": sh_out(["uname", "-a"]),
        "nproc": sh_out(["nproc"]),
        "memtotal": read_memtotal(),
        "sysctls": set_sysctls(),
        "ulimit_nofile": sh_out(["bash", "-c", "ulimit -n"]),
        "cpu_affinity": {"relay": prm.p("cores", "relay"),
                         "harness": prm.p("cores", "harness")},
        "params_toml": prm.raw,
        "params_sha256": prm.sha256,
        "read_ahead": read_ahead,
    }
    results = prm.path_of("results")
    results.mkdir(parents=True, exist_ok=True)
    (results / "run-meta.json").write_text(json.dumps(meta, indent=2))


def manifest_line(prm, unit, result, t0, t1, unit_dir):
    path = prm.path_of("results") / "manifest.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    line = {
        "workload": unit["workload"], "scenario": unit["scenario"],
        "label": unit["label"], "rep": unit["rep"],
        "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)),
        "end_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t1)),
        "load_avg_before": result.pop("load_avg", None),
        "exit_codes": result.get("cmds_rc"),
        "relay_rc": result.get("relay_rc"),
        "db_bytes": result.get("db_bytes"),
        "restart_ms": result.get("restart_ms"),
        "valid": result.get("valid"),
        "note": unit["note"],
        "path": str(unit_dir),
    }
    with open(path, "a") as f:
        f.write(json.dumps(line) + "\n")


def cmd_prep(prm):
    with read_ahead_ctx(prm) as rec:
        write_run_meta(prm, rec)
        prep_body(prm)


def prep_body(prm):
    d2 = prm.path_of("d2")
    events = d2 / "events.jsonl"
    if not events.exists():
        sys.exit(f"run.py: {events} missing — run `gen` first")
    harness = str(prm.path_of("harness"))
    work = prm.path_of("work")

    # regular.jsonl = exactly the first w6.n regular events each w6
    # rep imports into its own dir. holdout-regular.jsonl = the next
    # slice, sized for w6's additions plus w8's worst-case ingest.
    if "w6" in prm.cfg and "w8" in prm.cfg:
        n = int(prm.p("w6", "n"))
        w8 = prm.p("w8")
        max_diff = max(prm.p("w6", "diff")) / 100.0
        holdout_need = (int(n * max_diff / 2)
                        + int(w8["cycles"] * w8["kill_max"] * w8["rate"]))
        for argv in (
            [harness, "corpus-filter", "--regular", "--first", str(n),
             "--in", str(events), "--out", str(prm.path_of("regular"))],
            [harness, "corpus-filter", "--regular", "--skip", str(n),
             "--first", str(holdout_need),
             "--in", str(events), "--out", str(prm.path_of("holdout_regular"))],
        ):
            r = subprocess.run(argv)
            if r.returncode != 0:
                sys.exit("run.py: corpus-filter failed")
    else:
        print("prep: no [w6]/[w8] in params — skipping corpus-filter")

    # One events.jsonl import per relay into work/db/<bin> — the
    # shared db every read-only unit uses; there are no snapshots.
    # A populated db is left in place and only counted.
    bins = sorted({bin_of(l) for wl in ("w2", "w5", "w6") for l in prm.cfg.get(wl, {}).get("relays", [])
                   if not bin_of(l).startswith("nostr-rs")})
    import_log = prm.path_of("results") / "prep-imports.jsonl"
    import_log.parent.mkdir(parents=True, exist_ok=True)
    records = prep_records(prm)
    with open(import_log, "a") as jf:
        for bin_name in bins:
            entry = relay_entry(bin_name, prm)
            db = work / "db" / bin_name
            stored = count_events(prm, entry, db)
            rec = records.get(bin_name)
            if rec and stored is not None and stored >= rec["stored"]:
                stats = {"skipped": f"db already imported ({stored} events)",
                         "db_bytes": du_bytes(db)}
            elif db.exists() and stored:
                sys.exit(f"run.py: {db} holds {stored} events that do not "
                         f"match a prep record — remove it manually")
            else:
                if db.exists():
                    shutil.rmtree(db)
                db.mkdir(parents=True)
                with open(work / f"import-d2-{bin_name}.log", "wb") as log:
                    stats = timed_import(prm, entry, str(db), events, log)
                stored = count_events(prm, entry, db)
            jf.write(json.dumps({"corpus": "d2", "label": bin_name,
                                 "stored": stored, **stats}) + "\n")
            print(f"prep: {bin_name}: stored={stored}, "
                  f"{stats['db_bytes']} bytes")
    print("prep: done")


def cmd_status(prm):
    manifest = prm.path_of("results") / "manifest.jsonl"
    done = {}
    if manifest.exists():
        for line in manifest.read_text().splitlines():
            try:
                m = json.loads(line)
            except ValueError:
                continue
            done[(m["workload"], m["scenario"], m["label"], m["rep"])] = m.get("valid")
    for wl in ("w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8"):
        try:
            units = schedule(prm, wl, pilot=False)
        except SystemExit:
            units = []
        keys = {(u["workload"], u["scenario"], u["label"], u["rep"]) for u in units}
        finished = sum(1 for k in keys if k in done)
        valid = sum(1 for k in keys if done.get(k) is True)
        print(f"{wl}: {finished}/{len(units)} units done, {valid} valid")


def run_schedule(prm, units, dry_run):
    if dry_run:
        rec = read_ahead_record(prm)
        if rec["applied_kb"] is not None:
            print(f"[dry] read_ahead_kb: would set {rec['path']} "
                  f"to {rec['applied_kb']} (recorded {rec['original_kb']})")
        else:
            print(f"[dry] read_ahead_kb: {rec['path']} "
                  f"(recorded {rec['original_kb']}, no [host] pin)")
        run_units(prm, units, dry_run=True)
        return
    with read_ahead_ctx(prm) as rec:
        write_run_meta(prm, rec)
        require_main_dbs(prm, units)
        run_units(prm, units)


def run_units(prm, units, dry_run=False):
    results = prm.path_of("results")
    for u in units:
        unit_dir = results / u["workload"] / u["scenario"] / u["label"]
        head = (f"{u['workload']}/{u['scenario']}/{u['label']}/rep{u['rep']} "
                f"db={u['db']} cold={u['cold_cache']}")
        if dry_run:
            print(f"[dry] {head}")
            for cmd in u["cmds"]:
                print(f"      {' '.join(map(str, cmd))}")
            continue
        unit_dir.mkdir(parents=True, exist_ok=True)
        rep_json = unit_dir / f"rep{u['rep']}.json"
        if rep_json.exists():
            print(f"skip {head} (rep{u['rep']}.json exists)")
            continue
        assert_quiet()
        result = {"load_avg": loadavg()}
        print(f"run  {head}")
        t0 = time.time()
        result.update(RUNNERS[u["kind"]](prm, u, unit_dir))
        t1 = time.time()
        (unit_dir / f"rep{u['rep']}.result.json").write_text(
            json.dumps(result, indent=2))
        manifest_line(prm, u, result, t0, t1, unit_dir)
        print(f"     valid={result.get('valid')}")


def main():
    ap = argparse.ArgumentParser(description="round 7 benchmark orchestrator")
    ap.add_argument("--params", default=str(Path(__file__).with_name("params.toml")))
    ap.add_argument("--dry-run", action="store_true",
                    help="print the scheduled units and commands; start nothing")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prep")
    for wl in ("w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8"):
        sub.add_parser(wl)
    p = sub.add_parser("pilot")
    p.add_argument("workload", choices=["w1", "w5", *sorted(BUILDERS)])
    sub.add_parser("status")
    args = ap.parse_args()

    prm = Params(args.params)
    if args.cmd == "prep":
        if not args.dry_run:
            cmd_prep(prm)
        else:
            print("[dry] prep: corpus-filter + per-relay d2 import")
        return
    if args.cmd == "status":
        cmd_status(prm)
        return
    pilot = args.cmd == "pilot"
    workload = args.workload if pilot else args.cmd
    units = schedule(prm, workload, pilot)
    if pilot and workload == "w1":
        units = [u for u in units if u["scenario"].startswith("closed-")]
    run_schedule(prm, units, args.dry_run)


if __name__ == "__main__":
    main()
