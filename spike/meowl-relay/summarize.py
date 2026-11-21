#!/usr/bin/env python3
"""Print pass/fail/flaky/skip counts and the failing test list for a
Playwright JSON report. Usage: summarize.py <report.json>"""

import json
import re
import sys

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def walk(suite, out):
    for spec in suite.get("specs", []):
        for test in spec.get("tests", []):
            status = test.get("status")
            first = (test.get("results") or [{}])[0]
            error = ANSI.sub("", first.get("error", {}).get("message") or "")
            out.append(
                {
                    "file": spec.get("file"),
                    "title": spec.get("title"),
                    "status": status,
                    "error": error.splitlines()[0] if error else "",
                    "duration": first.get("duration", 0),
                }
            )
    for child in suite.get("suites", []):
        walk(child, out)


def main(path: str) -> None:
    report = json.load(open(path))
    tests = []
    for suite in report.get("suites", []):
        walk(suite, tests)
    counts = {}
    for t in tests:
        counts[t["status"]] = counts.get(t["status"], 0) + 1
    print(f"{path}: {counts} total={len(tests)}")
    for t in tests:
        if t["status"] in ("unexpected", "flaky"):
            print(f"  {t['status']:10} {t['file']} | {t['title']} | {t['error'][:110]}")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        main(arg)
