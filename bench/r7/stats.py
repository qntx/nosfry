"""Distribution-free statistics for small-rep benchmark comparisons.

Standard library only, so analyze.py runs inside the bench container.
Every function is deterministic; test_stats.py checks them against
SciPy and statsmodels.
"""
from __future__ import annotations

import itertools
import math
from statistics import median


def median_ci(values: list[float], confidence: float = 0.95) -> tuple[float, float, float]:
    """Distribution-free confidence interval for the median.

    Uses order statistics: the interval [x_(k), x_(n-k+1)] covers the
    population median with probability 1 - 2 * P(Binom(n, 1/2) < k).
    Returns (lower, upper, achieved_coverage) for the largest k whose
    coverage is at least `confidence`; when even [min, max] falls
    short (n <= 5 at 95%), returns [min, max] with its actual coverage.
    """
    xs = sorted(values)
    n = len(xs)
    if n == 0:
        raise ValueError("no values")
    if n == 1:
        return xs[0], xs[0], 0.0

    def coverage(k: int) -> float:
        tail = sum(math.comb(n, i) for i in range(k)) / 2**n
        return 1.0 - 2.0 * tail

    best = 1
    for k in range(1, n // 2 + 1):
        if coverage(k) >= confidence:
            best = k
        else:
            break
    return xs[best - 1], xs[n - best], coverage(best)


def _ranks(pooled: list[float]) -> list[float]:
    """Mid-ranks (1-based), ties share the average rank."""
    order = sorted(range(len(pooled)), key=lambda i: pooled[i])
    ranks = [0.0] * len(pooled)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and pooled[order[j + 1]] == pooled[order[i]]:
            j += 1
        mid = (i + j) / 2 + 1
        for t in range(i, j + 1):
            ranks[order[t]] = mid
        i = j + 1
    return ranks


def mann_whitney_exact(a: list[float], b: list[float]) -> tuple[float, float]:
    """Two-sided exact Mann-Whitney U test by full enumeration.

    Returns (U_a, p). U_a counts pairs (x in a, y in b) with x > y, ties
    counting one half. The permutation distribution of U over all
    C(n, len(a)) relabelings is computed on the observed mid-ranks, so
    ties are handled exactly; the two-sided p doubles the smaller tail
    (SciPy's convention), capped at 1. Intended for small samples
    (n_a + n_b <= 20).
    """
    na, nb = len(a), len(b)
    if na == 0 or nb == 0:
        raise ValueError("empty sample")
    if na + nb > 20:
        raise ValueError("use an asymptotic test for n > 20")
    pooled = list(a) + list(b)
    ranks = _ranks(pooled)

    def u_of(idx: tuple[int, ...]) -> float:
        return sum(ranks[i] for i in idx) - na * (na + 1) / 2

    observed = u_of(tuple(range(na)))
    total = low = high = 0
    for idx in itertools.combinations(range(na + nb), na):
        u = u_of(idx)
        total += 1
        low += u <= observed + 1e-9
        high += u >= observed - 1e-9
    return observed, min(1.0, 2 * min(low, high) / total)


def holm(pvalues: dict[str, float], alpha: float = 0.05) -> dict[str, tuple[float, bool]]:
    """Holm-Bonferroni step-down. Returns name -> (adjusted p, reject)."""
    items = sorted(pvalues.items(), key=lambda kv: kv[1])
    m = len(items)
    out: dict[str, tuple[float, bool]] = {}
    running = 0.0
    still_rejecting = True
    for i, (name, p) in enumerate(items):
        adj = min(1.0, (m - i) * p)
        running = max(running, adj)
        reject = still_rejecting and running <= alpha
        if not reject:
            still_rejecting = False
        out[name] = (running, reject)
    return out


def summarize(values: list[float]) -> dict[str, float]:
    lo, hi, cov = median_ci(values)
    return {
        "n": len(values),
        "median": median(values),
        "ci_lo": lo,
        "ci_hi": hi,
        "ci_coverage": cov,
        "min": min(values),
        "max": max(values),
    }


def compare(a: list[float], b: list[float]) -> dict[str, float | bool]:
    """a vs b: ratio of medians, exact MWU p, and whether the two
    median intervals are disjoint."""
    sa, sb = summarize(a), summarize(b)
    _, p = mann_whitney_exact(a, b)
    disjoint = sa["ci_hi"] < sb["ci_lo"] or sb["ci_hi"] < sa["ci_lo"]
    ratio = sa["median"] / sb["median"] if sb["median"] else math.inf
    return {"ratio": ratio, "p": p, "ci_disjoint": disjoint}
