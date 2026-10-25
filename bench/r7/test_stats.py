"""Cross-checks stats.py against SciPy and statsmodels.

Run: uv run --python 3.12 --with scipy --with statsmodels \
         python bench/r7/test_stats.py
"""
import random
import sys
from pathlib import Path

import numpy as np
from scipy.stats import binom, mannwhitneyu, permutation_test
from statsmodels.stats.multitest import multipletests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats  # noqa: E402

rng = random.Random(7)

# Exact MWU without ties against SciPy's exact method.
for _ in range(200):
    na, nb = rng.choice([(3, 3), (5, 5), (6, 6), (4, 7), (6, 5)])
    a = [round(rng.gauss(10, 2), 1) for _ in range(na)]
    b = [round(rng.gauss(11, 2), 1) for _ in range(nb)]
    if len(set(a + b)) != na + nb:
        continue
    u, p = stats.mann_whitney_exact(a, b)
    r = mannwhitneyu(a, b, alternative="two-sided", method="exact")
    assert abs(r.statistic - u) < 1e-9, (a, b, r.statistic, u)
    assert abs(r.pvalue - p) < 1e-9, (a, b, r.pvalue, p)


# With ties: SciPy's exhaustive permutation test on the U statistic.
def u_stat(x, y, axis):
    return mannwhitneyu(x, y, axis=axis, method="asymptotic").statistic


for _ in range(60):
    a = [rng.choice([1, 2, 2, 3, 4]) for _ in range(5)]
    b = [rng.choice([2, 3, 3, 4, 5]) for _ in range(6)]
    _, p = stats.mann_whitney_exact(a, b)
    r = permutation_test((a, b), u_stat, permutation_type="independent",
                         alternative="two-sided", n_resamples=np.inf)
    assert abs(min(1.0, r.pvalue) - p) < 1e-9, (a, b, r.pvalue, p)

# Order-statistic median interval coverage against the binomial CDF.
for n in range(2, 12):
    lo, _, cov = stats.median_ci(list(range(n)))
    expected = 1 - 2 * binom.cdf(lo, n, 0.5)
    assert abs(cov - expected) < 1e-12, (n, cov, expected)
assert stats.median_ci([1, 2, 3, 4, 5, 6]) == (1, 6, 0.96875)

# Holm step-down against statsmodels.
ps = {f"h{i}": rng.random() * 0.05 for i in range(8)}
ours = stats.holm(ps)
reject, adjusted, _, _ = multipletests(list(ps.values()), method="holm")
for (name, _), rej, adj in zip(ps.items(), reject, adjusted, strict=True):
    assert abs(ours[name][0] - adj) < 1e-12 and ours[name][1] == rej, (name, ours[name], adj, rej)

# 6 vs 6 with complete separation: the smallest attainable p.
assert abs(stats.mann_whitney_exact(range(6), range(6, 12))[1] - 2 / 924) < 1e-12
print("stats.py agrees with SciPy and statsmodels")
