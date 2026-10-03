"""Small exact / resampling statistics shared by the benchmarks (stdlib only).

  wilson            Wilson score interval (two-sided)
  clopper_pearson   exact binomial interval (two-sided) and one-sided lower bound
  mcnemar_exact     exact two-sided McNemar test on discordant pairs
  cluster_bootstrap percentile CI of a pooled proportion, resampling whole repositories
  paired_cluster_bootstrap
                    percentile CI of a paired accuracy difference, resampling repositories
  run_meta          the GitHub Actions run (and command) that produced a results file
"""
from __future__ import annotations

import math
import os
import random
import subprocess
import sys
import time
from pathlib import Path


def wilson(c: int, n: int, z: float = 1.96) -> list[float] | None:
    """Wilson score 95% interval for c successes out of n (ignores clustering)."""
    if not n:
        return None
    p = c / n
    d = 1 + z * z / n
    m = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(max(0.0, m - h), 4), round(min(1.0, m + h), 4)]


def _log_pmf(k: int, n: int, p: float) -> float:
    if p <= 0.0:
        return 0.0 if k == 0 else -math.inf
    if p >= 1.0:
        return 0.0 if k == n else -math.inf
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
            + k * math.log(p) + (n - k) * math.log1p(-p))


def binom_sf(x: int, n: int, p: float) -> float:
    """P(X >= x) for X ~ Binomial(n, p), summed exactly in log space."""
    if x <= 0:
        return 1.0
    if x > n:
        return 0.0
    logs = [_log_pmf(k, n, p) for k in range(x, n + 1)]
    m = max(logs)
    return 0.0 if m == -math.inf else min(1.0, math.exp(m) * sum(math.exp(v - m) for v in logs))


def binom_cdf(x: int, n: int, p: float) -> float:
    """P(X <= x) for X ~ Binomial(n, p)."""
    return 1.0 - binom_sf(x + 1, n, p) if x < n else 1.0


def _bisect(f, target: float, increasing: bool) -> float:
    lo, hi = 0.0, 1.0
    for _ in range(100):
        mid = (lo + hi) / 2
        v = f(mid)
        if (v < target) == increasing:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def cp_lower(c: int, n: int, alpha: float = 0.05) -> float | None:
    """One-sided exact (Clopper-Pearson) lower confidence bound at level 1 - alpha."""
    if not n:
        return None
    if c == 0:
        return 0.0
    if c == n:
        return round(alpha ** (1 / n), 4)
    return round(_bisect(lambda p: binom_sf(c, n, p), alpha, increasing=True), 4)


def cp_upper(c: int, n: int, alpha: float = 0.05) -> float | None:
    """One-sided exact (Clopper-Pearson) upper confidence bound at level 1 - alpha."""
    if not n:
        return None
    if c == n:
        return 1.0
    if c == 0:
        return round(1 - alpha ** (1 / n), 4)
    return round(_bisect(lambda p: binom_cdf(c, n, p), alpha, increasing=False), 4)


def clopper_pearson(c: int, n: int, alpha: float = 0.05) -> list[float] | None:
    """Two-sided exact (Clopper-Pearson) interval at level 1 - alpha."""
    if not n:
        return None
    return [cp_lower(c, n, alpha / 2), cp_upper(c, n, alpha / 2)]


def mcnemar_exact(only_a: int, only_b: int) -> float | None:
    """Exact two-sided McNemar p-value from the two discordant counts (None without discordance)."""
    m = only_a + only_b
    if not m:
        return None
    p = min(1.0, 2 * binom_cdf(min(only_a, only_b), m, 0.5))
    return float(f"{p:.3g}")


def proportion(c: int, n: int) -> dict:
    """correct / total / accuracy with Wilson, two-sided exact and one-sided exact-lower bounds."""
    return {"correct": c, "total": n, "accuracy": round(c / n, 4) if n else None,
            "wilson95": wilson(c, n), "clopper_pearson95": clopper_pearson(c, n),
            "cp_lower95_one_sided": cp_lower(c, n)}


def cluster_bootstrap(per_repo: list[tuple[int, int]], n_boot: int = 2000, seed: int = 0) -> list[float] | None:
    """95% percentile CI of the pooled accuracy, resampling whole repositories (clusters).

    Degenerate ([1, 1]) when every repository is at 100%; report the exact bound then."""
    per_repo = [x for x in per_repo if x[1]]
    if not per_repo:
        return None
    rng = random.Random(seed)
    stats = []
    for _ in range(n_boot):
        smp = [per_repo[rng.randrange(len(per_repo))] for _ in per_repo]
        stats.append(sum(c for c, _ in smp) / sum(t for _, t in smp))
    stats.sort()
    return [round(stats[int(0.025 * n_boot)], 4), round(stats[int(0.975 * n_boot) - 1], 4)]


def paired_cluster_bootstrap(per_repo: list[tuple[int, int, int]], n_boot: int = 2000,
                             seed: int = 0) -> list[float] | None:
    """95% percentile CI of acc(A) - acc(B) from per-repo (A correct, B correct, pairs), resampling repos."""
    per_repo = [x for x in per_repo if x[2]]
    if not per_repo:
        return None
    rng = random.Random(seed)
    stats = []
    for _ in range(n_boot):
        smp = [per_repo[rng.randrange(len(per_repo))] for _ in per_repo]
        n = sum(t for _, _, t in smp)
        stats.append((sum(a for a, _, _ in smp) - sum(b for _, b, _ in smp)) / n)
    stats.sort()
    return [round(stats[int(0.025 * n_boot)], 4), round(stats[int(0.975 * n_boot) - 1], 4)]


def table2x2(pairs: list[tuple[bool, bool]]) -> dict:
    """Paired outcome table for methods A and B on the same items, with an exact McNemar test."""
    both = sum(a and b for a, b in pairs)
    only_a = sum(a and not b for a, b in pairs)
    only_b = sum(b and not a for a, b in pairs)
    neither = sum(not a and not b for a, b in pairs)
    return {"both": both, "only_a": only_a, "only_b": only_b, "neither": neither,
            "mcnemar_exact_p": mcnemar_exact(only_a, only_b)}


def run_meta() -> dict:
    """The GitHub Actions run that produced a results file (nulls when run locally), plus the command."""
    rid = os.environ.get("GITHUB_RUN_ID")
    srv = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    rep = os.environ.get("GITHUB_REPOSITORY", "")
    commit = os.environ.get("GITHUB_SHA")
    if not commit:
        try:
            commit = subprocess.run(["git", "-C", str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"],
                                    capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            commit = None
    return {"run_id": int(rid) if rid else None,
            "run_url": f"{srv}/{rep}/actions/runs/{rid}" if rid else None,
            "commit": commit,
            "generated": "github-actions" if rid else "local",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "command": "python " + " ".join([Path(sys.argv[0]).as_posix().split("tracegate/", 1)[-1], *sys.argv[1:]])}
