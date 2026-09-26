#!/usr/bin/env python3
"""Evaluate the typosquat detector on real PyPI data.

Positives : every package name in OSV MAL-* advisories for PyPI (ossf/malicious-packages),
            minus names that are themselves in the top-15k (compromised legit packages).
Negatives : legitimate PyPI projects ranked 5,001-15,000 by 30-day downloads
            (top-pypi-packages), i.e. real packages the reference list does NOT whitelist.
Reference : top-5,000 PyPI projects = what a squatter would impersonate.

Detectors compared:
  mvp-difflib : the original MVP heuristic (difflib ratio >= 0.8 vs 14 hard-coded names)
  lev1        : plain Levenshtein <= 1 vs the same top-5k reference (typical OSS scanner)
  tracegate   : multi-technique TyposquatDetector (threshold sweep + ablation)

Usage: python benchmarks/typosquat_eval.py [--ref 5000] [--out results/]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tracegate.data import data_root, top_npm, top_pypi  # noqa: E402
from tracegate.osv import iter_zip_records, mal_mentions_typosquat  # noqa: E402
from tracegate.typosquat import TyposquatDetector, normalize  # noqa: E402
from tracegate.warden import POPULAR, DifflibWarden  # noqa: E402


def load_mal(zip_path: Path, eco: str) -> dict[str, bool]:
    """normalised name -> advisory text mentions typosquatting."""
    out: dict[str, bool] = {}
    for r in iter_zip_records(zip_path):
        if not r["id"].startswith("MAL-") or r.get("withdrawn"):
            continue
        for a in r.get("affected", []):
            if a.get("package", {}).get("ecosystem") == eco:
                n = normalize(a["package"]["name"])
                out[n] = out.get(n, False) or mal_mentions_typosquat(r)
    return out


def prf(tp: int, fp: int, fn: int, tn: int) -> dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0, "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0}


def evaluate(flag: dict[str, bool], pos: set[str], neg: set[str], typo_subset: set[str]) -> dict:
    tp = sum(flag[n] for n in pos)
    fp = sum(flag[n] for n in neg)
    res = prf(tp, fp, len(pos) - tp, len(neg) - fp)
    res["recall_typo_labelled"] = round(sum(flag[n] for n in typo_subset) / max(1, len(typo_subset)), 4)
    return res


def bootstrap_ci(flags: dict[str, dict[str, bool]], pos: set[str], neg: set[str], ref: str,
                 n_boot: int = 1000, seed: int = 0) -> dict:
    """Stratified bootstrap (positives and negatives resampled separately, seeded) of the
    test-half metrics: 95% percentile CIs per method, plus the paired F1 difference vs `ref`."""
    import numpy as np
    rng = np.random.default_rng(seed)
    P, N = sorted(pos), sorted(neg)
    fp_ = {m: np.array([fl[n] for n in P], dtype=np.int64) for m, fl in flags.items()}
    fn_ = {m: np.array([fl[n] for n in N], dtype=np.int64) for m, fl in flags.items()}
    samples: dict[str, dict[str, list[float]]] = {m: {"precision": [], "recall": [], "f1": [], "fpr": []}
                                                   for m in flags}
    diffs: dict[str, list[float]] = {m: [] for m in flags if m != ref}
    for _ in range(n_boot):
        wp = rng.multinomial(len(P), np.full(len(P), 1 / len(P)))
        wn = rng.multinomial(len(N), np.full(len(N), 1 / len(N)))
        f1s = {}
        for m in flags:
            tp, fp = int(wp @ fp_[m]), int(wn @ fn_[m])
            r = prf(tp, fp, len(P) - tp, len(N) - fp)
            for k in samples[m]:
                samples[m][k].append(r[k])
            f1s[m] = r["f1"]
        for m in diffs:
            diffs[m].append(f1s[m] - f1s[ref])

    def ci(xs: list[float]) -> list[float]:
        xs = sorted(xs)
        return [round(xs[int(0.025 * len(xs))], 4), round(xs[int(0.975 * len(xs)) - 1], 4)]
    return {"n_boot": n_boot, "seed": seed, "method": "stratified percentile bootstrap, 95%",
            "ci": {m: {k: ci(v) for k, v in d.items()} for m, d in samples.items()},
            "f1_diff_vs_" + ref: {m: {"ci": ci(v), "p_le_0": round(sum(x <= 0 for x in v) / len(v), 4)}
                                  for m, v in diffs.items()}}


def run(eco: str, ref_n: int, neg_hi: int, out: Path) -> dict:
    root = data_root()
    if eco == "PyPI":
        ranked = [normalize(n) for n in top_pypi()]
        zip_path = root / "osv/PyPI-all.zip"
    else:
        ranked = [normalize(n) for n in top_npm()]
        zip_path = root / "osv/npm-all.zip"
    mal = load_mal(zip_path, eco)
    ref = ranked[:ref_n]
    known = set(ranked[:neg_hi])
    pos = {n for n in mal if n not in known}
    neg = {n for n in ranked[ref_n:neg_hi] if n not in mal}
    # deterministic 50/50 dev/test split: thresholds are tuned on dev, reported on test
    def is_test(n: str) -> bool:
        return int(hashlib.sha256(n.encode()).hexdigest(), 16) % 2 == 0
    dev_pos, dev_neg = {n for n in pos if not is_test(n)}, {n for n in neg if not is_test(n)}
    pos, neg = {n for n in pos if is_test(n)}, {n for n in neg if is_test(n)}
    typo_subset = {n for n in pos if mal[n]}
    dev_typo = {n for n in dev_pos if mal[n]}
    names = sorted(pos | neg | dev_pos | dev_neg)
    print(f"[{eco}] reference={len(ref)} test positives={len(pos)} (typo-labelled {len(typo_subset)}) "
          f"test negatives={len(neg)}")

    results: dict[str, dict] = {}
    flags_by: dict[str, dict[str, bool]] = {}
    # --- baseline 0: the MVP heuristic --------------------------------------
    mvp = DifflibWarden(popular=POPULAR if eco == "PyPI" else ref[:14])
    t0 = time.perf_counter()
    flag = {n: mvp.score(n, "0").risk >= 0.5 for n in names}
    flags_by["mvp-difflib (14 names)"] = flag
    results["mvp-difflib (14 names)"] = {**evaluate(flag, pos, neg, typo_subset),
                                         "ms_per_name": round(1000 * (time.perf_counter() - t0) / len(names), 4)}
    # --- baseline 1: Levenshtein<=1 against the same reference --------------
    lev = TyposquatDetector(ref, long_name=10**9, enabled={"typo1"})
    t0 = time.perf_counter()
    flag = {n: lev.score(n).score > 0 for n in names}
    flags_by["lev1 (top-5k)"] = flag
    results["lev1 (top-5k)"] = {**evaluate(flag, pos, neg, typo_subset),
                                "ms_per_name": round(1000 * (time.perf_counter() - t0) / len(names), 4)}
    # --- tracegate: full detector, threshold sweep --------------------------
    det = TyposquatDetector(ref)
    t0 = time.perf_counter()
    scored = {n: det.score(n) for n in names}
    ms = round(1000 * (time.perf_counter() - t0) / len(names), 4)
    curve, dev_curve = [], []
    for th in [x / 100 for x in range(30, 100, 2)]:
        flag = {n: m.score >= th for n, m in scored.items()}
        curve.append({"threshold": th, **evaluate(flag, pos, neg, typo_subset)})
        dev_curve.append({"threshold": th, **evaluate(flag, dev_pos, dev_neg, dev_typo)})
    # operating point: best dev F1 among thresholds whose dev FPR <= 2 % (gate must not cry wolf)
    ok = [c for c in dev_curve if c["fpr"] <= 0.02] or dev_curve
    default_th = max(ok, key=lambda c: (c["f1"], c["threshold"]))["threshold"]
    flag = {n: m.score >= default_th for n, m in scored.items()}
    flags_by[f"tracegate (th={default_th})"] = flag
    results[f"tracegate (th={default_th})"] = {**evaluate(flag, pos, neg, typo_subset), "ms_per_name": ms}
    # same detector at the dev threshold whose FPR matches the lev1 baseline's dev FPR
    lev_dev_fpr = evaluate({n: lev.score(n).score > 0 for n in dev_pos | dev_neg}, dev_pos, dev_neg, dev_typo)["fpr"]
    th_m = min((c for c in dev_curve if c["fpr"] <= lev_dev_fpr), key=lambda c: c["threshold"])["threshold"]
    flag = {n: m.score >= th_m for n, m in scored.items()}
    flags_by[f"tracegate (th={th_m}, FPR-matched to lev1)"] = flag
    results[f"tracegate (th={th_m}, FPR-matched to lev1)"] = {**evaluate(flag, pos, neg, typo_subset), "ms_per_name": ms}
    # --- ablation: one technique at a time -----------------------------------
    ablation = {}
    for tech in TyposquatDetector.BASE:
        d1 = TyposquatDetector(ref, enabled={tech})
        flag = {n: d1.score(n).score >= default_th for n in names}
        ablation[tech] = evaluate(flag, pos, neg, typo_subset)
    # technique breakdown of true / false positives
    by_tech: dict[str, dict[str, int]] = {}
    for n, m in scored.items():
        if m.score >= default_th and (n in pos or n in neg):
            k = "tp" if n in pos else "fp"
            by_tech.setdefault(m.technique or "?", {"tp": 0, "fp": 0})[k] += 1
    fps = sorted(((n, m.target, m.technique, m.score) for n, m in scored.items()
                  if n in neg and m.score >= default_th), key=lambda x: -x[3])[:25]
    tps = sorted(((n, m.target, m.technique, m.score) for n, m in scored.items()
                  if n in pos and m.score >= default_th), key=lambda x: -x[3])[:25]
    report = {"ecosystem": eco, "reference_size": len(ref), "split": "50/50 by sha256(name); numbers are TEST half",
              "chosen_threshold": default_th, "dev_positives": len(dev_pos), "dev_negatives": len(dev_neg),
              "positives": len(pos), "negatives": len(neg),
              "typo_labelled_positives": len(typo_subset), "results": results, "curve": curve,
              "bootstrap": bootstrap_ci(flags_by, pos, neg, "lev1 (top-5k)"),
              "ablation": ablation, "by_technique": by_tech, "examples_tp": tps, "examples_fp": fps,
              "sources": {"malicious": "OSV MAL-* (ossf/malicious-packages) via osv-vulnerabilities bulk dump",
                          "popular": "hugovk/top-pypi-packages" if eco == "PyPI" else "wooorm/npm-high-impact"}}
    out.mkdir(parents=True, exist_ok=True)
    (out / f"typosquat_{eco.lower()}.json").write_text(json.dumps(report, indent=1))
    for k, v in results.items():
        print(f"  {k:26s} P={v['precision']:.3f} R={v['recall']:.3f} F1={v['f1']:.3f} "
              f"FPR={v['fpr']:.4f} R(typo-labelled)={v['recall_typo_labelled']:.3f} "
              f"F1 95%CI={report['bootstrap']['ci'][k]['f1']}")
    print("  paired F1 diff vs lev1:", report["bootstrap"]["f1_diff_vs_lev1 (top-5k)"])
    return report


def plot(reports: list[dict], out: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    fig, ax = plt.subplots(figsize=(6, 4.2), dpi=120)
    colors = ["#2563eb", "#d97706"]
    for rep, c in zip(reports, colors):
        xs = [p["recall"] for p in rep["curve"]]
        ys = [p["precision"] for p in rep["curve"]]
        ax.plot(xs, ys, "-", color=c, label=f"tracegate ({rep['ecosystem']}) threshold sweep")
        for name, marker in (("lev1 (top-5k)", "s"), ("mvp-difflib (14 names)", "x")):
            r = rep["results"][name]
            ax.plot(r["recall"], r["precision"], marker, color=c, markersize=8,
                    label=f"{name.split(' ')[0]} ({rep['ecosystem']})")
    ax.set_xlabel("recall (OSV MAL-* packages)")
    ax.set_ylabel("precision (vs. legit ranks 5k-15k)")
    ax.set_title("Typosquat detection on real malicious-package names")
    ax.grid(alpha=0.3)
    ax.set_xlim(0, max(0.6, ax.get_xlim()[1]))
    ax.set_ylim(0, 1.02)
    ax.legend(fontsize=7, loc="lower left")
    fig.tight_layout()
    fig.savefig(out / "typosquat_pr.png")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", type=int, default=5000)
    ap.add_argument("--neg-hi", type=int, default=15000)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "results"))
    ap.add_argument("--eco", nargs="*", default=["PyPI", "npm"])
    a = ap.parse_args()
    out = Path(a.out)
    reps = []
    for eco in a.eco:
        need = "osv/PyPI-all.zip" if eco == "PyPI" else "osv/npm-all.zip"
        if not (data_root() / need).exists():
            print(f"skip {eco}: {need} missing (run scripts/download_data.py osv)")
            continue
        reps.append(run(eco, a.ref, a.neg_hi, out))
    if reps:
        plot(reps, out)


if __name__ == "__main__":
    main()
