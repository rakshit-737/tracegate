#!/usr/bin/env python3
"""Real-repository benchmark: finding -> commit backtracking + reachability triage.

For each real OSS repo (cloned by scripts/download_data.py repos) and a set of
snapshots along its first-parent history:

 1. commit stage : every manifest-changing commit up to the snapshot (gitlineage)
 2. build stage  : the snapshot's pinned dependencies (at HEAD: the real Syft SBOM)
 3. scan stage   : OSV advisories for those pins (at HEAD also the real Trivy scan)
 4. all events are signed, verified and stitched by the normal pipeline
 5. every vulnerable dependency is backtracked to a commit and compared with
    `git blame --first-parent` on the pin line (independent attribution)

Baselines for attribution:
  last-manifest-commit : blame the most recent commit that touched the manifest
                         (what you get from "git log -1 -- requirements.txt")
  pickaxe-first        : oldest commit whose manifest diff mentions the package
                         (git log -G; finds when the *package* arrived, not the version)
  scanner-only         : Trivy/OSV output alone carries no commit -> 0 %

At HEAD, static reachability (tracegate.reach) is applied to measure how much
it shrinks the actionable (HIGH/CRITICAL) alert list.

Usage: python benchmarks/lineage_eval.py [--snapshots 12]
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tracegate.backtrack import origin_story  # noqa: E402
from tracegate.collector import Collector  # noqa: E402
from tracegate.data import data_root  # noqa: E402
from tracegate.enrich import actionable, enrich_static_reachability, enrich_warden  # noqa: E402
from tracegate.gitlineage import (  # noqa: E402
    _git,
    blame_introducers,
    commit_events,
    direct_deps_from_pip_compile,
    manifest_history,
    pickaxe_first_mention,
)
from tracegate.ingest import syft_json_to_build, trivy_json_to_scan  # noqa: E402
from tracegate.models import Severity, StageEvent  # noqa: E402
from tracegate.osv import OsvIndex  # noqa: E402
from tracegate.policy import evaluate  # noqa: E402
from tracegate.reach import app_imports, entrypoint_text, static_reachability  # noqa: E402
from tracegate.signing import HmacSigner, Verifier  # noqa: E402
from tracegate.warden import HeuristicWarden  # noqa: E402

REPOS = {  # name -> (manifest, source dirs)
    "healthchecks": ("requirements.txt", ["hc"]),
    "netbox": ("requirements.txt", ["netbox"]),
    "warehouse": ("requirements/main.txt", ["warehouse"]),
}
KEY = b"bench-key"


def build_events(repo: Path, manifest: str, hist, upto: int, pins: dict[str, str], osv: OsvIndex,
                 syft: Path | None, trivy: Path | None) -> list[StageEvent]:
    evs = commit_events(hist[: upto + 1], manifest)
    sha = hist[upto].sha
    if syft is not None:
        build = syft_json_to_build(syft, f"build-{sha[:8]}", commit=sha)
        build["sbom"]["artifacts"] = [a for a in build["sbom"]["artifacts"] if a["purl"].startswith("pkg:pypi/")]
    else:
        build = {"build_id": f"build-{sha[:8]}", "commit": sha, "tool": "manifest",
                 "sbom": {"artifacts": [{"name": n, "version": v} for n, v in pins.items()]}}
    evs.append(StageEvent("build", f"ci-{sha[:8]}", build))
    evs.append(StageEvent("scan", f"ci-{sha[:8]}", osv.scan_payload(pins.items())))
    if trivy is not None:
        evs.append(StageEvent("scan", f"ci-{sha[:8]}", trivy_json_to_scan(trivy)))
    return evs


def eval_repo(name: str, osv: OsvIndex, n_snap: int, warden: HeuristicWarden) -> dict | None:
    root = data_root()
    repo = root / "repos" / name
    manifest, srcs = REPOS[name]
    if not (repo / ".git").exists():
        print(f"skip {name}: not cloned")
        return None
    t0 = time.perf_counter()
    hist = manifest_history(repo, manifest)
    t_hist = time.perf_counter() - t0
    if not hist:
        return None
    idx = sorted({round(i * (len(hist) - 1) / max(1, n_snap - 1)) for i in range(n_snap)})
    signer, verifier = HmacSigner("bench", KEY), Verifier({"bench": KEY})
    rows = {"tracegate": [0, 0], "last-manifest-commit": [0, 0], "pickaxe-first": [0, 0]}
    disagreements, gate_ms, per_snapshot, reach_rows = [], [], [], []
    pick_cache: dict[str, str | None] = {}
    mods = app_imports([repo / s for s in srcs])  # HEAD sources, parsed once per repo
    ep = entrypoint_text(repo)
    head_stats = {}
    for k in idx:
        mc = hist[k]
        pins = mc.pins
        is_head = k == len(hist) - 1
        syft = root / "scans" / f"{name}.syft.json"
        trivy = root / "scans" / f"{name}.trivy.json"
        evs = build_events(repo, manifest, hist, k, pins, osv,
                           syft if is_head and syft.exists() else None,
                           trivy if is_head and trivy.exists() else None)
        envs = [signer.sign(e) for e in evs]
        t0 = time.perf_counter()
        res = Collector(verifier).collect(envs)
        enrich_warden(res, warden)
        dec = evaluate(res)
        gate_ms.append(1000 * (time.perf_counter() - t0))
        truth = blame_introducers(repo, manifest, mc.sha)
        vuln_pkgs = sorted({res.graph.nodes[f.node_id].attrs["name"].lower().replace("_", "-")
                            for f in res.graph.findings if f.source in ("osv", "trivy")})
        n_ok = 0
        for pkg in vuln_pkgs:
            if pkg not in truth:
                continue
            stories = origin_story(res.graph, pkg)
            got = next((s["introduced_by"]["sha"] for s in stories if s["introduced_by"]), None)
            want = truth[pkg]
            rows["tracegate"][0] += got == want
            rows["tracegate"][1] += 1
            n_ok += got == want
            if got != want and len(disagreements) < 15:
                disagreements.append({"snapshot": mc.sha[:10], "package": pkg, "tracegate": (got or "")[:10],
                                      "blame": want[:10],
                                      "blame_subject": _git(repo, "log", "-1", "--format=%s", want).strip()[:80]})
            rows["last-manifest-commit"][0] += mc.sha == want
            rows["last-manifest-commit"][1] += 1
            # first-parent history is linear, so the oldest mention reachable from HEAD is also
            # the oldest reachable from this snapshot (cached: pickaxe is slow on big histories)
            if pkg not in pick_cache:
                pick_cache[pkg] = pickaxe_first_mention(repo, manifest, pkg, hist[-1].sha)
            pk = pick_cache[pkg]
            rows["pickaxe-first"][0] += pk == want
            rows["pickaxe-first"][1] += 1
        per_snapshot.append({"sha": mc.sha[:10], "date": time.strftime("%Y-%m-%d", time.gmtime(mc.timestamp)),
                             "pins": len(pins), "vulnerable_pkgs": len(vuln_pkgs),
                             "findings": sum(f.source in ("osv", "trivy") for f in res.graph.findings),
                             "backtrack_correct": n_ok, "verdict": dec.verdict.value,
                             "graph": res.graph.stats()})
        # Static reachability. Only HEAD sources are checked out (blobless clone), so older
        # snapshots are analysed against HEAD's import set: an approximation, flagged in output.
        req_text = _git(repo, "show", f"{mc.sha}:{manifest}")
        rep = static_reachability(pins, [repo / s for s in srcs], repo, req_text, mods=mods, ep=ep)
        scan_f = [f for f in res.graph.findings if f.source in ("osv", "trivy")]
        hi = [f for f in scan_f if f.severity.rank >= Severity.HIGH.rank]
        enrich_static_reachability(res, rep)
        act = [f for f in actionable(scan_f)]
        after = evaluate(res)
        per_snapshot[-1].update({"high_plus": len(hi), "high_plus_actionable": len(act),
                                 "verdict_after_reachability": after.verdict.value,
                                 "warden_flags": [f.title for f in res.graph.findings if f.source == "warden"]})
        reach_rows.append((len(hi), len(act), [f"{f.cve} {res.graph.nodes[f.node_id].label}"
                                                for f in hi if f.reachable is False]))
        if is_head:
            direct = direct_deps_from_pip_compile(req_text)
            head_stats = {
                "sha": mc.sha[:12], "pins": len(pins),
                "reach_status_counts": {st: list(rep.status.values()).count(st)
                                        for st in ("imported", "entrypoint", "transitive", "unreached")},
                "unreached": sorted(d for d, st in rep.status.items() if st == "unreached"),
                "direct_deps": None if direct is None else len(direct),
                "direct_deps_marked_unreached": sorted(d for d in (direct or set())
                                                       if rep.status.get(d) == "unreached"),
                "trivy_findings": sum(f.source == "trivy" for f in res.graph.findings),
                "trivy_unmatched": len(res.unmatched),
            }
    acc = {k: {"correct": v[0], "total": v[1], "accuracy": round(v[0] / v[1], 4) if v[1] else None}
           for k, v in rows.items()}
    acc["scanner-only"] = {"correct": 0, "total": rows["tracegate"][1], "accuracy": 0.0}
    out = {"repo": name, "manifest": manifest, "manifest_commits": len(hist), "snapshots": len(idx),
           "history_walk_s": round(t_hist, 2), "gate_ms_median": round(statistics.median(gate_ms), 1),
           "gate_ms_max": round(max(gate_ms), 1), "attribution": acc, "disagreements": disagreements,
           "per_snapshot": per_snapshot, "head": head_stats,
           "reachability": {"high_plus_total": sum(r[0] for r in reach_rows),
                            "actionable_total": sum(r[1] for r in reach_rows),
                            "downgraded_examples": sorted({x for r in reach_rows for x in r[2]})[:20],
                            "note": "historical snapshots analysed against HEAD sources"}}
    print(f"[{name}] commits={len(hist)} snapshots={len(idx)} " +
          " ".join(f"{k}={v['accuracy']}" for k, v in acc.items()) +
          f" gate_ms~{out['gate_ms_median']} high+={out['reachability']['high_plus_total']}"
          f"->actionable={out['reachability']['actionable_total']}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshots", type=int, default=12)
    ap.add_argument("--repos", nargs="*", default=list(REPOS))
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "results"))
    a = ap.parse_args()
    zp = data_root() / "osv/PyPI-all.zip"
    if not zp.exists():
        sys.exit("need osv/PyPI-all.zip (python scripts/download_data.py osv)")
    t0 = time.perf_counter()
    osv = OsvIndex.from_zip(zp)
    print(f"OSV PyPI index: {osv.n_records} records, {len(osv.by_name)} packages, "
          f"{len(osv.mal)} malicious names ({time.perf_counter() - t0:.1f}s)")
    from tracegate.data import top_pypi
    warden = HeuristicWarden(popular=top_pypi(5000), osv=osv)
    results = [r for r in (eval_repo(n, osv, a.snapshots, warden) for n in a.repos) if r]
    tot = {}
    for r in results:
        for k, v in r["attribution"].items():
            c, t = tot.get(k, (0, 0))
            tot[k] = (c + v["correct"], t + v["total"])
    summary = {k: {"correct": c, "total": t, "accuracy": round(c / t, 4) if t else None} for k, (c, t) in tot.items()}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "lineage_real_repos.json").write_text(json.dumps({"summary": summary, "repos": results}, indent=1))
    print("TOTAL", json.dumps(summary))


if __name__ == "__main__":
    main()
