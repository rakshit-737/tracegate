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
  pickaxe-exact-pin    : `git log --first-parent -1 -S'<exact pin line>' <snapshot> -- manifest`,
                         the strongest one-liner a practitioner would write (near-identical to blame)
  scanner-only         : Trivy/OSV output alone carries no commit -> n/a (not measured)

At HEAD, static reachability (tracegate.reach) is applied to measure how much
it shrinks the actionable (HIGH/CRITICAL) alert list.

Usage: python benchmarks/lineage_eval.py [--snapshots 12]
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bump_oracle import METHODS, cluster_bootstrap, oracle_repo, run_meta  # noqa: E402

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
    materialize,
    pickaxe_first_mention,
)
from tracegate.ids import normalize_name, purl  # noqa: E402
from tracegate.ingest import syft_json_to_build, trivy_json_to_scan  # noqa: E402
from tracegate.lockfiles import ecosystem_for, pin_lines  # noqa: E402
from tracegate.models import Severity, StageEvent  # noqa: E402
from tracegate.osv import OsvIndex  # noqa: E402
from tracegate.policy import evaluate  # noqa: E402
from tracegate.reach import ENTRYPOINT_FILES, app_imports, entrypoint_text, static_reachability  # noqa: E402
from tracegate.signing import HmacSigner, Verifier  # noqa: E402
from tracegate.warden import HeuristicWarden  # noqa: E402

REPOS = {  # name -> (manifest, source dirs)
    "healthchecks": ("requirements.txt", ["hc"]),
    "netbox": ("requirements.txt", ["netbox"]),
    "warehouse": ("requirements/main.txt", ["warehouse"]),
    # v1.1: Go / Cargo / yarn / pnpm lock files (attribution only; reachability is Python-only)
    "caddy": ("go.sum", []),
    "hugo": ("go.mod", []),
    "ripgrep": ("Cargo.lock", []),
    "bat": ("Cargo.lock", []),
    "alacritty": ("Cargo.lock", []),
    "excalidraw": ("yarn.lock", []),
    "mastodon": ("yarn.lock", []),
    "vue-core": ("pnpm-lock.yaml", []),
}
OSV_ZIP = {"pypi": "PyPI", "npm": "npm", "golang": "Go", "cargo": "crates.io"}
KEY = b"bench-key"


def build_events(repo: Path, manifest: str, hist, upto: int, pins: dict[str, str], osv: OsvIndex,
                 syft: Path | None, trivy: Path | None) -> list[StageEvent]:
    evs = commit_events(hist[: upto + 1], manifest)
    sha = hist[upto].sha
    eco = ecosystem_for(manifest)
    if syft is not None:
        build = syft_json_to_build(syft, f"build-{sha[:8]}", commit=sha)
        build["sbom"]["artifacts"] = [a for a in build["sbom"]["artifacts"] if a["purl"].startswith("pkg:pypi/")]
    else:
        build = {"build_id": f"build-{sha[:8]}", "commit": sha, "tool": "manifest",
                 "sbom": {"artifacts": [{"name": n, "version": v, "purl": purl(n, v, eco)} for n, v in pins.items()]}}
    evs.append(StageEvent("build", f"ci-{sha[:8]}", build))
    evs.append(StageEvent("scan", f"ci-{sha[:8]}", osv.scan_payload(pins.items())))
    if trivy is not None:
        evs.append(StageEvent("scan", f"ci-{sha[:8]}", trivy_json_to_scan(trivy)))
    return evs


def eval_repo(name: str, osvs: dict[str, OsvIndex], n_snap: int, warden,
              per_snapshot_sources: bool = False) -> dict | None:
    root = data_root()
    repo = root / "repos" / name
    manifest, srcs = REPOS[name]
    eco = ecosystem_for(manifest)
    osv = osvs[eco]
    reach_on = eco == "pypi" and bool(srcs)

    def key(n: str) -> str:
        return normalize_name(n, eco).lower()
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
    rows = {"tracegate": [0, 0], "last-manifest-commit": [0, 0], "pickaxe-first": [0, 0],
            "pickaxe-exact-pin": [0, 0]}
    disagreements, gate_ms, per_snapshot, reach_rows = [], [], [], []
    pick_cache: dict[str, str | None] = {}
    strings: set[str] = set()
    if reach_on:
        mods = app_imports([repo / s for s in srcs], strings)  # HEAD sources, parsed once per repo
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
        truth = {key(n): s for n, s in blame_introducers(repo, mc.path or manifest, mc.sha).items()}
        vuln_pkgs = sorted({key(res.graph.nodes[f.node_id].attrs["name"])
                            for f in res.graph.findings if f.source in ("osv", "trivy")})
        n_ok = 0
        snap_lines = _git(repo, "show", f"{mc.sha}:{mc.path or manifest}").splitlines()
        line_of = {key(n): v[1] for n, v in pin_lines(mc.path or manifest, chr(10).join(snap_lines)).items()}
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
            li = line_of.get(pkg)
            tok = snap_lines[li].strip() if li is not None and li < len(snap_lines) else ""
            ex = _git(repo, "log", "--first-parent", "-1", "--format=%H", f"-S{tok}", mc.sha, "--",
                      mc.path or manifest).strip() if tok else ""
            rows["pickaxe-exact-pin"][0] += ex == want
            rows["pickaxe-exact-pin"][1] += 1
        per_snapshot.append({"sha": mc.sha[:10], "date": time.strftime("%Y-%m-%d", time.gmtime(mc.timestamp)),
                             "pins": len(pins), "vulnerable_pkgs": len(vuln_pkgs),
                             "findings": sum(f.source in ("osv", "trivy") for f in res.graph.findings),
                             "backtrack_correct": n_ok, "verdict": dec.verdict.value, "coverage": round(res.coverage, 3),
                             "graph": res.graph.stats()})
        if not reach_on:
            per_snapshot[-1]["warden_flags"] = [f.title for f in res.graph.findings if f.source == "warden"]
            continue
        # Static reachability. Only HEAD sources are checked out (blobless clone), so older
        # snapshots are analysed against HEAD's import set: an approximation, flagged in output.
        req_text = _git(repo, "show", f"{mc.sha}:{mc.path or manifest}")
        if per_snapshot_sources and not is_head:
            # Check out the sources that actually shipped with this snapshot (ADR 0004 gap).
            with tempfile.TemporaryDirectory() as td:
                materialize(repo, mc.sha, srcs, td, anywhere=ENTRYPOINT_FILES)
                s_strings: set[str] = set()
                s_mods = app_imports([Path(td) / s for s in srcs], s_strings)
                rep = static_reachability(pins, [Path(td) / s for s in srcs], Path(td), req_text,
                                          mods=s_mods, ep=entrypoint_text(Path(td)), strings=s_strings)
        else:
            rep = static_reachability(pins, [repo / s for s in srcs], repo, req_text, mods=mods, ep=ep,
                                      strings=strings)
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
                                        for st in ("imported", "entrypoint", "referenced", "transitive", "unreached")},
                "unreached": sorted(d for d, st in rep.status.items() if st == "unreached"),
                "direct_deps": None if direct is None else len(direct),
                "direct_deps_marked_unreached": sorted(d for d in (direct or set())
                                                       if rep.status.get(d) == "unreached"),
                "trivy_findings": sum(f.source == "trivy" for f in res.graph.findings),
                "trivy_unmatched": len(res.unmatched),
            }
    acc = {k: {"correct": v[0], "total": v[1], "accuracy": round(v[0] / v[1], 4) if v[1] else None}
           for k, v in rows.items()}
    acc["scanner-only"] = {"correct": None, "total": rows["tracegate"][1], "accuracy": None,
                           "note": "n/a: scanner output carries no commit"}
    out = {"repo": name, "manifest": manifest, "ecosystem": eco, "manifest_commits": len(hist), "snapshots": len(idx),
           "history_walk_s": round(t_hist, 2), "gate_ms_median": round(statistics.median(gate_ms), 1),
           "gate_ms_max": round(max(gate_ms), 1), "attribution": acc, "disagreements": disagreements,
           "per_snapshot": per_snapshot, "head": head_stats,
           "reachability": {"high_plus_total": sum(r[0] for r in reach_rows),
                            "actionable_total": sum(r[1] for r in reach_rows),
                            "downgraded_examples": sorted({x for r in reach_rows for x in r[2]})[:20],
                            "note": ("each snapshot analysed against its own materialized sources"
                                     if per_snapshot_sources else
                                     "historical snapshots analysed against HEAD sources")}
           if reach_on else None}
    print(f"[{name}] commits={len(hist)} snapshots={len(idx)} " +
          " ".join(f"{k}={v['accuracy']}" for k, v in acc.items()) +
          f" gate_ms~{out['gate_ms_median']}" + (f" high+={out['reachability']['high_plus_total']}"
                                                  f"->actionable={out['reachability']['actionable_total']}"
                                                  if reach_on else ""))
    return out


def wilson(c: int, n: int, z: float = 1.96) -> list[float] | None:
    """Wilson score 95% interval (ignores clustering of pins within repos)."""
    if not n:
        return None
    p = c / n
    d = 1 + z * z / n
    m = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(m - h, 4), round(m + h, 4)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshots", type=int, default=12)
    ap.add_argument("--repos", nargs="*", default=list(REPOS))
    ap.add_argument("--materialize", action="store_true",
                    help="analyse each historical snapshot against its own sources (slower)")
    ap.add_argument("--oracle", action="store_true",
                    help="also score against single-package bot-bump commits (independent oracle)")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "results"))
    a = ap.parse_args()
    ecos = sorted({ecosystem_for(REPOS[n][0]) for n in a.repos})
    osvs: dict[str, OsvIndex] = {}
    for eco in ecos:
        zp = data_root() / f"osv/{OSV_ZIP[eco]}-all.zip"
        if not zp.exists():
            sys.exit(f"need {zp.name} (python scripts/download_data.py osv)")
        t0 = time.perf_counter()
        osvs[eco] = OsvIndex.from_zip(zp, eco)
        print(f"OSV {eco} index: {osvs[eco].n_records} records, {len(osvs[eco].by_name)} packages, "
              f"{len(osvs[eco].mal)} malicious names ({time.perf_counter() - t0:.1f}s)")
    from tracegate.data import top_npm, top_pypi
    from tracegate.warden import MultiWarden
    pop = {"pypi": top_pypi(5000) if "pypi" in osvs else None, "npm": top_npm(5000) if "npm" in osvs else None}
    warden = MultiWarden({e: HeuristicWarden(popular=pop.get(e) or [], osv=o) for e, o in osvs.items()})
    results = [r for r in (eval_repo(n, osvs, a.snapshots, warden, a.materialize) for n in a.repos) if r]
    tot = {}
    for r in results:
        for k, v in r["attribution"].items():
            if v["correct"] is None:
                continue
            c, t = tot.get(k, (0, 0))
            tot[k] = (c + v["correct"], t + v["total"])
    summary = {k: {"correct": c, "total": t, "accuracy": round(c / t, 4) if t else None,
                   "wilson95": wilson(c, t),
                   "repo_cluster_bootstrap95": cluster_bootstrap(
                       [(r["attribution"][k]["correct"], r["attribution"][k]["total"]) for r in results
                        if r["attribution"].get(k, {}).get("correct") is not None])}
               for k, (c, t) in tot.items()}
    by_eco: dict[str, dict] = {}
    for r in results:
        for k, v in r["attribution"].items():
            if v["correct"] is None:
                continue
            e = by_eco.setdefault(r["ecosystem"], {}).setdefault(k, [0, 0])
            e[0] += v["correct"]
            e[1] += v["total"]
    summary_by_eco = {e: {k: {"correct": c, "total": t, "accuracy": round(c / t, 4) if t else None}
                          for k, (c, t) in d.items()} for e, d in by_eco.items()}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if not a.materialize:
        for r in results:
            if r.get("reachability"):
                r["reachability"]["headline"] = False
                r["reachability"]["caveat"] = ("HEAD-sources mode: older snapshots are checked against today's "
                                               "imports; superseded by lineage_real_repos_materialized.json")
    if a.oracle:
        orc = [o for o in (oracle_repo(data_root() / "repos" / n, REPOS[n][0]) for n in a.repos) if o]
        pooled: dict[str, dict] = {}
        for m in METHODS:
            for lab in ("at_bump", "later_snapshot"):
                pr = [(o["scores"][m][lab]["correct"], o["scores"][m][lab]["total"]) for o in orc]
                c, t = sum(x for x, _ in pr), sum(y for _, y in pr)
                pooled.setdefault(m, {})[lab] = {"correct": c, "total": t, "accuracy": round(c / t, 4) if t else None,
                                                 "wilson95": wilson(c, t), "repo_cluster_bootstrap95": cluster_bootstrap(pr)}
        (out / "lineage_bot_bump_oracle.json").write_text(json.dumps({
            **run_meta(),
            "oracle": ("bot-authored single-package bump commits; label = the bump commit, read from the commit "
                       "subject, independent of the pin parser and of git blame"),
            "ablation": "tracegate = version-diff attribution; blame = line attribution of the same pin",
            "pooled": pooled, "repos": orc}, indent=1))
        print("ORACLE", json.dumps(pooled))
    (out / ("lineage_real_repos_materialized.json" if a.materialize else "lineage_real_repos.json")).write_text(json.dumps({**run_meta(), "summary": summary, "summary_by_ecosystem": summary_by_eco,
                                "mode": "materialized per-snapshot sources" if a.materialize else "HEAD sources",
                                "materialize": a.materialize,
                                "repos": results}, indent=1))
    print("TOTAL", json.dumps(summary))


if __name__ == "__main__":
    main()
