#!/usr/bin/env python3
"""Real-repository benchmark: finding -> commit backtracking + reachability triage.

For each real OSS repo (cloned by scripts/download_data.py repos) and a set of
snapshots along its first-parent history:

 1. commit stage : every manifest-changing commit up to the snapshot (gitlineage)
 2. build stage  : the snapshot's pinned (name, version) pairs (at HEAD: the real Syft SBOM if present)
 3. scan stage   : OSV advisories for those pins (at HEAD also the real Trivy scan if present)
 4. all events are signed, verified and stitched by the normal pipeline
 5. every vulnerable (name, version) pin is backtracked to a commit and compared with
    `git blame --first-parent` on that pin's version line (line attribution; it shares the
    lock-file reader, so agreement is not correctness)

Lock files that hold several versions of one name contribute every version. `--single-version`
reproduces the older one-version-per-name readers (first entry wins) on the same data, so the
effect of that fix can be read off one workflow run.

Baselines for attribution:
  last-manifest-commit      : the most recent commit that touched the manifest (`git log -1 -- file`)
  pickaxe-first             : oldest commit whose manifest diff mentions the package name (git log -G)
  pickaxe-package-specific  : `git log --first-parent -1 -S'<package line(s) .. version line>'`, e.g.
                              the two-line `name = "x"` / `version = "y"` string of a Cargo.lock entry,
                              a yarn.lock block header plus its version line, the package-lock
                              `"node_modules/x": {` key plus version; one-line pins (pip, Go, pnpm keys)
                              are already package-specific
  pickaxe-version-line      : `git log --first-parent -1 -S'<version line>'`; not package-specific in
                              Cargo.lock / yarn.lock / package-lock.json (`version = "1.0.0"` is shared
                              by every crate at 1.0.0)
  scanner-only              : Trivy/OSV output alone carries no commit -> n/a (not measured)

Python repos also get static reachability (tracegate.reach) to measure how much it shrinks the
actionable (HIGH/CRITICAL) alert list; `--materialize` analyses each snapshot against its own sources
and writes every downgraded finding with audit evidence.

Usage: python benchmarks/lineage_eval.py [--snapshots 12] [--oracle] [--single-version] [--materialize]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from bump_oracle import oracle_repo, oracle_report  # noqa: E402
from stats import (  # noqa: E402
    cluster_bootstrap,
    paired_cluster_bootstrap,
    proportion,
    run_meta,
    table2x2,
)
from stats import wilson as wilson  # noqa: E402,F401  (kept importable from here)

from tracegate.collector import Collector  # noqa: E402
from tracegate.data import data_root  # noqa: E402
from tracegate.enrich import actionable, enrich_static_reachability, enrich_warden  # noqa: E402
from tracegate.gitlineage import (  # noqa: E402
    _git,
    blame_entry_introducers,
    commit_events,
    direct_deps_from_pip_compile,
    manifest_history,
    materialize,
    pickaxe_exact,
    pickaxe_first_mention,
)
from tracegate.ids import normalize_name, purl  # noqa: E402
from tracegate.ingest import syft_json_to_build, trivy_json_to_scan  # noqa: E402
from tracegate.lockfiles import ecosystem_for, pin_entries, pin_lines  # noqa: E402
from tracegate.models import NodeKind, Severity, StageEvent  # noqa: E402
from tracegate.osv import OsvIndex  # noqa: E402
from tracegate.policy import evaluate  # noqa: E402
from tracegate.reach import (  # noqa: E402
    ENTRYPOINT_FILES,
    app_imports,
    entrypoint_text,
    static_reachability,
    via_graph,
)
from tracegate.signing import HmacSigner, Verifier  # noqa: E402
from tracegate.warden import HeuristicWarden  # noqa: E402

REPOS = {  # name -> (manifest, source dirs)
    "healthchecks": ("requirements.txt", ["hc"]),
    "netbox": ("requirements.txt", ["netbox"]),
    "warehouse": ("requirements/main.txt", ["warehouse"]),
    # Go / Cargo / yarn / pnpm lock files (attribution only; reachability is Python-only)
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
METHODS = ("tracegate", "last-manifest-commit", "pickaxe-first", "pickaxe-package-specific", "pickaxe-version-line")
PAIRED = ("pickaxe-package-specific", "pickaxe-version-line")


def build_events(repo: Path, manifest: str, hist, upto: int, pairs: list[tuple[str, str]], osv: OsvIndex,
                 syft: Path | None, trivy: Path | None) -> list[StageEvent]:
    evs = commit_events(hist[: upto + 1], manifest)
    sha = hist[upto].sha
    eco = ecosystem_for(manifest)
    if syft is not None:
        build = syft_json_to_build(syft, f"build-{sha[:8]}", commit=sha)
        build["sbom"]["artifacts"] = [a for a in build["sbom"]["artifacts"] if a["purl"].startswith("pkg:pypi/")]
    else:
        build = {"build_id": f"build-{sha[:8]}", "commit": sha, "tool": "manifest",
                 "sbom": {"artifacts": [{"name": n, "version": v, "purl": purl(n, v, eco)} for n, v in pairs]}}
    evs.append(StageEvent("build", f"ci-{sha[:8]}", build))
    evs.append(StageEvent("scan", f"ci-{sha[:8]}", osv.scan_payload(pairs)))
    if trivy is not None:
        evs.append(StageEvent("scan", f"ci-{sha[:8]}", trivy_json_to_scan(trivy)))
    return evs


def _sha256(p: Path) -> str | None:
    if not p.exists():
        return None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def multi_version_counts(path: str, text: str) -> dict:
    """How many lock-file entries the one-version-per-name readers drop at this snapshot."""
    from collections import Counter
    ents = pin_entries(path, text) or []
    per_name = Counter(e.name for e in ents)
    names = set(per_name)
    multi = {n for n, c in per_name.items() if c > 1}
    return {"entries": len(ents), "names": len(names), "entries_dropped_by_single_version": len(ents) - len(names),
            "share_dropped": round((len(ents) - len(names)) / len(ents), 4) if ents else None,
            "entries_of_multi_version_names": sum(1 for e in ents if e.name in multi),
            "share_of_multi_version_names": round(sum(1 for e in ents if e.name in multi) / len(ents), 4) if ents else None}


def eval_repo(name: str, osvs: dict[str, OsvIndex], n_snap: int, warden,
              per_snapshot_sources: bool = False, multi_version: bool = True) -> dict | None:
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
    hist = manifest_history(repo, manifest, multi_version=multi_version)
    t_hist = time.perf_counter() - t0
    if not hist:
        return None
    idx = sorted({round(i * (len(hist) - 1) / max(1, n_snap - 1)) for i in range(n_snap)})
    signer, verifier = HmacSigner("bench", KEY), Verifier({"bench": KEY})
    rows = {m: [0, 0] for m in METHODS}
    pair_ok: dict[str, list[tuple[bool, bool]]] = {m: [] for m in PAIRED}  # (tracegate ok, baseline ok)
    disagreements, gate_ms, per_snapshot, reach_rows, downgraded = [], [], [], [], []
    pick_cache: dict[str, str | None] = {}
    strings: set[str] = set()
    if reach_on:
        mods = app_imports([repo / s for s in srcs], strings)  # HEAD sources, parsed once per repo
        ep = entrypoint_text(repo)
        head_req = _git(repo, "show", f"{hist[-1].sha}:{hist[-1].path or manifest}")
        head_via = via_graph(head_req)
    head_stats = {}
    for k in idx:
        mc = hist[k]
        path = mc.path or manifest
        pairs = sorted(mc.entries)
        pins = mc.pins
        is_head = k == len(hist) - 1
        syft = root / "scans" / f"{name}.syft.json"
        trivy = root / "scans" / f"{name}.trivy.json"
        evs = build_events(repo, manifest, hist, k, pairs, osv,
                           syft if is_head and syft.exists() else None,
                           trivy if is_head and trivy.exists() else None)
        envs = [signer.sign(e) for e in evs]
        t0 = time.perf_counter()
        res = Collector(verifier).collect(envs)
        enrich_warden(res, warden)
        dec = evaluate(res)
        gate_ms.append(1000 * (time.perf_counter() - t0))
        truth = {(key(n), v): s for (n, v), s in
                 blame_entry_introducers(repo, path, mc.sha, multi_version=multi_version).items()}
        g = res.graph
        vuln: dict[tuple[str, str], str] = {}  # (name, version) -> dependency node id
        for f in g.findings:
            if f.source in ("osv", "trivy"):
                node = g.nodes[f.node_id]
                vuln.setdefault((key(node.attrs["name"]), node.attrs["version"]), f.node_id)
        n_ok = 0
        text = _git(repo, "show", f"{mc.sha}:{path}")
        snap_lines = text.splitlines()
        if multi_version:
            ent_of = {(key(e.name), e.version): e for e in pin_entries(path, text) or []}
        else:
            ent_of = {(key(n), v): (n, v, i) for n, (v, i) in (pin_lines(path, text) or {}).items()}
        for (pk, ver), did in sorted(vuln.items()):
            if (pk, ver) not in truth:
                continue
            upath = g.upstream_path(did, NodeKind.COMMIT)
            got = g.nodes[upath[0]].attrs["sha"] if upath else None
            want = truth[(pk, ver)]
            ok_tg = got == want
            rows["tracegate"][0] += ok_tg
            rows["tracegate"][1] += 1
            n_ok += ok_tg
            rows["last-manifest-commit"][0] += mc.sha == want
            rows["last-manifest-commit"][1] += 1
            # first-parent history is linear, so the oldest mention reachable from HEAD is also
            # the oldest reachable from this snapshot (cached: pickaxe is slow on big histories)
            if pk not in pick_cache:
                pick_cache[pk] = pickaxe_first_mention(repo, manifest, pk, hist[-1].sha)
            rows["pickaxe-first"][0] += pick_cache[pk] == want
            rows["pickaxe-first"][1] += 1
            if not multi_version:  # the before-fix run only needs tracegate vs blame
                if not ok_tg:
                    disagreements.append({"snapshot": mc.sha[:12], "package": pk, "version": ver,
                                          "blame": want[:12], "tracegate": (got or "")[:12]})
                continue
            e = ent_of.get((pk, ver))
            if multi_version and e is not None:
                li, kl = e.line, min(e.key_line, e.line)
            elif e is not None:
                li = kl = e[2]
            else:
                li = kl = None
            tok_line = snap_lines[li].strip() if li is not None and li < len(snap_lines) else ""
            tok_pkg = "\n".join(snap_lines[kl:li + 1]).strip() if li is not None and li < len(snap_lines) else ""
            px_line = pickaxe_exact(repo, path, tok_line, mc.sha)
            px_pkg = px_line if tok_pkg == tok_line else pickaxe_exact(repo, path, tok_pkg, mc.sha)
            for m, ans in (("pickaxe-version-line", px_line), ("pickaxe-package-specific", px_pkg)):
                rows[m][0] += ans == want
                rows[m][1] += 1
                pair_ok[m].append((ok_tg, ans == want))
            if not ok_tg:
                disagreements.append({"snapshot": mc.sha[:12], "package": pk, "version": ver,
                                      "blame": want[:12], "tracegate": (got or "")[:12],
                                      "pickaxe_package_specific": (px_pkg or "")[:12],
                                      "pickaxe_version_line": (px_line or "")[:12],
                                      "blame_subject": _git(repo, "log", "-1", "--format=%s", want).strip()[:80],
                                      "tracegate_subject": (_git(repo, "log", "-1", "--format=%s", got).strip()[:80]
                                                            if got else None)})
        per_snapshot.append({"sha": mc.sha[:10], "date": time.strftime("%Y-%m-%d", time.gmtime(mc.timestamp)),
                             "pins": len(pairs), "names": len(pins), "vulnerable_pins": len(vuln),
                             "findings": sum(f.source in ("osv", "trivy") for f in g.findings),
                             "backtrack_correct": n_ok, "verdict": dec.verdict.value, "coverage": round(res.coverage, 3),
                             "graph": g.stats()})
        if not reach_on:
            per_snapshot[-1]["warden_flags"] = [f.title for f in g.findings if f.source == "warden"]
            continue
        # Static reachability. Mode 1 analyses every snapshot against HEAD sources (an approximation,
        # flagged in the output); --materialize checks out the sources that shipped with each snapshot.
        req_text = text
        if per_snapshot_sources and not is_head:
            with tempfile.TemporaryDirectory() as td:
                materialize(repo, mc.sha, srcs, td, anywhere=ENTRYPOINT_FILES)
                s_strings: set[str] = set()
                s_mods = app_imports([Path(td) / s for s in srcs], s_strings)
                rep = static_reachability(pins, [Path(td) / s for s in srcs], Path(td), req_text,
                                          mods=s_mods, ep=entrypoint_text(Path(td)), strings=s_strings)
        else:
            rep = static_reachability(pins, [repo / s for s in srcs], repo, req_text, mods=mods, ep=ep,
                                      strings=strings)
        scan_f = [f for f in g.findings if f.source in ("osv", "trivy")]
        hi = [f for f in scan_f if f.severity.rank >= Severity.HIGH.rank]
        enrich_static_reachability(res, rep)
        act = [f for f in actionable(scan_f)]
        after = evaluate(res)
        snap_via = via_graph(req_text)
        for f in hi:
            if f.reachable is not False:
                continue
            node = g.nodes[f.node_id]
            dist = normalize_name(node.attrs["name"])
            par_snap = sorted(snap_via.get(dist, ()))
            par_head = sorted(head_via.get(dist, ()))
            downgraded.append({"snapshot": mc.sha[:12], "date": per_snapshot[-1]["date"], "cve": f.cve,
                               "pin": node.label, "severity": f.severity.value, "status": rep.status.get(dist),
                               "evidence": rep.evidence.get(dist),
                               "via_at_snapshot": {p: rep.status.get(p) for p in par_snap},
                               "via_at_head": {p: rep.status.get(p) for p in par_head}})
        per_snapshot[-1].update({"high_plus": len(hi), "high_plus_actionable": len(act),
                                 "verdict_after_reachability": after.verdict.value,
                                 "warden_flags": [f.title for f in g.findings if f.source == "warden"]})
        reach_rows.append((len(hi), len(act)))
        if is_head:
            direct = direct_deps_from_pip_compile(req_text)
            head_stats = {
                "pins": len(pins),
                "reach_status_counts": {st: list(rep.status.values()).count(st)
                                        for st in ("imported", "entrypoint", "referenced", "transitive", "unreached", "unknown")},
                "unreached": sorted(d for d, st in rep.status.items() if st == "unreached"),
                "direct_deps": None if direct is None else len(direct),
                "direct_deps_marked_unreached": sorted(d for d in (direct or set())
                                                       if rep.status.get(d) == "unreached"),
                "trivy_findings": sum(f.source == "trivy" for f in g.findings),
                "trivy_unmatched": len(res.unmatched),
            }
    acc = {m: {"correct": c, "total": t, "accuracy": round(c / t, 4) if t else None} for m, (c, t) in rows.items()
           if t or m in ("tracegate", "last-manifest-commit", "pickaxe-first")}
    acc["scanner-only"] = {"correct": None, "total": rows["tracegate"][1], "accuracy": None,
                           "note": "n/a: scanner output carries no commit"}
    head_sha = _git(repo, "rev-parse", "HEAD").strip()
    head_text = _git(repo, "show", f"{hist[-1].sha}:{hist[-1].path or manifest}")
    out = {"repo": name, "manifest": manifest, "ecosystem": eco, "multi_version": multi_version,
           "repo_head": head_sha, "osv_dump": f"osv/{OSV_ZIP[eco]}-all.zip",
           "osv_dump_sha256": _sha256(root / f"osv/{OSV_ZIP[eco]}-all.zip"),
           "manifest_commits": len(hist), "snapshots": len(idx),
           "history_walk_s": round(t_hist, 2), "gate_ms_median": round(statistics.median(gate_ms), 1),
           "gate_ms_max": round(max(gate_ms), 1), "attribution": acc,
           "tracegate_vs": {m: table2x2(pair_ok[m]) for m in PAIRED if pair_ok[m]},
           "multi_version_at_head": multi_version_counts(hist[-1].path or manifest, head_text),
           "disagreements": disagreements[:3000], "disagreements_total": len(disagreements),
           "per_snapshot": per_snapshot, "head": head_stats,
           "reachability": {"high_plus_total": sum(r[0] for r in reach_rows),
                            "actionable_total": sum(r[1] for r in reach_rows),
                            "downgraded_total": len(downgraded),
                            "downgraded": downgraded,
                            "note": ("each snapshot analysed against its own materialized sources"
                                     if per_snapshot_sources else
                                     "historical snapshots analysed against HEAD sources")}
           if reach_on else None}
    print(f"[{name}] multi_version={multi_version} commits={len(hist)} snapshots={len(idx)} " +
          " ".join(f"{k}={v['accuracy']}" for k, v in acc.items()) +
          f" gate_ms~{out['gate_ms_median']}" + (f" high+={out['reachability']['high_plus_total']}"
                                                  f"->actionable={out['reachability']['actionable_total']}"
                                                  if reach_on else ""), flush=True)
    return out


def summarise(results: list[dict]) -> tuple[dict, dict]:
    """Pooled and per-ecosystem accuracy with Wilson, exact and repo-clustered intervals, plus paired tests."""
    def block(rs: list[dict]) -> dict:
        out: dict = {}
        for m in METHODS:
            per = [(r["attribution"][m]["correct"], r["attribution"][m]["total"]) for r in rs if m in r["attribution"]]
            c, t = sum(a for a, _ in per), sum(b for _, b in per)
            if not t:
                continue
            out[m] = {**proportion(c, t), "repo_cluster_bootstrap95": cluster_bootstrap(per),
                      "per_repo_range": [min(a / b for a, b in per if b), max(a / b for a, b in per if b)]}
        for m in PAIRED:
            if not all(m in r["tracegate_vs"] for r in rs) or not rs:
                continue
            agg = {k: sum(r["tracegate_vs"][m][k] for r in rs) for k in ("both", "only_a", "only_b", "neither")}
            agg.update(table2x2([(True, True)] * agg["both"] + [(True, False)] * agg["only_a"]
                                + [(False, True)] * agg["only_b"] + [(False, False)] * agg["neither"]))
            n_pairs = sum(agg[k] for k in ("both", "only_a", "only_b", "neither"))
            agg["accuracy_difference"] = round((agg["only_a"] - agg["only_b"]) / n_pairs, 4) if n_pairs else None
            agg["accuracy_difference_repo_cluster_bootstrap95"] = paired_cluster_bootstrap(
                [(r["attribution"]["tracegate"]["correct"], r["attribution"][m]["correct"],
                  r["attribution"]["tracegate"]["total"]) for r in rs])
            out.setdefault("tracegate_vs", {})[m] = agg
        return out
    by_eco = {}
    for e in sorted({r["ecosystem"] for r in results}):
        by_eco[e] = block([r for r in results if r["ecosystem"] == e])
    return block(results), by_eco


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--snapshots", type=int, default=12)
    ap.add_argument("--repos", nargs="*", default=list(REPOS))
    ap.add_argument("--materialize", action="store_true",
                    help="analyse each historical snapshot against its own sources (slower)")
    ap.add_argument("--oracle", action="store_true",
                    help="also score against the bot-bump oracle (results/lineage_bot_bump_oracle.json)")
    ap.add_argument("--oracle-only", action="store_true", help="run only the oracle")
    ap.add_argument("--single-version", action="store_true",
                    help="one version per package name (the readers before the multi-version fix); "
                         "writes lineage_real_repos_single_version.json")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "results"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    heads = {n: (_git(data_root() / "repos" / n, "rev-parse", "HEAD").strip()
                 if (data_root() / "repos" / n / ".git").exists() else None) for n in a.repos}
    if a.oracle or a.oracle_only:
        orc = [o for o in (oracle_repo(data_root() / "repos" / n, REPOS[n][0]) for n in a.repos) if o]
        for o in orc:
            o["repo_head"] = heads.get(o["repo"])
        (out / "lineage_bot_bump_oracle.json").write_text(json.dumps({**run_meta(), **oracle_report(orc)}, indent=1))
        print("ORACLE", json.dumps({s: {m: d.get("later_snapshot", d.get("at_bump")) for m, d in v.items()
                                        if m in ("tracegate", "blame")}
                                    for s, v in oracle_report(orc)["pooled"].items()}), flush=True)
        if a.oracle_only:
            return
    ecos = sorted({ecosystem_for(REPOS[n][0]) for n in a.repos})
    osvs: dict[str, OsvIndex] = {}
    for eco in ecos:
        zp = data_root() / f"osv/{OSV_ZIP[eco]}-all.zip"
        if not zp.exists():
            sys.exit(f"need {zp.name} (python scripts/download_data.py osv)")
        t0 = time.perf_counter()
        osvs[eco] = OsvIndex.from_zip(zp, eco)
        print(f"OSV {eco} index: {osvs[eco].n_records} records, {len(osvs[eco].by_name)} packages, "
              f"{len(osvs[eco].mal)} malicious names ({time.perf_counter() - t0:.1f}s)", flush=True)
    from tracegate.data import top_npm, top_pypi
    from tracegate.warden import MultiWarden
    pop = {"pypi": top_pypi(5000) if "pypi" in osvs else None, "npm": top_npm(5000) if "npm" in osvs else None}
    warden = MultiWarden({e: HeuristicWarden(popular=pop.get(e) or [], osv=o) for e, o in osvs.items()})
    results = [r for r in (eval_repo(n, osvs, a.snapshots, warden, a.materialize, not a.single_version)
                           for n in a.repos) if r]
    summary, summary_by_eco = summarise(results)
    if not a.materialize:
        for r in results:
            if r.get("reachability"):
                r["reachability"]["headline"] = False
                r["reachability"]["caveat"] = ("HEAD-sources mode: older snapshots are checked against today's "
                                               "imports; superseded by lineage_real_repos_materialized.json")
    if a.materialize:
        fname = "lineage_real_repos_materialized.json"
    elif a.single_version:
        fname = "lineage_real_repos_single_version.json"
    else:
        fname = "lineage_real_repos.json"
    reach_total = None
    if any(r.get("reachability") for r in results):
        hi = sum(r["reachability"]["high_plus_total"] for r in results if r.get("reachability"))
        act = sum(r["reachability"]["actionable_total"] for r in results if r.get("reachability"))
        reach_total = {"high_plus": hi, "actionable": act, "downgraded": hi - act,
                       "downgraded_share": proportion(hi - act, hi)}
    (out / fname).write_text(json.dumps({
        **run_meta(), "summary": summary, "summary_by_ecosystem": summary_by_eco,
        "reachability_total": reach_total,
        "mode": "materialized per-snapshot sources" if a.materialize else "HEAD sources",
        "materialize": a.materialize, "multi_version": not a.single_version,
        "unit": "(snapshot, vulnerable (name, version) pin) pairs",
        "reference": "git blame --first-parent on the pin's version line (shares the lock-file reader)",
        "repos": results}, indent=1))
    print("TOTAL", json.dumps({m: summary[m]["accuracy"] for m in METHODS if m in summary}), flush=True)


if __name__ == "__main__":
    random.seed(0)
    main()
