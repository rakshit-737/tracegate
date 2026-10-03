#!/usr/bin/env python3
"""Render the published result tables from results/*.json into README.md and docs/*.md.

Tables live between markers in the Markdown files:

    <!-- results:NAME -->
    ...generated...
    <!-- /results:NAME -->

  python scripts/render_results.py --write    # regenerate every marked block in place
  python scripts/render_results.py --check    # exit 1 if any block differs from the JSON (CI)

So every number inside a marked block is read from a committed results file, and CI fails when a
results file changes without the pages being regenerated (or a page is edited by hand).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results"
FILES = [ROOT / "README.md", ROOT / "docs" / "index.md", ROOT / "docs" / "evaluation.md"]
BLOCK = re.compile(r"(<!-- results:([\w-]+) -->\n)(.*?)(<!-- /results:\2 -->)", re.S)
ECO = {"pypi": "pip", "golang": "Go", "cargo": "Cargo", "npm": "npm"}


def load(name: str) -> dict:
    return json.loads((RES / name).read_text(encoding="utf-8"))


def pct(x: float | None, nd: int = 1) -> str:
    return "n/a" if x is None else f"{100 * x:.{nd}f}%"


def ci(iv: list[float] | None, nd: int = 1) -> str:
    return "n/a" if not iv else f"{100 * iv[0]:.{nd}f}-{100 * iv[1]:.{nd}f}"


def frac(d: dict) -> str:
    return f"{d['correct']}/{d['total']}"


def pval(p: float | None) -> str:
    if p is None:
        return "n/a (no discordant pairs)"
    return "< 0.001" if p < 0.001 else f"{p:.3f}" if p < 0.1 else f"{p:.2f}"


def run_link(rid: int | None) -> str:
    return f"[{rid}](https://github.com/rakshit-737/tracegate/actions/runs/{rid})" if rid else "local"


# ---- lineage -------------------------------------------------------------------------------
def lineage_repos() -> str:
    d = load("lineage_real_repos.json")
    rows = ["| Repository | Lock file | Pairs | TRACEGATE | pickaxe, package-specific | pickaxe, version line "
            "| last manifest commit | first mention | gate median / max ms |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for r in d["repos"]:
        a = r["attribution"]
        rows.append(f"| {r['repo']} | `{r['manifest'].rsplit('/', 1)[-1]}` | {a['tracegate']['total']} | "
                    f"{pct(a['tracegate']['accuracy'])} | {pct(a['pickaxe-package-specific']['accuracy'])} | "
                    f"{pct(a['pickaxe-version-line']['accuracy'])} | {pct(a['last-manifest-commit']['accuracy'])} | "
                    f"{pct(a['pickaxe-first']['accuracy'])} | {r['gate_ms_median']:.0f} / {r['gate_ms_max']:.0f} |")
    s = d["summary"]
    rows.append(f"| **all** | 11 repos | {s['tracegate']['total']} | **{pct(s['tracegate']['accuracy'])}** "
                f"[Wilson {ci(s['tracegate']['wilson95'])}; repo-clustered {ci(s['tracegate']['repo_cluster_bootstrap95'])}] | "
                f"{pct(s['pickaxe-package-specific']['accuracy'])} [clustered "
                f"{ci(s['pickaxe-package-specific']['repo_cluster_bootstrap95'])}] | "
                f"{pct(s['pickaxe-version-line']['accuracy'])} | {pct(s['last-manifest-commit']['accuracy'])} | "
                f"{pct(s['pickaxe-first']['accuracy'])} | |")
    return "\n".join(rows) + f"\n\nSource: `results/lineage_real_repos.json`, run {run_link(d['run_id'])}.\n"


def lineage_ecosystems() -> str:
    d = load("lineage_real_repos.json")
    rows = ["| Ecosystem | Pairs | TRACEGATE [Wilson 95%] | pickaxe, package-specific [Wilson 95%] "
            "| discordant pairs (TRACEGATE only : pickaxe only) | exact McNemar p | pickaxe, version line |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for e, s in [*d["summary_by_ecosystem"].items(), ("all", d["summary"])]:
        t, p, v = s["tracegate"], s["pickaxe-package-specific"], s["pickaxe-version-line"]
        vs = s["tracegate_vs"]["pickaxe-package-specific"]
        name = "**all**" if e == "all" else ECO.get(e, e)
        rows.append(f"| {name} | {t['total']} | {pct(t['accuracy'])} [{ci(t['wilson95'])}] | "
                    f"{pct(p['accuracy'])} [{ci(p['wilson95'])}] | {vs['only_a']} : {vs['only_b']} | "
                    f"{pval(vs['mcnemar_exact_p'])} | {pct(v['accuracy'])} |")
    return "\n".join(rows) + "\n"


def before_after() -> str:
    old = load("lineage_real_repos_v1.1.0.json")
    one = load("lineage_real_repos_single_version.json")
    new = load("lineage_real_repos.json")
    rows = ["| Ecosystem | v1.1.0 as published (run {}) | old readers, this run ({}) | multi-version readers, "
            "this run ({}) |".format(old["run_id"], one["run_id"], new["run_id"]),
            "| --- | ---: | ---: | ---: |"]
    for e in [*new["summary_by_ecosystem"], "all"]:
        cells = []
        for d in (old, one, new):
            s = d["summary"] if e == "all" else d["summary_by_ecosystem"].get(e)
            t = s["tracegate"] if s else None
            cells.append(f"{frac(t)} = {pct(t['accuracy'])}" if t else "n/a")
        rows.append(f"| {'**all**' if e == 'all' else ECO.get(e, e)} | " + " | ".join(cells) + " |")
    rows.append("| multi-version entries dropped by the old readers at HEAD | " + " | ".join(
        [""] * 2) + " | " + ", ".join(
        f"{r['repo']} {r['multi_version_at_head']['entries_dropped_by_single_version']}/"
        f"{r['multi_version_at_head']['entries']} ({pct(r['multi_version_at_head']['share_dropped'])})"
        for r in new["repos"] if r["multi_version_at_head"]["entries_dropped_by_single_version"]) + " |")
    return "\n".join(rows) + "\n"


# ---- oracle ----------------------------------------------------------------------------------
METHOD_LABEL = {"tracegate": "TRACEGATE", "tracegate-single-version": "old one-version readers",
                "first-introduction": "first introduction (no recency rule)", "blame": "`git blame`",
                "pickaxe-package-specific": "pickaxe, package-specific", "pickaxe-version-line": "pickaxe, version line"}


def oracle_strata() -> str:
    d = load("lineage_bot_bump_oracle.json")
    P = d["pooled"]
    methods = d["methods"]
    head = "| Stratum | usable / scored | " + " | ".join(METHOD_LABEL[m] for m in methods) + " |"
    rows = [head, "| --- | --- | " + " | ".join("---:" for _ in methods) + " |"]
    for s in [*d["strata"], "all"]:
        if s not in P:
            continue
        usable = sum(o["usable"][s] for o in d["repos"]) if s != "all" else sum(sum(o["usable"].values()) for o in d["repos"])
        n_b = P[s]["tracegate"]["at_bump"]["total"]
        n_l = P[s]["tracegate"].get("later_snapshot", {}).get("total", 0)
        for point, lab in (("at_bump", "at the labelled commit"), ("later_snapshot", "last later snapshot")):
            if point not in P[s]["tracegate"]:
                continue
            cells = [frac(P[s][m][point]) for m in methods]
            name = f"**{s}**" if s == "all" else s.replace("_", " ")
            rows.append(f"| {name}, {lab} | {usable} / {n_b if point == 'at_bump' else n_l} | " + " | ".join(cells) + " |")
    return "\n".join(rows) + f"\n\nSource: `results/lineage_bot_bump_oracle.json`, run {run_link(d['run_id'])}.\n"


def oracle_pooled() -> str:
    d = load("lineage_bot_bump_oracle.json")
    P = d["pooled"]["all"]
    rows = ["| Method | at the labelled commit | one-sided 95% exact lower bound | last later snapshot "
            "| one-sided 95% exact lower bound | Wilson 95% (later) | repo-clustered bootstrap 95% (later) |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for m in d["methods"]:
        b, l_ = P[m]["at_bump"], P[m]["later_snapshot"]
        rows.append(f"| {METHOD_LABEL[m]} | {frac(b)} ({pct(b['accuracy'])}) | {pct(b['cp_lower95_one_sided'])} | "
                    f"{frac(l_)} ({pct(l_['accuracy'])}) | {pct(l_['cp_lower95_one_sided'])} | {ci(l_['wilson95'])} | "
                    f"{ci(l_['repo_cluster_bootstrap95'])} |")
    vs = d["pooled"]["all"]["tracegate_vs"]["later_snapshot"]
    paired = "; ".join(f"vs {METHOD_LABEL[m]}: {vs[m]['only_a']} : {vs[m]['only_b']}, p {pval(vs[m]['mcnemar_exact_p'])}"
                       for m in ("blame", "pickaxe-package-specific", "tracegate-single-version") if m in vs)
    return "\n".join(rows) + f"\n\nPaired at later snapshots (TRACEGATE only : other only, exact McNemar, ignores clustering): {paired}.\n"


def oracle_exclusions() -> str:
    d = load("lineage_bot_bump_oracle.json")
    tot: dict[str, dict[str, int]] = {}
    lab: dict[str, int] = {}
    for o in d["repos"]:
        for src, ex in o["excluded"].items():
            for k, v in ex.items():
                tot.setdefault(src, {}).setdefault(k, 0)
                tot[src][k] += v
        for src, n in o["labelled"].items():
            lab[src] = lab.get(src, 0) + n
    rows = ["| Label source | labels | X@V already present at the parent | X@V not in the lock file | ambiguous name |",
            "| --- | ---: | ---: | ---: | ---: |"]
    for src in ("bot_single", "grouped", "revert"):
        t = tot.get(src, {})
        rows.append(f"| {src.replace('_', ' ')} | {lab.get(src, 0)} | {t.get('already_present', 0)} | "
                    f"{t.get('not_in_lock', 0)} | {t.get('ambiguous_name', 0)} |")
    per = ", ".join(f"{o['repo']} {sum(o['usable'].values())}" for o in d["repos"])
    return "\n".join(rows) + f"\n\nUsable labelled cases per repository (all strata): {per}.\n"


# ---- reachability / images / scale / adjudication ---------------------------------------------
def reachability() -> str:
    head = load("lineage_real_repos.json")
    mat = load("lineage_real_repos_materialized.json")
    hm = {r["repo"]: r["reachability"] for r in head["repos"] if r.get("reachability")}
    rows = ["| Repository | high+ findings | actionable, HEAD sources | actionable, own sources | downgraded (own sources) |",
            "| --- | ---: | ---: | ---: | ---: |"]
    for r in mat["repos"]:
        m = r["reachability"]
        h = hm.get(r["repo"], {})
        rows.append(f"| {r['repo']} | {m['high_plus_total']} | {h.get('actionable_total', 'n/a')} | "
                    f"{m['actionable_total']} | {m['downgraded_total']} |")
    t = mat["reachability_total"]
    ht = head.get("reachability_total") or {}
    rows.append(f"| **all** | {t['high_plus']} | {ht.get('actionable', 'n/a')} | {t['actionable']} "
                f"(-{pct(t['downgraded_share']['accuracy'])}, Wilson {ci(t['downgraded_share']['wilson95'])}) | "
                f"{t['downgraded']} |")
    return "\n".join(rows) + (f"\n\nSources: `results/lineage_real_repos_materialized.json` (run {run_link(mat['run_id'])}), "
                              f"HEAD-sources column from `results/lineage_real_repos.json` (run {run_link(head['run_id'])}).\n")


def audit() -> str:
    d = load("reachability_audit.json")
    s = d.get("summary")
    if not s:
        return "Audit not scored yet.\n"
    rows = ["| Verdict | (snapshot, pin) rows | findings |", "| --- | ---: | ---: |"]
    for v in ("loaded", "not_loaded", "undetermined"):
        rs = [r for r in d["rows"] if r.get("verdict") == v]
        rows.append(f"| {v.replace('_', ' ')} | {len(rs)} | {sum(len(r['findings']) for r in rs)} |")
    fp = s["false_unreached_rate_pins"]
    return "\n".join(rows) + (f"\n\nFalse-`unreached` rate among decided pins: {frac(fp)} = {pct(fp['accuracy'])} "
                              f"(exact 95% {ci(fp['clopper_pearson95'])}). Source: `results/reachability_audit.json`.\n")


def images() -> str:
    d = load("images_real.json")
    rows = ["| Image | Syft pkgs | Layers | Trivy findings | matched, naive name@version | matched, raw purl string "
            "| matched, canonical purl | Syft/Trivy SBOM Jaccard |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for r in d["images"]:
        jac = r["sbom_jaccard_syft_vs_trivy"]
        rows.append(f"| {r['image']} | {r['syft_packages']} | {r['layers']} | {r['trivy_findings']} | {r['match_naive']} | "
                    f"{r['match_raw_purl']} | {r['match_tracegate']} | {'n/a' if jac is None else f'{jac:.2f}'} |")
    ic = d["identity_convergence"]
    return "\n".join(rows) + (f"\n\nAll {ic['trivy_rows']} Trivy rows: naive {pct(ic['naive'])}, raw purl {pct(ic['raw'])}, "
                              f"canonical {pct(ic['canon'])}. Merged graph: {d['graph']['nodes']} nodes, {d['graph']['edges']} "
                              f"edges; {d['unique_finding_nodes']} unique finding nodes ({d['unique_cves']} CVEs), a "
                              f"{d['dedup_ratio']}x de-duplication; verdict `{d['verdict']}`; "
                              f"{d['unmatched_trivy_findings']} unattributed findings. Source: `results/images_real.json`, "
                              f"run {run_link(d.get('run_id'))}.\n")


def scale() -> str:
    d = load("scale_synthetic.json")
    rows = ["| Services | Deps | Events | Nodes | Edges | Gate median |", "| ---: | ---: | ---: | ---: | ---: | ---: |"]
    for r in d["rows"]:
        rows.append(f"| {r['services']} | {r['deps']} | {r['events']} | {r['nodes']:,} | {r['edges']:,} | "
                    f"{r['gate_s_median']:.3f} s |")
    return "\n".join(rows) + f"\n\nSynthetic data; source `results/scale_synthetic.json`, run {run_link(d.get('run_id'))}.\n"


def adjudication() -> str:
    d = load("lineage_adjudication.json")
    acc = d.get("adjudicated_accuracy")
    if not acc:
        return "Adjudication not scored yet.\n"
    rows = ["| Sample | cases | TRACEGATE | `git blame` | pickaxe, package-specific | pickaxe, version line | undecided |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for g, a in acc.items():
        n = a["tracegate"]["total"]
        cells = [f"{frac(a[m])} [{ci(a[m]['wilson95'], 0)}]" for m in
                 ("tracegate", "blame", "pickaxe_package_specific", "pickaxe_version_line")]
        rows.append(f"| {g} | {n} | " + " | ".join(cells) + f" | {a['undecided']} |")
    return "\n".join(rows) + "\n\nWilson 95% intervals in brackets. Source: `results/lineage_adjudication.json`.\n"


RENDER = {"lineage-repos": lineage_repos, "lineage-ecosystems": lineage_ecosystems, "before-after": before_after,
          "oracle-strata": oracle_strata, "oracle-pooled": oracle_pooled, "oracle-exclusions": oracle_exclusions,
          "reachability": reachability, "audit": audit, "images": images, "scale": scale,
          "adjudication": adjudication}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    a = ap.parse_args()
    stale = []
    for f in FILES:
        text = f.read_text(encoding="utf-8")

        def sub(m: re.Match) -> str:
            name = m.group(2)
            if name not in RENDER:
                stale.append(f"{f.name}: unknown block {name}")
                return m.group(0)
            body = RENDER[name]()
            if body != m.group(3):
                stale.append(f"{f.relative_to(ROOT)}: block {name} differs from results/")
            return m.group(1) + body + m.group(4)
        new = BLOCK.sub(sub, text)
        if a.write and new != text:
            f.write_text(new, encoding="utf-8")
    if a.check and stale:
        print("\n".join(stale), file=sys.stderr)
        print("run: python scripts/render_results.py --write", file=sys.stderr)
        return 1
    print(f"{'checked' if a.check else 'rendered'} result blocks in {', '.join(f.name for f in FILES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
