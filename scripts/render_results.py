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
sys.path.insert(0, str(ROOT / "benchmarks"))
from stats import proportion  # noqa: E402

FILES = [ROOT / "README.md", ROOT / "docs" / "index.md", ROOT / "docs" / "evaluation.md",
         ROOT / "docs" / "datasets.md"]
BLOCK = re.compile(r"(<!-- results:([\w-]+) -->\n)(.*?)(<!-- /results:\2 -->)", re.S)
ECO = {"pypi": "pip", "golang": "Go", "cargo": "Cargo", "npm": "npm (yarn, pnpm)"}


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
    return f"{p:.1e}" if p < 0.001 else f"{p:.3f}" if p < 0.1 else f"{p:.2f}"


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
        rows.append(f"| {r['repo']} | `{r['manifest']}` | {a['tracegate']['total']} | "
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
    hist = [("lineage_real_repos_materialized_v1.1.0.json", "v1.1.0: static tiers; `# via` read only below the pin"),
            ("lineage_real_repos_materialized_audited.json", "+ inline `# via` (older pip-compile layout)"),
            ("lineage_real_repos_materialized.json", "+ no downgrade when the manifest records no dependency edges")]
    rows = ["| Run | Static rule | high+ findings | actionable | downgraded [exact 95%] |",
            "| --- | --- | ---: | ---: | ---: |"]
    for fname, rule in hist:
        d = load(fname)
        rs = [r["reachability"] for r in d["repos"] if r.get("reachability")]
        hi = sum(r["high_plus_total"] for r in rs)
        act = sum(r["actionable_total"] for r in rs)
        cp = proportion(hi - act, hi)["clopper_pearson95"]
        rows.append(f"| {run_link(d['run_id'])} | {rule} | {hi} | {act} | {hi - act} ({pct((hi - act) / hi)}) "
                    f"[{ci(cp)}] |")
    cur = load("lineage_real_repos_materialized.json")
    per = ", ".join(f"{r['repo']} {r['reachability']['high_plus_total']} -> {r['reachability']['actionable_total']}"
                    for r in cur["repos"])
    return "\n".join(rows) + (f"\n\nCurrent run per repository (36 snapshots, each against its own sources): {per}. "
                              "Files: `results/lineage_real_repos_materialized*.json`.\n")


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
                              f"(exact 95% {ci(fp['clopper_pearson95'])}). Audited run: "
                              f"{run_link(d.get('source_run_id'))}; verdicts and evidence: `results/reachability_audit.json`.\n")


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


LICENCE = {
    "osv/": "per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0",
    "popular/top-pypi-packages": "hugovk/top-pypi-packages (no licence file; public BigQuery download counts)",
    "popular/npm-high-impact": "wooorm/npm-high-impact, MIT",
    "popular/crates-top": "crates.io API (names and download counts; crates.io data access policy)",
    "popular/nuget-top": "NuGet search API (names and download counts; nuget.org terms of use)",
    "popular/rubygems-top": "packages.ecosyste.ms (data CC BY-SA 4.0)",
    "bin/syft": "anchore/syft release, Apache-2.0", "bin/trivy": "aquasecurity/trivy release, Apache-2.0",
    "repos/alacritty": "Apache-2.0", "repos/bat": "MIT OR Apache-2.0", "repos/caddy": "Apache-2.0",
    "repos/excalidraw": "MIT", "repos/healthchecks": "BSD-3-Clause", "repos/hugo": "Apache-2.0",
    "repos/mastodon": "AGPL-3.0", "repos/netbox": "Apache-2.0", "repos/ripgrep": "Unlicense OR MIT",
    "repos/vue-core": "MIT", "repos/warehouse": "Apache-2.0",
}


def _lic(key: str) -> str:
    return next((v for k, v in LICENCE.items() if key.startswith(k)), "see source")


def datasets() -> str:
    rows = ["| Data | Used by | Source | Size | Fetched (UTC) | sha256 / commit | Licence or terms |",
            "| --- | --- | --- | ---: | --- | --- | --- |"]
    seen = set()
    for fname, used in (("data_manifest.json", "backtracking, oracle"),
                        ("data_manifest_typosquat.json", "typosquat"),
                        ("data_manifest_images.json", "images")):
        d = load(fname)
        for k, v in sorted(d.items()):
            if not isinstance(v, dict) or k.startswith("bin/") and k.endswith("checksums.txt"):
                continue
            ident = v.get("sha256") or v.get("head") or ""
            key = (k, ident)
            if key in seen:
                continue
            seen.add(key)
            size = f"{v['bytes'] / 1e6:.1f} MB" if v.get("bytes") else "blobless clone"
            src = v.get("url", "").replace("https://", "").split("?")[0]
            rows.append(f"| `{k}` | {used} (run {d.get('run_id')}) | {src} | {size} | {v.get('fetched', '')[:16]} | "
                        f"`{ident[:12]}` | {_lic(k)} |")
    return "\n".join(rows) + ("\n\nRendered from `results/data_manifest.json`, `data_manifest_typosquat.json` and "
                              "`data_manifest_images.json`; the 7 Docker images are pulled by tag and sha256-verified by "
                              "`scripts/pull_image.py` and never run. The Trivy vulnerability DB is a live feed and its "
                              "version is not pinned.\n")


def _latency(d: dict) -> str:
    by: dict[str, list[float]] = {}
    for r in d["repos"]:
        by.setdefault(r["ecosystem"], []).append(r["gate_ms_median"])
    mx = max(r["gate_ms_max"] for r in d["repos"])
    parts = []
    for e, v in by.items():
        lo, hi = min(v), max(v)
        parts.append(f"{ECO.get(e, e)} {lo:.0f}-{hi:.0f} ms" if round(lo) != round(hi) else f"{ECO.get(e, e)} {lo:.0f} ms")
    return ", ".join(parts) + f"; max {mx:.0f} ms (per snapshot graph)"


def _oracle_numbers() -> dict:
    o = load("lineage_bot_bump_oracle.json")
    P = o["pooled"]
    n_labels = sum(sum(r["usable"].values()) for r in o["repos"])
    return {"o": o, "P": P, "n_labels": n_labels,
            "repos": sum(1 for r in o["repos"] if sum(r["usable"].values()))}


def _typo() -> dict:
    d = load("typosquat_pypi.json")
    r = d["results"]
    default = next(k for k in r if k.startswith("tracegate (th=") and "FPR-matched" not in k)
    matched = next(k for k in r if k.startswith("tracegate (") and "FPR-matched" in k)
    diff = d["bootstrap"]["f1_diff_vs_lev1 (top-5k)"][matched]["ci"]
    return {"d": d, "default": r[default], "matched": r[matched], "lev1": r["lev1 (top-5k)"],
            "port": r["typomania/TypoGard (top-5k)"], "scan": r["pypi-scan (top-5k)"], "diff": diff}


def hero() -> str:
    d = load("lineage_real_repos.json")
    one = load("lineage_real_repos_single_version.json")
    t, pk = d["summary"]["tracegate"], d["summary"]["pickaxe-package-specific"]
    P = _oracle_numbers()["P"]["all"]
    ty = _typo()
    rows = ["| | |", "| --- | --- |",
            f"| **Agreement with `git blame`** | {pct(t['accuracy'])} of {t['total']:,} vulnerable (snapshot, pin) pairs in "
            f"11 repos and 4 ecosystems (one-version-per-name readers on the same data: "
            f"{pct(one['summary']['tracegate']['accuracy'])}); a package-specific `git log -S` pickaxe: {pct(pk['accuracy'])}. "
            f"Blame shares the lock-file reader, so this is agreement, not correctness. |",
            f"| **Commit-message oracle** | At the labelled commit TRACEGATE is right on {frac(P['tracegate']['at_bump'])} by "
            f"construction, as is `git blame` ({frac(P['blame']['at_bump'])}). At the last later snapshot still pinning the "
            f"version: TRACEGATE {frac(P['tracegate']['later_snapshot'])} (one-sided 95% exact lower bound "
            f"{pct(P['tracegate']['later_snapshot']['cp_lower95_one_sided'])}), `git blame` "
            f"{frac(P['blame']['later_snapshot'])} ({pct(P['blame']['later_snapshot']['accuracy'])}). The oracle tests version "
            f"tracking under line rewrites, not attribution independent of the lock-file reader. |",
            f"| **Typosquat (PyPI, supporting signal)** | F1 {ty['default']['f1']:.3f} at the dev-tuned threshold, "
            f"{ty['matched']['f1']:.3f} FPR-matched, vs Damerau-1 {ty['lev1']['f1']:.3f}; recall is low for every detector. |"]
    return "\n".join(rows) + (f"\n\nBacktracking: run {run_link(d['run_id'])}; oracle: run "
                              f"{run_link(load('lineage_bot_bump_oracle.json')['run_id'])}; typosquat: run "
                              f"{run_link(ty['d']['run_id'])}.\n")


def headline() -> str:
    d = load("lineage_real_repos.json")
    one = load("lineage_real_repos_single_version.json")
    s = d["summary"]
    t, pk, vl = s["tracegate"], s["pickaxe-package-specific"], s["pickaxe-version-line"]
    on = _oracle_numbers()
    P = on["P"]
    a = P["all"]
    mat = load("lineage_real_repos_materialized.json")["reachability_total"]
    eco = d["summary_by_ecosystem"]
    order = [e for e in ("pypi", "golang", "cargo", "npm") if e in eco]
    rows = ["| Question | Data | TRACEGATE | Baselines and ablations |", "| --- | --- | --- | --- |"]
    rows.append(f"| Finding -> introducing commit, agreement with `git blame --first-parent` | {t['total']:,} vulnerable "
                f"(snapshot, pin) pairs, {sum(r['snapshots'] for r in d['repos'])} snapshots of {len(d['repos'])} repos, "
                f"4 ecosystems | **{pct(t['accuracy'])}** [Wilson {ci(t['wilson95'])}; repo-clustered "
                f"{ci(t['repo_cluster_bootstrap95'])}]; old one-version readers on the same data "
                f"{pct(one['summary']['tracegate']['accuracy'])} | package-specific `git log -S` {pct(pk['accuracy'])}; "
                f"version-line `git log -S` {pct(vl['accuracy'])}; last manifest commit "
                f"{pct(s['last-manifest-commit']['accuracy'])}; first mention {pct(s['pickaxe-first']['accuracy'])} |")
    rows.append("| ... per ecosystem | " + " / ".join(f"{ECO[e]} {eco[e]['tracegate']['total']:,}" for e in order) + " pairs | "
                + " / ".join(pct(eco[e]["tracegate"]["accuracy"]) for e in order) + " | package-specific `git log -S`: "
                + " / ".join(pct(eco[e]["pickaxe-package-specific"]["accuracy"]) for e in order) + " |")
    b, l_ = a["tracegate"]["at_bump"], a["tracegate"]["later_snapshot"]
    rows.append(f"| Finding -> introducing commit, **commit-message oracle** ({on['n_labels']:,} labelled bumps, reverts and "
                f"re-bumps; {b['total']} sampled) | at the labelled commit / at the last later snapshot still pinning it "
                f"| {frac(b)} (by construction) / **{frac(l_)}** (one-sided 95% exact >= {pct(l_['cp_lower95_one_sided'])}) | "
                f"`git blame` {frac(a['blame']['at_bump'])} / {frac(a['blame']['later_snapshot'])} "
                f"({pct(a['blame']['later_snapshot']['accuracy'])}); package-specific `git log -S` "
                f"{frac(a['pickaxe-package-specific']['later_snapshot'])} later; old one-version readers "
                f"{frac(P['multi_version']['tracegate-single-version']['at_bump'])} on the multi-version stratum; no recency rule "
                f"{P['revert']['first-introduction']['at_bump']['correct'] + P['re_bump']['first-introduction']['at_bump']['correct']}/"
                f"{P['revert']['first-introduction']['at_bump']['total'] + P['re_bump']['first-introduction']['at_bump']['total']}"
                f" on reverts and re-bumps |")
    au = load("reachability_audit.json")["summary"]["false_unreached_rate_pins"]
    rows.append(f"| Reachability: high/critical findings left actionable | {mat['high_plus']} high+ OSV findings, 36 snapshots "
                f"of 3 Python repos, own sources | {mat['actionable']} ({mat['downgraded']} downgraded): the previous rule's "
                f"downgrades were audited and {frac(au)} pins were loaded (exact 95% {ci(au['clopper_pearson95'])}), so "
                f"without recorded dependency edges nothing is downgraded now | {mat['high_plus']} (raw scanner output) |")
    ty = _typo()
    rows.append(f"| Typosquat, PyPI (hash split, test half) | {ty['d']['positives']:,} OSV `MAL-*` names vs "
                f"{ty['d']['negatives']:,} packages ranked 5k-15k | F1 {ty['default']['f1']:.3f} at the dev-tuned default "
                f"(FPR {pct(ty['default']['fpr'])}); {ty['matched']['f1']:.3f} FPR-matched to Damerau-1 (paired F1 difference "
                f"[{ty['diff'][0]:+.3f}, {ty['diff'][1]:+.3f}]) | Damerau-1 {ty['lev1']['f1']:.3f}; typomania/TypoGard port "
                f"{ty['port']['f1']:.3f}; our pypi-scan port {ty['scan']['f1']:.3f} |")
    rows.append("| Keyless signing | dev build `cfd215e` wheel + sdist ([evidence](results/sigstore_evidence.json)); "
                "v1.1.0 release bundles on the release page | signed with GitHub OIDC, verified, Rekor entries checked | - |")
    rows.append("| Admission | kind cluster, 3 images ([decisions](results/kind_admission.json)) | admits only the image with a "
                "valid signature and complete signed provenance | cosign alone would admit the third image |")
    rows.append(f"| Gate latency (median per repo) | real lineage graphs | {_latency(d)} | - |")
    return "\n".join(rows) + "\n"


def index_headline() -> str:
    d = load("lineage_real_repos.json")
    t = d["summary"]["tracegate"]
    pk = d["summary"]["pickaxe-package-specific"]
    P = _oracle_numbers()["P"]["all"]
    rows = ["| Result | Value |", "| --- | --- |",
            f"| Agreement with `git blame`, {t['total']:,} (snapshot, vulnerable pin) pairs, 11 repos | {pct(t['accuracy'])} "
            f"[Wilson {ci(t['wilson95'])}, ignores clustering; repo-clustered {ci(t['repo_cluster_bootstrap95'])}]; "
            f"package-specific `git log -S` {pct(pk['accuracy'])} |",
            f"| Commit-message oracle, at the labelled commit | TRACEGATE {frac(P['tracegate']['at_bump'])} (by construction) vs "
            f"`git blame` {frac(P['blame']['at_bump'])} |",
            f"| Commit-message oracle, later snapshots | TRACEGATE {frac(P['tracegate']['later_snapshot'])} "
            f"(one-sided 95% exact >= {pct(P['tracegate']['later_snapshot']['cp_lower95_one_sided'])}) vs `git blame` "
            f"{frac(P['blame']['later_snapshot'])} ({pct(P['blame']['later_snapshot']['accuracy'])}) |"]
    return "\n".join(rows) + "\n"


RENDER = {"datasets": datasets, "hero": hero, "headline": headline, "index-headline": index_headline, "lineage-repos": lineage_repos, "lineage-ecosystems": lineage_ecosystems, "before-after": before_after,
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

        def sub(m: re.Match, f: Path = f) -> str:
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
