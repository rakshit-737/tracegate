#!/usr/bin/env python3
"""Real container images: cross-tool identity, dedup, blast radius, gate latency.

Inputs (from scripts/scan_real.py): for each pinned public image
  <slug>.syft.json       real Syft SBOM (per-layer dir scan, layer DiffIDs)
  <slug>.trivy.json      real Trivy vulnerability scan (PURL + layer DiffID per finding)
  <slug>.trivy.cdx.json  real Trivy CycloneDX SBOM (second, independent cataloguer)

Measures
  1. identity convergence: share of Trivy findings that land on a Syft SBOM node
       naive-name@version  : PkgName@InstalledVersion == Syft name@version
       raw-purl            : Trivy PURL string == Syft purl string
       tracegate           : canonical purl (qualifiers dropped, names normalised)
  2. SBOM agreement Syft vs Trivy (Jaccard over canonical purls)
  3. graph-level dedup: raw Trivy rows across all images vs unique finding nodes
  4. blast radius of every layer shared by >1 image (the Alpine base layer)
  5. gate latency over the combined multi-image graph
  6. Warden false positives on the language packages shipped in official images

Deployments are synthetic (one service per image) - labelled as such.
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tracegate.backtrack import blast_radius, origin_story  # noqa: E402
from tracegate.collector import Collector  # noqa: E402
from tracegate.data import data_root, top_npm, top_pypi  # noqa: E402
from tracegate.enrich import enrich_warden  # noqa: E402
from tracegate.ids import canonical_purl  # noqa: E402
from tracegate.ingest import cyclonedx_to_build, syft_json_to_build, trivy_json_to_scan  # noqa: E402
from tracegate.models import NodeKind, StageEvent  # noqa: E402
from tracegate.osv import OsvIndex  # noqa: E402
from tracegate.policy import evaluate  # noqa: E402
from tracegate.signing import HmacSigner, Verifier  # noqa: E402
from tracegate.warden import HeuristicWarden, MultiWarden  # noqa: E402

KEY = b"bench-key"


def _canon(p: str | None) -> str | None:
    try:
        return canonical_purl(p) if p else None
    except ValueError:
        return None


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "results"),
                    help="output directory (default: results/, the committed results)")
    a = ap.parse_args()
    scans = data_root() / "scans"
    slugs = sorted(p.name[:-len(".syft.json")] for p in scans.glob("*.syft.json")
                   if (scans / p.name.replace(".syft.json", ".trivy.json")).exists()
                   and not (data_root() / "repos" / p.name[:-len(".syft.json")]).exists())
    if not slugs:
        sys.exit("no image scans found (python scripts/scan_real.py images)")
    per_image, events = [], []
    tot = {"rows": 0, "naive": 0, "raw": 0, "canon": 0}
    for s in slugs:
        syft = json.loads((scans / f"{s}.syft.json").read_text(encoding="utf-8"))
        trivy = json.loads((scans / f"{s}.trivy.json").read_text(encoding="utf-8"))
        s_raw = {a.get("purl") for a in syft["artifacts"] if a.get("purl")}
        s_canon = {_canon(p) for p in s_raw} - {None}
        s_nv = {f"{a['name']}@{a['version']}" for a in syft["artifacts"]}
        rows = naive = raw = canon = 0
        for r in trivy.get("Results", []) or []:
            for v in r.get("Vulnerabilities") or []:
                rows += 1
                p = (v.get("PkgIdentifier") or {}).get("PURL")
                naive += f"{v['PkgName']}@{v.get('InstalledVersion')}" in s_nv
                raw += p in s_raw
                canon += _canon(p) in s_canon
        cdx = scans / f"{s}.trivy.cdx.json"
        jac = None
        if cdx.exists():
            t_canon = {a["purl"] for a in cyclonedx_to_build(cdx, "x")["sbom"]["artifacts"]}
            jac = round(len(s_canon & t_canon) / max(1, len(s_canon | t_canon)), 4)
        per_image.append({"image": syft["source"]["name"], "syft_packages": len(syft["artifacts"]),
                          "layers": len(syft["source"]["metadata"]["layers"]), "trivy_findings": rows,
                          "match_naive": naive, "match_raw_purl": raw, "match_tracegate": canon,
                          "sbom_jaccard_syft_vs_trivy": jac})
        for k, x in (("rows", rows), ("naive", naive), ("raw", raw), ("canon", canon)):
            tot[k] += x
        run = f"img-{s}"
        build = syft_json_to_build(syft, f"build-{s}")
        events += [StageEvent("build", run, build), StageEvent("scan", run, trivy_json_to_scan(trivy)),
                   StageEvent("deploy", run, {"service": f"svc-{s.split('_')[0]}",
                                              "image_digest": build["image"]["digest"],
                                              "containers": [f"{s.split('_')[0]}-0"]})]
    # commit stage: a synthetic monorepo commit so the gate's required stages are present
    events.insert(0, StageEvent("commit", "img-commit", {"sha": "0" * 40, "author": "bench", "pr": None,
                                                         "files": [], "deps_added": []}))
    signer = HmacSigner("bench", KEY)
    envs = [signer.sign(e) for e in events]
    root = data_root()
    warden = MultiWarden({})
    if (root / "osv/PyPI-all.zip").exists():
        osv_py = OsvIndex.from_zip(root / "osv/PyPI-all.zip")
        warden.by_ecosystem["pypi"] = HeuristicWarden(popular=top_pypi(5000), osv=osv_py)
    if (root / "osv/npm-all.zip").exists():
        osv_npm = OsvIndex.from_zip(root / "osv/npm-all.zip", "npm")
        warden.by_ecosystem["npm"] = HeuristicWarden(popular=top_npm(5000), osv=osv_npm)
    lat = []
    for _ in range(5):
        t0 = time.perf_counter()
        res = Collector(Verifier({"bench": KEY})).collect(envs)
        dec = evaluate(res)
        lat.append(1000 * (time.perf_counter() - t0))
    g = res.graph
    enrich_warden(res, warden)
    lang = [n for n in g.of_kind(NodeKind.DEPENDENCY) if n.attrs.get("ecosystem") in warden.by_ecosystem]
    flagged = [f"{g.nodes[f.node_id].attrs['ecosystem']}:{g.nodes[f.node_id].label} ({f.title})"
               for f in g.findings if f.source == "warden"]
    # layers shared across images
    shared = []
    for layer in g.of_kind(NodeKind.LAYER):
        br = blast_radius(g, layer.id)
        if len(br["images"]) > 1:
            shared.append({"layer": layer.attrs["digest"][:19], "images": br["images"],
                           "services": br["services"],
                           "packages_in_layer": sum(1 for e in g.inc[layer.id] if e.rel == "installed_in"),
                           "findings_in_layer": sum(len(g.findings_for(e.src)) for e in g.inc[layer.id])})
    scan_f = [f for f in g.findings if f.source == "trivy"]
    cves = {f.cve for f in scan_f}
    widest = sorted(((len(blast_radius(g, f.node_id)["images"]), f.cve, g.nodes[f.node_id].label)
                     for f in scan_f), reverse=True)[:5]
    example = origin_story(g, widest[0][1])[0] if widest else None
    out = {
        "images": per_image,
        "identity_convergence": {k: round(tot[k] / tot["rows"], 4) if tot["rows"] else None
                                 for k in ("naive", "raw", "canon")} | {"trivy_rows": tot["rows"]},
        "graph": g.stats(), "gate_ms_median": round(statistics.median(lat), 1),
        "verdict": dec.verdict.value, "unmatched_trivy_findings": len(res.unmatched),
        "unique_finding_nodes": len(scan_f), "unique_cves": len(cves),
        "dedup_ratio": round(tot["rows"] / max(1, len(scan_f)), 2),
        "shared_layers": shared, "widest_blast_radius": widest,
        "example_origin_story": example,
        "warden": {"language_packages_scored": len(lang), "flagged": flagged},
        "note": "deployments are synthetic (one service per image); SBOM via Syft per-layer dir scans",
    }
    res_dir = Path(a.out)
    res_dir.mkdir(exist_ok=True)
    (res_dir / "images_real.json").write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps({k: v for k, v in out.items() if k not in ("images", "example_origin_story")}, indent=1, default=str))
    for r in per_image:
        print(r)


if __name__ == "__main__":
    main()
