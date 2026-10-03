#!/usr/bin/env python3
"""Evidence for auditing static-reachability downgrades (false-unreached check).

Reads every downgraded finding in results/lineage_real_repos_materialized.json and, for each
(snapshot, pin), rebuilds what static reachability could not see at that snapshot: the
dependency edges between the snapshot's pins. Those requirement files carry no pip-compile
`# via` annotations, so the edges come from each pinned release's own metadata
(PyPI JSON `requires_dist`, markers evaluated for CPython 3.8 on Linux, extras off).

For each downgraded pin it records:
  * dependents  - pinned packages that require it (from requires_dist)
  * chain       - a shortest dependency chain from a package the snapshot's own sources import
                  (or name as an entry point) down to the downgraded pin, if one exists
  * metadata_missing - pinned packages whose release publishes no requires_dist

A person then writes the verdict for each pin into results/reachability_audit.json:
`loaded` when a chain exists (the package is imported when its dependent is: a false
`unreached`), `not_loaded` when the sources and every dependent were checked and nothing loads
it, `undetermined` otherwise. `--score` computes the false-unreached rate with exact intervals.

  python benchmarks/reach_audit.py --evidence   # needs the warehouse / netbox clones and pypi.org
  python benchmarks/reach_audit.py --score
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lineage_eval import REPOS  # noqa: E402
from stats import proportion, run_meta  # noqa: E402

from tracegate.data import data_root  # noqa: E402
from tracegate.gitlineage import _git, materialize, parse_requirements  # noqa: E402
from tracegate.ids import normalize_name  # noqa: E402
from tracegate.reach import ENTRYPOINT_FILES, app_imports, entrypoint_text, static_reachability  # noqa: E402

RESULTS = Path(__file__).resolve().parents[1] / "results"
ENV = {"python_version": "3.8", "python_full_version": "3.8.0", "sys_platform": "linux", "platform_system": "Linux",
       "os_name": "posix", "implementation_name": "cpython", "platform_python_implementation": "CPython",
       "platform_machine": "x86_64", "extra": ""}


def requires(name: str, version: str, cache: dict) -> list[str] | None:
    """Normalised names a pinned release requires (None when PyPI publishes no metadata)."""
    key = f"{name}=={version}"
    if key in cache:
        return cache[key]
    from packaging.markers import Marker
    from packaging.requirements import InvalidRequirement, Requirement
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "tracegate-audit"}),
                                        timeout=30) as r:
                info = json.load(r)["info"]
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                cache[key] = None
                return None
            time.sleep(2 * (attempt + 1))
        except OSError:
            time.sleep(2 * (attempt + 1))
    else:
        cache[key] = None
        return None
    out = None
    if info.get("requires_dist") is not None:
        out = []
        for req in info["requires_dist"]:
            try:
                r = Requirement(req)
            except InvalidRequirement:
                continue
            if r.marker is not None:
                try:
                    if not Marker(str(r.marker)).evaluate(ENV):
                        continue
                except Exception:  # noqa: BLE001 - unknown marker variable: keep the edge
                    pass
            out.append(normalize_name(r.name))
    cache[key] = out
    time.sleep(0.2)  # be gentle with pypi.org
    return out


def evidence(out_path: Path) -> None:
    mat = json.loads((RESULTS / "lineage_real_repos_materialized.json").read_text())
    cache_p = data_root() / "pypi_requires_cache.json"
    cache = json.loads(cache_p.read_text()) if cache_p.exists() else {}
    rows = []
    for r in mat["repos"]:
        rr = r.get("reachability") or {}
        if not rr.get("downgraded"):
            continue
        repo = data_root() / "repos" / r["repo"]
        manifest, srcs = REPOS[r["repo"]]
        by_snap: dict[str, list[dict]] = {}
        for d in rr["downgraded"]:
            by_snap.setdefault(d["snapshot"], []).append(d)
        for snap, ds in by_snap.items():
            sha = _git(repo, "rev-parse", snap).strip()
            path = next((p for p in (manifest, "requirements.txt", "requirements/main.txt")
                         if _git_ok(repo, f"{sha}:{p}")), manifest)
            req = _git(repo, "show", f"{sha}:{path}")
            pins = parse_requirements(req)
            with tempfile.TemporaryDirectory() as td:
                materialize(repo, sha, srcs, td, anywhere=ENTRYPOINT_FILES)
                strings: set[str] = set()
                mods = app_imports([Path(td) / s for s in srcs], strings)
                rep = static_reachability(pins, [Path(td) / s for s in srcs], Path(td), req,
                                          mods=mods, ep=entrypoint_text(Path(td)), strings=strings)
            deps = {n: requires(n, v, cache) for n, v in pins.items()}
            cache_p.write_text(json.dumps(cache))
            rdeps: dict[str, set[str]] = {}
            for n, ds_ in deps.items():
                for x in ds_ or []:
                    if x in pins:
                        rdeps.setdefault(x, set()).add(n)
            roots = {n for n, st in rep.status.items() if st in ("imported", "entrypoint", "referenced")}
            for pin in sorted({d["pin"] for d in ds}):
                name = normalize_name(pin.split("==")[0])
                chain = _chain(name, rdeps, roots)
                rows.append({"repo": r["repo"], "snapshot": snap, "date": ds[0]["date"], "pin": pin,
                             "findings": sorted(d["cve"] for d in ds if d["pin"] == pin),
                             "status_at_snapshot": rep.status.get(name),
                             "dependents": sorted(rdeps.get(name, ())),
                             "dependent_status": {p: rep.status.get(p) for p in sorted(rdeps.get(name, ()))},
                             "chain_from_app_import": chain,
                             "metadata_missing": sorted(n for n, v in deps.items() if v is None)})
            print(f"{r['repo']} {snap}: {len(ds)} downgraded findings checked", flush=True)
    out_path.write_text(json.dumps({**run_meta(), "source": "lineage_real_repos_materialized.json",
                                    "source_run_id": mat.get("run_id"), "edges": "PyPI requires_dist of each "
                                    "pinned release, markers for CPython 3.8 / Linux, extras off", "rows": rows},
                                   indent=1))
    print(f"wrote {len(rows)} (snapshot, pin) rows to {out_path}")


def _git_ok(repo: Path, spec: str) -> bool:
    try:
        _git(repo, "cat-file", "-e", spec)
        return True
    except Exception:  # noqa: BLE001
        return False


def _chain(name: str, rdeps: dict[str, set[str]], roots: set[str]) -> list[str] | None:
    """Shortest [root, ..., name] where each package requires the next one."""
    prev: dict[str, str | None] = {name: None}
    q = deque([name])
    while q:
        cur = q.popleft()
        if cur in roots and cur != name:
            path = [cur]
            while prev[path[-1]] is not None:
                path.append(prev[path[-1]])  # type: ignore[arg-type]
            return path
        for p in sorted(rdeps.get(cur, ())):
            if p not in prev:
                prev[p] = cur
                q.append(p)
    return None


def score(path: Path) -> None:
    doc = json.loads(path.read_text())
    pins = [r for r in doc["rows"] if r.get("verdict")]
    findings = [(r["verdict"], len(r["findings"])) for r in pins]
    decided_f = sum(n for v, n in findings if v in ("loaded", "not_loaded"))
    loaded_f = sum(n for v, n in findings if v == "loaded")
    decided_p = sum(1 for r in pins if r["verdict"] in ("loaded", "not_loaded"))
    loaded_p = sum(1 for r in pins if r["verdict"] == "loaded")
    doc["summary"] = {
        "findings_downgraded": sum(n for _, n in findings),
        "findings_undetermined": sum(n for v, n in findings if v == "undetermined"),
        "false_unreached_rate_findings": proportion(loaded_f, decided_f),
        "pins_audited": len(pins),
        "false_unreached_rate_pins": proportion(loaded_p, decided_p),
        "note": "findings in one (snapshot, pin) share a verdict, so the pin-level interval is the honest one",
    }
    path.write_text(json.dumps(doc, indent=1))
    print(json.dumps(doc["summary"], indent=1))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", action="store_true")
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--out", default=str(RESULTS / "reachability_audit.json"))
    a = ap.parse_args()
    if a.evidence:
        evidence(Path(a.out))
    if a.score:
        score(Path(a.out))
    if not (a.evidence or a.score):
        ap.print_help()


if __name__ == "__main__":
    main()
