#!/usr/bin/env python3
"""Evidence for adjudicating TRACEGATE-vs-blame disagreements by reading the lock-file diffs.

Takes the disagreements stored in results/lineage_real_repos.json and draws the sample the
adjudication covers: every pip and Go disagreement, plus a uniform random sample (seed 0) of
50 Cargo and npm disagreements. For each case and each distinct candidate commit (TRACEGATE,
blame, both pickaxe variants) it records the commit subject and the lock-file hunks of that
commit that mention the package, plus which versions of the package the file holds before and
after the commit. A person then reads each case and writes the verdict into
results/lineage_adjudication.json (`benchmarks/adjudicate.py --score` computes the accuracies).

  python benchmarks/adjudicate.py --evidence     # needs the repo clones; writes *_evidence.json
  python benchmarks/adjudicate.py --score        # reads the verdicts; writes accuracies + intervals

The correct introducer of X@V at snapshot S is the newest first-parent commit at or before S
whose diff makes X@V appear (it is absent at the commit's first parent and present after it).
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from stats import proportion, run_meta  # noqa: E402

from tracegate.data import data_root  # noqa: E402
from tracegate.gitlineage import _git  # noqa: E402
from tracegate.lockfiles import pin_entries  # noqa: E402

RESULTS = Path(__file__).resolve().parents[1] / "results"
CANDIDATES = ("tracegate", "blame", "pickaxe_package_specific", "pickaxe_version_line")
SAMPLE_CARGO_NPM, SEED = 50, 0


def sample(lineage: dict) -> list[dict]:
    """Every pip/Go disagreement plus a seeded uniform sample of Cargo/npm ones."""
    rows = []
    for r in lineage["repos"]:
        for d in r["disagreements"]:
            rows.append({**d, "repo": r["repo"], "ecosystem": r["ecosystem"],
                         "manifest": r["manifest"]})
    keep = [x for x in rows if x["ecosystem"] in ("pypi", "golang")]
    rest = [x for x in rows if x["ecosystem"] not in ("pypi", "golang")]
    keep += random.Random(SEED).sample(rest, min(SAMPLE_CARGO_NPM, len(rest)))
    return keep


def _hunks(diff: str, needle: str, limit: int = 40) -> list[str]:
    out, cur, hit = [], [], False
    for ln in diff.splitlines():
        if ln.startswith("@@"):
            if hit:
                out += cur
            cur, hit = [ln], False
            continue
        if cur:
            cur.append(ln)
            if needle in ln.lower():
                hit = True
    if hit:
        out += cur
    # keep only the lines near a mention of the package
    keep = set()
    for i, ln in enumerate(out):
        if needle in ln.lower() or ln.startswith("@@"):
            keep.update(range(max(0, i - 2), i + 4))
    return [out[i][:160] for i in sorted(keep) if i < len(out)][:limit]


def _versions(repo: Path, rev: str, path: str, pkg: str) -> list[str] | None:
    try:
        text = _git(repo, "show", f"{rev}:{path}")
    except Exception:  # noqa: BLE001 - file absent at that commit
        return None
    return sorted({e.version for e in pin_entries(path, text) or [] if e.name.lower() == pkg})


def evidence(lineage_path: Path, out_path: Path) -> None:
    lineage = json.loads(lineage_path.read_text())
    cases = sample(lineage)
    for c in cases:
        repo = data_root() / "repos" / c["repo"]
        full = {k: (_git(repo, "rev-parse", c[k]).strip() if c.get(k) else None) for k in ("snapshot", *CANDIDATES)}
        path = c["manifest"]
        c["candidates"] = {}
        for sha in sorted({full[k] for k in CANDIDATES if full.get(k)}):
            parent = _git(repo, "rev-parse", f"{sha}^1").strip()
            diff = _git(repo, "diff", "--unified=2", parent, sha, "--", path)
            needle = c["package"].lower().rsplit("/", 1)[-1]
            c["candidates"][sha[:12]] = {
                "methods": [k for k in CANDIDATES if full.get(k) == sha],
                "subject": _git(repo, "log", "-1", "--format=%s", sha).strip()[:120],
                "date": _git(repo, "log", "-1", "--format=%cs", sha).strip(),
                "versions_at_parent": _versions(repo, parent, path, c["package"]),
                "versions_after": _versions(repo, sha, path, c["package"]),
                "hunks": _hunks(diff, needle)}
        c["versions_at_snapshot"] = _versions(repo, full["snapshot"], path, c["package"])
    out_path.write_text(json.dumps({**run_meta(), "source": lineage_path.name, "source_run_id": lineage.get("run_id"),
                                    "sample_rule": "all pypi+golang disagreements; random.Random(0).sample of 50 "
                                                   "cargo+npm disagreements", "cases": cases}, indent=1))
    print(f"wrote {len(cases)} cases to {out_path}")


def score(verdict_path: Path) -> None:
    doc = json.loads(verdict_path.read_text())
    out: dict = {}
    for group, ecos in (("pypi+golang", ("pypi", "golang")), ("cargo+npm", ("cargo", "npm")),
                        ("all", ("pypi", "golang", "cargo", "npm"))):
        cs = [c for c in doc["cases"] if c["ecosystem"] in ecos and c.get("correct") is not None]
        for m in CANDIDATES:
            ok = sum(1 for c in cs if c.get(m) and c["correct"] and c[m].startswith(c["correct"][:10]))
            out.setdefault(group, {})[m] = proportion(ok, len(cs))
        out[group]["undecided"] = sum(1 for c in doc["cases"] if c["ecosystem"] in ecos and c.get("correct") is None)
    doc["adjudicated_accuracy"] = out
    verdict_path.write_text(json.dumps(doc, indent=1))
    print(json.dumps(out, indent=1))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", action="store_true")
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--lineage", default=str(RESULTS / "lineage_real_repos.json"))
    ap.add_argument("--out", default=str(RESULTS / "lineage_adjudication_evidence.json"))
    ap.add_argument("--verdicts", default=str(RESULTS / "lineage_adjudication.json"))
    a = ap.parse_args()
    if a.evidence:
        evidence(Path(a.lineage), Path(a.out))
    if a.score:
        score(Path(a.verdicts))
    if not (a.evidence or a.score):
        ap.print_help()


if __name__ == "__main__":
    main()
