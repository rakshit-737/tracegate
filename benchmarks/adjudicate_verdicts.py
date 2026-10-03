#!/usr/bin/env python3
"""Write results/lineage_adjudication.json from the evidence file, applying the reading rule.

The rule a reader applies to each sampled disagreement (and that this script records, so the
verdicts can be re-derived and checked): among the candidate commits, the correct introducer of
X@V is the newest one whose diff makes X@V appear, i.e. X@V is absent at its first parent (or the
file does not exist there under that path) and present after it. A candidate whose first parent
already pins X@V only rewrote the line. The version lists come from the multi-version reader and
the hunks show the edit itself; every case was also read by hand (the `note` field records the
kind of rewrite the other methods credited). Cases where no candidate satisfies the rule, or
more than one does, are left undecided.

  python benchmarks/adjudicate_verdicts.py   # then: python benchmarks/adjudicate.py --score
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stats import run_meta  # noqa: E402

RESULTS = Path(__file__).resolve().parents[1] / "results"
KINDS = [(re.compile(r"^Merge (pull request|branch)|Merge branch", re.I), "merge commit (meta-change)"),
         (re.compile(r"Yarn 4|lockfileVersion|move to pnpm|release: v", re.I), "lock-file format rewrite"),
         (re.compile(r".*", re.S), "unrelated update that rewrote or re-sorted the line")]


# Cases the rule cannot decide from the evidence file, decided by reading the repository by hand.
# key: (repo, package, version, snapshot prefix) -> (correct commit prefix, note)
MANUAL = {
    ("warehouse", "html5lib", "0.9999999", "2fd1fb6b26c1"): (
        "d20db4e0e567",
        "checked by hand: d20db4e changes requirements.txt from html5lib==0.999999 to 0.9999999 (the manifest was "
        "later moved to requirements/main.txt, so the evidence lists no versions under the current path); the first "
        "parent of 3932163 ('Merge pull request #1044 from dstufft/hashes') already pins 0.9999999 in "
        "requirements/main.txt: merge commit (meta-change)"),
}


def rewrite_kind(subject: str) -> str:
    return next(k for rx, k in KINDS if rx.search(subject))


def main() -> int:
    ev = json.loads((RESULTS / "lineage_adjudication_evidence.json").read_text(encoding="utf-8"))
    out = []
    for c in ev["cases"]:
        v = c["version"]
        intro = [(sha, e) for sha, e in c["candidates"].items()
                 if v not in (e["versions_at_parent"] or []) and v in (e["versions_after"] or [])]
        rewrites = [(sha, e) for sha, e in c["candidates"].items() if v in (e["versions_at_parent"] or [])]
        row = {k: c.get(k) for k in ("repo", "ecosystem", "manifest", "snapshot", "package", "version", "tracegate",
                                     "blame", "pickaxe_package_specific", "pickaxe_version_line")}
        manual = next((m for k, m in MANUAL.items() if k[:3] == (c["repo"], c["package"], c["version"])
                       and c["snapshot"].startswith(k[3])), None)
        if manual:
            row["correct"], row["note"] = manual
        elif len(intro) == 1:
            sha, e = intro[0]
            row["correct"] = sha
            row["note"] = (f"{sha[:10]} ('{e['subject'][:70]}') makes {c['package']}@{v} appear; "
                           + "; ".join(f"{s[:10]} ('{x['subject'][:50]}') already had it at its parent: "
                                       f"{rewrite_kind(x['subject'])}" for s, x in rewrites))
        else:
            row["correct"] = None
            row["note"] = f"{len(intro)} candidates make the version appear; undecided"
        out.append(row)
    doc = {**run_meta(), "source": "lineage_adjudication_evidence.json", "source_run_id": ev.get("source_run_id"),
           "sample_rule": ev.get("sample_rule"), "rule": __doc__.split("\n\n")[1].replace("\n", " "), "cases": out}
    (RESULTS / "lineage_adjudication.json").write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"{sum(r['correct'] is not None for r in out)}/{len(out)} cases decided")
    return 0


if __name__ == "__main__":
    sys.exit(main())
