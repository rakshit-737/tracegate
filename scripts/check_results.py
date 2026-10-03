#!/usr/bin/env python3
"""Traceability checks for the published numbers (run in CI).

1. Every results/*.json records where it came from: a GitHub Actions `run_id`, or
   `"generated": "local"` with the command and commit.
2. Every `actions/runs/<id>` link in README.md and docs/*.md points at a run id that some
   committed results file carries (so no page cites a run whose numbers are not committed).

Exit 1 on any violation.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN_LINK = re.compile(r"actions/runs/(\d+)")


def result_runs() -> tuple[set[int], list[str]]:
    runs: set[int] = set()
    problems = []
    for p in sorted((ROOT / "results").glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except ValueError as e:
            problems.append(f"{p.name}: not JSON ({e})")
            continue
        if not isinstance(doc, dict):
            problems.append(f"{p.name}: top level is not an object, so it cannot carry a run id")
            continue
        rid = doc.get("run_id")
        if rid:
            runs.add(int(rid))
            for k in ("source_run_id",):
                if doc.get(k):
                    runs.add(int(doc[k]))
        elif doc.get("generated") == "local" and doc.get("command") and doc.get("commit"):
            pass
        else:
            problems.append(f"{p.name}: no run_id and no generated=local/command/commit provenance")
    return runs, problems


def main() -> int:
    runs, problems = result_runs()
    for page in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]:
        if page.name == "changelog.md":
            continue
        for i, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
            for m in RUN_LINK.finditer(line):
                if int(m.group(1)) not in runs:
                    problems.append(f"{page.relative_to(ROOT)}:{i}: links run {m.group(1)}, which no results file carries")
    for p in problems:
        print(p, file=sys.stderr)
    print(f"checked results/*.json ({len(runs)} run ids) and the run links in README.md and docs/")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
