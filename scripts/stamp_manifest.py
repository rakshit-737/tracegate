#!/usr/bin/env python3
"""Copy a dataset MANIFEST.json into results/ and stamp it with the run that used it.

  python scripts/stamp_manifest.py "$TRACEGATE_DATA/MANIFEST.json" results/data_manifest.json

The data entries are unchanged (url, sha256, bytes, fetch time, repo heads); the top-level keys
run_id / run_url / commit / generated record the GitHub Actions run (nulls when run locally).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

from stats import run_meta  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifest", help="MANIFEST.json written by scripts/download_data.py")
    ap.add_argument("out", help="output path, e.g. results/data_manifest.json")
    a = ap.parse_args()
    src = Path(a.manifest)
    if not src.exists():
        print(f"no manifest at {src}", file=sys.stderr)
        return 1
    data = json.loads(src.read_text())
    meta = {k: v for k, v in run_meta().items() if k in ("run_id", "run_url", "commit", "generated", "generated_at")}
    Path(a.out).write_text(json.dumps({**meta, **data}, indent=2, sort_keys=True))
    print(f"wrote {a.out} ({len(data)} entries, run {meta['run_id']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
