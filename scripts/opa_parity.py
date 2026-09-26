#!/usr/bin/env python3
"""Check that policies/tracegate.rego and the Python policy DSL agree on every demo scenario.

Needs the `opa` binary on PATH (CI installs it). Exit 1 on any disagreement.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tracegate import synth  # noqa: E402
from tracegate.export import opa_input  # noqa: E402
from tracegate.pipeline import run  # noqa: E402

REGO = Path(__file__).resolve().parents[1] / "policies"


def main() -> int:
    opa = shutil.which("opa")
    if not opa:
        print("opa not installed; skipping parity check")
        return 0
    bad = 0
    for name, sc in synth.SCENARIOS.items():
        res, d = run(synth.signed(sc), {synth.DEMO_KEYID: synth.DEMO_KEY})
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(opa_input(res), f)
        out = subprocess.run([opa, "eval", "-f", "json", "-i", f.name, "-d", str(REGO),
                              "data.tracegate.decision.verdict"], capture_output=True, text=True, check=True)
        rego = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
        ok = rego == d.verdict.value
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {name:18s} python={d.verdict.value:5s} rego={rego}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
