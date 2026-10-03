#!/usr/bin/env python3
"""Check that policies/tracegate.rego and the Python policy DSL agree on every demo scenario.

Besides the six demo scenarios it checks two extra cases: a HIGH and a LOW scanner finding on a
package that is not in the SBOM (rule `unattributed_finding`).

Needs the `opa` binary on PATH (CI installs it). Exit 1 on any disagreement, and also when `opa`
is missing and CI=true or --require-opa is given (so a CI job cannot pass without checking).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tracegate import synth  # noqa: E402
from tracegate.export import opa_input  # noqa: E402
from tracegate.models import StageEvent  # noqa: E402
from tracegate.pipeline import run  # noqa: E402
from tracegate.signing import HmacSigner  # noqa: E402

REGO = Path(__file__).resolve().parents[1] / "policies"


def _with_unmatched(severity: str) -> list:
    evs = synth.events(synth.SCENARIOS["clean"])
    evs.append(StageEvent("scan", "run-extra", {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-2099-0001", "PkgName": "not-in-sbom", "InstalledVersion": "1.0.0",
         "Severity": severity, "Title": "finding on a package the SBOM does not list"}]}]}))
    s = HmacSigner(synth.DEMO_KEYID, synth.DEMO_KEY)
    return [s.sign(e) for e in evs]


def cases() -> dict[str, list]:
    """Scenario name -> signed envelopes."""
    out = {name: synth.signed(sc) for name, sc in synth.SCENARIOS.items()}
    out["unattributed-high"] = _with_unmatched("HIGH")
    out["unattributed-low"] = _with_unmatched("LOW")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--require-opa", action="store_true", help="fail when opa is not installed")
    a = ap.parse_args()
    opa = shutil.which("opa")
    if not opa:
        if a.require_opa or os.environ.get("CI") == "true":
            print("opa not installed: parity not checked", file=sys.stderr)
            return 1
        print("opa not installed; skipping parity check")
        return 0
    bad = 0
    for name, envs in cases().items():
        res, d = run(envs, {synth.DEMO_KEYID: synth.DEMO_KEY})
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(opa_input(res), f)
        out = subprocess.run([opa, "eval", "-f", "json", "-i", f.name, "-d", str(REGO),
                              "data.tracegate.decision"], capture_output=True, text=True, check=True)
        rego = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
        rules_py = sorted({r["rule"] for r in d.reasons})
        rules_rego = sorted({r["rule"] for r in rego["reasons"]})
        ok = rego["verdict"] == d.verdict.value and rules_py == rules_rego
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {name:18s} python={d.verdict.value:5s} rego={rego['verdict']:5s} "
              f"rules={rules_py}" + ("" if ok else f" rego_rules={rules_rego}"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
