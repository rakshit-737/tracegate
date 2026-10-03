#!/usr/bin/env python3
"""Read the Sigstore bundles next to each artefact, fetch the Rekor entry by logIndex from the
public log, and assert it records this artefact's sha256 and was integrated after signing.

Usage: python scripts/rekor_evidence.py DIST_DIR OUT.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

REKOR = "https://rekor.sigstore.dev/api/v1/log/entries?logIndex={}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dist", help="directory holding the artefacts and their <artefact>.sigstore.json bundles")
    ap.add_argument("out", help="evidence JSON to write")
    a = ap.parse_args()
    dist, out = Path(a.dist), Path(a.out)
    rows = []
    for b in sorted(dist.glob("*.sigstore.json")):
        art = b.with_name(b.name[: -len(".sigstore.json")])
        digest = hashlib.sha256(art.read_bytes()).hexdigest()
        bundle = json.loads(b.read_text())
        tlog = bundle["verificationMaterial"]["tlogEntries"][0]
        idx = int(tlog["logIndex"])
        with urllib.request.urlopen(REKOR.format(idx), timeout=30) as r:
            entry = next(iter(json.load(r).values()))
        body = json.loads(base64.b64decode(entry["body"]))
        spec = body["spec"]
        recorded = spec.get("data", {}).get("hash", {}).get("value")  # hashedrekord
        assert recorded == digest, f"{art.name}: Rekor entry {idx} records {recorded}, file is {digest}"
        assert int(entry["integratedTime"]) == int(tlog["integratedTime"]), f"{art.name}: integratedTime mismatch"
        rows.append({"artifact": art.name, "sha256": digest, "rekor_log_index": idx,
                     "rekor_kind": body.get("kind"), "integrated_time": int(entry["integratedTime"]),
                     "rekor_url": f"https://search.sigstore.dev/?logIndex={idx}"})
        print(f"{art.name}: Rekor logIndex {idx} records sha256 {digest[:16]}... OK")
    if not rows:
        print("no bundles found", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"issuer": "https://token.actions.githubusercontent.com", "entries": rows}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
