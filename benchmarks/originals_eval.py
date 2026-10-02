#!/usr/bin/env python3
"""Run the ORIGINAL published typosquat detectors on the exact test splits of typosquat_eval.py.

* TypoGard  : mt3443/typogard `typogard_npm.py` (Taylor et al., NSS 2020), fetched at a pinned
              commit by the benchmarks workflow. Its detection function
              `get_typosquatting_targets` is called unchanged after setting the module's two
              globals (popular list + set) to the same top-N reference TRACEGATE uses; the
              npm-registry dependency walk in its `main()` is not used.
* typomania : rustfoundation/typomania `examples/registry.rs`, built with cargo at a pinned
              commit; names are passed on the command line exactly as the example expects.

For each ecosystem/split dump written by `typosquat_eval.py --dump`, this reports the original
tool's precision/recall on the same positives and negatives, and how often our Python port
(`tracegate/baselines.py`) makes the same flag decision.

Usage: python benchmarks/originals_eval.py --dump DIR --typogard typogard_npm.py --typomania target/release/examples/registry
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bump_oracle import run_meta  # noqa: E402
from typosquat_eval import evaluate  # noqa: E402

PORT = "typomania/TypoGard (top-5k)"


def typogard_flags(src: Path, ref: list[str], names: list[str]) -> set[str]:
    spec = importlib.util.spec_from_file_location("typogard_npm", src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    mod.popular_package_list = list(ref)
    mod.popular_package_set = set(ref)
    return {n for n in names if mod.get_typosquatting_targets(n)}


def typomania_flags(binary: Path, ref: list[str], names: list[str], chunk: int = 1500) -> set[str]:
    out: set[str] = set()
    top = ",".join(r for r in ref if "," not in r)
    for i in range(0, len(names), chunk):
        part = names[i:i + chunk]
        res = subprocess.run([str(binary), "--top-packages", top, "--", *part], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(res.stderr[-2000:])
        for line in res.stdout.splitlines():
            name, sep, squats = line.partition(": ")
            if sep and squats.strip() not in ("", "[]"):
                out.add(name)
    return out


def agreement(a: set[str], b: set[str], universe: list[str]) -> dict:
    same = sum((n in a) == (n in b) for n in universe)
    return {"agree": same, "total": len(universe), "rate": round(same / len(universe), 4) if universe else None,
            "only_original": sorted(a - b)[:15], "only_port": sorted(b - a)[:15],
            "n_only_original": len(a - b), "n_only_port": len(b - a)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", required=True)
    ap.add_argument("--typogard", required=True)
    ap.add_argument("--typomania", required=True)
    ap.add_argument("--typogard-commit", default="")
    ap.add_argument("--typomania-commit", default="")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "results" / "typosquat_originals.json"))
    a = ap.parse_args()
    rows = []
    for f in sorted(Path(a.dump).glob("*.json")):
        d = json.loads(f.read_text())
        pos, neg, typo = set(d["pos"]), set(d["neg"]), set(d["typo"])
        names = sorted(pos | neg)
        port = set(d["port_flags"][PORT])
        row = {"ecosystem": d["ecosystem"], "split": d["split"], "reference_size": len(d["ref"]),
               "positives": len(pos), "negatives": len(neg),
               "port": evaluate({n: n in port for n in names}, pos, neg, typo)}
        for tool, fn, src in (("typogard (original)", typogard_flags, a.typogard),
                              ("typomania (original)", typomania_flags, a.typomania)):
            fl = fn(Path(src), d["ref"], names)
            row[tool] = {**evaluate({n: n in fl for n in names}, pos, neg, typo),
                         "agreement_with_port": agreement(fl, port, names)}
        print(f"[{row['ecosystem']} {row['split']}] port R={row['port']['recall']} "
              f"typogard R={row['typogard (original)']['recall']} agree={row['typogard (original)']['agreement_with_port']['rate']} "
              f"typomania R={row['typomania (original)']['recall']} agree={row['typomania (original)']['agreement_with_port']['rate']}",
              flush=True)
        rows.append(row)
    Path(a.out).write_text(json.dumps({
        **run_meta(),
        "tools": {"typogard": {"repo": "https://github.com/mt3443/typogard", "commit": a.typogard_commit,
                               "entry": "typogard_npm.get_typosquatting_targets (unchanged)"},
                  "typomania": {"repo": "https://github.com/rustfoundation/typomania", "commit": a.typomania_commit,
                                "entry": "cargo build --release --example registry (unchanged)"}},
        "note": ("same reference list, positives and negatives as results/typosquat_<eco>[_time].json; names are "
                 "the benchmark's normalised names (lower case, separators folded to '-') for every tool"),
        "rows": rows}, indent=1))


if __name__ == "__main__":
    main()
