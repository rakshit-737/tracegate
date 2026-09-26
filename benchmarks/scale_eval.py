#!/usr/bin/env python3
"""Synthetic scale benchmark: gate latency vs pipeline size (clearly synthetic data)."""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tracegate import ids, synth  # noqa: E402
from tracegate.pipeline import run  # noqa: E402

SIZES = [(10, 50), (50, 100), (100, 200), (200, 400)]


def main() -> None:
    rows = []
    for svcs, deps in SIZES:
        envs = synth.signed(synth.random_scenario(svcs, deps))
        lat = []
        for _ in range(3):
            for fn in (ids.canonical_purl, ids.purl, ids.dep_id_from_purl):
                fn.cache_clear()  # cold caches: honest per-run latency
            t0 = time.perf_counter()
            res, d = run(envs, {synth.DEMO_KEYID: synth.DEMO_KEY})
            lat.append(time.perf_counter() - t0)
        rows.append({"services": svcs, "deps": deps, "events": len(envs), **res.graph.stats(),
                     "gate_s_median": round(statistics.median(lat), 3)})
        print(rows[-1])
    out = Path(__file__).resolve().parents[1] / "results"
    out.mkdir(exist_ok=True)
    (out / "scale_synthetic.json").write_text(json.dumps(rows, indent=1))


if __name__ == "__main__":
    main()
