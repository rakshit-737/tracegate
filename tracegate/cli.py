"""tracegate CLI.

  tracegate synth SCENARIO OUT.json        write signed demo events
  tracegate gate EVENTS.json [--comment]   verify, graph, enrich, decide (exit 1 on block)
  tracegate backtrack EVENTS.json QUERY    CVE / package -> origin story + blast radius
  tracegate blast EVENTS.json LAYER_PREFIX layer -> downstream services
  tracegate demo                           run every scenario
  tracegate bench [--services N --deps M]  synthetic scale benchmark

Signing key: env TRACEGATE_KEYID / TRACEGATE_KEY (defaults to the demo key).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import synth
from .backtrack import layer_blast_radius, origin_story
from .pipeline import load_envelopes, run, save_envelopes
from .policy import pr_comment


def _trusted() -> dict[str, bytes]:
    key = os.environ.get("TRACEGATE_KEY")
    return {os.environ.get("TRACEGATE_KEYID", synth.DEMO_KEYID): key.encode() if key else synth.DEMO_KEY}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tracegate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("synth"); s.add_argument("scenario", choices=sorted(synth.SCENARIOS)); s.add_argument("out")
    g = sub.add_parser("gate"); g.add_argument("events"); g.add_argument("--comment", action="store_true")
    b = sub.add_parser("backtrack"); b.add_argument("events"); b.add_argument("query")
    bl = sub.add_parser("blast"); bl.add_argument("events"); bl.add_argument("layer")
    sub.add_parser("demo")
    be = sub.add_parser("bench"); be.add_argument("--services", type=int, default=50); be.add_argument("--deps", type=int, default=100)
    a = ap.parse_args(argv)

    if a.cmd == "synth":
        save_envelopes(synth.signed(synth.SCENARIOS[a.scenario]), a.out)
        print(f"wrote {a.out}")
        return 0
    if a.cmd == "gate":
        res, d = run(load_envelopes(a.events), _trusted())
        print(pr_comment(d) if a.comment else json.dumps(d.to_dict(), indent=2))
        return 1 if d.verdict.value == "block" else 0
    if a.cmd == "backtrack":
        res, _ = run(load_envelopes(a.events), _trusted())
        print(json.dumps(origin_story(res.graph, a.query), indent=2))
        return 0
    if a.cmd == "blast":
        res, _ = run(load_envelopes(a.events), _trusted())
        print(json.dumps(layer_blast_radius(res.graph, a.layer), indent=2))
        return 0
    if a.cmd == "demo":
        for name, sc in synth.SCENARIOS.items():
            res, d = run(synth.signed(sc), _trusted())
            print(f"\n=== scenario: {name} -> {d.verdict.value.upper()}  {res.graph.stats()}")
            for r in d.reasons:
                print(f"  [{r['verdict']}] {r['rule']}: {r.get('msg') or r.get('finding')}"
                      + (f"\n      path: {' -> '.join(r['path'])}" if r.get("path") else ""))
            if name == "cve-origin":
                st = origin_story(res.graph, "CVE-2020-14343")[0]
                print(f"  origin story: introduced by PR #{st['introduced_by']['pr']} "
                      f"({st['introduced_by']['author']}); services affected: {st['blast_radius']['services']}")
            if name == "clean":
                print(f"  base-layer blast radius: {layer_blast_radius(res.graph, synth.BASE_LAYER)['services']}")
        return 0
    if a.cmd == "bench":
        sc = synth.random_scenario(a.services, a.deps)
        envs = synth.signed(sc)
        t0 = time.perf_counter()
        res, d = run(envs, _trusted())
        dt = time.perf_counter() - t0
        raw = [f for f in res.graph.findings if f.source == "trivy"]
        from .enrich import actionable
        act = actionable(raw)
        hi = [f for f in raw if f.severity.rank >= 2]
        print(json.dumps({"events": len(envs), **res.graph.stats(), "gate_seconds": round(dt, 3),
                          "verdict": d.verdict.value, "high_plus_findings": len(hi),
                          "actionable_after_reachability": len(act)}, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
