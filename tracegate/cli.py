"""tracegate CLI.

Demo / synthetic
  tracegate synth SCENARIO OUT.json          write signed demo events
  tracegate demo                             run every scenario
  tracegate bench [--services N --deps M]    synthetic scale benchmark

Real pipelines
  tracegate keygen PREFIX                    Ed25519 keypair -> PREFIX.key / PREFIX.pub
  tracegate ingest --syft S.json [--trivy T.json] [--commit SHA] -o EV.json
                                             sign real Syft / CycloneDX / Trivy output as stage events
  tracegate lineage REPO MANIFEST -o EV.json sign commit events from a repo's pinned-manifest history
  tracegate merge A.json B.json ... -o EV.json

Decide / query
  tracegate gate EV.json [--comment] [--osv PyPI-all.zip] [--top-pypi] [--reach-repo DIR --reach-src SRC ...]
                                             verify, graph, enrich, decide (exit 1 on block)
  tracegate backtrack EV.json QUERY          CVE / package -> origin story + blast radius
  tracegate blast EV.json LAYER_PREFIX       layer -> downstream images / services
  tracegate export EV.json --format cypher|json|opa|intoto
  tracegate serve [--port 8080]              FastAPI + lineage explorer (needs .[api])

Keys: signing uses TRACEGATE_SIGNING_KEY (Ed25519 PEM path) or TRACEGATE_KEY (HMAC secret);
verification trusts TRACEGATE_PUBKEY (Ed25519 PEM path) or TRACEGATE_KEY, under TRACEGATE_KEYID.
With nothing set the gate fails closed (exit 2). The public demo HMAC key is used only with
--demo or TRACEGATE_DEMO=1 (demo, synth and bench always use it).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__, synth
from .backtrack import layer_blast_radius, origin_story
from .collector import Collector
from .enrich import enrich, enrich_static_reachability
from .models import StageEvent
from .pipeline import load_envelopes, run, save_envelopes
from .policy import evaluate, pr_comment
from .signing import Ed25519Signer, Verifier, intoto_statement
from .trust import NoTrustRoot, demo_allowed, keyid, load_signer, load_trust

_DEMO = False  # set from --demo / TRACEGATE_DEMO in main()


def _trusted() -> dict:
    return load_trust(_DEMO)


def _signer():
    return load_signer(_DEMO)


def _report_rejected(res) -> int:
    """Print rejected envelopes to stderr; return 1 if any were rejected."""
    if res.rejected:
        print(f"tracegate: {len(res.rejected)} envelope(s) failed verification and were ignored:",
              file=sys.stderr)
        for r in res.rejected[:10]:
            print(f"  {r}", file=sys.stderr)
        return 1
    return 0


def _warden(a):
    from .warden import HeuristicWarden
    osv = None
    if getattr(a, "osv", None):
        from .osv import OsvIndex
        osv = OsvIndex.from_zip(a.osv)
    popular = None
    if getattr(a, "top_pypi", False):
        from .data import top_pypi
        popular = top_pypi(5000)
    return HeuristicWarden(popular=popular, osv=osv)


def _gate(a):
    res = Collector(Verifier(_trusted())).collect(load_envelopes(a.events))
    enrich(res, _warden(a))
    if getattr(a, "reach_repo", None):
        from .gitlineage import parse_requirements
        from .reach import static_reachability
        repo = Path(a.reach_repo)
        req = (repo / a.reach_manifest).read_text(encoding="utf-8", errors="replace")
        rep = static_reachability(parse_requirements(req), [repo / s for s in a.reach_src], repo, req)
        enrich_static_reachability(res, rep)
    return res, evaluate(res)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the exit code (0 ok, 1 block / rejected envelopes, 2 error)."""
    try:
        return _main(argv)
    except NoTrustRoot as e:
        print(f"tracegate: error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 - one-line errors instead of tracebacks in CI logs
        print(f"tracegate: error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


def _main(argv: list[str] | None = None) -> int:
    global _DEMO
    ap = argparse.ArgumentParser(prog="tracegate", description="Provenance-aware CI/CD security gate")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--demo", action="store_true",
                    help="trust/sign with the PUBLIC demo key (never for real gates); also TRACEGATE_DEMO=1")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")
    _add = sub.add_parser

    def _sub(name: str, **kw):  # every subcommand also accepts --demo after its name
        p = _add(name, **kw)
        p.add_argument("--demo", action="store_true", default=argparse.SUPPRESS,
                       help="same as the global --demo")
        return p

    sub.add_parser = _sub  # type: ignore[method-assign]
    s = sub.add_parser("synth", help="write signed synthetic demo events for a scenario")
    s.add_argument("scenario", choices=sorted(synth.SCENARIOS), help="scenario name")
    s.add_argument("out", help="output events JSON")
    g = sub.add_parser("gate", help="verify, build the graph, enrich and decide (exit 1 on block)")
    g.add_argument("events", help="signed events JSON")
    g.add_argument("--comment", action="store_true", help="print a Markdown PR comment")
    g.add_argument("--osv", help="OSV PyPI-all.zip: flag known-malicious packages")
    g.add_argument("--top-pypi", action="store_true", help="typosquat reference = top-5k PyPI (needs dataset)")
    g.add_argument("--reach-repo", help="repo checkout for static reachability")
    g.add_argument("--reach-src", nargs="*", default=[], help="source dirs/files inside --reach-repo")
    g.add_argument("--reach-manifest", default="requirements.txt", help="manifest inside --reach-repo")
    b = sub.add_parser("backtrack", help="CVE / package -> origin commit/PR and blast radius")
    b.add_argument("events", help="signed events JSON")
    b.add_argument("query", help="CVE id, OSV id or package name")
    bl = sub.add_parser("blast", help="image layer -> downstream images and services")
    bl.add_argument("events", help="signed events JSON")
    bl.add_argument("layer", help="layer digest prefix")
    sub.add_parser("demo", help="run every synthetic scenario")
    be = sub.add_parser("bench", help="synthetic scale benchmark")
    be.add_argument("--services", type=int, default=50, help="number of services")
    be.add_argument("--deps", type=int, default=100, help="dependencies per service")
    k = sub.add_parser("keygen", help="Ed25519 keypair -> PREFIX.key (mode 0600) and PREFIX.pub")
    k.add_argument("prefix", help="output path prefix, e.g. ~/.tracegate/ci")
    ing = sub.add_parser("ingest", help="sign Syft / CycloneDX / Trivy / SARIF output as stage events")
    ing.add_argument("--syft", help="syft -o syft-json output (or CycloneDX with --cyclonedx)")
    ing.add_argument("--cyclonedx", action="store_true", help="--syft file is CycloneDX JSON")
    ing.add_argument("--trivy", action="append", default=[], help="trivy --format json output")
    ing.add_argument("--sarif", action="append", default=[], help="SARIF 2.1.0 (Semgrep/Bandit/CodeQL)")
    ing.add_argument("--commit", help="commit SHA the build / SARIF belongs to")
    ing.add_argument("--build-id", default=None, help="build id (default: derived from the SBOM file)")
    ing.add_argument("--run-id", default=None, help="pipeline run id")
    ing.add_argument("-o", "--out", required=True, help="output events JSON")
    ln = sub.add_parser("lineage", help="sign commit events from a repo's pinned-manifest history")
    ln.add_argument("repo", help="git repository path")
    ln.add_argument("manifest", help="manifest / lock file path inside the repo")
    ln.add_argument("--limit", type=int, default=None, help="max commits to walk")
    ln.add_argument("-o", "--out", required=True, help="output events JSON")
    mg = sub.add_parser("merge", help="concatenate event files")
    mg.add_argument("inputs", nargs="+", help="events JSON files")
    mg.add_argument("-o", "--out", required=True, help="output events JSON")
    ex = sub.add_parser("export", help="export the verified graph")
    ex.add_argument("events", help="signed events JSON")
    ex.add_argument("--format", choices=["cypher", "json", "opa", "intoto"], default="json",
                    help="output format")
    sv = sub.add_parser("serve", help="FastAPI + lineage explorer (needs tracegate[api])")
    sv.add_argument("--host", default="127.0.0.1", help="bind address")
    sv.add_argument("--port", type=int, default=8080, help="port")
    a = ap.parse_args(argv)
    _DEMO = demo_allowed(a.demo)

    if a.cmd == "synth":
        save_envelopes(synth.signed(synth.SCENARIOS[a.scenario]), a.out)
        print(f"wrote {a.out}")
        return 0
    if a.cmd == "gate":
        res, d = _gate(a)
        print(pr_comment(d) if a.comment else json.dumps(d.to_dict(), indent=2))
        _report_rejected(res)
        return 1 if d.verdict.value == "block" else 0
    if a.cmd == "backtrack":
        res, _ = run(load_envelopes(a.events), _trusted())
        stories = origin_story(res.graph, a.query)
        print(json.dumps(stories, indent=2))
        if not stories:
            print(f"tracegate: no match for {a.query}", file=sys.stderr)
        return _report_rejected(res)
    if a.cmd == "blast":
        res, _ = run(load_envelopes(a.events), _trusted())
        print(json.dumps(layer_blast_radius(res.graph, a.layer), indent=2))
        return _report_rejected(res)
    if a.cmd == "keygen":
        sg = Ed25519Signer.generate(keyid())
        prefix = os.path.expanduser(a.prefix)
        Path(prefix).parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(prefix + ".key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(sg.private_pem())
        Path(prefix + ".pub").write_bytes(sg.public_pem())
        print(f"wrote {a.prefix}.key (keep secret, CI only) and {a.prefix}.pub (give to the gate)")
        return 0
    if a.cmd == "ingest":
        from .ingest import cyclonedx_to_build, syft_json_to_build, trivy_json_to_scan
        run_id = a.run_id or f"ingest-{int(time.time())}"
        evs = []
        if a.syft:
            bid = a.build_id or f"build-{Path(a.syft).stem}"
            conv = cyclonedx_to_build if a.cyclonedx else syft_json_to_build
            evs.append(StageEvent("build", run_id, conv(a.syft, bid, commit=a.commit)))
        if a.sarif:
            from .sarif import sarif_to_sast
            if not a.commit:
                ap.error("--sarif needs --commit")
            evs.extend(StageEvent("sast", run_id, sarif_to_sast(s, a.commit)) for s in a.sarif)
        for t in a.trivy:
            evs.append(StageEvent("scan", run_id, trivy_json_to_scan(t)))
        sg = _signer()
        save_envelopes([sg.sign(e) for e in evs], a.out)
        print(f"wrote {len(evs)} signed event(s) to {a.out}")
        return 0
    if a.cmd == "lineage":
        from .gitlineage import commit_events, manifest_history
        hist = manifest_history(a.repo, a.manifest, limit=a.limit)
        if not hist:
            print(f"tracegate: error: no pinned history for {a.manifest} in {a.repo}", file=sys.stderr)
            return 2
        sg = _signer()
        save_envelopes([sg.sign(e) for e in commit_events(hist, a.manifest)], a.out)
        print(f"wrote {len(hist)} signed commit event(s) to {a.out}")
        return 0
    if a.cmd == "merge":
        envs = [e for p in a.inputs for e in load_envelopes(p)]
        save_envelopes(envs, a.out)
        print(f"wrote {len(envs)} envelope(s) to {a.out}")
        return 0
    if a.cmd == "export":
        from .export import opa_input, to_cypher, to_json
        envs = load_envelopes(a.events)
        res, _ = run(envs, _trusted())
        if res.rejected and a.format == "intoto":
            return _report_rejected(res)
        if a.format == "cypher":
            print(to_cypher(res.graph), end="")
        elif a.format == "json":
            print(json.dumps(to_json(res.graph), indent=1))
        elif a.format == "opa":
            print(json.dumps(opa_input(res), indent=1))
        else:
            v = Verifier(_trusted())
            builds = [ev.payload for ev in (v.verify(e) for e in envs) if ev.stage == "build"]
            print(json.dumps([intoto_statement(bp) for bp in builds], indent=1))
        return _report_rejected(res)
    if a.cmd == "serve":
        try:
            import uvicorn
        except ImportError:
            print("tracegate serve needs: pip install 'tracegate[api]'", file=sys.stderr)
            return 2
        if _DEMO:
            os.environ["TRACEGATE_DEMO"] = "1"
        load_trust(_DEMO)  # refuse to start without a trust root
        uvicorn.run("tracegate.api:app", host=a.host, port=a.port)
        return 0
    if a.cmd == "demo":
        for name, sc in synth.SCENARIOS.items():
            res, d = run(synth.signed(sc), {synth.DEMO_KEYID: synth.DEMO_KEY})
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
        from .enrich import actionable
        sc = synth.random_scenario(a.services, a.deps)
        envs = synth.signed(sc)
        t0 = time.perf_counter()
        res, d = run(envs, {synth.DEMO_KEYID: synth.DEMO_KEY})
        dt = time.perf_counter() - t0
        raw = [f for f in res.graph.findings if f.source == "trivy"]
        act = actionable(raw)
        hi = [f for f in raw if f.severity.rank >= 2]
        print(json.dumps({"events": len(envs), **res.graph.stats(), "gate_seconds": round(dt, 3),
                          "verdict": d.verdict.value, "high_plus_findings": len(hi),
                          "actionable_after_reachability": len(act)}, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
