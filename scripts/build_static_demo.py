"""Build the static lineage-explorer demo for the docs site (docs/demo/).

Runs the six synthetic spec scenarios through the real pipeline and writes, per scenario,
the API responses the UI needs (summary, graph, and backtrack answers for every CVE,
finding id and package name in the graph). The UI's static mode reads these files, so the
demo works on GitHub Pages without a server.

    python scripts/build_static_demo.py [--out docs/demo]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracegate import synth  # noqa: E402
from tracegate.backtrack import origin_story  # noqa: E402
from tracegate.export import to_json  # noqa: E402
from tracegate.pipeline import run  # noqa: E402
from tracegate.policy import pr_comment  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "docs" / "demo"))
    out = Path(ap.parse_args().out)
    (out / "data").mkdir(parents=True, exist_ok=True)
    html = (ROOT / "tracegate" / "ui" / "index.html").read_text(encoding="utf-8")
    html = html.replace('<html lang="en">', '<html lang="en" data-static="1">', 1)
    (out / "index.html").write_text(html, encoding="utf-8")
    for name, sc in synth.SCENARIOS.items():
        res, d = run(synth.signed(sc), {synth.DEMO_KEYID: synth.DEMO_KEY})
        g = res.graph
        queries = set()
        for f in g.findings:
            queries |= {(f.cve or "").lower(), f.id.lower(), str(g.nodes[f.node_id].attrs.get("name", "")).lower()}
        queries.discard("")
        doc = {"summary": {"run": name, **d.to_dict(), "graph": g.stats(), "coverage": res.coverage,
                           "rejected": res.rejected, "comment": pr_comment(d)},
               "graph": {**to_json(g), "decision": d.to_dict()},
               "backtrack": {q: origin_story(g, q) for q in sorted(queries)}}
        (out / "data" / f"{name}.json").write_text(json.dumps(doc, separators=(",", ":"), default=str),
                                                  encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
