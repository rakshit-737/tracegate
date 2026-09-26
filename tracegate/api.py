"""FastAPI service + lineage explorer UI.

  pip install -e .[api]
  uvicorn tracegate.api:app --port 8080     # then open http://localhost:8080

Endpoints
  POST /v1/gate                 signed envelopes (tracegate or DSSE JSON) -> decision; stores the run
  GET  /v1/runs                 stored run ids
  GET  /v1/runs/{rid}/graph     nodes / edges / findings (UI format)
  GET  /v1/runs/{rid}/backtrack?q=CVE-...|package
  GET  /v1/runs/{rid}/blast?layer=sha256:...
  GET  /v1/runs/{rid}/cypher    Neo4j MERGE script
  POST /v1/demo/{scenario}      run a built-in scenario (clean, cve-origin, ...)
  GET  /                        lineage explorer (static HTML)

The gate decision is the same deterministic policy the CLI uses; the API adds
no ML and no network calls. Runs are kept in memory (bounded LRU).
"""
from __future__ import annotations

import os
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse

from . import synth
from .backtrack import layer_blast_radius, origin_story
from .collector import CollectResult
from .export import to_cypher, to_json
from .models import Decision
from .pipeline import run
from .policy import pr_comment
from .signing import SignatureError, envelope_from_dict

UI = Path(__file__).with_name("ui") / "index.html"
MAX_RUNS = 32

app = FastAPI(title="TRACEGATE", version="0.2.0",
              description="Provenance-aware CI/CD security gate: signed lineage graph, backtracking, policy.")
_runs: OrderedDict[str, tuple[CollectResult, Decision]] = OrderedDict()


def _trusted() -> dict[str, Any]:
    key = os.environ.get("TRACEGATE_KEY")
    return {os.environ.get("TRACEGATE_KEYID", synth.DEMO_KEYID): key.encode() if key else synth.DEMO_KEY}


def _store(res: CollectResult, d: Decision) -> str:
    rid = uuid.uuid4().hex[:12]
    _runs[rid] = (res, d)
    while len(_runs) > MAX_RUNS:
        _runs.popitem(last=False)
    return rid


def _get(rid: str) -> tuple[CollectResult, Decision]:
    if rid not in _runs:
        raise HTTPException(404, f"unknown run {rid}")
    return _runs[rid]


def _summary(rid: str, res: CollectResult, d: Decision) -> dict[str, Any]:
    return {"run": rid, **d.to_dict(), "graph": res.graph.stats(), "coverage": res.coverage,
            "rejected": res.rejected, "comment": pr_comment(d)}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return UI.read_text(encoding="utf-8")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/gate")
def gate(envelopes: list[dict] = Body(...)) -> dict[str, Any]:
    try:
        envs = [envelope_from_dict(e) for e in envelopes]
    except SignatureError as e:  # malformed envelope: fail closed
        raise HTTPException(422, str(e)) from e
    res, d = run(envs, _trusted())
    rid = _store(res, d)
    return _summary(rid, res, d)


@app.post("/v1/demo/{scenario}")
def demo(scenario: str) -> dict[str, Any]:
    if scenario not in synth.SCENARIOS:
        raise HTTPException(404, f"scenarios: {sorted(synth.SCENARIOS)}")
    res, d = run(synth.signed(synth.SCENARIOS[scenario]), {synth.DEMO_KEYID: synth.DEMO_KEY})
    rid = _store(res, d)
    return _summary(rid, res, d)


@app.get("/v1/runs")
def runs() -> list[dict[str, Any]]:
    return [{"run": rid, "verdict": d.verdict.value, **res.graph.stats()} for rid, (res, d) in _runs.items()]


@app.get("/v1/runs/{rid}/graph")
def graph(rid: str) -> dict[str, Any]:
    res, d = _get(rid)
    return {**to_json(res.graph), "decision": d.to_dict()}


@app.get("/v1/runs/{rid}/backtrack")
def backtrack(rid: str, q: str) -> list[dict[str, Any]]:
    return origin_story(_get(rid)[0].graph, q)


@app.get("/v1/runs/{rid}/blast")
def blast(rid: str, layer: str) -> dict[str, list[str]]:
    try:
        return layer_blast_radius(_get(rid)[0].graph, layer)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e


@app.get("/v1/runs/{rid}/cypher", response_class=PlainTextResponse)
def cypher(rid: str) -> str:
    return to_cypher(_get(rid)[0].graph)
