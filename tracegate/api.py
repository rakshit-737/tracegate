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

Trust: the same roots as the CLI (TRACEGATE_PUBKEY Ed25519 and/or TRACEGATE_KEY HMAC under
TRACEGATE_KEYID). With none configured /v1/gate answers 503 (fail closed); the public demo
key is trusted only with TRACEGATE_DEMO=1. Limits: request bodies over TRACEGATE_MAX_BODY
bytes (default 10 MB) get 413, more than MAX_ENVELOPES envelopes get 413. If
TRACEGATE_API_TOKEN is set, /v1/gate and /v1/runs* require `Authorization: Bearer <token>`.
"""
from __future__ import annotations

import os
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from . import __version__, synth
from .backtrack import layer_blast_radius, origin_story
from .collector import CollectResult
from .export import to_cypher, to_json
from .models import Decision
from .pipeline import run
from .policy import pr_comment
from .signing import SignatureError, envelope_from_dict

UI = Path(__file__).with_name("ui") / "index.html"
MAX_RUNS = 32
MAX_ENVELOPES = 5000
MAX_BODY = int(os.environ.get("TRACEGATE_MAX_BODY", 10 * 1024 * 1024))

app = FastAPI(title="TRACEGATE", version=__version__,
              description="Provenance-aware CI/CD security gate: signed lineage graph, backtracking, policy.")
_runs: OrderedDict[str, tuple[CollectResult, Decision]] = OrderedDict()


class _BodyLimit:
    """ASGI middleware: 413 for bodies over MAX_BODY (declared Content-Length or streamed bytes)."""

    def __init__(self, app_: Any):
        self.app = app_

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        for k, v in scope.get("headers", []):
            if k == b"content-length" and v.isdigit() and int(v) > MAX_BODY:
                return await JSONResponse({"detail": f"body over {MAX_BODY} bytes"}, 413)(scope, receive, send)
        seen = 0

        async def limited() -> dict:
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > MAX_BODY:
                    raise HTTPException(413, f"body over {MAX_BODY} bytes")
            return msg
        await self.app(scope, limited, send)


app.add_middleware(_BodyLimit)


def _auth(authorization: str | None) -> None:
    token = os.environ.get("TRACEGATE_API_TOKEN")
    if token and authorization != f"Bearer {token}":
        raise HTTPException(401, "missing or wrong bearer token")


def _trusted() -> dict[str, Any]:
    """Shared fail-closed trust roots (see tracegate.trust); 503 when none configured."""
    from .trust import NoTrustRoot, load_trust
    try:
        return load_trust()
    except NoTrustRoot as e:
        raise HTTPException(503, str(e)) from e


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
    """Liveness probe."""
    return {"status": "ok"}


@app.post("/v1/gate")
def gate(envelopes: list[dict] = Body(...), authorization: str | None = Header(None)) -> dict[str, Any]:
    """Verify signed envelopes, build the graph, decide; stores the run and returns the summary."""
    _auth(authorization)
    if len(envelopes) > MAX_ENVELOPES:
        raise HTTPException(413, f"more than {MAX_ENVELOPES} envelopes")
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
def runs(authorization: str | None = Header(None)) -> list[dict[str, Any]]:
    """Stored runs with verdict and graph size."""
    _auth(authorization)
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
