"""API token on every route, separate demo store, and malformed envelopes rejected (not 500 / exit 2)."""
import json
from dataclasses import asdict

import pytest

from tracegate import synth
from tracegate.cli import main
from tracegate.collector import Collector
from tracegate.models import Envelope
from tracegate.signing import SignatureError, Verifier, envelope_from_dict

TRUST = {synth.DEMO_KEYID: synth.DEMO_KEY}
BAD = [{"sig": "é"}, {"sig": 12345}, {"keyid": {"a": 1}}, {"payload_type": ["x"]}, {"sig": "DEADBEEF"}]


@pytest.mark.parametrize("change", BAD)
def test_wrongly_typed_fields_are_rejected(change):
    env = asdict(synth.signed(synth.SCENARIOS["clean"])[0])
    with pytest.raises(SignatureError):
        envelope_from_dict({**env, **change})
    res = Collector(Verifier(TRUST)).collect([Envelope(**{**env, **change})])  # built directly, not parsed
    assert res.rejected and ("malformed" in res.rejected[0] or "signature" in res.rejected[0])


def test_non_object_entries_are_rejected():
    for d in (5, [], "x", None):
        with pytest.raises(SignatureError):
            envelope_from_dict(d)


def test_cli_gate_blocks_with_a_reason_on_a_malformed_entry(tmp_path, capsys):
    envs = [asdict(e) for e in synth.signed(synth.SCENARIOS["clean"])]
    envs.append({**envs[0], "sig": "é"})
    p = tmp_path / "ev.json"
    p.write_text(json.dumps(envs))
    assert main(["--demo", "gate", str(p), "--comment"]) == 1
    out = capsys.readouterr().out
    assert "## TRACEGATE: BLOCK" in out and "malformed envelope" in out


def _client(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from tracegate import api
    for k in ("TRACEGATE_KEY", "TRACEGATE_PUBKEY", "TRACEGATE_API_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TRACEGATE_DEMO", "1")
    api._runs.clear()
    api._demo_runs.clear()
    return TestClient(api.app), api


def test_token_guards_every_route(monkeypatch):
    c, _ = _client(monkeypatch)
    rid = c.post("/v1/demo/cve-origin").json()["run"]
    monkeypatch.setenv("TRACEGATE_API_TOKEN", "t0k")
    ok = {"Authorization": "Bearer t0k"}
    routes = [("get", f"/v1/runs/{rid}/graph"), ("get", f"/v1/runs/{rid}/backtrack?q=pyyaml"),
              ("get", f"/v1/runs/{rid}/cypher"), ("get", f"/v1/runs/{rid}/blast?layer=sha256"),
              ("get", "/v1/runs"), ("post", "/v1/demo/clean")]
    for method, url in routes:
        assert getattr(c, method)(url).status_code == 401, url
        assert getattr(c, method)(url, headers={"Authorization": "Bearer nope"}).status_code == 401, url
        assert getattr(c, method)(url, headers={"Authorization": "Bearer é".encode("latin-1")}).status_code == 401, url
        assert getattr(c, method)(url, headers=ok).status_code in (200, 404), url
    env = [asdict(e) for e in synth.signed(synth.SCENARIOS["clean"])]
    assert c.post("/v1/gate", json=env).status_code == 401
    assert c.post("/v1/gate", json=env, headers=ok).status_code == 200


def test_demo_runs_cannot_evict_gate_runs(monkeypatch):
    c, api = _client(monkeypatch)
    env = [asdict(e) for e in synth.signed(synth.SCENARIOS["clean"])]
    rid = c.post("/v1/gate", json=env).json()["run"]
    for _ in range(api.MAX_RUNS + 5):
        assert c.post("/v1/demo/clean").status_code == 200
    assert c.get(f"/v1/runs/{rid}/graph").status_code == 200
    assert len(api._demo_runs) == api.MAX_RUNS


def test_malformed_envelopes_get_422_not_500(monkeypatch):
    c, _ = _client(monkeypatch)
    env = asdict(synth.signed(synth.SCENARIOS["clean"])[0])
    for change in BAD:
        assert c.post("/v1/gate", json=[{**env, **change}]).status_code == 422, change
    assert c.post("/v1/gate", json=[5]).status_code in (422,)
