import json
from dataclasses import replace

import pytest

from tracegate import synth
from tracegate.backtrack import layer_blast_radius, origin_story
from tracegate.cli import main
from tracegate.graph import CycleError, ProvenanceGraph
from tracegate.ids import dep_id
from tracegate.models import Node, NodeKind, Verdict
from tracegate.pipeline import load_envelopes, run
from tracegate.policy import pr_comment
from tracegate.signing import SignatureError, Verifier
from tracegate.warden import HeuristicWarden, WardenScore

TRUST = {synth.DEMO_KEYID: synth.DEMO_KEY}


def gate(name, **kw):
    return run(synth.signed(synth.SCENARIOS[name]), TRUST, **kw)


# --- identity / graph ---------------------------------------------------
def test_content_address_is_stable_and_normalised():
    assert dep_id("PyYAML", "5.3") == dep_id("pyyaml", "5.3")
    assert dep_id("pyyaml", "5.3") != dep_id("pyyaml", "5.4")


def test_graph_rejects_cycles():
    g = ProvenanceGraph()
    for n in "abc":
        g.add_node(Node(n, NodeKind.BUILD, n))
    g.add_edge("a", "b", "x")
    g.add_edge("b", "c", "x")
    with pytest.raises(CycleError):
        g.add_edge("c", "a", "x")


def test_same_dependency_is_one_node_across_stages():
    res, _ = gate("cve-origin")
    deps = [n for n in res.graph.of_kind(NodeKind.DEPENDENCY) if n.attrs["name"] == "pyyaml"]
    assert len(deps) == 1
    assert "import_name" in deps[0].attrs  # merged from SBOM stage


# --- signing / fail-closed --------------------------------------------------
def test_signature_roundtrip_and_forgery():
    env = synth.signed(synth.SCENARIOS["clean"])[0]
    v = Verifier(TRUST)
    assert v.verify(env).stage == "commit"
    with pytest.raises(SignatureError):
        v.verify(replace(env, payload=env.payload.replace("a1b2", "ffff")))
    with pytest.raises(SignatureError):
        v.verify(replace(env, keyid="attacker"))
    with pytest.raises(SignatureError):
        v.verify(replace(env, sig=""))


def test_wrong_key_signed_events_block():
    envs = synth.signed(synth.SCENARIOS["clean"], key=b"attacker-key")
    res, d = run(envs, TRUST)
    assert d.verdict == Verdict.BLOCK
    assert res.graph.stats()["nodes"] == 0


def test_tampered_scan_blocks():
    _, d = gate("tampered")
    assert d.verdict == Verdict.BLOCK
    assert any("signature mismatch" in r.get("msg", "") for r in d.reasons)


def test_missing_stage_fails_closed():
    _, d = gate("unsigned-missing")
    assert d.verdict == Verdict.BLOCK
    assert "scan" in d.reasons[0]["msg"]


# --- demo scenarios ---------------------------------------------------------
def test_clean_passes():
    _, d = gate("clean")
    assert d.verdict == Verdict.PASS and d.reasons == []


def test_typosquat_blocked_with_commit_path():
    _, d = gate("malicious-dep")
    assert d.verdict == Verdict.BLOCK
    r = next(r for r in d.reasons if r["rule"] == "malicious_dependency")
    assert r["path"][0].startswith("commit:") and "reqeusts" in r["path"][-1]


def test_reachable_cve_blocks_and_unreachable_downgrades():
    res, d = gate("cve-origin")
    assert d.verdict == Verdict.BLOCK
    assert res.graph.findings[0].reachable is True
    res, d = gate("unreachable")
    assert d.verdict == Verdict.WARN
    assert res.graph.findings[0].reachable is False
    assert "not loaded" in res.graph.findings[0].evidence[0]


def test_unknown_reachability_stays_conservative():
    sc = replace(synth.SCENARIOS["cve-origin"], loaded={})
    res, d = run(synth.signed(sc), TRUST)
    assert res.graph.findings[0].reachable is None
    assert d.verdict == Verdict.BLOCK


def test_origin_story_and_blast_radius():
    res, _ = gate("cve-origin")
    [st] = origin_story(res.graph, "CVE-2020-14343")
    assert st["introduced_by"]["pr"] == 42
    assert st["blast_radius"]["services"] == ["api", "web", "worker"]
    assert len(st["builds"]) == 3
    assert origin_story(res.graph, "pyyaml")  # query by package name
    assert origin_story(res.graph, "CVE-0000-0000") == []


def test_base_layer_blast_radius():
    res, _ = gate("clean")
    assert layer_blast_radius(res.graph, synth.BASE_LAYER[:20])["services"] == ["api", "web", "worker"]


def test_pluggable_warden():
    class Deny:
        def score(self, name, version):
            return WardenScore(name, version, 0.99 if name == "flask" else 0.0, ["intel hit"])
    _, d = gate("clean", warden=Deny())
    assert d.verdict == Verdict.BLOCK


def test_heuristic_warden():
    w = HeuristicWarden()
    assert w.score("requests", "1").risk == 0.0
    assert w.score("reqeusts", "1").risk >= 0.8
    assert w.score("totally-unrelated-lib", "1").risk < 0.5


def test_sast_high_blocks():
    sc = replace(synth.SCENARIOS["clean"], sast=[
        {"file": "app/main.py", "rule": "B602", "severity": "HIGH", "title": "shell=True"}])
    _, d = run(synth.signed(sc), TRUST)
    assert d.verdict == Verdict.BLOCK
    assert "app/main.py" in d.reasons[0]["path"][-1]


def test_pr_comment_renders():
    _, d = gate("malicious-dep")
    c = pr_comment(d)
    assert "BLOCK" in c and "reqeusts" in c


# --- CLI / IO ---------------------------------------------------------------
def test_cli_roundtrip(tmp_path, capsys):
    p = tmp_path / "ev.json"
    assert main(["synth", "cve-origin", str(p)]) == 0
    assert main(["gate", str(p)]) == 1
    capsys.readouterr()
    assert main(["backtrack", str(p), "CVE-2020-14343"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out[0]["introduced_by"]["pr"] == 42
    assert main(["synth", "clean", str(p)]) == 0
    assert main(["gate", str(p), "--comment"]) == 0


def test_malformed_envelope_file_fails(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps([{"payload": "x"}]))
    with pytest.raises(SignatureError):
        load_envelopes(p)


def test_bench_scale():
    sc = synth.random_scenario(30, 80, seed=1)
    res, d = run(synth.signed(sc), TRUST)
    assert res.graph.stats()["nodes"] > 100
    assert not res.rejected
