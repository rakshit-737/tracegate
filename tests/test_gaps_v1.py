"""SARIF adapter and lock-file lineage (v1.0 gap closures)."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tracegate import synth
from tracegate.lockfiles import ecosystem_for, parse_manifest, parse_package_lock, parse_toml_packages
from tracegate.models import StageEvent
from tracegate.pipeline import run
from tracegate.sarif import sarif_to_sast
from tracegate.signing import HmacSigner

FIX = Path(__file__).parent / "fixtures"


def test_sarif_severity_and_files():
    p = sarif_to_sast(FIX / "bandit.sarif", commit="a" * 40)
    assert p["tool"] == "Bandit"
    got = {(f["rule"], f["severity"], f["file"]) for f in p["findings"]}
    assert got == {("B602", "high", "app/run.py"), ("B101", "low", "tests/test_x.py"),
                   ("py/sql-injection", "critical", "app/db.py")}


def test_sarif_feeds_collector_and_policy():
    sha = "b" * 40
    evs = [StageEvent("commit", "r1", {"sha": sha, "author": "a", "pr": 1, "message": "m", "seq": 0,
                                        "files": ["app/run.py"], "deps_added": [], "deps_removed": []}),
           StageEvent("sast", "r1", sarif_to_sast(FIX / "bandit.sarif", sha))]
    s = HmacSigner(synth.DEMO_KEYID, synth.DEMO_KEY)
    envs = [s.sign(e) for e in evs]
    res, decision = run(envs, {synth.DEMO_KEYID: synth.DEMO_KEY})
    sev = sorted(f.severity.value for f in res.graph.findings if f.source == "sast")
    assert sev == ["critical", "high", "low"]
    assert decision.verdict.value == "block"


def test_package_lock_v3_and_v1():
    v3 = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.21"},
        "node_modules/a/node_modules/Debug": {"version": "4.3.4"},
        "node_modules/local": {"link": True}}})
    assert parse_package_lock(v3) == {"lodash": "4.17.21", "debug": "4.3.4"}
    v1 = json.dumps({"lockfileVersion": 1, "dependencies": {
        "chalk": {"version": "5.3.0", "dependencies": {"ansi": {"version": "1.0.0"}}}}})
    assert parse_package_lock(v1) == {"chalk": "5.3.0", "ansi": "1.0.0"}


def test_poetry_and_uv_lock():
    text = '''version = 1
[[package]]
name = "Requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
]

[package.optional-dependencies]
socks = [{ name = "pysocks", version = "9" }]

[[package]]
name = "PyYAML"
version = "6.0.1"
'''
    assert parse_toml_packages(text) == {"requests": "2.32.3", "pyyaml": "6.0.1"}
    assert parse_manifest("sub/uv.lock", text) == parse_manifest("poetry.lock", text)
    assert parse_manifest("requirements.txt", "flask==3.0.0\n") == {"flask": "3.0.0"}
    assert ecosystem_for("web/package-lock.json") == "npm" and ecosystem_for("uv.lock") == "pypi"


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_lineage_over_package_lock(tmp_path):
    from tracegate.gitlineage import commit_events, manifest_history

    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    lock = tmp_path / "package-lock.json"
    for i, pk in enumerate([{"node_modules/lodash": {"version": "4.17.20"}},
                            {"node_modules/lodash": {"version": "4.17.21"},
                             "node_modules/chalk": {"version": "5.3.0"}}]):
        lock.write_text(json.dumps({"lockfileVersion": 3, "packages": pk}))
        git("add", ".")
        git("commit", "-q", "-m", f"bump deps (#{i + 10})")
    hist = manifest_history(tmp_path, "package-lock.json")
    assert [h.pr for h in hist] == [10, 11]
    assert hist[1].added == {"lodash": "4.17.21", "chalk": "5.3.0"}
    ev = commit_events(hist, "package-lock.json")[1]
    assert {d["ecosystem"] for d in ev.payload["deps_added"]} == {"npm"}
