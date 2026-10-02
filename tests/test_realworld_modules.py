"""Tests for the real-data modules, using small committed fixtures only."""
import json
import subprocess
from pathlib import Path

import pytest

from tracegate.backtrack import origin_story
from tracegate.collector import Collector
from tracegate.enrich import enrich_static_reachability, enrich_warden
from tracegate.export import opa_input, to_cypher, to_json
from tracegate.gitlineage import (
    blame_introducers,
    commit_events,
    direct_deps_from_pip_compile,
    manifest_history,
    materialize,
    parse_requirements,
)
from tracegate.ids import canonical_purl, dep_id, dep_id_from_purl
from tracegate.models import StageEvent, Verdict
from tracegate.osv import OsvIndex, cvss3_base, mal_mentions_typosquat
from tracegate.policy import evaluate
from tracegate.reach import app_imports, import_names, static_reachability, via_graph
from tracegate.signing import HmacSigner, SignatureError, Verifier, from_dsse_json, intoto_statement, to_dsse_json
from tracegate.typosquat import TyposquatDetector, damerau, normalize
from tracegate.warden import HeuristicWarden, MultiWarden

FIX = Path(__file__).parent / "fixtures"
KEY = {"k": b"test-key"}


# --- identity -------------------------------------------------------------------
def test_canonical_purl_drops_qualifiers_and_normalises():
    assert canonical_purl("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12") == \
        "pkg:deb/debian/libssl3@3.0.11-1~deb12u2"
    assert canonical_purl("pkg:pypi/PyYAML@5.3") == "pkg:pypi/pyyaml@5.3"
    assert canonical_purl("pkg:pypi/Django_Filter@2.0") == "pkg:pypi/django-filter@2.0"
    assert canonical_purl("pkg:npm/%40types/Node@1.0.0") == "pkg:npm/@types/node@1.0.0"
    assert dep_id("PyYAML", "5.3") == dep_id_from_purl("pkg:pypi/pyyaml@5.3?extra=x")


# --- typosquat ---------------------------------------------------------------------
@pytest.fixture(scope="module")
def det():
    return TyposquatDetector(["requests", "numpy", "python-dateutil", "cross-env", "urllib3",
                              "django", "beautifulsoup4", "colorama"])


@pytest.mark.parametrize("name,target,tech", [
    ("reqeusts", "requests", "typo1"),
    ("crossenv", "cross-env", "separator"),
    ("dateutil-python", "python-dateutil", "reorder"),
    ("requests-py", "requests", "combosquat"),
    ("reque5ts", "requests", "homoglyph"),
    ("colorama2", "colorama", "typo1"),
])
def test_typosquat_techniques(det, name, target, tech):
    m = det.score(name)
    assert m.target == target and m.technique == tech and m.score > 0.5


def test_typosquat_known_and_unrelated(det):
    assert det.score("Requests").score == 0.0  # normalised popular name
    assert det.score("totally-unrelated-lib").score == 0.0
    assert normalize("Python_DateUtil") == "python-dateutil"
    assert damerau("abcd", "abdc") == 1 and damerau("abc", "xyz") == 3


def test_more_popular_target_scores_higher():
    d = TyposquatDetector(["aaaaaaa", *[f"filler{i}" for i in range(500)], "bbbbbbb"])
    assert d.score("aaaaaab").score > d.score("bbbbbba").score


# --- OSV -------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def osv():
    return OsvIndex.from_records(json.loads((FIX / "osv_sample.json").read_text()))


def test_osv_vulns_and_severity_from_alias(osv):
    vs = osv.vulns("PyYAML", "5.3")
    assert {v.cve for v in vs} == {"CVE-2020-14343"}
    assert all(v.severity == "CRITICAL" for v in vs)  # PYSEC record inherits GHSA severity
    assert osv.vulns("pyyaml", "6.0.1") == []
    assert osv.malicious("pymocks") and not osv.malicious("pyyaml")


def test_osv_scan_payload_shape(osv):
    p = osv.scan_payload([("pyyaml", "5.3"), ("flask", "3.0.0")])
    vs = p["Results"][0]["Vulnerabilities"]
    assert vs and vs[0]["PURL"] == "pkg:pypi/pyyaml@5.3" and vs[0]["Severity"] == "CRITICAL"


def test_malicious_lookup_is_version_aware():
    # shapes copied from real ossf/malicious-packages records (MAL-2025-46969, MAL-2022-4933)
    recs = [
        {"id": "MAL-2025-46969", "affected": [{"package": {"name": "chalk", "ecosystem": "npm"},
                                               "versions": ["5.6.1"]}]},
        {"id": "MAL-2022-4933", "affected": [{"package": {"name": "npm-cli-docs", "ecosystem": "npm"},
                                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
    ]
    idx = OsvIndex.from_records(recs, "npm")
    assert idx.malicious("chalk", "5.6.1") and not idx.malicious("chalk", "2.4.1")
    assert idx.malicious("npm-cli-docs", "0.1.0") and idx.malicious("chalk")  # name-only query keeps all
    w = HeuristicWarden(popular=["chalk"], osv=idx)
    assert w.score("chalk", "5.6.1").risk == 1.0
    assert w.score("chalk", "2.4.1").risk == 0.0  # clean older release of a popular package


def test_cvss_and_typosquat_label():
    assert cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base("garbage") is None
    assert mal_mentions_typosquat({"summary": "", "details": "a typosquat of requests"})


def test_warden_uses_osv_malicious_records(osv):
    w = HeuristicWarden(osv=osv)
    s = w.score("pymocks", "0.0.1")
    assert s.risk == 1.0 and "MAL-2022-7426" in s.reasons[0]
    assert w.score("requests", "2.0").risk == 0.0


# --- ingest real tool output ------------------------------------------------------
def _real_image_events():
    from tracegate.ingest import syft_json_to_build, trivy_json_to_scan
    build = syft_json_to_build(FIX / "alpine.syft.json", "b1")
    scan = trivy_json_to_scan(FIX / "alpine.trivy.json")
    return build, scan, [
        StageEvent("commit", "r", {"sha": "c" * 40, "files": [], "deps_added": []}),
        StageEvent("build", "r", build), StageEvent("scan", "r", scan),
        StageEvent("deploy", "r", {"service": "edge", "image_digest": build["image"]["digest"],
                                   "containers": ["edge-0"]})]


def test_ingest_real_syft_and_trivy_converge_on_purl_nodes():
    build, scan, evs = _real_image_events()
    types = {a["purl"].split("/")[0] for a in build["sbom"]["artifacts"]}
    assert build["image"]["layers"] and types == {"pkg:apk", "pkg:generic"}  # apk db + busybox binary
    s = HmacSigner("k", KEY["k"])
    res = Collector(Verifier(KEY)).collect([s.sign(e) for e in evs])
    n_rows = sum(len(r["Vulnerabilities"]) for r in scan["Results"])
    assert n_rows > 0
    assert len(res.unmatched) == 0  # every Trivy finding landed on a Syft node
    assert sum(f.source == "trivy" for f in res.graph.findings) == n_rows
    assert evaluate(res).verdict == Verdict.BLOCK  # real HIGH/CRITICAL CVEs, reachability unknown


def test_os_packages_are_not_typosquat_scored():
    _, _, evs = _real_image_events()
    s = HmacSigner("k", KEY["k"])
    res = Collector(Verifier(KEY)).collect([s.sign(e) for e in evs])
    enrich_warden(res, MultiWarden({"pypi": HeuristicWarden()}))
    assert not [f for f in res.graph.findings if f.source == "warden"]


# --- git lineage ----------------------------------------------------------------------
def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@example.com")
    _git(r, "config", "user.name", "t")
    steps = [
        ("flask==2.0.0\npyyaml==5.3\n", "add deps (#1)"),
        ("flask==2.0.0\npyyaml==5.4\n", "bump pyyaml (#2)"),
        ("# pinned\nflask==2.0.0\npyyaml==5.4\n", "comment only (#3)"),
        ("flask==2.0.0\npyyaml==5.3\n", "Revert pyyaml (#4)"),
        ("flask==2.0.1\npyyaml==5.3\n", "bump flask (#5)"),
    ]
    for text, msg in steps:
        (r / "requirements.txt").write_text(text)
        _git(r, "add", "requirements.txt")
        _git(r, "commit", "-q", "-m", msg)
    return r


def test_manifest_history_and_backtrack_matches_blame(repo, osv):
    hist = manifest_history(repo, "requirements.txt")
    assert [h.pr for h in hist] == [1, 2, 4, 5]  # comment-only commit changes no pin
    assert hist[2].added == {"pyyaml": "5.3"} and hist[2].removed == {"pyyaml": "5.4"}
    s = HmacSigner("k", KEY["k"])
    evs = commit_events(hist, "requirements.txt")
    evs.append(StageEvent("build", "ci", {"build_id": "b", "commit": hist[-1].sha, "sbom": {"artifacts": [
        {"name": n, "version": v} for n, v in hist[-1].pins.items()]}}))
    evs.append(StageEvent("scan", "ci", osv.scan_payload(hist[-1].pins.items())))
    res = Collector(Verifier(KEY)).collect([s.sign(e) for e in evs])
    story = origin_story(res.graph, "CVE-2020-14343")[0]
    # pyyaml 5.3 was introduced twice (#1 and the revert #4): the shipped copy came from #4
    assert story["introduced_by"]["pr"] == 4
    assert blame_introducers(repo, "requirements.txt")["pyyaml"] == story["introduced_by"]["sha"]


def test_manifest_history_follows_rename(repo):
    (repo / "requirements").mkdir()
    _git(repo, "mv", "requirements.txt", "requirements/main.txt")
    _git(repo, "commit", "-q", "-m", "move manifest (#6)")
    (repo / "requirements" / "main.txt").write_text("flask==2.0.1" + chr(10) + "pyyaml==6.0" + chr(10))
    _git(repo, "commit", "-qam", "bump pyyaml (#7)")
    hist = manifest_history(repo, "requirements/main.txt")
    # pre-rename history is kept; the pure move changes no pin
    assert [h.pr for h in hist] == [1, 2, 4, 5, 7]
    assert blame_introducers(repo, "requirements/main.txt")["pyyaml"] == hist[-1].sha


def test_materialize_writes_snapshot_sources(repo, tmp_path):
    (repo / "app").mkdir()
    (repo / "app" / "main.py").write_text("import yaml" + chr(10))
    (repo / "app" / "notes.txt").write_text("x")
    (repo / "Dockerfile").write_text("FROM python:3.12" + chr(10))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add app")
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                         text=True, check=True).stdout.strip()
    (repo / "app" / "main.py").write_text("import flask" + chr(10))
    _git(repo, "commit", "-qam", "switch")
    out = tmp_path / "snap"
    assert materialize(repo, sha, ["app"], out) == 2
    assert (out / "app" / "main.py").read_text() == "import yaml" + chr(10)
    assert not (out / "app" / "notes.txt").exists() and (out / "Dockerfile").exists()


def test_parse_requirements_and_pip_compile():
    text = ("django==4.2.1 \\\n    --hash=sha256:abc\n    # via -r requirements/main.in\n"
            "asgiref==3.7.2\n    # via django\nPyYAML[extra]==6.0 ; python_version>'3'\n-r other.txt\n")
    assert parse_requirements(text) == {"django": "4.2.1", "asgiref": "3.7.2", "pyyaml": "6.0"}
    assert direct_deps_from_pip_compile(text) == {"django"}
    assert via_graph(text)["asgiref"] == {"django"}
    assert direct_deps_from_pip_compile("flask==1.0\n") is None


# --- reachability ------------------------------------------------------------------------
def test_static_reachability(tmp_path):
    src = tmp_path / "app"
    src.mkdir()
    (src / "main.py").write_text("import yaml\nfrom django.db import models\nAPPS=['rest_framework.apps']\n")
    (tmp_path / "Procfile").write_text("web: gunicorn app.wsgi\n")
    req = ("django==4.2\n    # via -r main.in\nasgiref==3.7\n    # via django\npyyaml==6.0\n"
           "gunicorn==21.0\ndjangorestframework==3.14\nlxml==4.9\n    # via -r main.in\n")
    pins = parse_requirements(req)
    rep = static_reachability(pins, [src], tmp_path, req)
    assert rep.status == {"django": "imported", "asgiref": "transitive", "pyyaml": "imported",
                          "gunicorn": "entrypoint", "djangorestframework": "imported", "lxml": "unreached"}
    assert "yaml" in import_names("PyYAML") and "django.db" in app_imports([src])


def test_static_reachability_implied_and_referenced(tmp_path):
    (tmp_path / "settings.py").write_text(
        "from google.cloud import storage" + chr(10)
        + "ENGINE = 'django.db.backends.postgresql'" + chr(10)
        + "SCHEMES = ['argon2', 'bcrypt']" + chr(10))
    pins = {"django": "4.2", "psycopg2-binary": "2.9", "google-cloud-storage": "2.0",
            "argon2-cffi": "23.1", "lxml": "4.9"}
    rep = static_reachability(pins, [tmp_path], tmp_path)
    assert rep.status["django"] == "imported"
    assert rep.status["google-cloud-storage"] == "imported"
    assert rep.status["psycopg2-binary"] == "transitive"
    assert rep.status["argon2-cffi"] == "referenced"
    assert rep.status["lxml"] == "unreached"


def test_static_reachability_downgrades_block_to_warn(tmp_path, osv):
    (tmp_path / "app.py").write_text("import flask\n")
    s = HmacSigner("k", KEY["k"])
    evs = [StageEvent("commit", "r", {"sha": "a" * 40, "deps_added": [{"name": "pyyaml", "version": "5.3"}]}),
           StageEvent("build", "r", {"build_id": "b", "commit": "a" * 40,
                                     "sbom": {"artifacts": [{"name": "pyyaml", "version": "5.3"},
                                                            {"name": "flask", "version": "3.0.0"}]}}),
           StageEvent("scan", "r", osv.scan_payload([("pyyaml", "5.3")]))]
    res = Collector(Verifier(KEY)).collect([s.sign(e) for e in evs])
    assert evaluate(res).verdict == Verdict.BLOCK
    rep = static_reachability({"pyyaml": "5.3", "flask": "3.0.0"}, [tmp_path], tmp_path)
    assert enrich_static_reachability(res, rep) == 1
    assert evaluate(res).verdict == Verdict.WARN


# --- signing / exports ---------------------------------------------------------------------
def test_ed25519_signing_and_dsse_roundtrip():
    pytest.importorskip("cryptography")
    from tracegate.signing import Ed25519Signer
    sg = Ed25519Signer.generate("ci")
    env = sg.sign(StageEvent("commit", "r", {"sha": "x"}))
    v = Verifier({"ci": sg.public_key})
    assert v.verify(from_dsse_json(to_dsse_json(env))).payload == {"sha": "x"}
    other = Ed25519Signer.generate("ci")
    with pytest.raises(SignatureError):
        Verifier({"ci": other.public_key}).verify(env)
    tampered = from_dsse_json(to_dsse_json(env))
    tampered.payload = tampered.payload.replace('"x"', '"y"')
    with pytest.raises(SignatureError):
        v.verify(tampered)


def test_intoto_statement_and_exports():
    build, _, evs = _real_image_events()
    st = intoto_statement(build)
    assert st["predicateType"] == "https://slsa.dev/provenance/v1" and st["subject"][0]["digest"]["sha256"]
    s = HmacSigner("k", KEY["k"])
    res = Collector(Verifier(KEY)).collect([s.sign(e) for e in evs])
    cy = to_cypher(res.graph)
    assert "MERGE (n:Artifact:Image" in cy and "[:INSTALLED_IN]" in cy and ":Finding" in cy
    j = to_json(res.graph)
    assert len(j["nodes"]) == res.graph.stats()["nodes"]
    oi = opa_input(res)
    assert oi["missing_stages"] == [] and oi["findings"][0]["path"]


def test_api_smoke():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from tracegate.api import app
    c = TestClient(app)
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.post("/v1/demo/cve-origin").json()
    assert r["verdict"] == "block"
    bt = c.get(f"/v1/runs/{r['run']}/backtrack", params={"q": "CVE-2020-14343"}).json()
    assert bt[0]["introduced_by"]["pr"] == 42
    assert c.post("/v1/gate", json=[{"bogus": 1}]).status_code == 422
    assert "TRACEGATE" in c.get("/").text


def test_api_trust_roots(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    pytest.importorskip("cryptography")
    from fastapi.testclient import TestClient

    from tracegate import synth
    from tracegate.api import app
    from tracegate.signing import Ed25519Signer, HmacSigner
    for k in ("TRACEGATE_KEY", "TRACEGATE_PUBKEY", "TRACEGATE_DEMO", "TRACEGATE_API_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    c = TestClient(app)
    from dataclasses import asdict
    events = synth.events(synth.SCENARIOS["clean"])
    sg = Ed25519Signer.generate("ci")
    good = [asdict(sg.sign(e)) for e in events]
    forged = [asdict(HmacSigner("ci", synth.DEMO_KEY).sign(e)) for e in events]
    assert c.post("/v1/gate", json=good).status_code == 503  # no trust root: fail closed
    (tmp_path / "ci.pub").write_bytes(sg.public_pem())
    monkeypatch.setenv("TRACEGATE_KEYID", "ci")
    monkeypatch.setenv("TRACEGATE_PUBKEY", str(tmp_path / "ci.pub"))
    r = c.post("/v1/gate", json=good).json()
    assert r["rejected"] == [] and r["verdict"] == "pass"
    r = c.post("/v1/gate", json=forged).json()
    assert r["verdict"] == "block" and len(r["rejected"]) == len(events)
    monkeypatch.setenv("TRACEGATE_API_TOKEN", "t0k")
    assert c.post("/v1/gate", json=good).status_code == 401
    assert c.post("/v1/gate", json=good, headers={"Authorization": "Bearer t0k"}).status_code == 200
    big = b"[" + b" " * (11 * 1024 * 1024) + b"]"
    assert c.post("/v1/gate", content=big, headers={"content-type": "application/json",
                                                    "Authorization": "Bearer t0k"}).status_code == 413


def test_warden_api_client_contract():
    """Fixture follows Warden's ScanOut schema (backend/app/schemas/scan.py); not a recorded response."""
    from tracegate.warden import WardenApiClient
    d = json.loads((FIX / "warden_scanout.json").read_text())
    s = WardenApiClient.parse("requests", "2.31.0", d)
    assert s.risk == 0.12 and "allow" in s.reasons[0]
    s = WardenApiClient.parse("x", "1", {**d, "decision": "block", "risk_score": 40, "matched_policy_rules": ["typo"]})
    assert s.risk == 0.9 and "warden rule: typo" in s.reasons
    c = WardenApiClient("http://warden.local/", token="t")
    r = c.request("requests", "2.31.0")
    assert r.full_url == "http://warden.local/api/v1/scans" and r.get_header("Authorization") == "Bearer t"
    assert json.loads(r.data) == {"ecosystem": "pypi", "name": "requests", "version": "2.31.0"}
