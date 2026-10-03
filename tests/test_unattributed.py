"""Scanner findings that match no SBOM node must reach the verdict (regression for a PASS on a CRITICAL)."""
import copy
import json
from pathlib import Path

from tracegate import synth
from tracegate.collector import Collector
from tracegate.export import opa_input
from tracegate.ingest import syft_json_to_build, trivy_json_to_scan
from tracegate.models import StageEvent
from tracegate.pipeline import run
from tracegate.policy import evaluate, pr_comment
from tracegate.signing import HmacSigner, Verifier

FX = Path(__file__).parent / "fixtures"
TRUST = {synth.DEMO_KEYID: synth.DEMO_KEY}


def _clean_plus(vuln: dict) -> list:
    evs = synth.events(synth.SCENARIOS["clean"])
    evs.append(StageEvent("scan", "run-extra", {"Results": [{"Vulnerabilities": [vuln]}]}))
    signer = HmacSigner(synth.DEMO_KEYID, synth.DEMO_KEY)
    return [signer.sign(e) for e in evs]


def test_clean_scenario_passes():
    _, d = run(synth.signed(synth.SCENARIOS["clean"]), TRUST)
    assert d.verdict.value == "pass"


def test_critical_on_package_missing_from_sbom_blocks():
    res, d = run(_clean_plus({"VulnerabilityID": "CVE-2099-0001", "PkgName": "ghostpkg", "InstalledVersion": "1.0.0",
                              "Severity": "CRITICAL", "Title": "x"}), TRUST)
    assert d.verdict.value == "block"
    r = [x for x in d.reasons if x["rule"] == "unattributed_finding"]
    assert r and r[0]["finding"] == "CVE-2099-0001" and "not attributable to an SBOM node" in r[0]["msg"]
    assert "unattributed_finding" in pr_comment(d)
    assert opa_input(res)["unmatched"][0]["cve"] == "CVE-2099-0001"


def test_version_spelling_mismatch_blocks():
    res, d = run(_clean_plus({"VulnerabilityID": "CVE-2099-0002", "PkgName": "flask", "InstalledVersion": "3.0.3.0",
                              "Severity": "HIGH", "Title": "x"}), TRUST)
    assert d.verdict.value == "block" and len(res.unmatched_findings) == 1


def test_exact_match_control_is_attributed():
    res, d = run(_clean_plus({"VulnerabilityID": "CVE-2099-0003", "PkgName": "flask", "InstalledVersion": "3.0.3",
                              "Severity": "CRITICAL", "Title": "x"}), TRUST)
    assert d.verdict.value == "block" and not res.unmatched_findings
    assert any(x["rule"] == "vulnerable_dependency" for x in d.reasons)


def test_low_unmatched_only_warns():
    _, d = run(_clean_plus({"VulnerabilityID": "CVE-2099-0004", "PkgName": "ghostpkg", "InstalledVersion": "1",
                            "Severity": "LOW", "Title": "x"}), TRUST)
    assert d.verdict.value == "warn"


def _alpine(strip_purl: bool):
    trivy = json.loads((FX / "alpine.trivy.json").read_text())
    if strip_purl:
        trivy = copy.deepcopy(trivy)
        for r in trivy["Results"]:
            for v in r.get("Vulnerabilities") or []:
                v.pop("PkgIdentifier", None)
    s = HmacSigner("k", b"k")
    evs = [StageEvent("commit", "r", {"sha": "0" * 40, "files": [], "deps_added": []}),
           StageEvent("build", "r", syft_json_to_build(FX / "alpine.syft.json", "b")),
           StageEvent("scan", "r", trivy_json_to_scan(trivy))]
    res = Collector(Verifier({"k": b"k"})).collect([s.sign(e) for e in evs])
    return res, evaluate(res)


def test_alpine_rows_without_purl_attach_by_trivy_type():
    res_a, d_a = _alpine(strip_purl=False)
    res_b, d_b = _alpine(strip_purl=True)
    assert d_a.verdict.value == d_b.verdict.value == "block"
    assert len(res_a.graph.findings) == len(res_b.graph.findings) == 14
    assert res_b.unmatched == [] and len(d_b.reasons) == len(d_a.reasons)


def test_trivy_type_mapping():
    from tracegate.ingest import trivy_ecosystem
    assert trivy_ecosystem("alpine") == "apk" and trivy_ecosystem("debian") == "deb"
    assert trivy_ecosystem("python-pkg") == "pypi" and trivy_ecosystem("gomod") == "golang"
    assert trivy_ecosystem("unknown-thing") is None
