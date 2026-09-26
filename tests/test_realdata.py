"""Tests against the full real datasets. Skipped unless scripts/download_data.py has run."""
import json

import pytest

from tracegate.data import data_root, have, top_npm, top_pypi

pytestmark = pytest.mark.realdata


@pytest.fixture(scope="module")
def osv_pypi():
    if not have("osv/PyPI-all.zip"):
        pytest.skip("OSV PyPI dump not downloaded")
    from tracegate.osv import OsvIndex
    return OsvIndex.from_zip(data_root() / "osv/PyPI-all.zip")


def test_osv_real_dump(osv_pypi):
    assert osv_pypi.n_records > 20000
    assert any(v.cve == "CVE-2020-14343" for v in osv_pypi.vulns("PyYAML", "5.3"))
    assert len(osv_pypi.mal) > 10000


def test_popularity_lists():
    if not have("popular/top-pypi-packages.min.json", "popular/npm-high-impact-top.js"):
        pytest.skip("popularity lists not downloaded")
    assert len(top_pypi()) >= 10000 and "requests" in top_pypi(100)
    assert len(top_npm()) >= 1000 and "lodash" in top_npm(500)


def test_typosquat_on_real_reference():
    if not have("popular/top-pypi-packages.min.json"):
        pytest.skip("top-pypi not downloaded")
    from tracegate.typosquat import TyposquatDetector
    d = TyposquatDetector(top_pypi(5000))
    for name in ("reqeusts", "python3-dateutil", "urlib3", "beautifulsoup"):
        assert d.score(name).score > 0.5, name
    for name in ("requests", "numpy", "django"):
        assert d.score(name).score == 0.0


def test_real_image_scans_converge():
    scans = data_root() / "scans"
    pairs = [(p, scans / p.name.replace(".syft.json", ".trivy.json")) for p in scans.glob("*.syft.json")]
    pairs = [(s, t) for s, t in pairs if t.exists() and "alpine" in s.name]
    if not pairs:
        pytest.skip("no real image scans")
    from tracegate.collector import Collector
    from tracegate.ingest import syft_json_to_build, trivy_json_to_scan
    from tracegate.models import StageEvent
    from tracegate.signing import HmacSigner, Verifier
    s = HmacSigner("k", b"k")
    for syft, trivy in pairs:
        evs = [StageEvent("build", "r", syft_json_to_build(syft, "b")),
               StageEvent("scan", "r", trivy_json_to_scan(trivy))]
        res = Collector(Verifier({"k": b"k"})).collect([s.sign(e) for e in evs])
        rows = sum(len(r.get("Vulnerabilities") or []) for r in json.loads(trivy.read_text())["Results"])
        assert rows == 0 or len(res.unmatched) / rows < 0.05, syft.name
