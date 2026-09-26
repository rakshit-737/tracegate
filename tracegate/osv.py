"""OSV (https://osv.dev) connector: offline index over the official bulk dumps.

`OsvIndex.from_zip("PyPI-all.zip")` loads every advisory for an ecosystem and
answers two questions the gate needs:

  * vulns(name, version) -> known vulnerabilities for a pinned dependency
  * malicious(name)      -> OSV MAL-* records (ossf/malicious-packages) for a name

The same index doubles as a scanner (`scan_payload`) producing Trivy-shaped
scan events, so a pipeline without Trivy can still attach findings.

Severity comes from the GHSA `database_specific.severity` label when present,
else from a CVSS v3 base score computed from the vector, else from any alias
in the same dump, else MEDIUM (conservative).
"""
from __future__ import annotations

import json
import math
import re
import urllib.request
import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .ids import normalize_name, purl

try:  # optional: only needed for records that give ranges but no explicit versions
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover
    Version = None  # type: ignore[assignment]
    InvalidVersion = Exception  # type: ignore[assignment,misc]

_ECO = {"pypi": "PyPI", "npm": "npm"}
_GHSA_SEV = {"LOW": "LOW", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}

# --- CVSS v3.x base score ------------------------------------------------------
_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base(vector: str) -> float | None:
    try:
        m = dict(kv.split(":", 1) for kv in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["C"][m["I"]]) * (1 - _W["C"][m["A"]])
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        raw = 1.08 * (impact + expl) if scope_changed else impact + expl
        return _roundup(min(raw, 10))
    except (KeyError, ValueError, IndexError):
        return None


def score_to_severity(s: float) -> str:
    return "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW"


@dataclass
class OsvVuln:
    id: str
    aliases: list[str]
    summary: str
    severity: str | None  # LOW..CRITICAL, None = unknown
    fixed: list[str] = field(default_factory=list)

    @property
    def cve(self) -> str:
        return next((a for a in self.aliases if a.startswith("CVE-")), self.id)


@dataclass
class _Affected:
    vuln: OsvVuln
    versions: frozenset[str]
    ranges: list[tuple[str | None, str | None, str | None]]  # (introduced, fixed, last_affected)


class OsvIndex:
    def __init__(self, ecosystem: str = "pypi"):
        self.ecosystem = ecosystem.lower()
        self.by_name: dict[str, list[_Affected]] = {}
        self.mal: dict[str, list[dict]] = {}  # normalised name -> MAL records (id, versions, summary)
        self.n_records = 0

    # ---- loading --------------------------------------------------------------
    @classmethod
    def from_zip(cls, path: str | Path, ecosystem: str = "pypi") -> OsvIndex:
        idx = cls(ecosystem)
        # two streaming passes (severity-by-alias, then index) so the full dump is never in memory
        idx.add_records(lambda: iter_zip_records(path))
        return idx

    @classmethod
    def from_records(cls, records: Iterable[dict], ecosystem: str = "pypi") -> OsvIndex:
        idx = cls(ecosystem)
        idx.add_records(records)
        return idx

    def add_records(self, records: Iterable[dict] | Callable[[], Iterable[dict]]) -> None:
        """`records` may be a re-iterable factory (callable) to allow streaming."""
        if callable(records):
            source = records
        else:
            kept = list(records)
            source = lambda: kept  # noqa: E731
        sev_by_id: dict[str, str] = {}
        for r in source():
            if r.get("withdrawn"):
                continue
            s = self._own_severity(r)
            if s:
                sev_by_id[r["id"]] = s
                for a in r.get("aliases", []) or []:
                    sev_by_id.setdefault(a, s)
        want = _ECO.get(self.ecosystem, self.ecosystem)
        for r in source():
            if r.get("withdrawn"):
                continue
            self.n_records += 1
            sev = sev_by_id.get(r["id"]) or next(
                (sev_by_id[a] for a in r.get("aliases", []) or [] if a in sev_by_id), None)
            for aff in r.get("affected", []) or []:
                pkg = aff.get("package", {}) or {}
                if pkg.get("ecosystem") != want:
                    continue
                name = normalize_name(pkg.get("name", ""), self.ecosystem)
                if r["id"].startswith("MAL-"):
                    self.mal.setdefault(name, []).append({
                        "id": r["id"], "versions": aff.get("versions", []),
                        "summary": r.get("summary", ""), "details": (r.get("details") or "")[:500],
                        "published": r.get("published")})
                    continue
                rng, fixed = [], []
                for rg in aff.get("ranges", []) or []:
                    if rg.get("type") not in ("ECOSYSTEM", "SEMVER"):
                        continue
                    intro = None
                    for e in rg.get("events", []):
                        if "introduced" in e:
                            intro = e["introduced"]
                        elif "fixed" in e:
                            rng.append((intro, e["fixed"], None))
                            fixed.append(e["fixed"])
                            intro = None
                        elif "last_affected" in e:
                            rng.append((intro, None, e["last_affected"]))
                            intro = None
                    if intro is not None:
                        rng.append((intro, None, None))
                v = OsvVuln(r["id"], list(r.get("aliases", []) or []), r.get("summary") or r["id"], sev, fixed)
                self.by_name.setdefault(name, []).append(
                    _Affected(v, frozenset(aff.get("versions", []) or []), rng))

    @staticmethod
    def _own_severity(r: dict) -> str | None:
        ds = (r.get("database_specific") or {}).get("severity")
        if isinstance(ds, str) and ds.upper() in _GHSA_SEV:
            return _GHSA_SEV[ds.upper()]
        for s in r.get("severity", []) or []:
            if s.get("type", "").startswith("CVSS_V3"):
                b = cvss3_base(s.get("score", ""))
                if b is not None:
                    return score_to_severity(b)
        return None

    # ---- queries ---------------------------------------------------------------
    def vulns(self, name: str, version: str) -> list[OsvVuln]:
        out, seen = [], set()
        for a in self.by_name.get(normalize_name(name, self.ecosystem), []):
            if a.vuln.id in seen:
                continue
            if version in a.versions or (not a.versions and self._in_ranges(version, a.ranges)):
                seen.add(a.vuln.id)
                out.append(a.vuln)
        return out

    @staticmethod
    def _in_ranges(version: str, ranges: list[tuple[str | None, str | None, str | None]]) -> bool:
        if Version is None or not ranges:
            return False
        try:
            v = Version(version)
            for intro, fixed, last in ranges:
                lo = Version(intro) if intro and intro != "0" else None
                if lo is not None and v < lo:
                    continue
                if fixed is not None and v >= Version(fixed):
                    continue
                if last is not None and v > Version(last):
                    continue
                return True
        except InvalidVersion:
            return False
        return False

    def malicious(self, name: str) -> list[dict]:
        return self.mal.get(normalize_name(name, self.ecosystem), [])

    def scan_payload(self, deps: Iterable[tuple[str, str]], tool: str = "osv") -> dict:
        """Trivy-shaped scan payload for (name, version) pairs."""
        vulns = []
        for name, version in deps:
            for v in self.vulns(name, version):
                vulns.append({"VulnerabilityID": v.cve, "PkgName": name, "InstalledVersion": version,
                              "Severity": v.severity or "MEDIUM", "Title": v.summary,
                              "FixedVersion": ", ".join(v.fixed) or None,
                              "PURL": purl(name, version, self.ecosystem), "OsvID": v.id})
        return {"tool": tool, "Results": [{"Target": "manifest", "Vulnerabilities": vulns}]}


def iter_zip_records(path: str | Path) -> Iterator[dict]:
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith(".json"):
                yield json.loads(z.read(n))


_MAL_TYPOSQUAT = re.compile(r"typo-?squat|typosquat|impersonat|masquerad|combosquat", re.I)


def mal_mentions_typosquat(rec: dict) -> bool:
    return bool(_MAL_TYPOSQUAT.search(f"{rec.get('summary', '')} {rec.get('details', '')}"))


class OsvApiClient:
    """Online fallback: POST https://api.osv.dev/v1/querybatch (no key needed)."""

    URL = "https://api.osv.dev/v1/querybatch"

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def query(self, deps: list[tuple[str, str, str]]) -> list[list[str]]:
        body = {"queries": [{"package": {"name": n, "ecosystem": _ECO.get(e.lower(), e)}, "version": v}
                            for n, v, e in deps]}
        req = urllib.request.Request(self.URL, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            res = json.load(r)["results"]
        return [[v["id"] for v in (x.get("vulns") or [])] for x in res]
