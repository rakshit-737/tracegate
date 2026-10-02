"""Warden connector seam.

TRACEGATE does not re-implement dependency-risk scoring; it consumes Warden.
`WardenClient` is the contract. `WardenApiClient` targets the real Warden API (POST /api/v1/scans);
`HeuristicWarden` is the offline stand-in: known-malicious lookup (OSV MAL-*
records from ossf/malicious-packages) + the multi-technique typosquat detector
against a popularity-ranked reference list (top-PyPI when the dataset is present).
`DifflibWarden` is the original MVP heuristic, kept as the benchmark baseline.
"""
from __future__ import annotations

import difflib
import json
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from .typosquat import TyposquatDetector, normalize

if TYPE_CHECKING:
    from .osv import OsvIndex

POPULAR = ["requests", "numpy", "pandas", "django", "flask", "urllib3", "pyyaml",
           "cryptography", "boto3", "setuptools", "jinja2", "pillow", "fastapi", "pydantic"]


@dataclass
class WardenScore:
    package: str
    version: str
    risk: float  # 0.0 benign .. 1.0 malicious
    reasons: list[str] = field(default_factory=list)


class WardenClient(Protocol):
    def score(self, name: str, version: str) -> WardenScore: ...


class HeuristicWarden:
    """Deterministic offline dependency-risk scorer.

    risk = 1.0 for a denylisted / OSV MAL-* package, else the typosquat score
    (0 for names in the reference list). Scores >= 0.8 map to CRITICAL (block).
    """

    def __init__(self, popular: Iterable[str] | None = None, denylist: set[str] | None = None,
                 osv: OsvIndex | None = None):
        self.detector = TyposquatDetector(list(popular) if popular is not None else POPULAR)
        self.denylist = {normalize(d) for d in (denylist or set())}
        self.osv = osv

    def score(self, name: str, version: str) -> WardenScore:
        n = normalize(name)
        if n in self.denylist:
            return WardenScore(name, version, 1.0, ["on denylist"])
        if self.osv is not None:
            mal = self.osv.malicious(name, version or None)
            if mal:  # version-aware: most MAL records cover every version, hijacks do not
                ids = ", ".join(m["id"] for m in mal[:3])
                return WardenScore(name, version, 1.0, [f"known malicious package (OSV {ids})"])
        m = self.detector.score(name)
        return WardenScore(name, version, m.score, m.reasons if m.score > 0 else [])


class MultiWarden:
    """Routes each dependency to the scorer for its ecosystem (pypi, npm, ...)."""

    def __init__(self, by_ecosystem: dict[str, WardenClient]):
        self.by_ecosystem = by_ecosystem

    def for_ecosystem(self, eco: str) -> WardenClient | None:
        return self.by_ecosystem.get(eco)

    def score(self, name: str, version: str) -> WardenScore:  # default: PyPI
        w = self.by_ecosystem.get("pypi")
        return w.score(name, version) if w else WardenScore(name, version, 0.0, [])


class DifflibWarden:
    """Original MVP heuristic (difflib ratio vs 14 names). Benchmark baseline only."""

    def __init__(self, popular: list[str] | None = None, denylist: set[str] | None = None):
        self.popular = popular or POPULAR
        self.denylist = {d.lower() for d in (denylist or set())}

    def score(self, name: str, version: str) -> WardenScore:
        n = name.lower()
        if n in self.denylist:
            return WardenScore(name, version, 1.0, ["on denylist"])
        if n in self.popular:
            return WardenScore(name, version, 0.0, [])
        best = max(self.popular, key=lambda p: difflib.SequenceMatcher(None, n, p).ratio())
        ratio = difflib.SequenceMatcher(None, n, best).ratio()
        if ratio >= 0.8:
            return WardenScore(name, version, round(0.5 + ratio / 2, 2),
                               [f"possible typosquat of '{best}' (similarity {ratio:.2f})"])
        return WardenScore(name, version, 0.1, [])


class WardenApiClient:
    """Client for the real Warden service (rakshit-737/warden-supply-chain-security).

    Calls ``POST {base}/api/v1/scans`` with ``{"ecosystem": "pypi", "name", "version"}`` and a
    bearer token (needs the ``scan:create`` permission) and maps the ``ScanOut`` response
    (``risk_score`` 0-100, ``decision``, ``matched_policy_rules``) to a WardenScore. Warden
    downloads and statically analyses the distribution, so never send names taken from OSV
    ``MAL-*`` records to it; use HeuristicWarden (offline, metadata only) for those.
    Configure with WARDEN_API (base URL) and WARDEN_TOKEN.
    """

    DECISION_FLOOR = {"block": 0.9, "review": 0.5, "warn": 0.5}

    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: float = 60.0):
        import os
        self.base_url = (base_url or os.environ["WARDEN_API"]).rstrip("/")
        self.token = token if token is not None else os.environ.get("WARDEN_TOKEN", "")
        self.timeout = timeout

    def request(self, name: str, version: str) -> urllib.request.Request:
        body = json.dumps({"ecosystem": "pypi", "name": name, "version": version or None}).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return urllib.request.Request(f"{self.base_url}/api/v1/scans", data=body, headers=headers, method="POST")

    @classmethod
    def parse(cls, name: str, version: str, d: dict) -> WardenScore:
        """Map a Warden ``ScanOut`` JSON object to a WardenScore."""
        decision = str(d.get("decision", "")).lower()
        risk = max(min(float(d.get("risk_score", 0)) / 100.0, 1.0), cls.DECISION_FLOOR.get(decision, 0.0))
        reasons = [f"warden decision: {decision or 'unknown'} (risk {d.get('risk_score')})"]
        reasons += [f"warden rule: {r}" for r in d.get("matched_policy_rules") or []]
        return WardenScore(name, d.get("version") or version, risk, reasons)

    def score(self, name: str, version: str) -> WardenScore:
        with urllib.request.urlopen(self.request(name, version), timeout=self.timeout) as r:
            return self.parse(name, version, json.load(r))
