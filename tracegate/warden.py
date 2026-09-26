"""Warden connector seam.

TRACEGATE does not re-implement dependency-risk scoring; it consumes Warden.
`WardenClient` is the contract. `HttpWardenClient` targets a running Warden API;
`HeuristicWarden` is an offline stand-in (typosquat distance) for demos/tests.
"""
from __future__ import annotations

import difflib
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

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


class HttpWardenClient:
    """Calls GET {base}/score?package=..&version=.. -> {risk, reasons}. Untested stub."""

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url, self.timeout = base_url.rstrip("/"), timeout

    def score(self, name: str, version: str) -> WardenScore:
        q = urllib.parse.urlencode({"package": name, "version": version})
        with urllib.request.urlopen(f"{self.base_url}/score?{q}", timeout=self.timeout) as r:
            d = json.load(r)
        return WardenScore(name, version, float(d["risk"]), list(d.get("reasons", [])))
