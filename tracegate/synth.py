"""Synthetic pipeline-event generator for demos, tests and scale benchmarks.

All data is fabricated; CVE ids reference real public advisories only as labels.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from .models import Envelope, StageEvent
from .signing import HmacSigner

DEMO_KEYID = "ci-demo"
DEMO_KEY = b"tracegate-demo-key-DO-NOT-USE-IN-PROD"

IMPORTS = {"pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4"}
BASE_LAYER = "sha256:" + hashlib.sha256(b"python:3.12-slim").hexdigest()


def _h(*parts: object) -> str:
    return "sha256:" + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()


@dataclass
class Dep:
    """A dependency in a synthetic scenario."""
    name: str
    version: str
    cve: str | None = None
    severity: str = "HIGH"


@dataclass
class Scenario:
    """A synthetic pipeline run: commit, PR, dependencies, image and service."""
    sha: str = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    pr: int = 42
    author: str = "dev@example.com"
    services: list[str] = field(default_factory=lambda: ["api", "worker", "web"])
    base_deps: list[Dep] = field(default_factory=lambda: [Dep("requests", "2.32.3"), Dep("flask", "3.0.3")])
    added: list[Dep] = field(default_factory=list)
    loaded: dict[str, list[str]] = field(default_factory=dict)  # service -> modules loaded
    sast: list[dict] = field(default_factory=list)
    tamper_stage: str | None = None
    drop_stage: str | None = None


def events(sc: Scenario) -> list[StageEvent]:
    """Unsigned stage events for a scenario."""
    run = f"run-{sc.pr}"
    evs = [StageEvent("commit", run, {
        "sha": sc.sha, "author": sc.author, "pr": sc.pr, "message": f"PR #{sc.pr}",
        "files": ["requirements.txt", "app/main.py"],
        "deps_added": [{"name": d.name, "version": d.version} for d in sc.added]})]
    if sc.sast:
        evs.append(StageEvent("sast", run, {"commit": sc.sha, "findings": sc.sast}))
    deps = sc.base_deps + sc.added
    for svc in sc.services:
        app_layer = _h(svc, "app", sc.sha)
        img = _h(svc, "image", sc.sha)
        evs.append(StageEvent("build", run, {
            "build_id": f"{run}-{svc}", "commit": sc.sha,
            "image": {"name": f"ghcr.io/demo/{svc}", "digest": img, "layers": [
                {"digest": BASE_LAYER, "created_by": "FROM python:3.12-slim"},
                {"digest": app_layer, "created_by": "RUN pip install -r requirements.txt"}]},
            "sbom": {"artifacts": [{"name": d.name, "version": d.version, "import_name": IMPORTS.get(d.name),
                                    "locations": [{"layerID": app_layer}]} for d in deps]}}))
        evs.append(StageEvent("scan", run, {"image_digest": img, "Results": [{"Vulnerabilities": [
            {"VulnerabilityID": d.cve, "PkgName": d.name, "InstalledVersion": d.version,
             "Severity": d.severity, "Title": f"{d.cve} in {d.name}"} for d in deps if d.cve]}]}))
        ctr = f"{svc}-7d9f-0"
        evs.append(StageEvent("deploy", run, {"service": svc, "image_digest": img, "containers": [ctr]}))
        if svc in sc.loaded:
            evs.append(StageEvent("runtime", run, {"container": ctr, "loaded_modules": sc.loaded[svc]}))
    if sc.drop_stage:
        evs = [e for e in evs if e.stage != sc.drop_stage]
    return evs


def signed(sc: Scenario, keyid: str = DEMO_KEYID, key: bytes = DEMO_KEY) -> list[Envelope]:
    """Stage events for a scenario signed with the public demo key (or another HMAC key)."""
    s = HmacSigner(keyid, key)
    envs = [s.sign(e) for e in events(sc)]
    if sc.tamper_stage:
        for env in envs:
            if f'"stage":"{sc.tamper_stage}"' in env.payload:
                env.payload = env.payload.replace('"Severity":"CRITICAL"', '"Severity":"LOW"')
                env.payload = env.payload.replace('"run_id"', '"run_id" ', 1)  # any byte change
                break
    return envs


SCENARIOS: dict[str, Scenario] = {
    "clean": Scenario(loaded={"api": ["requests", "flask"]}),
    "malicious-dep": Scenario(added=[Dep("reqeusts", "1.0.0")]),
    "cve-origin": Scenario(added=[Dep("pyyaml", "5.3", "CVE-2020-14343", "CRITICAL")],
                           loaded={"api": ["flask", "yaml"], "worker": ["yaml"]}),
    "unreachable": Scenario(added=[Dep("lxml", "4.6.2", "CVE-2021-43818", "CRITICAL")],
                            loaded={s: ["flask", "requests"] for s in ["api", "worker", "web"]}),
    "tampered": Scenario(added=[Dep("pyyaml", "5.3", "CVE-2020-14343", "CRITICAL")], tamper_stage="scan"),
    "unsigned-missing": Scenario(drop_stage="scan"),
}


def random_scenario(n_services: int, n_deps: int, seed: int = 0) -> Scenario:
    """Random large scenario for the scale benchmark.

    Args:
        n_services: Number of services.
        n_deps: Dependencies per service.
        seed: Random seed.

    Returns:
        A deterministic scenario.
    """
    rnd = random.Random(seed)
    deps = [Dep(f"pkg{i}", f"1.{rnd.randint(0, 9)}.0",
                f"CVE-2099-{i:05d}" if rnd.random() < 0.1 else None,
                rnd.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])) for i in range(n_deps)]
    svcs = [f"svc{i}" for i in range(n_services)]
    loaded = {s: [d.name for d in deps if rnd.random() < 0.3] for s in svcs}
    return Scenario(services=svcs, base_deps=deps, loaded=loaded)
