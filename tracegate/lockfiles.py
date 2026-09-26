"""Pinned-version parsers for lock files, dispatched on the manifest file name.

Supported: requirements*.txt (pip / pip-compile), package-lock.json (npm v1-v3),
poetry.lock and uv.lock (both TOML `[[package]]` tables). Returns
{normalised name: version} plus the ecosystem, which is what the lineage collector diffs.
The TOML reader is a tiny line scanner so it also works on Python 3.10 (no tomllib).
"""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from .ids import normalize_name

_KV = re.compile(r'^\s*(name|version)\s*=\s*"([^"]*)"\s*$')


def parse_package_lock(text: str) -> dict[str, str]:
    if not text.strip():
        return {}
    doc = json.loads(text)
    out: dict[str, str] = {}
    pkgs = doc.get("packages")
    if pkgs:  # lockfileVersion 2/3: keys are node_modules paths
        for path, meta in pkgs.items():
            if not path or meta.get("link") or "version" not in meta:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            out.setdefault(name.lower(), meta["version"])
        return out

    def walk(deps: dict) -> None:  # lockfileVersion 1: nested "dependencies"
        for name, meta in (deps or {}).items():
            if "version" in meta:
                out.setdefault(name.lower(), meta["version"])
            walk(meta.get("dependencies"))
    walk(doc.get("dependencies"))
    return out


def parse_toml_packages(text: str) -> dict[str, str]:
    """poetry.lock / uv.lock: name+version of each top-level `[[package]]` table."""
    out: dict[str, str] = {}
    cur: dict[str, str] | None = None

    def flush() -> None:
        if cur and "name" in cur and "version" in cur:
            out[normalize_name(cur["name"])] = cur["version"]

    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            flush()
            cur = {} if s == "[[package]]" else None
            continue
        if cur is not None:
            m = _KV.match(line)
            if m and m.group(1) not in cur:
                cur[m.group(1)] = m.group(2)
    flush()
    return out


def ecosystem_for(manifest: str) -> str:
    return "npm" if PurePosixPath(manifest).name == "package-lock.json" else "pypi"


def parse_manifest(manifest: str, text: str) -> dict[str, str]:
    name = PurePosixPath(manifest.replace("\\", "/")).name
    if name == "package-lock.json":
        return parse_package_lock(text)
    if name in ("poetry.lock", "uv.lock"):
        return parse_toml_packages(text)
    from .gitlineage import parse_requirements
    return parse_requirements(text)


__all__ = ["parse_manifest", "parse_package_lock", "parse_toml_packages", "ecosystem_for"]
