"""Content-addressing: the same artifact gets the same id at every stage.

Dependencies are keyed by a *canonical purl*: type + namespace + normalised name
+ version, with qualifiers (arch, distro, ...) and subpaths dropped. Syft,
Trivy, a requirements.txt diff and an OSV record all describe the same package
slightly differently; canonicalising the purl is what makes them converge on one
graph node.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from functools import lru_cache
from typing import Any

from .models import NodeKind

_PEP503 = re.compile(r"[-_.]+")


def canonical(obj: Any) -> str:
    """Canonical JSON (sorted keys, no spaces) used for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def digest(kind: NodeKind, identity: Any) -> str:
    """Content-addressed node id: the kind plus the sha256 of the canonical identity."""
    h = hashlib.sha256(canonical(identity).encode()).hexdigest()
    return f"{kind.value}:sha256:{h[:32]}"


def normalize_name(name: str, ecosystem: str = "pypi") -> str:
    """Normalise a package name the way its ecosystem compares names.

    Args:
        name: Package name as written.
        ecosystem: Ecosystem name such as ``pypi``, ``npm``, ``cargo`` or ``golang``.

    Returns:
        The normalised name.
    """
    eco = ecosystem.lower()
    n = name.strip()
    if eco == "pypi":
        return _PEP503.sub("-", n.lower())
    if eco in ("npm", "deb", "apk", "golang", "gem", "cargo", "nuget", "rpm"):
        return n.lower() if eco != "golang" else n
    return n


@lru_cache(maxsize=65536)
def purl(name: str, version: str, ecosystem: str = "pypi", namespace: str | None = None) -> str:
    """Build a package URL.

    Args:
        name: Package name.
        version: Exact version.
        ecosystem: Ecosystem name.
        namespace: Optional purl namespace, such as an npm scope.

    Returns:
        A purl string such as ``pkg:pypi/pyyaml@5.3.1``.
    """
    eco = ecosystem.lower()
    n = normalize_name(name, eco)
    ns = f"{namespace.lower()}/" if namespace else ""
    return f"pkg:{eco}/{ns}{urllib.parse.quote(n, safe='@/')}@{version}"


@lru_cache(maxsize=65536)
def canonical_purl(p: str) -> str:
    """Strip qualifiers/subpath and normalise the name, e.g.

    pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12 -> pkg:deb/debian/libssl3@3.0.11-1~deb12u2
    pkg:pypi/PyYAML@5.3 -> pkg:pypi/pyyaml@5.3
    """
    p = p.split("#", 1)[0].split("?", 1)[0]
    if not p.startswith("pkg:"):
        raise ValueError(f"not a purl: {p!r}")
    body = p[4:]
    typ, _, rest = body.partition("/")
    rest, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    parts = [urllib.parse.unquote(x) for x in rest.split("/")]
    name = parts[-1]
    ns = [x.lower() for x in parts[:-1]]
    typ = typ.lower()
    n = normalize_name(name, typ)
    enc = urllib.parse.quote(n, safe="")
    return f"pkg:{typ}/" + "/".join([*ns, enc]) + (f"@{urllib.parse.unquote(version)}" if version else "")


def dep_id(name: str, version: str, ecosystem: str = "pypi") -> str:
    # purl identity so manifest, Syft SBOM and Trivy findings converge on one node.
    """Node id of a dependency.

    The id is derived from the purl so that manifest pins, Syft SBOM entries and Trivy findings converge on one node.
    """
    return dep_id_from_purl(purl(name, version, ecosystem))


@lru_cache(maxsize=65536)
def dep_id_from_purl(p: str) -> str:
    """Node id of a dependency given its purl."""
    return digest(NodeKind.DEPENDENCY, canonical_purl(p))
