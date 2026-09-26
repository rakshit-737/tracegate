"""Content-addressing: the same artifact gets the same id at every stage."""
import hashlib
import json
from typing import Any

from .models import NodeKind


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def digest(kind: NodeKind, identity: Any) -> str:
    h = hashlib.sha256(canonical(identity).encode()).hexdigest()
    return f"{kind.value}:sha256:{h[:32]}"


def purl(name: str, version: str, ecosystem: str = "pypi") -> str:
    return f"pkg:{ecosystem}/{name.lower().replace('_', '-')}@{version}"


def dep_id(name: str, version: str, ecosystem: str = "pypi") -> str:
    # purl identity so manifest, Syft SBOM and Trivy findings converge on one node.
    return digest(NodeKind.DEPENDENCY, purl(name, version, ecosystem))
