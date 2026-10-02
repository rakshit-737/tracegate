"""Typed contracts shared by every TRACEGATE engine."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class NodeKind(str, Enum):
    """Kinds of node in the provenance graph."""
    COMMIT = "commit"
    FILE = "file"
    DEPENDENCY = "dependency"
    BUILD = "build"
    LAYER = "layer"
    IMAGE = "image"
    DEPLOYMENT = "deployment"
    CONTAINER = "container"


class Severity(str, Enum):
    """Finding severity, ordered low < medium < high < critical."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Position in the severity order (0 = low)."""
        return ["low", "medium", "high", "critical"].index(self.value)


class Verdict(str, Enum):
    """Gate verdict, ordered pass < warn < block."""
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        """Position in the verdict order (0 = pass)."""
        return ["pass", "warn", "block"].index(self.value)


@dataclass
class Node:
    """A content-addressed artefact in the graph."""
    id: str  # content-addressed, e.g. "dependency:sha256:..."
    kind: NodeKind
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Edge:
    """A directed relation from an input to what it produced."""
    src: str  # upstream input
    dst: str  # downstream output
    rel: str


@dataclass
class Finding:
    """A scanner, Warden or policy finding attached to a node."""
    id: str
    node_id: str
    source: str  # sast | trivy | warden | runtime
    severity: Severity
    title: str
    cve: str | None = None
    reachable: bool | None = None  # None = unknown
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict with enum values as strings."""
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class StageEvent:
    """One CI/CD stage emission, before signing."""
    stage: str  # commit | sast | build | scan | deploy | runtime
    run_id: str
    payload: dict[str, Any]


@dataclass
class Envelope:
    """DSSE-like signed envelope around a StageEvent."""
    payload_type: str
    payload: str  # canonical JSON of StageEvent
    keyid: str
    sig: str


@dataclass
class Decision:
    """Gate verdict with the reasons that produced it."""
    verdict: Verdict
    reasons: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict of the verdict and reasons."""
        return {"verdict": self.verdict.value, "reasons": self.reasons}
