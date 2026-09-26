"""Enrichment: Warden risk onto dependency nodes, reachability onto findings."""
from __future__ import annotations

from .collector import CollectResult
from .models import Finding, NodeKind, Severity
from .warden import WardenClient


def enrich_warden(res: CollectResult, warden: WardenClient, threshold: float = 0.5) -> None:
    g = res.graph
    for dep in g.of_kind(NodeKind.DEPENDENCY):
        s = warden.score(dep.attrs["name"], dep.attrs["version"])
        dep.attrs["warden_risk"] = s.risk
        if s.risk >= threshold:
            fid = f"warden@{dep.id}"
            if not any(f.id == fid for f in g.findings):
                sev = Severity.CRITICAL if s.risk >= 0.8 else Severity.HIGH
                g.add_finding(Finding(fid, dep.id, "warden", sev,
                                      f"Warden risk {s.risk:.2f}: " + "; ".join(s.reasons),
                                      evidence=s.reasons))


def enrich_reachability(res: CollectResult) -> None:
    """A dependency finding is reachable if any downstream container loaded its module.

    No runtime facts for any downstream container -> reachable stays None (unknown).
    """
    g = res.graph
    for f in g.findings:
        node = g.nodes[f.node_id]
        if node.kind != NodeKind.DEPENDENCY or f.source == "warden":
            continue
        mod = node.attrs.get("import_name", node.attrs["name"].lower().replace("-", "_"))
        containers = [c for c in g.descendants(node.id) if g.nodes[c].kind == NodeKind.CONTAINER]
        observed = [c for c in containers if c in res.runtime]
        if not observed:
            f.reachable = None
            continue
        hits = [g.nodes[c].label for c in observed if mod in res.runtime[c]]
        f.reachable = bool(hits)
        f.evidence.append(
            f"module '{mod}' loaded in {hits}" if hits
            else f"module '{mod}' not loaded in {len(observed)} observed container(s)")


def enrich(res: CollectResult, warden: WardenClient) -> None:
    enrich_warden(res, warden)
    enrich_reachability(res)


def actionable(findings: list[Finding], min_sev: Severity = Severity.HIGH) -> list[Finding]:
    return [f for f in findings if f.severity.rank >= min_sev.rank and f.reachable is not False]
