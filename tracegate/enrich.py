"""Enrichment: Warden risk onto dependency nodes, reachability onto findings."""
from __future__ import annotations

from .collector import CollectResult
from .models import Finding, NodeKind, Severity
from .warden import WardenClient


def _warden_for(warden, eco: str):
    if hasattr(warden, "for_ecosystem"):
        return warden.for_ecosystem(eco)
    return warden if eco == "pypi" else None  # plain Warden clients score PyPI only


def enrich_warden(res: CollectResult, warden: WardenClient, threshold: float = 0.5) -> None:
    g = res.graph
    for dep in g.of_kind(NodeKind.DEPENDENCY):
        w = _warden_for(warden, dep.attrs.get("ecosystem", "pypi"))
        if w is None:
            continue  # e.g. OS packages: no name-based risk model applies
        s = w.score(dep.attrs["name"], dep.attrs["version"])
        dep.attrs["warden_risk"] = s.risk
        if s.risk >= threshold:
            fid = f"warden@{dep.id}"
            if not g.has_finding(fid):
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


def enrich_static_reachability(res: CollectResult, report) -> int:
    """Fill reachability from a static `tracegate.reach.ReachReport` where runtime facts are absent.

    Runtime evidence always wins; returns the number of findings updated.
    """
    g, n = res.graph, 0
    for f in g.findings:
        node = g.nodes[f.node_id]
        if node.kind != NodeKind.DEPENDENCY or f.source == "warden" or f.reachable is not None:
            continue
        r = report.reachable(node.attrs["name"])
        if r is None:
            continue
        f.reachable = r
        f.evidence.append(f"static: {report.evidence.get(node.attrs['name'].lower(), report.status.get(node.attrs['name'].lower()))}")
        n += 1
    return n
