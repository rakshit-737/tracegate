"""Finding -> origin commit backtracking and blast-radius analysis."""
from __future__ import annotations

from typing import Any

from .graph import ProvenanceGraph
from .models import NodeKind


def blast_radius(g: ProvenanceGraph, node_id: str) -> dict[str, list[str]]:
    down = g.descendants(node_id)
    return {
        "images": sorted(g.nodes[n].label for n in down if g.nodes[n].kind == NodeKind.IMAGE),
        "services": sorted({g.nodes[n].label for n in down if g.nodes[n].kind == NodeKind.DEPLOYMENT}),
        "containers": sorted(g.nodes[n].label for n in down if g.nodes[n].kind == NodeKind.CONTAINER),
    }


def origin_story(g: ProvenanceGraph, query: str) -> list[dict[str, Any]]:
    """query: a CVE id, finding id, or package name. Returns one story per matching finding."""
    q = query.lower()
    out = []
    for f in g.findings:
        node = g.nodes[f.node_id]
        if q not in {(f.cve or "").lower(), f.id.lower(), str(node.attrs.get("name", "")).lower()}:
            continue
        path = g.upstream_path(f.node_id, NodeKind.COMMIT)
        commit = g.nodes[path[0]] if path else None
        builds = sorted(g.nodes[n].label for n in g.descendants(commit.id)
                        if g.nodes[n].kind == NodeKind.BUILD) if commit else []
        out.append({
            "finding": f.to_dict(),
            "artifact": node.label,
            "introduced_by": None if commit is None else {
                "sha": commit.attrs["sha"], "author": commit.attrs.get("author"),
                "pr": commit.attrs.get("pr"), "message": commit.attrs.get("message")},
            "builds": builds,
            "path": [f"{g.nodes[n].kind.value}:{g.nodes[n].label}" for n in (path or [])],
            "blast_radius": blast_radius(g, f.node_id),
        })
    return out


def layer_blast_radius(g: ProvenanceGraph, layer_digest_prefix: str) -> dict[str, list[str]]:
    for n in g.of_kind(NodeKind.LAYER):
        if n.attrs["digest"].startswith(layer_digest_prefix):
            return blast_radius(g, n.id)
    raise KeyError(f"no layer matching {layer_digest_prefix}")
