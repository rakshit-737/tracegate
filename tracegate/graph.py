"""In-memory provenance DAG. A Neo4j adapter is a TODO seam (same API)."""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable

from .models import Edge, Finding, Node, NodeKind


class CycleError(Exception):
    pass


class ProvenanceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.out: dict[str, set[Edge]] = defaultdict(set)
        self.inc: dict[str, set[Edge]] = defaultdict(set)
        self.findings: list[Finding] = []

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is not None:
            existing.attrs.update(node.attrs)
            return existing
        self.nodes[node.id] = node
        return node

    def add_edge(self, src: str, dst: str, rel: str) -> None:
        for n in (src, dst):
            if n not in self.nodes:
                raise KeyError(f"unknown node {n}")
        if src == dst or src in self.descendants(dst):
            raise CycleError(f"{src} -> {dst} would create a cycle")
        e = Edge(src, dst, rel)
        self.out[src].add(e)
        self.inc[dst].add(e)

    def add_finding(self, f: Finding) -> None:
        if f.node_id not in self.nodes:
            raise KeyError(f"finding on unknown node {f.node_id}")
        self.findings.append(f)

    def _walk(self, start: str, forward: bool) -> set[str]:
        adj = self.out if forward else self.inc
        seen: set[str] = set()
        q = deque([start])
        while q:
            cur = q.popleft()
            for e in adj.get(cur, ()):
                nxt = e.dst if forward else e.src
                if nxt not in seen:
                    seen.add(nxt)
                    q.append(nxt)
        return seen

    def ancestors(self, nid: str) -> set[str]:
        return self._walk(nid, forward=False)

    def descendants(self, nid: str) -> set[str]:
        return self._walk(nid, forward=True)

    def upstream_path(self, nid: str, kind: NodeKind) -> list[str] | None:
        """Shortest path [origin(kind) ... nid] walking upstream from nid."""
        prev: dict[str, str | None] = {nid: None}
        q = deque([nid])
        while q:
            cur = q.popleft()
            if cur != nid and self.nodes[cur].kind == kind:
                path = [cur]
                while prev[path[-1]] is not None:
                    path.append(prev[path[-1]])  # type: ignore[arg-type]
                return path
            for e in sorted(self.inc.get(cur, ()), key=lambda e: e.src):
                if e.src not in prev:
                    prev[e.src] = cur
                    q.append(e.src)
        return None

    def of_kind(self, kind: NodeKind) -> Iterable[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def findings_for(self, nid: str) -> list[Finding]:
        return [f for f in self.findings if f.node_id == nid]

    def stats(self) -> dict[str, int]:
        return {
            "nodes": len(self.nodes),
            "edges": sum(len(v) for v in self.out.values()),
            "findings": len(self.findings),
        }
