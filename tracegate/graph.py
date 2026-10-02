"""In-memory provenance DAG (see tracegate.neo4j for the Neo4j export/adapter)."""
from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable

from .models import Edge, Finding, Node, NodeKind


class CycleError(Exception):
    """Raised when an edge would make the provenance graph cyclic."""


class ProvenanceGraph:
    """Content-addressed DAG of commits, dependencies, builds, layers, images and services."""
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.out: dict[str, set[Edge]] = defaultdict(set)
        self.inc: dict[str, set[Edge]] = defaultdict(set)
        self.findings: list[Finding] = []
        self._finding_ids: set[str] = set()

    def add_node(self, node: Node) -> Node:
        """Add a node, merging with an existing node of the same id.

        Returns:
            The stored node.
        """
        existing = self.nodes.get(node.id)
        if existing is not None:
            existing.attrs.update(node.attrs)
            return existing
        self.nodes[node.id] = node
        return node

    def add_edge(self, src: str, dst: str, rel: str) -> None:
        """Add a ``src -> dst`` edge labelled ``rel``.

        Raises:
            CycleError: The edge would create a cycle.
        """
        for n in (src, dst):
            if n not in self.nodes:
                raise KeyError(f"unknown node {n}")
        if src == dst or src in self.descendants(dst):
            raise CycleError(f"{src} -> {dst} would create a cycle")
        e = Edge(src, dst, rel)
        self.out[src].add(e)
        self.inc[dst].add(e)

    def add_finding(self, f: Finding) -> None:
        """Attach a finding to its node; duplicates by id are ignored."""
        if f.node_id not in self.nodes:
            raise KeyError(f"finding on unknown node {f.node_id}")
        if f.id in self._finding_ids:
            return
        self._finding_ids.add(f.id)
        self.findings.append(f)

    def has_finding(self, fid: str) -> bool:
        """Return True when a finding with this id is already attached."""
        return fid in self._finding_ids

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
        """All nodes upstream of ``nid``."""
        return self._walk(nid, forward=False)

    def descendants(self, nid: str) -> set[str]:
        """All nodes downstream of ``nid``."""
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
            for e in sorted(self.inc.get(cur, ()), key=self._recency_key):
                if e.src not in prev:
                    prev[e.src] = cur
                    q.append(e.src)
        return None

    def _recency_key(self, e: Edge) -> tuple:
        # Newest upstream node first (commit `seq` is its position in history), so a
        # package version that was introduced, removed and re-introduced backtracks
        # to the commit that introduced the copy that is actually shipped.
        seq = self.nodes[e.src].attrs.get("seq")
        return (1 if seq is None else 0, -(seq or 0), e.src)

    def of_kind(self, kind: NodeKind) -> Iterable[Node]:
        """All nodes of one kind."""
        return [n for n in self.nodes.values() if n.kind == kind]

    def findings_for(self, nid: str) -> list[Finding]:
        """Findings attached to node ``nid``."""
        return [f for f in self.findings if f.node_id == nid]

    def stats(self) -> dict[str, int]:
        """Counts of nodes, edges and findings."""
        return {
            "nodes": len(self.nodes),
            "edges": sum(len(v) for v in self.out.values()),
            "findings": len(self.findings),
        }
