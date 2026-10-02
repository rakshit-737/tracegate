"""Graph exports: JSON (UI / API), Cypher (Neo4j), and OPA policy input.

Neo4j is optional. `to_cypher` writes an idempotent MERGE script you can pipe
into `cypher-shell`; `Neo4jSink` pushes the same statements through the
official driver when `neo4j` is installed (see docker-compose.yml).
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from .collector import CollectResult
from .graph import ProvenanceGraph
from .models import NodeKind

_LABEL = {k: k.value.capitalize() for k in NodeKind}


def to_json(g: ProvenanceGraph) -> dict[str, Any]:
    """Serialise a graph to plain JSON (nodes, edges, findings)."""
    return {
        "nodes": [{"id": n.id, "kind": n.kind.value, "label": n.label,
                   "attrs": {k: v for k, v in n.attrs.items() if isinstance(v, (str, int, float, bool, list, type(None)))},
                   "findings": len(g.findings_for(n.id))} for n in g.nodes.values()],
        "edges": [{"src": e.src, "dst": e.dst, "rel": e.rel} for es in g.out.values() for e in es],
        "findings": [f.to_dict() for f in g.findings],
    }


def _lit(v: Any) -> str:
    return json.dumps(v if isinstance(v, (str, int, float, bool)) or v is None else json.dumps(v))


def cypher_statements(g: ProvenanceGraph) -> Iterator[str]:
    """Yield Cypher statements that rebuild the graph in Neo4j."""
    yield "CREATE CONSTRAINT tg_node IF NOT EXISTS FOR (n:Artifact) REQUIRE n.id IS UNIQUE;"
    for n in g.nodes.values():
        props = {"label": n.label, "kind": n.kind.value,
                 **{k: v for k, v in n.attrs.items() if isinstance(v, (str, int, float, bool))}}
        sets = ", ".join(f"n.`{k}` = {_lit(v)}" for k, v in sorted(props.items()))
        yield f"MERGE (n:Artifact:{_LABEL[n.kind]} {{id: {_lit(n.id)}}}) SET {sets};"
    for es in g.out.values():
        for e in sorted(es, key=lambda e: (e.src, e.dst, e.rel)):
            rel = e.rel.upper()
            yield (f"MATCH (a:Artifact {{id: {_lit(e.src)}}}), (b:Artifact {{id: {_lit(e.dst)}}}) "
                   f"MERGE (a)-[:{rel}]->(b);")
    for f in g.findings:
        yield (f"MATCH (a:Artifact {{id: {_lit(f.node_id)}}}) MERGE (f:Finding {{id: {_lit(f.id)}}}) "
               f"SET f.source = {_lit(f.source)}, f.severity = {_lit(f.severity.value)}, "
               f"f.cve = {_lit(f.cve)}, f.title = {_lit(f.title)}, f.reachable = {_lit(f.reachable)} "
               f"MERGE (f)-[:AFFECTS]->(a);")


def to_cypher(g: ProvenanceGraph) -> str:
    """Return the whole graph as one Cypher script."""
    return "\n".join(cypher_statements(g)) + "\n"


class Neo4jSink:  # pragma: no cover - needs a running Neo4j
    """Writes a provenance graph to a live Neo4j database."""
    def __init__(self, uri: str = "bolt://localhost:7687", user: str = "neo4j", password: str | None = None):
        import os

        from neo4j import GraphDatabase  # optional dependency
        password = password or os.environ["NEO4J_PASSWORD"]
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def write(self, g: ProvenanceGraph) -> int:
        """Write every node and edge of ``g``.

        Returns:
            Number of statements executed.
        """
        n = 0
        with self._driver.session() as s:
            for stmt in cypher_statements(g):
                s.run(stmt)
                n += 1
        return n

    def close(self) -> None:
        """Close the database driver."""
        self._driver.close()


# Example backtrack query once loaded into Neo4j:
BACKTRACK_CYPHER = """
MATCH (f:Finding {cve: $cve})-[:AFFECTS]->(d:Dependency)<-[:INTRODUCED]-(c:Commit)
RETURN c.sha, c.author, c.pr, d.label ORDER BY c.seq DESC LIMIT 1
"""


def opa_input(res: CollectResult) -> dict[str, Any]:
    """Input document for policies/tracegate.rego (`opa eval -i input.json ...`)."""
    g = res.graph
    from .policy import _path  # local import to avoid a cycle
    return {
        "rejected": list(res.rejected),
        "missing_stages": sorted(res.missing_stages),
        "findings": [{**f.to_dict(), "path": _path(res, f)} for f in g.findings],
    }
