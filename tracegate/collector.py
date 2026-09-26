"""Provenance collector: verifies signed stage events and stitches them into the DAG.

Accepted payload shapes (subsets of the real tool outputs):
  commit  : {sha, author, pr, message, files:[path], deps_added:[{name, version}]}
  sast    : {commit, findings:[{file, rule, severity, title}]}
  build   : {build_id, commit, image:{name, digest, layers:[{digest, created_by}]},
             sbom:{artifacts:[{name, version, locations:[{layerID}]}]}}     # Syft-like
  scan    : {image_digest, Results:[{Vulnerabilities:[{VulnerabilityID, PkgName,
             InstalledVersion, Severity, Title}]}]}                         # Trivy-like
  deploy  : {service, image_digest, containers:[id]}
  runtime : {container, loaded_modules:[name]}
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .graph import ProvenanceGraph
from .ids import digest, dep_id, purl
from .models import Envelope, Finding, Node, NodeKind, Severity, StageEvent
from .signing import SignatureError, Verifier

REQUIRED_STAGES = frozenset({"commit", "build", "scan"})


def _sev(s: str) -> Severity:
    try:
        return Severity(str(s).lower())
    except ValueError:
        return Severity.MEDIUM  # UNKNOWN/NEGLIGIBLE -> medium, conservative


@dataclass
class CollectResult:
    graph: ProvenanceGraph
    rejected: list[str] = field(default_factory=list)
    stages_seen: set[str] = field(default_factory=set)
    runtime: dict[str, set[str]] = field(default_factory=dict)  # container id -> modules

    @property
    def missing_stages(self) -> set[str]:
        return set(REQUIRED_STAGES) - self.stages_seen

    @property
    def coverage(self) -> float:
        return len(self.stages_seen & REQUIRED_STAGES) / len(REQUIRED_STAGES)


class Collector:
    def __init__(self, verifier: Verifier):
        self.verifier = verifier

    def collect(self, envelopes: Iterable[Envelope]) -> CollectResult:
        res = CollectResult(ProvenanceGraph())
        events: list[StageEvent] = []
        for i, env in enumerate(envelopes):
            try:
                events.append(self.verifier.verify(env))
            except SignatureError as e:
                res.rejected.append(f"envelope[{i}]: {e}")
        order = ["commit", "sast", "build", "scan", "deploy", "runtime"]
        events.sort(key=lambda ev: order.index(ev.stage) if ev.stage in order else 99)
        for ev in events:
            handler = getattr(self, f"_on_{ev.stage}", None)
            if handler is None:
                res.rejected.append(f"unknown stage {ev.stage!r} (run {ev.run_id})")
                continue
            handler(res, ev)
            res.stages_seen.add(ev.stage)
        return res

    # --- stage handlers -------------------------------------------------
    @staticmethod
    def _commit_id(sha: str) -> str:
        return digest(NodeKind.COMMIT, sha)

    def _on_commit(self, res: CollectResult, ev: StageEvent) -> None:
        g, p = res.graph, ev.payload
        cid = self._commit_id(p["sha"])
        g.add_node(Node(cid, NodeKind.COMMIT, p["sha"][:12], {
            "sha": p["sha"], "author": p.get("author"), "pr": p.get("pr"),
            "message": p.get("message", ""), "run_id": ev.run_id}))
        for path in p.get("files", []):
            fid = digest(NodeKind.FILE, [p["sha"], path])
            g.add_node(Node(fid, NodeKind.FILE, path, {"path": path}))
            g.add_edge(cid, fid, "modifies")
        for d in p.get("deps_added", []):
            did = dep_id(d["name"], d["version"])
            g.add_node(Node(did, NodeKind.DEPENDENCY, f"{d['name']}=={d['version']}",
                            {"name": d["name"], "version": d["version"],
                             "purl": purl(d["name"], d["version"])}))
            g.add_edge(cid, did, "introduced")

    def _on_sast(self, res: CollectResult, ev: StageEvent) -> None:
        g, p = res.graph, ev.payload
        for i, f in enumerate(p.get("findings", [])):
            fid = digest(NodeKind.FILE, [p["commit"], f["file"]])
            if fid not in g.nodes:
                g.add_node(Node(fid, NodeKind.FILE, f["file"], {"path": f["file"]}))
                cid = self._commit_id(p["commit"])
                if cid in g.nodes:
                    g.add_edge(cid, fid, "modifies")
            g.add_finding(Finding(f"sast-{ev.run_id}-{i}", fid, "sast", _sev(f["severity"]),
                                  f"{f['rule']}: {f['title']}"))

    def _on_build(self, res: CollectResult, ev: StageEvent) -> None:
        g, p = res.graph, ev.payload
        bid = digest(NodeKind.BUILD, p["build_id"])
        g.add_node(Node(bid, NodeKind.BUILD, p["build_id"], {"run_id": ev.run_id}))
        cid = self._commit_id(p["commit"])
        if cid in g.nodes:
            g.add_edge(cid, bid, "built_by")
        img = p["image"]
        iid = digest(NodeKind.IMAGE, img["digest"])
        g.add_node(Node(iid, NodeKind.IMAGE, img.get("name", img["digest"][:19]),
                        {"digest": img["digest"]}))
        g.add_edge(bid, iid, "produced")
        layer_ids: dict[str, str] = {}
        for layer in img.get("layers", []):
            lid = digest(NodeKind.LAYER, layer["digest"])  # shared across images
            layer_ids[layer["digest"]] = lid
            g.add_node(Node(lid, NodeKind.LAYER, layer["digest"][:19],
                            {"digest": layer["digest"], "created_by": layer.get("created_by", "")}))
            g.add_edge(lid, iid, "layer_of")
        for art in p.get("sbom", {}).get("artifacts", []):
            did = dep_id(art["name"], art["version"])
            g.add_node(Node(did, NodeKind.DEPENDENCY, f"{art['name']}=={art['version']}",
                            {"name": art["name"], "version": art["version"],
                             "purl": purl(art["name"], art["version"]),
                             "import_name": art.get("import_name") or art["name"].lower().replace("-", "_")}))
            locs = [loc.get("layerID") for loc in art.get("locations", [])]
            targets = [layer_ids[l] for l in locs if l in layer_ids] or [iid]
            for t in targets:
                g.add_edge(did, t, "installed_in")

    def _on_scan(self, res: CollectResult, ev: StageEvent) -> None:
        g, p = res.graph, ev.payload
        for r in p.get("Results", []):
            for v in r.get("Vulnerabilities") or []:
                did = dep_id(v["PkgName"], v["InstalledVersion"])
                if did not in g.nodes:
                    continue  # finding for a package the SBOM never saw: ignore (logged via coverage)
                fid = f"{v['VulnerabilityID']}@{did}"
                if any(f.id == fid for f in g.findings):
                    continue
                g.add_finding(Finding(fid, did, "trivy", _sev(v.get("Severity", "medium")),
                                      v.get("Title", v["VulnerabilityID"]), cve=v["VulnerabilityID"]))

    def _on_deploy(self, res: CollectResult, ev: StageEvent) -> None:
        g, p = res.graph, ev.payload
        iid = digest(NodeKind.IMAGE, p["image_digest"])
        if iid not in g.nodes:
            res.rejected.append(f"deploy of unknown image {p['image_digest']} (no build provenance)")
            return
        depid = digest(NodeKind.DEPLOYMENT, [p["service"], p["image_digest"]])
        g.add_node(Node(depid, NodeKind.DEPLOYMENT, p["service"], {"service": p["service"]}))
        g.add_edge(iid, depid, "deployed_as")
        for c in p.get("containers", []):
            ctid = digest(NodeKind.CONTAINER, c)
            g.add_node(Node(ctid, NodeKind.CONTAINER, c, {"service": p["service"]}))
            g.add_edge(depid, ctid, "runs")

    def _on_runtime(self, res: CollectResult, ev: StageEvent) -> None:
        p = ev.payload
        ctid = digest(NodeKind.CONTAINER, p["container"])
        res.runtime.setdefault(ctid, set()).update(m.lower() for m in p.get("loaded_modules", []))
