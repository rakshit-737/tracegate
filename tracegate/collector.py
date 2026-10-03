"""Provenance collector: verifies signed stage events and stitches them into the DAG.

Accepted payload shapes (subsets of the real tool outputs; see tracegate.ingest
for the adapters that produce them from real Syft / CycloneDX / Trivy JSON):
  commit  : {sha, author, pr, message, seq?, timestamp?, files:[path],
             deps_added:[{name, version, ecosystem?}], deps_removed:[...]}
  sast    : {commit, findings:[{file, rule, severity, title}]}
  build   : {build_id, commit?, image?:{name, digest, layers:[{digest, created_by}]},
             sbom:{artifacts:[{name, version, purl?, locations:[{layerID}]}]}}  # Syft
  scan    : {image_digest?, Results:[{Type?, Vulnerabilities:[{VulnerabilityID, PkgName,
             InstalledVersion, Severity, Title, PURL?, Ecosystem?, LayerDiffID?}]}]}  # Trivy

A scanner finding that lands on no SBOM node is kept in `CollectResult.unmatched_findings`;
the policy blocks on unmatched HIGH/CRITICAL findings (rule `unattributed_finding`), so a
finding can never disappear from the verdict because its package is missing from the SBOM.
  deploy  : {service, image_digest, containers:[id]}
  runtime : {container, loaded_modules:[name]}
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .graph import ProvenanceGraph
from .ids import canonical_purl, dep_id_from_purl, digest, normalize_name, purl
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
    """Output of collection: the graph plus which stages were verified or rejected."""
    graph: ProvenanceGraph
    rejected: list[str] = field(default_factory=list)
    stages_seen: set[str] = field(default_factory=set)
    runtime: dict[str, set[str]] = field(default_factory=dict)  # container id -> modules
    unmatched: list[str] = field(default_factory=list)  # "CVE pkg@version" of scanner findings with no SBOM node
    unmatched_findings: list[dict] = field(default_factory=list)  # the same findings, structured (policy input)

    @property
    def missing_stages(self) -> set[str]:
        """Required pipeline stages that produced no verified event."""
        return set(REQUIRED_STAGES) - self.stages_seen

    @property
    def coverage(self) -> float:
        """Fraction of required stages that produced a verified event."""
        return len(self.stages_seen & REQUIRED_STAGES) / len(REQUIRED_STAGES)


class Collector:
    """Verifies signed stage events and merges them into one provenance graph."""
    def __init__(self, verifier: Verifier):
        self.verifier = verifier

    def collect(self, envelopes: Iterable[Envelope]) -> CollectResult:
        """Verify envelopes and build the provenance graph.

        Envelopes that fail verification are recorded in ``rejected`` and add nothing to the graph.

        Args:
            envelopes: Signed stage events.

        Returns:
            The graph, the stages seen and the rejected envelopes.
        """
        res = CollectResult(ProvenanceGraph())
        events: list[StageEvent] = []
        for i, env in enumerate(envelopes):
            try:
                events.append(self.verifier.verify(env))
            except SignatureError as e:
                res.rejected.append(f"envelope[{i}]: {e}")
            except Exception as e:  # noqa: BLE001 - any other failure on one envelope also fails closed
                res.rejected.append(f"envelope[{i}]: malformed ({type(e).__name__})")
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
            "message": p.get("message", ""), "run_id": ev.run_id,
            "seq": p.get("seq"), "timestamp": p.get("timestamp"),
            "deps_removed": [f"{d['name']}=={d['version']}" for d in p.get("deps_removed", [])]}))
        for path in p.get("files", []):
            fid = digest(NodeKind.FILE, [p["sha"], path])
            g.add_node(Node(fid, NodeKind.FILE, path, {"path": path}))
            g.add_edge(cid, fid, "modifies")
        for d in p.get("deps_added", []):
            eco = d.get("ecosystem", "pypi")
            pu = canonical_purl(d["purl"]) if d.get("purl") else purl(d["name"], d["version"], eco)
            did = dep_id_from_purl(pu)
            g.add_node(Node(did, NodeKind.DEPENDENCY, f"{d['name']}=={d['version']}",
                            {"name": d["name"], "version": d["version"], "purl": pu,
                             "ecosystem": eco}))
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
        g.add_node(Node(bid, NodeKind.BUILD, p["build_id"], {"run_id": ev.run_id,
                                                              "tool": p.get("tool")}))
        if p.get("commit"):
            cid = self._commit_id(p["commit"])
            if cid in g.nodes:
                g.add_edge(cid, bid, "built_by")
        img = p.get("image")
        default_target = bid
        layer_ids: dict[str, str] = {}
        if img and img.get("digest"):
            iid = digest(NodeKind.IMAGE, img["digest"])
            g.add_node(Node(iid, NodeKind.IMAGE, img.get("name") or img["digest"][:19],
                            {"digest": img["digest"], "repo_digests": img.get("repo_digests", [])}))
            g.add_edge(bid, iid, "produced")
            default_target = iid
            for layer in img.get("layers", []):
                lid = digest(NodeKind.LAYER, layer["digest"])  # shared across images
                layer_ids[layer["digest"]] = lid
                g.add_node(Node(lid, NodeKind.LAYER, layer["digest"][:19],
                                {"digest": layer["digest"], "created_by": layer.get("created_by", "")}))
                g.add_edge(lid, iid, "layer_of")
        for art in p.get("sbom", {}).get("artifacts", []):
            pu = art.get("purl") or purl(art["name"], art["version"])
            did = dep_id_from_purl(pu)
            eco = pu[4:].split("/", 1)[0]
            attrs = {"name": art["name"], "version": art["version"], "purl": canonical_purl(pu),
                     "ecosystem": eco}
            if eco == "pypi":
                attrs["import_name"] = art.get("import_name") or art["name"].lower().replace("-", "_")
            g.add_node(Node(did, NodeKind.DEPENDENCY, f"{art['name']}=={art['version']}", attrs))
            locs = [loc.get("layerID") for loc in art.get("locations", [])]
            targets = sorted({layer_ids[x] for x in locs if x in layer_ids}) or [default_target]
            for t in targets:
                g.add_edge(did, t, "installed_in")

    @staticmethod
    def _dep_index(g: ProvenanceGraph) -> dict[tuple[str, str, str], list[str]]:
        idx: dict[tuple[str, str, str], list[str]] = {}
        for n in g.of_kind(NodeKind.DEPENDENCY):
            eco = str(n.attrs.get("ecosystem") or "")
            name, ver = str(n.attrs.get("name", "")), str(n.attrs.get("version", ""))
            idx.setdefault((eco, normalize_name(name, eco or "pypi").lower(), ver), []).append(n.id)
            idx.setdefault(("*", name.lower(), ver), []).append(n.id)
        return idx

    def _match(self, g: ProvenanceGraph, v: dict, idx: dict) -> str | None:
        """Dependency node of a scanner row: its PURL, else a unique (ecosystem, name, version) match."""
        if v.get("PURL"):
            did = dep_id_from_purl(v["PURL"])
            return did if did in g.nodes else None
        eco = (v.get("Ecosystem") or "").lower()
        name, ver = str(v.get("PkgName", "")), str(v.get("InstalledVersion", ""))
        hits = idx.get((eco, normalize_name(name, eco).lower(), ver)) if eco else idx.get(("*", name.lower(), ver))
        return hits[0] if hits and len(set(hits)) == 1 else None

    def _on_scan(self, res: CollectResult, ev: StageEvent) -> None:
        g, p = res.graph, ev.payload
        idx = self._dep_index(g)
        for r in p.get("Results", []):
            for v in r.get("Vulnerabilities") or []:
                did = self._match(g, v, idx)
                if did is None:
                    # finding for a package the SBOM never saw: kept as a policy input (rule
                    # unattributed_finding), never silently dropped
                    res.unmatched.append(f"{v['VulnerabilityID']} {v['PkgName']}@{v['InstalledVersion']}")
                    res.unmatched_findings.append({
                        "id": f"{v['VulnerabilityID']}@{v['PkgName']}@{v['InstalledVersion']}",
                        "cve": v["VulnerabilityID"], "package": v["PkgName"], "version": v["InstalledVersion"],
                        "ecosystem": v.get("Ecosystem"), "purl": v.get("PURL"), "source": p.get("tool", "trivy"),
                        "severity": _sev(v.get("Severity", "medium")).value,
                        "title": v.get("Title", v["VulnerabilityID"])})
                    continue
                fid = f"{v['VulnerabilityID']}@{did}"
                if g.has_finding(fid):
                    continue
                ev_ = [f"fixed in {v['FixedVersion']}"] if v.get("FixedVersion") else []
                if v.get("LayerDiffID"):
                    ev_.append(f"layer {v['LayerDiffID'][:19]}")
                g.add_finding(Finding(fid, did, p.get("tool", "trivy"), _sev(v.get("Severity", "medium")),
                                      v.get("Title", v["VulnerabilityID"]), cve=v["VulnerabilityID"],
                                      evidence=ev_))

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
