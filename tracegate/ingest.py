"""Adapters from real tool output to TRACEGATE stage payloads.

  syft -o syft-json        -> build payload  (image, layers, SBOM artifacts with purls)
  syft -o cyclonedx-json   -> build payload  (components with purls; no layer info)
  trivy --format json      -> scan payload   (vulns with PkgIdentifier.PURL and Layer.DiffID)

Only the fields the collector needs are kept, so a large real scan becomes a
small, signable event. Unknown/missing fields degrade gracefully.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ids import canonical_purl


def _load(src: str | Path | dict) -> dict:
    if isinstance(src, dict):
        return src
    return json.loads(Path(src).read_text(encoding="utf-8"))


# Trivy result Type -> purl type, for rows that carry no PkgIdentifier.PURL
TRIVY_TYPE_ECOSYSTEM = {
    "alpine": "apk", "wolfi": "apk", "chainguard": "apk",
    "debian": "deb", "ubuntu": "deb",
    "redhat": "rpm", "centos": "rpm", "rocky": "rpm", "alma": "rpm", "amazon": "rpm", "oracle": "rpm",
    "fedora": "rpm", "photon": "rpm", "cbl-mariner": "rpm", "azurelinux": "rpm", "suse linux enterprise server": "rpm",
    "opensuse.leap": "rpm", "opensuse.tumbleweed": "rpm",
    "python-pkg": "pypi", "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "uv": "pypi",
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm", "bun": "npm",
    "gomod": "golang", "gobinary": "golang",
    "cargo": "cargo", "rust-binary": "cargo",
    "bundler": "gem", "gemspec": "gem",
    "nuget": "nuget", "dotnet-core": "nuget", "packages-props": "nuget",
    "jar": "maven", "pom": "maven", "gradle": "maven", "sbt": "maven",
    "composer": "composer", "composer-vendor": "composer", "conan": "conan", "cocoapods": "cocoapods",
    "swift": "swift", "pub": "pub", "hex": "hex", "conda-pkg": "conda",
}


def trivy_ecosystem(result_type: str | None) -> str | None:
    """purl type for a Trivy result ``Type`` (``alpine`` -> ``apk``, ``python-pkg`` -> ``pypi``), else None."""
    return TRIVY_TYPE_ECOSYSTEM.get((result_type or "").strip().lower())


def _eco_from_purl(p: str | None) -> str | None:
    if not p or not p.startswith("pkg:"):
        return None
    return p[4:].split("/", 1)[0].lower()


def syft_json_to_build(src: str | Path | dict, build_id: str, commit: str | None = None) -> dict[str, Any]:
    """Convert Syft JSON output into a build stage payload.

    Args:
        src: Path to, or parsed, ``syft -o syft-json`` output.
        build_id: Build identifier.
        commit: Commit SHA the build was made from.

    Returns:
        A build payload with image, layers and packages.
    """
    doc = _load(src)
    source = doc.get("source", {}) or {}
    meta = source.get("metadata", {}) or {}
    payload: dict[str, Any] = {"build_id": build_id, "commit": commit, "tool": "syft",
                               "tool_version": (doc.get("descriptor") or {}).get("version")}
    if source.get("type") == "image" or "imageID" in meta:
        layers = [{"digest": ly["digest"], "size": ly.get("size")} for ly in meta.get("layers", [])]
        payload["image"] = {
            "name": meta.get("userInput") or source.get("name"),
            "digest": meta.get("imageID") or meta.get("manifestDigest"),
            "repo_digests": meta.get("repoDigests", []),
            "layers": layers,
        }
    else:
        payload["source"] = {"type": source.get("type"), "name": source.get("name")}
    arts = []
    for a in doc.get("artifacts", []):
        p = a.get("purl")
        if not p or not a.get("version"):
            continue
        try:
            cp = canonical_purl(p)
        except ValueError:
            continue
        arts.append({
            "name": a["name"], "version": a["version"], "purl": cp, "type": a.get("type"),
            "locations": [{"layerID": loc.get("layerID"), "path": loc.get("path")}
                          for loc in a.get("locations", []) if loc.get("layerID") or loc.get("path")],
        })
    payload["sbom"] = {"artifacts": arts}
    return payload


def cyclonedx_to_build(src: str | Path | dict, build_id: str, commit: str | None = None) -> dict[str, Any]:
    """Convert a CycloneDX JSON SBOM into a build stage payload.

    Args:
        src: Path to, or parsed, CycloneDX JSON.
        build_id: Build identifier.
        commit: Commit SHA the build was made from.

    Returns:
        A build payload with the components as packages.
    """
    doc = _load(src)
    comps = []
    stack = list(doc.get("components", []))
    while stack:
        c = stack.pop()
        stack.extend(c.get("components", []) or [])
        p = c.get("purl")
        if not p or not c.get("version"):
            continue
        try:
            comps.append({"name": c["name"], "version": c["version"], "purl": canonical_purl(p),
                          "type": c.get("type"), "locations": []})
        except ValueError:
            continue
    md = (doc.get("metadata") or {}).get("component") or {}
    return {"build_id": build_id, "commit": commit, "tool": "cyclonedx",
            "source": {"type": md.get("type"), "name": md.get("name")},
            "sbom": {"artifacts": comps}}


def trivy_json_to_scan(src: str | Path | dict) -> dict[str, Any]:
    """Convert ``trivy --format json`` output into a scan stage payload.

    Args:
        src: Path to, or parsed, Trivy JSON.

    Returns:
        A scan payload with one finding per vulnerability and package.
    """
    doc = _load(src)
    md = doc.get("Metadata", {}) or {}
    results = []
    for r in doc.get("Results", []) or []:
        vulns = []
        eco = trivy_ecosystem(r.get("Type"))
        for v in r.get("Vulnerabilities") or []:
            ident = v.get("PkgIdentifier") or {}
            p = ident.get("PURL")
            try:
                p = canonical_purl(p) if p else None
            except ValueError:
                p = None
            vulns.append({
                "VulnerabilityID": v["VulnerabilityID"], "PkgName": v["PkgName"],
                "InstalledVersion": v.get("InstalledVersion", ""), "FixedVersion": v.get("FixedVersion"),
                "Severity": v.get("Severity", "UNKNOWN"), "Title": v.get("Title") or v["VulnerabilityID"],
                "PURL": p, "Ecosystem": _eco_from_purl(p) or eco, "LayerDiffID": (v.get("Layer") or {}).get("DiffID"),
            })
        results.append({"Target": r.get("Target"), "Class": r.get("Class"), "Type": r.get("Type"),
                        "Vulnerabilities": vulns})
    return {"artifact": doc.get("ArtifactName"), "image_digest": md.get("ImageID"),
            "diff_ids": md.get("DiffIDs", []), "tool": "trivy", "Results": results}


__all__ = ["syft_json_to_build", "cyclonedx_to_build", "trivy_json_to_scan", "trivy_ecosystem", "_eco_from_purl"]
