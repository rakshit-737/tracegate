#!/usr/bin/env python3
"""Run the real Syft + Trivy binaries over public images and the cloned repos.

Outputs (uncommitted) land in $TRACEGATE_DATA/scans/:
  <slug>.syft.json   syft -o syft-json            (SBOM with layer IDs / purls)
  <slug>.trivy.json  trivy --format json          (vulnerabilities with PURL + layer DiffID)

Images are pulled straight from the registry by scripts/pull_image.py (no
Docker daemon, sha256-verified blobs) for linux/amd64. They are pinned, *old*
official images chosen on purpose: they
share Alpine base layers (blast-radius demo) and carry many known CVEs. They
are only unpacked and catalogued, never run.

  python scripts/scan_real.py images
  python scripts/scan_real.py repos
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tracegate.data import data_root  # noqa: E402

IMAGES = [
    "alpine:3.14.2",
    "python:3.9.7-alpine3.14",
    "nginx:1.21.3-alpine",
    "redis:6.2.5-alpine3.14",
    "httpd:2.4.49-alpine3.14",
    "memcached:1.6.10-alpine3.14",
    "node:14.17.6-alpine3.14",
]
REPOS = {"healthchecks": "requirements.txt", "netbox": "requirements.txt",
         "warehouse": "requirements/main.txt",
         "securedrop": "securedrop/requirements/python3/requirements.txt"}

ROOT = data_root()
EXE = ".exe" if os.name == "nt" else ""
SYFT, TRIVY = ROOT / "bin" / f"syft{EXE}", ROOT / "bin" / f"trivy{EXE}"
OUT = ROOT / "scans"
CACHE = ROOT / "trivy-cache"


def slug(s: str) -> str:
    return s.replace("/", "_").replace(":", "_")


def _run(cmd: list[str], out: Path, tries: int = 4, cwd: Path | None = None) -> bool:
    if out.exists() and out.stat().st_size > 0:
        print(f"  cached  {out.name}")
        return True
    for attempt in range(1, tries + 1):
        t0 = time.time()
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        if r.returncode == 0 and out.exists():
            print(f"  ok      {out.name}  ({time.time() - t0:.0f}s)")
            return True
        print(f"  retry {attempt}: {r.stderr.strip().splitlines()[-1:] if r.stderr else r.returncode}")
        time.sleep(10 * attempt)
    return False


def _safe_extract(tar_gz: Path, dest: Path) -> None:
    """Extract regular files/dirs only (no links, devices, whiteouts, or names Windows rejects)."""
    import re
    import tarfile
    bad = re.compile(r'[<>:"|?*\x00-\x1f]')
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_gz, "r:*") as t:
        for m in t:
            name = m.name.lstrip("./")
            if not name or ".." in Path(name).parts or bad.search(name) or Path(name).name.startswith(".wh."):
                continue
            if not (m.isfile() or m.isdir()):
                continue
            m.name = name
            try:
                t.extract(m, dest, filter="data")
            except (OSError, tarfile.TarError):
                continue


def syft_per_layer(oci_dir: Path, ref: str, out: Path) -> None:
    """Syft's image source is broken on Windows (':' in layer cache paths), so run
    `syft dir:` on each extracted layer and attribute every package to the first
    layer it appears in (equivalent to syft's all-layers scope for append-only images).
    The result is written in syft-json shape so tracegate.ingest reads it unchanged."""
    import json
    import shutil
    index = json.loads((oci_dir / "index.json").read_text())
    mdig = index["manifests"][0]["digest"]
    manifest = json.loads((oci_dir / "blobs/sha256" / mdig.split(":")[1]).read_bytes())
    cfg_dig = manifest["config"]["digest"]
    config = json.loads((oci_dir / "blobs/sha256" / cfg_dig.split(":")[1]).read_bytes())
    diff_ids = config["rootfs"]["diff_ids"]
    history = [h for h in config.get("history", []) if not h.get("empty_layer")]
    arts, seen, version = [], set(), None
    work = out.parent / (out.stem + ".work")
    for i, (layer, diff_id) in enumerate(zip(manifest["layers"], diff_ids)):
        ldir = work / f"layer{i}"
        _safe_extract(oci_dir / "blobs/sha256" / layer["digest"].split(":")[1], ldir)
        lj = work / f"layer{i}.json"
        subprocess.run([str(SYFT), f"dir:{ldir}", "-q", "-o", f"syft-json={lj}"], check=True)
        doc = json.loads(lj.read_text(encoding="utf-8"))
        version = (doc.get("descriptor") or {}).get("version")
        for a in doc.get("artifacts", []):
            key = a.get("purl") or f"{a.get('name')}@{a.get('version')}"
            if key in seen:
                continue
            seen.add(key)
            a["locations"] = [{"path": loc.get("path"), "layerID": diff_id} for loc in a.get("locations", [])]
            arts.append(a)
    layers = [{"digest": d, "size": manifest["layers"][i].get("size"),
               "created_by": (history[i].get("created_by", "") if i < len(history) else "")}
              for i, d in enumerate(diff_ids)]
    merged = {"descriptor": {"name": "syft", "version": version, "mode": "per-layer dir scan"},
              "source": {"type": "image", "name": ref,
                         "metadata": {"userInput": ref, "imageID": cfg_dig, "manifestDigest": mdig,
                                      "layers": layers}},
              "artifacts": arts}
    out.write_text(json.dumps(merged), encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)


def scan_images() -> None:
    import tarfile

    from pull_image import pull
    idir = ROOT / "images"
    idir.mkdir(exist_ok=True)
    have_db = (CACHE / "db" / "trivy.db").exists()
    for img in IMAGES:
        s = slug(img)
        tar = idir / f"{s}.tar"
        if not tar.exists():
            pull(img, tar)
        oci = idir / s
        if not (oci / "index.json").exists():
            with tarfile.open(tar) as t:
                t.extractall(oci, filter="data")
        rel = os.path.relpath(oci, ROOT)  # trivy misparses 'C:' drive prefixes as image:tag
        if not (OUT / f"{s}.syft.json").exists():
            syft_per_layer(oci, img, OUT / f"{s}.syft.json")
            print(f"  ok      {s}.syft.json")
        _run([str(TRIVY), "image", "--input", rel, "--cache-dir", os.path.relpath(CACHE, ROOT),
              "--skip-db-update", "--format", "cyclonedx", "-q", "-o", f"scans/{s}.trivy.cdx.json"],
             OUT / f"{s}.trivy.cdx.json", cwd=ROOT)
        if have_db:
            _run([str(TRIVY), "image", "--input", rel, "--cache-dir", os.path.relpath(CACHE, ROOT),
                  "--skip-db-update", "--scanners", "vuln", "-q", "--format", "json",
                  "-o", f"scans/{s}.trivy.json"], OUT / f"{s}.trivy.json", cwd=ROOT)
        else:
            print("  (no trivy DB yet: vuln scan skipped; run `trivy image --download-db-only`)")


def scan_repos() -> None:
    for name, manifest in REPOS.items():
        repo = ROOT / "repos" / name
        if not repo.exists():
            print(f"  skip {name}: not cloned")
            continue
        target = repo / manifest
        _run([str(SYFT), f"file:{target}", "-q", "-o", f"syft-json={OUT / (name + '.syft.json')}"],
             OUT / f"{name}.syft.json")
        _run([str(TRIVY), "fs", "--cache-dir", str(CACHE), "--skip-db-update", "--scanners", "vuln",
              "--quiet", "--format", "json", "-o", str(OUT / f"{name}.trivy.json"), str(target)],
             OUT / f"{name}.trivy.json")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=["images", "repos", "all"])
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.what in ("images", "all"):
        scan_images()
    if a.what in ("repos", "all"):
        scan_repos()


if __name__ == "__main__":
    main()
