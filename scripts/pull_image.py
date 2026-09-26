#!/usr/bin/env python3
"""Minimal, dependency-free registry puller -> OCI image-layout tarball.

Why: Syft's registry source fails on Windows (layer cache paths contain ':'),
and pulling each image twice (Syft + Trivy) wastes bandwidth. This fetches the
linux/amd64 manifest, config and layer blobs from Docker Hub (anonymous token),
verifies every blob's sha256 against its digest, and writes an OCI archive that
both `syft oci-archive:<tar>` and `trivy image --input <tar>` read.

Images are only downloaded as data (tar layers), never executed.

  python scripts/pull_image.py alpine:3.14.2 out.tar
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def _parse(ref: str) -> tuple[str, str]:
    name, _, tag = ref.partition(":")
    if "/" not in name:
        name = f"library/{name}"
    return name, tag or "latest"


def _token(repo: str) -> str:
    url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)["token"]


def _get(url: str, token: str, accept: str | None = None, rng: int = 0) -> tuple[bytes, str]:
    h = {"Authorization": f"Bearer {token}"}
    if accept:
        h["Accept"] = accept
    if rng:
        h["Range"] = f"bytes={rng}-"
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=120) as r:
        return r.read(), r.headers.get("Content-Type", "")


def _blob(repo: str, digest: str, token: str, cache: Path) -> bytes:
    p = cache / digest.replace(":", "_")
    if p.exists() and "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest() == digest:
        return p.read_bytes()
    part = p.with_suffix(".part")
    for attempt in range(1, 40):
        have = part.stat().st_size if part.exists() else 0
        try:
            data, _ = _get(f"https://registry-1.docker.io/v2/{repo}/blobs/{digest}", token, rng=have)
            with part.open("ab" if have else "wb") as f:
                f.write(data)
            break
        except urllib.error.HTTPError as e:
            if e.code == 401:
                token = _token(repo)
            elif e.code == 416:
                break
            time.sleep(min(30, 2 * attempt))
        except OSError:
            time.sleep(min(30, 2 * attempt))
    data = part.read_bytes()
    got = "sha256:" + hashlib.sha256(data).hexdigest()
    if got != digest:
        part.unlink()
        raise SystemExit(f"digest mismatch for {digest}: got {got}")
    part.replace(p)
    return data


def pull(ref: str, out: Path, platform: str = "linux/amd64") -> None:
    repo, tag = _parse(ref)
    cache = out.parent / ".blobs"
    cache.mkdir(parents=True, exist_ok=True)
    token = _token(repo)
    body, ctype = _get(f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}", token, ACCEPT)
    doc = json.loads(body)
    if "manifests" in doc:  # index / manifest list
        os_, arch = platform.split("/")
        m = next(x for x in doc["manifests"]
                 if x.get("platform", {}).get("os") == os_ and x.get("platform", {}).get("architecture") == arch)
        body, ctype = _get(f"https://registry-1.docker.io/v2/{repo}/manifests/{m['digest']}", token, ACCEPT)
        doc = json.loads(body)
    mdigest = "sha256:" + hashlib.sha256(body).hexdigest()
    blobs = {doc["config"]["digest"]: _blob(repo, doc["config"]["digest"], token, cache)}
    for layer in doc["layers"]:
        blobs[layer["digest"]] = _blob(repo, layer["digest"], token, cache)
        print(f"  layer {layer['digest'][:19]} {layer['size'] / 1e6:.1f} MB")
    blobs[mdigest] = body
    mtype = doc.get("mediaType") or ctype.split(";")[0]
    index = {"schemaVersion": 2, "manifests": [{
        "mediaType": mtype, "digest": mdigest, "size": len(body),
        "annotations": {"org.opencontainers.image.ref.name": tag,
                        "io.containerd.image.name": f"docker.io/{repo}:{tag}"}}]}
    tmp = out.with_suffix(".tmp")
    with tarfile.open(tmp, "w") as t:
        def add(name: str, data: bytes) -> None:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        add("oci-layout", json.dumps({"imageLayoutVersion": "1.0.0"}).encode())
        add("index.json", json.dumps(index).encode())
        for d, data in blobs.items():
            add(f"blobs/sha256/{d.split(':', 1)[1]}", data)
    tmp.replace(out)
    print(f"wrote {out} ({out.stat().st_size / 1e6:.1f} MB, manifest {mdigest[:19]})")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    pull(sys.argv[1], Path(sys.argv[2]))
