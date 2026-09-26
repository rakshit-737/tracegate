#!/usr/bin/env python3
"""Fetch every real public dataset TRACEGATE's benchmarks use.

Nothing here is committed to git. Everything lands in $TRACEGATE_DATA
(default: ../../datasets/tracegate relative to the repo, else ./data).

  python scripts/download_data.py all          # everything below
  python scripts/download_data.py osv          # OSV PyPI + npm dumps (vulns + MAL-* malicious pkgs)
  python scripts/download_data.py popular      # top-PyPI + npm-high-impact popularity lists
  python scripts/download_data.py tools        # Syft + Trivy release binaries (checksum-verified)
  python scripts/download_data.py repos        # git clones of real OSS repos with pinned manifests

Mutable feeds (OSV, popularity lists) cannot be pinned by hash in advance, so
their sha256 is recorded in MANIFEST.json at download time and re-verified by
`python scripts/download_data.py verify`. Tool binaries are verified against the
vendor's published checksums file.

Safety: OSV MAL-* records are *metadata* (package names/versions). No malicious
package artefact is ever downloaded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def data_root() -> Path:
    env = os.environ.get("TRACEGATE_DATA")
    if env:
        return Path(env)
    sibling = REPO.parents[1] / "datasets" / "tracegate"
    return sibling if sibling.parent.exists() else REPO / "data"


ROOT = data_root()
MANIFEST = ROOT / "MANIFEST.json"

OSV = {
    "osv/PyPI-all.zip": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    "osv/npm-all.zip": "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    "osv/Alpine-all.zip": "https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip",
}
POPULAR = {
    # Hugo van Kemenade, top-pypi-packages (CC0 / public domain data from BigQuery PyPI downloads)
    "popular/top-pypi-packages.min.json": "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json",
    # Titus Wormer, npm-high-impact (MIT): npm packages with most downloads/dependents
    "popular/npm-high-impact-top.js": "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js",
}
TOOLS = {
    "syft": ("anchore/syft", "1.52.0", "syft_{v}_{os}_{arch}.{ext}", "syft_{v}_checksums.txt"),
    "trivy": ("aquasecurity/trivy", "0.74.0", "trivy_{v}_{tos}-{tarch}.{ext}", "trivy_{v}_checksums.txt"),
}
# Real OSS projects whose production dependencies are pinned in a requirements file.
# (name, url, manifest path, source dirs for import analysis)
REPOS = [
    ("healthchecks", "https://github.com/healthchecks/healthchecks.git", "requirements.txt", ["hc"]),
    ("netbox", "https://github.com/netbox-community/netbox.git", "requirements.txt", ["netbox"]),
    ("warehouse", "https://github.com/pypi/warehouse.git", "requirements/main.txt", ["warehouse"]),
]


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_manifest() -> dict:
    return json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}


def _save_manifest(m: dict) -> None:
    MANIFEST.write_text(json.dumps(m, indent=2, sort_keys=True))


def fetch(url: str, rel: str, force: bool = False) -> Path:
    dst = ROOT / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and not force:
        print(f"  cached  {rel}")
        return dst
    print(f"  fetch   {url}")
    tmp = dst.with_suffix(dst.suffix + ".part")
    for attempt in range(1, 31):  # resumable: flaky links reset long transfers
        have = tmp.stat().st_size if tmp.exists() else 0
        headers = {"User-Agent": "tracegate-data/1.0"}
        if have:
            headers["Range"] = f"bytes={have}-"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:
                mode = "ab" if have and r.status == 206 else "wb"
                with tmp.open(mode) as f:
                    shutil.copyfileobj(r, f, 1 << 16)
            break
        except (OSError, urllib.error.URLError) as e:
            if getattr(e, "code", None) == 416:  # range not satisfiable: already complete
                break
            print(f"    retry {attempt} after {type(e).__name__} at {tmp.stat().st_size if tmp.exists() else 0} bytes")
            time.sleep(min(30, 2 * attempt))
    else:
        sys.exit(f"giving up on {url}")
    tmp.replace(dst)
    m = _load_manifest()
    m[rel] = {"url": url, "sha256": _sha256(dst), "bytes": dst.stat().st_size,
              "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _save_manifest(m)
    return dst


def cmd_osv(force: bool) -> None:
    for rel, url in OSV.items():
        fetch(url, rel, force)


def cmd_popular(force: bool) -> None:
    for rel, url in POPULAR.items():
        fetch(url, rel, force)


def _platform() -> tuple[str, str, str, str, str]:
    sysname = platform.system().lower()
    mach = platform.machine().lower()
    arch = "arm64" if mach in ("arm64", "aarch64") else "amd64"
    os_ = {"windows": "windows", "darwin": "darwin"}.get(sysname, "linux")
    tos = {"windows": "windows", "darwin": "macOS"}.get(sysname, "Linux")
    tarch = "ARM64" if arch == "arm64" else "64bit"
    ext = "zip" if os_ == "windows" else "tar.gz"
    return os_, arch, tos, tarch, ext


def cmd_tools(force: bool) -> None:
    os_, arch, tos, tarch, ext = _platform()
    bindir = ROOT / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    for tool, (gh, v, pattern, sums) in TOOLS.items():
        exe = bindir / (tool + (".exe" if os_ == "windows" else ""))
        if exe.exists() and not force:
            print(f"  cached  {exe}")
            continue
        asset = pattern.format(v=v, os=os_, arch=arch, tos=tos, tarch=tarch, ext=ext)
        base = f"https://github.com/{gh}/releases/download/v{v}/"
        sums_p = fetch(base + sums.format(v=v), f"bin/{sums.format(v=v)}", force)
        arc = fetch(base + asset, f"bin/{asset}", force)
        want = next((ln.split()[0] for ln in sums_p.read_text().splitlines()
                     if ln.strip().endswith(asset)), None)
        got = _sha256(arc)
        if want != got:
            arc.unlink()
            sys.exit(f"checksum mismatch for {asset}: want {want} got {got}")
        print(f"  verified {asset} sha256={got[:16]}...")
        if ext == "zip":
            with zipfile.ZipFile(arc) as z:
                z.extract(exe.name, bindir)
        else:
            import tarfile
            with tarfile.open(arc) as t:
                t.extract(tool, bindir, filter="data")
            exe.chmod(0o755)


def prefetch_manifest_blobs(repo: Path, manifest: str) -> None:
    """Fetch every historical version of the manifest in a few batched requests.

    A blobless clone would otherwise lazily fetch each blob in its own round trip.
    """
    g = ["git", "-C", str(repo)]
    shas = subprocess.run([*g, "log", "--first-parent", "--format=%H", "--", manifest],
                          capture_output=True, text=True, check=True).stdout.split()
    oids = set()
    for c in shas:
        out = subprocess.run([*g, "ls-tree", c, manifest], capture_output=True, text=True).stdout.split()
        if len(out) >= 3:
            oids.add(out[2])
    env = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}
    chk = subprocess.run([*g, "cat-file", "--batch-check"], input="\n".join(sorted(oids)),
                         capture_output=True, text=True, env=env).stdout
    missing = [ln.split()[0] for ln in chk.splitlines() if ln.endswith("missing")]
    print(f"    {manifest}: {len(shas)} commits, {len(oids)} blobs, {len(missing)} to fetch")
    for i in range(0, len(missing), 150):
        for attempt in range(1, 6):
            r = subprocess.run([*g, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "--quiet", "--no-tags",
                                "--no-write-fetch-head", "--filter=blob:none", "origin", *missing[i:i + 150]])
            if r.returncode == 0:
                break
            time.sleep(5 * attempt)


def cmd_repos(force: bool) -> None:
    rdir = ROOT / "repos"
    rdir.mkdir(parents=True, exist_ok=True)
    for name, url, manifest, srcs in REPOS:
        dst = rdir / name
        if dst.exists():
            print(f"  cached  repos/{name}")
            prefetch_manifest_blobs(dst, manifest)
            continue
        print(f"  clone   {url}")
        # Blobless partial clone + sparse checkout: full commit history, but only the
        # manifest and application sources are materialised (keeps the download small).
        for attempt in range(1, 6):
            if dst.exists():
                shutil.rmtree(dst, ignore_errors=True)
            r = subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
                                "--single-branch", url, str(dst)])
            if r.returncode == 0:
                break
            print(f"    clone retry {attempt}")
            time.sleep(5 * attempt)
        else:
            sys.exit(f"could not clone {url}")
        g = ["git", "-C", str(dst)]
        subprocess.run([*g, "sparse-checkout", "set", "--no-cone", f"/{manifest}",
                        *[f"/{d}/**/*.py" for d in srcs], "/Dockerfile*", "/Procfile",
                        "/docker/**", "/bin/**"], check=True)
        for attempt in range(1, 6):
            if subprocess.run([*g, "checkout", "--quiet"]).returncode == 0:
                break
            time.sleep(5 * attempt)
        head = subprocess.run(["git", "-C", str(dst), "rev-parse", "HEAD"], check=True,
                              capture_output=True, text=True).stdout.strip()
        prefetch_manifest_blobs(dst, manifest)
        m = _load_manifest()
        m[f"repos/{name}"] = {"url": url, "head": head,
                              "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        _save_manifest(m)


def cmd_verify(_: bool) -> None:
    bad = 0
    for rel, meta in _load_manifest().items():
        p = ROOT / rel
        if "sha256" not in meta:
            continue
        ok = p.exists() and _sha256(p) == meta["sha256"]
        bad += not ok
        print(f"  {'ok ' if ok else 'BAD'} {rel}")
    sys.exit(1 if bad else 0)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=["all", "osv", "popular", "tools", "repos", "verify"])
    ap.add_argument("--force", action="store_true", help="re-download even if cached")
    a = ap.parse_args()
    ROOT.mkdir(parents=True, exist_ok=True)
    print(f"data root: {ROOT}")
    steps = {"osv": cmd_osv, "popular": cmd_popular, "tools": cmd_tools, "repos": cmd_repos,
             "verify": cmd_verify}
    for name in (["popular", "osv", "tools", "repos"] if a.what == "all" else [a.what]):
        print(f"[{name}]")
        steps[name](a.force)


if __name__ == "__main__":
    main()
