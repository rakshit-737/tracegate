"""Commit-stage collector for real git repositories.

Walks the first-parent history of a pinned dependency manifest
(requirements.txt / pip-compile output) and emits one `commit` stage event
per commit that changed a pin: which dependency versions it introduced and
which it removed. This is the "commit -> dependency" half of the lineage,
derived from the repository itself rather than from CI metadata.

`blame_introducers` is an *independent* ground truth used by the benchmark:
`git blame --first-parent` on the manifest line of each pinned package.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .ids import normalize_name
from .models import StageEvent

_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\,]+)")
_NL, _TAB = chr(10), chr(9)
_PR = re.compile(r"(?:\(#(\d+)\)\s*$|Merge pull request #(\d+))")


def parse_requirements(text: str) -> dict[str, str]:
    """Pinned `name==version` lines -> {normalised name: version}. Ignores -r, -e, URLs, hashes."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        m = _PIN.match(line)
        if m:
            out[normalize_name(m.group(1))] = m.group(2)
    return out


def direct_deps_from_pip_compile(text: str) -> set[str] | None:
    """pip-compile `# via -r requirements.in` annotations -> direct deps (None if not pip-compile)."""
    if "# via" not in text:
        return None
    direct: set[str] = set()
    cur = None
    for raw in text.splitlines():
        m = _PIN.match(raw)
        if m:
            cur = normalize_name(m.group(1))
            continue
        s = raw.strip()
        if cur and s.startswith("#") and "-r " in s and ".in" in s:
            direct.add(cur)
    return direct


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, encoding="utf-8", errors="replace").stdout


@dataclass
class ManifestCommit:
    sha: str
    author: str
    timestamp: int
    subject: str
    pins: dict[str, str]
    added: dict[str, str] = field(default_factory=dict)    # name -> new version
    removed: dict[str, str] = field(default_factory=dict)  # name -> old version
    path: str = ""  # manifest path at this commit (differs from the current one before a rename)

    @property
    def pr(self) -> int | None:
        m = _PR.search(self.subject)
        return int(m.group(1) or m.group(2)) if m else None


def follow_log(repo: str | Path, manifest: str, rev: str = "HEAD") -> list[tuple[str, str, int, str, str]]:
    """Oldest-first (sha, author, ts, subject, path-at-that-commit) for first-parent commits
    touching `manifest`, following renames (a manifest moved from requirements.txt to
    requirements/main.txt keeps its history, like `git blame` does)."""
    out = _git(Path(repo), "log", "--first-parent", "--follow", "--name-only",
               "--format=%x1e%H%x1f%ae%x1f%at%x1f%s", rev, "--", manifest)
    rows = []
    for block in out.split("\x1e")[1:]:
        head, _, rest = block.partition("\n")
        sha, author, ts, subject = head.split("\x1f", 3)
        paths = [ln.strip() for ln in rest.splitlines() if ln.strip()]
        rows.append((sha, author, int(ts), subject, paths[0] if paths else manifest))
    return rows[::-1]


def manifest_history(repo: str | Path, manifest: str, rev: str = "HEAD",
                     limit: int | None = None) -> list[ManifestCommit]:
    """Oldest-first list of first-parent commits that changed a pin in `manifest` (renames followed)."""
    repo = Path(repo)
    rows = follow_log(repo, manifest, rev)
    if limit:
        rows = rows[-limit:]
    out: list[ManifestCommit] = []
    prev: dict[str, str] = {}
    if limit and rows:  # seed the state from the parent of the first kept commit
        try:
            prev = parse_requirements(_git(repo, "show", f"{rows[0][0]}^:{rows[0][4]}"))
        except subprocess.CalledProcessError:
            prev = {}
    for sha, author, ts, subject, path in rows:
        try:
            text = _git(repo, "show", f"{sha}:{path}")
        except subprocess.CalledProcessError:
            text = ""  # file deleted in this commit
        pins = parse_requirements(text)
        mc = ManifestCommit(sha, author, ts, subject, pins, path=path)
        mc.added = {n: v for n, v in pins.items() if prev.get(n) != v}
        mc.removed = {n: v for n, v in prev.items() if pins.get(n) != v}
        if mc.added or mc.removed:
            out.append(mc)
        prev = pins
    return out


def commit_events(history: list[ManifestCommit], manifest: str, run_prefix: str = "git") -> list[StageEvent]:
    evs = []
    for i, mc in enumerate(history):
        evs.append(StageEvent("commit", f"{run_prefix}-{mc.sha[:8]}", {
            "sha": mc.sha, "author": mc.author, "pr": mc.pr, "message": mc.subject,
            "seq": i, "timestamp": mc.timestamp, "files": [manifest],
            "deps_added": [{"name": n, "version": v, "ecosystem": "pypi"} for n, v in sorted(mc.added.items())],
            "deps_removed": [{"name": n, "version": v} for n, v in sorted(mc.removed.items())],
        }))
    return evs


def blame_introducers(repo: str | Path, manifest: str, rev: str = "HEAD") -> dict[str, str]:
    """{normalised package: sha of the first-parent commit that last wrote its pin line}."""
    out: dict[str, str] = {}
    cur_sha = None
    for ln in _git(Path(repo), "blame", "--first-parent", "--line-porcelain", rev, "--", manifest).splitlines():
        if re.match(r"^[0-9a-f]{40} ", ln):
            cur_sha = ln.split()[0]
        elif ln.startswith("\t"):
            m = _PIN.match(ln[1:].split(" #", 1)[0])
            if m and cur_sha:
                out.setdefault(normalize_name(m.group(1)), cur_sha)
    return out


def pickaxe_first_mention(repo: str | Path, manifest: str, name: str, rev: str = "HEAD") -> str | None:
    """Naive baseline: oldest first-parent commit whose manifest diff mentions the package name."""
    out = _git(Path(repo), "log", "--first-parent", "--reverse", "--format=%H", "-i",
               f"-G^{re.escape(name)}[=<> \\[]", rev, "--", manifest).split()
    return out[0] if out else None


def materialize(repo: str | Path, sha: str, prefixes: list[str], dest: str | Path,
                suffixes: tuple[str, ...] = (".py",),
                names: tuple[str, ...] = ("Dockerfile", "Procfile")) -> int:
    """Write the files under `prefixes` (plus top-level `names`) as of `sha` into `dest`.

    Works on blobless clones: missing blobs are fetched in batches first. Used to run static
    reachability against the sources that actually shipped with a historical snapshot.
    """
    repo, dest = Path(repo), Path(dest)
    listing = _git(repo, "ls-tree", "-r", sha).splitlines()
    want: list[tuple[str, str]] = []
    for ln in listing:
        meta, _, path = ln.partition(_TAB)
        parts = meta.split()
        if len(parts) < 3 or parts[1] != "blob":
            continue
        under = any(path.startswith(p.rstrip("/") + "/") for p in prefixes)
        if (under and path.endswith(suffixes)) or path in names:
            want.append((parts[2], path))
    env_nolazy = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}
    chk = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch-check"],
                         input=_NL.join(o for o, _ in want), capture_output=True, text=True,
                         env=env_nolazy).stdout
    missing = [ln.split()[0] for ln in chk.splitlines() if ln.endswith("missing")]
    for i in range(0, len(missing), 200):
        subprocess.run(["git", "-C", str(repo), "-c", "fetch.negotiationAlgorithm=noop", "fetch", "--quiet",
                        "--no-tags", "--no-write-fetch-head", "--filter=blob:none", "origin", *missing[i:i + 200]],
                       check=False)
    n = 0
    for oid, path in want:
        out = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", oid], capture_output=True)
        if out.returncode != 0:
            continue
        target = dest / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(out.stdout)
        n += 1
    return n
