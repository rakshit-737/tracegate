"""Commit-stage collector for real git repositories.

Walks the first-parent history of a pinned dependency manifest
(requirements.txt / pip-compile output, package-lock.json, yarn.lock, pnpm-lock.yaml, go.mod,
go.sum, Cargo.lock, poetry.lock, uv.lock) and emits one `commit` stage event
per commit that changed a pin: which (package, version) pairs it introduced and
which it removed. This is the "commit -> dependency" half of the lineage,
derived from the repository itself rather than from CI metadata.

Pins are (name, version) pairs, so a lock file that ships two versions of one package
(debug 2.6.9 and debug 4.3.4) tracks both; `multi_version=False` reproduces the older
one-version-per-name behaviour (first entry wins) for before/after comparisons.

`blame_entry_introducers` is the line-based reference the benchmark compares against:
`git blame --first-parent` on the manifest line of each pinned (package, version).
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from .ids import normalize_name
from .lockfiles import ecosystem_for, parse_manifest, parse_manifest_entries, pin_entries, pin_lines
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
        m = _PIN.match(line) if len(line) < 4096 else None
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
        m = _PIN.match(raw) if len(raw) < 4096 else None
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


Pair = tuple[str, str]  # (normalised name, version)


@dataclass
class ManifestCommit:
    """One first-parent commit that changed a manifest, with the pins after it.

    Attributes:
        pins: One version per name (first entry in file order), for callers that need names only.
        entries: Every pinned (name, version) after this commit.
        added: Pairs present after this commit and not before it, sorted.
        removed: Pairs present before this commit and not after it, sorted.
    """
    sha: str
    author: str
    timestamp: int
    subject: str
    pins: dict[str, str]
    added: list[Pair] = field(default_factory=list)
    removed: list[Pair] = field(default_factory=list)
    path: str = ""  # manifest path at this commit (differs from the current one before a rename)
    entries: frozenset[Pair] = frozenset()

    @property
    def pr(self) -> int | None:
        """Pull-request number parsed from the commit subject, if any."""
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


def manifest_pairs(path: str, text: str, multi_version: bool = True) -> list[Pair]:
    """Pinned (name, version) pairs of a manifest; one per name when ``multi_version`` is False."""
    if multi_version:
        return parse_manifest_entries(path, text)
    return list(parse_manifest(path, text).items())


def manifest_history(repo: str | Path, manifest: str, rev: str = "HEAD",
                     limit: int | None = None, multi_version: bool = True) -> list[ManifestCommit]:
    """Oldest-first list of first-parent commits that changed a pin in `manifest` (renames followed).

    Args:
        repo: Repository path.
        manifest: Manifest path at ``rev``.
        rev: Revision to walk back from.
        limit: Keep only the newest ``limit`` manifest commits.
        multi_version: Track every version of a name (default). False keeps one version per
            name (the first entry), the behaviour before the multi-version fix.

    Returns:
        Commits that added or removed at least one (name, version) pin.
    """
    repo = Path(repo)
    rows = follow_log(repo, manifest, rev)
    if limit:
        rows = rows[-limit:]
    out: list[ManifestCommit] = []
    prev: set[Pair] = set()
    if limit and rows:  # seed the state from the parent of the first kept commit
        try:
            prev = set(manifest_pairs(rows[0][4], _git(repo, "show", f"{rows[0][0]}^:{rows[0][4]}"),
                                      multi_version))
        except (subprocess.CalledProcessError, ValueError):
            prev = set()
    for sha, author, ts, subject, path in rows:
        try:
            text = _git(repo, "show", f"{sha}:{path}")
        except subprocess.CalledProcessError:
            text = ""  # file deleted in this commit
        try:
            pairs = manifest_pairs(path, text, multi_version)
        except ValueError:  # malformed lock file at this commit
            pairs = []
        cur = set(pairs)
        pins: dict[str, str] = {}
        for n, v in pairs:
            pins.setdefault(n, v)
        mc = ManifestCommit(sha, author, ts, subject, pins, path=path, entries=frozenset(cur),
                            added=sorted(cur - prev), removed=sorted(prev - cur))
        if mc.added or mc.removed:
            out.append(mc)
        prev = cur
    return out


def commit_events(history: list[ManifestCommit], manifest: str, run_prefix: str = "git") -> list[StageEvent]:
    """Turn a manifest history into commit stage events.

    Args:
        history: Commits that changed the manifest, oldest first.
        manifest: Manifest path, used to pick the ecosystem.
        run_prefix: Prefix for the synthetic run ids.

    Returns:
        Unsigned stage events, one per commit.
    """
    eco = ecosystem_for(manifest)
    evs = []
    for i, mc in enumerate(history):
        evs.append(StageEvent("commit", f"{run_prefix}-{mc.sha[:8]}", {
            "sha": mc.sha, "author": mc.author, "pr": mc.pr, "message": mc.subject,
            "seq": i, "timestamp": mc.timestamp, "files": [manifest],
            "deps_added": [{"name": n, "version": v, "ecosystem": eco} for n, v in sorted(mc.added)],
            "deps_removed": [{"name": n, "version": v} for n, v in sorted(mc.removed)],
        }))
    return evs


def _blame(repo: str | Path, manifest: str, rev: str) -> tuple[list[str], list[str]]:
    shas: list[str] = []
    lines: list[str] = []
    cur_sha = None
    for ln in _git(Path(repo), "blame", "--first-parent", "--line-porcelain", rev, "--", manifest).splitlines():
        if re.match(r"^[0-9a-f]{40} ", ln):
            cur_sha = ln.split()[0]
        elif ln.startswith(_TAB) and cur_sha:
            shas.append(cur_sha)
            lines.append(ln[1:])
    return shas, lines


def blame_introducers(repo: str | Path, manifest: str, rev: str = "HEAD") -> dict[str, str]:
    """{normalised package: sha of the first-parent commit that last wrote its pin line}.

    One version per name (the first entry of a lock file); see `blame_entry_introducers` for
    every (name, version)."""
    shas, lines = _blame(repo, manifest, rev)
    pins = pin_lines(manifest, _NL.join(lines))
    if pins is None:
        return {}
    return {n: shas[i] for n, (_, i) in pins.items() if i < len(shas)}


def blame_entry_introducers(repo: str | Path, manifest: str, rev: str = "HEAD",
                            multi_version: bool = True) -> dict[Pair, str]:
    """{(normalised package, version): sha of the first-parent commit that last wrote its pin line}.

    The pin line comes from `lockfiles.pin_entries`, so every supported format (requirements,
    package-lock v2/v3, yarn, pnpm, go.mod, go.sum, Cargo/poetry/uv locks) gets the same
    reference: the commit that last wrote the line holding that version. With
    ``multi_version=False`` only the first entry per name is kept (the older behaviour)."""
    shas, lines = _blame(repo, manifest, rev)
    text = _NL.join(lines)
    if multi_version:
        ents = pin_entries(manifest, text)
        if ents is None:
            return {}
        return {(e.name, e.version): shas[e.line] for e in ents if e.line < len(shas)}
    pins = pin_lines(manifest, text)
    if pins is None:
        return {}
    return {(n, v): shas[i] for n, (v, i) in pins.items() if i < len(shas)}


def pickaxe_exact(repo: str | Path, manifest: str, token: str, rev: str = "HEAD") -> str | None:
    """Newest first-parent commit up to ``rev`` that changed how often ``token`` occurs in the manifest.

    ``git log --first-parent -1 -S<token>``; ``token`` may span several lines."""
    if not token:
        return None
    out = _git(Path(repo), "log", "--first-parent", "-1", "--format=%H", f"-S{token}", rev, "--", manifest).strip()
    return out or None


def pickaxe_first_mention(repo: str | Path, manifest: str, name: str, rev: str = "HEAD") -> str | None:
    """Naive baseline: oldest first-parent commit whose manifest diff mentions the package name."""
    if ecosystem_for(manifest) == "pypi" and not manifest.endswith(".lock"):
        pat = "^" + re.escape(name) + r"[=<> \[]"
    else:  # lock files: the name followed by a version/key delimiter
        pat = f"{re.escape(name)}[@\"/ :]"
    out = _git(Path(repo), "log", "--first-parent", "--reverse", "--format=%H", "-i",
               f"-G{pat}", rev, "--", manifest).split()
    return out[0] if out else None


def safe_relpath(path: str) -> bool:
    """True for a relative tree path with no '..', '.', '.git', backslash or drive component."""
    if not path or path.startswith("/") or "\\" in path or ":" in path:
        return False
    return all(p not in ("", ".", "..") and p.lower() != ".git" for p in path.split("/"))


def materialize(repo: str | Path, sha: str, prefixes: list[str], dest: str | Path,
                suffixes: tuple[str, ...] = (".py",),
                names: tuple[str, ...] = ("Dockerfile", "Procfile"),
                anywhere: tuple[str, ...] = ()) -> int:
    """Write the files under `prefixes` (plus top-level `names`) as of `sha` into `dest`.

    Works on blobless clones: missing blobs are fetched in batches first. Used to run static
    reachability against the sources that actually shipped with a historical snapshot.
    `anywhere` are basename globs (e.g. reach.ENTRYPOINT_FILES) matched across the whole tree.
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
        base = path.rsplit("/", 1)[-1]
        if not safe_relpath(path):
            continue
        if (under and path.endswith(suffixes)) or path in names or any(fnmatch(base, g) for g in anywhere):
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
    root = dest.resolve()
    for oid, path in want:
        out = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", oid], capture_output=True)
        if out.returncode != 0:
            continue
        target = (dest / path).resolve()
        if not target.is_relative_to(root):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(out.stdout)
        n += 1
    return n
