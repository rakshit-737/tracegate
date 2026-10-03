"""Pinned-version parsers for lock files, dispatched on the manifest file name.

Supported:
  PyPI  : requirements*.txt (pip / pip-compile), poetry.lock, uv.lock
  npm   : package-lock.json (v1-v3), yarn.lock (classic v1 and Berry v2+), pnpm-lock.yaml (v5-v9)
  Go    : go.mod (require directives), go.sum (highest listed module version)
  Cargo : Cargo.lock

`pin_entries(manifest, text)` returns every pinned (name, version) with the 0-based line that
carries the version and the line that names the package. Lock files that hold several versions
of one name (yarn, pnpm, package-lock, Cargo/poetry/uv) yield one entry per version, so a
package that ships as both debug 2.6.9 and debug 4.3.4 is two pins. `parse_manifest_entries`
is derived from it, and `gitlineage.blame_entry_introducers` uses the same line map on
`git blame` output, so the benchmark's ground truth and the collector always agree on *which*
line represents a pin.

`pin_lines` / `parse_manifest` are the older one-version-per-name views ({name: (version,
line)}; the first entry in file order wins for lock files). They are kept for callers that
only need names (reachability) and to reproduce the pre-fix benchmark figures.

Readers are small line scanners: no YAML/TOML dependency, works on Python 3.10.
"""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import NamedTuple

from .ids import normalize_name

_KV = re.compile(r'^\s*(name|version)\s*=\s*"([^"]*)"\s*$')
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\,]+)")
Pins = dict[str, tuple[str, int]]


class Entry(NamedTuple):
    """One pinned (name, version) of a manifest.

    Attributes:
        name: Normalised package name.
        version: Pinned version.
        line: 0-based line that carries the version (what `git blame` is run on).
        key_line: 0-based line that names the package (equal to ``line`` for one-line pins).
    """
    name: str
    version: str
    line: int
    key_line: int


def _dedupe(entries: list[Entry]) -> list[Entry]:
    """Drop repeated (name, version) pairs, keeping the first occurrence in file order."""
    seen: set[tuple[str, str]] = set()
    out = []
    for e in entries:
        if (e.name, e.version) not in seen:
            seen.add((e.name, e.version))
            out.append(e)
    return out


def _first_per_name(entries: list[Entry]) -> Pins:
    out: Pins = {}
    for e in entries:
        out.setdefault(e.name, (e.version, e.line))
    return out

ECOSYSTEM = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "go.mod": "golang", "go.sum": "golang", "Cargo.lock": "cargo",
}


def _base(manifest: str) -> str:
    return PurePosixPath(manifest.replace("\\", "/")).name


def ecosystem_for(manifest: str) -> str:
    """Ecosystem of a manifest from its file name (``pypi`` when unknown)."""
    return ECOSYSTEM.get(_base(manifest), "pypi")


# ---- PyPI ---------------------------------------------------------------------
def requirements_lines(text: str) -> Pins:
    """Exact ``name==version`` pins of a requirements file with their line numbers."""
    out: Pins = {}
    for i, raw in enumerate(text.splitlines()):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        m = _PIN.match(line) if len(line) < 4096 else None
        if m:
            out[normalize_name(m.group(1))] = (m.group(2), i)
    return out


def toml_package_entries(text: str, eco: str = "pypi") -> list[Entry]:
    """poetry.lock / uv.lock / Cargo.lock: name+version of every top-level `[[package]]` table."""
    out: list[Entry] = []
    cur: dict[str, tuple[str, int]] | None = None

    def flush() -> None:
        if cur and "name" in cur and "version" in cur:
            out.append(Entry(normalize_name(cur["name"][0], eco), cur["version"][0], cur["version"][1],
                             cur["name"][1]))

    for i, line in enumerate(text.splitlines()):
        s = line.strip()
        if s.startswith("["):
            flush()
            cur = {} if s == "[[package]]" else None
            continue
        if cur is not None:
            m = _KV.match(line)
            if m and m.group(1) not in cur:
                cur[m.group(1)] = (m.group(2), i)
    flush()
    return _dedupe(out)


def toml_package_lines(text: str, eco: str = "pypi") -> Pins:
    """One version per name of a TOML lock file (first `[[package]]` table wins)."""
    return _first_per_name(toml_package_entries(text, eco))


# ---- npm ----------------------------------------------------------------------
_PL_KEY = re.compile(r'^ {4}"([^"]*)": \{\s*$')
_PL_VER = re.compile(r'^ {6}"version": "([^"]+)"')


def package_lock_entries(text: str) -> list[Entry] | None:
    """lockfileVersion 2/3 pretty-printed `packages` map; None if the layout is not recognised."""
    out: list[Entry] = []
    in_pkgs, key, key_i = False, None, -1
    for i, line in enumerate(text.splitlines()):
        if line.startswith('  "packages": {'):
            in_pkgs = True
            continue
        if in_pkgs and line.startswith("  }"):
            break
        if not in_pkgs:
            continue
        m = _PL_KEY.match(line)
        if m:
            key, key_i = m.group(1), i
            continue
        m = _PL_VER.match(line)
        if m and key and "node_modules/" in key:
            out.append(Entry(key.rsplit("node_modules/", 1)[-1].lower(), m.group(1), i, key_i))
            key = None
    return _dedupe(out) if in_pkgs else None


def package_lock_lines(text: str) -> Pins | None:
    """One version per name of a pretty-printed package-lock (first path wins)."""
    ents = package_lock_entries(text)
    return None if ents is None else _first_per_name(ents)


def package_lock_pairs(text: str) -> list[tuple[str, str]]:
    """Every (name, version) of an npm ``package-lock.json`` (lockfile v1, v2 or v3), any layout."""
    if not text.strip():
        return []
    doc = json.loads(text)
    out: list[tuple[str, str]] = []
    pkgs = doc.get("packages")
    if pkgs:
        for path, meta in pkgs.items():
            if not path or meta.get("link") or "version" not in meta:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            out.append((name.lower(), meta["version"]))
    else:
        def walk(deps: dict) -> None:
            for name, meta in (deps or {}).items():
                if "version" in meta:
                    out.append((name.lower(), meta["version"]))
                walk(meta.get("dependencies"))
        walk(doc.get("dependencies"))
    return list(dict.fromkeys(out))


def parse_package_lock(text: str) -> dict[str, str]:
    """Pins of an npm ``package-lock.json`` (lockfile v1, v2 or v3).

    Returns:
        Package name to version; one version per name.
    """
    if not text.strip():
        return {}
    doc = json.loads(text)
    out: dict[str, str] = {}
    pkgs = doc.get("packages")
    if pkgs:  # lockfileVersion 2/3: keys are node_modules paths
        for path, meta in pkgs.items():
            if not path or meta.get("link") or "version" not in meta:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            out.setdefault(name.lower(), meta["version"])
        return out

    def walk(deps: dict) -> None:  # lockfileVersion 1: nested "dependencies"
        for name, meta in (deps or {}).items():
            if "version" in meta:
                out.setdefault(name.lower(), meta["version"])
            walk(meta.get("dependencies"))
    walk(doc.get("dependencies"))
    return out


def _npm_spec_name(spec: str) -> str:
    spec = spec.strip().strip('"').strip("'")
    at = spec.find("@", 1)
    return (spec[:at] if at > 0 else spec).lower()


_YARN_VER = re.compile(r'^\s{2}version:?\s+"?([^"\s]+)"?\s*$')


def yarn_lock_entries(text: str) -> list[Entry]:
    """yarn.lock v1 (`version "1.2.3"`) and Berry (`version: 1.2.3`): one entry per block."""
    out: list[Entry] = []
    name, head_i = None, -1
    for i, line in enumerate(text.splitlines()):
        if not line or line.startswith("#"):
            continue
        if not line[0].isspace():
            head = line.rstrip().rstrip(":")
            head_i = i
            name = None if head == "__metadata" else _npm_spec_name(head.split(",")[0])
            if name and ("@workspace:" in head or "@link:" in head or "@portal:" in head
                         or "@patch:" in head and "@npm" not in head):
                name = None
            continue
        if name:
            m = _YARN_VER.match(line)
            if m:
                if m.group(1) != "0.0.0-use.local":
                    out.append(Entry(name, m.group(1), i, head_i))
                name = None
    return _dedupe(out)


def yarn_lock_lines(text: str) -> Pins:
    """One version per name of a yarn.lock (first block wins)."""
    return _first_per_name(yarn_lock_entries(text))


_PNPM_KEY = re.compile(r"^  ['\"]?(/?[^'\":\s][^'\":]*?)['\"]?:\s*$")


def _pnpm_key(key: str) -> tuple[str, str] | None:
    k = key.lstrip("/")
    if k.startswith(("file:", "link:", "http")) or "registry." in k.split("/")[0]:
        return None
    k = k.split("(", 1)[0]
    parts = k.split("/")
    if len(parts) >= 2 and parts[-1][:1].isdigit():  # v5: /name/version_peers
        name, _, ver = k.rpartition("/")
        ver = ver.split("_", 1)[0]
    else:  # v6+: name@version
        at = k.find("@", 1)
        if at < 0:
            return None
        name, ver = k[:at], k[at + 1:]
    if not name or not ver or not ver[0].isdigit():
        return None
    return name.lower(), ver


def pnpm_lock_entries(text: str) -> list[Entry]:
    """Every ``packages:`` key of a ``pnpm-lock.yaml`` (peer-suffixed copies collapse to one)."""
    out: list[Entry] = []
    in_pkgs = False
    for i, line in enumerate(text.splitlines()):
        if line and not line[0].isspace():
            in_pkgs = line.rstrip() == "packages:"
            continue
        if not in_pkgs:
            continue
        m = _PNPM_KEY.match(line)
        if m:
            nv = _pnpm_key(m.group(1))
            if nv:
                out.append(Entry(nv[0], nv[1], i, i))
    return _dedupe(out)


def pnpm_lock_lines(text: str) -> Pins:
    """One version per name of a ``pnpm-lock.yaml`` (first key wins)."""
    return _first_per_name(pnpm_lock_entries(text))


# ---- Go -----------------------------------------------------------------------
_GOREQ = re.compile(r"^\s*(?:require\s+)?([^\s()]+)\s+(v[0-9]\S*)")


def go_mod_lines(text: str) -> Pins:
    """``require`` entries of a ``go.mod`` with their line numbers."""
    out: Pins = {}
    block = None
    for i, raw in enumerate(text.splitlines()):
        line = raw.split("//", 1)[0].rstrip()
        s = line.strip()
        if s.endswith("(") and s.split()[0] in ("require", "replace", "exclude", "retract", "tool", "godebug"):
            block = s.split()[0]
            continue
        if s == ")":
            block = None
            continue
        if block == "require" or (block is None and s.startswith("require ")):
            m = _GOREQ.match(s) if len(s) < 4096 else None
            if m and "." in m.group(1):
                out[m.group(1)] = (m.group(2), i)
    return out


def semver_key(v: str) -> tuple:
    """Order Go/npm/Cargo semver strings (leading 'v' ignored, build metadata dropped,
    pre-releases before the release, Go pseudo-versions compare by timestamp)."""
    v = v.lstrip("v").split("+", 1)[0]
    core, _, pre = v.partition("-")
    nums = []
    for p in core.split("."):
        nums.append(int(p) if p.isdigit() else 0)
    nums += [0] * (3 - len(nums))
    pre_key: tuple = (1,) if not pre else (0, *[(0, int(x), "") if x.isdigit() else (1, 0, x)
                                                for x in re.split(r"[.-]", pre)])
    return (*nums[:3], pre_key)


def go_sum_lines(text: str) -> Pins:
    """Module versions of a ``go.sum`` (one per module) with their line numbers."""
    best: dict[str, tuple[str, int]] = {}
    for i, raw in enumerate(text.splitlines()):
        parts = raw.split()
        if len(parts) != 3 or parts[1].endswith("/go.mod"):
            continue
        mod, ver = parts[0], parts[1]
        if mod not in best or semver_key(ver) > semver_key(best[mod][0]):
            best[mod] = (ver, i)
    return best


# ---- dispatch -----------------------------------------------------------------
def pin_lines(manifest: str, text: str) -> Pins | None:
    """{name: (version, line)}; None when the format has no line-level mapping (npm v1 JSON)."""
    name = _base(manifest)
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return package_lock_lines(text) if text.strip() else {}
    if name == "yarn.lock":
        return yarn_lock_lines(text)
    if name == "pnpm-lock.yaml":
        return pnpm_lock_lines(text)
    if name == "go.mod":
        return go_mod_lines(text)
    if name == "go.sum":
        return go_sum_lines(text)
    if name == "Cargo.lock":
        return toml_package_lines(text, "cargo")
    if name in ("poetry.lock", "uv.lock"):
        return toml_package_lines(text)
    return requirements_lines(text)


def pin_entries(manifest: str, text: str) -> list[Entry] | None:
    """Every pinned (name, version) with its lines; None when the format has no line map (npm v1 JSON).

    Lock files keep every version of a name. requirements files and go.mod keep one pin per
    name (the last line wins, as pip and Go do); go.sum keeps the highest version per module
    (go.mod is authoritative for Go).
    """
    name = _base(manifest)
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return package_lock_entries(text) if text.strip() else []
    if name == "yarn.lock":
        return yarn_lock_entries(text)
    if name == "pnpm-lock.yaml":
        return pnpm_lock_entries(text)
    if name == "Cargo.lock":
        return toml_package_entries(text, "cargo")
    if name in ("poetry.lock", "uv.lock"):
        return toml_package_entries(text)
    single = pin_lines(manifest, text) or {}
    return sorted((Entry(n, v, i, i) for n, (v, i) in single.items()), key=lambda e: e.line)


def parse_manifest_entries(manifest: str, text: str) -> list[tuple[str, str]]:
    """Every pinned (name, version) of any supported manifest or lock file, in file order."""
    ents = pin_entries(manifest, text)
    if ents is None:
        return package_lock_pairs(text)
    return [(e.name, e.version) for e in ents]


def parse_toml_packages(text: str) -> dict[str, str]:
    """Pins of a TOML lock file with ``[[package]]`` tables (such as Cargo.lock)."""
    return {n: v for n, (v, _) in toml_package_lines(text).items()}


def parse_manifest(manifest: str, text: str) -> dict[str, str]:
    """Pins of any supported manifest or lock file.

    Args:
        manifest: File path; its name selects the parser.
        text: File contents.

    Returns:
        Package name to pinned version.
    """
    lines = pin_lines(manifest, text)
    if lines is None:  # package-lock without the standard pretty-printed v2/v3 layout
        return parse_package_lock(text)
    return {n: v for n, (v, _) in lines.items()}


__all__ = ["Entry", "parse_manifest", "parse_manifest_entries", "parse_package_lock", "parse_toml_packages",
           "ecosystem_for", "pin_entries", "pin_lines", "semver_key", "yarn_lock_lines", "yarn_lock_entries",
           "pnpm_lock_lines", "pnpm_lock_entries", "package_lock_entries", "package_lock_pairs",
           "toml_package_entries", "go_mod_lines", "go_sum_lines"]
