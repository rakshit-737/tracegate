"""Pinned-version parsers for lock files, dispatched on the manifest file name.

Supported:
  PyPI  : requirements*.txt (pip / pip-compile), poetry.lock, uv.lock
  npm   : package-lock.json (v1-v3), yarn.lock (classic v1 and Berry v2+), pnpm-lock.yaml (v5-v9)
  Go    : go.mod (require directives), go.sum (highest listed module version)
  Cargo : Cargo.lock

`pin_lines(manifest, text)` returns {name: (version, 0-based line)} - the line that carries
the chosen version. `parse_manifest` is derived from it, and `gitlineage.blame_introducers`
uses the same line map on `git blame` output, so the benchmark's ground truth and the
collector always agree on *which* line represents a pin. Readers are small line scanners:
no YAML/TOML dependency, works on Python 3.10.
"""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from .ids import normalize_name

_KV = re.compile(r'^\s*(name|version)\s*=\s*"([^"]*)"\s*$')
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\,]+)")
Pins = dict[str, tuple[str, int]]

ECOSYSTEM = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "go.mod": "golang", "go.sum": "golang", "Cargo.lock": "cargo",
}


def _base(manifest: str) -> str:
    return PurePosixPath(manifest.replace("\\", "/")).name


def ecosystem_for(manifest: str) -> str:
    return ECOSYSTEM.get(_base(manifest), "pypi")


# ---- PyPI ---------------------------------------------------------------------
def requirements_lines(text: str) -> Pins:
    out: Pins = {}
    for i, raw in enumerate(text.splitlines()):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        m = _PIN.match(line) if len(line) < 4096 else None
        if m:
            out[normalize_name(m.group(1))] = (m.group(2), i)
    return out


def toml_package_lines(text: str, eco: str = "pypi") -> Pins:
    """poetry.lock / uv.lock / Cargo.lock: name+version of each top-level `[[package]]` table."""
    out: Pins = {}
    cur: dict[str, tuple[str, int]] | None = None

    def flush() -> None:
        if cur and "name" in cur and "version" in cur:
            out.setdefault(normalize_name(cur["name"][0], eco), (cur["version"][0], cur["version"][1]))

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
    return out


# ---- npm ----------------------------------------------------------------------
_PL_KEY = re.compile(r'^ {4}"([^"]*)": \{\s*$')
_PL_VER = re.compile(r'^ {6}"version": "([^"]+)"')


def package_lock_lines(text: str) -> Pins | None:
    """lockfileVersion 2/3 pretty-printed `packages` map; None if the layout is not recognised."""
    out: Pins = {}
    in_pkgs, key = False, None
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
            key = m.group(1)
            continue
        m = _PL_VER.match(line)
        if m and key and "node_modules/" in key:
            out.setdefault(key.rsplit("node_modules/", 1)[-1].lower(), (m.group(1), i))
            key = None
    return out if in_pkgs else None


def parse_package_lock(text: str) -> dict[str, str]:
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


def yarn_lock_lines(text: str) -> Pins:
    """yarn.lock v1 (`version "1.2.3"`) and Berry (`version: 1.2.3`)."""
    out: Pins = {}
    name = None
    for i, line in enumerate(text.splitlines()):
        if not line or line.startswith("#"):
            continue
        if not line[0].isspace():
            head = line.rstrip().rstrip(":")
            name = None if head == "__metadata" else _npm_spec_name(head.split(",")[0])
            if name and ("@workspace:" in head or "@link:" in head or "@portal:" in head
                         or "@patch:" in head and "@npm" not in head):
                name = None
            continue
        if name:
            m = _YARN_VER.match(line)
            if m:
                if m.group(1) != "0.0.0-use.local":
                    out.setdefault(name, (m.group(1), i))
                name = None
    return out


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


def pnpm_lock_lines(text: str) -> Pins:
    out: Pins = {}
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
                out.setdefault(nv[0], (nv[1], i))
    return out


# ---- Go -----------------------------------------------------------------------
_GOREQ = re.compile(r"^\s*(?:require\s+)?([^\s()]+)\s+(v[0-9]\S*)")


def go_mod_lines(text: str) -> Pins:
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


def parse_toml_packages(text: str) -> dict[str, str]:
    return {n: v for n, (v, _) in toml_package_lines(text).items()}


def parse_manifest(manifest: str, text: str) -> dict[str, str]:
    lines = pin_lines(manifest, text)
    if lines is None:  # package-lock without the standard pretty-printed v2/v3 layout
        return parse_package_lock(text)
    return {n: v for n, (v, _) in lines.items()}


__all__ = ["parse_manifest", "parse_package_lock", "parse_toml_packages", "ecosystem_for", "pin_lines",
           "semver_key", "yarn_lock_lines", "pnpm_lock_lines", "go_mod_lines", "go_sum_lines"]
