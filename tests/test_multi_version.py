"""Lock files that hold several versions of one package name (multi-version pins)."""
import json
import shutil
import subprocess

import pytest

from tracegate.collector import Collector
from tracegate.gitlineage import (
    blame_entry_introducers,
    commit_events,
    manifest_history,
    pickaxe_exact,
)
from tracegate.ids import dep_id
from tracegate.lockfiles import parse_manifest, parse_manifest_entries, pin_entries
from tracegate.models import NodeKind, StageEvent
from tracegate.signing import HmacSigner, Verifier

YARN_V1 = '''# yarn lockfile v1


debug@2.6.9, debug@^2.2.0:
  version "2.6.9"
  resolved "https://registry.yarnpkg.com/debug/-/debug-2.6.9.tgz"

debug@^4.1.0, debug@^4.3.1:
  version "4.3.4"
  resolved "https://registry.yarnpkg.com/debug/-/debug-4.3.4.tgz"
'''

YARN_BERRY = '''__metadata:
  version: 6

"debug@npm:2.6.9":
  version: 2.6.9

"debug@npm:^4.1.0":
  version: 4.3.4
'''

PNPM_V9 = '''lockfileVersion: '9.0'
packages:
  debug@2.6.9:
    resolution: {integrity: sha512-a}
  debug@4.3.4:
    resolution: {integrity: sha512-b}
snapshots:
  debug@2.6.9: {}
'''

PNPM_V5 = '''lockfileVersion: 5.4
packages:
  /debug/2.6.9:
    resolution: {integrity: sha512-a}
  /debug/4.3.4_supports-color@8.0.0:
    resolution: {integrity: sha512-b}
  /debug/4.3.4_supports-color@9.0.0:
    resolution: {integrity: sha512-c}
'''

PACKAGE_LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/debug": {"version": "4.3.4"},
    "node_modules/send/node_modules/debug": {"version": "2.6.9"},
    "node_modules/other/node_modules/debug": {"version": "4.3.4"},
}}, indent=2)

CARGO = '''version = 3

[[package]]
name = "syn"
version = "1.0.109"

[[package]]
name = "syn"
version = "2.0.48"
'''

BOTH = [("debug", "2.6.9"), ("debug", "4.3.4")]


@pytest.mark.parametrize("manifest,text", [
    ("yarn.lock", YARN_V1), ("yarn.lock", YARN_BERRY), ("pnpm-lock.yaml", PNPM_V9),
    ("pnpm-lock.yaml", PNPM_V5), ("package-lock.json", PACKAGE_LOCK)])
def test_two_versions_of_one_npm_name(manifest, text):
    assert sorted(parse_manifest_entries(manifest, text)) == BOTH
    assert len(parse_manifest(manifest, text)) == 1  # the one-version-per-name view keeps one


def test_two_versions_of_one_cargo_crate():
    assert parse_manifest_entries("Cargo.lock", CARGO) == [("syn", "1.0.109"), ("syn", "2.0.48")]
    ents = pin_entries("Cargo.lock", CARGO)
    lines = CARGO.splitlines()
    assert [lines[e.key_line] for e in ents] == ['name = "syn"', 'name = "syn"']
    assert [lines[e.line] for e in ents] == ['version = "1.0.109"', 'version = "2.0.48"']


def test_package_lock_json_fallback_keeps_every_version():
    compact = json.dumps({"lockfileVersion": 1, "dependencies": {
        "debug": {"version": "4.3.4"}, "send": {"version": "0.18.0", "dependencies": {"debug": {"version": "2.6.9"}}}}})
    assert sorted(parse_manifest_entries("package-lock.json", compact)) == [*BOTH, ("send", "0.18.0")]


def test_key_lines_point_at_the_package():
    lines = YARN_V1.splitlines()
    ents = pin_entries("yarn.lock", YARN_V1)
    assert [lines[e.key_line] for e in ents] == ["debug@2.6.9, debug@^2.2.0:", "debug@^4.1.0, debug@^4.3.1:"]
    assert [lines[e.line] for e in ents] == ['  version "2.6.9"', '  version "4.3.4"']


def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_history_attributes_each_version(tmp_path):
    """A bump of the second copy of `debug` is attributed to its own commit (the old
    first-entry reader never saw that copy change)."""
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    steps = [YARN_V1, YARN_V1.replace("4.3.4", "4.3.5"), YARN_V1.replace("4.3.4", "4.3.5") + '''
ms@^2.1.1:
  version "2.1.3"
''']
    for i, text in enumerate(steps):
        (tmp_path / "yarn.lock").write_text(text)
        _git(tmp_path, "add", ".")
        _git(tmp_path, "commit", "-q", "-m", f"step {i} (#{i + 1})")
    shas = _git(tmp_path, "log", "--format=%H", "--reverse").split()
    hist = manifest_history(tmp_path, "yarn.lock")
    assert [h.pr for h in hist] == [1, 2, 3]
    assert hist[1].added == [("debug", "4.3.5")] and hist[1].removed == [("debug", "4.3.4")]
    assert manifest_history(tmp_path, "yarn.lock", multi_version=False)[1].pr == 3  # blind to the bump
    blame = blame_entry_introducers(tmp_path, "yarn.lock")
    assert blame[("debug", "4.3.5")] == shas[1] and blame[("debug", "2.6.9")] == shas[0]
    signer = HmacSigner("k", b"k")
    evs = commit_events(hist, "yarn.lock")
    evs.append(StageEvent("build", "ci", {"build_id": "b", "commit": shas[-1], "sbom": {"artifacts": []}}))
    g = Collector(Verifier({"k": b"k"})).collect([signer.sign(e) for e in evs]).graph
    for (n, v), want in blame.items():
        path = g.upstream_path(dep_id(n, v, "npm"), NodeKind.COMMIT)
        assert g.nodes[path[0]].attrs["sha"] == want
    # a package-specific pickaxe token (header + version line) finds the bump; the bare version
    # line does too here, but would also match any other package at 4.3.5
    ent = next(e for e in pin_entries("yarn.lock", steps[2]) if e.version == "4.3.5")
    tok = "\n".join(steps[2].splitlines()[ent.key_line:ent.line + 1])
    assert pickaxe_exact(tmp_path, "yarn.lock", tok) == shas[1]
