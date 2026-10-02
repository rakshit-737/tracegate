"""Independent attribution oracle: single-package bot bumps, plus repo-clustered statistics.

A Dependabot / Renovate commit whose subject names exactly one package and its target version
("bump X from A to B", "update dependency X to vB") states which commit introduced X@B. The
label comes from the commit author and subject only, not from TRACEGATE's pin parser and not
from `git blame`. The parser is used solely to *select* cases (the snapshot must still pin B).

Methods scored against it (this is also the ablation the verifier asked for):
  tracegate (version diff)  : the verified provenance graph's commit -> dependency edge
  blame (line attribution)  : `git blame --first-parent` on the pin line
  pickaxe-exact-pin         : `git log --first-parent -1 -S'<pin line>'`
"""
from __future__ import annotations

import os
import random
import re
from pathlib import Path

from tracegate.collector import Collector
from tracegate.gitlineage import _git, blame_introducers, commit_events, manifest_history
from tracegate.ids import dep_id_from_purl, normalize_name, purl
from tracegate.lockfiles import ecosystem_for, pin_lines
from tracegate.models import NodeKind, StageEvent
from tracegate.signing import HmacSigner, Verifier

KEY = b"bench-key"
METHODS = ("tracegate (version diff)", "blame (line attribution)", "pickaxe-exact-pin")
_PFX = r"^(?:[\w-]+(?:\([\w-]+\))?!?: )?"
_BUMP = re.compile(_PFX + r"bump (\S+) from \S+ to v?([0-9][\w.+-]*?)(?:\s|$)", re.I)
_RENO = re.compile(_PFX + r"update (?:dependency |rust crate |module |npm package )?(\S+) to v?([0-9][\w.+-]*?)(?:\s|$)",
                   re.I)
_BOT = re.compile(r"dependabot|renovate|\[bot\]", re.I)


def bot_bump(author: str, subject: str) -> tuple[str, str] | None:
    """(package, target version) for a bot-authored single-package bump commit, else None."""
    if not _BOT.search(author) or re.search(r"\bgroup with\b|\bupdates\b|\band\b", subject, re.I):
        return None
    m = _BUMP.match(subject) or _RENO.match(subject)
    if not m or m.group(1).lower() == "the":
        return None
    return m.group(1), m.group(2).rstrip(".,)")


def _vnorm(v: str) -> str:
    return v.lstrip("vV").split("+")[0]


def tracegate_introducer(hist, upto: int, manifest: str, name: str, version: str) -> str | None:
    """Commit the signed, verified graph attributes `name==version` to at snapshot `upto`."""
    eco = ecosystem_for(manifest)
    sha = hist[upto].sha
    pu = purl(name, version, eco)
    evs = commit_events(hist[: upto + 1], manifest)
    evs.append(StageEvent("build", f"ci-{sha[:8]}", {"build_id": f"build-{sha[:8]}", "commit": sha, "tool": "manifest",
                                                     "sbom": {"artifacts": [{"name": name, "version": version,
                                                                             "purl": pu}]}}))
    signer = HmacSigner("bench", KEY)
    g = Collector(Verifier({"bench": KEY})).collect([signer.sign(e) for e in evs]).graph
    did = dep_id_from_purl(pu)
    path = g.upstream_path(did, NodeKind.COMMIT) if did in g.nodes else None
    return g.nodes[path[0]].attrs["sha"] if path else None


def oracle_repo(repo: Path, manifest: str, max_cases: int = 40, seed: int = 0) -> dict | None:
    """Score every method at the bump commit and at the last later snapshot still pinning B."""
    if not (repo / ".git").exists():
        return None
    eco = ecosystem_for(manifest)
    hist = manifest_history(repo, manifest)

    def key(n: str) -> str:
        return normalize_name(n, eco).lower()
    cands, skipped = [], {"package_not_in_pins": 0, "parser_version_mismatch": 0}
    for k, mc in enumerate(hist):
        bb = bot_bump(mc.author, mc.subject)
        if not bb:
            continue
        want = key(bb[0])
        match = [n for n in mc.pins if key(n) == want or key(n).endswith("/" + want)]
        if len(match) != 1:
            skipped["package_not_in_pins"] += 1
            continue
        pn = match[0]
        if _vnorm(mc.pins[pn]) != _vnorm(bb[1]):
            skipped["parser_version_mismatch"] += 1
            continue
        later = k
        while later + 1 < len(hist) and hist[later + 1].pins.get(pn) == mc.pins[pn]:
            later += 1
        cands.append((k, pn, later))
    usable = len(cands)
    random.Random(seed).shuffle(cands)
    cands = sorted(cands[:max_cases])
    rows = {m: {"at_bump": [0, 0], "later_snapshot": [0, 0]} for m in METHODS}
    misses = []
    for k, pn, later in cands:
        truth = hist[k].sha
        for label, j in (("at_bump", k), ("later_snapshot", later)):
            if label == "later_snapshot" and j == k:
                continue
            mc = hist[j]
            path = mc.path or manifest
            ver = mc.pins[pn]
            text = _git(repo, "show", f"{mc.sha}:{path}")
            li = {key(n): v[1] for n, v in pin_lines(path, text).items()}.get(key(pn))
            lines = text.splitlines()
            tok = lines[li].strip() if li is not None and li < len(lines) else ""
            got = {
                METHODS[0]: tracegate_introducer(hist, j, manifest, pn, ver),
                METHODS[1]: {key(n): s for n, s in blame_introducers(repo, path, mc.sha).items()}.get(key(pn)),
                METHODS[2]: (_git(repo, "log", "--first-parent", "-1", "--format=%H", f"-S{tok}", mc.sha,
                                  "--", path).strip() or None) if tok else None,
            }
            for m, sha in got.items():
                rows[m][label][0] += sha == truth
                rows[m][label][1] += 1
                if sha != truth and len(misses) < 12:
                    misses.append({"method": m, "case": label, "package": pn, "version": ver,
                                   "bump": truth[:10], "got": (sha or "")[:10]})
    print(f"[oracle {repo.name}] usable={usable} evaluated={len(cands)} " +
          " ".join(f"{m.split()[0]}={d['at_bump'][0]}/{d['at_bump'][1]};{d['later_snapshot'][0]}/{d['later_snapshot'][1]}"
                   for m, d in rows.items()), flush=True)
    return {"repo": repo.name, "ecosystem": eco, "bot_bumps_usable": usable, "evaluated": len(cands),
            "skipped": skipped, "misses": misses,
            "scores": {m: {lab: {"correct": c, "total": t} for lab, (c, t) in d.items()} for m, d in rows.items()}}


def cluster_bootstrap(per_repo: list[tuple[int, int]], n_boot: int = 2000, seed: int = 0) -> list[float] | None:
    """95% percentile CI of the pooled accuracy, resampling whole repositories (clusters)."""
    per_repo = [x for x in per_repo if x[1]]
    if not per_repo:
        return None
    rng = random.Random(seed)
    stats = []
    for _ in range(n_boot):
        smp = [per_repo[rng.randrange(len(per_repo))] for _ in per_repo]
        stats.append(sum(c for c, _ in smp) / sum(t for _, t in smp))
    stats.sort()
    return [round(stats[int(0.025 * n_boot)], 4), round(stats[int(0.975 * n_boot) - 1], 4)]


def run_meta() -> dict:
    """The GitHub Actions run that produced a results file (nulls when run locally)."""
    rid = os.environ.get("GITHUB_RUN_ID")
    srv = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    rep = os.environ.get("GITHUB_REPOSITORY", "")
    return {"run_id": int(rid) if rid else None,
            "run_url": f"{srv}/{rep}/actions/runs/{rid}" if rid else None,
            "commit": os.environ.get("GITHUB_SHA")}
