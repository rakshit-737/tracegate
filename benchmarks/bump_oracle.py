"""Bot-bump attribution oracle with strata it can fail, plus exact and repo-clustered statistics.

A labelled case is (commit C, package X, version V): the commit message says C moved X to V.
Labels come from commit messages only (never from git blame):

  single_package  bot single-package bump ("bump X from A to B", "update dependency X to vB");
                  X has one version in the lock file after the bump
  multi_version   the same, but the lock file holds several versions of X after the bump
                  (the case the old one-version-per-name readers got wrong)
  grouped         per-package labels of grouped / multi-package bot bumps, read from the commit
                  body ("Updates `X` from A to B"; Renovate's package table)
  revert          `Revert "<bump of X from A to B>"`: the revert commit restores X@A
  re_bump         a labelled commit that re-introduces X@V after an earlier copy of X@V was
                  removed (A -> B -> C -> B); bot or human message

Merge commits of bot branches ("Merge pull request #N from <owner>/dependabot/...") are labelled
from the PR title in the merge body: on the first-parent history that merge is the introducer.

Label check (all strata): with a reader that sees every version of every package, X@V must be
absent from the lock file at C's first parent and present at C. Labels that fail are not scored;
their counts are reported per source (`excluded`): `already_present` (X@V existed before C, so C
is not the introducer), `not_in_lock` (the reader finds no X@V at C), `ambiguous_name`.

Scoring points: at C itself, and at the last later manifest commit that still pins X@V
continuously. Methods (the ablation):
  tracegate                 version-diff attribution in the signed, verified graph (every version)
  tracegate-single-version  the same with the old one-version-per-name readers
  blame                     `git blame --first-parent` on the X@V version line
  pickaxe-package-specific  `git log --first-parent -1 -S'<package line(s) .. version line>'`
  pickaxe-version-line      `git log --first-parent -1 -S'<version line>'` (not package-specific
                            in Cargo.lock / yarn.lock / package-lock.json)

What it tests: at C every verified label is right for `tracegate` by construction (the label
check is its own criterion), so the information is in (1) the later-snapshot point, where line
rewrites and reader glitches can move the answer, (2) the single-version ablation, which fails
on the multi_version stratum, and (3) the revert / re_bump strata, where the first introduction
of X@V is the wrong answer. It does not test attribution independently of the lock-file reader.

Sampling: per repository and stratum, a uniform random sample without replacement of at most
`MAX_CASES` usable cases (random.Random(SEED).shuffle, then chronological order).
"""
from __future__ import annotations

import bisect
import random
import re
from pathlib import Path

from stats import (  # noqa: F401  (cluster_bootstrap / run_meta re-exported for older callers)
    cluster_bootstrap,
    mcnemar_exact,
    paired_cluster_bootstrap,
    proportion,
    run_meta,
    table2x2,
)

from tracegate.collector import Collector
from tracegate.gitlineage import _git, commit_events, follow_log, manifest_history
from tracegate.ids import dep_id, normalize_name
from tracegate.lockfiles import ecosystem_for, pin_entries
from tracegate.models import NodeKind
from tracegate.signing import HmacSigner, Verifier

KEY = b"bench-key"
METHODS = ("tracegate", "tracegate-single-version", "blame", "pickaxe-package-specific", "pickaxe-version-line")
STRATA = ("single_package", "multi_version", "grouped", "revert", "re_bump")
SOURCES = ("bot_single", "grouped", "revert")
POINTS = ("at_bump", "later_snapshot")
MAX_CASES, SEED = 40, 0
SELECTION = ("per repository and stratum: uniform random sample without replacement of at most 40 usable cases "
             "(random.Random(0).shuffle), then chronological")

_PFX = r"^(?:[\w-]+(?:\([\w./-]+\))?!?: )?"
_BUMP = re.compile(_PFX + r"bump (\S+) from v?(\S+) to v?([0-9][\w.+-]*?)(?:\s|$)", re.I)
_RENO = re.compile(_PFX + r"update (?:dependency |rust crate |module |npm package |gem )?(\S+) to v?([0-9][\w.+-]*?)"
                   r"(?:\s|$)", re.I)
_ANY = re.compile(r"\b(?:bump|update|upgrade|downgrade|pin|revert|roll ?back|lock)\s+(?:dependency\s+|rust crate\s+)?"
                  r"`?([@\w][\w@./-]*)`?\s+(?:from\s+v?\S+\s+)?(?:to|back to)\s+v?([0-9][\w.+-]*?)(?:[\s,);]|$)", re.I)
_BOT = re.compile(r"dependabot|renovate|\[bot\]", re.I)
_BOT_MERGE = re.compile(r"^Merge pull request #\d+ from [\w.-]+/(?:dependabot|renovate)/", re.I)
_GROUPISH = re.compile(r"\bgroup with\b|\bupdates\b|\band\b|\bgroup\b|\bmonorepo\b|\ball (?:non-major )?dependencies\b",
                       re.I)
_UPDATES = re.compile(r"^\s*Updates `([^`]+)` from v?(\S+?) to v?(\S+?)\.?\s*$", re.M)
_RENO_ROW = re.compile(r"^\|\s*\[([^\]]+)\]\([^|]*\|\s*\[?`v?([^`]+)`\s*(?:->|→)\s*`v?([^`]+)`", re.M)
_RENO_DS = re.compile(r"^\|\s*[\w-]+\s*\|\s*([@\w][\w@./-]*)\s*\|\s*v?([0-9][^\s|]*)\s*\|\s*v?([0-9][^\s|]*)\s*\|", re.M)
_MULTI_SUBJ = re.compile(r"([@\w][\w@./-]*) from v?(\S+) to v?([0-9][\w.+-]*)")
_REVERT = re.compile(r'^Revert "(.+)"', re.I)
_REVERTS_SHA = re.compile(r"This reverts commit ([0-9a-f]{7,40})")


def bot_bump(author: str, subject: str) -> tuple[str, str] | None:
    """(package, target version) for a bot-authored single-package bump commit, else None."""
    if not _BOT.search(author) or _GROUPISH.search(subject):
        return None
    m = _BUMP.match(subject)
    if m:
        name, ver = m.group(1), m.group(3)
    else:
        m = _RENO.match(subject)
        if not m:
            return None
        name, ver = m.group(1), m.group(2)
    if name.lower() == "the":
        return None
    return name, ver.rstrip(".,)")


def _vnorm(v: str) -> str:
    return v.strip().lstrip("vV").split("+")[0].rstrip(".,)")


def body_labels(body: str) -> list[tuple[str, str, str | None]]:
    """(package, target version, from version) labels in a grouped bot commit body."""
    out = [(n, _vnorm(b), _vnorm(a)) for n, a, b in _UPDATES.findall(body)]
    out += [(n, _vnorm(b), _vnorm(a)) for n, a, b in _RENO_ROW.findall(body)]
    out += [(n, _vnorm(b), _vnorm(a)) for n, a, b in _RENO_DS.findall(body)]
    return list(dict.fromkeys(out))


class _Repo:
    """Per-repository state: multi- and single-version histories, signed events, small caches."""

    def __init__(self, repo: Path, manifest: str):
        self.repo, self.manifest = repo, manifest
        self.eco = ecosystem_for(manifest)
        self.hist = manifest_history(repo, manifest)
        self.hist1 = manifest_history(repo, manifest, multi_version=False)
        order = {row[0]: i for i, row in enumerate(follow_log(repo, manifest))}  # oldest first
        self.pos = [order[mc.sha] for mc in self.hist]
        self.pos1 = [order[mc.sha] for mc in self.hist1]
        signer = HmacSigner("bench", KEY)
        self.envs = [signer.sign(e) for e in commit_events(self.hist, manifest)]
        self.envs1 = [signer.sign(e) for e in commit_events(self.hist1, manifest)]
        self.verifier = Verifier({"bench": KEY})
        self._graph: dict[tuple[str, int], object] = {}
        self._text: dict[str, str] = {}

    def key(self, n: str) -> str:
        return normalize_name(n, self.eco).lower()

    def text(self, j: int) -> str:
        mc = self.hist[j]
        if mc.sha not in self._text:
            if len(self._text) > 32:
                self._text.clear()
            self._text[mc.sha] = _git(self.repo, "show", f"{mc.sha}:{mc.path or self.manifest}")
        return self._text[mc.sha]

    def graph_answer(self, j: int, name: str, ver: str, single: bool) -> str | None:
        """Commit the verified graph as of hist[j] attributes name@ver to (None: not in the graph)."""
        if single:  # every single-version manifest commit up to and including hist[j]
            k = ("single", bisect.bisect_right(self.pos1, self.pos[j]))
            envs = self.envs1[: k[1]]
        else:
            k = ("multi", j + 1)
            envs = self.envs[: j + 1]
        if k not in self._graph:
            for old in [x for x in self._graph if x[0] == k[0]]:
                del self._graph[old]
            self._graph[k] = Collector(self.verifier).collect(envs).graph
        g = self._graph[k]
        did = dep_id(name, ver, self.eco)
        if did not in g.nodes:
            return None
        path = g.upstream_path(did, NodeKind.COMMIT)
        return g.nodes[path[0]].attrs["sha"] if path else None

    def answers(self, j: int, name: str, ver: str) -> dict[str, str | None]:
        """Every method's introducing commit for name@ver at snapshot hist[j]."""
        mc = self.hist[j]
        path = mc.path or self.manifest
        text = self.text(j)
        ent = next((e for e in pin_entries(path, text) or [] if e.name == name and e.version == ver), None)
        got: dict[str, str | None] = {m: None for m in METHODS}
        got["tracegate"] = self.graph_answer(j, name, ver, single=False)
        got["tracegate-single-version"] = self.graph_answer(j, name, ver, single=True)
        if ent is None:
            return got
        lines = text.splitlines()
        bl = _git(self.repo, "blame", "--first-parent", "--porcelain", "-L", f"{ent.line + 1},{ent.line + 1}",
                  mc.sha, "--", path).split()
        got["blame"] = bl[0] if bl and re.fullmatch(r"[0-9a-f]{40}", bl[0]) else None
        tok_line = lines[ent.line].strip()
        tok_pkg = "\n".join(lines[min(ent.key_line, ent.line): ent.line + 1]).strip()

        def pick(tok: str) -> str | None:
            return _git(self.repo, "log", "--first-parent", "-1", "--format=%H", f"-S{tok}", mc.sha, "--",
                        path).strip() or None
        got["pickaxe-version-line"] = pick(tok_line) if tok_line else None
        got["pickaxe-package-specific"] = (got["pickaxe-version-line"] if tok_pkg == tok_line
                                           else pick(tok_pkg) if tok_pkg else None)
        return got


def _labels(r: _Repo, j: int) -> list[tuple[str, str, str]]:
    """(source, package, version) labels stated by the message of manifest commit hist[j]."""
    mc = r.hist[j]
    subj, author = mc.subject, mc.author
    body: str | None = None
    if _BOT_MERGE.match(subj):  # the PR title is the first body line of a GitHub merge commit
        body = _git(r.repo, "log", "-1", "--format=%b", mc.sha)
        subj = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
        author = "dependabot[bot]"
    rv = _REVERT.match(subj)
    if rv:
        inner = rv.group(1)
        m = _BUMP.match(inner)
        if m:
            return [("revert", m.group(1), _vnorm(m.group(2)))]
        m = _RENO.match(inner)
        if not m:
            return []
        body = body if body is not None else _git(r.repo, "log", "-1", "--format=%b", mc.sha)
        sm = _REVERTS_SHA.search(body)
        if not sm:
            return []
        try:  # restored version = what the reverted commit replaced
            ptext = _git(r.repo, "show", f"{sm.group(1)}^:{mc.path or r.manifest}")
        except Exception:  # noqa: BLE001 - reverted commit not reachable in this clone
            return []
        old = {e.version for e in pin_entries(mc.path or r.manifest, ptext) or [] if r.key(e.name) == r.key(m.group(1))}
        return [("revert", m.group(1), _vnorm(v)) for v in sorted(old)]
    bb = bot_bump(author, subj)
    if bb:
        return [("bot_single", bb[0], _vnorm(bb[1]))]
    if _BOT.search(author):
        if body is None:
            body = _git(r.repo, "log", "-1", "--format=%b", mc.sha)
        labs = body_labels(body) or [(n, _vnorm(b), _vnorm(a)) for n, a, b in _MULTI_SUBJ.findall(subj)]
        return [("grouped", n, v) for n, v, _ in labs]
    m = _ANY.search(subj)  # human messages: only kept when they turn out to be re-bumps
    return [("human", m.group(1), _vnorm(m.group(2)))] if m else []


def _resolve(r: _Repo, j: int, name: str, ver: str) -> tuple[str | None, str | None, str | None]:
    """(lock-file name, lock-file version, exclusion reason) for a label at hist[j]."""
    mc = r.hist[j]
    want = r.key(name)
    names = {n for n, _ in mc.entries if r.key(n) == want or r.key(n).endswith("/" + want)}
    if len(names) > 1:
        return None, None, "ambiguous_name"
    if not names:
        return None, None, "not_in_lock"
    pn = next(iter(names))
    parent = r.hist[j - 1].entries if j else frozenset()
    vers = [v for n, v in mc.entries if n == pn and _vnorm(v) == ver]
    if not vers and ver.count(".") < 2:  # "update dependency X to v9": the new 9.x.y copy
        vers = [v for n, v in mc.entries if n == pn and _vnorm(v).startswith(ver + ".") and (pn, v) not in parent]
        if len(vers) > 1:
            return None, None, "ambiguous_name"
    if not vers:
        return pn, None, "not_in_lock"
    if (pn, vers[0]) in parent:
        return pn, vers[0], "already_present"
    return pn, vers[0], None


def oracle_repo(repo: Path, manifest: str, max_cases: int = MAX_CASES, seed: int = SEED) -> dict | None:
    """Collect labelled cases per stratum, sample them and score every method at both points."""
    if not (repo / ".git").exists():
        return None
    r = _Repo(repo, manifest)
    ever: set = set()  # (name, version) pairs present at any earlier manifest commit
    cands: dict[str, list] = {s: [] for s in STRATA}
    excluded = {s: {"already_present": 0, "not_in_lock": 0, "ambiguous_name": 0} for s in SOURCES}
    excluded_examples: list[dict] = []
    labelled = dict.fromkeys(SOURCES, 0)
    for j, mc in enumerate(r.hist):
        for src, name, ver in _labels(r, j):
            pn, hit, reason = _resolve(r, j, name, ver)
            if src == "human":
                if reason is None and (pn, hit) in ever:
                    cands["re_bump"].append((j, pn, hit))
                continue
            labelled[src] += 1
            if reason:
                excluded[src][reason] += 1
                if len(excluded_examples) < 30:
                    excluded_examples.append({"source": src, "reason": reason, "commit": mc.sha[:10],
                                              "subject": mc.subject[:100], "package": name, "version": ver})
                continue
            if src == "revert":
                stratum = "revert"
            elif (pn, hit) in ever:
                stratum = "re_bump"
            elif src == "grouped":
                stratum = "grouped"
            else:
                stratum = "multi_version" if sum(1 for n, _ in mc.entries if n == pn) > 1 else "single_package"
            cands[stratum].append((j, pn, hit))
        ever |= mc.entries
    usable = {s: len(c) for s, c in cands.items()}
    tasks = []  # (snapshot index, stratum, point, package, version, label commit index)
    for s in STRATA:
        cs = cands[s]
        random.Random(seed).shuffle(cs)
        for j, pn, ver in sorted(cs[:max_cases]):
            later = j
            while later + 1 < len(r.hist) and (pn, ver) in r.hist[later + 1].entries:
                later += 1
            tasks.append((j, s, "at_bump", pn, ver, j))
            if later != j:
                tasks.append((later, s, "later_snapshot", pn, ver, j))
    rows = {s: {m: {p: [0, 0] for p in POINTS} for m in METHODS} for s in STRATA}
    oks: dict = {s: {p: {m: [] for m in METHODS} for p in POINTS} for s in STRATA}
    misses = []
    for jj, s, point, pn, ver, j in sorted(tasks):  # snapshot order: one graph build per snapshot
        truth = r.hist[j].sha
        for m, sha in r.answers(jj, pn, ver).items():
            ok = sha == truth
            rows[s][m][point][0] += ok
            rows[s][m][point][1] += 1
            oks[s][point][m].append(ok)
            if not ok and len(misses) < 60:
                misses.append({"stratum": s, "method": m, "point": point, "package": pn, "version": ver,
                               "label": truth[:10], "snapshot": r.hist[jj].sha[:10], "got": (sha or "")[:10],
                               "label_subject": r.hist[j].subject[:100]})
    scores = {s: {m: {p: {"correct": c, "total": t} for p, (c, t) in d.items()} for m, d in ms.items()}
              for s, ms in rows.items()}
    vs: dict = {}
    for s in STRATA:
        for p in POINTS:
            tg = oks[s][p]["tracegate"]
            if tg:
                vs.setdefault(s, {})[p] = {o: table2x2(list(zip(tg, oks[s][p][o]))) for o in METHODS[1:]}
    print(f"[oracle {repo.name}] usable={usable} excluded={excluded} " + " ".join(
        f"{s}/{m}={d['at_bump'][0]}/{d['at_bump'][1]};{d['later_snapshot'][0]}/{d['later_snapshot'][1]}"
        for s, ms in rows.items() for m, d in ms.items() if d["at_bump"][1] and m in ("tracegate", "blame")),
        flush=True)
    return {"repo": repo.name, "ecosystem": r.eco, "manifest": manifest, "manifest_commits": len(r.hist),
            "labelled": labelled, "usable": usable, "evaluated": {s: min(usable[s], max_cases) for s in STRATA},
            "excluded": excluded, "excluded_examples": excluded_examples, "misses": misses,
            "scores": scores, "tracegate_vs": vs}


def pool(orc: list[dict]) -> dict:
    """Pooled figures per stratum and over all strata: exact, Wilson, clustered, population-weighted, paired."""
    out: dict = {}
    for s in (*STRATA, "all"):
        strata = STRATA if s == "all" else (s,)
        for m in METHODS:
            for p in POINTS:
                per_repo = [(sum(o["scores"][x][m][p]["correct"] for x in strata),
                             sum(o["scores"][x][m][p]["total"] for x in strata)) for o in orc]
                c, t = sum(a for a, _ in per_repo), sum(b for _, b in per_repo)
                if not t:
                    continue
                d = proportion(c, t)
                d["repo_cluster_bootstrap95"] = cluster_bootstrap(per_repo)
                w = [(o["usable"][x], o["scores"][x][m][p]) for o in orc for x in strata
                     if o["scores"][x][m][p]["total"]]
                tot = sum(u for u, _ in w)
                d["population_weighted_accuracy"] = (round(sum(u * sc["correct"] / sc["total"] for u, sc in w) / tot, 4)
                                                     if tot else None)
                out.setdefault(s, {}).setdefault(m, {})[p] = d
        for p in POINTS:
            for other in METHODS[1:]:
                tabs = [o["tracegate_vs"].get(x, {}).get(p, {}).get(other) for o in orc for x in strata]
                tabs = [t for t in tabs if t]
                if not tabs:
                    continue
                agg: dict = {k: sum(t[k] for t in tabs) for k in ("both", "only_a", "only_b", "neither")}
                agg["mcnemar_exact_p"] = mcnemar_exact(agg["only_a"], agg["only_b"])
                per_repo = [(sum(o["scores"][x]["tracegate"][p]["correct"] for x in strata),
                             sum(o["scores"][x][other][p]["correct"] for x in strata),
                             sum(o["scores"][x]["tracegate"][p]["total"] for x in strata)) for o in orc]
                agg["accuracy_difference_repo_cluster_bootstrap95"] = paired_cluster_bootstrap(per_repo)
                out.setdefault(s, {}).setdefault("tracegate_vs", {}).setdefault(p, {})[other] = agg
    return out


def oracle_report(orc: list[dict]) -> dict:
    """The full oracle results document (without run metadata)."""
    return {
        "oracle": ("labels from commit messages only (bot bump subjects and bodies, revert subjects, human "
                   "re-bump subjects); each label checked with the multi-version reader: X@V absent at the "
                   "parent and present at the labelled commit"),
        "what_it_tests": ("at the labelled commit tracegate is right by construction on every verified label; "
                          "the oracle can fail tracegate at later snapshots, on the multi_version stratum (single-"
                          "version ablation) and on revert / re_bump (first introduction is wrong). It does not "
                          "test attribution independently of the lock-file reader."),
        "max_cases": MAX_CASES, "seed": SEED, "selection": SELECTION,
        "strata": list(STRATA), "methods": list(METHODS),
        "pooled": pool(orc), "repos": orc}
