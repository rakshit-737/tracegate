"""Name-based typosquat / combosquat detector.

Given a reference list of popular package names (ordered by popularity), score
an unknown package name by how plausibly it impersonates one of them. Pure
stdlib and deterministic, so it can sit in the gate's dependency-risk node.

Techniques (each yields a base score, then scaled by target popularity):

  separator   : same letters, different separators  (crossenv  -> cross-env)
  homoglyph   : visually confusable chars           (reque5ts  -> requests)
  typo        : Damerau-Levenshtein 1 / 2 edits      (reqeusts  -> requests)
  reorder     : tokens swapped                       (dateutil-python -> python-dateutil)
  combosquat  : popular name + a common affix        (requests-py, python3-requests)

Candidate lookup uses a deletion-neighbourhood (SymSpell-style) index, so
scoring one name against 10k references is O(len(name)^2), not O(10k).
"""
from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

_SEP = re.compile(r"[-_.]+")

HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
              "rn": "m", "vv": "w", "i": "l"}
AFFIXES = ("python", "py", "python3", "py3", "3", "2", "js", "node", "lib", "sdk", "api",
           "dev", "utils", "util", "tools", "core", "client", "cli", "pkg", "package",
           "official", "latest", "new", "plus", "pro", "fix", "patch", "update")
# QWERTY neighbours for fat-finger substitutions.
_ROWS = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
KEY_NEIGHBOURS: dict[str, set[str]] = {}
for r, row in enumerate(_ROWS):
    for c, ch in enumerate(row):
        nb = set()
        for dr in (-1, 0, 1):
            rr = r + dr
            if 0 <= rr < len(_ROWS):
                for dc in (-1, 0, 1):
                    cc = c + dc
                    if (dr or dc) and 0 <= cc < len(_ROWS[rr]):
                        nb.add(_ROWS[rr][cc])
        KEY_NEIGHBOURS[ch] = nb


def normalize(name: str) -> str:
    """PEP 503-style normalisation (also applied to npm names, minus scope)."""
    n = name.strip().lower()
    if n.startswith("@") and "/" in n:
        n = n.split("/", 1)[1]
    return _SEP.sub("-", n)


def squash(name: str) -> str:
    return _SEP.sub("", normalize(name))


def damerau(a: str, b: str, cap: int = 3) -> int:
    """Optimal-string-alignment distance with early exit at `cap`."""
    if abs(len(a) - len(b)) >= cap:
        return cap
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            best = min(best, cur[j])
        if best >= cap:
            return cap
        prev2, prev = prev, cur
    return min(prev[-1], cap)


def _deletes(s: str, k: int) -> set[str]:
    out = {s}
    frontier = {s}
    for _ in range(k):
        nxt = set()
        for w in frontier:
            for i in range(len(w)):
                nxt.add(w[:i] + w[i + 1:])
        out |= nxt
        frontier = nxt
    return out


def _deglyph(s: str) -> str:
    for k, v in HOMOGLYPHS.items():
        s = s.replace(k, v)
    return s


@dataclass
class Match:
    name: str
    score: float  # 0..1
    target: str | None = None
    technique: str | None = None
    detail: str = ""
    reasons: list[str] = field(default_factory=list)


class TyposquatDetector:
    """Score names against a popularity-ranked reference list.

    `max_edits=2` is only used for names of length >= `long_name` to keep the
    false-positive rate on short names down (short names are dense).
    """

    BASE = {"separator": 0.95, "homoglyph": 0.9, "typo1": 0.85, "typo2": 0.65,
            "reorder": 0.8, "combosquat": 0.6, "suffix": 0.7, "brandjack": 0.45}

    def __init__(self, popular: Iterable[str], min_len: int = 4, long_name: int = 9,
                 enabled: Iterable[str] | None = None, brand_top: int = 300):
        self.ranked = []
        seen = set()
        for p in popular:
            n = normalize(p)
            if n and n not in seen:
                seen.add(n)
                self.ranked.append(n)
        self.rank = {n: i for i, n in enumerate(self.ranked)}
        self.min_len, self.long_name = min_len, long_name
        self.brand_top = brand_top
        self.enabled = set(enabled) if enabled else set(self.BASE)
        self.squashed: dict[str, str] = {}
        self.deglyphed: dict[str, str] = {}
        self.tokens: dict[tuple[str, ...], str] = {}
        # deletion key -> reference name(s); a bare str for the common single-name case keeps
        # the index small (it holds ~100 keys per long reference name)
        self.index: dict[str, str | list[str]] = {}
        for n in self.ranked:
            self.squashed.setdefault(squash(n), n)
            self.deglyphed.setdefault(_deglyph(squash(n)), n)
            toks = tuple(sorted(t for t in n.split("-") if t))
            if len(toks) > 1:
                self.tokens.setdefault(toks, n)
            if len(n) >= min_len:
                k = 2 if len(n) >= long_name else 1
                for d in _deletes(n, k):
                    cur = self.index.get(d)
                    if cur is None:
                        self.index[d] = n
                    elif isinstance(cur, str):
                        if cur != n:
                            self.index[d] = [cur, n]
                    elif n not in cur:
                        cur.append(n)

    def _lookup(self, key: str) -> list[str] | tuple[str, ...]:
        v = self.index.get(key)
        if v is None:
            return ()
        return (v,) if isinstance(v, str) else v

    # popularity weight: rank 0 -> 1.0, rank 10k -> ~0.55
    def _pop(self, target: str) -> float:
        r = self.rank.get(target, len(self.ranked))
        return 1.0 - 0.1 * math.log10(1 + r)

    @staticmethod
    def _len_factor(tech: str, tgt: str) -> float:
        # one edit on a 4-letter name is far more likely to be an unrelated project
        if tech != "typo1":
            return 1.0
        return {4: 0.7, 5: 0.8, 6: 0.9}.get(len(tgt), 1.0 if len(tgt) > 6 else 0.6)

    def _best(self, cands: list[tuple[str, str, str]]) -> Match | None:
        best: Match | None = None
        for tech, tgt, detail in cands:
            s = round(self.BASE[tech] * self._pop(tgt) * self._len_factor(tech, tgt), 4)
            if best is None or s > best.score or (s == best.score and self.rank[tgt] < self.rank[best.target]):
                best = Match("", s, tgt, tech, detail)
        return best

    def score(self, name: str) -> Match:
        n = normalize(name)
        if n in self.rank:
            return Match(name, 0.0, reasons=["is a known popular package"])
        cands: list[tuple[str, str, str]] = []
        sq = squash(n)
        if "separator" in self.enabled and sq in self.squashed and self.squashed[sq] != n:
            cands.append(("separator", self.squashed[sq], "separator-only difference"))
        if "homoglyph" in self.enabled:
            dg = _deglyph(sq)
            if dg != sq and dg in self.deglyphed and self.deglyphed[dg] != n:
                cands.append(("homoglyph", self.deglyphed[dg], "confusable characters"))
        if len(n) >= self.min_len and ("typo1" in self.enabled or "typo2" in self.enabled):
            k = 2 if len(n) >= self.long_name else 1
            pool: set[str] = set()
            for d in _deletes(n, k):
                pool.update(self._lookup(d))
            for tgt in pool:
                if tgt == n:
                    continue
                dist = damerau(n, tgt)
                if dist == 1 and "typo1" in self.enabled:
                    cands.append(("typo1", tgt, self._describe(n, tgt)))
                elif dist == 2 and "typo2" in self.enabled and min(len(n), len(tgt)) >= self.long_name:
                    cands.append(("typo2", tgt, "2 edits"))
        toks = [t for t in n.split("-") if t]
        if "reorder" in self.enabled and len(toks) > 1:
            key = tuple(sorted(toks))
            if key in self.tokens and self.tokens[key] != n:
                cands.append(("reorder", self.tokens[key], "tokens reordered"))
        if "combosquat" in self.enabled and len(toks) > 1:
            cands.extend(self._combo(toks))
        if "suffix" in self.enabled:
            stripped = n.rstrip("0123456789-")
            if stripped != n and len(stripped) >= self.min_len:
                if stripped in self.rank:
                    cands.append(("suffix", stripped, f"'{stripped}' + version-like suffix"))
                else:
                    for d in _deletes(stripped, 1):
                        for tgt in self._lookup(d):
                            if not tgt[-1:].isdigit() and damerau(stripped, tgt) <= 1:
                                cands.append(("suffix", tgt, "typo + version-like suffix"))
        if "brandjack" in self.enabled and len(toks) > 1:
            for t in toks:
                r = self.rank.get(t)
                if r is not None and r < self.brand_top and len(t) >= 5:
                    cands.append(("brandjack", t, f"reuses top-{self.brand_top} name '{t}' as a token"))
        m = self._best(cands)
        if m is None:
            return Match(name, 0.0)
        m.name = name
        m.reasons = [f"possible {m.technique} of '{m.target}' ({m.detail}; target rank #{self.rank[m.target] + 1})"]
        return m

    def _combo(self, toks: list[str]) -> list[tuple[str, str, str]]:
        out = []
        for i in range(len(toks)):
            for j in range(i + 1, len(toks) + 1):
                if j - i == len(toks):
                    continue
                core = "-".join(toks[i:j])
                rest = toks[:i] + toks[j:]
                if core in self.rank and len(core) >= self.min_len and all(t in AFFIXES for t in rest):
                    out.append(("combosquat", core, f"'{core}' + affix {rest}"))
        return out

    @staticmethod
    def _describe(a: str, b: str) -> str:
        if len(a) == len(b):
            diff = [(x, y) for x, y in zip(a, b) if x != y]
            if len(diff) == 2 and diff[0] == diff[1][::-1]:
                return "transposition"
            if len(diff) == 1:
                x, y = diff[0]
                return "adjacent-key substitution" if y in KEY_NEIGHBOURS.get(x, ()) else "substitution"
        return "insertion" if len(a) > len(b) else "omission"


def pairwise_edit_baseline(popular: list[str], names: Iterable[str], max_dist: int = 1,
                           min_len: int = 4) -> dict[str, str | None]:
    """Plain Levenshtein<=k baseline (what most typosquat scanners do)."""
    det = TyposquatDetector(popular, min_len=min_len, long_name=10**9, enabled={"typo1"})
    out = {}
    for n in names:
        m = det.score(n)
        out[n] = m.target if m.score > 0 else None
    return out


__all__ = ["TyposquatDetector", "Match", "normalize", "squash", "damerau",
           "pairwise_edit_baseline"]
