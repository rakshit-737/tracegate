"""Faithful re-implementations of published typosquat detectors, for head-to-head comparison.

* `Typomania` - the Rust Foundation's `typomania` 0.2 (github.com/rustfoundation/typomania),
  itself a port of TypoGard (Taylor, Vaidya, Davidson, De Carli, Rastogi, "Defending Against
  Package Typosquatting", NSS 2020, LNCS 12570). Checks and parameters follow typomania's
  `Harness::builder()` defaults (repeated character, swapped characters, version suffix) plus
  the checks its `examples/registry.rs` adds (bitflips, omitted character, swapped words over
  "-_.", and the TypoGard keyboard/visual typo table), with the example's alphabet.
  Every check *generates* variants of the candidate name and asks whether the corpus contains
  one; there is no score, only a set of matched corpus names. typomania also suppresses a match
  when the two packages share an author - we have no author data, so that filter is off.

* `pypi_scan` - IQT Labs `pypi-scan` (github.com/IQTLabs/pypi-scan): Levenshtein distance
  <= MAX_DISTANCE (1) to a top package, skipping top packages shorter than
  MIN_LEN_PACKAGE_NAME (5). Its default corpus is the top 50 PyPI packages; the benchmark
  runs both that default and the same top-5k reference TRACEGATE uses.
"""
from __future__ import annotations

from collections.abc import Iterable
from itertools import permutations

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-_"

TYPOS: dict[str, list[str]] = {
    "1": ["2", "q", "i", "l"], "2": ["1", "q", "w", "3"], "3": ["2", "w", "e", "4"],
    "4": ["3", "e", "r", "5"], "5": ["4", "r", "t", "6", "s"], "6": ["5", "t", "y", "7"],
    "7": ["6", "y", "u", "8"], "8": ["7", "u", "i", "9"], "9": ["8", "i", "o", "0"],
    "0": ["9", "o", "p", "-"], "-": ["_", "0", "p", ".", ""], "_": ["-", "0", "p", ".", ""],
    "q": ["1", "2", "w", "a"], "w": ["2", "3", "e", "s", "a", "q", "vv"],
    "e": ["3", "4", "r", "d", "s", "w"], "r": ["4", "5", "t", "f", "d", "e"],
    "t": ["5", "6", "y", "g", "f", "r"], "y": ["6", "7", "u", "h", "t", "i"],
    "u": ["7", "8", "i", "j", "y", "v"], "i": ["1", "8", "9", "o", "l", "k", "j", "u", "y"],
    "o": ["9", "0", "p", "l", "i"], "p": ["0", "-", "o"], "a": ["q", "w", "s", "z"],
    "s": ["w", "d", "x", "z", "a", "5"], "d": ["e", "r", "f", "c", "x", "s"],
    "f": ["r", "g", "v", "c", "d"], "g": ["t", "h", "b", "v", "f"], "h": ["y", "j", "n", "b", "g"],
    "j": ["u", "i", "k", "m", "n", "h"], "k": ["i", "o", "l", "m", "j"], "l": ["i", "o", "p", "k", "1"],
    "z": ["a", "s", "x"], "x": ["z", "s", "d", "c"], "c": ["x", "d", "f", "v"],
    "v": ["c", "f", "g", "b", "u"], "b": ["v", "g", "h", "n"], "n": ["b", "h", "j", "m"],
    "m": ["n", "j", "k", "rn"], ".": ["-", "_", ""],
}


def _bitflips(name: str) -> Iterable[str]:
    for i, ch in enumerate(name):
        o = ord(ch)
        if o > 127:
            continue
        for b in range(8):
            f = o ^ (1 << b)
            if f < 128:
                yield name[:i] + chr(f) + name[i + 1:]


class Typomania:
    CHECKS = ("repeated", "swapped_chars", "version", "bitflips", "omitted", "swapped_words", "typos")

    def __init__(self, corpus: Iterable[str], alphabet: str = ALPHABET, delimiters: str = "-_.",
                 max_k: int = 5, enabled: set[str] | None = None):
        self.names = list(dict.fromkeys(corpus))
        self.corpus = set(self.names)
        self.alphabet = alphabet
        self.delims = delimiters
        self.max_k = max_k
        self.enabled = set(enabled) if enabled else set(self.CHECKS)
        allowed = set(alphabet)
        self._bitflip: dict[str, list[str]] = {}
        if "bitflips" in self.enabled:
            for n in self.names:
                for bf in _bitflips(n):
                    if all(c in allowed for c in bf):
                        self._bitflip.setdefault(bf, []).append(n)

    def _hit(self, cand: str, name: str) -> bool:
        return cand != name and cand in self.corpus

    def check(self, name: str) -> list[tuple[str, str]]:
        """[(check, corpus name)] for every check that fires."""
        out: list[tuple[str, str]] = []
        e = self.enabled
        chars = list(name)
        if "repeated" in e:
            for i in range(len(chars) - 1):
                if chars[i] == chars[i + 1] and chars[i].isascii():
                    c = name[:i] + chars[i] + name[i + 2:]
                    if self._hit(c, name):
                        out.append(("repeated", c))
        if "swapped_chars" in e:
            for i in range(len(chars) - 1):
                if chars[i] != chars[i + 1]:
                    c = name[:i] + chars[i + 1] + chars[i] + name[i + 2:]
                    if self._hit(c, name):
                        out.append(("swapped_chars", c))
        if "version" in e:
            t = name.rstrip("0123456789").rstrip("-")
            if t and t != name and self._hit(t, name):
                out.append(("version", t))
        if "bitflips" in e:
            for c in self._bitflip.get(name, []):
                if self._hit(c, name):
                    out.append(("bitflips", c))
        if "omitted" in e:
            for i in range(len(name) + 1):
                for a in self.alphabet:
                    c = name[:i] + a + name[i:]
                    if self._hit(c, name):
                        out.append(("omitted", c))
        if "swapped_words" in e:
            toks = [t for t in _split(name, self.delims)]
            if len(toks) > 1:
                k = min(len(toks), self.max_k)
                for perm in permutations(toks, k):
                    for d in self.delims:
                        c = d.join(perm)
                        if self._hit(c, name):
                            out.append(("swapped_words", c))
        if "typos" in e:
            for i, ch in enumerate(name):
                for t in TYPOS.get(ch, ()):
                    c = name[:i] + t + name[i + 1:]
                    if self._hit(c, name):
                        out.append(("typos", c))
        return out

    def flag(self, name: str) -> bool:
        return bool(self.check(name))


def _split(name: str, delims: str) -> list[str]:
    toks, cur = [], ""
    for ch in name:
        if ch in delims:
            toks.append(cur)
            cur = ""
        else:
            cur += ch
    toks.append(cur)
    return toks


def levenshtein(a: str, b: str, cap: int = 2) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


class PypiScan:
    """IQT Labs pypi-scan: flag a name within Levenshtein MAX_DISTANCE of a top package
    whose name is at least MIN_LEN_PACKAGE_NAME long (constants.py: 1 and 5)."""

    def __init__(self, top: Iterable[str], max_distance: int = 1, min_len: int = 5):
        if max_distance != 1:
            raise ValueError("only pypi-scan's default MAX_DISTANCE=1 is indexed")
        self.max_distance = max_distance
        # symmetric-delete index: lev(a, b) <= 1 implies a 0/1-deletion of a equals one of b,
        # so candidates are found by lookup and then confirmed with the exact distance.
        self.index: dict[str, set[str]] = {}
        for t in dict.fromkeys(top):
            if len(t) >= min_len:
                for d in _dels(t):
                    self.index.setdefault(d, set()).add(t)

    def check(self, name: str) -> list[str]:
        cands: set[str] = set()
        for d in _dels(name):
            cands |= self.index.get(d, set())
        return sorted(t for t in cands if t != name and levenshtein(name, t, 1) <= 1)

    def flag(self, name: str) -> bool:
        return bool(self.check(name))


def _dels(s: str) -> set[str]:
    return {s} | {s[:i] + s[i + 1:] for i in range(len(s))}
