"""Deterministic Python policy DSL, mirrored by policies/tracegate.rego (parity checked in CI, ADR 0003).

Each rule inspects the enriched CollectResult and yields (verdict, reason dict).
The overall verdict is the max over rules; every reason carries its graph path.
No ML / LLM participates in the decision.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator

from .collector import CollectResult
from .models import Decision, Finding, NodeKind, Severity, Verdict

Rule = Callable[[CollectResult], Iterator[tuple[Verdict, dict]]]
RULES: list[Rule] = []
SCANNERS = frozenset({"trivy", "grype", "osv"})


def rule(fn: Rule) -> Rule:
    """Decorator that registers a policy rule."""
    RULES.append(fn)
    return fn


def _path(res: CollectResult, f: Finding) -> list[str]:
    g = res.graph
    p = g.upstream_path(f.node_id, NodeKind.COMMIT) or [f.node_id]
    return [f"{g.nodes[n].kind.value}:{g.nodes[n].label}" for n in p]


@rule
def provenance_integrity(res: CollectResult):
    """Block on rejected attestations and missing required stages."""
    for r in res.rejected:
        yield Verdict.BLOCK, {"rule": "provenance_integrity", "msg": r}
    if res.missing_stages:
        yield Verdict.BLOCK, {"rule": "provenance_integrity",
                              "msg": f"missing signed provenance for stages {sorted(res.missing_stages)}"}


@rule
def malicious_dependency(res: CollectResult):
    """Block on dependencies flagged as malicious."""
    for f in res.graph.findings:
        if f.source == "warden":
            v = Verdict.BLOCK if f.severity == Severity.CRITICAL else Verdict.WARN
            yield v, {"rule": "malicious_dependency", "finding": f.id, "msg": f.title, "path": _path(res, f)}


@rule
def vulnerable_dependency(res: CollectResult):
    """Block on reachable high or critical CVEs; warn on the rest."""
    for f in res.graph.findings:
        if f.source not in SCANNERS:
            continue
        if f.severity.rank >= Severity.HIGH.rank:
            v = Verdict.WARN if f.reachable is False else Verdict.BLOCK
        elif f.severity == Severity.MEDIUM:
            v = Verdict.WARN
        else:
            continue
        yield v, {"rule": "vulnerable_dependency", "finding": f.cve, "severity": f.severity.value,
                  "reachable": f.reachable, "evidence": f.evidence, "path": _path(res, f)}


@rule
def sast(res: CollectResult):
    """Turn SAST findings into reasons by severity."""
    for f in res.graph.findings:
        if f.source == "sast" and f.severity.rank >= Severity.MEDIUM.rank:
            v = Verdict.BLOCK if f.severity.rank >= Severity.HIGH.rank else Verdict.WARN
            yield v, {"rule": "sast", "finding": f.title, "path": _path(res, f)}


def evaluate(res: CollectResult, rules: list[Rule] | None = None) -> Decision:
    """Apply policy rules and combine them into one verdict.

    Args:
        res: Collection result.
        rules: Rules to apply; the registered rules when None.

    Returns:
        The strictest verdict and every reason.
    """
    verdict, reasons = Verdict.PASS, []
    for r in rules or RULES:
        for v, reason in r(res):
            reason["verdict"] = v.value
            reasons.append(reason)
            if v.rank > verdict.rank:
                verdict = v
    return Decision(verdict, reasons)


def pr_comment(d: Decision) -> str:
    """Render a decision as a Markdown pull-request comment."""
    icon = {"pass": "PASS", "warn": "WARN", "block": "BLOCK"}[d.verdict.value]
    lines = [f"## TRACEGATE: {icon}", ""]
    for r in d.reasons:
        lines.append(f"- **[{r['verdict']}] {r['rule']}**: {r.get('msg') or r.get('finding')}")
        if r.get("path"):
            lines.append(f"  - path: `{' -> '.join(r['path'])}`")
        for e in r.get("evidence", []) or []:
            lines.append(f"  - evidence: {e}")
    if not d.reasons:
        lines.append("No policy violations.")
    return "\n".join(lines)
