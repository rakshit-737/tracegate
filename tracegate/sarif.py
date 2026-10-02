"""SARIF 2.1.0 -> `sast` stage-event payload.

Works with the SARIF emitted by Semgrep, Bandit (`-f sarif`), CodeQL and most other
static analysers. Severity comes from, in order: `properties.security-severity`
(CVSS-like 0-10, used by CodeQL/GitHub), the rule's `defaultConfiguration.level`, then the
result `level`. SARIF levels map error->high, warning->medium, note/none->low.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "low"}


def _cvss_band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _severity(result: dict, rule: dict) -> str:
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        s = props.get("security-severity")
        if s is not None:
            try:
                return _cvss_band(float(s))
            except (TypeError, ValueError):
                pass
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return _LEVEL.get(level, "medium")


def _file(result: dict) -> str:
    for loc in result.get("locations") or []:
        uri = ((loc.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
        if uri:
            return uri.removeprefix("file://").lstrip("/") if uri.startswith("file://") else uri
    return "<unknown>"


def sarif_to_sast(src: str | Path | dict, commit: str) -> dict[str, Any]:
    """Convert a SARIF 2.1.0 log into a SAST stage payload.

    Args:
        src: Path to, or parsed, SARIF JSON.
        commit: Commit SHA the analysis ran on.

    Returns:
        A SAST payload with one finding per result.
    """
    doc = src if isinstance(src, dict) else json.loads(Path(src).read_text(encoding="utf-8"))
    findings = []
    tools = []
    for run in doc.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tools.append(driver.get("name", "sarif"))
        rules = {r.get("id"): r for r in driver.get("rules") or []}
        for res in run.get("results") or []:
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown-rule"
            rule = rules.get(rid, {})
            if res.get("kind") not in (None, "fail"):
                continue  # pass / notApplicable / informational results are not findings
            title = ((res.get("message") or {}).get("text")
                     or (rule.get("shortDescription") or {}).get("text") or rid)
            findings.append({"file": _file(res), "rule": rid, "severity": _severity(res, rule),
                             "title": title.strip().splitlines()[0][:200]})
    return {"commit": commit, "tool": "+".join(tools) or "sarif", "findings": findings}


__all__ = ["sarif_to_sast"]
