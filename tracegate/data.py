"""Location of the (uncommitted) real datasets fetched by scripts/download_data.py."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]


def data_root() -> Path:
    """Dataset directory: ``$TRACEGATE_DATA`` or the portfolio default."""
    env = os.environ.get("TRACEGATE_DATA")
    if env:
        return Path(env)
    sibling = _REPO.parents[1] / "datasets" / "tracegate"
    return sibling if sibling.exists() else _REPO / "data"


def have(*rel: str) -> bool:
    """Return True when every relative path exists under the dataset root."""
    return all((data_root() / r).exists() for r in rel)


def top_pypi(n: int | None = None) -> list[str]:
    """Most-downloaded PyPI project names, most popular first.

    Args:
        n: Keep only the first ``n`` names; all when None.

    Returns:
        Project names.
    """
    rows = json.loads((data_root() / "popular/top-pypi-packages.min.json").read_text())["rows"]
    names = [r["project"] for r in sorted(rows, key=lambda r: -r["download_count"])]
    return names[:n] if n else names


def top_npm(n: int | None = None) -> list[str]:
    """High-impact npm package names, most popular first.

    Args:
        n: Keep only the first ``n`` names; all when None.

    Returns:
        Package names.
    """
    text = (data_root() / "popular/npm-high-impact-top.js").read_text(encoding="utf-8")
    names = re.findall(r"^\s*'([^']+)',?\s*$", text, re.M)
    return names[:n] if n else names


def top_popular(which: str, n: int | None = None) -> list[str]:
    """Download-ranked names: 'pypi', 'npm', or a paged list ('crates', 'rubygems', 'nuget')."""
    if which == "pypi":
        return top_pypi(n)
    if which == "npm":
        return top_npm(n)
    rows = json.loads((data_root() / f"popular/{which}-top.json").read_text())
    names = [r["name"] for r in rows]
    return names[:n] if n else names
