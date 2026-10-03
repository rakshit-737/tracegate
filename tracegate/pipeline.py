"""End-to-end: envelopes -> verified graph -> enrichment -> gate decision."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .collector import Collector, CollectResult
from .enrich import enrich
from .models import Decision, Envelope
from .policy import evaluate
from .signing import SignatureError, Verifier, envelope_from_dict, malformed
from .warden import HeuristicWarden, WardenClient


def run(envelopes: list[Envelope], trusted: dict[str, bytes],
        warden: WardenClient | None = None) -> tuple[CollectResult, Decision]:
    """Verify envelopes, build the graph, enrich it and evaluate the policy.

    Args:
        envelopes: Signed stage events.
        trusted: Key id to trusted key; envelopes signed by any other key are rejected.
        warden: Optional malicious-package scorer.

    Returns:
        The collection result and the gate decision.
    """
    res = Collector(Verifier(trusted)).collect(envelopes)
    enrich(res, warden or HeuristicWarden())
    return res, evaluate(res)


def save_envelopes(envs: list[Envelope], path: str | Path) -> None:
    """Write envelopes to a JSON file.

    Args:
        envs: Envelopes to write.
        path: Output path.
    """
    Path(path).write_text(json.dumps([asdict(e) for e in envs], indent=1))


def load_envelopes(path: str | Path, lenient: bool = False) -> list[Envelope]:
    """Read envelopes from a JSON file (TRACEGATE or standard DSSE layout).

    Args:
        path: Input path.
        lenient: Turn a malformed entry into a placeholder the collector rejects (so the gate
            blocks with a reason) instead of raising.

    Returns:
        The envelopes, not yet verified.

    Raises:
        SignatureError: An entry is not a well-formed envelope (strict mode), or the file is not a list.
    """
    doc = json.loads(Path(path).read_text())
    if not isinstance(doc, list):
        raise SignatureError("malformed events file: expected a JSON list of envelopes")
    out = []
    for i, d in enumerate(doc):
        try:
            out.append(envelope_from_dict(d))
        except SignatureError as e:
            if not lenient:
                raise
            out.append(malformed(f"entry {i}: {e}"))
    return out
