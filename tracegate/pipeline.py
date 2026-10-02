"""End-to-end: envelopes -> verified graph -> enrichment -> gate decision."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .collector import Collector, CollectResult
from .enrich import enrich
from .models import Decision, Envelope
from .policy import evaluate
from .signing import Verifier, envelope_from_dict
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


def load_envelopes(path: str | Path) -> list[Envelope]:
    """Read envelopes from a JSON file (TRACEGATE or standard DSSE layout).

    Args:
        path: Input path.

    Returns:
        The envelopes, not yet verified.

    Raises:
        SignatureError: An entry is not a well-formed envelope.
    """
    return [envelope_from_dict(d) for d in json.loads(Path(path).read_text())]
