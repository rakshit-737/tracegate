"""End-to-end: envelopes -> verified graph -> enrichment -> gate decision."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .collector import CollectResult, Collector
from .enrich import enrich
from .models import Decision, Envelope
from .policy import evaluate
from .signing import Verifier, envelope_from_dict
from .warden import HeuristicWarden, WardenClient


def run(envelopes: list[Envelope], trusted: dict[str, bytes],
        warden: WardenClient | None = None) -> tuple[CollectResult, Decision]:
    res = Collector(Verifier(trusted)).collect(envelopes)
    enrich(res, warden or HeuristicWarden())
    return res, evaluate(res)


def save_envelopes(envs: list[Envelope], path: str | Path) -> None:
    Path(path).write_text(json.dumps([asdict(e) for e in envs], indent=1))


def load_envelopes(path: str | Path) -> list[Envelope]:
    return [envelope_from_dict(d) for d in json.loads(Path(path).read_text())]
