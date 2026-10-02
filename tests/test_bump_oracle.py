import sys
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
if not (_BENCH / "bump_oracle.py").exists():  # the sdist ships tests but not benchmarks/
    pytest.skip("benchmarks/ not present", allow_module_level=True)
sys.path.insert(0, str(_BENCH))

from bump_oracle import bot_bump, cluster_bootstrap  # noqa: E402

BOT = "49699333+dependabot[bot]@users.noreply.github.com"


def test_bot_bump_single_package():
    assert bot_bump(BOT, "build(deps): bump google.golang.org/grpc from 1.83.1 to 1.83.2 (#8028)") == \
        ("google.golang.org/grpc", "1.83.2")
    assert bot_bump(BOT, "chore(deps): bump webob from 1.8.10 to 1.8.11 (#20456)") == ("webob", "1.8.11")
    assert bot_bump("renovate[bot]@x", "chore(deps): update rust crate serde to v1.0.200") == ("serde", "1.0.200")


def test_bot_bump_rejects_groups_and_humans():
    assert bot_bump(BOT, "chore(deps): bump the python-packages group with 8 updates (#20569)") is None
    assert bot_bump(BOT, "chore(deps): bump readme-renderer and comrak (#20520)") is None
    assert bot_bump("jacob@z7x.org", "Bump PyJWT from 2.13 to 2.14 (#20572)") is None


def test_cluster_bootstrap_bounds():
    ci = cluster_bootstrap([(9, 10), (5, 10), (10, 10)])
    assert ci is not None and 0.5 <= ci[0] <= ci[1] <= 1.0
    assert cluster_bootstrap([]) is None
