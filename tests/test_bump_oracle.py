import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
if not (_BENCH / "bump_oracle.py").exists():  # the sdist ships tests but not benchmarks/
    pytest.skip("benchmarks/ not present", allow_module_level=True)
sys.path.insert(0, str(_BENCH))

from bump_oracle import body_labels, bot_bump, cluster_bootstrap, oracle_repo, oracle_report  # noqa: E402
from stats import clopper_pearson, cp_lower, mcnemar_exact, wilson  # noqa: E402

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


def test_grouped_body_labels():
    body = """Bumps the npm_and_yarn group with 2 updates: [braces](https://x) and [ws](https://y).

Updates `braces` from 3.0.2 to 3.0.3
- [Commits](https://x)

Updates `ws` from 8.13.0 to 8.17.1
"""
    assert body_labels(body) == [("braces", "3.0.3", "3.0.2"), ("ws", "8.17.1", "8.13.0")]
    reno = "| Package | Change |\n|---|---|\n| [@babel/core](https://babel.dev) ([source](https://g)) | " \
           "[`7.22.5` -> `7.22.9`](https://renovatebot.com/diffs/npm) |\n"
    assert body_labels(reno) == [("@babel/core", "7.22.9", "7.22.5")]


def test_exact_bounds_and_mcnemar():
    assert cp_lower(231, 231) == 0.9871 and cp_lower(243, 243) == 0.9877
    lo, hi = clopper_pearson(219, 231)
    assert abs(lo - 0.911) < 1e-3 and abs(hi - 0.9729) < 1e-3  # scipy beta.ppf reference values
    assert mcnemar_exact(8, 0) == 0.00781 and mcnemar_exact(0, 1) == 1.0 and mcnemar_exact(0, 0) is None
    assert wilson(354, 362) == [0.957, 0.9888]


def test_cluster_bootstrap_bounds():
    ci = cluster_bootstrap([(9, 10), (5, 10), (10, 10)])
    assert ci is not None and 0.5 <= ci[0] <= ci[1] <= 1.0
    assert cluster_bootstrap([]) is None


def _git(repo, *a, author=None):
    env = None
    if author:
        import os
        env = {**os.environ, "GIT_AUTHOR_NAME": "dependabot[bot]", "GIT_AUTHOR_EMAIL": author}
    return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True, env=env).stdout


def _lock(**versions: list[str]) -> str:
    out = "# yarn lockfile v1\n\n"
    for name, vers in versions.items():
        for i, v in enumerate(vers):
            out += f'\n{name}@^{i}.0.0:\n  version "{v}"\n'
    return out


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_oracle_strata_can_fail(tmp_path):
    """Synthetic history with every stratum. The single-version ablation must miss the
    multi-version bump; the version diff must get the revert and the re-bump right."""
    repo = tmp_path / "repos" / "demo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "dev@example.com")
    _git(repo, "config", "user.name", "dev")
    steps = [  # (lock, subject, bot?)
        (_lock(debug=["2.6.9", "4.3.4"], ms=["2.1.2"]), "initial lock", False),
        (_lock(debug=["2.6.9", "4.3.5"], ms=["2.1.2"]), "Bump debug from 4.3.4 to 4.3.5", True),
        (_lock(debug=["2.6.9", "4.3.5"], ms=["2.1.3"]), "Bump ms from 2.1.2 to 2.1.3", True),
        (_lock(debug=["2.6.9", "4.3.5"], ms=["2.1.2"]), 'Revert "Bump ms from 2.1.2 to 2.1.3"', False),
        (_lock(debug=["2.6.9", "4.3.6"], ms=["2.1.2"]), "Bump debug from 4.3.5 to 4.3.6", True),
        (_lock(debug=["2.6.9", "4.3.5"], ms=["2.1.2"]), "Pin debug to 4.3.5 again", False),
        (_lock(debug=["2.6.9", "4.3.5"], ms=["2.1.2"], extra=["1.0.0"]), "add extra", False),
    ]
    for text, subject, bot in steps:
        (repo / "yarn.lock").write_text(text)
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", subject, author=BOT if bot else None)
    o = oracle_repo(repo, "yarn.lock")
    assert o["usable"]["multi_version"] == 2  # debug 4.3.5 and 4.3.6 sit next to 2.6.9
    assert o["usable"]["single_package"] == 1 and o["usable"]["revert"] == 1 and o["usable"]["re_bump"] == 1
    sc = o["scores"]
    for s in ("single_package", "multi_version", "revert", "re_bump"):
        assert sc[s]["tracegate"]["at_bump"]["correct"] == sc[s]["tracegate"]["at_bump"]["total"], s
    assert sc["multi_version"]["tracegate-single-version"]["at_bump"]["correct"] == 0
    # without the recency rule the oldest introduction wins, which is wrong for reverts and re-bumps
    assert sc["revert"]["first-introduction"]["at_bump"]["correct"] == 0
    assert sc["re_bump"]["first-introduction"]["at_bump"]["correct"] == 0
    # re-bump: 4.3.5 came back in "Pin debug to 4.3.5 again"; still pinned at the last commit
    assert sc["re_bump"]["tracegate"]["later_snapshot"] == {"correct": 1, "total": 1}
    rep = oracle_report([o])
    assert rep["max_cases"] == 40 and rep["seed"] == 0 and "random.Random(0)" in rep["selection"]
    assert rep["pooled"]["all"]["tracegate"]["at_bump"]["cp_lower95_one_sided"] is not None
