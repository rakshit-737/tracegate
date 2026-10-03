# Contributing to TRACEGATE

Thanks for your interest. TRACEGATE is a small research-grade project, so the process is light.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest -q          # unit tests use committed fixtures only (no downloads)
python -m ruff check .
```

Real-data tests are marked `@pytest.mark.realdata` and skip automatically when the datasets are
absent. To run them, fetch the data first (see the [Reproduce](https://rakshit-737.github.io/tracegate-cicd-security-gate/reproduce/) page or the README "Reproducibility" section):

```bash
python scripts/download_data.py all
python -m pytest -q -m realdata
```

## Ground rules

- **The gate stays deterministic.** No ML or LLM may take part in a pass/warn/block decision. Scores
  (Warden, typosquat) are inputs to explicit, reviewable rules in `tracegate/policy.py`, and the same
  rules are mirrored in `policies/tracegate.rego`. If you change one, change the other; CI checks
  that they agree.
- **Fail closed.** New stage types, key types or inputs must reject on anything unexpected.
- **Never commit datasets** or files over about 1 MB. Add a download step to `scripts/download_data.py`
  (with a checksum where the source allows it) and commit only small derived results in `results/`.
- **No live malware.** Malicious-package data is used as metadata (names, versions, advisories) only.
  Never download or install a package from an OSV `MAL-*` record.
- **Report benchmarks honestly.** Keep the baselines. If a change makes a number worse, say so in the PR.

## Commits and PRs

- Use conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`, `refactor:`, `ci:`).
- Keep each PR focused, add tests for new behaviour, and update `CHANGELOG.md` under *Unreleased*.
- For a design change, add an ADR in `docs/adr/` (copy the format of an existing one).

## Docs

```bash
pip install -r docs/requirements.txt -e .
python scripts/build_static_demo.py   # step 1: writes docs/demo/data/*.json (git-ignored)
mkdocs build --strict                 # step 2: the site docs.yml publishes (or `mkdocs serve`)
```

Without step 1 the static demo ships without data.
