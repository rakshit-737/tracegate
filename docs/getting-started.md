# Getting started

```bash
git clone https://github.com/rakshit-737/tracegate-cicd-security-gate && cd tracegate-cicd-security-gate
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate (Git Bash: . .venv/Scripts/activate)
pip install -e ".[dev]"            # the core gate is stdlib-only; extras add crypto/osv/api
python -m pytest -q                # about 100 tests; real-data tests skip without datasets
python -m tracegate.cli demo       # the six spec scenarios
```

Gate a real image scan with Ed25519-signed provenance:

```bash
tracegate keygen ~/.tracegate/ci
export TRACEGATE_KEYID=ci TRACEGATE_SIGNING_KEY=~/.tracegate/ci.key TRACEGATE_PUBKEY=~/.tracegate/ci.pub
syft  <image> -o syft-json=sbom.json
trivy image --format json -o trivy.json <image>
tracegate ingest --syft sbom.json --trivy trivy.json --commit $(git rev-parse HEAD) -o img.json
tracegate lineage . requirements.txt -o commits.json       # commit -> dependency lineage
tracegate merge commits.json img.json -o events.json
tracegate gate events.json --comment                        # exit 1 on block
tracegate backtrack events.json CVE-2023-0465
tracegate export events.json --format intoto > provenance.intoto.json
tracegate export events.json --format cypher | cypher-shell -u neo4j -p ...
```

Service and UI: `tracegate --demo serve` starts the API with the lineage explorer at http://127.0.0.1:8080 and the built-in scenarios (public demo key). For a real gate give it a trust root, for example `TRACEGATE_KEYID=ci TRACEGATE_PUBKEY=~/.tracegate/ci.pub tracegate serve`; with no trust root it refuses to start (exit 2). Set `TRACEGATE_API_TOKEN` before exposing it beyond localhost. `NEO4J_PASSWORD=... TRACEGATE_PUBKEY_FILE=~/.tracegate/ci.pub docker compose up --build` adds Neo4j (localhost-only ports); compose refuses to start without `NEO4J_PASSWORD`.

Demo scenarios (these follow the spec):

| Scenario | Outcome |
| --- | --- |
| `clean` | pass; also prints the base-layer blast radius |
| `malicious-dep` | typosquat blocked, with the commit -> dependency path |
| `cve-origin` | reachable CVE blocked; the origin story names PR #42 and 3 services |
| `unreachable` | critical CVE in a module that is never loaded -> warn |
| `tampered` | forged scan attestation -> block (fail closed) |
| `unsigned-missing` | missing stage -> block |

## SAST (SARIF)

Any SARIF 2.1.0 producer works (Semgrep, Bandit `-f sarif`, CodeQL):

```bash
bandit -r app -f sarif -o bandit.sarif
tracegate ingest --sarif bandit.sarif --commit $(git rev-parse HEAD) -o sast.json
```

Severity comes from `security-severity` when present (CVSS bands), otherwise from the SARIF level (error=high, warning=medium, note=low).

## Lock files

`tracegate lineage` understands `requirements*.txt`, `poetry.lock`, `uv.lock`, `package-lock.json` (v1-v3), `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` (v5-v9), `go.mod` / `go.sum` and `Cargo.lock`, chosen by file name. It exits 2 if the manifest has no pinned history:

```bash
tracegate lineage path/to/app-repo package-lock.json -o npm-commits.json
```

## Reproducibility

Every benchmark command, its output file and its runtime on the GitHub runner are on the [Reproduce](reproduce.md) page. The short version:

```bash
python scripts/download_data.py osv && python scripts/download_data.py popular
python scripts/download_data.py repos --pin-from results/data_manifest.json
python benchmarks/lineage_eval.py --snapshots 12            # backtracking
python benchmarks/lineage_eval.py --oracle-only             # commit-message oracle
python scripts/render_results.py --write                    # re-render the tables in README.md and docs/
```

OSV dumps, popularity lists and the Trivy DB are live feeds, so a re-run on a later date can shift finding counts and typosquat numbers; the sha256 of what each run used is in its `results/data_manifest*.json`.

Evaluation design, including the splits, the references and why download counts are *not* used as a typosquat feature, is in [ADR 0005](adr/0005-real-data-evaluation-design.md).
