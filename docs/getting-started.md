# Getting started

```bash
git clone https://github.com/rakshit-737/tracegate && cd tracegate
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

`make` is optional. Each target is a single command:

```bash
python scripts/download_data.py all      # make data   (OSV, popularity lists, tools, repos)
trivy image --download-db-only --cache-dir <data>/trivy-cache   # Trivy vuln DB (not fetched by the script)
python scripts/scan_real.py all          # make scans  (real Syft + Trivy over images and repos)
python benchmarks/typosquat_eval.py      # -> results/typosquat_{pypi,npm}.json, typosquat_pr.png
python benchmarks/lineage_eval.py --snapshots 12   # -> results/lineage_real_repos.json
python benchmarks/images_eval.py         # -> results/images_real.json
python benchmarks/scale_eval.py          # -> results/scale_synthetic.json
python -m pytest -q -m realdata          # real-data tests (need the datasets)
```

OSV dumps, popularity lists and the Trivy DB are live feeds, so a re-run on a later date can shift finding counts and typosquat numbers; the sha256 of what was used is in `results/data_manifest.json`. Re-running `images_eval.py` on the same data reproduced every count in `results/images_real.json` exactly (only latency changed).

Evaluation design, including the splits, ground truth and why download counts are *not* used as a typosquat feature, is in [ADR 0005](adr/0005-real-data-evaluation-design.md).