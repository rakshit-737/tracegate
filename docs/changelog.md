# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.1] - 2026-10-03

### Security
- Scanner findings that match no SBOM node now reach the verdict: rule `unattributed_finding` blocks on HIGH/CRITICAL and warns on the rest (Python DSL and Rego, parity-checked). Before, a CRITICAL CVE on a package missing from the SBOM, or with a differently spelled version, gave PASS. Trivy rows without a PURL are matched by the ecosystem of their result type instead of defaulting to PyPI.
- With `TRACEGATE_API_TOKEN` set, every `/v1` route requires the token (constant-time comparison); before, `/v1/runs/{rid}/graph`, `backtrack`, `blast` and `cypher` were open, and unauthenticated demo calls could evict gate runs. Demo runs now have their own store; the explorer UI sends the token.
- Envelopes with wrongly typed fields (non-string or non-hex `sig`, object `keyid`) are rejected instead of crashing the API (500) or the CLI (exit 2 with no verdict); the CLI gate blocks with the reason.
- SECURITY.md: release verification pinned to `release.yml@refs/tags/vX.Y.Z` (cosign blob and image, `gh attestation verify`).

### Changed (published numbers; several worse)
- Backtracking now reads every version of a package name and pins the repositories to the committed run's commits: agreement with blame 92.4% of 3,969 pairs (old readers on the same data 88.5%; v1.1.0 88.8%).
- The exact-pin pickaxe baseline is now package-specific: it ties TRACEGATE on Cargo and Go, is ahead (on agreement) on pip, and behind on npm with a clustered interval that includes 0. The v1.1.0 Cargo lead (95.0% vs 54.7%) was an artefact of a version-line token; that arm is kept and labelled `version line`.
- The bot-bump oracle is replaced by a commit-message oracle with five strata and checked labels: at later snapshots TRACEGATE 436/436, blame 419/436; at the labelled commit both are right on every case (TRACEGATE by construction). Two v1.1.0 labels were wrong and blame was right on both.
- Reachability: the audit found every downgraded pin loaded, and static downgrades now need recorded dependency edges, so the reduction on the benchmark repositories is 0% (was -5.7%, unaudited).
- Real images re-run in CI with Syft and Trivy on Linux: Trivy finds 511 rows (was 507); Syft's Linux image scan matches Trivy's SBOM more closely (Jaccard 0.94-1.00).
- Synthetic scale latency re-run on the CI runner.

### Added
- Lock-file readers keep every version of a package name (yarn, pnpm, package-lock, Cargo, poetry, uv); `manifest_history` diffs (name, version) pairs; `--single-version` reproduces the old readers.
- Commit-message oracle with five strata (single package, multi-version, grouped, revert, re-bump), a label check with the multi-version reader, two ablations (old readers, no recency rule), exact one-sided bounds and recorded sampling rule.
- Package-specific `git log -S` baseline; exact McNemar tests and paired clustered bootstraps; Wilson and Clopper-Pearson intervals in every results file.
- Adjudication of TRACEGATE-vs-blame disagreements from the diffs (`benchmarks/adjudicate.py`) and an audit of every reachability downgrade (`benchmarks/reach_audit.py`).
- `scripts/render_results.py` renders every result table in README.md and docs/ from `results/*.json`; CI checks the tables and that every run link points at a run a results file carries. Images and scale benchmarks run in CI; the benchmarks workflow runs its legs in parallel and pins the repositories to the committed run's commits (`download_data.py repos --pin-from`).
- How it works: version diff vs line blame, with the mastodon Yarn-4 and bat ansi_term cases.

### Fixed
- Static reachability read only the newer pip-compile `# via` layout, and downgraded pins in manifests without any dependency edges; both produced false `unreached` (all 17 audited pins were loaded). Pins without recorded edges are now `unknown` and never downgraded.
- Binomial tails no longer underflow to p = 0; typosquat bootstrap p-values use (k+1)/(B+1) (the committed typosquat files of run 37003433022 still hold the old values; none is quoted).
- `rekor_evidence.py --help`, `opa_parity.py` fails in CI when `opa` is missing, CONTRIBUTING runs the demo builder once, Windows venv activation and working `serve`/`compose` commands in the docs.

## [1.1.0] - 2026-10-02

Supersedes v1.0.0, whose wheel and image trust the demo key implicitly (fail-open).

### Added
- Independent backtracking oracle from single-package Dependabot/Renovate bumps (`results/lineage_bot_bump_oracle.json`): TRACEGATE 231/231 at later snapshots, `git blame` 219/231, exact-pin pickaxe 197/231; repo-clustered bootstrap intervals for all lineage figures.
- The original TypoGard script and the original typomania binary run on the same typosquat splits in the benchmarks workflow (`results/typosquat_originals.json`); our typomania port agrees on 99.97-100% of names.
- kind admission demo adds a cosign-valid image with incomplete signed provenance, denied by the TRACEGATE gate itself.
- Sigstore CI builds use a `.post0.devN+g<sha>` version; the benchmark result JSONs written by the benchmarks, kind-admission and sigstore workflows record the Actions run that produced them (`data_manifest.json`, `images_real.json` and `scale_synthetic.json` did not; corrected after the release).
- Lock-file lineage for yarn.lock, pnpm-lock.yaml, go.mod/go.sum and Cargo.lock.
- CI: Sigstore keyless signing with Rekor checks, a kind cluster admission job, signed-pipeline e2e, wheel/sdist/Docker jobs, Python 3.10-3.14 plus Windows.
- Typosquat comparison with re-implementations of typomania/TypoGard and pypi-scan, a time split, more ecosystems and precision at realistic prevalence.
- Exact-pin pickaxe baseline and Wilson intervals in the lineage benchmark.

### Security
- The gate fails closed when no trust root is configured (CLI exit 2, API 503); the public demo key needs `--demo` / `TRACEGATE_DEMO=1`.
- The API verifies Ed25519 envelopes (`TRACEGATE_PUBKEY`), caps request bodies and envelope counts, and supports an optional bearer token.
- Keyless trust: an Ed25519 key is trusted only through a verified Sigstore bundle bound to a workflow identity.
- ReDoS-free pin regexes; `materialize()` refuses path-traversal tree entries; MAL range matching fails closed and uses SemVer outside PyPI.

### Changed (published numbers, several worse)
- Backtracking evaluated on 11 repos and 4 ecosystems: 88.8% agreement with blame (was 97.5% on 3 pip repos). A new exact-pin `git log -S` baseline reaches 100% on pip and Go, so the old 17.3% "best baseline" understated the competition; TRACEGATE leads only on Cargo and npm lock files.
- Reachability reduction after the false-unreached audit: -10.3% (HEAD sources) and -5.7% (own sources), down from -15.1% / -25.8%.
- Typosquat tables now include typomania/TypoGard and pypi-scan re-implementations, five ecosystems, a time split and precision at 1% prevalence.

### Fixed
- Release notes extraction, duplicate `latest` tag, sdist missing test fixtures.
- Audited false-`unreached` reachability cases (pycrypto, paramiko/ncclient/readme_renderer/alembic dependencies, Django ImageField -> Pillow).

## [1.0.0] - 2026-09-26

### Added
- **SARIF 2.1.0 adapter** (`tracegate ingest --sarif`) for Semgrep, Bandit, CodeQL and other SAST tools;
  severity from `security-severity` or the SARIF level.
- **Lock-file lineage**: `tracegate lineage` now walks `package-lock.json` (v1-v3), `poetry.lock` and
  `uv.lock` history, with the npm ecosystem set on commit events.
- **Per-snapshot reachability** in the lineage benchmark (`--materialize`): each historical snapshot is
  analysed against its own sources and config/CI entrypoints.
- **Bootstrap confidence intervals** (seeded, stratified, 1,000 resamples) and paired F1 differences
  in the typosquat benchmark.
- **Docs site** (MkDocs Material) on GitHub Pages with a static, server-free lineage-explorer demo.
- **Release workflow**: tagged builds push `ghcr.io/rakshit-737/tracegate` and attach wheel/sdist.

### Changed
- Reachability headline now reports both runs: -15.1% actionable with HEAD sources, -25.8% with
  per-snapshot sources. Typosquat point estimates re-ran unchanged; CIs added.

## [0.2.0] - 2026-09-26

Real-data release: TRACEGATE now ingests unmodified output from real Syft/Trivy runs,
walks real git history, and is benchmarked on public datasets instead of synthetic events.

### Added
- **Ingest adapters** for raw Syft JSON, CycloneDX JSON and Trivy JSON (`tracegate ingest`).
- **Canonical purl identities**: Syft, Trivy and manifest pins for the same package converge
  on one graph node (qualifiers dropped, names normalised per ecosystem, memoised).
- **Git lineage collector** (`tracegate lineage`): emits signed `commit` events from the
  first-parent history of a pinned manifest, following renames, with PR numbers parsed from
  commit subjects.
- **Offline OSV index** over the official bulk dumps (PyPI, npm, Alpine) with ECOSYSTEM/SEMVER
  range matching and CVSS v3 base-score computation.
- **Multi-technique typosquat detector** (edit distance via deletion index, Damerau
  transpositions, separator/homoglyph/suffix/combosquat/brandjack checks) and a `HeuristicWarden`
  that combines it with OSV `MAL-*` records; `MultiWarden` routes by ecosystem.
- **Static reachability** fallback: app imports (AST), dotted/bare string references,
  entrypoints (Dockerfile, Procfile, CI/config), implied framework dependencies, and pip-compile
  `# via` propagation. Unreached findings are downgraded block -> warn with evidence.
- **Ed25519 DSSE signing**, standard DSSE JSON envelopes and in-toto v1 / SLSA provenance
  statements (`tracegate keygen`, `tracegate export --format intoto`).
- **Neo4j Cypher export** and an **OPA/Rego port** of the gate policy with a CI parity job.
- **FastAPI service** (`tracegate serve`) with a dependency-free lineage explorer UI.
- **Dockerfile + docker-compose** demo stack (API + Neo4j).
- **Data and benchmark scripts**: checksum-verified downloads, a daemon-free registry puller,
  a real Syft/Trivy scan driver, and four benchmarks (typosquat, lineage, images, scale).
- Docs: ADRs 0001-0005, CONTRIBUTING, this changelog.

### Fixed
- OSV malicious-package lookups are now version-aware. Account-takeover advisories such as the
  Sept-2025 npm `chalk`/`debug` hijack list only the trojanised releases; matching on the name
  alone flagged 13 clean packages in the real `node:14` image.
- Lineage benchmark blames the manifest path each snapshot actually had after a rename.
- Windows scans keep long `node_modules` paths (extended-length prefix), so Syft sees npm
  packages in image layers; layer symlinks are materialised and apk purls rebuilt.

## [0.1.0] - 2026-09-20

### Added
- MVP: typed stage events, content-addressed IDs, HMAC-signed envelopes with fail-closed
  collector, in-memory provenance DAG, Python policy DSL, backtracker and blast radius,
  synthetic event generator, six demo scenarios, CLI and CI workflow.
