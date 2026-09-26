# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
