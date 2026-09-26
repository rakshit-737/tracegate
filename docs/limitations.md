# Limitations and roadmap

## Limitations

- **Reachability is static and at module level.** Runtime facts are supported as events, but no eBPF or `/proc/*/maps` collector ships. Historical snapshots in the lineage benchmark use HEAD sources. `gitlineage.materialize()` exists to check out per-snapshot sources, but it is not yet wired into the benchmark.
- **The 15% reduction has no false-negative audit.** There is no public ground truth for "exploitable in this app".
- **Lineage covers `requirements*.txt`, `package-lock.json`, `poetry.lock` and `uv.lock`.** Go modules, Cargo and yarn/pnpm locks are not parsed yet. The real-repo lineage benchmark numbers are for pip manifests only.
- **Signing uses Ed25519 or HMAC keys, not Sigstore keyless.** There is no Rekor transparency log.
- **Warden is a stand-in.** The HTTP contract to the real Warden service (`GET /score`) is assumed.
- **Typosquat recall is low in absolute terms** (see above). Treat it as one signal, not a malware detector.
- **SAST comes in as SARIF 2.1.0** (`tracegate ingest --sarif`, tested on Bandit-style fixtures). SAST findings are attached to files, not to dependencies, so reachability does not apply to them.
- Image deployments in the image benchmark are synthetic (one service per image).

## Roadmap

- Per-snapshot source materialisation in the reachability benchmark; eBPF / `sys.modules` runtime collector.
- Lock-file lineage for Go modules, Cargo and yarn/pnpm.
- Sigstore keyless signing + Rekor inclusion proofs.
- Neo4j live adapter (currently Cypher export) and a React lineage explorer.
- EPSS-based prioritisation and a GitHub App for PR comments.

## Prior art

| Tool | What it does | TRACEGATE |
| --- | --- | --- |
| Syft | SBOM generation | consumes its unmodified JSON as the build/layer stage |
| Trivy / Grype | per-artifact vuln scanning | attaches findings to shared graph nodes and adds commit lineage and blast radius |
| Sigstore / SLSA / in-toto | attestation formats and verification | emits DSSE + in-toto SLSA statements; its contribution is the queryable graph on top |
| GUAC (OpenSSF) | supply-chain metadata graph | GUAC is a large multi-service aggregator; TRACEGATE is a stdlib-only CI gate with deterministic verdicts and commit-level backtracking |
| Snyk / GitHub Advanced Security | commercial suites | open source, and gives one graph you can query across stages |
| typosquat scanners (e.g. Levenshtein-based) | name similarity | benchmarked here against a Levenshtein-1 baseline on real `MAL-*` data |

SBOMs, scanning and attestation formats are not novel. The contribution is the integration: canonical cross-tool identity, finding -> commit backtracking evaluated against git blame, and reachability-aware, fail-closed gating.