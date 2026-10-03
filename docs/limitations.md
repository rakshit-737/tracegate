# Limitations and roadmap

## Limitations

- **The reference is line blame, and the oracle shares the reader.** Agreement with `git blame` is not correctness; the commit-message oracle is right for TRACEGATE by construction at the labelled commit and tests version tracking under rewrites at later snapshots, not attribution independent of the lock-file reader. Disagreements were adjudicated for a sample only ([Evaluation](evaluation.md)).
- **Only as good as the lock-file reader.** The readers keep every version of a name (yarn, pnpm, package-lock, Cargo, poetry, uv). go.sum is used as published (highest version per module); go.mod is authoritative for Go. Unusual layouts (non-pretty-printed package-lock v2/v3) fall back to a JSON reader without line numbers, so blame and the pickaxes cannot run on them.
- **Static reachability fires only with dependency edges.** Without pip-compile `# via` annotations the gate cannot tell a transitive dependency of an imported package from an unused one, so it no longer downgrades there. An audit of every earlier downgrade found all of them loaded ([Evaluation](evaluation.md)). Dynamic imports, plugins loaded by name from settings and C-extension loading stay invisible, and the sources are written by the PR under review, so static downgrades must not be trusted on untrusted PRs. No eBPF or `/proc/*/maps` runtime collector ships.
- **Keyless signing covers the CI key, not each envelope.** CI signs an ephemeral Ed25519 public key with Sigstore (Fulcio + Rekor) and the gate verifies that bundle with `cosign`; envelopes themselves are Ed25519. The kind admission demo is a gate step before `kubectl apply`, not an in-cluster validating webhook.
- **Warden integration is contract-tested only.** `WardenApiClient` follows the real Warden `POST /api/v1/scans` schema, but no end-to-end run against a live Warden is in CI; offline results use `HeuristicWarden`.
- **Typosquat recall is low in absolute terms** (see the [Evaluation](evaluation.md)). Treat it as one signal, not a malware detector.
- **SAST comes in as SARIF 2.1.0** (`tracegate ingest --sarif`, tested on Bandit-style fixtures). SAST findings are attached to files, not to dependencies, so reachability does not apply to them.
- **Samples and clustering.** The oracle scores at most 40 cases per repository and stratum (uniform random, seed 0); exact bounds treat cases as independent, and repository clustering would widen them. Image deployments in the image benchmark are synthetic (one service per image).

## Roadmap

- eBPF / `sys.modules` runtime collector (needs a Linux runtime; not feasible on the Windows dev machine).
- An in-cluster validating admission webhook.
- Dependency edges from release metadata (or a lock file with a resolved graph) so static reachability can run on manifests without `# via` annotations.
- Sigstore DSSE signing of each envelope (sigstore-python) instead of a Sigstore-bound key.
- Neo4j live adapter (currently Cypher export) and a React lineage explorer.
- EPSS-based prioritisation and a GitHub App for PR comments.

## Prior art

| Work | What it does | TRACEGATE |
| --- | --- | --- |
| Syft | SBOM generation | consumes its unmodified JSON as the build/layer stage |
| Trivy / Grype | per-artifact vuln scanning | attaches findings to shared graph nodes and adds commit lineage and blast radius |
| Sigstore / SLSA / in-toto | attestation formats and verification | emits DSSE + in-toto SLSA statements; its contribution is the queryable graph on top |
| GUAC (OpenSSF) | supply-chain metadata graph | GUAC is a large multi-service aggregator; TRACEGATE is a stdlib-only CI gate with deterministic verdicts and commit-level backtracking |
| Snyk / GitHub Advanced Security | commercial suites | open source, and gives one graph you can query across stages |
| SZZ (Śliwerski, Zimmermann and Zeller, MSR 2005) and its variants: AG-SZZ (Kim et al., ASE 2006) skips cosmetic changes, MA-SZZ (da Costa et al., IEEE TSE 2017) skips meta-changes such as merges | find bug-introducing commits by blaming the lines a fix changed | a different question (which commit introduced a dependency *version*) on lock files, where line blame suffers the same cosmetic and meta-change failures; TRACEGATE compares (package, version) pairs instead of lines. `git blame` and two `git log -S` pickaxes are its line baselines |
| Rosa et al., developer-informed SZZ oracle (ICSE 2021); Lyu et al., SZZ on the Linux kernel (IEEE TSE; arXiv 2308.05060) | evaluate SZZ implementations against labels from developers / commit messages | the bot-bump oracle takes the same approach: labels from commit messages |
| typomania / TypoGard (Taylor et al., NSS 2020), pypi-scan | name similarity | original typomania and TypoGard code run on the same splits in CI (port agreement 98.99-100%); pypi-scan is our port (see [Evaluation](evaluation.md)) |

SBOMs, scanning, attestation formats and line-based attribution are not novel. The contribution is applying version-aware attribution, diffing (package, version) pairs rather than lines, to lock-file history, inside a fail-closed, signature-verified CI gate. Cross-tool identity, reachability and typosquat scoring are supporting components.
