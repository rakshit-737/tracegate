# Limitations and roadmap

## Limitations

- **Reachability is static and at module level.** Runtime facts are supported as events, but no eBPF or `/proc/*/maps` collector ships. Per-snapshot source materialisation is available in the lineage benchmark (`--materialize`); dynamic imports, plugins loaded by name from settings, and C-extension loading are still invisible.
- **Reachability reductions have only a manual false-negative audit.** There is no public ground truth for "exploitable in this app"; an audit of the earlier run found packages the apps do load marked `unreached` (fixed rules are listed in the CHANGELOG). Static downgrades must not be trusted on untrusted PRs.
- **Lock-file parsers keep one version per package name.** yarn, pnpm, npm and Cargo locks that hold several versions of one package (7-14% of entries on the real lock files we checked) contribute only one of them, so the others are never matched against OSV or attributed. go.sum is used as published; go.mod is authoritative for Go.
- **Keyless signing covers the CI key, not each envelope.** CI signs an ephemeral Ed25519 public key with Sigstore (Fulcio + Rekor) and the gate verifies that bundle with `cosign`; envelopes themselves are Ed25519. The kind admission demo is a gate step before `kubectl apply`, not an in-cluster validating webhook.
- **Warden integration is contract-tested only.** `WardenApiClient` follows the real Warden `POST /api/v1/scans` schema, but no end-to-end run against a live Warden is in CI; offline results use `HeuristicWarden`.
- **Typosquat recall is low in absolute terms** (see the [Evaluation](evaluation.md)). Treat it as one signal, not a malware detector.
- **SAST comes in as SARIF 2.1.0** (`tracegate ingest --sarif`, tested on Bandit-style fixtures). SAST findings are attached to files, not to dependencies, so reachability does not apply to them.
- Image deployments in the image benchmark are synthetic (one service per image).
- **Bot-bump oracle is a capped convenience sample.** At most 40 bumps per repo are evaluated (warehouse, hugo, bat, excalidraw and mastodon hit the cap); ripgrep and alacritty contribute one case each and netbox none. For a single-package bump the oracle label and TRACEGATE's answer are close to the same event, so the oracle tests version tracking under line rewrites, not attribution when lines are reformatted; multi-package bumps, reverts and re-bumps are not yet in it. The repo-clustered bootstrap for 231/231 is degenerate; the one-sided Clopper-Pearson 95% lower bound is about 98.7%.
- **Pooled 88.8% is an implementation figure.** It includes the one-version-per-name parser limitation above, which depresses vue-core (pnpm) and mastodon (yarn); it is not a pure property of the method.
- **Some result files lack a run id.** `data_manifest.json`, `scale_synthetic.json` and `images_real.json` were generated locally.
- **Docs build is two steps.** Run `python scripts/build_static_demo.py` before `mkdocs build --strict`, or the demo ships without data (docs.yml does this).

## Roadmap

- eBPF / `sys.modules` runtime collector (needs a Linux runtime; not feasible on the Windows dev machine).
- Multi-version lock-file pins and an in-cluster validating admission webhook.
- Sigstore DSSE signing of each envelope (sigstore-python) instead of a Sigstore-bound key.
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
| typomania / TypoGard (Taylor et al., NSS 2020), pypi-scan | name similarity | our ports (not validated against the original code) benchmarked on the same splits (see Evaluation) |

SBOMs, scanning and attestation formats are not novel. The contribution is the integration: canonical cross-tool identity, finding -> commit backtracking evaluated against git blame, and reachability-aware, fail-closed gating.