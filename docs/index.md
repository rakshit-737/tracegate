# TRACEGATE

**TRACEGATE attributes every scanner finding to the commit and PR that introduced the vulnerable version by version-aware diffing of lock-file history, inside a fail-closed, signature-verified CI gate: 88.8% agreement with `git blame` across 11 repos and 4 ecosystems; on Cargo and npm lock files it is far closer to blame than an exact-pin `git log -S` pickaxe (95.0% vs 54.7%, 83.9% vs 70.6%), and on pip and Go the pickaxe ties.** [Evaluation](evaluation.md)

[![Lineage explorer after backtracking CVE-2020-14343](img/demo.png)](demo/index.html)

**TRACEGATE is a provenance-aware CI/CD security gate.** It merges real Syft SBOMs, Trivy scans, git history and OSV data into one signed, content-addressed provenance graph. It can then answer the question most scanners leave open: *which commit, and which PR, put this CVE in production, and what else inherits it?*

- **Gate.** Every PR gets a deterministic pass/warn/block verdict. Each reason is the graph path that produced it (commit -> dependency -> layer -> image -> service).
- **Backtrack.** Takes a CVE or package and returns the commit, PR, author and build that introduced it.
- **Blast radius.** Lists every image, service and container that inherits a vulnerable dependency or base layer.
- **Reachability triage.** A critical CVE in a package the app never imports or loads is downgraded from block to warn, with the evidence attached.
- **Fail closed.** The gate blocks on an unsigned, forged or tampered attestation and on a missing required stage, and refuses to run with no trust root configured.

[Try the static demo](demo/index.html){ .md-button .md-button--primary } [Getting started](getting-started.md){ .md-button } [Evaluation](evaluation.md){ .md-button }

## Headline results

| Result | Value |
| --- | --- |
| Backtrack agreement with `git blame`, 3,203 pairs, 11 repos | 88.8% [Wilson 87.7-89.8, ignores clustering]; Cargo 95.0% vs 54.7% and npm 83.9% vs 70.6% for exact-pin `git log -S`; on pip and Go the pickaxe is slightly better (100% vs 97.8% / 99.7%); repo-clustered bootstrap 79.0-97.5 |
| Backtrack vs an independent oracle (231 bot single-package bumps, later snapshots) | 100% (blame 94.8%, exact-pin `git log -S` 85.3%) |
| High/critical findings left actionable after reachability | -5.7% (each snapshot against its own sources); the remaining downgrades are unaudited |
| Typosquat F1, PyPI | 0.133 dev-tuned / 0.153 FPR-matched vs 0.147 Damerau-1, 0.125 and 0.112 for our ports of typomania/TypoGard and pypi-scan (low recall for all) |
| Signing and admission | keyless Sigstore signing with Rekor checks in CI; kind cluster admits only the signed image |

## At a glance

| Aspect | Details |
| --- | --- |
| Inputs | Syft JSON / CycloneDX, Trivy JSON, SARIF 2.1.0, git history of pip, poetry, uv, npm, yarn, pnpm, Go and Cargo lock files, OSV bulk dumps |
| Output | pass / warn / block verdict with the graph path behind each reason, PR comment, exit code |
| Trust | DSSE envelopes signed with Ed25519, HMAC, or a Sigstore-bound CI key; unsigned, tampered or missing stages block, and no trust root means no gate |
| Core deps | Python standard library only; extras add crypto, OSV range matching, FastAPI, Neo4j |

Safety: TRACEGATE is a defensive, lab-only tool. It reads pipeline metadata you produce; images are unpacked as data and never executed.
