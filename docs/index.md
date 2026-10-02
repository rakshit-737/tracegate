# TRACEGATE

**TRACEGATE attributes every scanner finding to the commit and PR that introduced the vulnerable version by version-aware diffing of lock-file history, inside a fail-closed, signature-verified CI gate: 88.8% agreement with `git blame` across 11 repos and 4 ecosystems, and 95.0% vs 54.7% for an exact-pin `git log -S` on Cargo lock files.** [Evaluation](evaluation.md)

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
| Backtrack agreement with `git blame`, 3,205 pairs, 11 repos | 88.8% [87.7-89.8]; Cargo 95.0% vs 54.7% and npm 83.9% vs 70.6% for exact-pin `git log -S`; pip and Go tie near 100% |
| High/critical findings left actionable after reachability | -10.2% (HEAD sources), -5.7% (per-snapshot sources), after an audit that removed false "unreached" cases |
| Typosquat F1, PyPI | 0.153 vs 0.147 Damerau-1, 0.125 typomania/TypoGard, 0.112 pypi-scan (low recall for all) |
| Signing and admission | keyless Sigstore signing with Rekor checks in CI; kind cluster admits only the signed image |

## At a glance

| Aspect | Details |
| --- | --- |
| Inputs | Syft JSON / CycloneDX, Trivy JSON, SARIF 2.1.0, git history of pip, poetry, uv, npm, yarn, pnpm, Go and Cargo lock files, OSV bulk dumps |
| Output | pass / warn / block verdict with the graph path behind each reason, PR comment, exit code |
| Trust | DSSE envelopes signed with Ed25519, HMAC, or a Sigstore-bound CI key; unsigned, tampered or missing stages block, and no trust root means no gate |
| Core deps | Python standard library only; extras add crypto, OSV range matching, FastAPI, Neo4j |

Safety: TRACEGATE is a defensive, lab-only tool. It reads pipeline metadata you produce; images are unpacked as data and never executed.
