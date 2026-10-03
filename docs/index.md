# TRACEGATE

**Which commit, and which PR, put this CVE in production?** TRACEGATE answers from the lock-file history, inside a signed, fail-closed CI gate.

**Contribution.** TRACEGATE applies version-aware attribution to lock-file history: it credits each scanner finding to the commit whose diff introduced that exact (package, version) pair, not to whoever last rewrote the line, and it does this inside a fail-closed gate that verifies signed provenance for every pipeline stage. ([How it works](how-it-works.md#7-version-diff-vs-line-blame) · [Evaluation](evaluation.md))

<!-- results:hero -->
| | |
| --- | --- |
| **Agreement with `git blame`** | 92.4% of 3,969 vulnerable (snapshot, pin) pairs in 11 repos and 4 ecosystems (one-version-per-name readers on the same data: 88.5%); a package-specific `git log -S` pickaxe: 89.6%. Blame shares the lock-file reader, so this is agreement, not correctness. |
| **Commit-message oracle** | At the labelled commit TRACEGATE is right on 458/458 by construction, as is `git blame` (458/458). At the last later snapshot still pinning the version: TRACEGATE 436/436 (one-sided 95% exact lower bound 99.3%), `git blame` 419/436 (96.1%). The oracle tests version tracking under line rewrites, not attribution independent of the lock-file reader. |
| **Typosquat (PyPI, supporting signal)** | F1 0.133 at the dev-tuned threshold, 0.153 FPR-matched, vs Damerau-1 0.147; recall is low for every detector. |

Backtracking: run [37091106360](https://github.com/rakshit-737/tracegate/actions/runs/37091106360); oracle: run [37091106360](https://github.com/rakshit-737/tracegate/actions/runs/37091106360); typosquat: run [37003433022](https://github.com/rakshit-737/tracegate/actions/runs/37003433022).
<!-- /results:hero -->

[![Lineage explorer after backtracking CVE-2020-14343](img/demo.png)](demo/index.html)

**TRACEGATE is a provenance-aware CI/CD security gate.** It merges real Syft SBOMs, Trivy scans, git history and OSV data into one signed, content-addressed provenance graph. It can then answer the question most scanners leave open: *which commit, and which PR, put this CVE in production, and what else inherits it?*

- **Gate.** Every PR gets a deterministic pass/warn/block verdict. Each reason is the graph path that produced it (commit -> dependency -> layer -> image -> service).
- **Backtrack.** Takes a CVE or package and returns the commit, PR, author and build that introduced it.
- **Blast radius.** Lists every image, service and container that inherits a vulnerable dependency or base layer.
- **Reachability triage.** A critical CVE in a package the app never imports or loads is downgraded from block to warn, with the evidence attached, but only when the manifest records dependency edges (pip-compile `# via`).
- **Fail closed.** The gate blocks on an unsigned, forged, tampered or malformed attestation, on a missing required stage and on a HIGH/CRITICAL scanner finding it cannot attribute to an SBOM node, and refuses to run with no trust root configured.

[Try the static demo](demo/index.html){ .md-button .md-button--primary } [Getting started](getting-started.md){ .md-button } [Evaluation](evaluation.md){ .md-button }

## Headline results

<!-- results:index-headline -->
| Result | Value |
| --- | --- |
| Agreement with `git blame`, 3,969 (snapshot, vulnerable pin) pairs, 11 repos | 92.4% [Wilson 91.5-93.2, ignores clustering; repo-clustered 82.7-99.5]; package-specific `git log -S` 89.6% |
| Commit-message oracle, at the labelled commit | TRACEGATE 458/458 (by construction) vs `git blame` 458/458 |
| Commit-message oracle, later snapshots | TRACEGATE 436/436 (one-sided 95% exact >= 99.3%) vs `git blame` 419/436 (96.1%) |
<!-- /results:index-headline -->

The oracle at the labelled commit is right for TRACEGATE by construction (the label check is its own criterion); the informative points are later snapshots, the old-reader ablation and reverts. Static reachability no longer downgrades without recorded dependency edges, after an audit found every earlier downgrade loaded. Signing and admission: keyless Sigstore signing with Rekor checks in CI; the kind cluster admits only the image with a valid signature and complete signed provenance. Details and every interval: [Evaluation](evaluation.md).

## At a glance

| Aspect | Details |
| --- | --- |
| Inputs | Syft JSON / CycloneDX, Trivy JSON, SARIF 2.1.0, git history of pip, poetry, uv, npm, yarn, pnpm, Go and Cargo lock files, OSV bulk dumps |
| Output | pass / warn / block verdict with the graph path behind each reason, PR comment, exit code |
| Trust | DSSE envelopes signed with Ed25519, HMAC, or a Sigstore-bound CI key; unsigned, tampered or missing stages block, and no trust root means no gate |
| Core deps | Python standard library only; extras add crypto, OSV range matching, FastAPI, Neo4j |

Safety: TRACEGATE is a defensive, lab-only tool. It reads pipeline metadata you produce; images are unpacked as data and never executed.
