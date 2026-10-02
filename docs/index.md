# TRACEGATE

**TRACEGATE is a provenance-aware CI/CD security gate.** It merges real Syft SBOMs, Trivy scans, git history and OSV data into one signed, content-addressed provenance graph. It can then answer the question most scanners leave open: *which commit, and which PR, put this CVE in production, and what else inherits it?*

- **Gate.** Every PR gets a deterministic pass/warn/block verdict. Each reason is the graph path that produced it (commit -> dependency -> layer -> image -> service).
- **Backtrack.** Takes a CVE or package and returns the commit, PR, author and build that introduced it.
- **Blast radius.** Lists every image, service and container that inherits a vulnerable dependency or base layer.
- **Reachability triage.** A critical CVE in a package the app never imports or loads is downgraded from block to warn, with the evidence attached.
- **Fail closed.** The gate blocks on an unsigned, forged or tampered attestation, and on a missing required stage.

[Try the static demo](demo/index.html){ .md-button .md-button--primary } [Getting started](getting-started.md){ .md-button } [Evaluation](evaluation.md){ .md-button }

## At a glance

| | |
| --- | --- |
| Inputs | Syft JSON / CycloneDX, Trivy JSON, SARIF 2.1.0, git history of `requirements*.txt`, `package-lock.json`, `poetry.lock`, `uv.lock`, OSV bulk dumps |
| Output | pass / warn / block verdict with the graph path behind each reason, PR comment, exit code |
| Trust | DSSE envelopes signed with Ed25519 or HMAC; unsigned, tampered or missing stages block |
| Core deps | Python standard library only; extras add crypto, OSV range matching, FastAPI, Neo4j |

Safety: TRACEGATE is a defensive, lab-only tool. It reads pipeline metadata you produce; images are unpacked as data and never executed.
