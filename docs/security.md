# Security Policy

TRACEGATE is a portfolio and research MVP. Do not rely on it as your only supply-chain control.

- **Reporting:** use GitHub private vulnerability reporting (Security tab -> "Report a vulnerability") on this repository. Please do not file public issues for vulnerabilities.
- **Keys:** the demo key in `tracegate/synth.py` is public and is for demos only. The gate never trusts it unless you pass `--demo` or set `TRACEGATE_DEMO=1`. For real gates set `TRACEGATE_PUBKEY` (Ed25519), use keyless mode (`TRACEGATE_PUBKEY_BUNDLE` + `TRACEGATE_SIGSTORE_IDENTITY`), or set `TRACEGATE_KEY` from a CI secret.
- **Scope:** the tool is defensive. It analyses metadata that your own pipeline emits. It has no scanning or exploitation capability against external systems.
- **Release artefacts:** from the next release on, the wheel, sdist and container image are keyless-signed with Sigstore (GitHub OIDC) and carry build-provenance attestations; verify with `cosign verify-blob --bundle <file>.sigstore.json --certificate-identity-regexp '^https://github.com/rakshit-737/tracegate/' --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>`.
- **Supported versions:** only the latest `main`.
