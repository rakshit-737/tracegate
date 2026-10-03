# Security Policy

TRACEGATE is a portfolio and research MVP. Do not rely on it as your only supply-chain control.

- **Reporting:** use GitHub private vulnerability reporting (Security tab -> "Report a vulnerability") on this repository. Please do not file public issues for vulnerabilities.
- **Supported versions:** the latest release (currently v1.1.1) and `main`. v1.0.0 is superseded: it trusts the public demo key implicitly (fail-open).
- **Keys:** the demo key in `tracegate/synth.py` is public and is for demos only. The gate never trusts it unless you pass `--demo` or set `TRACEGATE_DEMO=1`. For real gates set `TRACEGATE_PUBKEY` (Ed25519), use keyless mode (`TRACEGATE_PUBKEY_BUNDLE` + `TRACEGATE_SIGSTORE_IDENTITY`), or set `TRACEGATE_KEY` from a CI secret.
- **Scope:** the tool is defensive. It analyses metadata that your own pipeline emits. It has no scanning or exploitation capability against external systems.

## Verifying a release

Since v1.1.0 the wheel, sdist, `SHA256SUMS` and the container image are keyless-signed with Sigstore by the `release` workflow (GitHub OIDC) and carry build-provenance attestations. Pin the signer to the release workflow at that tag; a looser identity such as `^https://github.com/rakshit-737/tracegate-cicd-security-gate/` would also accept the dev builds that the `sigstore` and `kind-admission` workflows sign on `main`.

```bash
V=1.1.1
ID="https://github.com/rakshit-737/tracegate-cicd-security-gate/.github/workflows/release.yml@refs/tags/v$V"
ISSUER=https://token.actions.githubusercontent.com

# Python artefacts (download the file and its .sigstore.json from the GitHub release)
cosign verify-blob --bundle "tracegate-$V-py3-none-any.whl.sigstore.json" \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" "tracegate-$V-py3-none-any.whl"

# Container image
cosign verify "ghcr.io/rakshit-737/tracegate-cicd-security-gate:$V" --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"

# Build-provenance attestations (wheel, sdist or image)
gh attestation verify "tracegate-$V-py3-none-any.whl" -R rakshit-737/tracegate-cicd-security-gate \
  --signer-workflow rakshit-737/tracegate-cicd-security-gate/.github/workflows/release.yml
gh attestation verify "oci://ghcr.io/rakshit-737/tracegate-cicd-security-gate:$V" -R rakshit-737/tracegate-cicd-security-gate \
  --signer-workflow rakshit-737/tracegate-cicd-security-gate/.github/workflows/release.yml
```

To accept any future release, use `--certificate-identity-regexp '^https://github\.com/rakshit-737/tracegate-cicd-security-gate/\.github/workflows/release\.yml@refs/tags/v'` instead of `--certificate-identity`.
