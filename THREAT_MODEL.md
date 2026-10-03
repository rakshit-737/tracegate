# Threat Model

## Assets
- The integrity of the provenance graph. Every gate decision and every backtrack depends on it.
- The trust roots: an Ed25519 public key (`TRACEGATE_PUBKEY`), an HMAC secret (`TRACEGATE_KEY`), or an ephemeral Ed25519 key bound to a CI workflow identity by a Sigstore keyless bundle (`TRACEGATE_PUBKEY_BUNDLE` + `TRACEGATE_SIGSTORE_IDENTITY`).
- The CI pipeline and the gate verdict (its exit code).

## Attackers modelled
| Threat | Mitigation |
| --- | --- |
| Malicious or typosquatted dependency | The Warden score produces a `malicious_dependency` block, and the reason includes the commit path |
| Tampered build or scan output | Every stage event is a DSSE envelope (PAE + Ed25519 or HMAC-SHA256). A signature mismatch rejects the envelope and the gate blocks |
| Forged attestation from an untrusted signer | Only configured `keyid`s are accepted. An unknown key is rejected and the gate blocks |
| Misconfigured gate with no trust root | The CLI exits 2 and the API answers 503. The public demo key is trusted only with `--demo` / `TRACEGATE_DEMO=1`, and a warning is printed |
| Stolen or long-lived signing key | Keyless mode: CI generates a one-run Ed25519 key and signs its public key with cosign (GitHub OIDC -> Fulcio certificate -> Rekor entry). The gate trusts the key only after `cosign verify-blob` checks the workflow identity and the transparency-log entry |
| Stripping a stage to hide findings | Required stages (`commit`, `build`, `scan`) must all be present, otherwise the gate blocks (fail closed) |
| Hiding a finding by leaving its package out of the SBOM (or spelling its version differently) | A scanner finding that matches no SBOM node is kept as a policy input: rule `unattributed_finding` blocks on HIGH/CRITICAL and warns on the rest, and the PR comment, CLI JSON and API summary list it. Rows without a PURL are matched by (ecosystem from the Trivy result type, name, version) |
| Malformed or wrongly typed envelopes | Non-string fields or a non-hex signature are rejected (`envelope[i]: malformed`), never a crash: the API answers 422 and the CLI gate blocks with the reason |
| Deploying an unsigned image | `kind-admission` CI job: an image is applied to the cluster only if `cosign verify` succeeds against the workflow identity and `tracegate gate` passes on its signed events |
| Using reachability to hide a vuln | Static analysis can mark a package `unreached`, which downgrades a block to a warn; it never suppresses the finding. Runtime facts, when present, override static results. Static analysis is evadable (computed imports such as `importlib.import_module("ya" + "ml")` look unreached), and the sources it reads are written by the PR under review, so do not rely on static downgrades for untrusted PRs. Known false-`unreached` cases are listed in ADR 0004 and the results JSON |
| Graph poisoning via cycles | The DAG rejects cycle-creating edges |
| Oversized or unauthenticated API requests | Bodies over 10 MB (configurable) get 413, more than 5,000 envelopes get 413. With `TRACEGATE_API_TOKEN` set, every `/v1` route (gate, runs, `runs/{rid}/*`, demo) requires the bearer token, compared in constant time; demo runs have their own store, so they cannot evict gate runs |
| Crafted repository trees during benchmarking | `materialize()` refuses tree paths with `..`, `.git`, absolute or drive components and checks that each target stays under the destination |

## Trust boundaries
- CI runner to collector: only signed envelopes cross this boundary.
- Warden to TRACEGATE: Warden is treated as advisory input. It can only raise severity, never clear a finding.
- The policy is deterministic Python (with a Rego port checked for parity in CI). No ML or LLM is involved in the decision.

## Known weaknesses
- HMAC uses a shared symmetric key, so anyone holding the verify key can also sign. Prefer Ed25519 or keyless mode.
- There is no replay protection across runs. A signed scan from an older run is accepted, and the scan stage is not yet bound to the digest of the image the build produced.
- Runtime `loaded_modules` facts are self-reported by the signer. An attacker who controls the runtime key could use them to suppress findings.
- Only the stages in `REQUIRED_STAGES` are enforced. `deploy` and `runtime` are optional.
- The kind admission demo is a CI gate step in front of `kubectl apply`, not an in-cluster validating webhook.
- A scanner that omits a finding altogether is out of scope: the gate can only judge what the signed scan reports. A row without a PURL whose (ecosystem, name, version) matches several SBOM nodes is treated as unattributed (and blocks if HIGH/CRITICAL) rather than guessed.
- With no `TRACEGATE_API_TOKEN` the API is open to anyone who can reach it; it binds to 127.0.0.1 by default and run ids are 48-bit random, but set a token before exposing it.
