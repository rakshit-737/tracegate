# Threat Model

## Assets
- The integrity of the provenance graph. Every gate decision and every backtrack depends on it.
- The signing keys. In the MVP this is the HMAC key; in the target design it is the cosign/Sigstore identity.
- The CI pipeline and the gate verdict (its exit code).

## Attackers modelled
| Threat | Mitigation in MVP |
| --- | --- |
| Malicious or typosquatted dependency | The Warden score produces a `malicious_dependency` block, and the reason includes the commit path |
| Tampered build or scan output | Every stage event is signed (DSSE PAE + HMAC-SHA256). A signature mismatch blocks the gate |
| Forged attestation from an untrusted signer | Only trusted `keyid`s are accepted. An unknown key is rejected and the gate blocks |
| Stripping a stage to hide findings | Required stages (`commit`, `build`, `scan`) must all be present, otherwise the gate blocks (fail closed) |
| Deploying an image with no build provenance | The deploy is rejected, which is a provenance_integrity block |
| Using reachability to hide a vuln | A finding is only downgraded when runtime facts exist and show the module is not loaded. Unknown reachability is treated as reachable |
| Graph poisoning via cycles | The DAG rejects cycle-creating edges |

## Trust boundaries
- CI runner to collector: only signed envelopes cross this boundary.
- Warden to TRACEGATE: Warden is treated as advisory input. It can only raise severity, never clear a finding.
- The policy is deterministic Python. No ML or LLM is involved in the decision.

## Known weaknesses (MVP)
- HMAC uses a shared symmetric key, so anyone holding the verify key can also sign. Moving to asymmetric keys (cosign) is required for real use.
- There is no replay protection across runs yet. `run_id` binding and nonces or timestamps are TODO.
- Runtime `loaded_modules` facts are self-reported by the signer. An attacker who controls the runtime key could use them to suppress findings.
- Only the stages in `REQUIRED_STAGES` are enforced. `deploy` and `runtime` are optional.
