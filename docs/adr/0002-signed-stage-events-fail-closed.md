# ADR 0002: DSSE-signed stage events, fail closed

- Status: accepted
- Date: 2026-09-26

## Context

If an attacker can forge or remove provenance, the graph cannot be trusted. The SLSA threat model
lists tampering with build output and forging attestations as core threats.

## Decision

- Each CI stage emits a `StageEvent` wrapped in a DSSE envelope. The signature covers the DSSE v1
  pre-authentication encoding (PAE), so the payload type is bound to the signature.
- There are two signers behind one verifier. HMAC-SHA256 needs no extra dependency. Ed25519, via
  the optional `cryptography` package, is asymmetric: the gate holds only public keys and so cannot
  forge provenance itself.
- Envelopes round-trip through the standard DSSE JSON form. Build payloads can also be emitted as
  in-toto v1 Statements with a SLSA provenance v1 predicate, for use with other tooling.
- The gate blocks when an envelope fails verification, a keyid is unknown, a required stage
  (`commit`, `build`, `scan`) is missing, or a deploy references an image that has no build
  provenance.

## Consequences

- Stripping the scan stage to hide findings blocks the gate. So does replaying a tampered scan.
- Replay of an old but validly signed event is not yet detected. Binding events to a run nonce is on
  the roadmap.
- Real Sigstore keyless signing (Fulcio/Rekor) is out of scope. The envelope format was chosen so
  that cosign-produced DSSE can be accepted later without changing the graph code.
