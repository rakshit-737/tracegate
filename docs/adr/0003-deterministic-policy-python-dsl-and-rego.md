# ADR 0003: Deterministic policy in a Python DSL, mirrored in Rego

- Status: accepted
- Date: 2026-09-26

## Context

The gate decision has to be auditable and reproducible. The spec rules out an LLM in the decision
path. OPA/Rego is the industry default for policy-as-code, but OPA is a Go binary that the core
package should not require.

## Decision

The rules live in `tracegate/policy.py` as small generator functions. Each yields
`(verdict, reason)`, and every reason carries the graph path (commit to dependency to ...) that
triggered it. The same rules are ported to `policies/tracegate.rego` and evaluated over
`tracegate export --format opa`. CI installs OPA and checks that the two engines agree on every
demo scenario.

Scores (Warden risk, typosquat score, EPSS in future) are only ever inputs to thresholds in the
rules. They never produce a verdict directly.

## Consequences

- Rules are unit-testable in Python with no extra runtime.
- Keeping two implementations in sync costs effort. The CI parity check keeps that honest.
