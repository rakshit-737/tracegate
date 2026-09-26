# ADR 0001: Content-addressed identity keyed on canonical purls

- Status: accepted
- Date: 2026-09-26

## Context

Every tool describes the same artifact differently. Syft reports
`pkg:apk/alpine/busybox@1.33.1-r3?arch=x86_64&upstream=busybox&distro=alpine-3.14.2`, Trivy reports
`pkg:apk/alpine/busybox@1.33.1-r3?arch=x86_64&distro=3.14.2`, a requirements.txt says `PyYAML==5.3`,
and OSV says `pyyaml`. Unless these converge, the graph ends up holding several disconnected
"busybox" nodes, and a Trivy finding cannot be walked back to the commit that introduced the package.

## Decision

Every node id is `kind:sha256(canonical identity)`. For a dependency, the canonical identity is the
purl with its qualifiers and subpath removed and its name normalised for the ecosystem (PEP 503 for
PyPI, lower case for npm, deb and apk). Layers are keyed by their uncompressed DiffID, which both
Syft and Trivy report, and images by their config digest (the image ID).

## Consequences

- On the real image benchmark, Trivy findings land on Syft SBOM nodes by canonical purl, where exact
  purl-string matching fails because the tools write different qualifiers. See
  `results/images_real.json`.
- Packages that differ only by architecture qualifier collapse into one node. This is acceptable
  for single-arch pipelines. Multi-arch builds would need `arch` added back into the identity.
- A shared base layer becomes a single node, so blast-radius queries are a single graph walk.
