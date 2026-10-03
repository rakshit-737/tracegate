# ADR 0004: Reachability, runtime facts first, static import analysis as fallback

- Status: accepted
- Date: 2026-09-26

## Context

The research question is how much reachability enrichment cuts actionable alerts without missing
exploitable findings. Runtime facts (modules loaded in a running container) are the most reliable
signal, but most pipelines do not collect them.

## Decision

1. If a `runtime` stage reports the modules loaded in a downstream container, that evidence decides
   the result. The package is reachable if it was loaded anywhere and unreachable if it was observed
   nowhere.
2. Otherwise `tracegate.reach` makes a conservative static estimate. A package counts as reachable
   if the app sources import it (AST imports, `importlib.import_module`, dotted-path strings such as
   Django `INSTALLED_APPS`), or if it is named in an entrypoint file (Dockerfile, Procfile, shell,
   ini, toml, yaml), or if a reachable package requires it according to the pip-compile `# via`
   annotations.
3. Unknown reachability is treated as reachable. Being unreachable only downgrades a finding from
   block to warn. It never suppresses the finding.

## Consequences

- Any import on any code path counts, including cold ones. The estimate therefore over-approximates
  reachability, and the reduction it reports is a lower bound.
- Two cases produce a false "unreached": packages loaded only through entry-point plugins, and
  packages loaded through computed import strings. For pip-compile repos the benchmark lists every
  *direct* dependency that was marked unreached, so these cases can be audited by hand
  (`results/lineage_real_repos.json`).
- The mapping from distribution name to import name is a curated table plus heuristics, because
  wheel `top_level.txt` metadata is not fetched. A wrong mapping can only cause a false
  "unreached", and that outcome is still reported as a warning.

## Amendment (after the v1.1.0 audit)

An audit of every static downgrade in the per-snapshot reachability benchmark (45 findings on 17
pins of warehouse and netbox) found all 17 pins loaded: each is required by a package the
snapshot's sources import (`google-cloud-bigquery -> google-auth -> rsa / pyasn1`,
`webauthn -> cbor2`, `django-rest-swagger -> PyYAML`). Those requirement files record no
dependency edges, so a third failure mode dominates: a transitive dependency of an imported
package looks exactly like an unused pin. Two changes follow:

1. `via_graph` also reads the older inline layout (`pyyaml==3.11  # via pymlconf`).
2. Without any pip-compile `# via` annotation in the manifest, a pin that is not imported gets the
   status `unknown`, which never downgrades. `unreached` now requires recorded dependency edges.

On the benchmark's 36 snapshots the static rule therefore downgrades nothing. Evidence and
verdicts: `results/reachability_audit.json`.

