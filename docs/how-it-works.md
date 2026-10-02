# How it works

This page follows one finding from the pipeline to the PR comment, using the `cve-origin`
scenario of the [live demo](demo/index.html). The demo data is synthetic (PR #42,
`dev@example.com`); the same code path runs on the real repositories in the
[Evaluation](evaluation.md).

![The cve-origin scenario in the lineage explorer after backtracking CVE-2020-14343](img/demo.png)

## 1. Every stage emits a signed event

Each CI stage writes one *stage event* and wraps it in a DSSE envelope:

| Stage | Producer | Payload |
| --- | --- | --- |
| `commit` | `tracegate lineage REPO MANIFEST` | the pins the commit introduced or changed, its PR number and author |
| `build` | `tracegate ingest --syft` | the unchanged Syft (or CycloneDX) SBOM: packages, layers, image digest |
| `scan` | `tracegate ingest --trivy` / `--sarif` | the unchanged Trivy or SARIF findings |
| `deploy`, `runtime` | your deploy job | which image runs as which service, and which modules containers loaded |

Envelopes are signed with Ed25519, HMAC, or (in CI) an ephemeral Ed25519 key whose public key
is itself signed keylessly with Sigstore, so the gate can check that the key came from a
specific GitHub workflow (Fulcio certificate plus Rekor transparency-log entry).

## 2. The collector verifies and fails closed

`collector.py` verifies every envelope against the configured trust root. An envelope with a
bad signature or an unknown `keyid` is rejected, and a run missing any of the required
`commit`, `build` and `scan` stages blocks with a `provenance_integrity` reason. With no trust
root configured at all, the CLI exits 2 and the API answers 503: nothing is trusted by
default.

## 3. The events become one content-addressed graph

Verified payloads are merged into a DAG:
`commit -introduced-> dependency -installed_in-> layer -layer_of-> image -> deployment -> container`.
Dependencies are keyed by a canonical purl, so the manifest pin, the Syft package and the Trivy
finding for `pyyaml==5.3` become **one** node, and a base layer shared by three images is one
node too. In the screenshot the three `image` nodes share layers and builds with `pyyaml==5.3`.

## 4. Enrichment adds risk and reachability

- **OSV and Warden.** `OsvIndex` matches pins against the offline OSV dump, including
  malicious-package (`MAL-*`) records, and the typosquat detector scores names against the
  ecosystem's most-downloaded packages.
- **Reachability.** Runtime facts win: here two containers report that module `yaml` was
  loaded, so the finding is reachable and keeps its `block`. Without runtime facts, a static
  pass over the app's imports, entrypoints and `# via` edges can mark a package `unreached`,
  which downgrades `block` to `warn` but never hides the finding (see the
  [threat model](threat-model.md) for why this is advisory on untrusted PRs).

## 5. The policy explains itself with a graph path

`policy.py` (mirrored in `policies/tracegate.rego`, parity-checked in CI) turns the enriched
graph into a verdict. Every reason carries the path that produced it and its evidence. This is
the PR comment `tracegate gate --comment` prints for the scenario:

```markdown
## TRACEGATE: BLOCK

- **[block] vulnerable_dependency**: CVE-2020-14343
  - path: `commit:a1b2c3d4e5f6 -> dependency:pyyaml==5.3`
  - evidence: module 'yaml' loaded in ['api-7d9f-0', 'worker-7d9f-0']
```

The exit code is 1 on block, so the CI job fails.

## 6. Backtrack and blast radius

`tracegate backtrack events.json CVE-2020-14343` walks the graph backwards to the commit that
introduced the vulnerable version and forwards to everything that inherits it:

```json
{
  "artifact": "pyyaml==5.3",
  "introduced_by": {"sha": "a1b2c3d4e5f6...", "author": "dev@example.com", "pr": 42},
  "builds": ["run-42-api", "run-42-web", "run-42-worker"],
  "blast_radius": {"images": ["ghcr.io/demo/api", "ghcr.io/demo/web", "ghcr.io/demo/worker"],
                   "services": ["api", "web", "worker"]}
}
```

The introducing commit is found by version-aware diffing of the lock-file history (which pin
*changed version* in which first-parent commit), not by line blame, so a later commit that only
re-formats or re-hashes the line does not take the credit. A CVE disclosed months after the
merge still gets its origin story. The [Evaluation](evaluation.md) measures this against
`git blame` and an exact-pin `git log -S` on real repositories.

## 7. Admission

The `kind-admission` CI workflow shows the last step: two images are built and pushed to a
localhost registry, only one is signed keylessly, and each is applied to a kind cluster only if
`cosign verify` accepts it against the workflow identity **and** `tracegate gate` passes on its
signed events. The signed image runs; the unsigned one is denied by cosign; a third image that is
validly signed but whose signed provenance lacks the build and scan stages is denied by the
TRACEGATE gate. Each reason is recorded in `decisions.json`.
