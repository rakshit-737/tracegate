# CLI and API reference

## CLI

`tracegate <command>`; every command prints JSON unless stated. Signing keys come from
`TRACEGATE_KEYID`, `TRACEGATE_SIGNING_KEY` (Ed25519 PEM) or the HMAC demo key; the gate trusts
`TRACEGATE_PUBKEY`.

| Command | Purpose |
| --- | --- |
| `synth <scenario> <out>` | write a signed synthetic scenario (`clean`, `malicious-dep`, `cve-origin`, `unreachable`, `tampered`, `unsigned-missing`) |
| `gate <events> [--comment] [--osv zip] [--top-pypi] [--reach-repo dir --reach-src ... --reach-manifest f]` | verdict; exit 1 on block |
| `backtrack <events> <CVE or package>` | origin story: commit, PR, author, builds, blast radius |
| `blast <events> <layer-digest-prefix>` | images, services and containers inheriting a layer |
| `ingest [--syft f [--cyclonedx]] [--trivy f]... [--sarif f]... --commit sha -o out` | sign unmodified tool output as stage events |
| `lineage <repo> <manifest> [--limit n] -o out` | commit events from manifest / lock-file history |
| `merge <in>... -o out` | concatenate envelope files |
| `export <events> --format json\|cypher\|opa\|intoto` | graph exports |
| `keygen <prefix>` | Ed25519 key pair |
| `serve [--host --port]` | FastAPI service and lineage explorer |
| `demo`, `bench` | run the spec scenarios / synthetic scale check |

## HTTP API (`tracegate serve`)

| Method | Path | Returns |
| --- | --- | --- |
| GET | `/` | lineage explorer UI |
| GET | `/healthz` | `{"status": "ok"}` |
| POST | `/v1/gate` | body: list of DSSE envelopes; returns verdict summary and run id (422 on malformed envelopes) |
| POST | `/v1/demo/{scenario}` | run a synthetic scenario |
| GET | `/v1/runs` | stored runs |
| GET | `/v1/runs/{run}/graph` | nodes, edges, findings, decision |
| GET | `/v1/runs/{run}/backtrack?q=` | origin stories |
| GET | `/v1/runs/{run}/blast?layer=` | layer blast radius |
| GET | `/v1/runs/{run}/cypher` | Neo4j Cypher script |

## Python API

::: tracegate.pipeline
::: tracegate.ingest
::: tracegate.sarif
::: tracegate.lockfiles
::: tracegate.gitlineage
::: tracegate.backtrack
::: tracegate.policy
