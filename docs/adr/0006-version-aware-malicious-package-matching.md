# ADR 0006: Match OSV malicious-package records by version, not by name

- Status: accepted
- Date: 2026-09-26

## Context

`HeuristicWarden` treats any package that has an OSV `MAL-*` record (ossf/malicious-packages) as
risk 1.0, which blocks the gate. The first version looked records up by package name only. That
works for most of the dataset: in the npm dump, about 197k affected entries use the range
`introduced: 0` with no upper bound, which means every version is malicious (typosquats,
dependency-confusion names, spam).

Account-takeover incidents are different. The September 2025 npm hijack of `chalk`, `debug`,
`ansi-regex` and related packages produced records such as `MAL-2025-46969`, whose `affected`
entry lists only the trojanised release (`versions: ["5.6.1"]`). About 14k npm affected entries
are version-specific like this. When the real `node:14.17.6-alpine3.14` image was scanned, the
name-only lookup flagged 13 clean, years-old installs (`chalk 2.4.1`, `debug 3.1.0`, ...) as known
malware. With a blocking gate, that means every Node image fails for a reason that is false.

## Decision

Follow OSV semantics: a version is affected if it appears in `versions` **or** falls inside one
of the `ranges`.

- A record with neither versions nor ranges is treated as affecting every version. This fails
  closed.
- A range of `introduced: 0` with no `fixed` or `last_affected` event matches without parsing the
  version, so versions that do not follow PEP 440 or semver are still caught.
- Bounded ranges reuse the same matcher as vulnerability ranges (`packaging.Version`).
- `OsvIndex.malicious(name)` with no version still returns every record. Name-level questions
  ("has this name ever been malicious?") remain available for UI and triage.

## Consequences

- On the real node image, Warden flags dropped from 16 to 3. The 3 left are `npm-cli-docs`, which
  has a real all-versions MAL record for the public name even though npm bundles an internal
  package with that name, and two typosquat-heuristic hits (`ansistyles`, `uid-number`) that are
  legitimate packages. These are reported as false positives in the README.
- A hijacked release is still blocked exactly. Pinning the clean version clears the gate, which is
  the remediation you want.
- Regression test: `test_malicious_lookup_is_version_aware`, which uses the real record shapes.
