# Evaluation

Every number on this page is read from a committed JSON file in [`results/`](https://github.com/rakshit-737/tracegate/tree/main/results); the tables between generated markers are rendered from those files by `scripts/render_results.py`, and CI fails if a table and its file disagree. Each file records the GitHub Actions run that produced it:

| Results | Files | Run |
| --- | --- | --- |
| Backtracking (multi-version and old readers on the same data), adjudication evidence, dataset manifest | `lineage_real_repos.json`, `lineage_real_repos_single_version.json`, `lineage_adjudication*.json`, `data_manifest.json` | [37091106360](https://github.com/rakshit-737/tracegate/actions/runs/37091106360) |
| Bot-bump oracle | `lineage_bot_bump_oracle.json` | [37091106360](https://github.com/rakshit-737/tracegate/actions/runs/37091106360) |
| Reachability, each snapshot against its own sources | `lineage_real_repos_materialized.json` (current), `..._audited.json` (the audited run), `..._v1.1.0.json` | [37091106360](https://github.com/rakshit-737/tracegate/actions/runs/37091106360), [37090410909](https://github.com/rakshit-737/tracegate/actions/runs/37090410909), [37003433022](https://github.com/rakshit-737/tracegate/actions/runs/37003433022) |
| Reachability audit (evidence and verdicts, written locally from the audited run) | `reachability_audit.json` | generated locally from [37090410909](https://github.com/rakshit-737/tracegate/actions/runs/37090410909) |
| Real images, synthetic scale | `images_real.json`, `scale_synthetic.json`, `data_manifest_images.json` | [37088867445](https://github.com/rakshit-737/tracegate/actions/runs/37088867445) |
| Typosquat, original TypoGard / typomania, PR figure | `typosquat_*.json`, `typosquat_originals.json`, `data_manifest_typosquat.json`, `typosquat_pr.png` | [37003433022](https://github.com/rakshit-737/tracegate/actions/runs/37003433022) |
| v1.1.0 backtracking and oracle, kept for the before/after comparison | `lineage_real_repos_v1.1.0.json`, `lineage_bot_bump_oracle_v1.1.0.json` | [37003433022](https://github.com/rakshit-737/tracegate/actions/runs/37003433022) |
| kind admission, Sigstore evidence | `kind_admission.json`, `sigstore_evidence.json` | [37003568257](https://github.com/rakshit-737/tracegate/actions/runs/37003568257), [37003568357](https://github.com/rakshit-737/tracegate/actions/runs/37003568357) |

How to re-run each: [Reproduce](reproduce.md).

## Methodology

- **Backtracking.** For each repository the first-parent history of its lock file is walked and 12 snapshots are spread evenly over it. The repositories are cloned at the commits recorded in `results/data_manifest.json`, so re-runs walk the same histories. At each snapshot every pinned (package, version) pair is matched against the offline OSV dump; for every vulnerable pair, TRACEGATE's answer (the newest commit whose diff made that pair appear) is compared with `git blame --first-parent` on the pair's version line. The unit is a (snapshot, vulnerable pin) pair, so a long-lived pin counts once per snapshot; pairs are clustered by repository, so the Wilson and exact intervals are too narrow and a bootstrap that resamples whole repositories (2,000 draws) is reported beside them. Methods are compared on the same pairs with exact McNemar tests on the discordant pairs.
- **Baselines.** The last commit that touched the manifest; the first `git log -G` mention of the package name; and two `git log --first-parent -1 -S` pickaxes: a *package-specific* token (the two-line `name = "x"` / `version = "y"` of a Cargo.lock entry, a yarn.lock block header plus its version line, a package-lock key plus version; pip, Go and pnpm pins are already one package-specific line) and the *version line* alone, which in Cargo.lock, yarn.lock and package-lock is shared by every package at that version. Blame and both pickaxes are line attribution, the B-SZZ idea (Śliwerski, Zimmermann and Zeller, MSR 2005).
- **Blame is a reference, not ground truth.** It shares the lock-file reader and has the failure modes the SZZ literature names: it credits meta-changes such as merges (what MA-SZZ, da Costa et al., TSE 2017, filters out) and cosmetic rewrites (AG-SZZ, Kim et al., ASE 2006). Agreement is therefore checked two more ways: by reading the diffs of a sample of disagreements, and against labels taken from commit messages (the oracle), the idea behind the developer-informed SZZ oracle of Rosa et al. (ICSE 2021). Lyu et al. (IEEE TSE; arXiv 2308.05060) compare SZZ variants on the Linux kernel. `git log -L` and PyDriller's SZZ are further line-history tools; they are line-based like blame and are not run here.
- **Reachability.** For the three Python repositories, every high/critical OSV finding is checked against static reachability (imports, entrypoints, pip-compile `# via` edges, implied framework dependencies), with each snapshot analysed against its own sources (`--materialize`). Every downgrade is then audited (below).
- **Typosquat.** Positives are OSV `MAL-*` package names of the ecosystem that are not themselves popular; negatives are real packages ranked just below the reference list. Hash split: 50/50 by sha256(name), thresholds tuned on the dev half. The `FPR-matched` row picks the lowest threshold whose **dev** FPR is at most Damerau-1's dev FPR (no test data is used); the dev-tuned default (best dev F1 at dev FPR <= 2%) is shown beside it. Time split: positives first published before 2025-01-01 tune, later ones test (OSV `published` dates are dominated by bulk backfills); negatives stay hash-split. CIs are a seeded stratified bootstrap (1,000 resamples). Precision is also reported at 1% prevalence, because the test sets are mostly malicious.
- **Design notes** are in [ADR 0005](adr/0005-real-data-evaluation-design.md).

## Backtracking: finding -> introducing commit

<!-- results:lineage-repos -->
| Repository | Lock file | Pairs | TRACEGATE | pickaxe, package-specific | pickaxe, version line | last manifest commit | first mention | gate median / max ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| healthchecks | `requirements.txt` | 20 | 100.0% | 100.0% | 100.0% | 40.0% | 20.0% | 7 / 13 |
| netbox | `requirements.txt` | 108 | 100.0% | 100.0% | 100.0% | 39.8% | 14.8% | 14 / 26 |
| warehouse | `requirements/main.txt` | 234 | 96.6% | 100.0% | 100.0% | 6.0% | 4.7% | 70 / 633 |
| caddy | `go.sum` | 195 | 100.0% | 100.0% | 100.0% | 13.9% | 10.3% | 283 / 917 |
| hugo | `go.mod` | 133 | 99.2% | 100.0% | 100.0% | 9.8% | 6.8% | 304 / 1251 |
| ripgrep | `Cargo.lock` | 76 | 98.7% | 97.4% | 69.7% | 10.5% | 13.2% | 40 / 87 |
| bat | `Cargo.lock` | 188 | 98.9% | 98.9% | 59.6% | 8.5% | 25.0% | 71 / 135 |
| alacritty | `Cargo.lock` | 259 | 99.6% | 99.6% | 46.7% | 4.2% | 16.6% | 129 / 644 |
| excalidraw | `yarn.lock` | 1265 | 99.7% | 89.3% | 74.9% | 20.7% | 10.4% | 126 / 583 |
| mastodon | `yarn.lock` | 999 | 87.2% | 74.2% | 46.6% | 7.8% | 12.6% | 483 / 1619 |
| vue-core | `pnpm-lock.yaml` | 492 | 68.1% | 97.2% | 97.2% | 14.0% | 20.5% | 147 / 780 |
| **all** | 11 repos | 3969 | **92.4%** [Wilson 91.5-93.2; repo-clustered 82.7-99.5] | 89.6% [clustered 82.2-99.4] | 72.2% | 13.8% | 13.1% | |

Source: `results/lineage_real_repos.json`, run [37091106360](https://github.com/rakshit-737/tracegate/actions/runs/37091106360).
<!-- /results:lineage-repos -->

Per ecosystem, with the paired comparison against the package-specific pickaxe:

<!-- results:lineage-ecosystems -->
| Ecosystem | Pairs | TRACEGATE [Wilson 95%] | pickaxe, package-specific [Wilson 95%] | discordant pairs (TRACEGATE only : pickaxe only) | exact McNemar p | pickaxe, version line |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cargo | 523 | 99.2% [98.0-99.7] | 99.0% [97.8-99.6] | 1 : 0 | 1.00 | 54.7% |
| Go | 328 | 99.7% [98.3-100.0] | 100.0% [98.8-100.0] | 0 : 1 | 1.00 | 100.0% |
| npm (yarn, pnpm) | 2756 | 89.5% [88.3-90.6] | 85.2% [83.9-86.5] | 360 : 242 | 1.7e-06 | 68.6% |
| pip | 362 | 97.8% [95.7-98.9] | 100.0% [99.0-100.0] | 0 : 8 | 0.008 | 100.0% |
| **all** | 3969 | 92.4% [91.5-93.2] | 89.6% [88.6-90.5] | 361 : 251 | 1.0e-05 | 72.2% |
<!-- /results:lineage-ecosystems -->

Reading: on pip requirements and go.mod the pin line changes only with the version, so blame and both pickaxes coincide and TRACEGATE disagrees only where a commit rewrote the line without changing the version (warehouse: a merge that added hashes, a pip-compile run that lower-cased names; hugo: a `go.mod` restructuring). On Cargo.lock the package-specific pickaxe and TRACEGATE are tied; the old version-line token is far behind because `version = "x"` is shared by every crate at that version. On yarn and pnpm lock files, header lines change whenever a range is added, so even the package-specific token follows rewrites; TRACEGATE agrees more often, but by a margin the clustered interval cannot separate from 0. Latency is per snapshot graph (verify, build, enrich, decide).

### Before and after the multi-version readers

Until this release the yarn, pnpm, package-lock and Cargo readers kept one version per package name, so a lock file holding debug 2.6.9 and debug 4.3.4 contributed one of them. The old readers are kept behind `--single-version` and were run on the same clones and the same OSV dump as the new ones:

<!-- results:before-after -->
| Ecosystem | v1.1.0 as published (run 37003433022) | old readers, this run (37091106360) | multi-version readers, this run (37091106360) |
| --- | ---: | ---: | ---: |
| Cargo | 459/483 = 95.0% | 459/483 = 95.0% | 519/523 = 99.2% |
| Go | 327/328 = 99.7% | 327/328 = 99.7% | 327/328 = 99.7% |
| npm (yarn, pnpm) | 1704/2030 = 83.9% | 1709/2045 = 83.6% | 2467/2756 = 89.5% |
| pip | 354/362 = 97.8% | 354/362 = 97.8% | 354/362 = 97.8% |
| **all** | 2844/3203 = 88.8% | 2849/3218 = 88.5% | 3667/3969 = 92.4% |
| multi-version entries dropped by the old readers at HEAD |  |  | ripgrep 1/63 (1.6%), bat 11/317 (3.5%), alacritty 33/292 (11.3%), excalidraw 201/1444 (13.9%), mastodon 102/1354 (7.5%), vue-core 56/642 (8.7%) |
<!-- /results:before-after -->

On the same data the new readers agree with blame on 92.4% of 3,969 pairs and the old ones on 88.5% of 3,218; the v1.1.0 figure was 88.8% of 3,203 (run 37003433022, older OSV data and the old readers). The denominators differ because the new readers find vulnerable versions that sat in second copies of a package name. The last row counts, per repository at the pinned HEAD, the lock-file entries the old readers dropped; it replaces the "7-14%" range quoted in v1.1.0, which had no committed source.

### Reading the disagreements

The disagreements between TRACEGATE and blame were read against the lock-file diffs: every pip and Go disagreement, and a uniform random sample (seed 0) of 50 Cargo and npm ones. For each case the correct introducer is the newest first-parent commit at or before the snapshot whose diff makes the pinned version appear. The evidence (each candidate commit's subject, the hunks that mention the package, and the versions before and after) is in `results/lineage_adjudication_evidence.json`; the verdicts, one line of reasoning each, are in `results/lineage_adjudication.json`.

<!-- results:adjudication -->
| Sample | cases | TRACEGATE | `git blame` | pickaxe, package-specific | pickaxe, version line | undecided |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| pypi+golang | 9 | 9/9 [70-100] | 0/9 [0-30] | 0/9 [0-30] | 0/9 [0-30] | 0 |
| cargo+npm | 50 | 50/50 [93-100] | 0/50 [0-7] | 3/50 [2-16] | 1/50 [0-10] | 0 |
| all | 59 | 59/59 [94-100] | 0/59 [0-6] | 3/59 [2-14] | 1/59 [0-9] | 0 |

Wilson 95% intervals in brackets. Source: `results/lineage_adjudication.json`.
<!-- /results:adjudication -->

In every sampled case the commit `git blame` names already pinned the version at its first parent, so it rewrote the line rather than introduced the version; the `note` field of each case records which kind of rewrite (merge, lock-file format migration, unrelated update). Both pickaxes coincide with blame except where they found TRACEGATE's commit. The reading rule is TRACEGATE's own definition, so the adjudication shows that the disagreements are rewrites; it cannot show that the reader is right where every method agrees (that is what the oracle and the multi-version tests are for). One case was decided by reading the repository by hand (a manifest renamed after the introducing commit); it is marked in the file.

### Bot-bump oracle

Labels come from commit messages only: a Dependabot or Renovate subject that names one package and its target version, the per-package lines of a grouped bump's body ("Updates `X` from A to B", Renovate's table), `Revert "Bump X from A to B"` (the revert restores X@A), and any message that re-introduces an earlier version (A -> B -> C -> B, labelled with the second B commit). Merge commits of bot branches are labelled from the PR title in the merge body. Each label is checked with the multi-version reader: X@V must be absent at the commit's first parent and present after it. Cases are scored at the labelled commit and at the last later manifest commit that still pins X@V.

**What it tests, and what it does not.** At the labelled commit TRACEGATE is right on every verified label *by construction*: the label check is its own criterion. The oracle can fail TRACEGATE at later snapshots (line rewrites, reader glitches between the two points), and it does fail the two ablations: the old one-version-per-name readers on the multi-version stratum, and "first introduction" (no recency rule) on reverts and re-bumps. It does not test attribution independently of the lock-file reader.

**Sample.** Per repository and stratum, a uniform random sample without replacement of at most 40 usable cases (`random.Random(0).shuffle`, then chronological order); `max_cases`, `seed` and `selection` are recorded in the JSON.

<!-- results:oracle-strata -->
| Stratum | usable / scored | TRACEGATE | old one-version readers | first introduction (no recency rule) | `git blame` | pickaxe, package-specific | pickaxe, version line |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| single package, at the labelled commit | 4022 / 264 | 264/264 | 264/264 | 264/264 | 264/264 | 264/264 | 264/264 |
| single package, last later snapshot | 4022 / 251 | 251/251 | 249/251 | 251/251 | 240/251 | 233/251 | 218/251 |
| multi version, at the labelled commit | 340 / 67 | 67/67 | 13/67 | 67/67 | 67/67 | 67/67 | 67/67 |
| multi version, last later snapshot | 340 / 66 | 66/66 | 13/66 | 66/66 | 63/66 | 56/66 | 44/66 |
| grouped, at the labelled commit | 130 / 87 | 87/87 | 87/87 | 87/87 | 87/87 | 87/87 | 87/87 |
| grouped, last later snapshot | 130 / 85 | 85/85 | 85/85 | 85/85 | 84/85 | 83/85 | 80/85 |
| revert, at the labelled commit | 19 / 19 | 19/19 | 19/19 | 0/19 | 19/19 | 19/19 | 19/19 |
| revert, last later snapshot | 19 / 16 | 16/16 | 16/16 | 0/16 | 15/16 | 15/16 | 14/16 |
| re bump, at the labelled commit | 21 / 21 | 21/21 | 21/21 | 0/21 | 21/21 | 21/21 | 20/21 |
| re bump, last later snapshot | 21 / 18 | 18/18 | 18/18 | 0/18 | 17/18 | 16/18 | 15/18 |
| **all**, at the labelled commit | 4532 / 458 | 458/458 | 404/458 | 418/458 | 458/458 | 458/458 | 457/458 |
| **all**, last later snapshot | 4532 / 436 | 436/436 | 381/436 | 402/436 | 419/436 | 403/436 | 371/436 |

Source: `results/lineage_bot_bump_oracle.json`, run [37091106360](https://github.com/rakshit-737/tracegate/actions/runs/37091106360).
<!-- /results:oracle-strata -->

Pooled over all strata, with exact one-sided lower bounds (Clopper-Pearson; they treat the cases as independent, and clustering by repository would widen them):

<!-- results:oracle-pooled -->
| Method | at the labelled commit | one-sided 95% exact lower bound | last later snapshot | one-sided 95% exact lower bound | Wilson 95% (later) | repo-clustered bootstrap 95% (later) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| TRACEGATE | 458/458 (100.0%) | 99.4% | 436/436 (100.0%) | 99.3% | 99.1-100.0 | 100.0-100.0 |
| old one-version readers | 404/458 (88.2%) | 85.4% | 381/436 (87.4%) | 84.5% | 83.9-90.2 | 74.7-99.2 |
| first introduction (no recency rule) | 418/458 (91.3%) | 88.8% | 402/436 (92.2%) | 89.8% | 89.3-94.4 | 89.2-95.4 |
| `git blame` | 458/458 (100.0%) | 99.4% | 419/436 (96.1%) | 94.2% | 93.8-97.5 | 91.2-100.0 |
| pickaxe, package-specific | 458/458 (100.0%) | 99.4% | 403/436 (92.4%) | 90.0% | 89.6-94.6 | 85.8-99.2 |
| pickaxe, version line | 457/458 (99.8%) | 99.0% | 371/436 (85.1%) | 82.0% | 81.4-88.1 | 72.7-96.6 |

Paired at later snapshots (TRACEGATE only : other only, exact McNemar, ignores clustering): vs `git blame`: 17 : 0, p 1.5e-05; vs pickaxe, package-specific: 33 : 0, p 2.3e-10; vs old one-version readers: 55 : 0, p 5.6e-17.
<!-- /results:oracle-pooled -->

Labels that failed the check are not scored:

<!-- results:oracle-exclusions -->
| Label source | labels | X@V already present at the parent | X@V not in the lock file | ambiguous name |
| --- | ---: | ---: | ---: | ---: |
| bot single | 4450 | 53 | 26 | 0 |
| grouped | 143 | 0 | 9 | 0 |
| revert | 19 | 0 | 0 | 0 |

Usable labelled cases per repository (all strata): healthchecks 8, netbox 1, warehouse 992, caddy 102, hugo 620, ripgrep 3, bat 361, alacritty 1, excalidraw 142, mastodon 2243, vue-core 59.
<!-- /results:oracle-exclusions -->

Reading: at the labelled commit every method except the two ablations agrees with the label (TRACEGATE by construction; `git blame` and the package-specific pickaxe as well). At the later snapshot TRACEGATE keeps every case while `git blame` loses 17. Each of those 17 credits a commit that rewrote the line and kept the version: mastodon's "Upgrade to Yarn 4" (`757d7c73c0`) and "Force all NPM packages to their exact versions" (`95b782fcde`), vue-core's "chore: Merge branch 'main' into minor" merges (the meta-changes MA-SZZ filters out) and dependency updates that re-sorted `pnpm-lock.yaml`, and hugo's "Upgrade to deploy to use AWS SDK V2", which moved a `go.mod` line. The gap is significant if cases are treated as independent (exact McNemar above), but 16 of the 17 come from two repositories, so the repo-clustered interval for the difference starts at 0. The ablations fail where they should: the old one-version readers on the multi-version stratum, and attribution without the recency rule on every revert and re-bump.

The v1.1.0 oracle (`results/lineage_bot_bump_oracle_v1.1.0.json`, 243 bumps) counted two blame "misses" at the bump that were label errors: bat's unicode-width 0.2.0 entered `Cargo.lock` with an earlier console bump, and excalidraw's loader-utils 2.0.4 was already locked through another range. The label check now excludes such cases (`already_present` above), and TRACEGATE's agreement with those wrong labels came from the first-entry reader.

## Reachability

<!-- results:reachability -->
| Run | Static rule | high+ findings | actionable | downgraded [exact 95%] |
| --- | --- | ---: | ---: | ---: |
| [37003433022](https://github.com/rakshit-737/tracegate/actions/runs/37003433022) | v1.1.0: static tiers; `# via` read only below the pin | 887 | 836 | 51 (5.7%) [4.3-7.5] |
| [37090410909](https://github.com/rakshit-737/tracegate/actions/runs/37090410909) | + inline `# via` (older pip-compile layout) | 887 | 842 | 45 (5.1%) [3.7-6.7] |
| [37091106360](https://github.com/rakshit-737/tracegate/actions/runs/37091106360) | + no downgrade when the manifest records no dependency edges | 887 | 887 | 0 (0.0%) [0.0-0.4] |

Current run per repository (36 snapshots, each against its own sources): healthchecks 139 -> 139, netbox 324 -> 324, warehouse 424 -> 424. Files: `results/lineage_real_repos_materialized*.json`.
<!-- /results:reachability -->

### Audit of every downgrade

`benchmarks/reach_audit.py` rebuilds, for each downgraded (snapshot, pin), the dependency edges its requirement file did not record (the pinned releases' own `requires_dist` metadata on PyPI, plus the snapshot's sources) and finds a chain from a package the app imports down to the pin. Each pin then gets a verdict by hand: `loaded` when such a chain exists or the sources load it, `not loaded` when the sources and every dependent were checked and nothing loads it.

<!-- results:audit -->
| Verdict | (snapshot, pin) rows | findings |
| --- | ---: | ---: |
| loaded | 17 | 45 |
| not loaded | 0 | 0 |
| undetermined | 0 | 0 |

False-`unreached` rate among decided pins: 17/17 = 100.0% (exact 95% 80.5-100.0). Audited run: [37090410909](https://github.com/rakshit-737/tracegate/actions/runs/37090410909); verdicts and evidence: `results/reachability_audit.json`.
<!-- /results:audit -->

Every one of the 17 downgraded pins (45 findings) is loaded: warehouse imports `google.cloud.bigquery`, which requires google-auth, which requires rsa and pyasn1; webauthn requires cbor2 and future; readme-renderer 21.0 requires future; netbox lists `rest_framework_swagger` in `INSTALLED_APPS`, and the pinned django-rest-swagger 0.3.4 imports `yaml`. The requirement files at those snapshots record no dependency edges, so the gate could not tell a transitive dependency of an imported package from an unused pin. The earlier reductions (-5.7% in v1.1.0, -5.1% after the inline-`# via` fix) were therefore not useful triage, and static reachability now marks such pins `unknown` and downgrades nothing on these 36 snapshots. This is a result where TRACEGATE does worse than it claimed. A published reference point with a different method and ecosystem: Pashchenko et al. found about 20% of the vulnerable dependencies of Java libraries "not deployed" (ESEM 2018; arXiv 1808.09753v1, abstract and Sec. 6 RQ1, p. 7), where "not deployed" means test- or development-scope dependencies, a different notion from import reachability.

## Typosquat detection

Source: run [37003433022](https://github.com/rakshit-737/tracegate/actions/runs/37003433022) (`results/typosquat_*.json`; inputs in `results/data_manifest_typosquat.json`).

Detectors: TRACEGATE (multi-technique, threshold tuned on dev), Damerau-1 (TRACEGATE's own `typo1` technique alone, top-5k reference), re-implementations of **typomania / TypoGard** (Rust Foundation port of Taylor et al., *Defending Against Package Typosquatting*, NSS 2020) and **pypi-scan** (IQT Labs), and the original 14-name difflib heuristic. The re-implementations live in `tracegate/baselines.py`; the typomania/TypoGard port is validated against the original code (below); the pypi-scan rows remain *our port of* that tool. The TypoGard paper states that its signals "detected approximately 60% of known past attacks reported by the npm security team as typosquatting" (Taylor et al., NSS 2020; arXiv 2003.03471v1, where the tool is named SpellBound, Sec. 4.3 "Signal Detection Rates", p. 9); on the OSV labels here, where most names are not look-alikes, every detector's recall is far lower.

### Original TypoGard and typomania on the same splits

The benchmarks workflow fetches the original `typogard_npm.py` (mt3443/typogard at `9c10636`) and builds the original typomania `registry` example (rustfoundation/typomania at `10e27e8`) with cargo, then runs both unchanged on exactly the test positives, negatives and reference list of every ecosystem and split ([`results/typosquat_originals.json`](https://github.com/rakshit-737/tracegate/blob/main/results/typosquat_originals.json), run 37003433022). TypoGard's detection function is called directly with its two globals set to our reference list; its npm dependency walk is not used.

| Ecosystem | Split | F1, our port | F1, original typomania | F1, original TypoGard | flag agreement port vs typomania | port vs TypoGard |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| PyPI | hash | 0.125 | 0.125 | 0.121 | 100.00% | 99.62% |
| PyPI | time | 0.051 | 0.051 | 0.045 | 100.00% | 99.54% |
| npm | hash | 0.005 | 0.005 | 0.004 | 99.97% | 99.87% |
| npm | time | 0.005 | 0.005 | 0.003 | 99.98% | 99.90% |
| RubyGems | hash | 0.027 | 0.027 | 0.021 | 99.98% | 99.43% |
| RubyGems | time | 0.031 | 0.031 | 0.024 | 99.98% | 99.44% |
| crates.io | hash | 0.026 | 0.026 | 0.039 | 100.00% | 98.99% |
| crates.io | time | 0.023 | 0.023 | 0.033 | 100.00% | 98.99% |
| NuGet | hash | 0.000 | 0.000 | 0.000 | 100.00% | 99.52% |
| NuGet | time | 0.000 | 0.000 | 0.000 | 100.00% | 99.42% |

The port reproduces the original typomania to within a handful of names per split (identical F1 everywhere), so the typomania/TypoGard rows in the tables are the published tool's numbers. The original 2020 TypoGard script differs a little more (it has no bitflip check, skips omitted-character checks below 4 characters, and its version-suffix rule differs); its F1 is within 0.007 of the port except on crates.io, where it is slightly higher. The conclusion is unchanged: on OSV `MAL-*` labels every name-similarity detector has low recall.

### PyPI, hash split

5964 test positives (313 labelled typosquat), 4973 test negatives; reference = top 5000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.855 | 0.016 | 0.031 [0.025, 0.037] | 0.0032 | 0.048 | 0.067 |
| lev1 (top-5k) | 0.746 | 0.081 | 0.147 [0.135, 0.159] | 0.0332 | 0.024 | 0.137 |
| typomania/TypoGard (top-5k) | 0.788 | 0.068 | 0.125 [0.114, 0.136] | 0.0219 | 0.030 | 0.093 |
| pypi-scan (top-50) | 0.930 | 0.009 | 0.018 [0.013, 0.022] | 0.0008 | 0.101 | 0.029 |
| pypi-scan (top-5k) | 0.735 | 0.061 | 0.112 [0.101, 0.123] | 0.0263 | 0.023 | 0.128 |
| tracegate (th=0.54) | 0.834 | 0.072 | 0.133 [0.122, 0.145] | 0.0173 | 0.041 | 0.105 |
| tracegate (th=0.46, FPR-matched to lev1) | 0.762 | 0.085 | 0.153 [0.142, 0.165] | 0.0320 | 0.026 | 0.141 |

### PyPI, time split

2630 test positives (361 labelled typosquat), 4973 test negatives; reference = top 5000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.673 | 0.013 | 0.025 [0.017, 0.033] | 0.0032 | 0.038 | 0.055 |
| lev1 (top-5k) | 0.365 | 0.036 | 0.066 [0.053, 0.078] | 0.0332 | 0.011 | 0.130 |
| typomania/TypoGard (top-5k) | 0.394 | 0.027 | 0.051 [0.039, 0.062] | 0.0219 | 0.012 | 0.100 |
| pypi-scan (top-50) | 0.867 | 0.010 | 0.019 [0.013, 0.027] | 0.0008 | 0.111 | 0.028 |
| pypi-scan (top-5k) | 0.385 | 0.031 | 0.058 [0.046, 0.070] | 0.0263 | 0.012 | 0.116 |
| tracegate (th=0.54) | 0.491 | 0.032 | 0.059 [0.047, 0.071] | 0.0173 | 0.018 | 0.116 |
| tracegate (th=0.46, FPR-matched to lev1) | 0.430 | 0.046 | 0.083 [0.068, 0.096] | 0.0320 | 0.014 | 0.161 |

### npm, hash split

109330 test positives (727 labelled typosquat), 4083 test negatives; reference = top 5000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.821 | 0.000 | 0.000 [0.000, 0.001] | 0.0012 | 0.002 | 0.001 |
| lev1 (top-5k) | 0.711 | 0.003 | 0.005 [0.004, 0.006] | 0.0272 | 0.001 | 0.010 |
| typomania/TypoGard (top-5k) | 0.694 | 0.003 | 0.005 [0.005, 0.006] | 0.0316 | 0.001 | 0.008 |
| pypi-scan (top-50) | 0.846 | 0.000 | 0.000 [0.000, 0.000] | 0.0005 | 0.002 | 0.001 |
| pypi-scan (top-5k) | 0.626 | 0.002 | 0.003 [0.003, 0.004] | 0.0255 | 0.001 | 0.007 |
| tracegate (th=0.52) | 0.745 | 0.002 | 0.004 [0.003, 0.004] | 0.0176 | 0.001 | 0.010 |
| tracegate (th=0.48, FPR-matched to lev1) | 0.752 | 0.003 | 0.005 [0.005, 0.006] | 0.0240 | 0.001 | 0.011 |

### npm, time split

201706 test positives (1473 labelled typosquat), 4083 test negatives; reference = top 5000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.896 | 0.000 | 0.000 [0.000, 0.001] | 0.0012 | 0.002 | 0.001 |
| lev1 (top-5k) | 0.798 | 0.002 | 0.004 [0.004, 0.005] | 0.0272 | 0.001 | 0.007 |
| typomania/TypoGard (top-5k) | 0.781 | 0.002 | 0.004 [0.004, 0.005] | 0.0316 | 0.001 | 0.008 |
| pypi-scan (top-50) | 0.917 | 0.000 | 0.000 [0.000, 0.000] | 0.0005 | 0.002 | 0.002 |
| pypi-scan (top-5k) | 0.739 | 0.002 | 0.003 [0.003, 0.003] | 0.0255 | 0.001 | 0.006 |
| tracegate (th=0.52) | 0.827 | 0.002 | 0.003 [0.003, 0.004] | 0.0176 | 0.001 | 0.009 |
| tracegate (th=0.48, FPR-matched to lev1) | 0.817 | 0.002 | 0.004 [0.004, 0.005] | 0.0240 | 0.001 | 0.011 |

### RubyGems, hash split

2086 test positives (0 labelled typosquat), 2479 test negatives; reference = top 5000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.984 | 0.119 | 0.213 [0.191, 0.236] | 0.0016 | 0.430 | 0.000 |
| lev1 (top-5k) | 0.601 | 0.041 | 0.077 [0.062, 0.093] | 0.0230 | 0.018 | 0.000 |
| typomania/TypoGard (top-5k) | 0.341 | 0.014 | 0.027 [0.018, 0.037] | 0.0226 | 0.006 | 0.000 |
| pypi-scan (top-50) | 0.987 | 0.035 | 0.069 [0.054, 0.085] | 0.0004 | 0.473 | 0.000 |
| pypi-scan (top-5k) | 0.667 | 0.040 | 0.076 [0.061, 0.092] | 0.0169 | 0.024 | 0.000 |
| tracegate (th=0.54) | 0.739 | 0.039 | 0.075 [0.060, 0.091] | 0.0117 | 0.033 | 0.000 |
| tracegate (th=0.46, FPR-matched to lev1) | 0.626 | 0.042 | 0.078 [0.063, 0.095] | 0.0210 | 0.020 | 0.000 |

On RubyGems the simplest baseline wins: the 14-name difflib check beats every top-5k detector, TRACEGATE included (F1 0.213 vs 0.075 on the hash split, 0.234 vs 0.074 on the time split; paired F1 difference vs Damerau-1 +0.115 to +0.156), because the `MAL-*` names there are floods of variants of a few top gems (mostly `bundler`). This is a result where TRACEGATE does worse.

### RubyGems, time split

3430 test positives (0 labelled typosquat), 2479 test negatives; reference = top 5000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.991 | 0.133 | 0.234 [0.216, 0.252] | 0.0016 | 0.456 | 0.000 |
| lev1 (top-5k) | 0.723 | 0.043 | 0.082 [0.069, 0.095] | 0.0230 | 0.019 | 0.000 |
| typomania/TypoGard (top-5k) | 0.495 | 0.016 | 0.031 [0.023, 0.039] | 0.0226 | 0.007 | 0.000 |
| pypi-scan (top-50) | 0.992 | 0.037 | 0.071 [0.059, 0.083] | 0.0004 | 0.481 | 0.000 |
| pypi-scan (top-5k) | 0.774 | 0.042 | 0.080 [0.067, 0.092] | 0.0169 | 0.025 | 0.000 |
| tracegate (th=0.58) | 0.910 | 0.038 | 0.074 [0.062, 0.086] | 0.0052 | 0.070 | 0.000 |
| tracegate (th=0.46, FPR-matched to lev1) | 0.743 | 0.044 | 0.083 [0.070, 0.096] | 0.0210 | 0.021 | 0.000 |

### crates.io, hash split

7 test positives (1 labelled typosquat), 2559 test negatives; reference = top 5000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.333 | 0.143 | 0.200 [0.000, 0.545] | 0.0008 | 0.643 | 1.000 |
| lev1 (top-5k) | 0.011 | 0.143 | 0.021 [0.000, 0.065] | 0.0348 | 0.040 | 1.000 |
| typomania/TypoGard (top-5k) | 0.014 | 0.143 | 0.026 [0.000, 0.080] | 0.0274 | 0.050 | 1.000 |
| pypi-scan (top-50) | 0.500 | 0.143 | 0.222 [0.000, 0.600] | 0.0004 | 0.783 | 1.000 |
| pypi-scan (top-5k) | 0.015 | 0.143 | 0.027 [0.000, 0.085] | 0.0254 | 0.054 | 1.000 |
| tracegate (th=0.68) | 0.250 | 0.143 | 0.182 [0.000, 0.533] | 0.0012 | 0.546 | 1.000 |
| tracegate (th=0.48, FPR-matched to lev1) | 0.015 | 0.143 | 0.027 [0.000, 0.083] | 0.0262 | 0.052 | 1.000 |

### crates.io, time split

15 test positives (6 labelled typosquat), 2559 test negatives; reference = top 5000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.500 | 0.133 | 0.210 [0.000, 0.455] | 0.0008 | 0.627 | 0.333 |
| lev1 (top-5k) | 0.011 | 0.067 | 0.019 [0.000, 0.062] | 0.0348 | 0.019 | 0.167 |
| typomania/TypoGard (top-5k) | 0.014 | 0.067 | 0.023 [0.000, 0.077] | 0.0274 | 0.024 | 0.167 |
| pypi-scan (top-50) | 0.500 | 0.067 | 0.118 [0.000, 0.333] | 0.0004 | 0.627 | 0.167 |
| pypi-scan (top-5k) | 0.015 | 0.067 | 0.025 [0.000, 0.083] | 0.0254 | 0.026 | 0.167 |
| tracegate (th=0.68) | 0.250 | 0.067 | 0.105 [0.000, 0.316] | 0.0012 | 0.360 | 0.167 |
| tracegate (th=0.48, FPR-matched to lev1) | 0.015 | 0.067 | 0.024 [0.000, 0.081] | 0.0262 | 0.025 | 0.167 |

No detector is useful on crates.io (7 and 15 test positives) or NuGet (CIs reach 0 for every detector).

### NuGet, hash split

377 test positives (0 labelled typosquat), 1509 test negatives; reference = top 1000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.111 | 0.003 | 0.005 [0.000, 0.016] | 0.0053 | 0.005 | 0.000 |
| lev1 (top-5k) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0040 | 0.000 | 0.000 |
| typomania/TypoGard (top-5k) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0080 | 0.000 | 0.000 |
| pypi-scan (top-50) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0000 | 0.000 | 0.000 |
| pypi-scan (top-5k) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0027 | 0.000 | 0.000 |
| tracegate (th=0.56) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0027 | 0.000 | 0.000 |
| tracegate (th=0.54, FPR-matched to lev1) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0027 | 0.000 | 0.000 |

### NuGet, time split

44 test positives (0 labelled typosquat), 1509 test negatives; reference = top 1000.

| Detector | P | R | F1 [95% CI] | FPR | P at 1% prevalence | R on typo-labelled |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mvp-difflib (14 names) | 0.273 | 0.068 | 0.109 [0.000, 0.226] | 0.0053 | 0.115 | 0.000 |
| lev1 (top-5k) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0040 | 0.000 | 0.000 |
| typomania/TypoGard (top-5k) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0080 | 0.000 | 0.000 |
| pypi-scan (top-50) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0000 | 0.000 | 0.000 |
| pypi-scan (top-5k) | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 0.0027 | 0.000 | 0.000 |
| tracegate (th=0.48) | 0.100 | 0.045 | 0.062 [0.000, 0.156] | 0.0119 | 0.037 | 0.000 |
| tracegate (th=0.54, FPR-matched to lev1) | 0.333 | 0.045 | 0.080 [0.000, 0.192] | 0.0027 | 0.145 | 0.000 |

### Single-technique ablation (PyPI, hash split, default threshold)

| Technique alone | R | FPR | F1 |
| --- | ---: | ---: | ---: |
| separator | 0.000 | 0.0004 | 0.000 |
| homoglyph | 0.000 | 0.0004 | 0.000 |
| typo1 | 0.070 | 0.0165 | 0.130 |
| typo2 | 0.001 | 0.0004 | 0.001 |
| reorder | 0.000 | 0.0000 | 0.001 |
| combosquat | 0.000 | 0.0000 | 0.001 |
| suffix | 0.002 | 0.0004 | 0.003 |
| brandjack | 0.000 | 0.0000 | 0.000 |

Edit distance 1 (`typo1`) carries almost all of the signal; the other techniques add a fraction of a point of recall. On this data TRACEGATE is close to a scored Damerau-1 check, which is why typosquat detection is a supporting component, not the novelty claim.

![Typosquat precision/recall, rendered from the typosquat_pypi/npm JSON of run 37003433022](img/typosquat_pr.png)

## Signing and admission

- [`results/sigstore_evidence.json`](https://github.com/rakshit-737/tracegate/blob/main/results/sigstore_evidence.json): the wheel and sdist of dev build `cfd215e` (`1.0.0.post0.dev11+gcfd215e`), signed keylessly with the `sigstore` workflow's GitHub OIDC identity; each Rekor entry fetched by logIndex and checked to record the artefact's sha256. The v1.1.0 release artefacts carry their own `*.sigstore.json` bundles on the [release page](https://github.com/rakshit-737/tracegate/releases/tag/v1.1.0); how to verify them is in [Security](security.md).
- [`results/kind_admission.json`](https://github.com/rakshit-737/tracegate/blob/main/results/kind_admission.json): in a kind cluster the signed image is admitted and Running; the unsigned one is denied by cosign (`no signatures found`); a third image with a valid keyless signature but signed provenance missing the build and scan stages passes cosign and is denied by `tracegate gate` (`missing signed provenance for stages ['build', 'scan']`).

## Real images: what the gate sees

Seven pinned official images are pulled as data (sha256-verified, never run) and scanned with real Syft and Trivy on the runner. Identity matters only against raw purl strings: Trivy and Syft spell the same package's purl differently (qualifiers, namespaces), while naive name@version matching and TRACEGATE's canonical purls both attach every finding on these images.

<!-- results:images -->
| Image | Syft pkgs | Layers | Trivy findings | matched, naive name@version | matched, raw purl string | matched, canonical purl | Syft/Trivy SBOM Jaccard |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| alpine:3.14.2 | 14 | 1 | 43 | 43 | 0 | 43 | 1.00 |
| httpd:2.4.49-alpine3.14 | 49 | 5 | 99 | 99 | 0 | 99 | 0.97 |
| memcached:1.6.10-alpine3.14 | 33 | 6 | 44 | 44 | 0 | 44 | 0.95 |
| nginx:1.21.3-alpine | 56 | 6 | 105 | 105 | 0 | 105 | 1.00 |
| node:14.17.6-alpine3.14 | 430 | 4 | 94 | 94 | 51 | 94 | 1.00 |
| python:3.9.7-alpine3.14 | 64 | 5 | 83 | 83 | 12 | 83 | 0.97 |
| redis:6.2.5-alpine3.14 | 32 | 6 | 43 | 43 | 0 | 43 | 0.94 |

All 511 Trivy rows: naive 100.0%, raw purl 12.3%, canonical 100.0%. Merged graph: 535 nodes, 637 edges; 219 unique finding nodes (146 CVEs), a 2.33x de-duplication; verdict `block`; 0 unattributed findings. Source: `results/images_real.json`, run [37088867445](https://github.com/rakshit-737/tracegate/actions/runs/37088867445).
<!-- /results:images -->

Warden (dependency-risk) scoring of the 401 language packages flags 3. One is `npm-cli-docs`: OSV has an all-versions MAL record for that public name, and npm bundles an internal package with the same name. The other two are typosquat-heuristic false positives on legitimate packages (`ansistyles`, `uid-number`). An earlier name-only MAL lookup flagged 13 more clean packages (`chalk 2.4.1`, `debug 3.1.0`, ...). The cause was the Sept-2025 npm hijack records, which list only the trojanised versions. The fix is covered in [ADR 0006](adr/0006-version-aware-malicious-package-matching.md).

## Scale (synthetic, for graph growth only)

<!-- results:scale -->
| Services | Deps | Events | Nodes | Edges | Gate median |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 50 | 41 | 104 | 562 | 0.004 s |
| 50 | 100 | 201 | 354 | 5,302 | 0.038 s |
| 100 | 200 | 401 | 704 | 20,602 | 0.132 s |
| 200 | 400 | 801 | 1,404 | 81,202 | 0.622 s |

Synthetic data; source `results/scale_synthetic.json`, run [37088867445](https://github.com/rakshit-737/tracegate/actions/runs/37088867445).
<!-- /results:scale -->
