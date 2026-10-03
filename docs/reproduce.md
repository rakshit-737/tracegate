# Reproduce

Every published number comes from a script in `benchmarks/` and a JSON file in
[`results/`](https://github.com/rakshit-737/tracegate-cicd-security-gate/tree/main/results); each file records the
GitHub Actions run (or, for local files, the command and commit) that produced it, and the
[Evaluation](evaluation.md) page lists them. The full-data runs execute in the
[`benchmarks` workflow](https://github.com/rakshit-737/tracegate-cicd-security-gate/actions/workflows/benchmarks.yml)
on GitHub-hosted `ubuntu-latest` runners (4 vCPU, 16 GB RAM). Its inputs choose the legs, which
run in parallel; each leg downloads its own data and uploads `results/` plus its log:

```bash
gh workflow run benchmarks.yml -f lineage=true -f legs='["lineage", "oracle", "materialized"]' \
  -f typosquat=true -f images=true
```

## Locally

Python 3.10+; about 1 GB of disk for OSV dumps, popularity lists and blobless clones
(plus about 1.7 GB if you also fetch Syft, Trivy and the Trivy DB for the image benchmark).

```bash
pip install -e ".[bench,osv,crypto]" numpy
export TRACEGATE_DATA=$HOME/tracegate-data          # anywhere outside the repo
python scripts/download_data.py osv                 # OSV dumps: PyPI, npm, Alpine, Go, crates.io, RubyGems, NuGet
python scripts/download_data.py popular             # top-N name lists per ecosystem (--only pypi npm for lineage)
python scripts/download_data.py repos --pin-from results/data_manifest.json   # the 11 repos at the committed run's commits
```

| Step | Command | Writes | Key expected output | Runtime on the runner |
| --- | --- | --- | --- | --- |
| Backtracking, multi-version readers | `python benchmarks/lineage_eval.py --snapshots 12` | `results/lineage_real_repos.json` | `TOTAL {"tracegate": ..., "pickaxe-package-specific": ...}` | 40 min 10 s |
| Backtracking, old one-version readers (same data) | `python benchmarks/lineage_eval.py --snapshots 12 --single-version` | `results/lineage_real_repos_single_version.json` | same, tracegate and baselines without pickaxes | 24 min 6 s |
| Adjudication evidence | `python benchmarks/adjudicate.py --evidence`, then verdicts by hand, then `--score` | `results/lineage_adjudication_evidence.json`, `lineage_adjudication.json` | one record per sampled disagreement | 7 s |
| Commit-message oracle | `python benchmarks/lineage_eval.py --oracle-only` | `results/lineage_bot_bump_oracle.json` | one `[oracle <repo>]` line per repository, then `ORACLE {...}` | 8 min 49 s |
| Reachability, per-snapshot sources | `python benchmarks/lineage_eval.py --snapshots 12 --materialize --repos healthchecks netbox warehouse` | `results/lineage_real_repos_materialized.json` | `high+=... -> actionable=...` per repo | 2 min 46 s |
| Reachability audit | `python benchmarks/reach_audit.py --evidence`, verdicts by hand, `--score` (needs pypi.org for release metadata) | `results/reachability_audit.json` | false-`unreached` rate with exact interval | a few minutes locally |
| Typosquat, hash split | `python benchmarks/typosquat_eval.py --eco PyPI npm RubyGems crates.io NuGet --dump ../dump` | `results/typosquat_<eco>.json`, `typosquat_pr.png` | P / R / F1 / FPR per detector with bootstrap CIs | 7 min 26 s (run 37003433022) |
| Typosquat, time split | add `--split time` | `results/typosquat_<eco>_time.json` | same table, tuned on MAL records published before 2025-01-01 | 7 min 34 s |
| Original TypoGard / typomania | fetch `typogard_npm.py` at `9c10636`, build typomania `registry` at `10e27e8` (see `benchmarks.yml`), then `python benchmarks/originals_eval.py --dump ../dump --typogard ... --typomania ...` | `results/typosquat_originals.json` | flag agreement port vs original per split | 3 min 27 s |
| Redraw the PR figure from committed JSON | `python benchmarks/typosquat_eval.py --plot-only` | `results/typosquat_pr.png` | the figure, labelled with its source run | seconds |
| Images | `python scripts/download_data.py tools && trivy image --download-db-only --cache-dir $TRACEGATE_DATA/trivy-cache && python scripts/scan_real.py images && python benchmarks/images_eval.py` | `results/images_real.json` | per-image Syft/Trivy counts, identity convergence | 1 min 19 s (pull + scan 61 s, benchmark 18 s, downloads 11 s) |
| Scale (synthetic) | `python benchmarks/scale_eval.py` | `results/scale_synthetic.json` | gate median per graph size | 3 s |
| Sigstore | `sigstore` workflow (needs GitHub OIDC) | `results/sigstore_evidence.json` | Rekor logIndex per artefact | - |
| Admission | `kind-admission` workflow | `results/kind_admission.json` | signed allowed, unsigned and incomplete-provenance denied | - |
| Result tables in README and docs | `python scripts/render_results.py --write` (CI runs `--check`) | marked blocks in `README.md`, `docs/*.md` | `rendered result blocks in ...` | seconds |
| Docs site | `python scripts/build_static_demo.py && mkdocs build --strict` | `site/` | the demo needs the first step (it writes `docs/demo/data/`, git-ignored) | about 1 min |

Cloning the 11 repositories at their pinned commits takes about 2.5 minutes per leg. Runtimes are wall-clock step times in run [37091106360](https://github.com/rakshit-737/tracegate-cicd-security-gate/actions/runs/37091106360) (lineage, oracle and reachability legs), run
[37088867445](https://github.com/rakshit-737/tracegate-cicd-security-gate/actions/runs/37088867445) (images and scale) and run 37003433022 (typosquat). The longest step is the
multi-version backtracking leg: mastodon's yarn.lock history makes thousands of `git log -S`
pickaxe calls over a 15,000-line file.

## Live feeds

OSV dumps, popularity lists and the Trivy DB change daily, so a later re-run can shift finding
counts and typosquat numbers. Every leg stamps the dataset manifest it used into `results/`
(`data_manifest.json`, `data_manifest_typosquat.json`, `data_manifest_images.json`) with the
sha256 and fetch time of each file and the commit of each clone.
