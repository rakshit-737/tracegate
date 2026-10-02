# Reproduce

Every published number comes from a script in `benchmarks/` and a JSON file in
[`results/`](https://github.com/rakshit-737/tracegate/tree/main/results). The full-data runs
execute in the [`benchmarks` workflow](https://github.com/rakshit-737/tracegate/actions/workflows/benchmarks.yml)
on a GitHub-hosted `ubuntu-latest` runner (4 vCPU, 16 GB RAM), which downloads the data,
runs every benchmark and uploads `results/` as an artefact; only the small JSON files are
committed. You can trigger it yourself with `gh workflow run benchmarks.yml` on a fork.

## Locally

Python 3.10+; about 1 GB of disk for OSV dumps, popularity lists and blobless clones
(plus about 1.7 GB if you also fetch Syft, Trivy and the Trivy DB for the image benchmark).

```bash
pip install -e ".[bench,osv,crypto]" numpy
export TRACEGATE_DATA=$HOME/tracegate-data          # anywhere outside the repo
python scripts/download_data.py osv                 # OSV dumps: PyPI, npm, Alpine, Go, crates.io, RubyGems, NuGet
python scripts/download_data.py popular             # top-N name lists per ecosystem
python scripts/download_data.py repos               # blobless clones of the 11 lineage repositories
```

| Step | Command | Writes | Key expected output |
| --- | --- | --- | --- |
| Typosquat, hash split | `python benchmarks/typosquat_eval.py --eco PyPI npm RubyGems crates.io NuGet` | `results/typosquat_<eco>.json`, `typosquat_pr.png` | one line per detector with P / R / F1 / FPR and the bootstrap F1 CI |
| Typosquat, time split | `python benchmarks/typosquat_eval.py --split time --eco PyPI npm RubyGems crates.io NuGet` | `results/typosquat_<eco>_time.json` | same table, tuned on MAL records published before 2025-01-01 |
| Lineage, HEAD sources | `python benchmarks/lineage_eval.py --snapshots 12` | `results/lineage_real_repos.json` | `TOTAL {"tracegate": {"correct": ..., "accuracy": ...}, ...}` |
| Lineage, per-snapshot sources | `python benchmarks/lineage_eval.py --snapshots 12 --materialize --repos healthchecks netbox warehouse` | `results/lineage_real_repos_materialized.json` | same, with `"materialize": true` |
| Images | `python scripts/download_data.py tools && python scripts/scan_real.py all && python benchmarks/images_eval.py` | `results/images_real.json` | 507 Trivy findings, 538 nodes |
| Scale (synthetic) | `python benchmarks/scale_eval.py --out /tmp/scale` | `scale_synthetic.json` | gate median per graph size |
| Sigstore | `sigstore` workflow (needs GitHub OIDC) | `results/sigstore_evidence.json` | Rekor logIndex per artefact |
| Admission | `kind-admission` workflow | `results/kind_admission.json` | signed allowed, unsigned denied |

Runtimes on the GitHub runner are in the workflow logs; the lineage history walk dominates
(about 3 minutes for pypi/warehouse, under 20 seconds for healthchecks and netbox).

## Live feeds

OSV dumps and popularity lists change daily, so a later re-run can shift finding counts and
typosquat numbers. `results/data_manifest.json` records the sha256 and fetch time of every
file the committed run used.
