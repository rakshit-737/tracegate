# Datasets

Nothing large is committed. `scripts/download_data.py` fetches everything into `$TRACEGATE_DATA` (default: a sibling `../../datasets/tracegate` if present, else `./data/`, which is git-ignored) and records a sha256 and a timestamp for each file in `MANIFEST.json`. Tool binaries are verified against the release checksums. The OSV dumps, popularity lists and blobless clones take about 1 GB; Syft, Trivy and the Trivy vulnerability DB (only for the image benchmark) add about 1.7 GB. The sha256 values of the committed run are in `results/data_manifest.json`.

| Data | Source | Size | Licence |
| --- | --- | --- | --- |
| OSV bulk dumps: PyPI, npm, Alpine (includes ossf/malicious-packages `MAL-*`) | `osv-vulnerabilities.storage.googleapis.com` | 244 MB | per source: OSV/GHSA/PyPA data CC-BY-4.0, malicious-packages Apache-2.0 |
| Top PyPI packages (30-day downloads) | hugovk/top-pypi-packages | 1 MB | see upstream repo |
| npm high-impact list | wooorm/npm-high-impact | <1 MB | MIT |
| Git history: healthchecks, netbox, pypi/warehouse (blobless clones) | GitHub | 79 MB | BSD-3 / Apache-2.0 / Apache-2.0 |
| 7 pinned official Docker images (pulled as data, sha256-verified, **never run**) | Docker Hub | 283 MB | per image |
| Syft 1.52.0, Trivy 0.74.0 binaries + Trivy DB | anchore/syft, aquasecurity/trivy | ~1.7 GB | Apache-2.0 |

Small fixtures derived from real tool output (`tests/fixtures/alpine.syft.json`, `alpine.trivy.json`, `osv_sample.json`) keep CI independent of the downloads.

## Citations

- OSV: *Open Source Vulnerabilities* schema and database, Google / OpenSSF, <https://osv.dev> (data CC-BY-4.0 per source).
- OpenSSF malicious-packages, <https://github.com/ossf/malicious-packages> (Apache-2.0).
- H. van Kemenade, *top-pypi-packages*, <https://github.com/hugovk/top-pypi-packages>.
- T. Wormer, *npm-high-impact*, <https://github.com/wooorm/npm-high-impact> (MIT).
- Anchore Syft, <https://github.com/anchore/syft>; Aqua Security Trivy, <https://github.com/aquasecurity/trivy> (Apache-2.0).
- Popularity lists for RubyGems (packages.ecosyste.ms), crates.io (crates.io API, by downloads) and NuGet (NuGet search API, by total downloads) are fetched by `scripts/download_data.py popular` inside the `benchmarks` workflow; they are names and download counts only.
- M. Taylor, R. Vaidya, D. Davidson, L. De Carli, V. Rastogi, *Defending Against Package Typosquatting*, NSS 2020 (arXiv [2003.03471](https://arxiv.org/abs/2003.03471)); <https://github.com/mt3443/typogard>; Rust Foundation <https://github.com/rustfoundation/typomania>; IQT Labs <https://github.com/IQTLabs/pypi-scan>.
