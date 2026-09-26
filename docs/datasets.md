# Datasets

Nothing large is committed. `scripts/download_data.py` fetches everything into `$TRACEGATE_DATA` (default: a sibling `../../datasets/tracegate` if present, else `./data/`, which is git-ignored) and records a sha256 and a timestamp for each file in `MANIFEST.json`. Tool binaries are verified against the release checksums. The total is about 2.8 GB, of which about 1.4 GB is the Trivy vulnerability DB.

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

- OSV: *Open Source Vulnerabilities* schema and database, Google / OpenSSF, https://osv.dev (data CC-BY-4.0 per source).
- OpenSSF malicious-packages, https://github.com/ossf/malicious-packages (Apache-2.0).
- H. van Kemenade, *top-pypi-packages*, https://github.com/hugovk/top-pypi-packages.
- T. Wormer, *npm-high-impact*, https://github.com/wooorm/npm-high-impact (MIT).
- Anchore Syft, https://github.com/anchore/syft; Aqua Security Trivy, https://github.com/aquasecurity/trivy (Apache-2.0).
