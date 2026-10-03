# Datasets

Nothing large is committed. `scripts/download_data.py` fetches everything into `$TRACEGATE_DATA` (default: a sibling `../../datasets/tracegate` if present, else `./data/`, which is git-ignored) and records a sha256, size and fetch time for each file, and the head commit of each clone, in `MANIFEST.json`. Each benchmark leg copies that manifest into `results/` stamped with its run; `download_data.py repos --pin-from results/data_manifest.json` checks out the exact commits a committed run used. Tool binaries are verified against the release checksums. The OSV dumps, popularity lists and blobless clones take about 1 GB; Syft, Trivy and the Trivy vulnerability DB (only for the image benchmark) add about 1.7 GB.

<!-- results:datasets -->
| Data | Used by | Source | Size | Fetched (UTC) | sha256 / commit | Licence or terms |
| --- | --- | --- | ---: | --- | --- | --- |
| `osv/Alpine-all.zip` | backtracking, oracle (run 37091106360) | osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip | 4.0 MB | 2026-10-03T02:49 | `c3a745816d2c` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/Go-all.zip` | backtracking, oracle (run 37091106360) | osv-vulnerabilities.storage.googleapis.com/Go/all.zip | 12.0 MB | 2026-10-03T02:49 | `77bb6a0cb7bc` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/NuGet-all.zip` | backtracking, oracle (run 37091106360) | osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip | 2.5 MB | 2026-10-03T02:49 | `a58050f8574f` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/PyPI-all.zip` | backtracking, oracle (run 37091106360) | osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip | 35.4 MB | 2026-10-03T02:49 | `7c3a5ff9e05d` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/RubyGems-all.zip` | backtracking, oracle (run 37091106360) | osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip | 5.0 MB | 2026-10-03T02:49 | `11454ea786ae` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/crates.io-all.zip` | backtracking, oracle (run 37091106360) | osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip | 3.5 MB | 2026-10-03T02:49 | `a461c7e74e7a` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/npm-all.zip` | backtracking, oracle (run 37091106360) | osv-vulnerabilities.storage.googleapis.com/npm/all.zip | 217.4 MB | 2026-10-03T02:49 | `303a96ffacce` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `popular/npm-high-impact-top.js` | backtracking, oracle (run 37091106360) | raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js | 0.4 MB | 2026-10-03T02:49 | `bbc16e783283` | wooorm/npm-high-impact, MIT |
| `popular/top-pypi-packages.min.json` | backtracking, oracle (run 37091106360) | hugovk.dev/top-pypi-packages/top-pypi-packages.min.json | 0.8 MB | 2026-10-03T02:49 | `55fee05ed02b` | hugovk/top-pypi-packages (no licence file; public BigQuery download counts) |
| `repos/alacritty` | backtracking, oracle (run 37091106360) | github.com/alacritty/alacritty.git | blobless clone | 2026-10-03T02:50 | `d692748d3f61` | Apache-2.0 |
| `repos/bat` | backtracking, oracle (run 37091106360) | github.com/sharkdp/bat.git | blobless clone | 2026-10-03T02:50 | `4608fc959aa8` | MIT OR Apache-2.0 |
| `repos/caddy` | backtracking, oracle (run 37091106360) | github.com/caddyserver/caddy.git | blobless clone | 2026-10-03T02:50 | `ac834b5dc70a` | Apache-2.0 |
| `repos/excalidraw` | backtracking, oracle (run 37091106360) | github.com/excalidraw/excalidraw.git | blobless clone | 2026-10-03T02:50 | `ed10ac7dca7e` | MIT |
| `repos/healthchecks` | backtracking, oracle (run 37091106360) | github.com/healthchecks/healthchecks.git | blobless clone | 2026-10-03T02:49 | `e566e1c40099` | BSD-3-Clause |
| `repos/hugo` | backtracking, oracle (run 37091106360) | github.com/gohugoio/hugo.git | blobless clone | 2026-10-03T02:50 | `6b3ba3a7e22a` | Apache-2.0 |
| `repos/mastodon` | backtracking, oracle (run 37091106360) | github.com/mastodon/mastodon.git | blobless clone | 2026-10-03T02:51 | `73fe2b73467a` | AGPL-3.0 |
| `repos/netbox` | backtracking, oracle (run 37091106360) | github.com/netbox-community/netbox.git | blobless clone | 2026-10-03T02:49 | `251458b89a5e` | Apache-2.0 |
| `repos/ripgrep` | backtracking, oracle (run 37091106360) | github.com/BurntSushi/ripgrep.git | blobless clone | 2026-10-03T02:50 | `3fce3b5bb023` | Unlicense OR MIT |
| `repos/vue-core` | backtracking, oracle (run 37091106360) | github.com/vuejs/core.git | blobless clone | 2026-10-03T02:51 | `4ab865a848a1` | MIT |
| `repos/warehouse` | backtracking, oracle (run 37091106360) | github.com/pypi/warehouse.git | blobless clone | 2026-10-03T02:50 | `81b91d6b8199` | Apache-2.0 |
| `osv/Go-all.zip` | typosquat (run 37003433022) | osv-vulnerabilities.storage.googleapis.com/Go/all.zip | 12.0 MB | 2026-10-02T11:52 | `daba95c43d1d` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/PyPI-all.zip` | typosquat (run 37003433022) | osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip | 35.3 MB | 2026-10-02T11:52 | `f2248ff61726` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/RubyGems-all.zip` | typosquat (run 37003433022) | osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip | 5.0 MB | 2026-10-02T11:52 | `b4f202bd02af` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/crates.io-all.zip` | typosquat (run 37003433022) | osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip | 3.5 MB | 2026-10-02T11:52 | `cd0cdc315668` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `osv/npm-all.zip` | typosquat (run 37003433022) | osv-vulnerabilities.storage.googleapis.com/npm/all.zip | 217.3 MB | 2026-10-02T11:52 | `d5432a4ae379` | per source, mostly CC-BY-4.0 (OSV, GHSA, PyPA, Go); `MAL-*` records from ossf/malicious-packages, Apache-2.0 |
| `popular/crates-top.json` | typosquat (run 37003433022) | crates.io/api/v1/crates | 0.5 MB | 2026-10-02T11:54 | `3e53adbbe87d` | crates.io API (names and download counts; crates.io data access policy) |
| `popular/nuget-top.json` | typosquat (run 37003433022) | azuresearch-usnc.nuget.org/query | 0.2 MB | 2026-10-02T11:58 | `e85f38327093` | NuGet search API (names and download counts; nuget.org terms of use) |
| `popular/rubygems-top.json` | typosquat (run 37003433022) | packages.ecosyste.ms/api/v1/registries/rubygems.org/packages | 0.5 MB | 2026-10-02T11:58 | `a0212eace429` | packages.ecosyste.ms (data CC BY-SA 4.0) |
| `bin/syft_1.52.0_linux_amd64.tar.gz` | images (run 37088867445) | github.com/anchore/syft/releases/download/v1.52.0/syft_1.52.0_linux_amd64.tar.gz | 29.3 MB | 2026-10-03T02:10 | `caeedb81fb04` | anchore/syft release, Apache-2.0 |
| `bin/trivy_0.74.0_Linux-64bit.tar.gz` | images (run 37088867445) | github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz | 50.4 MB | 2026-10-03T02:10 | `2ae6fe3ee734` | aquasecurity/trivy release, Apache-2.0 |

Rendered from `results/data_manifest.json`, `data_manifest_typosquat.json` and `data_manifest_images.json`; the 7 Docker images are pulled by tag and sha256-verified by `scripts/pull_image.py` and never run. The Trivy vulnerability DB is a live feed and its version is not pinned.
<!-- /results:datasets -->

Small fixtures derived from real tool output (`tests/fixtures/alpine.syft.json`, `alpine.trivy.json`, `osv_sample.json`) keep CI independent of the downloads.

## Citations

- OSV: *Open Source Vulnerabilities* schema and database, Google / OpenSSF, <https://osv.dev> (data CC-BY-4.0 per source).
- OpenSSF malicious-packages, <https://github.com/ossf/malicious-packages> (Apache-2.0).
- H. van Kemenade, *top-pypi-packages*, <https://github.com/hugovk/top-pypi-packages>.
- T. Wormer, *npm-high-impact*, <https://github.com/wooorm/npm-high-impact> (MIT).
- Anchore Syft, <https://github.com/anchore/syft>; Aqua Security Trivy, <https://github.com/aquasecurity/trivy> (Apache-2.0).
- Popularity lists for RubyGems (packages.ecosyste.ms), crates.io (crates.io API, by downloads) and NuGet (NuGet search API, by total downloads) are fetched by `scripts/download_data.py popular` inside the `benchmarks` workflow; they are names and download counts only.
- M. Taylor, R. Vaidya, D. Davidson, L. De Carli, V. Rastogi, *Defending Against Package Typosquatting*, NSS 2020 (arXiv [2003.03471](https://arxiv.org/abs/2003.03471)); <https://github.com/mt3443/typogard>; Rust Foundation <https://github.com/rustfoundation/typomania>; IQT Labs <https://github.com/IQTLabs/pypi-scan>.
- J. Śliwerski, T. Zimmermann, A. Zeller, *When do changes induce fixes?*, MSR 2005 (SZZ).
- S. Kim, T. Zimmermann, K. Pan, E. J. Whitehead, *Automatic Identification of Bug-Introducing Changes*, ASE 2006 (AG-SZZ).
- D. A. da Costa, S. McIntosh, W. Shang, U. Kulesza, R. Coelho, A. E. Hassan, *A Framework for Evaluating the Results of the SZZ Approach for Identifying Bug-Introducing Changes*, IEEE TSE 2017 (MA-SZZ).
- G. Rosa, L. Pascarella, S. Scalabrino, R. Tufano, G. Bavota, M. Lanza, R. Oliveto, *Evaluating SZZ Implementations Through a Developer-informed Oracle*, ICSE 2021 (arXiv [2102.03300](https://arxiv.org/abs/2102.03300)).
- Y. Lyu, H. J. Kang, R. Widyasari, J. Lawall, D. Lo, *Evaluating SZZ Implementations: An Empirical Study on the Linux Kernel*, IEEE TSE (arXiv [2308.05060](https://arxiv.org/abs/2308.05060)).
- I. Pashchenko, H. Plate, S. E. Ponta, A. Sabetta, F. Massacci, *Vulnerable Open Source Dependencies: Counting Those That Matter*, ESEM 2018 (arXiv [1808.09753](https://arxiv.org/abs/1808.09753)).
