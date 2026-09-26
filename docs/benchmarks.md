# Benchmarks and results

All numbers below come from the committed runs in [`results/`](https://github.com/rakshit-737/tracegate/tree/main/results). You can reproduce them with the commands in [Reproducibility](getting-started.md#reproducibility).

| Question | Data | TRACEGATE | Best baseline |
| --- | --- | --- | --- |
| Finding -> introducing commit (backtrack accuracy) | 365 pinned packages over 36 historical snapshots of 3 real repos (healthchecks, netbox, pypi/warehouse) | **97.5%** (356/365) | 17.3% "last manifest commit"; 9.3% "first pickaxe mention"; 0% scanner-only |
| Cross-tool identity (Trivy finding -> Syft SBOM node) | 507 Trivy findings on 7 real official images | **100%** matched | 100% with naive `name@version`; 11.6% with raw purl string equality |
| Reachability: how many high/critical findings stay actionable | 829 high+ OSV findings across the same 36 snapshots | **704 actionable (-15.1%)** | 829 (raw scanner output) |
| Typosquat detection, PyPI (test half) | 5,952 OSV `MAL-*` names vs 4,969 legitimate packages ranked 5k-15k | P **0.84** / FPR **1.7%** (th 0.54); F1 **0.159** at matched FPR | Levenshtein <= 1: P 0.75 / FPR 3.3%, F1 0.153 |
| Base-image blast radius | 7 official Alpine-3.14 images | 1 shared base layer -> 7 images / 7 services; 43 findings in that layer; each OpenSSL CVE reaches 7 services | n/a (per-image scanners report the same CVE 7 times) |
| Gate latency | real graphs | median 37 ms (healthchecks), 70 ms (netbox), 448 ms (warehouse, 184 pins), 72 ms (7-image graph, 538 nodes) | — |

What the numbers mean, stated plainly:

- **Backtracking is the strongest result.** The ground truth is `git blame --first-parent` on the pin line, which is computed independently of TRACEGATE's diff-based lineage walk. The 9 disagreements are listed in `results/lineage_real_repos.json`, and they fall into two groups:

- 3 are merge commits (`Merge pull request #1044 ...`). Blame credits the merge, while TRACEGATE credits the commit on the branch that changed the pin. Both answers can be defended.
- 6 are cases where blame credits a later commit that *rewrote the line without changing the version* (for example, `Bump boto3 ... (#4934)` re-emitted the hashes for `celery`, `jinja2` and `mako`). TRACEGATE tracks version changes, not text changes, so its answer is arguably the right one.
- **Cross-tool identity is table stakes on these images, not a win over every baseline.** A naive `name@version` join also matches all 507 findings on these images. The canonical purl only beats raw purl string equality (Syft and Trivy emit different qualifiers). Its value is that the same key merges manifest, Syft and Trivy nodes and keeps ecosystems apart, which a bare `name@version` join cannot guarantee.
- **Reachability cuts about 15% of high/critical alerts, but there is no exploitability ground truth.** On the netbox snapshots, the downgraded findings include `pycrypto`, `paramiko` and `ecdsa` pins that the app never imports. Older snapshots are analysed against HEAD sources, which is an approximation and is flagged in the output. At netbox HEAD, 6 of 45 pins are "unreached". Four of them (mkdocs*, django-rich) are correctly docs/dev-only. `tablib` is probably a miss: netbox's own code never imports it, so it is most likely loaded by django-tables2's export feature, and the `# via` data needed to see that edge is not in netbox's plain `requirements.txt`.
- **Typosquat recall is low for every detector.** This is expected: most `MAL-*` records are random names, dependency-confusion names or spam, not look-alikes of popular packages. On the subset whose advisory text says "typosquat", recall is 10.5% at the default threshold and 14.1% at matched FPR. TRACEGATE's advantage over plain Levenshtein is **half the false-positive rate for about the same F1**. It is not a big recall gain. On npm, all detectors are near zero recall (F1 0.005), because the npm `MAL-*` set (~109k names) is mostly spam.

![Typosquat precision/recall on real OSV malicious-package names](img/typosquat_pr.png)

### Real images: what the gate sees

| Image | Syft pkgs | Layers | Trivy findings | Matched to SBOM node | Syft/Trivy SBOM Jaccard |
| --- | ---: | ---: | ---: | ---: | ---: |
| alpine:3.14.2 | 15 | 1 | 43 | 43 | 0.93 |
| httpd:2.4.49-alpine3.14 | 36 | 5 | 99 | 99 | 0.94 |
| memcached:1.6.10-alpine3.14 | 20 | 6 | 44 | 44 | 0.90 |
| nginx:1.21.3-alpine | 45 | 6 | 105 | 105 | 0.93 |
| node:14.17.6-alpine3.14 | 417 | 4 | 90 | 90 | 0.995 |
| python:3.9.7-alpine3.14 | 51 | 5 | 83 | 83 | 0.95 |
| redis:6.2.5-alpine3.14 | 19 | 6 | 43 | 43 | 0.89 |

When the 7 images are merged into one graph, the result has 538 nodes and 556 edges. The 507 per-image Trivy rows collapse into 215 unique finding nodes (142 unique CVEs), a 2.4x de-duplication. The gate verdict is `block`.

Warden (dependency-risk) scoring of the 401 language packages flags 3. One is `npm-cli-docs`: OSV has an all-versions MAL record for that public name, and npm bundles an internal package with the same name. The other two are typosquat-heuristic false positives on legitimate packages (`ansistyles`, `uid-number`). An earlier name-only MAL lookup flagged 13 more clean packages (`chalk 2.4.1`, `debug 3.1.0`, ...). The cause was the Sept-2025 npm hijack records, which list only the trojanised versions. The fix is covered in [ADR 0006](adr/0006-version-aware-malicious-package-matching.md).

### Scale (synthetic, for graph growth only)

| Services | Deps | Events | Nodes | Edges | Gate median |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 50 | 41 | 104 | 562 | 0.014 s |
| 50 | 100 | 201 | 354 | 5,302 | 0.17 s |
| 100 | 200 | 401 | 704 | 20,602 | 0.55 s |
| 200 | 400 | 801 | 1,404 | 81,202 | 1.63 s |