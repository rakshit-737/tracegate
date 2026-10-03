# ADR 0005: How the real-data benchmarks are built

- Status: accepted
- Date: 2026-09-26

## Decisions

- **Typosquat detection.** Positives are OSV `MAL-*` package names (ossf/malicious-packages).
  Negatives are real packages ranked 5,001 to 15,000 by downloads (npm: the npm-high-impact list
  beyond its top 5,000), which are legitimate and not whitelisted. The reference list is the top
  5,000. A deterministic 50/50 split by sha256(name) gives a dev half for choosing thresholds and a
  test half for reporting. Candidate download counts are **not** used as a feature. They would
  separate the two classes trivially, because the negatives were chosen by popularity.
- **Backtracking.** The reference is `git blame --first-parent` on the pin's version line. It is
  computed by a different algorithm from TRACEGATE's diff-based lineage but shares the lock-file
  reader (which line holds a pin), so it measures agreement, not correctness. The baselines are
  "last manifest commit", "first pickaxe mention" and two `git log -S` pickaxes (package-specific
  token and version line). Every disagreement is stored with the commit subjects; a sample is
  adjudicated by reading the diffs, and a commit-message oracle (bot bumps, grouped bumps,
  reverts, re-bumps) checks attribution against labels that do not come from blame. *(Amended
  after v1.1.0; the first version called blame the ground truth.)*
- **Images.** Only official images, pinned, old, and Alpine-based: small downloads that share base
  layers and carry known CVEs. They are pulled as data with every blob checked against its sha256
  and are never run. On Windows, Syft's image source fails, so Syft scans each extracted layer
  (`dir:`). Its Windows dir scan also cannot detect the distro, so the driver rebuilds apk purls in
  Syft's own format. This workaround is recorded in the output (`descriptor.mode`).
- **What is synthetic.** The deploy manifests (one service per image) in the image benchmark, the
  single commit event in that benchmark, and the scale benchmark. Everything else comes from real
  tools run on real data.
