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
- **Backtracking.** The ground truth is `git blame --first-parent` on the pin line, which is
  computed independently of TRACEGATE's diff-based lineage. The baselines are "last manifest
  commit" and "first pickaxe mention". Any disagreement is listed with the commit subject so it can
  be judged by hand.
- **Images.** Only official images, pinned, old, and Alpine-based: small downloads that share base
  layers and carry known CVEs. They are pulled as data with every blob checked against its sha256
  and are never run. On Windows, Syft's image source fails, so Syft scans each extracted layer
  (`dir:`). Its Windows dir scan also cannot detect the distro, so the driver rebuilds apk purls in
  Syft's own format. This workaround is recorded in the output (`descriptor.mode`).
- **What is synthetic.** The deploy manifests (one service per image) in the image benchmark, the
  single commit event in that benchmark, and the scale benchmark. Everything else comes from real
  tools run on real data.
