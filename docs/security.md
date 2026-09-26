# Security Policy

TRACEGATE is a portfolio and research MVP. Do not rely on it as your only supply-chain control.

- **Reporting:** open a private GitHub security advisory on this repository, or email the maintainer. Please do not file public issues for vulnerabilities.
- **Keys:** the demo key in `tracegate/synth.py` is public and is for demos only. Always set `TRACEGATE_KEYID` and `TRACEGATE_KEY` from a CI secret.
- **Scope:** the tool is defensive. It analyses metadata that your own pipeline emits. It has no scanning or exploitation capability against external systems.
- **Supported versions:** only the latest `main`.
