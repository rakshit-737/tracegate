#!/usr/bin/env bash
# End-to-end signed pipeline used by CI.
#   1. sign commit (lineage of a throwaway repo), build (Syft) and scan (Trivy) stage events
#      with an Ed25519 key generated in this job;
#   2. the gate with the matching public key must see every stage (no provenance_integrity);
#   3. one flipped payload byte must be rejected; a second keypair's public key must reject all.
# With KEYLESS=1 the public key is additionally bound to this workflow run by a Sigstore
# keyless signature (cosign sign-blob, GitHub OIDC, Rekor), and the gate verifies that bundle
# before trusting the key (TRACEGATE_PUBKEY_BUNDLE).
set -euo pipefail
W=$(mktemp -d)
tg() { python -m tracegate.cli "$@"; }

export TRACEGATE_KEYID=ci
tg keygen "$W/ci"
tg keygen "$W/other"

# a tiny application repo with a pinned manifest -> signed commit-stage events
git init -q "$W/app"
git -C "$W/app" -c user.name=ci -c user.email=ci@example.invalid commit -q --allow-empty -m init
printf 'requests==2.31.0\n' > "$W/app/requirements.txt"
git -C "$W/app" add requirements.txt
git -C "$W/app" -c user.name=ci -c user.email=ci@example.invalid commit -q -m "pin requests (#1)"
SHA=$(git -C "$W/app" rev-parse HEAD)

export TRACEGATE_SIGNING_KEY="$W/ci.key"
tg lineage "$W/app" requirements.txt -o "$W/commits.json"
tg ingest --syft tests/fixtures/alpine.syft.json --trivy tests/fixtures/alpine.trivy.json --commit "$SHA" -o "$W/img.json"
tg merge "$W/commits.json" "$W/img.json" -o "$W/all.json"
unset TRACEGATE_SIGNING_KEY

export TRACEGATE_PUBKEY="$W/ci.pub"
if [ "${KEYLESS:-0}" = 1 ]; then
  cosign sign-blob --yes --bundle "$W/ci.pub.sigstore.json" "$W/ci.pub" > /dev/null
  export TRACEGATE_PUBKEY_BUNDLE="$W/ci.pub.sigstore.json"
  export TRACEGATE_SIGSTORE_IDENTITY="^https://github.com/${GITHUB_REPOSITORY}/\.github/workflows/"
  cp "$W/ci.pub" "$W/ci.pub.sigstore.json" "${OUT_DIR:-.}/" 2>/dev/null || true
fi

tg export "$W/all.json" --format intoto > /dev/null
set +e
tg gate "$W/all.json" --comment > "$W/out.md" 2> "$W/err.txt"; rc=$?
set -e
cat "$W/out.md"
test "$rc" -le 1 || { cat "$W/err.txt"; exit 1; }
if grep -q provenance_integrity "$W/out.md"; then echo "signed pipeline should verify every stage"; exit 1; fi
if grep -q "failed verification" "$W/err.txt"; then echo "no envelope should be rejected"; exit 1; fi

# tamper: flip one payload byte -> rejected, gate blocks on integrity
python - "$W/all.json" "$W/tampered.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d[-1]["payload"] = d[-1]["payload"].replace('"', "'", 1)
json.dump(d, open(sys.argv[2], "w"))
PY
set +e; tg gate "$W/tampered.json" > "$W/t.out" 2>&1; rc=$?; set -e
test "$rc" -eq 1 && grep -q "failed verification" "$W/t.out"

# wrong trust root: a second keypair's public key -> every envelope rejected, exit 1
set +e
TRACEGATE_PUBKEY="$W/other.pub" TRACEGATE_PUBKEY_BUNDLE= tg gate "$W/all.json" > "$W/w.out" 2>&1; rc=$?
set -e
test "$rc" -eq 1 && grep -q "signature mismatch" "$W/w.out"

if [ "${KEYLESS:-0}" = 1 ]; then
  # a bundle checked against a different identity must not be trusted (fail closed, exit 2)
  set +e
  TRACEGATE_SIGSTORE_IDENTITY='^https://github.com/someone-else/' tg gate "$W/all.json" > "$W/i.out" 2>&1; rc=$?
  set -e
  test "$rc" -eq 2 && grep -q "Sigstore verification" "$W/i.out"
fi
echo "signed pipeline checks passed"
