#!/usr/bin/env sh
# Copy policies/ into the Python package. policies/ is the source of truth; the package ships a copy
# so that `pip install` works without the repository. tests/test_policy.py fails when they differ.
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
dest="$root/python/src/guardrail_rag_jev/policies"
mkdir -p "$dest/packs"
cp "$root/policies/standard-rag-v1.json" "$dest/"
cp "$root"/policies/packs/*.json "$dest/packs/"
echo "synced policies into $dest"
