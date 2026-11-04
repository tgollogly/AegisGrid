#!/usr/bin/env bash
# AegisGrid first-run demo (safe local sandbox). Requires: pip install -e .
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if command -v aegisgrid >/dev/null 2>&1; then
  AG=(aegisgrid)
else
  AG=(python3 -m cli)
fi

echo "==> Demo root: $TMP"
export AEGIS_MANIFEST_HMAC_KEY="${AEGIS_MANIFEST_HMAC_KEY:-demo-manifest-key-change-me}"

"${AG[@]}" --root "$TMP" init
"${AG[@]}" --root "$TMP" status
"${AG[@]}" --root "$TMP" temperature set --value 4.0
"${AG[@]}" --root "$TMP" threat add --indicator 198.51.100.9 --type scan --severity 6
"${AG[@]}" --root "$TMP" threat list

echo "==> Demo complete. No files left in your repo (uses temp dir)."
