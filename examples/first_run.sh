#!/usr/bin/env bash
# AegisGrid first-run demo (safe local sandbox). Requires: pip install -e .
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Demo root: $TMP"
export AEGIS_MANIFEST_HMAC_KEY="${AEGIS_MANIFEST_HMAC_KEY:-demo-manifest-key-change-me}"

aegisgrid --root "$TMP" init
aegisgrid --root "$TMP" status
aegisgrid --root "$TMP" temperature set --value 4.0
aegisgrid --root "$TMP" threat add --indicator 198.51.100.9 --type scan --severity 6
aegisgrid --root "$TMP" threat list

echo "==> Demo complete. No files left in your repo (uses temp dir)."
