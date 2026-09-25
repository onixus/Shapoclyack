#!/usr/bin/env bash
# Refresh the Public Suffix List snapshot the scanner derives seed domains from.
#
# The scanner never fetches the list at run time -- it runs in restricted
# networks. It reads scanner/pipeline/public_suffix_list.dat, committed
# byte-for-byte as published, so refreshing is: run this, review the diff,
# commit. See scanner/pipeline/public_suffix.py for why the file sits there
# and not under scanner/data.
#   https://publicsuffix.org/list/
#
# Usage:
#   ./scripts/fetch-public-suffix-list.sh     # → scanner/pipeline/public_suffix_list.dat
#   ./scripts/fetch-public-suffix-list.sh -o /tmp/public_suffix_list.dat
set -euo pipefail

OUT="scanner/pipeline/public_suffix_list.dat"
# The list's own header asks to be pulled from this URL and no other.
URL="${PSL_URL:-https://publicsuffix.org/list/public_suffix_list.dat}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading the Public Suffix List…"
curl -fsSL "$URL" -o "$TMP/public_suffix_list.dat"

# A truncated download would quietly lose the private section -- github.io,
# herokuapp.com, com.ru -- which is exactly the part seed derivation needs.
# public_suffix.py refuses such a file at load time; refuse it here first.
for marker in "// VERSION:" "===END ICANN DOMAINS===" "===END PRIVATE DOMAINS==="; do
  if ! grep -qF -- "$marker" "$TMP/public_suffix_list.dat"; then
    echo "error: '$marker' not found in the download (truncated or format changed?)" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$OUT")"
mv "$TMP/public_suffix_list.dat" "$OUT"
echo "wrote $(grep -F -m1 '// VERSION:' "$OUT" | sed 's|^// ||') → $OUT"
