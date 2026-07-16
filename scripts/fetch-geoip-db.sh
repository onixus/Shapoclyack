#!/usr/bin/env bash
# Download MaxMind GeoLite2-City MMDB for Octo-man GeoIP enrichment.
#
# Requires a free MaxMind license key:
#   https://www.maxmind.com/en/geolite2/signup
#
# Usage:
#   MAXMIND_LICENSE_KEY=xxxx ./scripts/fetch-geoip-db.sh
#   MAXMIND_LICENSE_KEY=xxxx ./scripts/fetch-geoip-db.sh -o scanner/data/geoip/GeoLite2-City.mmdb
set -euo pipefail

OUT="scanner/data/geoip/GeoLite2-City.mmdb"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
  echo "error: set MAXMIND_LICENSE_KEY" >&2
  exit 1
fi

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading GeoLite2-City…"
curl -fsSL "$URL" -o "$TMP/geolite.tar.gz"
tar -xzf "$TMP/geolite.tar.gz" -C "$TMP"
MMDB="$(find "$TMP" -name 'GeoLite2-City.mmdb' | head -n1)"
if [[ -z "$MMDB" ]]; then
  echo "error: GeoLite2-City.mmdb not found in archive" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
cp "$MMDB" "$OUT"
echo "Wrote $OUT"
echo "Update scanner config enrichment.geoip.database to: $OUT"
