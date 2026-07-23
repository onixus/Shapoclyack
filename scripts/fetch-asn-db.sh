#!/usr/bin/env bash
# Download an ASN MMDB for Shapoclyack ASN/org enrichment (attack-surface graph).
#
# Sources:
#   --provider maxmind  (default) MaxMind GeoLite2-ASN — needs MAXMIND_LICENSE_KEY
#                       https://www.maxmind.com/en/geolite2/signup
#   --provider dbip     DB-IP ASN Lite (CC BY 4.0) — no key; attribute https://db-ip.com
#
# Usage:
#   MAXMIND_LICENSE_KEY=xxxx ./scripts/fetch-asn-db.sh
#   ./scripts/fetch-asn-db.sh --provider dbip -o scanner/data/asn/asn.mmdb
set -euo pipefail

PROVIDER="maxmind"
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT="$2"; shift 2 ;;
    --provider) PROVIDER="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ "$PROVIDER" == "dbip" ]]; then
  OUT="${OUT:-scanner/data/asn/dbip-asn-lite.mmdb}"
  YM="$(date -u +%Y-%m)"
  URL="https://download.db-ip.com/free/dbip-asn-lite-${YM}.mmdb.gz"
  echo "Downloading DB-IP ASN Lite (${YM})…"
  if ! curl -fsSL "$URL" -o "$TMP/dbip.mmdb.gz"; then
    YM="$(python3 -c "from datetime import date; d=date.today().replace(day=1); m=d.month-1 or 12; y=d.year if d.month>1 else d.year-1; print(f'{y:04d}-{m:02d}')")"
    URL="https://download.db-ip.com/free/dbip-asn-lite-${YM}.mmdb.gz"
    echo "Retry previous month ${YM}…"
    curl -fsSL "$URL" -o "$TMP/dbip.mmdb.gz"
  fi
  gzip -dc "$TMP/dbip.mmdb.gz" > "$TMP/dbip.mmdb"
  MMDB="$TMP/dbip.mmdb"
elif [[ "$PROVIDER" == "maxmind" ]]; then
  OUT="${OUT:-scanner/data/asn/GeoLite2-ASN.mmdb}"
  if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
    echo "error: set MAXMIND_LICENSE_KEY (or use --provider dbip)" >&2
    exit 1
  fi
  URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
  echo "Downloading GeoLite2-ASN…"
  curl -fsSL "$URL" -o "$TMP/geolite.tar.gz"
  tar -xzf "$TMP/geolite.tar.gz" -C "$TMP"
  MMDB="$(find "$TMP" -name 'GeoLite2-ASN.mmdb' | head -n1)"
  if [[ -z "$MMDB" ]]; then
    echo "error: GeoLite2-ASN.mmdb not found in archive" >&2
    exit 1
  fi
else
  echo "error: unknown provider '$PROVIDER' (maxmind|dbip)" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUT")"
cp "$MMDB" "$OUT"
echo "Wrote $OUT"
echo "Update scanner config enrichment.asn.database to: $OUT"
