#!/usr/bin/env bash
# Download an ASN MMDB for Shapoclyack ASN/org enrichment (attack-surface graph).
#
# Sources:
#   --provider maxmind  (default) MaxMind GeoLite2-ASN — needs MAXMIND_LICENSE_KEY
#                       https://www.maxmind.com/en/geolite2/signup
#   --provider dbip     DB-IP ASN Lite (CC BY 4.0) — no key; attribute https://db-ip.com
#
# Mirror (#339): ASN_URL names the database anywhere else — the .mmdb itself, a
# DB-IP-style .mmdb.gz or a MaxMind-style .tar.gz, over https, http or file://.
# With it set no monthly file name is guessed and no licence key is sent; the
# provider only says whose data it is. Downloads go through scripts/feed_fetch.py
# (OCTO_HTTPS_PROXY / OCTO_CA_BUNDLE apply), and whatever arrives must hold a
# MaxMind DB or nothing is written. See docs/air-gap.md.
#
# Usage:
#   MAXMIND_LICENSE_KEY=xxxx ./scripts/fetch-asn-db.sh
#   ./scripts/fetch-asn-db.sh --provider dbip -o scanner/data/asn/asn.mmdb
#   ASN_URL=https://mirror.internal/geo/dbip-asn-lite.mmdb.gz ./scripts/fetch-asn-db.sh -o scanner/data/asn/asn.mmdb
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER="maxmind"
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT="$2"; shift 2 ;;
    --provider) PROVIDER="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,19p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() { python3 "$HERE/feed_fetch.py" get "$1" -o "$TMP/download"; }

EDITION=""
if [[ "$PROVIDER" != "dbip" && "$PROVIDER" != "maxmind" ]]; then
  echo "error: unknown provider '$PROVIDER' (maxmind|dbip)" >&2
  exit 2
fi
if [[ -n "${ASN_URL:-}" ]]; then
  OUT="${OUT:-scanner/data/asn/asn.mmdb}"
  echo "Downloading ASN (${PROVIDER} data) from the configured mirror…"
  fetch "$ASN_URL"
elif [[ "$PROVIDER" == "dbip" ]]; then
  OUT="${OUT:-scanner/data/asn/dbip-asn-lite.mmdb}"
  YM="$(date -u +%Y-%m)"
  echo "Downloading DB-IP ASN Lite (${YM})…"
  if ! fetch "https://download.db-ip.com/free/dbip-asn-lite-${YM}.mmdb.gz"; then
    YM="$(python3 -c "from datetime import date; d=date.today().replace(day=1); m=d.month-1 or 12; y=d.year if d.month>1 else d.year-1; print(f'{y:04d}-{m:02d}')")"
    echo "Retry previous month ${YM}…"
    fetch "https://download.db-ip.com/free/dbip-asn-lite-${YM}.mmdb.gz"
  fi
else
  OUT="${OUT:-scanner/data/asn/GeoLite2-ASN.mmdb}"
  if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
    echo "error: set MAXMIND_LICENSE_KEY (or use --provider dbip, or ASN_URL for a mirror)" >&2
    exit 1
  fi
  EDITION="GeoLite2-ASN"
  echo "Downloading GeoLite2-ASN…"
  fetch "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
fi

# Unpacked and validated in Python rather than with `tar -x`: only a regular
# *.mmdb member is ever read out of a tarball, nothing is extracted by name, and
# a download that is not a MaxMind DB (an HTML error page answered with 200)
# is refused instead of replacing a working database.
python3 "$HERE/feed_fetch.py" mmdb "$TMP/download" -o "$OUT" ${EDITION:+--edition "$EDITION"}
echo "Wrote $OUT"
echo "Update scanner config enrichment.asn.database to: $OUT"
