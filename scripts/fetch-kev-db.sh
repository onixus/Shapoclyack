#!/usr/bin/env bash
# Build a KEV (Known Exploited Vulnerabilities) overlay from the CISA feed.
#
# No API key required. CISA updates the catalog on an ongoing basis.
#   https://www.cisa.gov/known-exploited-vulnerabilities-catalog
#
# Output matches api/services/risk_scoring.py::_load_kev_set:
#   {"version":1,"source":"cisa-kev","updated":"<date>","entries":["CVE-…",…]}
#
# Mirror: KEV_URL names the same JSON anywhere else (https, http, or file://) —
# see docs/air-gap.md. Downloaded through scripts/feed_fetch.py, so
# OCTO_HTTPS_PROXY / OCTO_CA_BUNDLE apply (#339).
#
# Usage:
#   ./scripts/fetch-kev-db.sh                      # → scanner/data/kev/kev-overlay.json
#   ./scripts/fetch-kev-db.sh -o /data/kev/kev-overlay.json
#   KEV_URL=file:///mnt/mirror/kev/known_exploited_vulnerabilities.json ./scripts/fetch-kev-db.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="scanner/data/kev/kev-overlay.json"
URL="${KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading CISA KEV catalog…"
python3 "$HERE/feed_fetch.py" get "$URL" -o "$TMP/kev.json"

python3 - "$TMP/kev.json" "$OUT" "$URL" "$HERE" <<'PY'
import json, os, sys
from datetime import datetime, timezone

src, out, url = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, sys.argv[4])
from feed_fetch import redact_url
raw = json.load(open(src, encoding="utf-8"))
cves = []
for item in raw.get("vulnerabilities") or []:
    cve = item.get("cveID") or item.get("cve") or item.get("cve_id")
    if cve:
        cves.append(str(cve).upper())
cves = sorted(set(cves))

if not cves:
    print("error: parsed 0 KEV entries (feed format changed?)", file=sys.stderr)
    sys.exit(1)

os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
payload = {
    "version": 1,
    "source": "cisa-kev",
    "updated": str(raw.get("dateReleased") or "")[:10]
    or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    # Where these bytes came from, for the enrichment manifest and the offline
    # bundle (#339). Redacted: a mirror URL may carry credentials.
    "origin_url": redact_url(url),
    "entries": cves,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
    fh.write("\n")
print(f"wrote {len(cves)} KEV CVEs → {out} (released={payload['updated']})")
PY
