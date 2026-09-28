#!/usr/bin/env bash
# Build a CVE → EPSS overlay from the FIRST.org "current" EPSS feed.
#
# No API key required. EPSS is refreshed daily by FIRST.org.
#   https://www.first.org/epss/  (CC BY 4.0 — attribute FIRST.org)
#
# Output matches api/services/risk_scoring.py::_load_cve_float_map:
#   {"version":1,"source":"first-epss","updated":"<date>","entries":{"CVE-…":0.97,…}}
#
# Mirror: EPSS_URL names the same .csv.gz anywhere else (https, http, or file://
# for a mounted directory) — see docs/air-gap.md. Downloaded through
# scripts/feed_fetch.py, so OCTO_HTTPS_PROXY / OCTO_CA_BUNDLE apply (#339).
#
# Usage:
#   ./scripts/fetch-epss-db.sh                       # → scanner/data/epss/epss-overlay.json
#   ./scripts/fetch-epss-db.sh -o /data/epss/epss-overlay.json
#   EPSS_URL=https://mirror.internal/epss/epss_scores-current.csv.gz ./scripts/fetch-epss-db.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="scanner/data/epss/epss-overlay.json"
URL="${EPSS_URL:-https://epss.cyentia.com/epss_scores-current.csv.gz}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading EPSS scores…"
python3 "$HERE/feed_fetch.py" get "$URL" -o "$TMP/epss.csv.gz"
gzip -dc "$TMP/epss.csv.gz" > "$TMP/epss.csv"

python3 - "$TMP/epss.csv" "$OUT" "$URL" "$HERE" <<'PY'
import csv, json, sys
from datetime import datetime, timezone

src, out, url = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, sys.argv[4])
from feed_fetch import redact_url
entries: dict[str, float] = {}
score_date = ""
with open(src, newline="", encoding="utf-8") as fh:
    for row in csv.reader(fh):
        if not row:
            continue
        first = row[0].strip()
        if first.startswith("#"):
            # Metadata line: #model_version:v2023.03.01,score_date:2024-04-01T00:00:00+0000
            for part in ",".join(row).lstrip("#").split(","):
                if part.startswith("score_date:"):
                    score_date = part.split(":", 1)[1].strip()[:10]
            continue
        if first.lower() == "cve":  # header row
            continue
        try:
            entries[first.upper()] = round(float(row[1]), 6)
        except (IndexError, ValueError):
            continue

if not entries:
    print("error: parsed 0 EPSS entries (feed format changed?)", file=sys.stderr)
    sys.exit(1)

import os
os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
payload = {
    "version": 1,
    "source": "first-epss",
    "updated": score_date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    # Where these bytes came from, for the enrichment manifest and the offline
    # bundle (#339). Redacted: a mirror URL may carry credentials.
    "origin_url": redact_url(url),
    "entries": entries,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
    fh.write("\n")
print(f"wrote {len(entries)} EPSS entries → {out} (score_date={payload['updated']})")
PY
