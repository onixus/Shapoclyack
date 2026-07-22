#!/usr/bin/env bash
# Refresh scipag/vulscan's offline CVE/vulnerability databases, used by the
# "vuln-offline" NSE profile (scanner/config/default.yaml) for fully offline
# CVE matching — no vulners.com/internet dependency at scan time.
#
# vulscan.nse auto-discovers every *.csv already present in its own install
# directory (no --script-args needed), so refreshing the CSVs in place is
# enough; nothing else has to be reconfigured.
#
# The Dockerfile/Dockerfile.allinone clone vulscan pinned to a specific git
# commit for reproducible builds — which also freezes these CSVs at whatever
# vulscan's maintainers had bundled at that commit. This mirrors vulscan's own
# update.sh (https://github.com/scipag/vulscan), fetching the same
# computec.ch-published CSVs with curl instead of wget and per-database
# non-fatal error handling (one feed being down doesn't block the others,
# matching scripts/fetch-enrichment.sh's philosophy) so a build/refresh never
# fails outright — it just keeps whatever CSV was already there.
#
# Usage:
#   ./scripts/fetch-vulscan-db.sh                             # -> /usr/share/nmap/scripts/vulscan
#   ./scripts/fetch-vulscan-db.sh -o /path/to/vulscan/dir
set -uo pipefail

OUT="/usr/share/nmap/scripts/vulscan"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT"

databases="cve exploitdb openvas osvdb scipvuldb securityfocus securitytracker xforce"
status=0
for db in $databases; do
  url="https://www.computec.ch/projekte/vulscan/download/${db}.csv"
  tmp="$(mktemp)"
  if curl -fsSL "$url" -o "$tmp"; then
    mv "$tmp" "$OUT/${db}.csv"
    echo "==> ${db}.csv: ok"
  else
    rm -f "$tmp"
    echo "==> ${db}.csv: FAILED (keeping existing file, continuing)" >&2
    status=1
  fi
done

exit $status
