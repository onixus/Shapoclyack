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
# vulscan's maintainers had bundled at that commit. This refreshes them, with
# per-database non-fatal error handling (one feed being down doesn't block the
# others, matching scripts/fetch-enrichment.sh's philosophy) so a build/refresh
# never fails outright — it just keeps whatever CSV was already there.
#
# Where the CSVs come from (#246): vulscan's own update.sh pulls them from
# www.computec.ch, and that host now sits behind a Cloudflare managed challenge
# — it answers *every* non-browser client with HTTP 403 and a
# "cf-mitigated: challenge" header, regardless of User-Agent. That is what took
# all eight databases down at once in CI. It is a challenge meant to be solved
# in a browser, not a header to be guessed, so there is nothing to work around.
# The primary source is instead scipag/vulscan on GitHub — the same maintainer
# publishing the same CSVs, literally the files the pinned clone above already
# ships, at their current revision. computec.ch is kept as a fallback for closed
# networks that mirror it but block GitHub.
#
# Usage:
#   ./scripts/fetch-vulscan-db.sh                             # -> /usr/share/nmap/scripts/vulscan
#   ./scripts/fetch-vulscan-db.sh -o /path/to/vulscan/dir
#   VULSCAN_BASE_URLS="https://mirror.internal/vulscan" ./scripts/fetch-vulscan-db.sh
set -uo pipefail

OUT="/usr/share/nmap/scripts/vulscan"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT"

databases="cve exploitdb openvas osvdb scipvuldb securityfocus securitytracker xforce"
BASE_URLS="${VULSCAN_BASE_URLS:-https://raw.githubusercontent.com/scipag/vulscan/master https://www.computec.ch/projekte/vulscan/download}"

# A challenge page arrives as an error status and is rejected by curl -f, but a
# mirror or a captive portal can answer 200 with HTML. vulscan's databases are
# semicolon-separated rows starting with a numeric id, so anything opening with
# '<' is a page, not a database — and overwriting a good CSV with one would
# break offline CVE matching far more quietly than a failed download does.
looks_like_csv() {
  local file="$1"
  [[ -s "$file" ]] || return 1
  [[ "$(head -c 1 "$file")" != "<" ]]
}

status=0
for db in $databases; do
  tmp="$(mktemp)"
  fetched=0
  for base in $BASE_URLS; do
    if curl -fsSL "${base}/${db}.csv" -o "$tmp" && looks_like_csv "$tmp"; then
      mv "$tmp" "$OUT/${db}.csv"
      echo "==> ${db}.csv: ok (${base})"
      fetched=1
      break
    fi
  done
  if [[ $fetched -eq 0 ]]; then
    rm -f "$tmp"
    echo "==> ${db}.csv: FAILED (keeping existing file, continuing)" >&2
    status=1
  fi
done

exit $status
