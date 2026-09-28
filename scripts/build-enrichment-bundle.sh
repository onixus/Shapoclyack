#!/usr/bin/env bash
# Build an offline enrichment bundle on a connected host (#339): refresh every
# feed into a working directory, then pack it with scripts/enrichment_bundle.py
# for an air-gapped installation to load. `make enrichment-bundle` runs this.
#
# What is fetched follows the same switches as the in-cluster refresh
# (scripts/fetch-enrichment.sh): MAXMIND_LICENSE_KEY, NVD_API_KEY,
# OCTO_ADVISORY_FETCH_ENABLED, OCTO_NVD_CPE_FETCH_ENABLED, every *_URL mirror
# override, and OCTO_HTTPS_PROXY / OCTO_CA_BUNDLE. On top of that it refreshes
# the exploit-maturity overlay, which the daily job leaves to a deliberate run.
#
# The working directory is kept between runs, and should be: the CVSS4 and NVD
# CPE refreshes are incremental and continue what is there (the NVD CPE one
# needs a one-time `fetch-nvd-cpe.py --full` into it first — docs/air-gap.md).
#
# Exit codes, the refresh's own:
#   0  bundle written, every source refreshed
#   1  bundle written, but a source was unreachable — the bundle carries the
#      previous (or seed) data for it and its manifest says `stale`
#   2  a required dataset has no usable data; no bundle is written, since the
#      air-gapped side would refuse to install it over usable data anyway
#
# Usage:
#   make enrichment-bundle
#   ENRICHMENT_BUILD_DIR=/srv/enrichment ENRICHMENT_BUNDLE=/srv/out/enrichment-bundle.tar.gz \
#     scripts/build-enrichment-bundle.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${ENRICHMENT_BUILD_DIR:-$ROOT/build/enrichment}"
OUT="${ENRICHMENT_BUNDLE:-$ROOT/dist/enrichment-bundle.tar.gz}"
mkdir -p "$DIR"

# An inherited OCTO_ENRICHMENT_OFFLINE would turn this into a no-op that still
# writes a bundle — of whatever happened to be in the directory.
OCTO_ENRICHMENT_DIR="$DIR" OCTO_ENRICHMENT_OFFLINE=false "$ROOT/scripts/fetch-enrichment.sh"
status=$?
if [[ $status -ge 2 ]]; then
  echo "error: a required dataset under $DIR has no usable data; no bundle written" >&2
  exit 2
fi

echo "==> exploit overlay"
python3 "$ROOT/scripts/fetch-exploit-db.py" -o "$DIR/exploit/exploit-overlay.json"
case $? in
  0) exploit=(--refreshed exploit) ;;
  # Published, with one of its two sources missing: fresh, and degraded.
  2) exploit=(--refreshed exploit); status=1 ;;
  *) exploit=(--failed exploit) ;;
esac
# Re-describe the directory with the exploit result; every other dataset keeps
# the origin the refresh above just recorded.
python3 "$ROOT/scripts/enrichment_manifest.py" --dir "$DIR" "${exploit[@]}"
verdict=$?
if [[ $verdict -ge 2 ]]; then
  echo "error: a required dataset under $DIR has no usable data; no bundle written" >&2
  exit 2
fi
[[ $verdict -gt $status ]] && status=$verdict

if ! python3 "$ROOT/scripts/enrichment_bundle.py" build --dir "$DIR" -o "$OUT"; then
  exit 2
fi
python3 "$ROOT/scripts/enrichment_bundle.py" verify "$OUT" >/dev/null || exit 2
if [[ $status -eq 1 ]]; then
  echo "warning: $OUT was written, but a source was unreachable — see 'origin' above" >&2
fi
exit $status
