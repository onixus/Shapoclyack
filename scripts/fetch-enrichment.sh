#!/usr/bin/env bash
# Refresh all enrichment data (GeoIP, CVSS4, EPSS, KEV) into one directory.
#
# Designed to run as a Kubernetes CronJob / initContainer or a compose
# one-shot service, writing onto a shared volume that API + scanner replicas
# mount read-only — see k8s/shapoclyack/base/enrichment/ and
# docker-compose.enrichment.yml.
#
# Behavior:
#   - EPSS/KEV/CVSS4 never end up with zero usable data: the repo's committed
#     seed overlays are copied to the target path first (only if it doesn't
#     already exist) as a floor, then each real feed overwrites it in place —
#     same file, same format, so a failed fetch just leaves the previous
#     (seed or last-good) content behind.
#   - GeoIP has no such floor: the real database is a MaxMind/DB-IP .mmdb, a
#     different format from the committed 5-IP JSON overlay, so there's no
#     redistributable seed to fall back to at the .mmdb path. Until the first
#     successful fetch, public-IP lookups just return empty (identical to
#     today's behavior when no database is configured) — RFC1918/loopback
#     labeling in scanner/pipeline/geoip.py::_private_geo works regardless.
#   - Each source is independent and non-fatal: a failing fetch is logged and
#     skipped rather than aborting the others, so e.g. no MAXMIND_LICENSE_KEY
#     or a transient network blip on one feed doesn't block the rest.
#   - "Source unreachable" and "no data at all" are *different* outcomes, and
#     the exit code says which (0 / 1 / 2 — see the tail of this script). Every
#     run also writes an enrichment-manifest.json recording, per dataset, where
#     the bytes came from and how many entries they hold, which is what makes a
#     silently-degraded image distinguishable from a fresh one (#246).
#
# GeoIP source selection: MaxMind GeoLite2-City if MAXMIND_LICENSE_KEY is set
# (more accurate, needs a free account), else DB-IP City Lite (no key).
#
# Usage:
#   ./scripts/fetch-enrichment.sh                    # → scanner/data/
#   OCTO_ENRICHMENT_DIR=/data ./scripts/fetch-enrichment.sh
#   MAXMIND_LICENSE_KEY=xxxx ./scripts/fetch-enrichment.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${OCTO_ENRICHMENT_DIR:-scanner/data}"

# Datasets this run actually refreshed vs. the ones whose fetch failed. The
# bytes on disk look the same either way, so this is the only place that knows
# the difference -- it is handed to scripts/enrichment_manifest.py, which
# records it in the image so GET /api/system can report where each dataset came
# from instead of only its age (#246).
refreshed=""
failed=""
run() {
  local name="$1" label="$2"; shift 2
  echo "==> ${label}"
  if "$@"; then
    echo "==> ${label}: ok"
    refreshed="${refreshed},${name}"
  else
    echo "==> ${label}: FAILED (continuing)" >&2
    failed="${failed},${name}"
  fi
}

mkdir -p "$DEST/geoip" "$DEST/asn" "$DEST/cvss4" "$DEST/epss" "$DEST/kev" "$DEST/exploit"

# Floor: copy any missing seed file to DEST so scoring never runs with zero
# data even if every fetch below fails (e.g. no network egress). GeoIP is
# intentionally excluded here — see the header comment.
#
# The seed is read from a pristine copy the image keeps outside the runtime data
# directory. In Kubernetes, DEST is /app/scanner/data — the very path the image
# bakes the seed into — so an enrichment volume mounted there shadows it, and a
# floor reading from $ROOT/scanner/data would find the same empty directory it
# is trying to fill. Falls back to $ROOT/scanner/data for a plain source
# checkout, where nothing is mounted and the two are genuinely the same tree.
SEED_DIR="${OCTO_ENRICHMENT_SEED_DIR:-/opt/shapoclyack/seed-data}"
if [[ ! -d "$SEED_DIR" ]]; then
  SEED_DIR="$ROOT/scanner/data"
fi
# exploit-overlay.json has no fetch step here (scripts/fetch-exploit-db.py is
# run deliberately, not daily), so the floor is the *only* way it reaches a
# mounted enrichment volume — without it, exploit-maturity scoring on a k8s
# deployment reads an absent overlay and reports "nobody asked" for every CVE.
for pair in \
  "cvss4/cvss4.json" \
  "epss/epss-overlay.json" \
  "kev/kev-overlay.json" \
  "exploit/exploit-overlay.json"; do
  src="$SEED_DIR/$pair"
  dst="$DEST/$pair"
  # Same file (source checkout with no volume mounted): nothing to floor.
  [[ "$src" -ef "$dst" ]] && continue
  if [[ -f "$src" && ! -f "$dst" ]]; then
    cp "$src" "$dst"
    echo "seeded $dst from committed overlay"
  fi
done

# Always write to the same filename regardless of provider, so
# enrichment.geoip.database / OCTO_GEOIP_DATABASE can point at a stable path
# even if MAXMIND_LICENSE_KEY is added/removed between refreshes.
GEOIP_MMDB="$DEST/geoip/geoip.mmdb"
# Also recorded in the manifest: the two providers produce the same file name in
# the same format, so nothing about the .mmdb on disk says which one wrote it.
if [[ -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
  MMDB_PROVIDER="maxmind"
else
  MMDB_PROVIDER="dbip"
fi
run geoip "geoip (${MMDB_PROVIDER})" "$ROOT/scripts/fetch-geoip-db.sh" \
  --provider "$MMDB_PROVIDER" -o "$GEOIP_MMDB"

# ASN/org database (attack-surface graph clustering); same stable-path,
# provider-by-key convention as GeoIP above.
ASN_MMDB="$DEST/asn/asn.mmdb"
run asn "asn (${MMDB_PROVIDER})" "$ROOT/scripts/fetch-asn-db.sh" \
  --provider "$MMDB_PROVIDER" -o "$ASN_MMDB"

# Incremental, not --full: the committed scanner/data/cvss4/cvss4.json (baked
# into every image) is the baseline, and this only layers on what NVD changed
# recently. A --full rebuild pages the entire 370k-CVE corpus and belongs in a
# deliberate, keyed run -- not in a daily job with an activeDeadlineSeconds.
# The 8-day window covers a missed run or two without re-walking history; the
# script merges, so nothing already in the database is lost.
# --seed carries the image's committed baseline onto a volume that already has
# a database: the floor above only fires when the file is absent, so without
# this an upgrade to an image with a bigger baseline would never reach an
# existing volume. Existing entries always win over the baseline.
run cvss4 "cvss4" python3 "$ROOT/scripts/fetch-cvss4-db.py" --last-mod-days 8 \
  --seed "$SEED_DIR/cvss4/cvss4.json" -o "$DEST/cvss4/cvss4.json"
run epss "epss" "$ROOT/scripts/fetch-epss-db.sh" -o "$DEST/epss/epss-overlay.json"
run kev "kev" "$ROOT/scripts/fetch-kev-db.sh" -o "$DEST/kev/kev-overlay.json"

# Record what is actually on disk now, and let the manifest decide the exit
# code. The three outcomes are deliberately not the same thing:
#   0  every source refreshed
#   1  a source was unreachable, but every required dataset still holds usable
#      data (a warning: a foreign server being down must not fail a build)
#   2  a required dataset is missing or is a demo stub — the risk model would
#      be scoring blind, which is what a release build has to refuse (#246)
python3 "$ROOT/scripts/enrichment_manifest.py" --dir "$DEST" \
  --refreshed "$refreshed" --failed "$failed" \
  --source "geoip=$MMDB_PROVIDER" --source "asn=$MMDB_PROVIDER"
status=$?

case $status in
  0) echo "All enrichment sources refreshed under $DEST" ;;
  1) echo "One or more enrichment sources failed — existing/seed data under $DEST is still in place" >&2 ;;
  *) echo "A required enrichment dataset under $DEST has no usable data (see the manifest above)" >&2 ;;
esac
exit $status
