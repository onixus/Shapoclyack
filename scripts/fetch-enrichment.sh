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

status=0
run() {
  local label="$1"; shift
  echo "==> ${label}"
  if "$@"; then
    echo "==> ${label}: ok"
  else
    echo "==> ${label}: FAILED (continuing)" >&2
    status=1
  fi
}

mkdir -p "$DEST/geoip" "$DEST/asn" "$DEST/cvss4" "$DEST/epss" "$DEST/kev"

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
for pair in \
  "cvss4/cvss4.json" \
  "epss/epss-overlay.json" \
  "kev/kev-overlay.json"; do
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
if [[ -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
  run "geoip (maxmind)" "$ROOT/scripts/fetch-geoip-db.sh" --provider maxmind -o "$GEOIP_MMDB"
else
  run "geoip (dbip)" "$ROOT/scripts/fetch-geoip-db.sh" --provider dbip -o "$GEOIP_MMDB"
fi

# ASN/org database (attack-surface graph clustering); same stable-path,
# provider-by-key convention as GeoIP above.
ASN_MMDB="$DEST/asn/asn.mmdb"
if [[ -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
  run "asn (maxmind)" "$ROOT/scripts/fetch-asn-db.sh" --provider maxmind -o "$ASN_MMDB"
else
  run "asn (dbip)" "$ROOT/scripts/fetch-asn-db.sh" --provider dbip -o "$ASN_MMDB"
fi

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
run "cvss4" python3 "$ROOT/scripts/fetch-cvss4-db.py" --last-mod-days 8 \
  --seed "$SEED_DIR/cvss4/cvss4.json" -o "$DEST/cvss4/cvss4.json"
run "epss" "$ROOT/scripts/fetch-epss-db.sh" -o "$DEST/epss/epss-overlay.json"
run "kev" "$ROOT/scripts/fetch-kev-db.sh" -o "$DEST/kev/kev-overlay.json"

if [[ $status -eq 0 ]]; then
  echo "All enrichment sources refreshed under $DEST"
else
  echo "One or more enrichment sources failed — existing/seed data under $DEST is still in place" >&2
fi
exit $status
