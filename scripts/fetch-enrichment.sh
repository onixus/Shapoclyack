#!/usr/bin/env bash
# Refresh all enrichment data (GeoIP, CVSS4, EPSS, KEV) into one directory.
#
# Designed to run as a Kubernetes CronJob / initContainer or a compose
# one-shot service, writing onto a shared volume that API + scanner replicas
# mount read-only — see k8s/octo-man/base/enrichment/ and
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

mkdir -p "$DEST/geoip" "$DEST/cvss4" "$DEST/epss" "$DEST/kev"

# Floor: seed data ships in the image at $ROOT/scanner/data; copy anything
# missing at DEST so scoring never runs with zero data even if every fetch
# below fails (e.g. no network egress). GeoIP is intentionally excluded here —
# see the header comment.
for pair in \
  "cvss4/cvss4.json" \
  "epss/epss-overlay.json" \
  "kev/kev-overlay.json"; do
  src="$ROOT/scanner/data/$pair"
  dst="$DEST/$pair"
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

run "cvss4" python3 "$ROOT/scripts/fetch-cvss4-db.py" -o "$DEST/cvss4/cvss4.json"
run "epss" "$ROOT/scripts/fetch-epss-db.sh" -o "$DEST/epss/epss-overlay.json"
run "kev" "$ROOT/scripts/fetch-kev-db.sh" -o "$DEST/kev/kev-overlay.json"

if [[ $status -eq 0 ]]; then
  echo "All enrichment sources refreshed under $DEST"
else
  echo "One or more enrichment sources failed — existing/seed data under $DEST is still in place" >&2
fi
exit $status
