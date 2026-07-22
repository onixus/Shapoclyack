#!/usr/bin/env bash
# Refresh nuclei's template pack beyond whatever was bundled at the pinned
# NUCLEI_TEMPLATES_REF commit in Dockerfile/Dockerfile.allinone.
#
# Uses nuclei's own supported update mechanism (-update-templates), which
# downloads the latest signed nuclei-templates release into the given
# directory — no separate checksum bookkeeping needed here, nuclei verifies
# the release itself. Requires the `nuclei` binary to already be on PATH.
#
# Usage:
#   ./scripts/fetch-nuclei-templates.sh                      # -> /usr/share/nuclei-templates
#   ./scripts/fetch-nuclei-templates.sh /path/to/templates
set -uo pipefail

DEST="${1:-/usr/share/nuclei-templates}"

if ! command -v nuclei >/dev/null 2>&1; then
  echo "nuclei binary not found on PATH — skipping template refresh" >&2
  exit 1
fi

mkdir -p "$DEST"
if nuclei -update-templates -update-template-dir "$DEST" -disable-update-check -silent; then
  echo "nuclei-templates refreshed under $DEST"
else
  echo "nuclei-templates refresh FAILED — keeping existing templates under $DEST" >&2
  exit 1
fi
