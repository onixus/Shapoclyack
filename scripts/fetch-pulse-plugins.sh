#!/usr/bin/env bash
# Install Rhai Pulse plugins from git into a content directory.
#
# Release images do not contain scanner/pipeline/pulse_data/plugins. This
# script is how a sensor, a single host or an air-gapped mirror gets them,
# and how a second repository of your own plugins is added. The scanner reads
# the destination (service_probe.pulse.plugins_dir or OCTO_PULSE_PLUGINS_DIR,
# default /var/lib/shapoclyack/pulse-plugins). A checkout of this repository
# still runs from the tree in git until a destination is set.
#
# One official repository (the default repo is this one, the default path is
# scanner/pipeline/pulse_data/plugins):
#
#   PULSE_PLUGINS_REF=v1.2.0 \
#   PULSE_PLUGINS_COMMIT=<40-character commit that tag names> \
#     scripts/fetch-pulse-plugins.sh /var/lib/shapoclyack/pulse-plugins
#
# PULSE_PLUGINS_REPO overrides the official URL (https, ssh, file or
# git@host:path). PULSE_PLUGINS_REF is required: there is no floating branch.
# PULSE_PLUGINS_COMMIT, when set, is the commit that ref must resolve to.
#
# Several repositories, official and your own. List the one you trust first.
# A later file cannot replace an earlier name. Either a JSON file:
#
#   PULSE_PLUGINS_SOURCES=/etc/shapoclyack/pulse-plugins.json \
#     scripts/fetch-pulse-plugins.sh /var/lib/shapoclyack/pulse-plugins
#
# or the same list in the scan config, service_probe.pulse.plugin_sources:
#
#   scripts/fetch-pulse-plugins.sh --config scanner/config/default.yaml \
#     /var/lib/shapoclyack/pulse-plugins
#
# A config whose plugin_sources list is empty falls through to PULSE_PLUGINS_*.
# Pass the file or --config, not both. The checkout is staged beside the
# destination and swapped in only after every source is fetched and at least
# one script is accepted. A destination that is a mount point is updated in
# place. OCTO_HTTPS_PROXY, OCTO_HTTP_PROXY, OCTO_NO_PROXY and OCTO_CA_BUNDLE
# apply to the git fetch the way they do for nuclei templates.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DEST="/var/lib/shapoclyack/pulse-plugins"
CONFIG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="${2:-}"
      if [[ -z "$CONFIG" ]]; then
        echo "error: --config needs a path" >&2
        exit 2
      fi
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "error: unknown option $1" >&2
      exit 2
      ;;
    *)
      DEST="$1"
      shift
      ;;
  esac
done
if [[ $# -gt 0 ]]; then
  DEST="$1"
fi

if [[ -n "${OCTO_HTTPS_PROXY:-}" ]]; then
  export https_proxy="$OCTO_HTTPS_PROXY" HTTPS_PROXY="$OCTO_HTTPS_PROXY"
fi
if [[ -n "${OCTO_HTTP_PROXY:-}" ]]; then
  export http_proxy="$OCTO_HTTP_PROXY"
fi
if [[ -n "${OCTO_NO_PROXY:-}" ]]; then
  export no_proxy="$OCTO_NO_PROXY" NO_PROXY="$OCTO_NO_PROXY"
fi
CA_FILE=""
cleanup() {
  [[ -n "$CA_FILE" ]] && rm -f "$CA_FILE"
}
trap cleanup EXIT
if [[ -n "${OCTO_CA_BUNDLE:-}" ]]; then
  CA_FILE="$(mktemp)"
  if ! python3 "$HERE/feed_fetch.py" ca-bundle -o "$CA_FILE"; then
    echo "error: OCTO_CA_BUNDLE=$OCTO_CA_BUNDLE is not usable" >&2
    exit 1
  fi
  export GIT_SSL_CAINFO="$CA_FILE"
fi

export PYTHONPATH="${ROOT}${PYTHONPATH:+:$PYTHONPATH}"
# An activated virtualenv owns the interpreter. The image has no VIRTUAL_ENV
# and uses the interpreter on PATH, which has the installed dependencies.
if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
  PY="${VIRTUAL_ENV}/bin/python"
else
  PY="${PYTHON:-python3}"
fi
if [[ -n "$CONFIG" ]]; then
  exec "$PY" -m scanner.pipeline.pulse_plugin_content fetch --dest "$DEST" --config "$CONFIG"
fi
exec "$PY" -m scanner.pipeline.pulse_plugin_content fetch --dest "$DEST"
