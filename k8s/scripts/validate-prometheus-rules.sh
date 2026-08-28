#!/usr/bin/env bash
# Validate SLO alert rules with promtool (issue #186).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RULES="$ROOT/k8s/shapoclyack/examples/prometheus-slo.rules.yaml"

if [[ ! -f "$RULES" ]]; then
  echo "missing $RULES" >&2
  exit 1
fi

IMAGE="${PROMTOOL_IMAGE:-prom/prometheus:v2.54.1}"
echo "promtool check rules ($IMAGE)"
docker run --rm -v "$ROOT":/src -w /src --entrypoint /bin/promtool "$IMAGE" \
  check rules k8s/shapoclyack/examples/prometheus-slo.rules.yaml
echo OK
