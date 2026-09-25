#!/usr/bin/env bash
# Validate the alert rules and the Grafana dashboards' queries with promtool
# (issues #186, #334):
#
#   check rules  examples/prometheus-slo.rules.yaml       — the rules parse
#   test rules   examples/prometheus-slo.rules.test.yaml  — the alerts fire when
#                                                            they should, and only then
#   check rules  every dashboard query, as a recording rule
#                (k8s/scripts/grafana-queries-as-rules.py) — the panels parse
#
# promtool comes from the pinned Prometheus image through docker — what both
# pipelines have always used — unless a local one is the same version: $PROMTOOL
# must be (or the script stops, since it was asked for explicitly), a promtool on
# PATH is used only if it is. A local pass is then worth what the CI pass is.
# PROMTOOL_ALLOW_VERSION_DRIFT=1 accepts an explicit $PROMTOOL of another
# version, for deliberately trying a newer parser.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

RULES="k8s/shapoclyack/examples/prometheus-slo.rules.yaml"
RULE_TESTS="k8s/shapoclyack/examples/prometheus-slo.rules.test.yaml"
# Inside the repository, not in a temp dir: the docker fallback mounts only $ROOT.
DASHBOARD_QUERIES="k8s/.dashboard-queries.rules.yaml"

for file in "$RULES" "$RULE_TESTS"; do
  if [[ ! -f "$file" ]]; then
    echo "missing $file" >&2
    exit 1
  fi
done

IMAGE="${PROMTOOL_IMAGE:-prom/prometheus:v2.54.1@sha256:f6639335d34a77d9d9db382b92eeb7fc00934be8eae81dbc03b31cfe90411a94}"
if [[ "$IMAGE" =~ :v?([0-9]+\.[0-9]+\.[0-9]+) ]]; then
  PINNED="${BASH_REMATCH[1]}"
else
  echo "cannot read a version from PROMTOOL_IMAGE=$IMAGE" >&2
  exit 1
fi

promtool_version() {
  "$1" --version 2>/dev/null | sed -n 's/^promtool, version \([0-9][0-9.]*\).*/\1/p' | head -n 1
}

if [[ -n "${PROMTOOL:-}" ]]; then
  # || true: under pipefail a PROMTOOL that is not there would end the script
  # here, exit 127 and not a word; the message below names it instead.
  found="$(promtool_version "$PROMTOOL" || true)"
  if [[ -z "$found" ]]; then
    echo "PROMTOOL=$PROMTOOL did not answer --version as promtool (version unknown);" >&2
    echo "the pin is $PINNED ($IMAGE). Point PROMTOOL at a promtool $PINNED, or unset it." >&2
    exit 1
  fi
  if [[ "$found" != "$PINNED" && "${PROMTOOL_ALLOW_VERSION_DRIFT:-}" != "1" ]]; then
    echo "PROMTOOL=$PROMTOOL is version $found, the pin is $PINNED ($IMAGE)." >&2
    echo "A pass with it would not mean the CI check passes; set PROMTOOL_ALLOW_VERSION_DRIFT=1" >&2
    echo "to use it anyway." >&2
    exit 1
  fi
else
  PROMTOOL="$(command -v promtool || true)"
  if [[ -n "$PROMTOOL" && "$(promtool_version "$PROMTOOL")" != "$PINNED" ]]; then
    echo "promtool on PATH is not $PINNED; using $IMAGE"
    PROMTOOL=""
  fi
fi

run_promtool() {
  if [[ -n "$PROMTOOL" ]]; then
    "$PROMTOOL" "$@"
  else
    docker run --rm -v "$ROOT":/src -w /src --entrypoint /bin/promtool "$IMAGE" "$@"
  fi
}

echo "promtool: ${PROMTOOL:-$IMAGE}"
echo "promtool check rules $RULES"
run_promtool check rules "$RULES"
echo "promtool test rules $RULE_TESTS"
run_promtool test rules "$RULE_TESTS"

trap 'rm -f "$DASHBOARD_QUERIES"' EXIT
python3 k8s/scripts/grafana-queries-as-rules.py "$DASHBOARD_QUERIES"
echo "promtool check rules (Grafana dashboard queries)"
run_promtool check rules "$DASHBOARD_QUERIES"
echo OK
