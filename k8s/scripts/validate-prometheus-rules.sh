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
# promtool comes from $PROMTOOL, else from PATH, else from the pinned Prometheus
# image through docker — which is what both pipelines have always used.
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

IMAGE="${PROMTOOL_IMAGE:-prom/prometheus:v2.54.1}"
PROMTOOL="${PROMTOOL:-$(command -v promtool || true)}"

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
