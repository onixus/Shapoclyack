#!/usr/bin/env bash
#
# ci-helm.sh: the Helm chart gate (#341).
#
#   1. `helm lint --strict` on charts/shapoclyack, with the defaults and with
#      each optional feature switched on (ingress, External Secrets, an existing
#      Secret, NetworkPolicy off) so a template that only breaks under one
#      switch fails here and not at the first operator who flips it.
#   2. The chart rendered with its default values (plus ci/parity-values.yaml,
#      which only adds the release namespace object the base also contains) must
#      hold the same objects, with the same content, as
#      `kubectl kustomize k8s/shapoclyack/base`. See scripts/helm_parity.py for
#      what is normalised; securityContext, NetworkPolicy and ServiceAccount
#      settings are compared like everything else. The chart is the base in
#      another packaging, and this is what keeps it so.
#
# Usage: scripts/ci-helm.sh [--sync]
#   --sync  first rewrite charts/shapoclyack/files/ from the kustomize render
#           (the ConfigMap payloads are plain files the chart loads); run it
#           after editing anything under k8s/shapoclyack/base/{config,clickhouse,
#           nats,backup}, then commit the result.
#
#   PYTHON=<interpreter>  one with PyYAML (default: python3)
#
# Needs helm >= 3.12 (or 4.x), kubectl and PyYAML. Jenkins/GitHub wiring: docs/helm.md.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="${ROOT_DIR}/charts/shapoclyack"
PYTHON="${PYTHON:-python3}"

for tool in helm kubectl "${PYTHON}"; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "[helm] ${tool} is required" >&2
    exit 1
  fi
done
if ! "${PYTHON}" -c "import yaml" 2>/dev/null; then
  echo "[helm] ${PYTHON} has no PyYAML (pip install -r requirements.txt)" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

echo "[helm] kustomize base"
kubectl kustomize "${ROOT_DIR}/k8s/shapoclyack/base" > "${work}/kustomize.yaml"

if [[ "${1:-}" == "--sync" ]]; then
  "${PYTHON}" "${ROOT_DIR}/scripts/helm_parity.py" --sync "${work}/kustomize.yaml" "${CHART}"
fi

parity=(-f "${CHART}/ci/parity-values.yaml")

echo "[helm] lint"
helm lint --strict "${CHART}" "${parity[@]}"
helm lint --strict "${CHART}" --set ingress.enabled=true --set ingress.className=nginx
helm lint --strict "${CHART}" --set externalSecrets.enabled=true
helm lint --strict "${CHART}" --set existingSecrets.api=api-creds --set networkPolicy.enabled=false

echo "[helm] render: every switch must produce a manifest"
# A namespace is passed because the chart takes the control plane's from the release.
for args in \
  "--set ingress.enabled=true" \
  "--set externalSecrets.enabled=true" \
  "--set existingSecrets.api=api-creds" \
  "--set networkPolicy.enabled=false" \
  "--set backup.postgres.enabled=false --set backup.clickhouse.enabled=false"; do
  # shellcheck disable=SC2086
  helm template shapoclyack "${CHART}" --namespace network-scan ${args} > /dev/null
done

echo "[helm] parity with kustomize base"
helm template shapoclyack "${CHART}" --namespace network-scan "${parity[@]}" > "${work}/helm.yaml"
"${PYTHON}" "${ROOT_DIR}/scripts/helm_parity.py" "${work}/kustomize.yaml" "${work}/helm.yaml"

echo "[helm] OK"
