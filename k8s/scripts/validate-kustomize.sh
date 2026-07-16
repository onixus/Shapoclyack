#!/usr/bin/env bash
# Local / CI validation for Octo-man kustomize overlays.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi

for target in base overlays/dev overlays/prod overlays/api-readonly; do
  echo "kustomize: octo-man/${target}"
  kubectl kustomize "${ROOT}/octo-man/${target}" > /dev/null
done

echo "OK"
