#!/usr/bin/env bash
# Local / CI validation for Octo-man kustomize overlays.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi

for target in base overlays/dev overlays/prod overlays/api-readonly overlays/agents; do
  echo "kustomize: octo-man/${target}"
  kubectl kustomize "octo-man/${target}" > .kustomize-validate.out
done

rm -f .kustomize-validate.out
echo OK
