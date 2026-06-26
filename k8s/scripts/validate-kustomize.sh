#!/usr/bin/env bash
# Локальная / CI-проверка kustomize (без GitHub Actions workflow scope).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for overlay in base overlays/dev overlays/prod; do
  echo "kustomize: network-scan-cli/${overlay}"
  kubectl kustomize "${ROOT}/network-scan-cli/${overlay}" > /dev/null
done
echo "OK"
