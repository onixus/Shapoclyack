#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

python3 -m compileall scanner

if [[ -d ".venv" ]]; then
  .venv/bin/python -m scanner.main --config scanner/config/default.yaml
else
  python3 -m scanner.main --config scanner/config/default.yaml
fi

echo "Smoke test completed."
