#!/usr/bin/env bash
# Smoke: Pulse binary present + service_probe pulse path on localhost.
# Usage (from repo root, with pulse on PATH or OCTO_PULSE_BIN set):
#   scripts/smoke-pulse.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PULSE_BIN="${OCTO_PULSE_BIN:-$(command -v pulse || true)}"
if [[ -z "${PULSE_BIN}" || ! -x "${PULSE_BIN}" ]]; then
  echo "FAIL: pulse not found (install via scripts/install-pulse.sh or image bake)"
  exit 1
fi

echo "==> pulse: ${PULSE_BIN}"
"${PULSE_BIN}" --version || "${PULSE_BIN}" --help | head -3

echo "==> pulse localhost top-10 JSON"
# Same pinned inputs as the adapter (ADR 0002, #543): our port table, private HOME.
SERVICES_DB="$(cd "$(dirname "$0")/.." && pwd)/scanner/pipeline/pulse_data/services.tsv"
PULSE_HOME="$(mktemp -d)"
trap 'rm -rf "${PULSE_HOME}"' EXIT
OUT="$(HOME="${PULSE_HOME}" env -u PULSE_SERVICES_DB "${PULSE_BIN}" 127.0.0.1 --top 10 --services-db "${SERVICES_DB}" -f json -q 2>/dev/null || true)"
if ! echo "$OUT" | grep -q '"stats"'; then
  echo "FAIL: pulse JSON missing stats"
  echo "$OUT" | head -20
  exit 1
fi
echo "OK: pulse CLI smoke"

# Adapter unit tests (no live net beyond optional)
if command -v pytest >/dev/null 2>&1; then
  echo "==> pytest tests/test_pulse_probe.py"
  pytest -q tests/test_pulse_probe.py
fi

echo "==> all pulse smokes passed"
