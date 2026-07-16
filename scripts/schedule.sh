#!/usr/bin/env bash
# Run the Octo-man scheduler (Phase 1).
# Usage:
#   ./scripts/schedule.sh                  # honor scheduler.* from default.yaml
#   ./scripts/schedule.sh --once           # single immediate scan
#   ./scripts/schedule.sh --dry-run
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec python -m scanner.scheduler --config scanner/config/default.yaml "$@"
