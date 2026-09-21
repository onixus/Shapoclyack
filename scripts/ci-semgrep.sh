#!/usr/bin/env bash
#
# ci-semgrep.sh: the SAST quality gate.
#
# Two passes on purpose:
#   1. every severity, --no-error, JSON to a file. WARNING and INFO findings
#      have to be visible in the artifact without blocking anyone.
#   2. --severity ERROR --error. The gate is the exit code, not a JSON parse:
#      fewer moving parts between a finding and a red build.
#
# It runs early in the pipeline for the same reason: an ERROR finding fails the
# build in a couple of minutes instead of after an hour of image builds.
#
# Until this script existed the stage lived only in the Jenkinsfile, which is
# the one place docs/development.md called out as unmatched in the reference
# workflow. Both now call this.
#
#   SEMGREP_IMAGE   Scanner image. Default: semgrep/semgrep:latest
#   SEMGREP_JSON    Report path, relative to the repo root. Default: semgrep.json
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

SEMGREP_IMAGE="${SEMGREP_IMAGE:-semgrep/semgrep:latest}"
SEMGREP_JSON="${SEMGREP_JSON:-semgrep.json}"
RULES=(--config p/security-audit --config p/secrets --config p/python)

run_semgrep() {
  docker run --rm -v "${ROOT_DIR}":/src -w /src "${SEMGREP_IMAGE}" semgrep scan "$@"
}

echo "[sast] full report -> ${SEMGREP_JSON}"
run_semgrep "${RULES[@]}" --metrics=off --no-error --json --output "${SEMGREP_JSON}"

echo "[sast] quality gate: fail on ERROR"
run_semgrep "${RULES[@]}" --metrics=off --severity ERROR --error
