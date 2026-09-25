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
# The mount is the sharp edge. `docker run -v X:/src` is resolved by the daemon,
# so X has to be a path on the *host* running that daemon. Today both callers
# run on the host and the repository root is right; the moment this stage is
# wrapped in `docker { image ... }` like its neighbours in the Jenkinsfile, the
# root becomes a path inside the container and the daemon mounts whatever it
# finds under that name on the host. A wholly absent path semgrep catches itself
# ("Detected Docker environment without a code volume", exit 2) — but a path
# that exists and is not this repository does not: measured, mounting an
# unrelated directory with one .py in it prints "Ran 19 rules on 1 file:
# 0 findings" and exits 0. A silently green SAST stage is the worst kind of
# green, so the mount is probed before either pass and the caller can name the
# host path explicitly.
#
# Usage: scripts/ci-semgrep.sh [host-root]
#   host-root  Path the *daemon* should mount. Default: SEMGREP_HOST_ROOT, else
#              the repository root (correct when docker runs on this machine).
#
#   SEMGREP_IMAGE   Scanner image. Default: semgrep 1.177.0 pinned by digest
#                   (#313); :latest gave each run whichever engine was newest.
#   SEMGREP_JSON    Report path, relative to the repo root. Default: semgrep.json
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

HOST_ROOT="${1:-${SEMGREP_HOST_ROOT:-${ROOT_DIR}}}"
SEMGREP_IMAGE="${SEMGREP_IMAGE:-semgrep/semgrep:1.177.0@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198}"
SEMGREP_JSON="${SEMGREP_JSON:-semgrep.json}"
RULES=(--config p/security-audit --config p/secrets --config p/python)

# A file every checkout has and no stray directory does. If it is not visible
# inside the mount, /src is not this repository.
MOUNT_PROBE="requirements-dev.txt"

run_semgrep() {
  docker run --rm -v "${HOST_ROOT}":/src -w /src "${SEMGREP_IMAGE}" semgrep scan "$@"
}

echo "[sast] mount: ${HOST_ROOT} -> /src"
if ! docker run --rm --entrypoint sh -v "${HOST_ROOT}":/src "${SEMGREP_IMAGE}" \
  -c "test -f /src/${MOUNT_PROBE}"; then
  echo "[sast] ${HOST_ROOT} does not appear inside the container: no /src/${MOUNT_PROBE}." >&2
  echo "[sast] the daemon resolves -v against its own host. If this stage now runs" >&2
  echo "[sast] in a container, pass the host workspace path: scripts/ci-semgrep.sh \"\$WORKSPACE\"" >&2
  exit 1
fi

echo "[sast] full report -> ${SEMGREP_JSON}"
run_semgrep "${RULES[@]}" --metrics=off --no-error --json --output "${SEMGREP_JSON}"

echo "[sast] quality gate: fail on ERROR"
run_semgrep "${RULES[@]}" --metrics=off --severity ERROR --error
