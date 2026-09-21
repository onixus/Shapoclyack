#!/usr/bin/env bash
#
# ci-web.sh: the web-next gate (install, lint, typecheck, test, build).
#
# Takes the directory to build in, because the Jenkins stage does not build in
# the workspace: on macOS the workspace is a VirtioFS bind mount, and `npm ci`
# unpacking node_modules onto it lost writes silently (build #25 died on a run
# of NUL bytes inside language-subtag-registry). It copies web-next/ onto the
# container's own filesystem first and points this script at the copy. GitHub
# Actions has no such mount and builds web-next/ in place.
#
# Usage: scripts/ci-web.sh [dir]   (default: <repo>/web-next)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${1:-${ROOT_DIR}/web-next}"

if [[ ! -f "${WEB_DIR}/package.json" ]]; then
  echo "[web] no package.json in ${WEB_DIR}" >&2
  exit 1
fi

cd "${WEB_DIR}"
echo "[web] building in ${WEB_DIR}"
npm ci
npm run lint
npm run typecheck
npm test
npm run build
