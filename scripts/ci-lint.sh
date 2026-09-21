#!/usr/bin/env bash
#
# ci-lint.sh: the repository's Ruff gate, in one place.
#
# Both CI pipelines call this instead of spelling out `ruff check <packages>`
# themselves. The two copies had already drifted apart in both halves: the
# Jenkinsfile pinned ruff 0.15.22 while .github/workflows/ci.yml pinned
# 0.15.20, and neither of them linted `agent/` — the sensor worker, which is
# production code the test matrix compiles but nobody checked.
#
# The pin is not written here either: it is read out of requirements-dev.txt,
# which is what a developer installs locally. One file names the version, so
# there is nothing left to keep in sync by hand.
#
# Usage: scripts/ci-lint.sh [--install]
#   --install  pip-install the pinned Ruff first (CI containers start bare;
#              a local checkout already has it in .venv).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# The packages under lint. `agent` is the sensor worker (agent/worker.py);
# `recon` is Go and `web-next` has its own eslint gate, so neither belongs here.
PACKAGES=(scanner api tests agent)

ruff_pin() {
  # e.g. "ruff==0.15.22" -> the whole requirement, comments and blanks dropped.
  local pin
  pin="$(sed -n 's/^\(ruff==[A-Za-z0-9.+-]*\).*$/\1/p' requirements-dev.txt | head -n 1)"
  if [[ -z "${pin}" ]]; then
    echo "[lint] no 'ruff==' pin in requirements-dev.txt" >&2
    exit 1
  fi
  printf '%s\n' "${pin}"
}

PIN="$(ruff_pin)"

if [[ "${1:-}" == "--install" ]]; then
  echo "[lint] installing ${PIN}"
  pip install --quiet "${PIN}"
elif [[ $# -gt 0 ]]; then
  echo "Usage: $0 [--install]" >&2
  exit 2
fi

RUFF="ruff"
if ! command -v "${RUFF}" >/dev/null 2>&1; then
  if [[ -x ".venv/bin/ruff" ]]; then
    RUFF=".venv/bin/ruff"
  else
    echo "[lint] ruff not found; install ${PIN} or re-run with --install" >&2
    exit 1
  fi
fi

# Reported, not asserted: a local .venv may legitimately be a version ahead of
# the pin, and failing the developer's lint over that helps nobody. CI installs
# the pin itself one line above, so there the two always agree.
echo "[lint] pinned: ${PIN}"
echo "[lint] running: $(${RUFF} --version)"
echo "[lint] packages: ${PACKAGES[*]}"
exec "${RUFF}" check "${PACKAGES[@]}"
