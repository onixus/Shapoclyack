#!/usr/bin/env bash
#
# ci-lint.sh: the repository's Ruff gate, in one place.
#
# Both CI pipelines call this instead of spelling out `ruff check <packages>`
# themselves, and both READMEs point developers at the same script. The copies
# had already drifted apart in every half: the Jenkinsfile pinned ruff 0.15.22
# while .github/workflows/ci.yml pinned 0.15.20, neither of them linted `agent/`
# — the sensor worker, which is production code the test matrix compiles — and
# the READMEs said `ruff check .`, a third scope again.
#
# The scope is now the repository root, so nothing tracked can fall outside it:
# a package list would have silently dropped the next scripts/*.py the way it
# dropped `agent/` (tests/test_ci_checks.py asserts the coverage). Ruff honours
# .gitignore, so build output and node_modules stay out on their own.
#
# The pin is not written here either: it is read out of requirements-dev.txt,
# which is what a developer installs locally. One file names the version, so
# there is nothing left to keep in sync by hand — and the version actually in
# use is checked against it, because "lint is clean here" is only worth
# anything if it means the CI lint is clean too.
#
# Usage: scripts/ci-lint.sh [--install]
#   --install  pip-install the pinned Ruff first, hash-checked from
#              requirements-dev.lock (CI containers start bare; a local
#              checkout already has it in .venv).
#
#   OCTO_LINT_ALLOW_RUFF_DRIFT=1  downgrade a version mismatch to a warning,
#                                 for deliberately trying a newer Ruff.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# The whole tree. `recon` is Go and `web-next` has its own eslint gate; neither
# contains Python, so naming the root costs nothing and leaves no gap.
TARGETS=(.)

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
PINNED_VERSION="${PIN#ruff==}"

if [[ "${1:-}" == "--install" ]]; then
  # From the lock, hash-checked like every other CI install (#313): the ruff
  # entry of requirements-dev.lock, i.e. its line and the --hash lines that
  # continue it. Ruff has no dependencies, so --no-deps loses nothing.
  echo "[lint] installing ${PIN} from requirements-dev.lock"
  lockdir="$(mktemp -d)"
  awk -v pin="${PIN}" '$1 == pin { keep = 1 } keep { print; if ($0 !~ /\\$/) exit }' \
    requirements-dev.lock > "${lockdir}/ruff.lock"
  if [[ ! -s "${lockdir}/ruff.lock" ]]; then
    rm -rf "${lockdir}"
    echo "[lint] ${PIN} is not in requirements-dev.lock; run scripts/lock-python-deps.sh" >&2
    exit 1
  fi
  pip install --quiet --require-hashes --only-binary=:all: --no-deps -r "${lockdir}/ruff.lock"
  rm -rf "${lockdir}"
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

# Asserted, not merely reported: docs/development.md tells developers that a
# local pass means the CI lint passes, and that is only true while the two
# versions agree — a .venv one release ahead of the pin has rules CI does not
# have, and vice versa. The repair is one command, printed below.
RUNNING_VERSION="$(${RUFF} --version | awk '{print $2}')"
if [[ "${RUNNING_VERSION}" != "${PINNED_VERSION}" ]]; then
  if [[ "${OCTO_LINT_ALLOW_RUFF_DRIFT:-}" == "1" ]]; then
    echo "[lint] warning: running ruff ${RUNNING_VERSION}, pin is ${PINNED_VERSION}" >&2
  else
    echo "[lint] ruff ${RUNNING_VERSION} is not the pinned ${PINNED_VERSION}." >&2
    echo "[lint] a pass here would not mean the CI lint passes. Install the pin:" >&2
    echo "[lint]   python -m pip install ${PIN}" >&2
    echo "[lint] or set OCTO_LINT_ALLOW_RUFF_DRIFT=1 to check with this one anyway." >&2
    exit 1
  fi
fi

echo "[lint] pinned: ${PIN}"
echo "[lint] running: $(${RUFF} --version)"
echo "[lint] scope: ${TARGETS[*]}"
exec "${RUFF}" check "${TARGETS[@]}"
