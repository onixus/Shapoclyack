#!/usr/bin/env bash
#
# lock-python-deps.sh: regenerate the hash-pinned Python locks (#313).
#
# requirements*.txt stay the files people edit: direct dependencies, pinned
# with ==, and a comment on why. What the images and the pipelines install is
# the *.lock compiled from them — every transitive dependency pinned too, and
# every file allowed for it listed by sha256 — with `pip install
# --require-hashes`, so a wheel that is not the one this lock was compiled
# against is refused rather than installed. A pin alone does not do that: PyPI
# lets a maintainer upload new files for an existing version, and a pin says
# nothing about a dependency the pinned packages pull in.
#
# One lock per install set, named for the input it is compiled from:
#
#   requirements-pip.lock   <- requirements-pip.txt    pip itself, upgraded first in every image
#   requirements.lock       <- requirements.txt        scanner image (Dockerfile)
#   requirements-api.lock   <- requirements-api.txt    api and all-in-one images
#   requirements-dev.lock   <- requirements-dev.txt    CI (PR gate, full CI, Jenkins)
#   requirements-agent.lock <- requirements-agent.txt  native sensor hosts (scripts/install-agent.sh)
#
# scripts/install-agent.sh carries requirements-agent.lock inline, since
# `curl … | bash` brings no other file to the host (#476); the script
# rewrites that copy from the lock it has just compiled.
#
# --universal resolves once for every platform and Python >= 3.11 instead of
# for the machine running this script: the images build for linux/amd64 and
# linux/arm64 on Python 3.12, CI runs 3.11 and 3.12, and a lock compiled on a
# Mac would otherwise quietly lack whatever only Linux needs. Platform-specific
# lines keep their environment markers, and --generate-hashes lists every file
# of each pinned version, so an arm64 build finds its wheel's hash as well.
# --no-strip-extras keeps `psycopg[binary]` as written: stripped to `psycopg`,
# an input that grew an extra without a relock would still look in sync, and
# the image would miss the extra's packages.
#
# The header uv writes into each lock records the command. Renovate re-runs
# exactly that command when it bumps a dependency (its pip-compile manager
# refuses options it does not know), and tests/test_python_locks.py holds the
# header to the same argument list — which is why the options are spelled
# --opt=value and why nothing else may be added to them.
#
# Usage: scripts/lock-python-deps.sh [uv pip compile options...]
#   e.g. scripts/lock-python-deps.sh --upgrade-package certifi
#        scripts/lock-python-deps.sh --upgrade    (refresh every transitive pin)
#   uv leaves --upgrade/--upgrade-package out of the header, so they are safe
#   to pass; anything else lands in the header and fails the lock test.
#
#   OCTO_LOCK_ALLOW_UV_DRIFT=1  accept a uv other than UV_VERSION below.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# The uv these locks are compiled with. A different release can order or
# annotate the output differently, which would turn every regeneration into a
# noisy diff; the resolution itself is what the lock test checks.
UV_VERSION="0.12.18"

# lock:input pairs; see the table above.
LOCKS=(
  "requirements-pip.lock:requirements-pip.txt"
  "requirements.lock:requirements.txt"
  "requirements-api.lock:requirements-api.txt"
  "requirements-dev.lock:requirements-dev.txt"
  "requirements-agent.lock:requirements-agent.txt"
)

# The copy of requirements-agent.lock in the installer: everything between
# its heredoc line and the LOCK terminator. tests/test_agent_install_pins.py
# runs the heredoc and compares it with the lock byte for byte.
AGENT_INSTALLER="scripts/install-agent.sh"
AGENT_LOCK_START="    cat <<'LOCK' > \"\$1\""

sync_agent_installer() {
  local starts ends tmp
  starts="$(grep -cxF -- "${AGENT_LOCK_START}" "${AGENT_INSTALLER}" || true)"
  ends="$(grep -cx 'LOCK' "${AGENT_INSTALLER}" || true)"
  if [[ "${starts}" != "1" || "${ends}" != "1" ]]; then
    echo "[lock] ${AGENT_INSTALLER}: expected one '${AGENT_LOCK_START}' and one 'LOCK' line;" >&2
    echo "[lock]   paste requirements-agent.lock between them by hand" >&2
    exit 1
  fi
  tmp="$(mktemp)"
  awk -v start="${AGENT_LOCK_START}" -v lock="requirements-agent.lock" '
    $0 == "LOCK" { copied = 0 }
    !copied { print }
    $0 == start { while ((getline line < lock) > 0) print line; copied = 1 }
  ' "${AGENT_INSTALLER}" > "${tmp}"
  # cat, not mv: the installer keeps its mode and stays the same file.
  cat "${tmp}" > "${AGENT_INSTALLER}"
  rm -f "${tmp}"
}

if ! command -v uv >/dev/null 2>&1; then
  echo "[lock] uv not found; install it with: python -m pip install uv==${UV_VERSION}" >&2
  exit 1
fi

RUNNING_VERSION="$(uv --version | awk '{print $2}')"
if [[ "${RUNNING_VERSION}" != "${UV_VERSION}" ]]; then
  if [[ "${OCTO_LOCK_ALLOW_UV_DRIFT:-}" == "1" ]]; then
    echo "[lock] warning: running uv ${RUNNING_VERSION}, pin is ${UV_VERSION}" >&2
  else
    echo "[lock] uv ${RUNNING_VERSION} is not the pinned ${UV_VERSION}." >&2
    echo "[lock]   python -m pip install uv==${UV_VERSION}" >&2
    echo "[lock] or set OCTO_LOCK_ALLOW_UV_DRIFT=1 to compile with this one anyway." >&2
    exit 1
  fi
fi

for entry in "${LOCKS[@]}"; do
  lock="${entry%%:*}"
  input="${entry#*:}"
  echo "[lock] ${input} -> ${lock}"
  uv pip compile --quiet \
    --universal --no-strip-extras --generate-hashes --python-version=3.11 \
    --output-file="${lock}" "${input}" "$@"
done
echo "[lock] requirements-agent.lock -> ${AGENT_INSTALLER}"
sync_agent_installer
