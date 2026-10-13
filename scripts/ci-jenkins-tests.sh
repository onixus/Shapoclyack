#!/usr/bin/env bash
# Container-side setup for one Jenkins Python cell. Jenkins owns containers,
# networks and report publication; ci-pytest.sh owns pytest options and gates.
# Requires root for hashed dependency installation, and a non-root workspace.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CI_UID=$(stat -c %u .)
CI_GID=$(stat -c %g .)
if [ "$CI_UID" = 0 ]; then
  echo '[ci] the workspace is owned by root; refusing to run the suite as root' >&2
  exit 1
fi

# psycopg[binary] carries libpq: no apt or compiler needed in this cell.
pip install --quiet --require-hashes --only-binary=:all: -r requirements-dev.lock
mkdir -p /tmp/ci-home
chown "$CI_UID:$CI_GID" /tmp/ci-home
as_agent() {
  HOME=/tmp/ci-home setpriv --reuid="$CI_UID" --regid="$CI_GID" --clear-groups "$@"
}

as_agent python -m compileall -q scanner api tests agent

wait_for() {
  local service=$1
  shift
  local attempt
  for ((attempt=1; attempt<60; attempt++)); do
    # A refused connection is expected while the service starts: keep the
    # log readable and show the probe's own error only on the last attempt.
    if "$@" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  if "$@"; then
    return 0
  fi
  echo "[ci] $service did not become ready after 60 attempts" >&2
  return 1
}

# Fixed Docker aliases are created by Jenkins, not host loopback addresses.
# Exhaustion must stop here, before migrations or a misleading pytest run.
wait_for postgres python -c "import socket; socket.create_connection(('pg', 5432), 1).close()"
wait_for jetstream python -c "import urllib.request; urllib.request.urlopen('http://nats:8222/healthz', timeout=1).close()"
alembic -c api/db/alembic.ini upgrade head
as_agent scripts/ci-pytest.sh "$@"
