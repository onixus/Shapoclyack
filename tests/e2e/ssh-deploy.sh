#!/usr/bin/env bash
# Run tests/test_ssh_deploy_live.py against a real sshd in a throwaway container.
#
# Local use: needs docker and an OpenSSH client on this host; the tests run
# with this host's Python (the .venv when present). The Jenkins stage of the
# same name orchestrates the same container from Groovy, because the Jenkins
# agent's loopback is not the host's and a published port is not reachable
# from there.
#
# Usage: tests/e2e/ssh-deploy.sh [extra pytest args]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Pinned by digest, like every other image CI pulls: the test is about our
# argv against OpenSSH, not about whatever linuxserver published this week.
SSHD_IMAGE="${SSHD_IMAGE:-lscr.io/linuxserver/openssh-server@sha256:2a48f9ce01f61c1d7b376b7be99bd12801a3ecd9f339a4c7e7698d529e8d0b47}"
NAME="sshd-live-$$"
PORT="${SSHD_PORT:-$(( 20000 + RANDOM % 20000 ))}"
USER_NAME="deploy"
PASSWORD="deploy-$(date +%s)-$$"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ssh-deploy.XXXXXX")"

cleanup() {
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N "" -f "${WORK}/client_key"

echo "[ssh-e2e] starting sshd (${SSHD_IMAGE}) on 127.0.0.1:${PORT}"
docker run -d --name "${NAME}" -p "127.0.0.1:${PORT}:2222" \
  -e PASSWORD_ACCESS=true -e USER_NAME="${USER_NAME}" -e USER_PASSWORD="${PASSWORD}" \
  -e PUBLIC_KEY="$(cat "${WORK}/client_key.pub")" \
  -e PUID=1000 -e PGID=1000 \
  "${SSHD_IMAGE}" >/dev/null

for _ in $(seq 1 60); do
  if ssh-keyscan -T 2 -t ed25519 -p "${PORT}" 127.0.0.1 2>/dev/null | grep -q ed25519; then
    break
  fi
  sleep 1
done

# The fingerprint comes from the server's own key file, not from the wire: the
# test's job is to show the probe's answer matches what the host really holds.
FINGERPRINT="$(docker exec "${NAME}" ssh-keygen -lf /config/ssh_host_keys/ssh_host_ed25519_key.pub | awk '{print $2}')"
echo "[ssh-e2e] server key ${FINGERPRINT}"

PYTHON="python3"
[[ -x "${ROOT_DIR}/.venv/bin/python" ]] && PYTHON="${ROOT_DIR}/.venv/bin/python"

cd "${ROOT_DIR}"
OCTO_SSHD_TEST_HOST=127.0.0.1 \
OCTO_SSHD_TEST_PORT="${PORT}" \
OCTO_SSHD_TEST_USER="${USER_NAME}" \
OCTO_SSHD_TEST_PASSWORD="${PASSWORD}" \
OCTO_SSHD_TEST_FINGERPRINT="${FINGERPRINT}" \
OCTO_SSHD_TEST_KEY_FILE="${WORK}/client_key" \
  "${PYTHON}" -m pytest -q tests/test_ssh_deploy_live.py "$@"
