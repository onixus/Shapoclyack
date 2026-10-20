#!/usr/bin/env bash
# Test the actual API/all-in-one image; never install a replacement test client.
set -euo pipefail
IMAGE="${1:?usage: ci-ssh-client.sh IMAGE SSHD_IMAGE}"
SSHD_IMAGE="${2:?pinned sshd image required}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="shapo-client-$$-${RANDOM}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/shapo-client.XXXXXX")"
cleanup() {
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
  docker network rm "${NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT
# The runtime image's normal user owns generated private keys and test files.
chmod 777 "${WORK}"
cp "${ROOT_DIR}/tests/e2e/ssh-client-runtime.py" "${WORK}/ssh-client-runtime.py"
chmod 644 "${WORK}/ssh-client-runtime.py"
docker run --rm --entrypoint ssh-keygen -v "${WORK}:/ssh-test" "${IMAGE}" \
  -q -t ed25519 -N '' -f /ssh-test/client_key
docker network create "${NAME}" >/dev/null
docker run -d --name "${NAME}" --network "${NAME}" --network-alias sshd \
  -e PASSWORD_ACCESS=true -e USER_NAME=deploy -e USER_PASSWORD=deploy-ci-secret \
  -e PUID=1000 -e PGID=1000 -e PUBLIC_KEY="$(cat "${WORK}/client_key.pub")" \
  "${SSHD_IMAGE}" >/dev/null
FINGERPRINT=''
for _ in $(seq 1 60); do
  FINGERPRINT="$(docker exec "${NAME}" ssh-keygen -lf /config/ssh_host_keys/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print $2}' || true)"
  [[ -n "${FINGERPRINT}" ]] && break
  sleep 1
done
[[ -n "${FINGERPRINT}" ]] || { echo 'sshd did not write host keys' >&2; exit 1; }
docker run --rm --network "${NAME}" --entrypoint python \
  -v "${WORK}:/ssh-test" \
  -e PYTHONPATH=/app -e OCTO_SSHD_TEST_FINGERPRINT="${FINGERPRINT}" \
  "${IMAGE}" /ssh-test/ssh-client-runtime.py
