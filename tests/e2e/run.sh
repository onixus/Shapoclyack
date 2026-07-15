#!/usr/bin/env bash
# End-to-end smoke scan: run the built image against a throwaway target container
# on a private docker network and assert the pipeline produced real findings.
#
# Usage: tests/e2e/run.sh [IMAGE]
set -euo pipefail

IMAGE="${1:-network-scan-cli:ci}"
TARGET_IMAGE="${TARGET_IMAGE:-nginx:alpine}"
NET="scan-e2e-net-$$"
TARGET="e2e-target-$$"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"

cleanup() {
  docker rm -f "${TARGET}" >/dev/null 2>&1 || true
  docker network rm "${NET}" >/dev/null 2>&1 || true
  # Output files are owned by the container's non-root uid; fall back to sudo.
  rm -rf "${WORK}" 2>/dev/null || sudo rm -rf "${WORK}" 2>/dev/null || true
}
trap cleanup EXIT

echo "[e2e] creating network and target (${TARGET_IMAGE})"
docker network create "${NET}" >/dev/null
docker run -d --name "${TARGET}" --network "${NET}" "${TARGET_IMAGE}" >/dev/null

# Wait for the target to come up.
for _ in $(seq 1 10); do
  if docker exec "${TARGET}" sh -c 'wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || true'; then
    break
  fi
  sleep 1
done

TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${TARGET}")"
echo "[e2e] target ip: ${TARGET_IP}"
if [[ -z "${TARGET_IP}" ]]; then
  echo "[e2e] failed to resolve target IP" >&2
  exit 1
fi

mkdir -p "${WORK}/inputs" "${WORK}/config" "${WORK}/output" "${WORK}/state"
printf '%s\n' "${TARGET_IP}" > "${WORK}/inputs/ranges.txt"
printf '# no domains\n' > "${WORK}/inputs/domains.txt"
printf '80\n' > "${WORK}/inputs/ports.txt"
cp "${ROOT_DIR}/tests/e2e/config.yaml" "${WORK}/config/default.yaml"
# The image runs as the non-root 'scanner' user; make mounts writable regardless of uid.
chmod -R 777 "${WORK}"

echo "[e2e] running scanner image"
docker run --rm --network "${NET}" \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "${WORK}/inputs:/app/scanner/inputs" \
  -v "${WORK}/config:/app/scanner/config" \
  -v "${WORK}/output:/app/scanner/output" \
  -v "${WORK}/state:/app/scanner/state" \
  "${IMAGE}" --config scanner/config/default.yaml --mode safe

echo "[e2e] validating results"
python3 "${ROOT_DIR}/tests/e2e/check_results.py" "${WORK}/output" "${TARGET_IP}"
