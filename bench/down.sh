#!/usr/bin/env bash
# Tear down the emulated bench network and target containers.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=bench/env.defaults
source "${ROOT_DIR}/bench/env.defaults"

for name in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep "^bench-alive-${BENCH_NET_NAME}-" || true); do
  docker rm -f "${name}" >/dev/null 2>&1 || true
done

docker network rm "${BENCH_NET_NAME}" >/dev/null 2>&1 || true
rm -f "${ROOT_DIR}/scanner/inputs/bench/.bench-net"
echo "[bench] removed network ${BENCH_NET_NAME} and target containers"
