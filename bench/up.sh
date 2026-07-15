#!/usr/bin/env bash
# Create an emulated docker lab network and alive target containers.
#
# Usage:
#   bench/up.sh [alive_hosts] [target_count] [cidr|list]
#
# Examples:
#   bench/up.sh                    # defaults: 32 alive, /22 CIDR (~1024 addrs)
#   bench/up.sh 64 1000 list       # 1000 IPs in BENCH_SUBNET, 64 nginx containers
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=bench/env.defaults
source "${ROOT_DIR}/bench/env.defaults"

BENCH_ALIVE_HOSTS="${1:-${BENCH_ALIVE_HOSTS}}"
BENCH_TARGET_COUNT="${2:-${BENCH_TARGET_COUNT}}"
BENCH_TARGET_MODE="${3:-${BENCH_TARGET_MODE}}"

INPUT_DIR="${ROOT_DIR}/scanner/inputs/bench"
RANGES_FILE="${INPUT_DIR}/ranges.txt"
STATE_FILE="${INPUT_DIR}/.bench-net"

mkdir -p "${INPUT_DIR}"

if docker network inspect "${BENCH_NET_NAME}" >/dev/null 2>&1; then
  echo "[bench] network ${BENCH_NET_NAME} already exists"
else
  echo "[bench] creating network ${BENCH_NET_NAME} (${BENCH_SUBNET})"
  docker network create --subnet="${BENCH_SUBNET}" "${BENCH_NET_NAME}" >/dev/null
fi

echo "[bench] starting ${BENCH_ALIVE_HOSTS} alive target(s) (${BENCH_TARGET_IMAGE})"
for i in $(seq 1 "${BENCH_ALIVE_HOSTS}"); do
  name="bench-alive-${BENCH_NET_NAME}-${i}"
  if docker ps -a --format '{{.Names}}' | grep -qx "${name}"; then
    docker start "${name}" >/dev/null 2>&1 || true
  else
    docker run -d --name "${name}" --network "${BENCH_NET_NAME}" "${BENCH_TARGET_IMAGE}" >/dev/null
  fi
done

echo "[bench] waiting for targets"
for i in $(seq 1 "${BENCH_ALIVE_HOSTS}"); do
  name="bench-alive-${BENCH_NET_NAME}-${i}"
  for _ in $(seq 1 20); do
    if docker exec "${name}" sh -c 'wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || true'; then
      break
    fi
    sleep 0.5
  done
done

if [[ "${BENCH_TARGET_MODE}" == "list" ]]; then
  echo "[bench] generating ${BENCH_TARGET_COUNT} target IPs in ${BENCH_SUBNET}"
  python3 - "${BENCH_SUBNET}" "${BENCH_TARGET_COUNT}" "${RANGES_FILE}" <<'PY'
import ipaddress
import sys
from pathlib import Path

net = ipaddress.ip_network(sys.argv[1], strict=False)
count = int(sys.argv[2])
out = Path(sys.argv[3])
hosts = [str(h) for h in list(net.hosts())[:count]]
out.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
print(f"wrote {len(hosts)} IPs to {out}")
PY
else
  echo "${BENCH_SUBNET}" > "${RANGES_FILE}"
  echo "[bench] wrote CIDR target ${BENCH_SUBNET} -> ${RANGES_FILE}"
fi

alive_ips=()
for i in $(seq 1 "${BENCH_ALIVE_HOSTS}"); do
  name="bench-alive-${BENCH_NET_NAME}-${i}"
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${name}")"
  [[ -n "${ip}" ]] && alive_ips+=("${ip}")
done

{
  echo "BENCH_NET_NAME=${BENCH_NET_NAME}"
  echo "BENCH_SUBNET=${BENCH_SUBNET}"
  echo "BENCH_TARGET_MODE=${BENCH_TARGET_MODE}"
  echo "BENCH_TARGET_COUNT=${BENCH_TARGET_COUNT}"
  echo "BENCH_ALIVE_HOSTS=${BENCH_ALIVE_HOSTS}"
  echo "ALIVE_IPS=${alive_ips[*]}"
} > "${STATE_FILE}"

echo "[bench] ready: network=${BENCH_NET_NAME} targets=$(wc -l < "${RANGES_FILE}") alive=${#alive_ips[@]}"
echo "[bench] sample alive: ${alive_ips[0]:-none} ..."
