#!/usr/bin/env bash
# Synthetic load test: spin up N target containers on a private docker network,
# run the scanner image against them, optionally exercise --resume, and validate results.
#
# Usage:
#   tests/load/run.sh [IMAGE] [--hosts N] [--config PATH] [--resume-test] [--run-id ID]
#
# Environment:
#   TARGET_IMAGE   target container image (default: nginx:alpine)
#   MIN_FRACTION   minimum fraction of targets that must pass (default: 0.95)
set -euo pipefail

IMAGE="${1:-network-scan-cli:ci}"
shift || true

HOST_COUNT=16
CONFIG_REL="tests/load/config.yaml"
RESUME_TEST=0
RUN_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts)
      HOST_COUNT="${2:?--hosts requires a number}"
      shift 2
      ;;
    --config)
      CONFIG_REL="${2:?--config requires a path}"
      shift 2
      ;;
    --resume-test)
      RESUME_TEST=1
      shift
      ;;
    --run-id)
      RUN_ID="${2:?--run-id requires a value}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

TARGET_IMAGE="${TARGET_IMAGE:-nginx:alpine}"
MIN_FRACTION="${MIN_FRACTION:-0.95}"
NET="scan-load-net-$$"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
SCANNER_NAME="scanner-load-$$"
METRICS_FILE="${WORK}/metrics.json"
TARGETS_FILE="${WORK}/targets.txt"
PEAK_FILE="${WORK}/peak_rss_kb"
CONFIG_SRC="${ROOT_DIR}/${CONFIG_REL}"
START_TS="$(date +%s)"

cleanup() {
  if [[ "${KEEP_WORK:-0}" == "1" ]]; then
    echo "[load] KEEP_WORK=1 — leaving ${WORK}" >&2
    return 0
  fi
  docker rm -f "${SCANNER_NAME}" >/dev/null 2>&1 || true
  for name in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep "^load-target-${NET}-" || true); do
    docker rm -f "${name}" >/dev/null 2>&1 || true
  done
  docker network rm "${NET}" >/dev/null 2>&1 || true
  rm -rf "${WORK}" 2>/dev/null || sudo rm -rf "${WORK}" 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -f "${CONFIG_SRC}" ]]; then
  echo "[load] config not found: ${CONFIG_SRC}" >&2
  exit 2
fi

if [[ "${RESUME_TEST}" -eq 1 && -z "${RUN_ID}" ]]; then
  RUN_ID="load-resume-$$"
fi

echo "[load] creating network and ${HOST_COUNT} target(s) (${TARGET_IMAGE})"
docker network create "${NET}" >/dev/null

target_names=()
for i in $(seq 1 "${HOST_COUNT}"); do
  name="load-target-${NET}-${i}"
  target_names+=("${name}")
  docker run -d --name "${name}" --network "${NET}" "${TARGET_IMAGE}" >/dev/null
done

echo "[load] waiting for targets to become ready"
for name in "${target_names[@]}"; do
  for _ in $(seq 1 15); do
    if docker exec "${name}" sh -c 'wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || true'; then
      break
    fi
    sleep 1
  done
done

: > "${TARGETS_FILE}"
for name in "${target_names[@]}"; do
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${name}")"
  if [[ -z "${ip}" ]]; then
    echo "[load] failed to resolve IP for ${name}" >&2
    exit 1
  fi
  echo "${ip}" >> "${TARGETS_FILE}"
done

mkdir -p "${WORK}/inputs" "${WORK}/config" "${WORK}/output" "${WORK}/state"
cp "${TARGETS_FILE}" "${WORK}/inputs/ranges.txt"
printf '# no domains\n' > "${WORK}/inputs/domains.txt"
printf '80\n' > "${WORK}/inputs/ports.txt"
cp "${CONFIG_SRC}" "${WORK}/config/default.yaml"
chmod -R 777 "${WORK}"

scanner_args=(--config scanner/config/default.yaml --mode safe)
if [[ -n "${RUN_ID}" ]]; then
  scanner_args+=(--run-id "${RUN_ID}")
fi

docker_scan() {
  docker run --rm --network "${NET}" \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    --name "${SCANNER_NAME}" \
    -v "${WORK}/inputs:/app/scanner/inputs" \
    -v "${WORK}/config:/app/scanner/config" \
    -v "${WORK}/output:/app/scanner/output" \
    -v "${WORK}/state:/app/scanner/state" \
    "${IMAGE}" "${scanner_args[@]}" "$@"
}

_run_with_timeout() {
  local limit="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "${limit}" "$@"
  else
    "$@"
  fi
}

_start_peak_monitor() {
  echo 0 > "${PEAK_FILE}"
  python3 - "${SCANNER_NAME}" "${PEAK_FILE}" <<'PY' &
import re
import subprocess
import sys
import time
from pathlib import Path

name = sys.argv[1]
out = Path(sys.argv[2])
peak_kb = 0
pat = re.compile(r"^([\d.]+)\s*([KMG]?i?B)")

def to_kb(value: str, unit: str) -> int:
    num = float(value)
    unit = unit.upper().replace("IB", "B")
    mult = {"B": 1 / 1024, "KB": 1, "KIB": 1, "MB": 1024, "MIB": 1024, "GB": 1024 * 1024, "GIB": 1024 * 1024}
    return int(num * mult.get(unit, 1))

while True:
    proc = subprocess.run(["docker", "inspect", name], capture_output=True, timeout=5)
    if proc.returncode != 0:
        break
    try:
        proc = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", name],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        time.sleep(1)
        continue
    if proc.returncode == 0 and proc.stdout.strip():
        first = proc.stdout.strip().split()[0]
        m = pat.match(first)
        if m:
            peak_kb = max(peak_kb, to_kb(m.group(1), m.group(2)))
    time.sleep(1)

out.write_text(str(peak_kb), encoding="utf-8")
PY
  echo $!
}

_stop_peak_monitor() {
  local mon_pid="$1"
  local waited=0
  while kill -0 "${mon_pid}" 2>/dev/null && (( waited < 15 )); do
    sleep 1
    waited=$((waited + 1))
  done
  kill "${mon_pid}" 2>/dev/null || true
  wait "${mon_pid}" 2>/dev/null || true
  cat "${PEAK_FILE}"
}

_resume_interrupt_stage() {
  echo "ports"
}

_checkpoint_path() {
  if [[ -n "${RUN_ID}" ]] && grep -q 'per_run_output: true' "${WORK}/config/default.yaml"; then
    echo "${WORK}/state/runs/${RUN_ID}/checkpoint.json"
  else
    echo "${WORK}/state/checkpoint.json"
  fi
}

_wait_for_checkpoint_progress() {
  local ckpt="$1"
  local timeout_sec="${2:-180}"
  local want="${3:-any}"
  local elapsed=0
  while [[ "${elapsed}" -lt "${timeout_sec}" ]]; do
    if [[ -f "${ckpt}" ]]; then
      if CKPT_WANT="${want}" python3 - "${ckpt}" <<'PY'
import json, os, sys
from pathlib import Path

want = os.environ.get("CKPT_WANT", "any")
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
items = data.get("items", {})
stages = data.get("stages", {})

def has(stage: str) -> bool:
    return bool(items.get(stage)) or bool(stages.get(stage))

if want == "discover" and has("discover"):
    raise SystemExit(0)
if want == "ports" and has("ports"):
    raise SystemExit(0)
if want == "nse" and has("nse"):
    raise SystemExit(0)
if want == "any" and (has("discover") or has("ports") or has("nse")):
    raise SystemExit(0)
raise SystemExit(1)
PY
      then
        return 0
      fi
    fi
    if (( elapsed > 0 && elapsed % 30 == 0 )); then
      echo "[load] still waiting for checkpoint (${want}, ${elapsed}s) at ${ckpt}"
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

SCAN_RC=0
PEAK_RSS_KB=0

if [[ "${RESUME_TEST}" -eq 1 ]]; then
  echo "[load] starting scanner in background for resume test"
  docker run -d --network "${NET}" \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    --name "${SCANNER_NAME}" \
    -v "${WORK}/inputs:/app/scanner/inputs" \
    -v "${WORK}/config:/app/scanner/config" \
    -v "${WORK}/output:/app/scanner/output" \
    -v "${WORK}/state:/app/scanner/state" \
    "${IMAGE}" "${scanner_args[@]}" >/dev/null

  ckpt="$(_checkpoint_path)"
  interrupt_stage="$(_resume_interrupt_stage)"
  ckpt_timeout="${CHECKPOINT_TIMEOUT_SEC:-120}"
  # Interrupt before NSE: with skip_discovery, discover finishes instantly (safe cut point).
  if ! _wait_for_checkpoint_progress "${ckpt}" "${ckpt_timeout}" "${interrupt_stage}"; then
    echo "[load] timed out waiting for ${interrupt_stage} checkpoint progress at ${ckpt}" >&2
    docker logs "${SCANNER_NAME}" 2>&1 | tail -50 || true
    exit 1
  fi
  echo "[load] ${interrupt_stage} checkpoint progress detected; stopping scanner for resume"
  docker kill "${SCANNER_NAME}" >/dev/null 2>&1 || true
  docker rm -f "${SCANNER_NAME}" >/dev/null 2>&1 || true

  echo "[load] resuming scan (--resume --run-id ${RUN_ID})"
  mon_pid="$(_start_peak_monitor)"
  scan_timeout="${SCAN_TIMEOUT_SEC:-2400}"
  set +e
  _run_with_timeout "${scan_timeout}" docker run --rm --network "${NET}" \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    --name "${SCANNER_NAME}" \
    -v "${WORK}/inputs:/app/scanner/inputs" \
    -v "${WORK}/config:/app/scanner/config" \
    -v "${WORK}/output:/app/scanner/output" \
    -v "${WORK}/state:/app/scanner/state" \
    "${IMAGE}" "${scanner_args[@]}" --resume
  SCAN_RC=$?
  set -e
  if [[ "${SCAN_RC}" -eq 124 ]]; then
    echo "[load] resume scan exceeded ${scan_timeout}s timeout" >&2
  fi
  peak2="$(_stop_peak_monitor "${mon_pid}")"
  PEAK_RSS_KB="${peak2}"
else
  echo "[load] running scanner (${HOST_COUNT} targets)"
  mon_pid="$(_start_peak_monitor)"
  scan_timeout="${SCAN_TIMEOUT_SEC:-2400}"
  set +e
  _run_with_timeout "${scan_timeout}" docker run --rm --network "${NET}" \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    --name "${SCANNER_NAME}" \
    -v "${WORK}/inputs:/app/scanner/inputs" \
    -v "${WORK}/config:/app/scanner/config" \
    -v "${WORK}/output:/app/scanner/output" \
    -v "${WORK}/state:/app/scanner/state" \
    "${IMAGE}" "${scanner_args[@]}"
  SCAN_RC=$?
  set -e
  if [[ "${SCAN_RC}" -eq 124 ]]; then
    echo "[load] scan exceeded ${scan_timeout}s timeout" >&2
  fi
  PEAK_RSS_KB="$(_stop_peak_monitor "${mon_pid}")"
fi

END_TS="$(date +%s)"
DURATION_SEC="$((END_TS - START_TS))"

if [[ "${SCAN_RC}" -ne 0 ]]; then
  echo "[load] scanner exited with code ${SCAN_RC}" >&2
  exit "${SCAN_RC}"
fi

OUTPUT_DIR="${WORK}/output"
if [[ -n "${RUN_ID}" ]] && grep -q 'per_run_output: true' "${WORK}/config/default.yaml"; then
  OUTPUT_DIR="${WORK}/output/runs/${RUN_ID}"
fi

echo "[load] validating results in ${OUTPUT_DIR}"
python3 "${ROOT_DIR}/tests/load/check_results.py" \
  "${OUTPUT_DIR}" "${TARGETS_FILE}" \
  --min-fraction "${MIN_FRACTION}" \
  --metrics-out "${METRICS_FILE}"

python3 - "${METRICS_FILE}" "${HOST_COUNT}" "${DURATION_SEC}" "${PEAK_RSS_KB}" "${RESUME_TEST}" "${RUN_ID}" <<'PY'
import json, sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data.update({
    "host_count": int(sys.argv[2]),
    "duration_sec": float(sys.argv[3]),
    "peak_rss_kb": int(sys.argv[4]),
    "peak_rss_mb": round(int(sys.argv[4]) / 1024, 1),
    "resume_test": bool(int(sys.argv[5])),
    "run_id": sys.argv[6] or None,
})
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(json.dumps(data))
PY

echo "[load] done in ${DURATION_SEC}s (peak RSS ~$((PEAK_RSS_KB / 1024)) MiB)"

if [[ -n "${METRICS_COPY_TO:-}" ]]; then
  mkdir -p "$(dirname "${METRICS_COPY_TO}")"
  cp "${METRICS_FILE}" "${METRICS_COPY_TO}"
  echo "[load] metrics copied to ${METRICS_COPY_TO}"
fi
