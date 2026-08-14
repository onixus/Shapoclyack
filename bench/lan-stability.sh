#!/usr/bin/env bash
# Measure how reliably naabu recovers known-open ports on a real LAN, and how
# much that varies between identical runs.
#
# Why this exists: on a macOS/Docker Desktop host the pipeline's port stage
# intermittently returns zero open ports for hosts that demonstrably have them,
# and no single knob (rate, scan type, batch size) predicted the outcome --
# repeated identical commands disagreed with each other. A single measurement is
# therefore worthless here; only the spread over repeats says anything. Run this
# on the suspect host and again on a Linux box with a real NIC on the same
# segment, then compare. If the Linux run is tight and the macOS run is not, the
# host network stack is the culprit and moving the scanner is justified. If both
# scatter, the scanner's runtime is not the problem and migrating will not help.
#
# Usage:
#   bench/lan-stability.sh --targets hosts.txt [--repeats 5] [--label mac-docker]
#
# hosts.txt: one IP per line. Keep it small (<= 16) -- ground truth costs one
# scan per host per repeat. Scan only hosts you are authorised to scan.
#
# Needs: bash, awk, sort. Plus either naabu on PATH, or docker (falls back to
# running naabu from the scanner image).
set -euo pipefail

REPEATS=5
LABEL=""
TARGETS=""
IMAGE="${LANBENCH_IMAGE:-ghcr.io/onixus/shapoclyack-aio:kind-dev}"
TOP_PORTS=1000
# On Linux --network host puts the container in the host's namespace, on its real
# NIC -- which is the thing being measured. On Docker Desktop for macOS the same
# flag only reaches the helper VM's network, no closer to the LAN than the
# bridge, so it buys nothing there.
case "$(uname -s)" in
  Linux) DOCKER_NET="host" ;;
  *)     DOCKER_NET="bridge" ;;
esac

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --targets) TARGETS="${2:-}"; shift 2 ;;
    --repeats) REPEATS="${2:-}"; shift 2 ;;
    --label)   LABEL="${2:-}"; shift 2 ;;
    --image)   IMAGE="${2:-}"; shift 2 ;;
    --top-ports) TOP_PORTS="${2:-}"; shift 2 ;;
    --docker-net) DOCKER_NET="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done

[ -n "${TARGETS}" ] || { echo "--targets is required" >&2; usage 1; }
[ -r "${TARGETS}" ] || { echo "cannot read ${TARGETS}" >&2; exit 1; }

# naabu accepts only these three; anything else makes it exit before scanning
# ("invalid top ports option") which reads downstream as "no open ports".
case "${TOP_PORTS}" in
  100|1000|full) ;;
  *) echo "--top-ports must be one of: 100, 1000, full (naabu's accepted set)" >&2; exit 1 ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
grep -vE '^\s*(#|$)' "${TARGETS}" | tr -d '\r' > "${WORK}/hosts.txt"
HOST_COUNT="$(wc -l < "${WORK}/hosts.txt" | tr -d ' ')"
[ "${HOST_COUNT}" -gt 0 ] || { echo "no targets in ${TARGETS}" >&2; exit 1; }

# ---------------------------------------------------------------- runner ----
# Prefer a local naabu so nothing about the measurement runs inside a container
# on a host we are trying to indict. Fall back to the image when absent.
FAILED_RUNS=0

# A SYN scan needs CAP_NET_RAW; without it naabu exits 255 and prints nothing.
# Swallowing that looks exactly like "the host has no open ports", which is the
# very conclusion this harness exists to avoid drawing by accident -- so count
# failures and surface them rather than folding them into the numbers.
if command -v naabu >/dev/null 2>&1; then
  RUNNER="local"
  naabu_run() {
    naabu "$@" 2>/dev/null || { FAILED_RUNS=$((FAILED_RUNS + 1)); return 0; }
  }
elif command -v docker >/dev/null 2>&1; then
  # Default bridge, not --network host: on Docker Desktop for macOS the "host"
  # network is the helper VM's, which reaches the LAN no better than the bridge.
  RUNNER="docker(${IMAGE}, net=${DOCKER_NET})"
  naabu_run() {
    docker run --rm --network "${DOCKER_NET}" --cap-add=NET_RAW --cap-add=NET_ADMIN \
      -v "${WORK}:${WORK}" "${IMAGE}" naabu "$@" 2>/dev/null \
      || { FAILED_RUNS=$((FAILED_RUNS + 1)); return 0; }
  }
else
  echo "need naabu on PATH or docker installed" >&2; exit 1
fi

# Fail fast on a runner that cannot scan at all, instead of reporting its
# silence as a measurement.
preflight() {
  probe_host="$1"
  if ! naabu_run -host "${probe_host}" -p 1 -s s -silent -Pn >/dev/null; then
    return 1
  fi
  [ "${FAILED_RUNS}" -eq 0 ]
}

# ------------------------------------------------------------ environment ----
[ -n "${LABEL}" ] || LABEL="$(uname -s)-$(hostname -s 2>/dev/null || echo host)"
FIRST_TARGET="$(head -1 "${WORK}/hosts.txt")"

echo "# lan-stability"
echo "label:       ${LABEL}"
echo "date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "kernel:      $(uname -srm)"
echo "runner:      ${RUNNER}"
echo "hosts:       ${HOST_COUNT}"
echo "repeats:     ${REPEATS}"
echo "top-ports:   ${TOP_PORTS}"
# A default route on a tunnel interface means LAN traffic may be policy-routed
# or blocked by a VPN kill-switch -- a known source of asymmetric LAN behaviour.
if command -v ip >/dev/null 2>&1; then
  echo "default-route: $(ip route show default 2>/dev/null | head -1)"
  echo "route-to-target: $(ip route get "${FIRST_TARGET}" 2>/dev/null | head -1)"
elif command -v route >/dev/null 2>&1; then
  echo "default-route: $(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
  echo "route-to-target: $(route -n get "${FIRST_TARGET}" 2>/dev/null | awk '/interface:/{print $2}')"
fi
[ -f /.dockerenv ] && echo "in-container: yes" || true
echo

if ! preflight "${FIRST_TARGET}"; then
  echo "Runner cannot execute a SYN scan (naabu exited non-zero on a trivial probe)." >&2
  echo "A SYN scan needs CAP_NET_RAW. With the docker runner that means the image" >&2
  echo "must start with --cap-add=NET_RAW; with a local naabu, setcap the binary:" >&2
  echo "  sudo setcap cap_net_raw,cap_net_admin+eip \$(command -v naabu)" >&2
  echo "Refusing to measure -- every scenario would report zero for the wrong reason." >&2
  exit 3
fi
FAILED_RUNS=0

# ----------------------------------------------------------- ground truth ----
# Single-host scans were the one mode that stayed consistent while everything
# else scattered, so they define truth here. Union over repeats: a port seen
# once is real (false positives need a listener), a port missed once is loss.
echo "==> ground truth (per-host scans, union of ${REPEATS} passes)"
: > "${WORK}/truth.txt"
r=1
while [ "${r}" -le "${REPEATS}" ]; do
  while read -r h; do
    [ -n "${h}" ] || continue
    naabu_run -host "${h}" -silent -Pn -top-ports "${TOP_PORTS}" -s s >> "${WORK}/truth.txt"
  done < "${WORK}/hosts.txt"
  r=$((r + 1))
done
sort -u "${WORK}/truth.txt" -o "${WORK}/truth.txt"
TRUTH_COUNT="$(wc -l < "${WORK}/truth.txt" | tr -d ' ')"
sed 's/^/    /' "${WORK}/truth.txt"
echo "    ground truth: ${TRUTH_COUNT} endpoint(s)"
echo

if [ "${TRUTH_COUNT}" -eq 0 ]; then
  echo "No open ports found at all -- nothing to measure." >&2
  echo "Either the targets genuinely have no open ports, or this host cannot" >&2
  echo "reach them. Verify with a single known-open endpoint before rerunning." >&2
  exit 2
fi

# Known-open port list, for the scenario that keeps probe volume tiny.
KNOWN_PORTS="$(awk -F: '{print $NF}' "${WORK}/truth.txt" | sort -un | paste -sd, -)"

# -------------------------------------------------------------- scenarios ----
# Each pairs a description with the naabu arguments that follow "-list <file>".
# S1 is the control; S2 is what the pipeline actually does.
scenario_args() {
  case "$1" in
    S1_per_host)      echo "PERHOST -silent -Pn -rate 2000 -retries 1 -top-ports ${TOP_PORTS} -s s" ;;
    S2_batch_r2000)   echo "LIST -silent -Pn -rate 2000 -retries 1 -top-ports ${TOP_PORTS} -s s" ;;
    S3_batch_r500)    echo "LIST -silent -Pn -rate 500 -retries 2 -top-ports ${TOP_PORTS} -s s" ;;
    S4_batch_known    ) echo "LIST -silent -Pn -rate 2000 -retries 1 -p ${KNOWN_PORTS} -s s" ;;
    S5_batch_connect) echo "LIST -silent -Pn -rate 2000 -retries 1 -top-ports ${TOP_PORTS} -s c" ;;
  esac
}
SCENARIOS="S1_per_host S2_batch_r2000 S3_batch_r500 S4_batch_known S5_batch_connect"

printf '%-18s %-8s %s\n' "scenario" "recall%" "per-repeat recall%"
printf '%-18s %-8s %s\n' "------------------" "-------" "-------------------"

JSON="${WORK}/result.json"
{ echo "{"; echo "  \"label\": \"${LABEL}\","; echo "  \"truth\": ${TRUTH_COUNT},"; echo "  \"scenarios\": {"; } > "${JSON}"
sep=""

for s in ${SCENARIOS}; do
  spec="$(scenario_args "${s}")"
  mode="${spec%% *}"; args="${spec#* }"
  : > "${WORK}/recalls.txt"
  r=1
  while [ "${r}" -le "${REPEATS}" ]; do
    : > "${WORK}/found.txt"
    if [ "${mode}" = "PERHOST" ]; then
      while read -r h; do
        [ -n "${h}" ] || continue
        # shellcheck disable=SC2086
        naabu_run -host "${h}" ${args} >> "${WORK}/found.txt"
      done < "${WORK}/hosts.txt"
    else
      # shellcheck disable=SC2086
      naabu_run -list "${WORK}/hosts.txt" ${args} >> "${WORK}/found.txt"
    fi
    sort -u "${WORK}/found.txt" -o "${WORK}/found.txt"
    hit="$(comm -12 "${WORK}/truth.txt" "${WORK}/found.txt" | wc -l | tr -d ' ')"
    awk -v h="${hit}" -v t="${TRUTH_COUNT}" 'BEGIN{printf "%d\n", (h*100)/t}' >> "${WORK}/recalls.txt"
    r=$((r + 1))
  done

  stats="$(sort -n "${WORK}/recalls.txt" | awk '
    {v[NR]=$1; s+=$1}
    END{
      med = (NR%2) ? v[(NR+1)/2] : int((v[NR/2]+v[NR/2+1])/2)
      printf "%d %d %d", med, v[1], v[NR]
    }')"
  med="$(echo "${stats}" | cut -d' ' -f1)"
  lo="$(echo "${stats}" | cut -d' ' -f2)"
  hi="$(echo "${stats}" | cut -d' ' -f3)"
  series="$(paste -sd' ' "${WORK}/recalls.txt")"

  # A wide min..max on identical repeats is the finding, not noise to average away.
  flag=""
  [ "$((hi - lo))" -ge 25 ] && flag="  <-- unstable"
  printf '%-18s %-8s %s%s\n' "${s}" "${med}" "${series}" "${flag}"

  printf '%s    "%s": {"median": %s, "min": %s, "max": %s, "runs": [%s]}' \
    "${sep}" "${s}" "${med}" "${lo}" "${hi}" "$(paste -sd, "${WORK}/recalls.txt")" >> "${JSON}"
  sep=$',\n'
done

{ echo; echo "  }"; echo "}"; } >> "${JSON}"

OUT="lan-stability-${LABEL}-$(date -u +%Y%m%dT%H%M%SZ).json"
cp "${JSON}" "${OUT}"
echo
if [ "${FAILED_RUNS}" -gt 0 ]; then
  echo "WARNING: ${FAILED_RUNS} naabu invocation(s) exited non-zero and contributed"
  echo "zero results. Treat the numbers above as a lower bound, not a measurement."
  echo
fi
echo "recall% = share of the ground-truth endpoints this scenario recovered."
echo "S1 is the control (per-host); S2 is what the pipeline's port stage runs."
echo "Compare the SPREAD between hosts, not just the median."
echo "json: ${OUT}"
