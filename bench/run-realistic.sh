#!/usr/bin/env bash
# Realistic discovery bench: CIDR /22, naabu host discovery (no skip_discovery).
#
# Usage:
#   bench/run-realistic.sh [alive_hosts]   # default 400 nginx on 10.99.0.0/22
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export BENCH_CONFIG="${BENCH_CONFIG:-scanner/config/discovery-bench-realistic.yaml}"
export BENCH_MODE="${BENCH_MODE:-balanced}"
export BENCH_CPUS="${BENCH_CPUS:-$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
export BENCH_DOCKER_LIMITS="${BENCH_DOCKER_LIMITS:-1}"
export BENCH_TARGET_MODE="${BENCH_TARGET_MODE:-cidr}"

exec "${ROOT_DIR}/bench/run-discovery.sh" "${1:-400}"
