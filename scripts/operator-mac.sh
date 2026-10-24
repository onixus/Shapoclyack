#!/usr/bin/env bash
# Explicit staging (download) is separate from offline startup.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPERATOR_MODELS_DIR="${OPERATOR_MODELS_DIR:-${ROOT_DIR}/.operator-models}"
export OPERATOR_MODELS_DIR
MODEL_FILE="${OPERATOR_MODELS_DIR}/Qwen3.5-9B-Q4_K_M.gguf"
MODEL_SHA256=03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8
MODEL_REVISION=3885219b6810b007914f3a7950a8d1b469d598a5
RUNTIME_IMAGE=ghcr.io/ggml-org/llama.cpp@sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44

verify_model() {
  test -f "$MODEL_FILE" && test ! -L "$MODEL_FILE" || { echo 'Missing regular model file' >&2; exit 1; }
  local actual
  actual="$(shasum -a 256 "$MODEL_FILE" | awk '{print $1}')"
  test "$actual" = "$MODEL_SHA256" || { echo 'Model checksum mismatch; refusing launch' >&2; exit 1; }
}

case "${1:-up}" in
  download)
    mkdir -p "$OPERATOR_MODELS_DIR"
    test ! -L "$OPERATOR_MODELS_DIR" && test ! -L "${MODEL_FILE}.part" || exit 1
    curl --fail --location --retry 3 --connect-timeout 15 \
      "https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/${MODEL_REVISION}/Qwen3.5-9B-Q4_K_M.gguf?download=true" \
      --output "${MODEL_FILE}.part"
    actual="$(shasum -a 256 "${MODEL_FILE}.part" | awk '{print $1}')"
    test "$actual" = "$MODEL_SHA256" || { echo 'Downloaded model checksum mismatch' >&2; exit 1; }
    mv "${MODEL_FILE}.part" "$MODEL_FILE"
    chmod 444 "$MODEL_FILE"
    docker pull "$RUNTIME_IMAGE"
    ;;
  verify) verify_model ;;
  up)
    verify_model
    docker image inspect "$RUNTIME_IMAGE" >/dev/null
    if ! docker network inspect shapo-operator-offline >/dev/null 2>&1; then
      docker network create --internal --subnet 172.30.83.0/24 shapo-operator-offline >/dev/null
    fi
    network_config="$(docker network inspect shapo-operator-offline --format '{{.Internal}} {{(index .IPAM.Config 0).Subnet}}')"
    test "$network_config" = 'true 172.30.83.0/24' || { echo 'Unexpected inference network; refusing launch' >&2; exit 1; }
    docker compose -p shapo-operator -f "$ROOT_DIR/compose.operator-mac.yml" up -d --pull never
    ;;
  down|ps|logs)
    docker compose -p shapo-operator -f "$ROOT_DIR/compose.operator-mac.yml" "$1"
    ;;
  *) echo 'Usage: bash scripts/operator-mac.sh [download|verify|up|down|ps|logs]' >&2; exit 2 ;;
esac
