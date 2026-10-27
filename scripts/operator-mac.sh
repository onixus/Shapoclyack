#!/usr/bin/env bash
# Explicit staging (download) is separate from offline startup.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPERATOR_MODELS_DIR="${OPERATOR_MODELS_DIR:-${ROOT_DIR}/.operator-models}"
export OPERATOR_MODELS_DIR
OPERATOR_MODEL_STORAGE="${OPERATOR_MODEL_STORAGE:-native}"
export OPERATOR_MODEL_STORAGE
case "$OPERATOR_MODEL_STORAGE" in native|bind) ;; *) echo 'Model storage must be native or bind' >&2; exit 2 ;; esac
COMPOSE=(docker compose -p shapo-operator -f "$ROOT_DIR/compose.operator-mac.yml")
if [ "$OPERATOR_MODEL_STORAGE" = native ]; then
  COMPOSE+=(-f "$ROOT_DIR/compose.operator-mac.native.yml")
fi
MODEL_FILE="${OPERATOR_MODELS_DIR}/Qwen3.5-9B-Q4_K_M.gguf"
MODEL_SHA256=03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8
MODEL_REVISION=3885219b6810b007914f3a7950a8d1b469d598a5
EMBEDDING_FILE="${OPERATOR_MODELS_DIR}/Qwen3-Embedding-0.6B-Q8_0.gguf"
EMBEDDING_SHA256=06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439
EMBEDDING_REVISION=370f27d7550e0def9b39c1f16d3fbaa13aa67728
RUNTIME_IMAGE=ghcr.io/ggml-org/llama.cpp:server@sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44

verify_model() {
  test -f "$MODEL_FILE" && test ! -L "$MODEL_FILE" || { echo 'Missing regular model file' >&2; exit 1; }
  local actual
  actual="$(shasum -a 256 "$MODEL_FILE" | awk '{print $1}')"
  test "$actual" = "$MODEL_SHA256" || { echo 'Model checksum mismatch; refusing launch' >&2; exit 1; }
  test -f "$EMBEDDING_FILE" && test ! -L "$EMBEDDING_FILE" || { echo 'Missing embedding file' >&2; exit 1; }
  actual="$(shasum -a 256 "$EMBEDDING_FILE" | awk '{print $1}')"
  test "$actual" = "$EMBEDDING_SHA256" || { echo 'Embedding checksum mismatch' >&2; exit 1; }
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
    test ! -L "${EMBEDDING_FILE}.part" || exit 1
    curl --fail --location --retry 3 --connect-timeout 15 \
      "https://huggingface.co/Qwen/Qwen3-Embedding-0.6B-GGUF/resolve/${EMBEDDING_REVISION}/Qwen3-Embedding-0.6B-Q8_0.gguf?download=true" \
      --output "${EMBEDDING_FILE}.part"
    actual="$(shasum -a 256 "${EMBEDDING_FILE}.part" | awk '{print $1}')"
    test "$actual" = "$EMBEDDING_SHA256" || { echo 'Embedding download checksum mismatch' >&2; exit 1; }
    mv "${EMBEDDING_FILE}.part" "$EMBEDDING_FILE"
    chmod 444 "$EMBEDDING_FILE"
    docker pull "$RUNTIME_IMAGE"
    ;;
  verify) verify_model ;;
  stage)
    python3 "$ROOT_DIR/scripts/operator-runtime-manifest.py" stage-volume
    ;;
  up)
    if [ "$OPERATOR_MODEL_STORAGE" = native ]; then
      stage_result="$(python3 "$ROOT_DIR/scripts/operator-runtime-manifest.py" stage-volume)"
      OPERATOR_MODELS_VOLUME="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["volume_name"])' <<< "$stage_result")"
      export OPERATOR_MODELS_VOLUME
    else
      verify_model
      echo 'Host bind storage is a diagnostic profile; native-volume acceptance is not implied.' >&2
    fi
    docker image inspect "$RUNTIME_IMAGE" >/dev/null
    if ! docker network inspect shapo-operator-offline >/dev/null 2>&1; then
      docker network create --internal --subnet 172.30.83.0/24 shapo-operator-offline >/dev/null
    fi
    network_config="$(docker network inspect shapo-operator-offline --format '{{.Internal}} {{(index .IPAM.Config 0).Subnet}}')"
    test "$network_config" = 'true 172.30.83.0/24' || { echo 'Unexpected inference network; refusing launch' >&2; exit 1; }
    "${COMPOSE[@]}" up -d --pull never --wait --wait-timeout 180
    python3 "$ROOT_DIR/scripts/operator-runtime-manifest.py"
    ;;
  down|ps|logs)
    if [ "$OPERATOR_MODEL_STORAGE" = native ] && [ -z "${OPERATOR_MODELS_VOLUME:-}" ]; then
      OPERATOR_MODELS_VOLUME="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["volume"]["name"])' "$ROOT_DIR/.operator-local/runtime/model-storage.json")"
      export OPERATOR_MODELS_VOLUME
    fi
    "${COMPOSE[@]}" "$1"
    ;;
  *) echo 'Usage: bash scripts/operator-mac.sh [download|verify|stage|up|down|ps|logs]' >&2; exit 2 ;;
esac
