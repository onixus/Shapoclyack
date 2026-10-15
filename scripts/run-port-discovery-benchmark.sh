#!/usr/bin/env bash
# Run only in a new disposable namespace. No external target arguments exist.
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi
source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$1"
output_root="$(cd "$1" && pwd)"
if [[ -e "$output_root/run" ]]; then
  echo 'OUTPUT_DIRECTORY/run already exists; choose a fresh directory' >&2
  exit 2
fi
runtime='shapo-issue452-benchmark:local'
# The Pulse build the committed benchmark ran (run-provenance.json).
PULSE_IMAGE="${PULSE_IMAGE:-ghcr.io/onixus/pulse:v1.4.0@sha256:70ab0ef673f1b49a9a52d8648999efb711dc0fa8e8cf81bab461e02dbf751ce2}"
if ! docker image inspect "$runtime" >/dev/null 2>&1; then
  build_root="$(mktemp -d)"
  naabu_input=''
  pulse_input=''
  cleanup() {
    [[ -z "$naabu_input" ]] || docker rm -f "$naabu_input" >/dev/null
    [[ -z "$pulse_input" ]] || docker rm -f "$pulse_input" >/dev/null
    rm -rf "$build_root"
  }
  trap cleanup EXIT
  tools='shapo-go-tools-check:latest'
  if ! docker image inspect "$tools" >/dev/null 2>&1; then
    tools='shapo-issue452-go-tools:local'
    docker build --target go-tools -t "$tools" "$source_root"
  fi
  naabu_input="$(docker create --network none "$tools")"
  docker cp "$naabu_input:/out/naabu" "$build_root/naabu"
  docker rm "$naabu_input" >/dev/null
  naabu_input=''
  pulse_input="$(docker create --network none "$PULSE_IMAGE")"
  docker cp "$pulse_input:/pulse" "$build_root/pulse"
  docker rm "$pulse_input" >/dev/null
  pulse_input=''
  docker build --pull=false -t "$runtime" \
    -f "$source_root/docs/benchmarks/port-discovery-20261015/Runtime.Dockerfile" "$build_root"
fi
image="$(docker image inspect "$runtime" --format '{{.Id}}')"
docker image inspect "$runtime" --format '{{.Id}} {{.Architecture}}' > "$output_root/runtime-image.txt"
docker run --pull never --rm --network none --cap-add NET_RAW --cap-add NET_ADMIN \
  --user 0 --mount "type=bind,source=$source_root/scripts,target=/bench,readonly" \
  --mount "type=bind,source=$output_root,target=/results" \
  --entrypoint python "$image" /bench/benchmark-port-discovery.py \
  --output /results/run --repeats 5
