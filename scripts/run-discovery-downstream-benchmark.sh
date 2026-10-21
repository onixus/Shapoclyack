#!/usr/bin/env bash
# Fixed network-none fixture; no external scope argument is accepted.
set -euo pipefail
[[ $# == 1 ]] || { echo "Usage: $0 FRESH_OUTPUT_DIRECTORY" >&2; exit 2; }
source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$1"
output_root="$(cd "$1" && pwd)"
[[ ! -e "$output_root/downstream" ]] || { echo 'Choose fresh output directory' >&2; exit 2; }
image='sha256:027c27a08d698850806df0f724fa9fa9dd240f40e840429fe5253e38b2516d0e'
donor='sha256:9c84d15ed0392d9f49842cfa749d0a1d21df991ef93a6778a087cbdd78d367f3'
build_root="$(mktemp -d)"
container=''
cleanup() {
  [[ -z "$container" ]] || docker rm -f "$container" >/dev/null
  rm -rf "$build_root"
}
trap cleanup EXIT
container="$(docker create --network none "$donor")"
docker cp "$container:/out/nuclei" "$build_root/nuclei"
docker rm "$container" >/dev/null
container=''
docker run --pull never --rm --network none --cap-add NET_RAW --cap-add NET_ADMIN --user 0 \
  --mount "type=bind,source=$source_root/scripts,target=/bench,readonly" \
  --mount "type=bind,source=$build_root/nuclei,target=/usr/local/bin/nuclei,readonly" \
  --mount "type=bind,source=$source_root/docs/benchmarks/port-discovery-20261020,target=/template,readonly" \
  --mount "type=bind,source=$output_root,target=/results" \
  --entrypoint python "$image" /bench/benchmark-discovery-downstream.py --output /results/downstream --repeats 5
