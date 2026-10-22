#!/usr/bin/env bash
# Speed benchmark on a test stand (docs/benchmark-speed.md § Stand): build the
# released scanner image plus libpcap0.8 and masscan, then run the matrix in a
# privileged container that creates its own throwaway network namespaces.
# Nothing it sends leaves the container's namespaces; no target arguments.
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 OUTPUT_DIRECTORY   (env: RATES='1000 10000 100000' REPEATS=5 SCALE=small)" >&2
  exit 2
fi
if [[ -e "$1" ]]; then
  echo "$1 already exists; choose a fresh directory" >&2
  exit 2
fi
source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rates="${RATES:-1000 10000 100000}"
repeats="${REPEATS:-5}"
scale="${SCALE:-small}"
image='shapo-speed-stand:local'
docker build --pull=false -t "$image" -f "$source_root/docs/benchmarks/speed/Stand.Dockerfile" "$source_root/docs/benchmarks/speed"
mkdir -p "$1"
output_root="$(cd "$1" && pwd)"
git -C "$source_root" rev-parse HEAD > "$output_root/source-commit.txt" 2>/dev/null || true
docker image inspect "$image" --format '{{.Id}}' > "$output_root/stand-image.txt"
# --network none: the container has only loopback, and the harness adds two
# namespaces joined to each other and nothing else. --privileged is what
# creating network namespaces and raw sockets inside the container takes.
bench() {
  docker run --rm --network none --privileged \
    --mount "type=bind,source=$source_root/scripts,target=/bench,readonly" \
    --mount "type=bind,source=$output_root,target=/results" \
    "$image" run --scale "$scale" --repeats "$repeats" "$@"
}
for rate in $rates; do
  bench --scenario dense --rate "$rate" --output "/results/dense-$rate"
done
bench --scenario sparse --rate "${rates##* }" --output /results/sparse
bench --scenario allports --rate "${rates##* }" --output /results/allports
echo "results in $output_root"
