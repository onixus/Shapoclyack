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
read -r -a rates <<< "${RATES:-1000 10000 100000}"
if [[ ${#rates[@]} -eq 0 ]]; then
  echo 'RATES is empty' >&2
  exit 2
fi
repeats="${REPEATS:-5}"
scale="${SCALE:-small}"
image='shapo-speed-stand:local'
docker build --pull=false -t "$image" -f "$source_root/docs/benchmarks/speed/Stand.Dockerfile" "$source_root/docs/benchmarks/speed"
mkdir -p "$1"
output_root="$(cd "$1" && pwd)"
# "-dirty" when the tree has uncommitted changes: the results then come from
# code that this hash alone does not reproduce.
if commit="$(git -C "$source_root" rev-parse HEAD 2>/dev/null)"; then
  git -C "$source_root" diff --quiet HEAD -- || commit="$commit-dirty"
  echo "$commit" > "$output_root/source-commit.txt"
fi
docker image inspect "$image" --format '{{.Id}}' > "$output_root/stand-image.txt"
# --network none: the container has only loopback, and the harness adds two
# namespaces joined to each other and nothing else. --privileged is what
# creating network namespaces and raw sockets inside the container takes.
bench() {
  docker run --rm --network none --privileged --user 0:0 \
    --mount "type=bind,source=$source_root/scripts,target=/bench,readonly" \
    --mount "type=bind,source=$output_root,target=/results" \
    "$image" run --scale "$scale" --repeats "$repeats" "$@"
}
for rate in "${rates[@]}"; do
  bench --scenario dense --rate "$rate" --output "/results/dense-$rate"
done
fastest="${rates[${#rates[@]}-1]}"
bench --scenario sparse --rate "$fastest" --output /results/sparse
bench --scenario allports --rate "$fastest" --output /results/allports
echo "results in $output_root"
