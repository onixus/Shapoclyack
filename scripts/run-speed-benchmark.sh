#!/usr/bin/env bash
# Run the speed benchmark matrix (docs/benchmark-speed.md) on this host.
# No target arguments exist: every address is generated inside 198.19.0.0/16
# and lives in a throwaway network namespace.
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 OUTPUT_DIRECTORY   (env: SCALE=small|full RATE=pps REPEATS=n TOOLS=a,b)" >&2
  exit 2
fi
if [[ $EUID -ne 0 ]]; then
  echo 'needs root: it creates network namespaces and raw sockets' >&2
  exit 2
fi
if [[ -e "$1" ]]; then
  echo "$1 already exists; choose a fresh directory" >&2
  exit 2
fi
source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scale="${SCALE:-small}"
rate="${RATE:-10000}"
repeats="${REPEATS:-5}"
tools="${TOOLS:-naabu-syn,naabu-connect,masscan}"
mkdir -p "$1"
output_root="$(cd "$1" && pwd)"
# "-dirty" when what the run uses (scripts) has uncommitted
# changes or untracked files: the results then come from code that this hash
# alone does not reproduce.
if commit="$(git -C "$source_root" rev-parse HEAD 2>/dev/null)"; then
  if [[ -n "$(git -C "$source_root" status --porcelain --untracked-files=all -- scripts)" ]]; then
    commit="$commit-dirty"
  fi
  echo "$commit" > "$output_root/source-commit.txt"
fi
run() {
  local name="$1"; shift
  python3 "$source_root/scripts/benchmark-speed.py" run --scale "$scale" --rate "$rate" \
    --repeats "$repeats" --tools "$tools" --output "$output_root/$name" "$@"
}
run sparse --scenario sparse
run dense --scenario dense
run allports --scenario allports
run dense-impaired --scenario dense --impaired
echo "results in $output_root"
