#!/usr/bin/env bash
# Local / CI validation for Shapoclyack kustomize overlays.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi

# Discovered, not listed: the hand-written list had drifted and left
# overlays/kind-restore and overlays/enrichment-advisories unrendered — the
# only two nobody would notice breaking, because nothing else builds them.
targets=(base)
for dir in shapoclyack/overlays/*/; do
  targets+=("overlays/$(basename "${dir}")")
done

for target in "${targets[@]}"; do
  echo "kustomize: shapoclyack/${target}"
  kubectl kustomize "shapoclyack/${target}" > .kustomize-validate.out
done

rm -f .kustomize-validate.out
echo OK
