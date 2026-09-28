#!/usr/bin/env bash
# Local / CI validation for Shapoclyack kustomize overlays.
#
# OCTO_K8S_RENDER_DIR=<dir>: also keep every render there, as <dir>/base.yaml
# and <dir>/overlays/<name>.yaml — what tests/test_k8s_pod_security.py and
# tests/test_k8s_topology.py read where kubectl is not installed (the Jenkins
# test containers, #338).
set -euo pipefail

render_dir="${OCTO_K8S_RENDER_DIR:-}"
if [[ -n "${render_dir}" && "${render_dir}" != /* ]]; then
  render_dir="${PWD}/${render_dir}"
fi
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

if [[ -n "${render_dir}" ]]; then
  mkdir -p "${render_dir}/overlays"
fi
for target in "${targets[@]}"; do
  echo "kustomize: shapoclyack/${target}"
  kubectl kustomize "shapoclyack/${target}" > .kustomize-validate.out
  if [[ -n "${render_dir}" ]]; then
    cp .kustomize-validate.out "${render_dir}/${target}.yaml"
  fi
done

rm -f .kustomize-validate.out
echo OK
