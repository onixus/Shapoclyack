#!/usr/bin/env bash
# Local dev cluster for Shapoclyack — replaces `docker compose up --build`.
#
# Builds the all-in-one image, loads it into a kind cluster, and applies
# k8s/shapoclyack/overlays/kind-dev (dev resources + local image tag + NodePort).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

CLUSTER_NAME="shapoclyack-dev"
IMAGE="ghcr.io/onixus/shapoclyack-aio:kind-dev"
NAMESPACE="network-scan"

if ! kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
  echo "==> Creating kind cluster '${CLUSTER_NAME}'"
  kind create cluster --config k8s/kind-config.yaml
else
  echo "==> Reusing existing kind cluster '${CLUSTER_NAME}'"
fi

echo "==> Building ${IMAGE}"
# Pulse ships from a private repo, so the image build needs a GitHub token to
# resolve the release asset. Dockerfile.allinone declares the secret with
# required=false and falls back to the public download URL without it -- which
# 404s for a private repo, so pass the token whenever one is available.
BUILD_SECRET=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  BUILD_SECRET=(--secret "id=github_token,env=GITHUB_TOKEN")
elif command -v gh >/dev/null 2>&1 && GITHUB_TOKEN="$(gh auth token 2>/dev/null)" && [ -n "${GITHUB_TOKEN}" ]; then
  export GITHUB_TOKEN
  BUILD_SECRET=(--secret "id=github_token,env=GITHUB_TOKEN")
else
  echo "    no GitHub token found (env GITHUB_TOKEN or 'gh auth token');" >&2
  echo "    the Pulse download will fail while ${PULSE_GITHUB_REPO:-onixus/GenDec} is private" >&2
fi

docker build -f Dockerfile.allinone -t "${IMAGE}" "${BUILD_SECRET[@]}" .

echo "==> Loading image into kind"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

echo "==> Applying k8s/shapoclyack/overlays/kind-dev"
kubectl apply -k k8s/shapoclyack/overlays/kind-dev

echo "==> Waiting for rollout"
kubectl -n "${NAMESPACE}" rollout status statefulset/shapoclyack-postgres --timeout=180s

# The image tag is always :kind-dev and imagePullPolicy is IfNotPresent, so a
# rebuild leaves the PodSpec byte-identical: `apply` reports "configured", no
# pod is recreated, and `rollout status` returns success against the OLD
# ReplicaSet. The script would print "Ready" over a lab still running the
# previous build. Force the restart so a rebuild always reaches the cluster.
echo "==> Restarting the API to pick up the rebuilt image"
kubectl -n "${NAMESPACE}" rollout restart deployment/shapoclyack-api
kubectl -n "${NAMESPACE}" rollout status deployment/shapoclyack-api --timeout=180s

# The API tolerates a missing scan-targets Secret (its volume is optional), but
# job.yaml / job-resume.yaml / cronjob.yaml mount it as required. Without it the
# kubelet cannot create the scan pod at all: it sits in ContainerCreating until
# activeDeadlineSeconds (1h here) kills the Job, taking the pod -- and therefore
# every log and event -- with it, so the failure surfaces as a bare
# DeadlineExceeded an hour later with nothing to read. Nothing inside the pod can
# warn about this (no container ever starts), so check from out here.
if ! kubectl -n "${NAMESPACE}" get secret scan-targets >/dev/null 2>&1; then
  echo
  echo "WARNING: Secret 'scan-targets' is missing -- the API is fine, but any" >&2
  echo "         scan Job/CronJob will hang in ContainerCreating and then fail" >&2
  echo "         with DeadlineExceeded. Create it before starting a scheduled scan:" >&2
  echo "           kubectl apply -f k8s/shapoclyack/examples/scan-targets.secret.example.yaml" >&2
  echo "         (edit ranges.txt in it first -- the example scans nothing)" >&2
fi

echo
# 127.0.0.1, not localhost: kind publishes the NodePort on 0.0.0.0 (IPv4 only),
# while localhost resolves to ::1 first on macOS -- which just gets refused.
echo "Ready: http://127.0.0.1:8080"
echo "Sign in as operator / operator-change-me"
echo "Change the JWT secret and demo passwords before exposing this beyond a trusted lab."
echo
echo "Logs:   kubectl -n ${NAMESPACE} logs deploy/shapoclyack-api -f"
echo "Down:   scripts/dev-down.sh"
