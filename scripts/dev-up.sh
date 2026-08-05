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
docker build -f Dockerfile.allinone -t "${IMAGE}" .

echo "==> Loading image into kind"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

echo "==> Applying k8s/shapoclyack/overlays/kind-dev"
kubectl apply -k k8s/shapoclyack/overlays/kind-dev

echo "==> Waiting for rollout"
kubectl -n "${NAMESPACE}" rollout status statefulset/shapoclyack-postgres --timeout=180s
kubectl -n "${NAMESPACE}" rollout status deployment/shapoclyack-api --timeout=180s

echo
echo "Ready: http://localhost:8080"
echo "Sign in as operator / operator-change-me"
echo "Change the JWT secret and demo passwords before exposing this beyond a trusted lab."
echo
echo "Logs:   kubectl -n ${NAMESPACE} logs deploy/shapoclyack-api -f"
echo "Down:   scripts/dev-down.sh"
