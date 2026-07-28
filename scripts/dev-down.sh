#!/usr/bin/env bash
# Tear down the local kind dev cluster created by scripts/dev-up.sh.
set -euo pipefail

CLUSTER_NAME="shapoclyack-dev"

if kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
  kind delete cluster --name "${CLUSTER_NAME}"
  echo "Deleted kind cluster '${CLUSTER_NAME}'."
else
  echo "No kind cluster named '${CLUSTER_NAME}' found."
fi
