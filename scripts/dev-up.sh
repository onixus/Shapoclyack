#!/usr/bin/env bash
# Local dev cluster for Shapoclyack — replaces `docker compose up --build`.
#
# Builds the all-in-one image, loads it into a kind cluster, and applies a
# kind overlay (dev resources + local image tag + NodePort).
#
# Overlay selection:
#   OVERLAY=kind-dev          base local lab (default on a fresh cluster)
#   OVERLAY=kind-enrichment   ...plus real GeoIP/ASN/EPSS/KEV/CVSS4 data
#
# With OVERLAY unset the script keeps whatever the cluster already runs: if the
# enrichment PVC is present it re-applies kind-enrichment. Applying kind-dev
# over an enrichment deployment silently strips the API's enrichment volume,
# initContainer and OCTO_*_DATABASE vars, leaving it to read the image's seed
# again — a downgrade with no error and no obvious symptom.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

CLUSTER_NAME="shapoclyack-dev"
IMAGE="ghcr.io/onixus/shapoclyack-aio:kind-dev"
NAMESPACE="network-scan"
# Where scans run since #338: the scanner-executor, in a namespace of its own.
EXECUTOR_NAMESPACE="network-scan-executor"
EXECUTOR_SECRET="shapoclyack-scanner-executor"

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

# Resolve the overlay only now: the cluster has to exist before we can ask it
# what is already deployed.
if [ -n "${OVERLAY:-}" ]; then
  echo "==> Overlay '${OVERLAY}' (from OVERLAY)"
elif kubectl -n "${NAMESPACE}" get pvc enrichment-data >/dev/null 2>&1; then
  OVERLAY="kind-enrichment"
  echo "==> Overlay 'kind-enrichment' (enrichment-data PVC present; OVERLAY=kind-dev to drop it)"
else
  OVERLAY="kind-dev"
  echo "==> Overlay 'kind-dev' (OVERLAY=kind-enrichment for real enrichment data)"
fi

OVERLAY_DIR="k8s/shapoclyack/overlays/${OVERLAY}"
if [ ! -d "${OVERLAY_DIR}" ]; then
  echo "unknown overlay '${OVERLAY}' — no such directory ${OVERLAY_DIR}" >&2
  echo "available: $(ls k8s/shapoclyack/overlays | tr '\n' ' ')" >&2
  exit 1
fi

echo "==> Applying ${OVERLAY_DIR}"
kubectl apply -k "${OVERLAY_DIR}"

# After the apply, because the Secret needs the namespace the overlay creates,
# and before the rollout wait below, because the API mounts it. A pod that
# starts first sits in ContainerCreating until the Secret appears rather than
# failing, so the order is a matter of not waiting three minutes for something
# that could be there in one second.
if [ "${OVERLAY}" = "kind-dev" ] || [ "${OVERLAY}" = "kind-enrichment" ]; then
  NAMESPACE="${NAMESPACE}" ./scripts/dev-tls-cert.sh
fi

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

# Scans run in the scanner-executor (#338), which starts only once it holds a
# provisioning key -- until then it waits in CreateContainerConfigError naming
# the Secret. A key is minted by the API, so it cannot ship with the manifests;
# on the stand the demo admin account can mint one, which is what this does.
# Once: an existing Secret is kept, because every run minting a new key would
# leave the previous ones valid and unaccounted for.
#
# The key reaches kubectl on stdin (printf is a builtin), never through argv or
# the terminal: it is a credential that enrolls scanners into tenant `default`.
# Checked for emptiness first -- a Secret holding an empty key would satisfy
# the "already enrolled" test above on every later run.
enroll_executor() {
  local api="https://127.0.0.1:8080" ca=".dev-tls/ca.crt" token key
  if kubectl -n "${EXECUTOR_NAMESPACE}" get secret "${EXECUTOR_SECRET}" >/dev/null 2>&1; then
    echo "==> scanner-executor already enrolled (Secret ${EXECUTOR_NAMESPACE}/${EXECUTOR_SECRET})"
    return 0
  fi
  echo "==> Enrolling the scanner-executor into tenant 'default'"
  token="$(curl -fsS --cacert "${ca}" "${api}/api/auth/login" \
      -H 'Content-Type: application/json' \
      -d '{"username":"admin","password":"admin-change-me"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token") or "")' 2>/dev/null)" || token=""
  if [ -z "${token}" ]; then
    echo "WARNING: could not sign in as the demo admin, so the scanner-executor is not" >&2
    echo "         enrolled and scans will stay queued. Mint a key and store it:" >&2
    echo "           docs/k8s-hardening.md § Enrolling the scanner-executor" >&2
    return 0
  fi
  key="$(curl -fsS --cacert "${ca}" -X POST "${api}/api/tenants/default/provisioning-keys" \
      -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' \
      -d '{"label":"kind scanner-executor (scripts/dev-up.sh)"}' \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin).get("key") or "")' 2>/dev/null)" || key=""
  if [ -z "${key}" ]; then
    echo "WARNING: minting the scanner-executor's provisioning key failed; scans will" >&2
    echo "         stay queued until it is enrolled (docs/k8s-hardening.md)." >&2
    return 0
  fi
  printf '%s' "${key}" | kubectl -n "${EXECUTOR_NAMESPACE}" create secret generic "${EXECUTOR_SECRET}" \
    --from-file=provisioning_key=/dev/stdin >/dev/null
}

if [ "${OVERLAY}" = "kind-dev" ] || [ "${OVERLAY}" = "kind-enrichment" ]; then
  enroll_executor
fi
# Same byte-identical PodSpec problem as the API above, once there is a pod to
# restart. An executor without its Secret yet is left to start on its own.
if kubectl -n "${EXECUTOR_NAMESPACE}" get secret "${EXECUTOR_SECRET}" >/dev/null 2>&1 \
    && kubectl -n "${EXECUTOR_NAMESPACE}" get statefulset/shapoclyack-scanner-executor >/dev/null 2>&1; then
  echo "==> Restarting the scanner-executor to pick up the rebuilt image"
  kubectl -n "${EXECUTOR_NAMESPACE}" rollout restart statefulset/shapoclyack-scanner-executor
  kubectl -n "${EXECUTOR_NAMESPACE}" rollout status statefulset/shapoclyack-scanner-executor --timeout=180s
fi

# Only an overlay with base/local-scan still has a scan Job/CronJob (#338).
# The API tolerates a missing scan-targets Secret (its volume is optional), but
# job.yaml / job-resume.yaml / cronjob.yaml mount it as required. Without it the
# kubelet cannot create the scan pod at all: it sits in ContainerCreating until
# activeDeadlineSeconds (1h here) kills the Job, taking the pod -- and therefore
# every log and event -- with it, so the failure surfaces as a bare
# DeadlineExceeded an hour later with nothing to read. Nothing inside the pod can
# warn about this (no container ever starts), so check from out here.
if kubectl -n "${NAMESPACE}" get cronjob network-scan-scheduled >/dev/null 2>&1 \
    && ! kubectl -n "${NAMESPACE}" get secret scan-targets >/dev/null 2>&1; then
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
if [ "${OVERLAY}" = "kind-dev" ] || [ "${OVERLAY}" = "kind-enrichment" ]; then
  echo "Ready: https://127.0.0.1:8080  (CA: .dev-tls/ca.crt)"
else
  echo "Ready: http://127.0.0.1:8080"
fi
echo "Sign in as operator / operator-change-me"
echo "Change the JWT secret and demo passwords before exposing this beyond a trusted lab."
echo
echo "Logs:   kubectl -n ${NAMESPACE} logs deploy/shapoclyack-api -f"
echo "        kubectl -n ${EXECUTOR_NAMESPACE} logs statefulset/shapoclyack-scanner-executor -f"
echo "Down:   scripts/dev-down.sh"
