#!/usr/bin/env bash
# Prove that base/networkpolicy-datastores.yaml is enforced, on a cluster whose
# CNI enforces NetworkPolicy — which kind's default (kindnet) does not.
#
# The policies were reviewed and validated as objects (#225, #236); what had
# never been shown is a packet being dropped because of them. This script
# creates a throwaway kind cluster with Calico, deploys the kind-dev overlay
# (the real workloads, not stand-ins), waits for the API to come up — which is
# the *allowed* direction working under enforcement, since the API reaches all
# three datastores on the way to Ready — and then connects from pods the
# policies must refuse and from pods they must admit.
#
# Expected matrix (TCP connect, 3 s):
#   unlabeled pod  → postgres:5432, clickhouse:8123/9000, nats:4222   REFUSED
#   unlabeled pod  → nats:8222 (monitoring rule, any source)          ALLOWED
#   component=backup → postgres:5432                                  ALLOWED
#   component=agent  → nats:4222 ALLOWED, postgres:5432 REFUSED
#   api pod          → all three                                      ALLOWED (implied by Ready)
#
# Usage: k8s/scripts/verify-networkpolicy.sh
#   IMAGE=...  aio image to load (default: what scripts/dev-up.sh builds)
#   KEEP=1     keep the cluster afterwards for inspection
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="shapoclyack-netpol"
NS="network-scan"
IMAGE="${IMAGE:-ghcr.io/onixus/shapoclyack-aio:kind-dev}"
# Pinned: the assertion is about our policies under a CNI that enforces them,
# not about whatever Calico released this week.
CALICO_VERSION="${CALICO_VERSION:-v3.30.3}"
CALICO_MANIFEST="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
PROBE_IMAGE="${PROBE_IMAGE:-alpine:3}"
KEEP="${KEEP:-0}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/netpol.XXXXXX")"

cleanup() {
  if [[ "${KEEP}" != "1" ]]; then
    kind delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
  else
    echo "[netpol] KEEP=1: cluster '${CLUSTER}' left running (kubectl config use-context kind-${CLUSTER})"
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "[netpol] image ${IMAGE} not found locally; build it first (scripts/dev-up.sh builds it)" >&2
  exit 2
fi

cat > "${WORK}/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER}
networking:
  # kindnet does not enforce NetworkPolicy; Calico below does.
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
nodes:
  - role: control-plane
EOF

echo "[netpol] creating kind cluster '${CLUSTER}' without a CNI"
kind delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
kind create cluster --config "${WORK}/kind.yaml" --wait 0s >/dev/null
K="kubectl --context kind-${CLUSTER}"

echo "[netpol] installing Calico ${CALICO_VERSION}"
${K} apply -f "${CALICO_MANIFEST}" >/dev/null
${K} -n kube-system rollout status daemonset/calico-node --timeout=300s >/dev/null
${K} -n kube-system rollout status deployment/calico-kube-controllers --timeout=300s >/dev/null
${K} -n kube-system rollout status deployment/coredns --timeout=300s >/dev/null
${K} wait --for=condition=Ready node --all --timeout=120s >/dev/null

echo "[netpol] loading ${IMAGE}"
kind load docker-image "${IMAGE}" --name "${CLUSTER}" >/dev/null
${K} get nodes -o wide --no-headers

echo "[netpol] applying overlays/kind-dev (base + networkpolicy-datastores.yaml)"
${K} apply -k "${ROOT_DIR}/k8s/shapoclyack/overlays/kind-dev" >/dev/null
${K} -n "${NS}" get networkpolicy

echo "[netpol] waiting for the datastores — their kubelet probes must survive the policy"
for sts in shapoclyack-postgres shapoclyack-clickhouse shapoclyack-nats; do
  ${K} -n "${NS}" rollout status "statefulset/${sts}" --timeout=300s
done
echo "[netpol] waiting for the API — Ready means it reached all three through the allow rules"
${K} -n "${NS}" rollout status deployment/shapoclyack-api --timeout=420s

# --- the refusals -----------------------------------------------------------

FAIL=0
report() { # expected actual label
  local expected="$1" actual="$2" label="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    printf '  %-52s %-8s ok\n' "${label}" "${actual}"
  else
    printf '  %-52s %-8s FAIL (expected %s)\n' "${label}" "${actual}" "${expected}"
    FAIL=1
  fi
}

# probe NAME LABELS "host:port ..." → prints "host:port=ALLOWED|REFUSED" per target
probe() {
  local name="$1" labels="$2" targets="$3"
  local script='for t in '"${targets}"'; do h=${t%%:*}; p=${t##*:}; if nc -z -w 3 "$h" "$p" 2>/dev/null; then echo "$t=ALLOWED"; else echo "$t=REFUSED"; fi; done'
  local args=(--restart=Never --image="${PROBE_IMAGE}" --rm -i -q)
  [[ -n "${labels}" ]] && args+=(--labels="${labels}")
  ${K} -n "${NS}" run "${name}" "${args[@]}" -- sh -c "${script}"
}

PG=shapoclyack-postgres:5432
CH_HTTP=shapoclyack-clickhouse:8123
CH_NATIVE=shapoclyack-clickhouse:9000
NATS=shapoclyack-nats:4222
NATS_MON=shapoclyack-nats:8222

echo "[netpol] unlabeled pod (no rule admits it)"
OUT="$(probe netpol-anon "" "${PG} ${CH_HTTP} ${CH_NATIVE} ${NATS} ${NATS_MON}")"
for t in "${PG}" "${CH_HTTP}" "${CH_NATIVE}" "${NATS}"; do
  report REFUSED "$(grep -o "^${t}=.*" <<<"${OUT}" | cut -d= -f2)" "anon → ${t}"
done
report ALLOWED "$(grep -o "^${NATS_MON}=.*" <<<"${OUT}" | cut -d= -f2)" "anon → ${NATS_MON} (monitoring rule)"

echo "[netpol] pod labeled as the backup CronJob"
OUT="$(probe netpol-backup "app.kubernetes.io/name=shapoclyack,app.kubernetes.io/component=backup" "${PG} ${CH_HTTP} ${NATS}")"
report ALLOWED "$(grep -o "^${PG}=.*" <<<"${OUT}" | cut -d= -f2)" "backup → ${PG}"
report REFUSED "$(grep -o "^${CH_HTTP}=.*" <<<"${OUT}" | cut -d= -f2)" "backup → ${CH_HTTP}"
report REFUSED "$(grep -o "^${NATS}=.*" <<<"${OUT}" | cut -d= -f2)" "backup → ${NATS}"

echo "[netpol] pod labeled as an in-cluster agent"
OUT="$(probe netpol-agent "app.kubernetes.io/name=shapoclyack,app.kubernetes.io/component=agent" "${NATS} ${PG} ${CH_NATIVE}")"
report ALLOWED "$(grep -o "^${NATS}=.*" <<<"${OUT}" | cut -d= -f2)" "agent → ${NATS}"
report REFUSED "$(grep -o "^${PG}=.*" <<<"${OUT}" | cut -d= -f2)" "agent → ${PG}"
report REFUSED "$(grep -o "^${CH_NATIVE}=.*" <<<"${OUT}" | cut -d= -f2)" "agent → ${CH_NATIVE}"

echo "[netpol] the API pod itself, explicitly rather than only via Ready"
API_POD="$(${K} -n "${NS}" get pod -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')"
OUT="$(${K} -n "${NS}" exec "${API_POD}" -c api -- python -c '
import socket
for t in ["shapoclyack-postgres:5432","shapoclyack-clickhouse:8123","shapoclyack-clickhouse:9000","shapoclyack-nats:4222"]:
    h, p = t.rsplit(":", 1)
    try:
        socket.create_connection((h, int(p)), timeout=3).close(); print(f"{t}=ALLOWED")
    except OSError:
        print(f"{t}=REFUSED")
' 2>/dev/null || true)"
for t in "${PG}" "${CH_HTTP}" "${CH_NATIVE}" "${NATS}"; do
  report ALLOWED "$(grep -o "^${t}=.*" <<<"${OUT}" | cut -d= -f2)" "api → ${t}"
done

echo
if [[ "${FAIL}" == "0" ]]; then
  echo "[netpol] PASS — every refusal and every admission matched networkpolicy-datastores.yaml under Calico ${CALICO_VERSION}"
else
  echo "[netpol] FAIL — see the rows above" >&2
  exit 1
fi
