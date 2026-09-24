#!/usr/bin/env bash
# Generate the self-signed CA and server certificate the kind stand serves TLS
# with, and put them in the cluster as a Secret.
#
# Why the stand needs TLS at all, beyond being closer to a real deployment: an
# endpoint agent refuses a remotely offered upgrade over plain HTTP (#358). The
# build and the sha256 that vouches for it travel on the same connection, so
# without TLS whoever can rewrite one can rewrite both and the check proves
# nothing. Testing remote upgrades against a plaintext stand therefore means
# either disabling that refusal or giving the stand a certificate; this is the
# second.
#
# A CA of our own rather than a bare self-signed leaf: the agent pins a CA file
# (`tls_ca_file`), which is how an internal PKI is meant to be used, and a leaf
# can be reissued -- for a new address, or when it expires -- without every
# agent needing a new trust anchor.
#
# Idempotent: an existing, still-valid certificate covering the requested
# addresses is left alone, so `dev-up.sh` does not hand every agent a new trust
# anchor on each run.
set -euo pipefail

CERT_DIR="${CERT_DIR:-.dev-tls}"
NAMESPACE="${NAMESPACE:-network-scan}"
SECRET_NAME="${SECRET_NAME:-shapoclyack-api-tls}"
DAYS="${DAYS:-825}"

mkdir -p "${CERT_DIR}"
chmod 700 "${CERT_DIR}"

# Every address the stand is reached by. The LAN address is what an agent on
# another machine connects to, and a certificate without it fails verification
# there while working perfectly from the host that made it -- the exact shape
# of bug that is found last.
LAN_IP="${LAN_IP:-$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || true)}"
SANS="DNS:localhost,DNS:shapoclyack-api,DNS:shapoclyack-api.${NAMESPACE}.svc,IP:127.0.0.1"
if [ -n "${LAN_IP}" ]; then
  SANS="${SANS},IP:${LAN_IP}"
fi

needs_issue() {
  [ -f "${CERT_DIR}/server.crt" ] || return 0
  # Still valid for at least a week...
  openssl x509 -in "${CERT_DIR}/server.crt" -checkend 604800 -noout >/dev/null 2>&1 || return 0
  # ...and still covers the address we would hand out today.
  if [ -n "${LAN_IP}" ]; then
    openssl x509 -in "${CERT_DIR}/server.crt" -noout -text \
      | grep -q "IP Address:${LAN_IP}" || return 0
  fi
  return 1
}

if needs_issue; then
  echo "==> Issuing a development CA and server certificate for ${SANS}"
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
    -subj "/CN=Shapoclyack development CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

  openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.csr" \
    -subj "/CN=shapoclyack-api" 2>/dev/null

  openssl x509 -req -in "${CERT_DIR}/server.csr" -days "${DAYS}" -sha256 \
    -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
    -out "${CERT_DIR}/server.crt" \
    -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "${SANS}") 2>/dev/null

  rm -f "${CERT_DIR}/server.csr"
  chmod 600 "${CERT_DIR}"/*.key
else
  echo "==> Reusing ${CERT_DIR}/server.crt (valid, and covers ${LAN_IP:-127.0.0.1})"
fi

if command -v kubectl >/dev/null 2>&1 && kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
  echo "==> Putting the certificate in ${NAMESPACE}/${SECRET_NAME}"
  kubectl create secret generic "${SECRET_NAME}" \
    --namespace "${NAMESPACE}" \
    --from-file=tls.crt="${CERT_DIR}/server.crt" \
    --from-file=tls.key="${CERT_DIR}/server.key" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
fi

# The scanner-executor verifies this certificate too (#338), from its own
# namespace, where it cannot read the Secret above and has no business holding
# the key. It gets the CA certificate only, as a ConfigMap
# (k8s/shapoclyack/overlays/kind-dev/executor-tls-patch.yaml mounts it).
EXECUTOR_NAMESPACE="${EXECUTOR_NAMESPACE:-network-scan-executor}"
if command -v kubectl >/dev/null 2>&1 && kubectl get namespace "${EXECUTOR_NAMESPACE}" >/dev/null 2>&1; then
  echo "==> Putting the CA certificate in ${EXECUTOR_NAMESPACE}/shapoclyack-api-ca"
  kubectl create configmap shapoclyack-api-ca \
    --namespace "${EXECUTOR_NAMESPACE}" \
    --from-file=ca.crt="${CERT_DIR}/ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
fi

echo
echo "CA for agents and clients: ${CERT_DIR}/ca.crt"
if [ -n "${LAN_IP}" ]; then
  echo "Stand: https://${LAN_IP}:8080  (and https://127.0.0.1:8080)"
fi
