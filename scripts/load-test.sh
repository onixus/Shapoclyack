#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <cidr>"
  echo "Example: $0 10.0.0.0/16"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIDR="$1"
cd "${ROOT_DIR}"

cat > scanner/inputs/ranges.txt <<EOF
${CIDR}
EOF
cat > scanner/inputs/domains.txt <<EOF
# optional FQDN targets
EOF
cat > scanner/inputs/ports.txt <<EOF
# use profile top-ports
EOF

docker build -t network-scan-cli:local -f Dockerfile .
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "${ROOT_DIR}/scanner/inputs:/app/scanner/inputs" \
  -v "${ROOT_DIR}/scanner/config:/app/scanner/config" \
  -v "${ROOT_DIR}/scanner/output:/app/scanner/output" \
  -v "${ROOT_DIR}/scanner/state:/app/scanner/state" \
  network-scan-cli:local \
  --config scanner/config/default.yaml --mode fast
echo "Load profile run finished. Check scanner/output/summary.json"
