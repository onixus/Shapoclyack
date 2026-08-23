#!/usr/bin/env bash
# ==============================================================================
# Shapoclyack Remote Agent Universal Installer
# Compatible with Ubuntu/Debian, RHEL/Rocky/Alma/Fedora, Alpine, Arch Linux.
# ==============================================================================

set -euo pipefail

SERVER_URL=""
PROVISIONING_KEY=""
TENANT_ID="default"
AGENT_ID=""
INSTALL_DIR="/opt/shapoclyack-agent"
CONF_DIR="/etc/shapoclyack"
USE_DOCKER=0
NATS_URL=""

log() {
    echo -e "\033[1;34m[INFO]\033[0m $*"
}

warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*"
}

error() {
    echo -e "\033[1;31m[ERROR]\033[0m $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage: $0 --server <URL> --key <PROVISIONING_KEY> [OPTIONS]

Required:
  -s, --server <URL>            Shapoclyack server base URL (e.g. http://192.168.1.100:8000)
  -k, --key <KEY>               Agent Provisioning Key (octo-pk-...)

Options:
  -t, --tenant <TENANT_ID>      Tenant ID (default: default)
  -a, --agent-id <ID>           Explicit Agent ID (defaults to hostname-hash)
  -d, --install-dir <PATH>      Installation root directory (default: /opt/shapoclyack-agent)
      --docker                  Deploy agent as a Docker container
      --nats-url <URL>          Optional NATS JetStream server URL
  -h, --help                    Show this help message
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--server)
            SERVER_URL="$2"
            shift 2
            ;;
        -k|--key)
            PROVISIONING_KEY="$2"
            shift 2
            ;;
        -t|--tenant)
            TENANT_ID="$2"
            shift 2
            ;;
        -a|--agent-id)
            AGENT_ID="$2"
            shift 2
            ;;
        -d|--install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --docker)
            USE_DOCKER=1
            shift
            ;;
        --nats-url)
            NATS_URL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown argument: $1"
            ;;
    esac
done

if [[ -z "${SERVER_URL}" ]]; then
    error "Missing required argument: --server <URL>"
fi

if [[ -z "${PROVISIONING_KEY}" ]]; then
    error "Missing required argument: --key <KEY>"
fi

SERVER_URL="${SERVER_URL%/}"

if [[ -z "${AGENT_ID}" ]]; then
    HOST_SHORT=$(hostname -s 2>/dev/null || echo "agent")
    RAND_SUFFIX=$(head -c 4 /dev/urandom 2>/dev/null | xxd -p 2>/dev/null || echo "$$")
    AGENT_ID="agent-${HOST_SHORT}-${RAND_SUFFIX}"
fi

log "Installing Shapoclyack Agent (${AGENT_ID}) for tenant '${TENANT_ID}' connecting to ${SERVER_URL}..."

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    error "This installer must be run as root (or via sudo)."
fi

# Docker Deployment Mode
if [[ "${USE_DOCKER}" -eq 1 ]]; then
    log "Setting up Docker-based agent deployment..."
    if ! command -v docker &>/dev/null; then
        error "Docker is not installed on this system. Install Docker first or run without --docker."
    fi

    CONTAINER_NAME="shapoclyack-agent"
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

    log "Starting Docker container '${CONTAINER_NAME}'..."
    docker run -d \
        --name "${CONTAINER_NAME}" \
        --restart always \
        --net host \
        -e OCTO_SERVER_URL="${SERVER_URL}" \
        -e OCTO_PROVISIONING_KEY="${PROVISIONING_KEY}" \
        -e OCTO_TENANT_ID="${TENANT_ID}" \
        -e OCTO_AGENT_ID="${AGENT_ID}" \
        -e OCTO_NATS_URL="${NATS_URL}" \
        ghcr.io/onixus/shapoclyack:latest \
        python -m agent.worker --server "${SERVER_URL}" --key "${PROVISIONING_KEY}" --agent-id "${AGENT_ID}"

    log "Docker agent container '${CONTAINER_NAME}' started successfully!"
    exit 0
fi

# Native Systemd Installation Mode
log "Detecting OS package manager..."
if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-venv curl tar ca-certificates
elif command -v dnf &>/dev/null; then
    dnf install -y -q python3 python3-pip curl tar ca-certificates
elif command -v yum &>/dev/null; then
    yum install -y -q python3 python3-pip curl tar ca-certificates
elif command -v apk &>/dev/null; then
    apk add --no-cache python3 py3-pip curl tar ca-certificates
elif command -v pacman &>/dev/null; then
    pacman -Sy --noconfirm python python-pip curl tar ca-certificates
fi

# Create dedicated system user
if ! id -u shapoclyack &>/dev/null; then
    log "Creating system user 'shapoclyack'..."
    useradd --system --shell /usr/sbin/nologin --home-dir "${INSTALL_DIR}" --create-home shapoclyack || \
    adduser -S -D -H -h "${INSTALL_DIR}" -s /sbin/nologin shapoclyack 2>/dev/null || true
fi

# Prepare directories
mkdir -p "${INSTALL_DIR}" "${CONF_DIR}"
chown -R shapoclyack:shapoclyack "${INSTALL_DIR}"

# Create Python Virtual Environment
log "Setting up virtual environment in ${INSTALL_DIR}/venv..."
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade --quiet pip setuptools wheel

# Fetch agent bundle or install dependencies
log "Installing agent requirements..."
"${INSTALL_DIR}/venv/bin/pip" install --quiet fastapi httpx pydantic psutil requests 2>/dev/null || true

# Download/sync agent source from server if available, or write runtime bundle
cat << 'EOF' > "${INSTALL_DIR}/agent_runner.py"
import os
import sys
import runpy

# Run agent worker module
if __name__ == "__main__":
    server_url = os.environ.get("OCTO_SERVER_URL")
    key = os.environ.get("OCTO_PROVISIONING_KEY")
    tenant = os.environ.get("OCTO_TENANT_ID", "default")
    agent_id = os.environ.get("OCTO_AGENT_ID")
    sys.argv = ["worker.py", "--server", server_url, "--key", key, "--tenant", tenant]
    if agent_id:
        sys.argv.extend(["--agent-id", agent_id])
    from agent import worker
    worker.main()
EOF

# Fetch agent package from server
log "Fetching latest agent bundle from server..."
curl -sSL "${SERVER_URL}/api/agent/bundle.tar.gz" -o "${INSTALL_DIR}/bundle.tar.gz" 2>/dev/null || true
if [[ -f "${INSTALL_DIR}/bundle.tar.gz" ]] && tar -tzf "${INSTALL_DIR}/bundle.tar.gz" &>/dev/null; then
    tar -xzf "${INSTALL_DIR}/bundle.tar.gz" -C "${INSTALL_DIR}"
    rm -f "${INSTALL_DIR}/bundle.tar.gz"
fi

# Write environment configuration
log "Writing environment config to ${CONF_DIR}/agent.env..."
cat <<EOF > "${CONF_DIR}/agent.env"
OCTO_SERVER_URL=${SERVER_URL}
OCTO_PROVISIONING_KEY=${PROVISIONING_KEY}
OCTO_TENANT_ID=${TENANT_ID}
OCTO_AGENT_ID=${AGENT_ID}
OCTO_NATS_URL=${NATS_URL}
EOF
chmod 0600 "${CONF_DIR}/agent.env"
chown shapoclyack:shapoclyack "${CONF_DIR}/agent.env"

# Install Systemd Service
if command -v systemctl &>/dev/null && [[ -d /etc/systemd/system ]]; then
    log "Configuring systemd service 'shapoclyack-agent.service'..."
    cat <<EOF > /etc/systemd/system/shapoclyack-agent.service
[Unit]
Description=Shapoclyack Security Scanning Agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=shapoclyack
Group=shapoclyack
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-${CONF_DIR}/agent.env
ExecStart=${INSTALL_DIR}/venv/bin/python -m agent.worker --server \${OCTO_SERVER_URL} --key \${OCTO_PROVISIONING_KEY} --tenant \${OCTO_TENANT_ID} --agent-id \${OCTO_AGENT_ID}
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable shapoclyack-agent.service
    systemctl restart shapoclyack-agent.service
    log "Systemd service 'shapoclyack-agent.service' started and enabled on boot!"
else
    log "Systemd not detected. Starting agent in background..."
    nohup sudo -u shapoclyack env $(cat "${CONF_DIR}/agent.env" | xargs) \
        "${INSTALL_DIR}/venv/bin/python" -m agent.worker --server "${SERVER_URL}" --key "${PROVISIONING_KEY}" --tenant "${TENANT_ID}" --agent-id "${AGENT_ID}" \
        > "${INSTALL_DIR}/agent.log" 2>&1 &
fi

log "================================================================="
log "Shapoclyack Agent ${AGENT_ID} installed successfully!"
log "Status: Active & Connecting to ${SERVER_URL}"
log "================================================================="
