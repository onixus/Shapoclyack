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
BUNDLE_URL="${BUNDLE_URL:-}"

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
      --bundle-url <URL>        Where to fetch the agent package tarball from.
                                Required for native installs unless the package
                                is already staged in the install directory: the
                                Shapoclyack API does not serve one.
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
        --bundle-url)
            BUNDLE_URL="$2"
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
if ! "${INSTALL_DIR}/venv/bin/pip" install --quiet fastapi httpx pydantic psutil requests; then
    error "Failed to install agent dependencies into ${INSTALL_DIR}/venv."
fi

# Obtain the agent package
#
# The API serves no agent bundle, so a native install cannot silently "sync"
# one from the server. The package comes from an explicit --bundle-url, or it
# is already staged in the install directory. Anything else is a failed
# install and says so, rather than leaving systemd to restart an agent that
# cannot import its own module.
if [[ -n "${BUNDLE_URL}" ]]; then
    log "Fetching agent package from ${BUNDLE_URL}..."
    if ! curl -fsSL "${BUNDLE_URL}" -o "${INSTALL_DIR}/bundle.tar.gz"; then
        error "Could not download the agent package from ${BUNDLE_URL}."
    fi
    if ! tar -tzf "${INSTALL_DIR}/bundle.tar.gz" &>/dev/null; then
        rm -f "${INSTALL_DIR}/bundle.tar.gz"
        error "The file at ${BUNDLE_URL} is not a readable tarball."
    fi
    tar -xzf "${INSTALL_DIR}/bundle.tar.gz" -C "${INSTALL_DIR}"
    rm -f "${INSTALL_DIR}/bundle.tar.gz"
elif [[ -d "${INSTALL_DIR}/agent" ]]; then
    log "Using the agent package already staged in ${INSTALL_DIR}."
else
    error "No agent package available.
  The Shapoclyack API does not serve one, so a native install needs either:
    --bundle-url <URL>   a tarball containing the 'agent' package, or
    an 'agent' directory already staged in ${INSTALL_DIR}
  Alternatively run this installer with --docker, which takes the agent from
  the published image and needs no bundle."
fi

chown -R shapoclyack:shapoclyack "${INSTALL_DIR}"

# Fail here rather than in a restart loop: if the worker cannot be imported,
# systemd would report the unit as active while it crashes every RestartSec.
log "Verifying the agent package is importable..."
if ! (cd "${INSTALL_DIR}" && "${INSTALL_DIR}/venv/bin/python" -c "import agent.worker" 2>/dev/null); then
    error "The agent package in ${INSTALL_DIR} cannot be imported ('import agent.worker' failed).
  The installation is incomplete; the service has not been started."
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

    # Type=simple means systemd calls the unit active the moment it forks, so
    # the unit being "started" proves nothing. Give it a moment and re-check.
    sleep 3
    if ! systemctl is-active --quiet shapoclyack-agent.service; then
        error "Service 'shapoclyack-agent.service' is not running after start.
  Inspect it with: journalctl -u shapoclyack-agent.service -n 50"
    fi
    log "Systemd service 'shapoclyack-agent.service' started and enabled on boot!"
else
    log "Systemd not detected. Starting agent in background..."
    nohup sudo -u shapoclyack env $(cat "${CONF_DIR}/agent.env" | xargs) \
        "${INSTALL_DIR}/venv/bin/python" -m agent.worker --server "${SERVER_URL}" --key "${PROVISIONING_KEY}" --tenant "${TENANT_ID}" --agent-id "${AGENT_ID}" \
        > "${INSTALL_DIR}/agent.log" 2>&1 &
fi

log "================================================================="
log "Shapoclyack Agent ${AGENT_ID} installed."
log "Connecting to ${SERVER_URL}. Confirm it appears in the agent fleet view;"
log "the host has no self-update mechanism, so upgrades are a reinstall."
log "================================================================="
