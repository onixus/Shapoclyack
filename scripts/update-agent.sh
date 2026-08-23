#!/usr/bin/env bash
# ==============================================================================
# Shapoclyack Remote Agent Self-Updater Script
# Upgrades local agent installation to the latest available server release.
# ==============================================================================

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/shapoclyack-agent}"
CONF_DIR="${CONF_DIR:-/etc/shapoclyack}"

log() {
    echo -e "\033[1;34m[INFO]\033[0m $*"
}

error() {
    echo -e "\033[1;31m[ERROR]\033[0m $*" >&2
    exit 1
}

if [[ ! -f "${CONF_DIR}/agent.env" ]]; then
    error "Agent config not found at ${CONF_DIR}/agent.env. Is the agent installed?"
fi

# Load existing environment
source "${CONF_DIR}/agent.env"

SERVER_URL="${OCTO_SERVER_URL%/}"
log "Checking for updates from ${SERVER_URL}..."

# Update Python dependencies & packages
if [[ -d "${INSTALL_DIR}/venv" ]]; then
    log "Updating agent dependencies..."
    "${INSTALL_DIR}/venv/bin/pip" install --upgrade --quiet pip setuptools wheel
fi

# Download updated bundle if served
curl -sSL "${SERVER_URL}/api/agent/bundle.tar.gz" -o "${INSTALL_DIR}/bundle.tar.gz" 2>/dev/null || true
if [[ -f "${INSTALL_DIR}/bundle.tar.gz" ]] && tar -tzf "${INSTALL_DIR}/bundle.tar.gz" &>/dev/null; then
    log "Applying update payload..."
    tar -xzf "${INSTALL_DIR}/bundle.tar.gz" -C "${INSTALL_DIR}"
    rm -f "${INSTALL_DIR}/bundle.tar.gz"
fi

# Restart service
if command -v systemctl &>/dev/null && systemctl is-active --quiet shapoclyack-agent.service; then
    log "Restarting shapoclyack-agent.service..."
    systemctl restart shapoclyack-agent.service
    log "Agent service restarted successfully!"
elif command -v docker &>/dev/null && docker ps --format '{{.Names}}' | grep -q "^shapoclyack-agent$"; then
    log "Restarting Docker agent container..."
    docker restart shapoclyack-agent
    log "Docker agent container restarted successfully!"
fi

log "Update process complete."
