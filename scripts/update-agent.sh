#!/usr/bin/env bash
# ==============================================================================
# Shapoclyack Remote Agent Updater
#
# Reinstalls the agent package on this host from a bundle URL you provide, then
# restarts the service. There is no self-update: the Shapoclyack API serves no
# agent bundle and the `Upgrade` action in the Web UI is a marker on the agent
# record, not a command channel to this host. Without --bundle-url this script
# can refresh dependencies and restart the service, and it says so rather than
# reporting an update it did not perform.
# ==============================================================================

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/shapoclyack-agent}"
CONF_DIR="${CONF_DIR:-/etc/shapoclyack}"
BUNDLE_URL="${BUNDLE_URL:-}"
RESTART_ONLY=0

log() {
    echo -e "\033[1;34m[INFO]\033[0m $*"
}

error() {
    echo -e "\033[1;31m[ERROR]\033[0m $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage: $0 [--bundle-url <URL>] [--restart-only]

Options:
      --bundle-url <URL>   Tarball containing the 'agent' package to install.
      --restart-only       Refresh dependencies and restart without replacing
                           the agent package.
  -h, --help               Show this help message.

The API does not serve an agent bundle, so one of the two options above is
required: this script will not pretend to have updated anything.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bundle-url)
            BUNDLE_URL="$2"
            shift 2
            ;;
        --restart-only)
            RESTART_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown argument: $1"
            ;;
    esac
done

if [[ ! -f "${CONF_DIR}/agent.env" ]]; then
    error "Agent config not found at ${CONF_DIR}/agent.env. Is the agent installed?"
fi

if [[ -z "${BUNDLE_URL}" && "${RESTART_ONLY}" -eq 0 ]]; then
    error "Nothing to update from.
  Pass --bundle-url <URL> with the agent package, or --restart-only to just
  refresh dependencies and restart. The Shapoclyack API does not serve an
  agent bundle, so there is no source to fall back to."
fi

# Update Python dependencies
if [[ -d "${INSTALL_DIR}/venv" ]]; then
    log "Updating agent dependencies..."
    "${INSTALL_DIR}/venv/bin/pip" install --upgrade --quiet pip setuptools wheel
fi

# Replace the agent package
if [[ -n "${BUNDLE_URL}" ]]; then
    log "Fetching agent package from ${BUNDLE_URL}..."
    if ! curl -fsSL "${BUNDLE_URL}" -o "${INSTALL_DIR}/bundle.tar.gz"; then
        error "Could not download the agent package from ${BUNDLE_URL}."
    fi
    if ! tar -tzf "${INSTALL_DIR}/bundle.tar.gz" &>/dev/null; then
        rm -f "${INSTALL_DIR}/bundle.tar.gz"
        error "The file at ${BUNDLE_URL} is not a readable tarball."
    fi
    log "Applying update payload..."
    tar -xzf "${INSTALL_DIR}/bundle.tar.gz" -C "${INSTALL_DIR}"
    rm -f "${INSTALL_DIR}/bundle.tar.gz"
    chown -R shapoclyack:shapoclyack "${INSTALL_DIR}" 2>/dev/null || true

    if ! (cd "${INSTALL_DIR}" && "${INSTALL_DIR}/venv/bin/python" -c "import agent.worker" 2>/dev/null); then
        error "The updated package cannot be imported ('import agent.worker' failed).
  The service has not been restarted; the previous installation is still in place."
    fi
fi

# Restart service
RESTARTED=0
if command -v systemctl &>/dev/null && systemctl is-active --quiet shapoclyack-agent.service; then
    log "Restarting shapoclyack-agent.service..."
    systemctl restart shapoclyack-agent.service
    sleep 3
    if ! systemctl is-active --quiet shapoclyack-agent.service; then
        error "Service is not running after restart.
  Inspect it with: journalctl -u shapoclyack-agent.service -n 50"
    fi
    RESTARTED=1
elif command -v docker &>/dev/null && docker ps --format '{{.Names}}' | grep -q "^shapoclyack-agent$"; then
    log "Restarting Docker agent container..."
    docker restart shapoclyack-agent
    RESTARTED=1
fi

if [[ "${RESTARTED}" -eq 0 ]]; then
    error "No running agent service or container was found to restart."
fi

if [[ -n "${BUNDLE_URL}" ]]; then
    log "Agent package replaced and service restarted."
else
    log "Dependencies refreshed and service restarted. The agent package was not changed."
fi
