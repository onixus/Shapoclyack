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
KEY_FROM_STDIN=0
NATS_URL=""
BUNDLE_URL="${BUNDLE_URL:-}"
# The image --docker runs: the released scanner image, pinned as tag@digest
# like the k8s/ manifests, because the tag is a name its owner can move and
# the container restarts for good. The release re-pins it along with them and
# with SENSOR_IMAGE in api/services/agents.py, which the console's deployment
# snippets print (tests/test_agent_install_pins.py keeps the two equal).
AGENT_IMAGE="${AGENT_IMAGE:-ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.46-0922@sha256:7eb82c8dab4071517ee7af8825bb8df58d7706afac4eb6e1da6ca4759f44fa66}"

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
      --key-stdin               Read the provisioning key from stdin instead.
                                Prefer this: an argument is visible to every
                                local user in this host's process list.

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

Environment:
  AGENT_IMAGE                   Image --docker runs; currently
                                ${AGENT_IMAGE}
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
        --key-stdin)
            KEY_FROM_STDIN=1
            shift
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

# Read before the check below, so --key-stdin satisfies the same requirement.
# One line, so whatever follows it on the channel (nothing, today) is left for
# the caller rather than swallowed into the credential.
if [[ "${KEY_FROM_STDIN}" -eq 1 ]]; then
    IFS= read -r PROVISIONING_KEY || true
    PROVISIONING_KEY="${PROVISIONING_KEY%$'\r'}"
fi

if [[ -z "${PROVISIONING_KEY}" ]]; then
    if [[ "${KEY_FROM_STDIN}" -eq 1 ]]; then
        error "--key-stdin was given but no provisioning key arrived on stdin."
    fi
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

# Environment file
#
# The single place the provisioning key is written, and the only channel it
# reaches the agent through. It is deliberately NOT passed on any command line:
# argv is world-readable on this host (`ps`, /proc/*/cmdline), and the key
# registers agents into the tenant for as long as it is not revoked.
#
# The variable names are the ones agent/worker.py actually reads. Earlier
# versions wrote OCTO_SERVER_URL / OCTO_PROVISIONING_KEY and then relied on
# --server / --key flags, neither of which the worker has ever accepted.
write_env_file() {
    mkdir -p "${CONF_DIR}"
    # Subshell so the umask does not outlive this function and turn every later
    # file the installer writes (the systemd unit, the log) into 0600 as well.
    (
        umask 077
        cat <<EOF > "${CONF_DIR}/agent.env"
OCTO_API_URL=${SERVER_URL}
OCTO_AGENT_PROVISIONING_KEY=${PROVISIONING_KEY}
OCTO_AGENT_ID=${AGENT_ID}
OCTO_TENANT_ID=${TENANT_ID}
OCTO_NATS_URL=${NATS_URL}
EOF
    )
    chmod 0600 "${CONF_DIR}/agent.env"
}

# The native sensor's Python dependencies: requirements-agent.lock, verbatim.
# A copy rather than a download because `curl … | bash` brings no other file
# to the host, and fetching one would be a second thing to trust.
# tests/test_agent_install_pins.py runs this function and compares what it
# writes with the lock byte for byte; after regenerating the lock (see
# requirements-agent.txt), paste it over the text between the LOCK lines.
write_agent_lock() {
    cat <<'LOCK' > "$1"
# This file was autogenerated by uv via the following command:
#    uv pip compile --universal --no-strip-extras --generate-hashes --python-version=3.11 --output-file=requirements-agent.lock requirements-agent.txt
nats-py==2.15.0 \
    --hash=sha256:6622c547d9a7d2313d9c147d46c386188f4ec2c7b5c9f9a0438a4d1b55f54a93 \
    --hash=sha256:9f8d36aa52a9926a88b8f1d70cf1fdce0ad387941479b500ee9ab3e51073cefd
    # via -r requirements-agent.txt
psutil==7.2.2 \
    --hash=sha256:0746f5f8d406af344fd547f1c8daa5f5c33dbc293bb8d6a16d80b4bb88f59372 \
    --hash=sha256:076a2d2f923fd4821644f5ba89f059523da90dc9014e85f8e45a5774ca5bc6f9 \
    --hash=sha256:11fe5a4f613759764e79c65cf11ebdf26e33d6dd34336f8a337aa2996d71c841 \
    --hash=sha256:1a571f2330c966c62aeda00dd24620425d4b0cc86881c89861fbc04549e5dc63 \
    --hash=sha256:1a7b04c10f32cc88ab39cbf606e117fd74721c831c98a27dc04578deb0c16979 \
    --hash=sha256:1fa4ecf83bcdf6e6c8f4449aff98eefb5d0604bf88cb883d7da3d8d2d909546a \
    --hash=sha256:2edccc433cbfa046b980b0df0171cd25bcaeb3a68fe9022db0979e7aa74a826b \
    --hash=sha256:7b6d09433a10592ce39b13d7be5a54fbac1d1228ed29abc880fb23df7cb694c9 \
    --hash=sha256:8c233660f575a5a89e6d4cb65d9f938126312bca76d8fe087b947b3a1aaac9ee \
    --hash=sha256:917e891983ca3c1887b4ef36447b1e0873e70c933afc831c6b6da078ba474312 \
    --hash=sha256:ab486563df44c17f5173621c7b198955bd6b613fb87c71c161f827d3fb149a9b \
    --hash=sha256:ae0aefdd8796a7737eccea863f80f81e468a1e4cf14d926bd9b6f5f2d5f90ca9 \
    --hash=sha256:b0726cecd84f9474419d67252add4ac0cd9811b04d61123054b9fb6f57df6e9e \
    --hash=sha256:b58fabe35e80b264a4e3bb23e6b96f9e45a3df7fb7eed419ac0e5947c61e47cc \
    --hash=sha256:c7663d4e37f13e884d13994247449e9f8f574bc4655d509c3b95e9ec9e2b9dc1 \
    --hash=sha256:e452c464a02e7dc7822a05d25db4cde564444a67e58539a00f929c51eddda0cf \
    --hash=sha256:e78c8603dcd9a04c7364f1a3e670cea95d51ee865e4efb3556a3a63adef958ea \
    --hash=sha256:eb7e81434c8d223ec4a219b5fc1c47d0417b12be7ea866e24fb5ad6e84b3d988 \
    --hash=sha256:ed0cace939114f62738d808fdcecd4c869222507e266e574799e9c0faa17d486 \
    --hash=sha256:eed63d3b4d62449571547b60578c5b2c4bcccc5387148db46e0c2313dad0ee00 \
    --hash=sha256:fd04ef36b4a6d599bbdb225dd1d3f51e00105f6d48a28f006da7f9822f2606d8
    # via -r requirements-agent.txt
LOCK
}

# Docker Deployment Mode
if [[ "${USE_DOCKER}" -eq 1 ]]; then
    log "Setting up Docker-based agent deployment..."
    if ! command -v docker &>/dev/null; then
        error "Docker is not installed on this system. Install Docker first or run without --docker."
    fi

    log "Writing environment config to ${CONF_DIR}/agent.env..."
    write_env_file

    CONTAINER_NAME="shapoclyack-agent"
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

    # --env-file rather than -e: a -e assignment is an argument of the docker
    # client, so the key would be in this host's process list every time the
    # container is (re)created.
    log "Starting Docker container '${CONTAINER_NAME}' from ${AGENT_IMAGE}..."
    docker run -d \
        --name "${CONTAINER_NAME}" \
        --restart always \
        --net host \
        --cap-add NET_RAW \
        --cap-add NET_ADMIN \
        --env-file "${CONF_DIR}/agent.env" \
        --entrypoint python \
        "${AGENT_IMAGE}" \
        -m agent

    log "Docker agent container '${CONTAINER_NAME}' started successfully!"
    exit 0
fi

# Native Systemd Installation Mode

# The agent needs Python 3.11 or newer (`from datetime import UTC` in
# agent/logging_setup.py; ruff targets py311). Several supported distributions
# still point `python3` at something older and ship a newer interpreter as a
# separately named package beside it: RHEL/Rocky/Alma 9 default to 3.9 with
# python3.11/python3.12 in AppStream, Ubuntu 22.04 to 3.10 with python3.11 in
# universe. Without this check such a host got a venv the agent cannot run in,
# and the failure surfaced only as "import agent.worker failed".
python_ok() {
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' &>/dev/null
}

find_python() {
    local candidate
    for candidate in python3 python3.14 python3.13 python3.12 python3.11; do
        if command -v "${candidate}" &>/dev/null && python_ok "${candidate}"; then
            PYTHON="$(command -v "${candidate}")"
            return 0
        fi
    done
    return 1
}

log "Detecting OS package manager..."
PKG_MANAGER=""
# RHEL 9 and its rebuilds ship curl-minimal, which provides /usr/bin/curl and
# conflicts with the full curl package: asking dnf for "curl" there fails the
# whole transaction. Only ask for curl where there is none.
CURL_PKG=""
command -v curl &>/dev/null || CURL_PKG="curl"
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-venv ${CURL_PKG} tar ca-certificates
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    dnf install -y -q python3 python3-pip ${CURL_PKG} tar ca-certificates
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    yum install -y -q python3 python3-pip ${CURL_PKG} tar ca-certificates
elif command -v apk &>/dev/null; then
    PKG_MANAGER="apk"
    apk add --no-cache python3 py3-pip ${CURL_PKG} tar ca-certificates
elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman"
    pacman -Sy --noconfirm python python-pip ${CURL_PKG} tar ca-certificates
fi

PYTHON=""
if ! find_python; then
    log "The default python3 is older than 3.11; looking for a newer interpreter package..."
    for version in 3.12 3.11; do
        case "${PKG_MANAGER}" in
            apt)
                apt-cache show "python${version}-venv" &>/dev/null || continue
                apt-get install -y -qq "python${version}" "python${version}-venv" || continue
                ;;
            dnf|yum)
                "${PKG_MANAGER}" -q info "python${version}" &>/dev/null || continue
                "${PKG_MANAGER}" install -y -q "python${version}" || continue
                ;;
            *)
                break
                ;;
        esac
        find_python && break
    done
fi
if [[ -z "${PYTHON}" ]]; then
    error "The agent needs Python 3.11 or newer, and none was found or installable.
  Found: $(command -v python3 &>/dev/null && python3 --version 2>&1 || echo 'no python3').
  Install python3.11 (or newer) with its venv module and re-run this installer,
  or use --docker, which brings its own interpreter."
fi
log "Using $(${PYTHON} --version 2>&1) at ${PYTHON}."

# Create dedicated system user and group
#
# The group is created explicitly rather than left to useradd's
# USERGROUPS_ENAB default, and BusyBox (Alpine) has no default at all:
# `adduser -S` without -G puts the account in 'nogroup' and creates no
# 'shapoclyack' group, so every `chown shapoclyack:shapoclyack` below and the
# unit's Group= would fail. A failed creation stops the install here instead
# of surfacing later as an unrelated chown error.
if id -u shapoclyack &>/dev/null; then
    if [[ "$(id -gn shapoclyack)" != "shapoclyack" ]]; then
        # Typically left behind by an older installer on Alpine. Rewriting an
        # existing account is not this script's call.
        error "The account 'shapoclyack' exists but its primary group is '$(id -gn shapoclyack)', not 'shapoclyack'.
  Remove it (userdel shapoclyack, or deluser shapoclyack on Alpine) and re-run."
    fi
else
    log "Creating system user 'shapoclyack'..."
    if command -v useradd &>/dev/null \
        && { getent group shapoclyack &>/dev/null || groupadd --system shapoclyack; } \
        && useradd --system --gid shapoclyack --shell /usr/sbin/nologin \
            --home-dir "${INSTALL_DIR}" --create-home shapoclyack; then
        :
    elif command -v adduser &>/dev/null \
        && { getent group shapoclyack &>/dev/null || addgroup -S shapoclyack; } \
        && adduser -S -D -H -G shapoclyack -h "${INSTALL_DIR}" -s /sbin/nologin shapoclyack; then
        :
    fi
    if ! id -u shapoclyack &>/dev/null || [[ "$(id -gn shapoclyack)" != "shapoclyack" ]]; then
        error "Could not create the system user 'shapoclyack' in group 'shapoclyack' (tried useradd and adduser)."
    fi
fi

# Prepare directories
mkdir -p "${INSTALL_DIR}" "${CONF_DIR}"
chown -R shapoclyack:shapoclyack "${INSTALL_DIR}"

# Create Python Virtual Environment
#
# A venv left by an earlier run on a too-old interpreter is rebuilt: `venv`
# does not replace an existing bin/python, so building over it would keep 3.9.
log "Setting up virtual environment in ${INSTALL_DIR}/venv..."
VENV_CLEAR=""
if [[ -d "${INSTALL_DIR}/venv" ]] && ! python_ok "${INSTALL_DIR}/venv/bin/python"; then
    VENV_CLEAR=1
fi
"${PYTHON}" -m venv ${VENV_CLEAR:+--clear} "${INSTALL_DIR}/venv"

# Only what the lock names, only the files it hashes: --require-hashes refuses
# a file whose sha256 is not listed and a dependency that is not pinned there,
# and --only-binary stops pip building an sdist, whose build requirements it
# would fetch with no hash check at all. pip itself stays the one the venv
# came with; upgrading it from PyPI first would be the one unchecked install.
log "Installing sensor dependencies from the hash-pinned lock..."
write_agent_lock "${INSTALL_DIR}/requirements-agent.lock"
if ! "${INSTALL_DIR}/venv/bin/pip" install --quiet --disable-pip-version-check \
        --require-hashes --only-binary :all: \
        -r "${INSTALL_DIR}/requirements-agent.lock"; then
    error "Failed to install the sensor dependencies into ${INSTALL_DIR}/venv.
  Each file is checked against ${INSTALL_DIR}/requirements-agent.lock, and
  only wheels are accepted: x86_64 and aarch64, glibc or musl."
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
if ! IMPORT_OUTPUT=$(cd "${INSTALL_DIR}" && "${INSTALL_DIR}/venv/bin/python" -c "import agent.worker" 2>&1); then
    error "The agent package in ${INSTALL_DIR} cannot be imported ('import agent.worker' failed):
$(printf '%s\n' "${IMPORT_OUTPUT}" | tail -n 5 | sed 's/^/    /')
  The installation is incomplete; the service has not been started."
fi

# Write environment configuration
log "Writing environment config to ${CONF_DIR}/agent.env..."
write_env_file
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
# Not optional (no leading "-"): without the file the agent has no credential,
# and a unit that starts anyway just restart-loops. The key stays in the
# environment and out of ExecStart, which every local user can read in `ps`.
EnvironmentFile=${CONF_DIR}/agent.env
ExecStart=${INSTALL_DIR}/venv/bin/python -m agent
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
    # The env file is sourced inside the child rather than expanded into an
    # `env VAR=value` argument list, which would put the provisioning key back
    # into this host's process list.
    #
    # Not sudo: Alpine (OpenRC, the usual host without systemd) and minimal
    # Debian images have none, and the old `nohup sudo …&` failed in the
    # background while this script went on to report success. runuser is
    # util-linux; su covers BusyBox, where `su USER -c CMD ARG0 ARGS` hands
    # the trailing arguments to the shell. `-s /bin/sh` because the account's
    # own shell is nologin.
    #
    # The `cd` is the unit's WorkingDirectory=: `-m agent` resolves the package
    # from the working directory, and without it the agent died at once with
    # "No module named agent" — which nobody saw, for the reason above.
    LAUNCH_SCRIPT='set -a; . "$1"; set +a; cd "$3" && exec "$2" -m agent'

    # A reinstall is the upgrade path, and without a supervisor nothing else
    # stops the agent the previous run started: it would go on running the old
    # code beside the new one, both claiming jobs. Found by owner and exact
    # command line rather than a pid file, which the agent account could
    # rewrite to point this root script at any process.
    AGENT_UID="$(id -u shapoclyack)"
    OLD_PIDS=()
    for proc in /proc/[0-9]*; do
        [[ "$(stat -c %u "${proc}" 2>/dev/null)" == "${AGENT_UID}" ]] || continue
        cmdline="$(tr '\0' ' ' < "${proc}/cmdline" 2>/dev/null)" || continue
        [[ "${cmdline}" == "${INSTALL_DIR}/venv/bin/python -m agent " ]] && OLD_PIDS+=("${proc#/proc/}")
    done
    if [[ ${#OLD_PIDS[@]} -gt 0 ]]; then
        log "Stopping the agent started by a previous install (pid ${OLD_PIDS[*]})..."
        kill -TERM "${OLD_PIDS[@]}" 2>/dev/null || true
        for _ in $(seq 1 30); do
            still_running=0
            for pid in "${OLD_PIDS[@]}"; do
                kill -0 "${pid}" 2>/dev/null && still_running=1
            done
            [[ "${still_running}" -eq 0 ]] && break
            sleep 1
        done
        if [[ "${still_running}" -eq 1 ]]; then
            warn "The previous agent did not stop within 30s of SIGTERM; killing it."
            kill -KILL "${OLD_PIDS[@]}" 2>/dev/null || true
        fi
    fi

    if command -v runuser &>/dev/null; then
        DROP_PRIVS=(runuser -u shapoclyack -- /bin/sh -c "${LAUNCH_SCRIPT}")
    else
        DROP_PRIVS=(su -s /bin/sh shapoclyack -c "${LAUNCH_SCRIPT}")
    fi
    nohup "${DROP_PRIVS[@]}" \
        sh "${CONF_DIR}/agent.env" "${INSTALL_DIR}/venv/bin/python" "${INSTALL_DIR}" \
        > "${INSTALL_DIR}/agent.log" 2>&1 &
    AGENT_PID=$!

    # Same reasoning as the systemd branch: a background launch that dies
    # immediately must not be reported as an installed agent.
    sleep 3
    if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
        error "The agent exited right after start.
  Last lines of ${INSTALL_DIR}/agent.log:
$(tail -n 5 "${INSTALL_DIR}/agent.log" 2>/dev/null | sed 's/^/    /')"
    fi
    log "Agent started in background (pid ${AGENT_PID}), logging to ${INSTALL_DIR}/agent.log."
fi

log "================================================================="
log "Shapoclyack Agent ${AGENT_ID} installed."
log "Connecting to ${SERVER_URL}. Confirm it appears in the agent fleet view;"
log "the host has no self-update mechanism, so upgrades are a reinstall."
log "================================================================="
