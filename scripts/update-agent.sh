#!/usr/bin/env bash
# ==============================================================================
# Shapoclyack Sensor Updater
#
# Installs the signed sensor bundle on a native sensor host (#363). The work is
# done by `python -m agent.update` from the installed package: it fetches the
# bundle the API publishes (GET /api/agent/bundle) with the sensor's own
# credential, or reads one from --bundle-dir, and installs it only if the
# manifest carries the release key's signature, the archive matches the signed
# digest, and the signed version is newer than the installed one and not below
# OCTO_AGENT_MIN_VERSION.
#
# Root does two things here and nothing else: run that verifier as the
# sensor's own account, and restart the unit. The install directory belongs to
# that account (scripts/install-agent.sh), so root executing the venv's python
# or the agent package would be the account's way to root; as the account, it
# changes nothing the account could not already change. It runs in a session
# of its own, reading /dev/null and writing into a pipe whose reader drops
# every control character, so it has no hold on the terminal root started
# this from either: no TIOCSTI (CVE-2016-2779), and no escape sequence for the
# terminal to answer into root's input. The bundle replaces the `agent`
# package only: scanner/ and the venv are not in it. The verdict on the
# restart -- the unit staying up as one process -- is taken here, and decides
# whether the release is kept (--commit) or the previous one put back
# (--rollback). Interrupted (^C, a dropped SSH session, SIGTERM), it stops the
# verifier and puts the previous release back before it exits.
#
# The API is not trusted to vouch for the bundle; only the key pinned in the
# installed package is. An unsigned tarball from a URL is no longer installed
# by this script: that is what --bundle-url used to do. A host whose installed
# package predates agent/update.py has no verifier yet and is upgraded once by
# re-running scripts/install-agent.sh.
#
# Keep this script where only root can write it (e.g. /usr/local/sbin): it is
# what runs as root. A container sensor is upgraded by its image instead.
# ==============================================================================

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/shapoclyack-agent}"
CONF_DIR="${CONF_DIR:-/etc/shapoclyack}"
SENSOR_USER="${SENSOR_USER:-shapoclyack}"
UNIT="${UNIT:-shapoclyack-agent.service}"
HEALTH_SECONDS="${HEALTH_SECONDS:-20}"
BUNDLE_DIR=""
CHECK_ONLY=0
RESTART_ONLY=0
AUTO=0
# agent/update.py: --pending found the bundle already installed.
EXIT_NOTHING_TO_DO=3
# agent/update.py: --pending put back the release an interrupted update left
# live, and stopped there for the unit to be restarted onto it.
EXIT_RECOVERED=4

log() {
    echo -e "\033[1;34m[INFO]\033[0m $*"
}

error() {
    echo -e "\033[1;31m[ERROR]\033[0m $*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage: $0 [--bundle-dir <DIR>] [--check] [--auto] [--restart-only]

With no option, fetches the signed sensor bundle from the API this sensor
reports to (OCTO_API_URL in ${CONF_DIR}/agent.env) and installs it.

Options:
      --bundle-dir <DIR>   Install from sensor-bundle.json, sensor-bundle.json.sig
                           and the archive in DIR instead (air-gapped hosts).
                           Verified exactly as a download is.
      --check              Verify the bundle and report; change nothing. Stops
                           with an error if an interrupted update is waiting
                           to be put back (a run without --check does that).
      --auto               For a timer: do nothing unless OCTO_AGENT_AUTO_UPDATE=true.
      --restart-only       Restart the sensor without touching the package.
  -h, --help               Show this help message.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bundle-dir)
            BUNDLE_DIR="${2:?--bundle-dir needs a directory}"
            shift 2
            ;;
        --check)
            CHECK_ONLY=1
            shift
            ;;
        --auto)
            AUTO=1
            shift
            ;;
        --restart-only)
            RESTART_ONLY=1
            shift
            ;;
        --bundle-url)
            error "--bundle-url is gone: it installed an unsigned tarball from wherever the URL
  pointed. Put the signed bundle (sensor-bundle.json, sensor-bundle.json.sig and the
  archive) in a directory and pass --bundle-dir, or run with no option to fetch it
  from the API. See docs/operations.md, \"Sensor bundle updates\"."
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

has_unit() {
    command -v systemctl &>/dev/null && systemctl cat "${UNIT}" &>/dev/null
}

if [[ "${RESTART_ONLY}" -eq 1 ]]; then
    if has_unit; then
        log "Restarting ${UNIT}..."
        systemctl restart "${UNIT}"
    elif command -v docker &>/dev/null && docker ps --format '{{.Names}}' | grep -q "^shapoclyack-agent$"; then
        log "Restarting Docker agent container..."
        docker restart shapoclyack-agent
    else
        error "No running agent service or container was found to restart."
    fi
    log "Restarted. The agent package was not changed."
    exit 0
fi

PYTHON="${INSTALL_DIR}/venv/bin/python"
if [[ ! -e "${PYTHON}" ]]; then
    error "${PYTHON} not found: this is not a native sensor install. A container
  sensor is upgraded by pulling the new image."
fi

# The verifier, as the sensor's account, from the install directory: `agent`
# there is the package being replaced, and the verifier that runs is the one
# already installed, not the one arriving.
#
# Detached from root's terminal: neither runuser nor su without a pty gives
# the account's process a terminal of its own, so it would share root's, and
# TIOCSTI on it types into root's shell once this script exits. setsid takes
# the controlling terminal away; stdin from /dev/null and output through a
# FIFO leave no descriptor on it either. What comes out of the FIFO reaches
# root's terminal as printable ASCII, tabs and newlines only: an escape
# sequence some terminals answer (a title report, DECRQSS) would otherwise
# put the account's bytes into root's input all the same.
#
# setsid runs as an asynchronous command, which in a script without job
# control is never a process-group leader. util-linux's setsid and BusyBox's
# (which has no -w, as on Alpine with the runuser package but without
# util-linux-misc) both call setsid(2) and exec in place for a non-leader, so
# the pid `$!` names is the new session and its process group, and `wait` on
# it is the verifier's exit status.
set +m
command -v setsid &>/dev/null \
    || error "setsid not found: it is what keeps the sensor's code off root's terminal."
command -v mkfifo &>/dev/null || error "mkfifo not found."
FIFO_DIR="$(mktemp -d)"
trap 'rm -rf "${FIFO_DIR}"' EXIT
FIFO="${FIFO_DIR}/out"
mkfifo -m 0600 "${FIFO}"

# The process running as the account, while one does.
SENSOR_PID=""
IN_SENSOR=0
# The signal that interrupted this run, and whether the run had started
# changing anything an interruption has to undo.
INTERRUPTED=""
CHANGING=0
ABORTING=0

stop_sensor() {
    # TERM, whatever arrived here: an asynchronous command of a script starts
    # with SIGINT ignored, and Python keeps it ignored.
    kill -s TERM -- "-${SENSOR_PID}" 2>/dev/null || kill -s TERM "${SENSOR_PID}" 2>/dev/null || true
}

as_sensor() {
    local status=127 waited filter
    # Immune to the signals meant for this script, so the verifier never
    # writes into a FIFO nobody reads; draining whatever a dead terminal
    # would not take, for the same reason.
    (trap '' INT TERM HUP; LC_ALL=C tr -cd '\011\012\040-\176' || cat >/dev/null) <"${FIFO}" &
    filter=$!
    IN_SENSOR=1
    if command -v runuser &>/dev/null; then
        (cd "${INSTALL_DIR}" && exec setsid runuser -u "${SENSOR_USER}" -- "$@") \
            </dev/null >"${FIFO}" 2>&1 &
    else
        # BusyBox (Alpine) has su but no runuser.
        (cd "${INSTALL_DIR}" && exec setsid su -s /bin/sh "${SENSOR_USER}" -c "$(printf '%q ' "$@")") \
            </dev/null >"${FIFO}" 2>&1 &
    fi
    SENSOR_PID=$!
    # A signal between the start and $! found no pid to pass on.
    [[ -z "${INTERRUPTED}" || "${ABORTING}" -eq 1 ]] || stop_sensor
    while :; do
        waited=0
        wait "${SENSOR_PID}" || waited=$?
        # 127 the second time round: no child of this shell any more, and its
        # status came with the wait before.
        [[ "${waited}" -eq 127 && "${status}" -ne 127 ]] && break
        status="${waited}"
        # A trapped signal ends `wait` early (>128) with the process still
        # running, and it is waited for again.
        if [[ "${status}" -le 128 ]] || ! kill -0 "${SENSOR_PID}" 2>/dev/null; then
            break
        fi
    done
    SENSOR_PID=""
    wait "${filter}" || true
    IN_SENSOR=0
    return "${status}"
}

# Interrupted: the verifier gets the signal (it has a session of its own, so
# ^C at root's terminal does not reach it), and whatever this run swapped in
# without a verdict is put back -- not left live for the next restart of the
# unit to pick up unchecked.
abort_update() {
    ABORTING=1
    set +e
    # Noted and otherwise ignored from here: putting the release back is what
    # the signal asked for.
    trap ':' INT TERM HUP
    local code=143 put_back=0
    [[ "${INTERRUPTED}" == INT ]] && code=130
    [[ "${INTERRUPTED}" == HUP ]] && code=129
    if [[ "${CHANGING}" -eq 1 ]]; then
        echo "Interrupted (SIG${INTERRUPTED}); putting the previous release back..." >&2
        updater --abort
        put_back=$?
        if [[ "${put_back}" -eq "${EXIT_RECOVERED}" ]]; then
            if has_unit; then
                systemctl restart "${UNIT}" \
                    || echo "${UNIT} did not restart onto the previous release. Inspect it with: journalctl -u ${UNIT} -n 50" >&2
            else
                echo "Restart the sensor process yourself: it may run the release put back." >&2
            fi
        elif [[ "${put_back}" -ne 0 ]]; then
            echo "Could not put the previous release back; the next run of this script does." >&2
        fi
    fi
    exit "${code}"
}

on_signal() {
    INTERRUPTED="$1"
    if [[ "${IN_SENSOR}" -eq 1 ]]; then
        # as_sensor returns once the process is gone; its caller aborts.
        [[ -z "${SENSOR_PID}" ]] || stop_sensor
        return 0
    fi
    abort_update
}
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
trap 'on_signal HUP' HUP

updater() {
    local status=0
    as_sensor "${PYTHON}" -m agent.update --install-dir "${INSTALL_DIR}" \
        --env-file "${CONF_DIR}/agent.env" "$@" || status=$?
    [[ -z "${INTERRUPTED}" || "${ABORTING}" -eq 1 ]] || abort_update
    return "${status}"
}

probe=0
as_sensor "${PYTHON}" -c "import agent.update" || probe=$?
[[ -z "${INTERRUPTED}" ]] || abort_update
if [[ "${probe}" -ne 0 ]]; then
    error "The bundle verifier did not start as ${SENSOR_USER} (its output, if any, is
  above). A sensor installed before agent/update.py existed, or whose venv lacks its
  dependencies, is upgraded once by re-running scripts/install-agent.sh; from then
  on this script can update it."
fi

ARGS=()
[[ -n "${BUNDLE_DIR}" ]] && ARGS+=(--bundle-dir "${BUNDLE_DIR}")
[[ "${AUTO}" -eq 1 ]] && ARGS+=(--auto)

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    exec_status=0
    updater --check ${ARGS[@]+"${ARGS[@]}"} || exec_status=$?
    exit "${exec_status}"
fi

CHANGING=1
if ! has_unit; then
    # No systemd (OpenRC, a bare nohup start): the updater's own health check
    # is the import of the swapped-in tree; the process is restarted by hand.
    updater ${ARGS[@]+"${ARGS[@]}"}
    exit $?
fi

# Type=simple calls a unit active the moment it forks and Restart=always brings
# a crashing one back every few seconds, so "active" proves nothing on its own.
# The main PID staying the same for HEALTH_SECONDS is the test.
healthy() {
    systemctl restart "${UNIT}" || return 1
    sleep 1
    local pid now
    pid="$(systemctl show -p MainPID --value "${UNIT}")"
    [[ -n "${pid}" && "${pid}" != "0" ]] || return 1
    for ((i = 0; i < HEALTH_SECONDS; i++)); do
        systemctl is-active --quiet "${UNIT}" || return 1
        now="$(systemctl show -p MainPID --value "${UNIT}")"
        [[ "${now}" == "${pid}" ]] || return 1
        sleep 1
    done
}

status=0
updater --pending ${ARGS[@]+"${ARGS[@]}"} || status=$?
if [[ "${status}" -eq "${EXIT_RECOVERED}" ]]; then
    # A previous run was killed between the restart and its verdict: the unit
    # runs a release that is no longer live. Restart it onto the one put back
    # before anything else, whatever the bundle turns out to be.
    log "An interrupted update was rolled back; restarting ${UNIT} onto the previous release..."
    systemctl restart "${UNIT}" \
        || error "${UNIT} did not restart onto the previous release. Inspect it with: journalctl -u ${UNIT} -n 50"
    status=0
    updater --pending ${ARGS[@]+"${ARGS[@]}"} || status=$?
fi
if [[ "${status}" -eq "${EXIT_NOTHING_TO_DO}" ]]; then
    exit 0
elif [[ "${status}" -ne 0 ]]; then
    exit "${status}"
fi

if healthy; then
    updater --commit
    log "${UNIT} stayed up for ${HEALTH_SECONDS}s on the new agent package; kept."
    exit 0
fi

updater --rollback || true
systemctl restart "${UNIT}" || true
error "${UNIT} did not stay up on the new release; the previous release is back.
  Inspect it with: journalctl -u ${UNIT} -n 50"
