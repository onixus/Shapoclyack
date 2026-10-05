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
KEEP_KEY=0
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
Usage: $0 --server <URL> (--key <PROVISIONING_KEY> | --key-stdin | --keep-key) [OPTIONS]

Required:
  -s, --server <URL>            Shapoclyack server base URL (e.g. http://192.168.1.100:8000)
  -k, --key <KEY>               Agent Provisioning Key (octo-pk-...)
      --key-stdin               Read the provisioning key from stdin instead.
                                Prefer this: an argument is visible to every
                                local user in this host's process list.
      --keep-key                Or keep the key already in
                                /etc/shapoclyack/agent.env, to reinstall the
                                sensor configured there. Refused unless that
                                file holds an agent ID and a key, is for the
                                same --tenant, and names the same agent ID as
                                --agent-id (when given).

Options:
  -t, --tenant <TENANT_ID>      Tenant ID (default: default)
  -a, --agent-id <ID>           Explicit Agent ID (default: the one in
                                /etc/shapoclyack/agent.env from an earlier
                                install for the same tenant, otherwise
                                agent-<short hostname>-<random>)
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
        --keep-key)
            KEEP_KEY=1
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

# --keep-key reads the key from agent.env further down, once root is checked.
if [[ "${KEEP_KEY}" -eq 1 ]]; then
    if [[ -n "${PROVISIONING_KEY}" || "${KEY_FROM_STDIN}" -eq 1 ]]; then
        error "--keep-key takes the key from ${CONF_DIR}/agent.env; do not combine it with --key or --key-stdin."
    fi
else
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
        error "Missing required argument: --key <KEY> (or --key-stdin, or --keep-key)"
    fi
fi

SERVER_URL="${SERVER_URL%/}"

# Check root privileges
#
# Before the agent ID is chosen, because that starts from an earlier install's
# agent.env, which is 0600 and unreadable to anyone else.
if [[ $EUID -ne 0 ]]; then
    error "This installer must be run as root (or via sudo)."
fi

# The last value of one variable in an existing agent.env, or nothing.
#
# Parsed rather than sourced: the file holds the provisioning key, the native
# path hands it to the account the sensor runs as, and this runs as root, so
# sourcing it would run whatever that account wrote into it.
env_file_value() {
    local value=""
    if [[ -r "${CONF_DIR}/agent.env" ]]; then
        value=$(sed -n "s/^[[:space:]]*$1=//p" "${CONF_DIR}/agent.env" 2>/dev/null | tail -n 1) || true
    fi
    printf '%s' "${value%$'\r'}"
}

# Reinstalling the sensor that agent.env describes, with the key it already
# holds -- what the SSH push does for a host that already runs one, so no key
# has to be minted and none revoked. Each check below refuses a file that is
# not that sensor's: its key would be refused the ID, or register it elsewhere.
if [[ "${KEEP_KEY}" -eq 1 ]]; then
    PROVISIONING_KEY=$(env_file_value OCTO_AGENT_PROVISIONING_KEY)
    PREVIOUS_ID=$(env_file_value OCTO_AGENT_ID)
    PREVIOUS_TENANT=$(env_file_value OCTO_TENANT_ID)
    if [[ -z "${PROVISIONING_KEY}" || -z "${PREVIOUS_ID}" ]]; then
        error "--keep-key needs an agent ID and a provisioning key in ${CONF_DIR}/agent.env, and it has no such pair."
    fi
    if [[ -n "${PREVIOUS_TENANT}" && "${PREVIOUS_TENANT}" != "${TENANT_ID}" ]]; then
        error "--keep-key: ${CONF_DIR}/agent.env is for tenant '${PREVIOUS_TENANT}', not '${TENANT_ID}'."
    fi
    if [[ -n "${AGENT_ID}" && "${AGENT_ID}" != "${PREVIOUS_ID}" ]]; then
        error "--keep-key: ${CONF_DIR}/agent.env is for agent ${PREVIOUS_ID}, not ${AGENT_ID}; its key is not this sensor's."
    fi
    AGENT_ID="${PREVIOUS_ID}"
    log "Keeping agent ID ${AGENT_ID} and its provisioning key from ${CONF_DIR}/agent.env."
    unset PREVIOUS_ID
fi

# A re-run on a host that already has a sensor is how that sensor is upgraded,
# so it keeps the ID it registered under. A fresh one would register a second
# sensor, leave the first stale in the fleet view (and announced as
# agent_offline), and drop the group an operator had put it in.
if [[ -z "${AGENT_ID}" ]]; then
    AGENT_ID=$(env_file_value OCTO_AGENT_ID)
    PREVIOUS_TENANT=$(env_file_value OCTO_TENANT_ID)
    if [[ -n "${AGENT_ID}" && -n "${PREVIOUS_TENANT}" && "${PREVIOUS_TENANT}" != "${TENANT_ID}" ]]; then
        # An ID is bound to its tenant, and revoking a key does not release it
        # across tenants, so keeping it would be refused until the other
        # tenant deletes the row. Moving tenants makes a new sensor.
        log "Not reusing agent ID ${AGENT_ID}: ${CONF_DIR}/agent.env is for tenant '${PREVIOUS_TENANT}'."
        AGENT_ID=""
    fi
    if [[ -n "${AGENT_ID}" ]]; then
        log "Keeping agent ID ${AGENT_ID} from ${CONF_DIR}/agent.env (pass --agent-id to change it)."
        PREVIOUS_KEY=$(env_file_value OCTO_AGENT_PROVISIONING_KEY)
        if [[ -n "${PREVIOUS_KEY}" && "${PREVIOUS_KEY}" != "${PROVISIONING_KEY}" ]]; then
            warn "The provisioning key differs from the one ${AGENT_ID} was installed with.
  The API refuses this ID under a new key while the previous key is active:
  revoke that key (the sensor then authenticates on its next retry), or pass
  --agent-id to register this host as a new sensor. See docs/operations.md,
  'Revoke before you re-provision'."
        fi
        unset PREVIOUS_KEY
    else
        HOST_SHORT=$(hostname -s 2>/dev/null || echo "agent")
        RAND_SUFFIX=$(head -c 4 /dev/urandom 2>/dev/null | xxd -p 2>/dev/null || echo "$$")
        AGENT_ID="agent-${HOST_SHORT}-${RAND_SUFFIX}"
    fi
fi

log "Installing Shapoclyack Agent (${AGENT_ID}) for tenant '${TENANT_ID}' connecting to ${SERVER_URL}..."

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
# writes with the lock byte for byte; scripts/lock-python-deps.sh rewrites the
# text between the LOCK lines whenever it regenerates the lock.
write_agent_lock() {
    cat <<'LOCK' > "$1"
# This file was autogenerated by uv via the following command:
#    uv pip compile --universal --no-strip-extras --generate-hashes --python-version=3.11 --output-file=requirements-agent.lock requirements-agent.txt
cffi==2.1.1 ; platform_python_implementation != 'PyPy' \
    --hash=sha256:046bfc24911b37851ee1b51aab8bffe713d89c68c6a057b09484ce9fd5f69b4e \
    --hash=sha256:06c72bb76605a4b0cd0aad6930b69d4baf7dd5d806cfc409b824191099700e66 \
    --hash=sha256:0beceaabe56af686895136a2de78db54ecd8e4046b236b8fd6d6cb61389e9bf2 \
    --hash=sha256:154852545011f779917b11c78db2358d095da62a9a172b78ad0a583ee5adc0d0 \
    --hash=sha256:194cffa889098ced9976c3fc6340305e43f6303657d298da55366907c05c22d6 \
    --hash=sha256:19ee6127ee34de7d83ce3d371ebc5ed91addbdcc39f9ab15ce4eb35a4e534971 \
    --hash=sha256:1a18a57b58cfb21fc28d72e876acf10eaed67a1ed96226f92af4df681d571c4c \
    --hash=sha256:1aa5645c30469b09530c4ebca77ebf8f17618293c58f8549cb1a543a50236e7d \
    --hash=sha256:1dea0e4d7d4f11f619fe8c1d76caf49e24405b4b5743c0e3be16a500ecd930c9 \
    --hash=sha256:208f941bb9d18e768138677f0a6d2ce01f590df56043dda1df1535ac57c88517 \
    --hash=sha256:210019b6c7cf07f081b4c54635c8cf744377001350e29cc0f81c4377b4797735 \
    --hash=sha256:246fa40ce8645a614ff682e0b70f37134e460eaf93a775e0cbe3cca585a67a80 \
    --hash=sha256:25792eac27877609e7bb06d42ff88278a6624fff2ba9bbb523c09616b117e80f \
    --hash=sha256:27350daa11d4f10c540e6e89dada4c54feb7256ad03e9a4dc075ebad7ba360d1 \
    --hash=sha256:28907ab9bfb6aa13184cfc17c6b8e1023c5ab6fd7076d8c20a35e59fe04f8f29 \
    --hash=sha256:2ae64be792b8966f2c69538199728b290e34726562896df1e5dc8ffd8d8188e8 \
    --hash=sha256:31348097ff5bbe827ccc41795d4dd099d9f0625e7def00ee653c137a490c2a6c \
    --hash=sha256:3143d81e29e1e20a9ce10901ec369012947876596f75a222235965f2b7ae832e \
    --hash=sha256:3222ba5d678f80a030e6afbcc33dc1ae5cb45facabb61cee2c7016b8432fde48 \
    --hash=sha256:3311ed60d36f83378794e1009ac6258bafbf81f7888b4caa7b35a521e3f95813 \
    --hash=sha256:334644fbac4eff73d985a17a91226df55d0f394160c4cfb880e084c8f7161cac \
    --hash=sha256:34e261f78cb6ceaaa36f42f2613f4380d94d9c759a9c73c769ee6e0247364632 \
    --hash=sha256:363e05fa78e15116c3c32c210ee36884fd6b9afa6d440e47112c3bd511d64cb6 \
    --hash=sha256:398aff33cee2767e3e781d2554c54bd0dff386bb437581e0d8011fde1a942ec1 \
    --hash=sha256:3d22a20b1fb1632cc72c22f95f7b0d2961c3e1c235f245ba4c606c4771035659 \
    --hash=sha256:42a494cee34437f05546455144f2b5d9ac09b1face62bcfce597d2e521066688 \
    --hash=sha256:42e2f76b9455f5a9a844f770bf3e200ed3da0e15f5df3db9c31fe80b04b3d004 \
    --hash=sha256:42f6930c31dc7f50732c9ae793c2786c7b6b044195967bbdde40bb9be81c4cc0 \
    --hash=sha256:456a61fa52d579ebf9df2e9552ead5129855dbaff6c1e5a9b1bc408809bdc062 \
    --hash=sha256:471cee653ae88de62096552e6d24ccb4a5adb8c8c9f10b5054d0122c15bf2779 \
    --hash=sha256:49cbc70e6542d4ccccb936558d1064a8012541e78f821f955cff24e357776c94 \
    --hash=sha256:4a7c934f7360e8cd64fe9efadcbd10c7c6364f531e432b9a4bf5ccbc9e0e8b50 \
    --hash=sha256:4be96343e422f2dfcd12ab5c9f5aebe03f82f737c6bffeca6830b3875cb44aab \
    --hash=sha256:4f42141fc14250de6dde5ee7ea4432be017252d91f19c5ad043c084cea629cac \
    --hash=sha256:507a24c282e0f42f8ed737cf048572cbf580468da5555764a8331735e9c736b6 \
    --hash=sha256:51b31d1c98274844cfd7838ce00bfc27c7423a4dc00fc0772fc3331c2cc90676 \
    --hash=sha256:58acb8ab8e295e6c5ea12f888cbb13cf21511ef2a3303a23f4325c29d17fe5c1 \
    --hash=sha256:5a59cc1c4442bc3d5c703bf720b51138d0bfc173618807c9ee2490a7541dd3d9 \
    --hash=sha256:5bb4e7ea95dcd6a014a6fef62e62467d67d8e582326443f3d68e71d6320a9fcf \
    --hash=sha256:5c58fe613dc5e5336357eff555824a314d8e43282600435c8d1cb6a7a2fedd13 \
    --hash=sha256:5e7cecbaadb83884793e05828cee59b210b24583b9c7425d0ba6a754fe22eb4e \
    --hash=sha256:616f097f2fe415bc92a247f02e11f634e1f9e9a83d327e3c915c15089c87869e \
    --hash=sha256:63bbfd5ded17c4840ac07cd8f1c21ba9d9708141f840b324f422f41b207e3973 \
    --hash=sha256:64faea20f4e2613363a1a9b9c7dd73058f3ecd00133a511e72ad7c511658f527 \
    --hash=sha256:661c298b4821edebead0c91edd2b00374d67ad7c5a1f7a91d4442633b79d6a72 \
    --hash=sha256:68e62fe11f30d5ca8289242866f0a5291402d8529ca2178ab8afc5c9694ae890 \
    --hash=sha256:6a8dddef476fab96d066d578fc88526767b836ab5ab21754e1d5bf3879c31c7c \
    --hash=sha256:6e192623c49c94421616a5778fba35cf0d5a8d000650c1967ef4448ee5cdd990 \
    --hash=sha256:7225e4514edb64eb6740324353e0da0711954fd8d7da4576755b1c6e09b697cd \
    --hash=sha256:75f80557d1389eddbd0de2681f6a390a0c5338c31ddaa821381c203fc3fd50d9 \
    --hash=sha256:770de9db11e84213beec501cfcaa013b019820ca881e03344dea5844f7876d94 \
    --hash=sha256:7750c6449dff7864bb9bb27ddfb0267756189201a3afc911d82b3caacd70dfc3 \
    --hash=sha256:7bde5e4cc5c10140859842b9d383af292b22639a4dffb725314baf45968cef80 \
    --hash=sha256:7ce713ace7c0e4520535b42b77eaa742c16dab813978064913e5a3cf82973b41 \
    --hash=sha256:7da0c5eff80f0197f3b3d1232ec5a682a9325f4ae9016a78f5f5ca35f9ced1f5 \
    --hash=sha256:7dbb61fe3a7699468030f71bbe5f8a0e326a151daa91beb11a6fc1f980c55e1c \
    --hash=sha256:811bd1e21d32de12efca32393a0ab3f5133b54fce9bd44b8bd77ab07da14bf6a \
    --hash=sha256:8ef53b2de9bcb9197d31854256575d59dbac0cba72ac627bb291ef5eceb74be4 \
    --hash=sha256:937c0052c05a31ca1daf18de3158eed4dbfcb9cc107adbea227728d647be701e \
    --hash=sha256:9d2055050ea716bd38b7f7f1579c275386646b4894c155a3e2f3cd62ed41b7c6 \
    --hash=sha256:9f8d177621de5cb38ee3e731eda45d421db093ec0739f46a5594babda7987a98 \
    --hash=sha256:a2d7755bef5a12ed488f4ef1f1b69ee9191d7396083b755a5d2295f6edb4768b \
    --hash=sha256:a48d62ab9d6f4f98c983223a547af44be6ca3691074c31cecced6facd3ba2dc1 \
    --hash=sha256:a4f00aa42f75d6e4595e8866e748cc1705adc0cddfeb2ca86d0d03993d63ba03 \
    --hash=sha256:a6e721d4b0e45d5b65e87534470e67b18dcd092c83f68fba09f152b9cbc061af \
    --hash=sha256:a730a083190634c65cca36ba5f489531576ebd79bcd5c8e172130f6453127231 \
    --hash=sha256:a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2 \
    --hash=sha256:aa9511c62d14da7aacc9b4bf51f3f697a621e83b2d6919008243c3aad168eea3 \
    --hash=sha256:ab36d55f9ed2d067327667c2fea18dda018eb628dd6347aa01dda6cf1f5d3836 \
    --hash=sha256:ad2c86c495b899d862ea0f4b42891b8713a3bd45dd4105c7fd51c2a72f39f3a5 \
    --hash=sha256:aeae0e330c9f6acd681f647d46cefd30c29f93e3392882e792e82080c9691399 \
    --hash=sha256:b0431303acaea1089ad4b3e9ce4e6518193def1118d4073ca848635ee4ea2e96 \
    --hash=sha256:b5bdfd1c873d4e093aabc0ca84c4ca6dbc4f752afb5c86f146d9742580c9da2e \
    --hash=sha256:baed1e86cc735622097354b9d1281406caf42ff42a886d29faa8e8d1630333be \
    --hash=sha256:c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf \
    --hash=sha256:c26608d2222fb1e94487e4a387d85f13eb55d5ed725cb25a0c589ac4ee60e7bc \
    --hash=sha256:c7659f22557c5a0bc4855cd635f55edec690cc008a40768527762cb9fb263455 \
    --hash=sha256:c8c69575568085ba0b1b10c0249d779a214aea6f6522e949a0fc9fb0fcb449d0 \
    --hash=sha256:c8d2c9fd1f2d16f780d15127abb050d13d1a76c03a4bd87d7e4980e45e511e12 \
    --hash=sha256:ca82be1a1d406ecfe1d25dc16cb33488e5a16bf4438c9fb590484ea29d92478b \
    --hash=sha256:cc572dace3f60ef98d7b12ff411d20f5362feb31a0439eab0085bbfd349982d7 \
    --hash=sha256:d18e5ac0f2f03f4f518d3e23db0f0cad7faa1da8620e9c09461d443bbf6e6692 \
    --hash=sha256:d28630f5854ab07ab1fd4aba756de52326c82e6be15d414b12793f1975048b54 \
    --hash=sha256:d9c275eaacd24aa73f94ffd6de08fc3f932424d8b6c376f4bed7cde376fe7bc3 \
    --hash=sha256:da0e573f9f97159390c89d9f1a9e41908b66d408cc5b58d08cf3847d844c531b \
    --hash=sha256:dd31f52ea1086513bb9df30f8fcee9b8918323ae067a3d5b78bc826a000712be \
    --hash=sha256:dddad92b554513a31f272570678ba307fb9f618f05e3d4a5eacafff9eae03e1d \
    --hash=sha256:df423d40ee8654634421812bc3b196da3f9bd7d32929da813f8394c4348a5358 \
    --hash=sha256:df913725b79db7bcf03448f36b7bf8815363417d5b58deecf9305e3e30f0f21a \
    --hash=sha256:e0bcb7e0f677f543555d2adff3bf19c05f66cdb4796e5ff602442ab2fe3c4ef7 \
    --hash=sha256:e2d65b31f36619cda3999b78b2aa9632e76b78448e7a56fc4240824200e7c4fc \
    --hash=sha256:e6e8cff14d6fb0be70a09c0bdc58096f501952d04624ebf867e0e56da2df8960 \
    --hash=sha256:f16c709686a78c727bbbf059f92b0bf41c6fc60deec706d2dc19f529175a6125 \
    --hash=sha256:f24fb43132a4c6b4cb4eb029492919b2db645be6808d738f244fd146c03c32cb \
    --hash=sha256:f53e442b08449d42821fa4a4fba000095af9f62742a500f978a9f557ec44339a \
    --hash=sha256:f5cfbc5fe74540d335175b656c725d74d90e3730c626d92575eea35029d9afaa \
    --hash=sha256:f81b3b8f3d4e343550fa4baa0e479bba9f2d29ce9c2e9b51d1ce1718d7442fcf \
    --hash=sha256:f8ec5e643a9a937f64e1999eb9f75d072263751912dc5cd06d3c85f8f44be7c3 \
    --hash=sha256:fb92203a88b3d3053034db775110081c49d28be6551923805e039924093761e4 \
    --hash=sha256:fcd22650c908d7b7da162bbfaab594a1227a15d1643a98c68b122ac642fa2264
    # via cryptography
cryptography==50.0.0 \
    --hash=sha256:031e2d5dd4bb9caa3ca9c82e5a197fd8ae680232cee62603d1a813f3f07e3d03 \
    --hash=sha256:06a32a980526a6ab9a4b9bf8f7385800791e2bb960903cb6b530e4817509a3b7 \
    --hash=sha256:07479a1cb08219ab719147e742e76090c9c773321959bb94946fffdd397a6437 \
    --hash=sha256:07949c449a1abcf60d1ee6e88956d89404c7df3c8258f46589e912988e551987 \
    --hash=sha256:105110f43a471dbd0060b9c9516cb8a6a79233631a04cc2ba16f28323ac6e025 \
    --hash=sha256:11b74db56cdbe3cdee6e3f6982ecb70334fa10dce99ed58bf7894aaaa3b2a037 \
    --hash=sha256:12b9c6996425c76ea6c457ace4f3073e715b8c545add07cd1a8f3a4f90691269 \
    --hash=sha256:1489e263a8048bb8b6a8bac662eb2d402ea5d2b7b4699b72f385f1e2772db105 \
    --hash=sha256:19736989797678c6af1e55cd49055cdbcb55d8f6b5583ac5335f933aba9101dc \
    --hash=sha256:1b4a266766514614f8aa60416e71f2fc6e575d36e7bdc90f644fadb2f4b75b95 \
    --hash=sha256:2a8183b489dc1f7f80f135780fadc1108f14b31b8a40411c7a5b17425f65f28b \
    --hash=sha256:37fdb0d0111f1e2ff07139dfb79f1b49531f8e213c46f1163dd7642979b58c47 \
    --hash=sha256:3f5735ffe4996d28b809371756219f5354864902a3b9e7c0b9ee87041209fc9c \
    --hash=sha256:49e7d93abdbd2990caced757e5fade25302f719c3c8fb6e6fff2dde98999fc41 \
    --hash=sha256:5e34edd123674534acd70147f0ca331eaa2c74e6325fb2028c886aa26ba0b68c \
    --hash=sha256:62598a8a57f815db4c6259a4e97d857dab56697e7de8e8ab02352ab74da1995d \
    --hash=sha256:65c2c3add92b45fd0709db8594536aea39c2a67af0e27ffcf049c498501140b7 \
    --hash=sha256:6ba6a53445bd3cfa809ef3ef5f1589aa6ba08784a1d962bf47d0940e871dab1c \
    --hash=sha256:6e7d61120573a7f2cd94cc095f9e81f6967c61ccdf194285aa143ecec8e0b708 \
    --hash=sha256:7cec5b856506da6defb290f30c9ee687d5f5e8cb0bd3f6459dde43b0b4fa40ef \
    --hash=sha256:80b63928fa35083b33966ce1efb70e5b9607181e49dcd1c22c8c005e319f667f \
    --hash=sha256:82148ec5bddac30b51a5b3c1945075f896fa022cb93f8e4a01e9f6ee95292c5f \
    --hash=sha256:828743d939e9629bc267b8e2d08d8bb67cd4319c771a33d4b18b22dd8fb7440a \
    --hash=sha256:8d89f3976b10b4ce31118de72329025f70d2c6ead14a8217c5514dd2c6d5a78f \
    --hash=sha256:8eb5e1172eb569ea8a872796576e6a67c276351728b6455d5beb01242b027c6a \
    --hash=sha256:900131fafd8aead39ac7dd3a7e833be754c17a95cfd91221636949fe4eb0aa8a \
    --hash=sha256:910d11e1a385c654bf738bf3e6b8e6ed5de0f5610fcae2be9e5b398d8081d20e \
    --hash=sha256:910e1d2668e7de9648f2bcee30e180db2a6b15c30f887d7c4c93ddf96e3992e3 \
    --hash=sha256:9aa87839c383bdbab6ef865787a1fb877af8dd03464c4400322726feaaadfc6d \
    --hash=sha256:a1b30560f2acc95aa8b2e06e716a13dbfc97314747b80d9707e307f77b40d6b3 \
    --hash=sha256:a91296cb61e8df6f86d0c19cc4068228da256bf59bf86049fbd821084565327f \
    --hash=sha256:b42a28c1844fd9de8f3f7d540e36b66f3a9c83fceac7170ebc7a6a19edd9dcae \
    --hash=sha256:bd1c592e4d5974f0d08d4888e432157adba757c66da0246918e43677fafa2d30 \
    --hash=sha256:c87f62a3d3b9888ed0fdde100ec06aa61ca9cd44bad9057d1dff9a516b5f5bb9 \
    --hash=sha256:c99c003e088647b8a5b7c145d6f78c335f6348332b62e142d411c4b63d1460b9 \
    --hash=sha256:ccdc4a71a4dabae05de219404f9f4abc38e3b58422177ff93d0da05967dafa07 \
    --hash=sha256:d24fead1d4d076e1bfb006dcec392074a3cd8d7b4fc8a595aa64073b2b7a96ba \
    --hash=sha256:d58c3db7cd6eed54e6c06744db55456b65ebd7492ddeae9c1e93cfca7aa857d3 \
    --hash=sha256:d764dcf130c428ef66786f866dd750f53182bc608813489915e9fc106bb0c82f \
    --hash=sha256:df2a58a472f332225671c35b0a830208b86d004f82baa8530fa3782c85646533 \
    --hash=sha256:e722f16708d854fe924790e051061f6704a472c3bac347b6fd88033ea8dd0dc5 \
    --hash=sha256:ecfed7367f965a0328cfbdd70da860f15441f002f613185668c6e6ebf5a0ac11 \
    --hash=sha256:eeac2acb5a20ed25e0ad6d1df9891a520b78b404266b6d11778f25d5d691a6c9 \
    --hash=sha256:f59e38625469987d7ef6d495323c55e7db6c212eaf6112267e0d3b565a2e9c9f \
    --hash=sha256:f89831ef99dd7dd169ab06d63a831adb9e20a87aac6d380266bbda5823349169 \
    --hash=sha256:fd9192b7b70c573d7f214eb1ae35e00d359f6f5e4b27c7e21e30de1fc6204645
    # via -r requirements-agent.txt
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
pycparser==3.0 ; implementation_name != 'PyPy' and platform_python_implementation != 'PyPy' \
    --hash=sha256:600f49d217304a5902ac3c37e1281c9fe94e4d0489de643a9504c5cdfdfc6b29 \
    --hash=sha256:b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992
    # via cffi
pyyaml==6.0.3 \
    --hash=sha256:00c4bdeba853cc34e7dd471f16b4114f4162dc03e6b7afcc2128711f0eca823c \
    --hash=sha256:0150219816b6a1fa26fb4699fb7daa9caf09eb1999f3b70fb6e786805e80375a \
    --hash=sha256:02893d100e99e03eda1c8fd5c441d8c60103fd175728e23e431db1b589cf5ab3 \
    --hash=sha256:02ea2dfa234451bbb8772601d7b8e426c2bfa197136796224e50e35a78777956 \
    --hash=sha256:0f29edc409a6392443abf94b9cf89ce99889a1dd5376d94316ae5145dfedd5d6 \
    --hash=sha256:10892704fc220243f5305762e276552a0395f7beb4dbf9b14ec8fd43b57f126c \
    --hash=sha256:16249ee61e95f858e83976573de0f5b2893b3677ba71c9dd36b9cf8be9ac6d65 \
    --hash=sha256:1d37d57ad971609cf3c53ba6a7e365e40660e3be0e5175fa9f2365a379d6095a \
    --hash=sha256:1ebe39cb5fc479422b83de611d14e2c0d3bb2a18bbcb01f229ab3cfbd8fee7a0 \
    --hash=sha256:214ed4befebe12df36bcc8bc2b64b396ca31be9304b8f59e25c11cf94a4c033b \
    --hash=sha256:2283a07e2c21a2aa78d9c4442724ec1eb15f5e42a723b99cb3d822d48f5f7ad1 \
    --hash=sha256:22ba7cfcad58ef3ecddc7ed1db3409af68d023b7f940da23c6c2a1890976eda6 \
    --hash=sha256:27c0abcb4a5dac13684a37f76e701e054692a9b2d3064b70f5e4eb54810553d7 \
    --hash=sha256:28c8d926f98f432f88adc23edf2e6d4921ac26fb084b028c733d01868d19007e \
    --hash=sha256:2e71d11abed7344e42a8849600193d15b6def118602c4c176f748e4583246007 \
    --hash=sha256:34d5fcd24b8445fadc33f9cf348c1047101756fd760b4dacb5c3e99755703310 \
    --hash=sha256:37503bfbfc9d2c40b344d06b2199cf0e96e97957ab1c1b546fd4f87e53e5d3e4 \
    --hash=sha256:3c5677e12444c15717b902a5798264fa7909e41153cdf9ef7ad571b704a63dd9 \
    --hash=sha256:3ff07ec89bae51176c0549bc4c63aa6202991da2d9a6129d7aef7f1407d3f295 \
    --hash=sha256:41715c910c881bc081f1e8872880d3c650acf13dfa8214bad49ed4cede7c34ea \
    --hash=sha256:418cf3f2111bc80e0933b2cd8cd04f286338bb88bdc7bc8e6dd775ebde60b5e0 \
    --hash=sha256:44edc647873928551a01e7a563d7452ccdebee747728c1080d881d68af7b997e \
    --hash=sha256:4a2e8cebe2ff6ab7d1050ecd59c25d4c8bd7e6f400f5f82b96557ac0abafd0ac \
    --hash=sha256:4ad1906908f2f5ae4e5a8ddfce73c320c2a1429ec52eafd27138b7f1cbe341c9 \
    --hash=sha256:501a031947e3a9025ed4405a168e6ef5ae3126c59f90ce0cd6f2bfc477be31b7 \
    --hash=sha256:5190d403f121660ce8d1d2c1bb2ef1bd05b5f68533fc5c2ea899bd15f4399b35 \
    --hash=sha256:5498cd1645aa724a7c71c8f378eb29ebe23da2fc0d7a08071d89469bf1d2defb \
    --hash=sha256:5cf4e27da7e3fbed4d6c3d8e797387aaad68102272f8f9752883bc32d61cb87b \
    --hash=sha256:5e0b74767e5f8c593e8c9b5912019159ed0533c70051e9cce3e8b6aa699fcd69 \
    --hash=sha256:5ed875a24292240029e4483f9d4a4b8a1ae08843b9c54f43fcc11e404532a8a5 \
    --hash=sha256:5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b \
    --hash=sha256:5fdec68f91a0c6739b380c83b951e2c72ac0197ace422360e6d5a959d8d97b2c \
    --hash=sha256:6344df0d5755a2c9a276d4473ae6b90647e216ab4757f8426893b5dd2ac3f369 \
    --hash=sha256:64386e5e707d03a7e172c0701abfb7e10f0fb753ee1d773128192742712a98fd \
    --hash=sha256:652cb6edd41e718550aad172851962662ff2681490a8a711af6a4d288dd96824 \
    --hash=sha256:66291b10affd76d76f54fad28e22e51719ef9ba22b29e1d7d03d6777a9174198 \
    --hash=sha256:66e1674c3ef6f541c35191caae2d429b967b99e02040f5ba928632d9a7f0f065 \
    --hash=sha256:6adc77889b628398debc7b65c073bcb99c4a0237b248cacaf3fe8a557563ef6c \
    --hash=sha256:79005a0d97d5ddabfeeea4cf676af11e647e41d81c9a7722a193022accdb6b7c \
    --hash=sha256:7c6610def4f163542a622a73fb39f534f8c101d690126992300bf3207eab9764 \
    --hash=sha256:7f047e29dcae44602496db43be01ad42fc6f1cc0d8cd6c83d342306c32270196 \
    --hash=sha256:8098f252adfa6c80ab48096053f512f2321f0b998f98150cea9bd23d83e1467b \
    --hash=sha256:850774a7879607d3a6f50d36d04f00ee69e7fc816450e5f7e58d7f17f1ae5c00 \
    --hash=sha256:8d1fab6bb153a416f9aeb4b8763bc0f22a5586065f86f7664fc23339fc1c1fac \
    --hash=sha256:8da9669d359f02c0b91ccc01cac4a67f16afec0dac22c2ad09f46bee0697eba8 \
    --hash=sha256:8dc52c23056b9ddd46818a57b78404882310fb473d63f17b07d5c40421e47f8e \
    --hash=sha256:9149cad251584d5fb4981be1ecde53a1ca46c891a79788c0df828d2f166bda28 \
    --hash=sha256:93dda82c9c22deb0a405ea4dc5f2d0cda384168e466364dec6255b293923b2f3 \
    --hash=sha256:96b533f0e99f6579b3d4d4995707cf36df9100d67e0c8303a0c55b27b5f99bc5 \
    --hash=sha256:9c57bb8c96f6d1808c030b1687b9b5fb476abaa47f0db9c0101f5e9f394e97f4 \
    --hash=sha256:9c7708761fccb9397fe64bbc0395abcae8c4bf7b0eac081e12b809bf47700d0b \
    --hash=sha256:9f3bfb4965eb874431221a3ff3fdcddc7e74e3b07799e0e84ca4a0f867d449bf \
    --hash=sha256:a33284e20b78bd4a18c8c2282d549d10bc8408a2a7ff57653c0cf0b9be0afce5 \
    --hash=sha256:a80cb027f6b349846a3bf6d73b5e95e782175e52f22108cfa17876aaeff93702 \
    --hash=sha256:b30236e45cf30d2b8e7b3e85881719e98507abed1011bf463a8fa23e9c3e98a8 \
    --hash=sha256:b3bc83488de33889877a0f2543ade9f70c67d66d9ebb4ac959502e12de895788 \
    --hash=sha256:b865addae83924361678b652338317d1bd7e79b1f4596f96b96c77a5a34b34da \
    --hash=sha256:b8bb0864c5a28024fac8a632c443c87c5aa6f215c0b126c449ae1a150412f31d \
    --hash=sha256:ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc \
    --hash=sha256:bdb2c67c6c1390b63c6ff89f210c8fd09d9a1217a465701eac7316313c915e4c \
    --hash=sha256:c1ff362665ae507275af2853520967820d9124984e0f7466736aea23d8611fba \
    --hash=sha256:c2514fceb77bc5e7a2f7adfaa1feb2fb311607c9cb518dbc378688ec73d8292f \
    --hash=sha256:c3355370a2c156cffb25e876646f149d5d68f5e0a3ce86a5084dd0b64a994917 \
    --hash=sha256:c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5 \
    --hash=sha256:d0eae10f8159e8fdad514efdc92d74fd8d682c933a6dd088030f3834bc8e6b26 \
    --hash=sha256:d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f \
    --hash=sha256:ebc55a14a21cb14062aa4162f906cd962b28e2e9ea38f9b4391244cd8de4ae0b \
    --hash=sha256:eda16858a3cab07b80edaf74336ece1f986ba330fdb8ee0d6c0d68fe82bc96be \
    --hash=sha256:ee2922902c45ae8ccada2c5b501ab86c36525b883eff4255313a253a3160861c \
    --hash=sha256:efd7b85f94a6f21e4932043973a7ba2613b059c4a000551892ac9f1d11f5baf3 \
    --hash=sha256:f7057c9a337546edc7973c0d3ba84ddcdf0daa14533c2065749c9075001090e6 \
    --hash=sha256:fa160448684b4e94d80416c0fa4aac48967a969efe22931448d853ada8baf926 \
    --hash=sha256:fc09d0aa354569bc501d4e787133afc08552722d3ab34836a80547331bb5d4a0
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
# The installer does not "sync" the package from the server: it comes from an
# explicit --bundle-url, or it is already staged in the install directory.
# Later updates install the signed bundle the API publishes, verified against
# the key pinned in the package installed here (scripts/update-agent.sh,
# agent/update.py, #363) -- this script is the one that put that key on the
# host, so it cannot also be the one fetching from the API. Anything else is a failed
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
    # After a bundle update, agent is a symlink into releases/ (#363). Extract
    # a plain directory in its place rather than through the link into a
    # release the updater keeps for rollback; BusyBox tar would follow it.
    if [[ -L "${INSTALL_DIR}/agent" ]]; then
        rm -f "${INSTALL_DIR}/agent"
    fi
    tar -xzf "${INSTALL_DIR}/bundle.tar.gz" -C "${INSTALL_DIR}"
    rm -f "${INSTALL_DIR}/bundle.tar.gz"
elif [[ -d "${INSTALL_DIR}/agent" ]]; then
    log "Using the agent package already staged in ${INSTALL_DIR}."
else
    error "No agent package available.
  The installer does not fetch one from the API, so a native install needs either:
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
log "the host has no self-update mechanism, so upgrades are a reinstall,"
log "which keeps this agent ID."
log "================================================================="
