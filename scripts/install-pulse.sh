#!/usr/bin/env bash
# Install Pulse CLI for Shapoclyack service_probe backend.
#
# Preferred: GitHub Release from GenDec (no cargo required).
#   PULSE_VERSION=v0.2.6 scripts/install-pulse.sh
#   GITHUB_TOKEN=... scripts/install-pulse.sh   # private GenDec
#
# Fallback: build from local clone or git URL.
#   PULSE_REPO=/path/to/GenDec scripts/install-pulse.sh
#   PULSE_FROM_SOURCE=1 scripts/install-pulse.sh
set -euo pipefail

DEST="${PULSE_DEST:-/usr/local/bin/pulse}"
VERSION="${PULSE_VERSION:-v0.2.6}"
REPO="${PULSE_GITHUB_REPO:-onixus/GenDec}"
FROM_SOURCE="${PULSE_FROM_SOURCE:-0}"
LOCAL_REPO="${PULSE_REPO:-}"
REPO_URL="${PULSE_GIT_URL:-https://github.com/${REPO}.git}"

install_bin() {
  local bin="$1"
  install -m 0755 "$bin" "$DEST"
  echo "==> installed $DEST ($("$DEST" --version 2>/dev/null || echo ok))"
  echo "    set OCTO_SERVICE_BACKEND=pulse  or  service_probe.backend: pulse"
  if command -v setcap >/dev/null 2>&1 && [[ "$(uname -s)" == "Linux" ]]; then
    echo "    optional: sudo setcap cap_net_raw,cap_net_admin+ep $DEST"
  fi
}

if [[ -n "$LOCAL_REPO" || "$FROM_SOURCE" == "1" ]]; then
  if [[ -n "$LOCAL_REPO" ]]; then
    echo "==> building Pulse from $LOCAL_REPO"
    (cd "$LOCAL_REPO" && cargo build --release)
    install_bin "$LOCAL_REPO/target/release/pulse"
    exit 0
  fi
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  REF="${PULSE_REF:-${VERSION}}"
  echo "==> cloning $REPO_URL @ $REF"
  git clone --depth 1 --branch "$REF" "$REPO_URL" "$TMP/pulse" 2>/dev/null \
    || git clone --depth 1 "$REPO_URL" "$TMP/pulse"
  (cd "$TMP/pulse" && cargo build --release)
  install_bin "$TMP/pulse/target/release/pulse"
  exit 0
fi

# --- release tarball (default) ---
VERSION="v${VERSION#v}"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
machine="$(uname -m)"
case "${os}-${machine}" in
  linux-x86_64|linux-amd64) asset="linux-amd64" ;;
  linux-aarch64|linux-arm64) asset="linux-arm64" ;;
  darwin-arm64) asset="darwin-arm64" ;;
  darwin-x86_64) asset="darwin-amd64" ;;
  *)
    echo "unsupported platform ${os}-${machine}; set PULSE_FROM_SOURCE=1" >&2
    exit 1
    ;;
esac

name="pulse-${VERSION}-${asset}.tar.gz"
url="https://github.com/${REPO}/releases/download/${VERSION}/${name}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "==> downloading ${url}"
auth=()
if [[ -n "${GITHUB_TOKEN:-${GH_TOKEN:-}}" ]]; then
  auth=(-H "Authorization: Bearer ${GITHUB_TOKEN:-${GH_TOKEN}}")
fi
if ! curl -fsSL "${auth[@]}" -o "${tmp}/${name}" "$url"; then
  echo "release download failed; try PULSE_FROM_SOURCE=1 or check PULSE_VERSION / token" >&2
  exit 1
fi
tar -xzf "${tmp}/${name}" -C "$tmp"
install_bin "${tmp}/pulse"
