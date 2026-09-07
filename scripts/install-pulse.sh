#!/usr/bin/env bash
# Install the Pulse CLI for the Shapoclyack service_probe backend.
#
# Default: the GenDec GitHub Release tarball for this platform, verified
# against the release's checksums.txt (no cargo required).
#   scripts/install-pulse.sh
#   PULSE_VERSION=v1.1.0 scripts/install-pulse.sh
#   GITHUB_TOKEN=… scripts/install-pulse.sh      # private GenDec (GH_TOKEN also works)
#   PULSE_DEST=$HOME/.local/bin/pulse scripts/install-pulse.sh
#   PULSE_SKIP_CHECKSUM=1 scripts/install-pulse.sh  # only for a release without checksums.txt
#
# Fallback: build from a local clone or from git.
#   PULSE_REPO=/path/to/GenDec scripts/install-pulse.sh
#   PULSE_FROM_SOURCE=1 [PULSE_REF=main] scripts/install-pulse.sh
#
# Keep the download logic in step with the pulse-bin stage of Dockerfile /
# Dockerfile.allinone: same asset names, same private-release dance, same
# checksum file.
set -euo pipefail

DEST="${PULSE_DEST:-/usr/local/bin/pulse}"
VERSION="${PULSE_VERSION:-v1.1.0}"
REPO="${PULSE_GITHUB_REPO:-onixus/GenDec}"
FROM_SOURCE="${PULSE_FROM_SOURCE:-0}"
LOCAL_REPO="${PULSE_REPO:-}"
REPO_URL="${PULSE_GIT_URL:-https://github.com/${REPO}.git}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

install_bin() {
  local bin="$1"
  install -m 0755 "$bin" "$DEST"
  echo "==> installed $DEST ($("$DEST" --version 2>/dev/null || echo ok))"
  echo "    set OCTO_SERVICE_BACKEND=pulse  or  service_probe.backend: pulse"
  if command -v setcap >/dev/null 2>&1 && [[ "$(uname -s)" == "Linux" ]]; then
    # Same file capabilities the images set: needed for --syn and --os.
    # Without them pulse still works in connect mode; the scanner drops --os.
    echo "    optional: sudo setcap cap_net_raw,cap_net_admin+eip $DEST"
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
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Print the API url of a named asset from a release JSON document on stdin.
asset_api_url() {
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg name "$1" '.assets[] | select(.name == $name) | .url'
  else
    python3 -c '
import json, sys
name = sys.argv[1]
print(next((a["url"] for a in json.load(sys.stdin).get("assets", []) if a.get("name") == name), ""))
' "$1"
  fi
}

release_json=""
fetch_asset() {  # fetch_asset <asset name> <dest path>
  local asset_name="$1" dest="$2" asset_url
  if [[ -n "$TOKEN" ]]; then
    # Private repos: releases/download/<tag>/<name> answers 404 even with a
    # valid token (that path only serves public repos and browser sessions).
    # Resolve the numeric asset id through the API, then fetch the asset
    # endpoint with Accept: application/octet-stream.
    if [[ -z "$release_json" ]]; then
      release_json="$(curl -fsSL -H "Authorization: Bearer ${TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}")" || return 1
    fi
    asset_url="$(printf '%s' "$release_json" | asset_api_url "$asset_name")"
    if [[ -z "$asset_url" ]]; then
      echo "release ${VERSION} of ${REPO} has no asset named ${asset_name}" >&2
      return 1
    fi
    echo "==> downloading ${asset_name} (private release, via API)"
    curl -fsSL -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/octet-stream" \
      -o "$dest" "$asset_url"
  else
    local url="https://github.com/${REPO}/releases/download/${VERSION}/${asset_name}"
    echo "==> downloading ${url}"
    curl -fsSL -o "$dest" "$url"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# checksums.txt lines look like "<sha256>  dist/<asset>" (the release job hashes
# from its dist/ directory); match on the basename so either form works.
verify_checksum() {  # verify_checksum <file> <checksums.txt>
  local base expected actual
  base="$(basename "$1")"
  expected="$(awk -v n="$base" '{ f = $2; sub(/^\*/, "", f); sub(/.*\//, "", f); if (f == n) { print $1; exit } }' "$2")"
  if [[ -z "$expected" ]]; then
    echo "checksums.txt on release ${VERSION} has no entry for ${base}" >&2
    return 1
  fi
  actual="$(sha256_of "$1")"
  if [[ "$expected" != "$actual" ]]; then
    echo "sha256 mismatch for ${base}: release says ${expected}, downloaded file is ${actual}" >&2
    return 1
  fi
  echo "==> sha256 verified: ${base}"
}

if ! fetch_asset "$name" "${tmp}/${name}"; then
  echo "release download failed; check PULSE_VERSION (${VERSION}) and, for the private repo, GITHUB_TOKEN/GH_TOKEN; or build with PULSE_FROM_SOURCE=1" >&2
  exit 1
fi

if [[ "${PULSE_SKIP_CHECKSUM:-0}" == "1" ]]; then
  echo "==> WARNING: PULSE_SKIP_CHECKSUM=1, installing an unverified tarball" >&2
else
  if ! fetch_asset "checksums.txt" "${tmp}/checksums.txt"; then
    echo "release ${VERSION} has no checksums.txt; refusing to install an unverified binary (PULSE_SKIP_CHECKSUM=1 overrides)" >&2
    exit 1
  fi
  verify_checksum "${tmp}/${name}" "${tmp}/checksums.txt"
fi

tar -xzf "${tmp}/${name}" -C "$tmp"
test -x "${tmp}/pulse" || chmod 755 "${tmp}/pulse"
install_bin "${tmp}/pulse"
