#!/usr/bin/env bash
# Install the Pulse CLI for the Shapoclyack service_probe backend.
#
# This is the single implementation of "get the pinned Pulse release onto a
# machine": the pulse-bin stage of Dockerfile / Dockerfile.allinone runs this
# same script, so a change here reaches host installs and images alike.
#
# Default: the GenDec GitHub Release tarball for this platform, checked
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
# No `set -x` anywhere in here on purpose: the token would be traced.
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
  mkdir -p "$(dirname "$DEST")"
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

if [[ -n "$TOKEN" ]] && ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "a private release needs jq or python3 to read the GitHub API response; install one" >&2
  exit 1
fi

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

# Exit code for "not on the release" -- the only case where skipping the
# checksum is a sane answer -- as opposed to a download that merely failed
# and should be retried. Decided on the HTTP status, not curl's exit code:
# with -f curl reports a 404 as 22 over HTTP/1.1 but as 56 over HTTP/2.
readonly RC_NO_ASSET=44

http_get() {  # http_get <url> <dest> [curl header args...]
  local url="$1" dest="$2" code
  shift 2
  code="$(curl -sSL "$@" -o "$dest" -w '%{http_code}' "$url")" || return 1
  case "$code" in
    2??) return 0 ;;
    404) rm -f "$dest"; return "$RC_NO_ASSET" ;;
    *) echo "HTTP ${code} from ${url}" >&2; rm -f "$dest"; return 1 ;;
  esac
}

release_json=""
fetch_asset() {  # fetch_asset <asset name> <dest path>
  local asset_name="$1" dest="$2" asset_url rc=0
  if [[ -n "$TOKEN" ]]; then
    # Private repos: releases/download/<tag>/<name> answers 404 even with a
    # valid token (that path only serves public repos and browser sessions).
    # Resolve the numeric asset id through the API, then fetch the asset
    # endpoint with Accept: application/octet-stream.
    if [[ -z "$release_json" ]]; then
      http_get "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}" "${tmp}/release.json" \
        -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/vnd.github+json" || rc=$?
      if [[ "$rc" == "$RC_NO_ASSET" ]]; then
        echo "no release ${VERSION} in ${REPO} (or the token cannot see it)" >&2
        return "$RC_NO_ASSET"
      elif [[ "$rc" != 0 ]]; then
        return "$rc"
      fi
      release_json="$(cat "${tmp}/release.json")"
    fi
    asset_url="$(printf '%s' "$release_json" | asset_api_url "$asset_name")"
    if [[ -z "$asset_url" || "$asset_url" == "null" ]]; then
      echo "release ${VERSION} of ${REPO} has no asset named ${asset_name}" >&2
      return "$RC_NO_ASSET"
    fi
    echo "==> downloading ${asset_name} (private release, via API)"
    http_get "$asset_url" "$dest" \
      -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/octet-stream"
  else
    local url="https://github.com/${REPO}/releases/download/${VERSION}/${asset_name}"
    echo "==> downloading ${url}"
    # The public path cannot tell a missing asset from a missing release (or a
    # private one without a token); a 404 is "no asset" either way.
    http_get "$url" "$dest"
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

# checksums.txt first: it is a few hundred bytes and decides whether the
# multi-MB tarball is worth downloading at all.
if [[ "${PULSE_SKIP_CHECKSUM:-0}" == "1" ]]; then
  echo "==> WARNING: PULSE_SKIP_CHECKSUM=1, installing an unverified tarball" >&2
else
  rc=0
  fetch_asset "checksums.txt" "${tmp}/checksums.txt" || rc=$?
  if [[ "$rc" == "$RC_NO_ASSET" ]]; then
    echo "release ${VERSION} ships no checksums.txt (or is not reachable: check PULSE_VERSION and GITHUB_TOKEN/GH_TOKEN); refusing to install an unverified binary. PULSE_SKIP_CHECKSUM=1 overrides, only for a release you have checked by hand" >&2
    exit 1
  elif [[ "$rc" != 0 ]]; then
    echo "downloading checksums.txt failed (curl exit ${rc}); this is a network/API error, not a missing file -- retry, do not skip the checksum" >&2
    exit 1
  fi
fi

rc=0
fetch_asset "$name" "${tmp}/${name}" || rc=$?
if [[ "$rc" == "$RC_NO_ASSET" ]]; then
  echo "no ${name} on release ${VERSION}; check PULSE_VERSION and, for the private repo, GITHUB_TOKEN/GH_TOKEN; or build with PULSE_FROM_SOURCE=1" >&2
  exit 1
elif [[ "$rc" != 0 ]]; then
  echo "downloading ${name} failed (curl exit ${rc}); retry" >&2
  exit 1
fi

if [[ "${PULSE_SKIP_CHECKSUM:-0}" != "1" ]]; then
  verify_checksum "${tmp}/${name}" "${tmp}/checksums.txt"
fi

tar -xzf "${tmp}/${name}" -C "$tmp"
install_bin "${tmp}/pulse"
