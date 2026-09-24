#!/usr/bin/env bash
# Install the Pulse CLI for the Shapoclyack service_probe backend.
#
# This is the single implementation of "get the pinned Pulse release onto a
# machine": the pulse-bin stage of Dockerfile / Dockerfile.allinone runs this
# same script, so a change here reaches host installs and images alike.
#
# Default: the GenDec GitHub Release tarball for this platform, checked
# against the digest pinned for it below (no cargo required).
#   scripts/install-pulse.sh
#   PULSE_VERSION=v1.1.0 scripts/install-pulse.sh
#   GITHUB_TOKEN=… scripts/install-pulse.sh      # private GenDec (GH_TOKEN also works)
#   PULSE_DEST=$HOME/.local/bin/pulse scripts/install-pulse.sh
#   PULSE_SKIP_CHECKSUM=1 scripts/install-pulse.sh  # only for an UNPINNED release
#
# Integrity comes from scripts/pulse-pinned.sha256: a digest committed in this
# repository and reviewed here, not fetched from the release being installed.
# When the version is pinned there, the tarball is checked against that value
# and PULSE_SKIP_CHECKSUM cannot turn the check off. A version with no pin (a
# one-off tag someone is trying out) falls back to the release's own
# checksums.txt, which is the weaker, download-integrity-only check.
#   PULSE_PINS=/path/to/pins scripts/install-pulse.sh  # override the pin file
#
# The images also ask for an install record (#340), which names the tarball,
# the check it passed and the digest of the binary that came out of it:
#   PULSE_RECORD=/usr/local/share/shapoclyack/pulse-install.txt scripts/install-pulse.sh
# scripts/verify-pulse-image.py reads it back out of a published image.
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
# Ships next to this script; the image stage copies both into the same dir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PINS="${PULSE_PINS:-${SCRIPT_DIR}/pulse-pinned.sha256}"
# "" writes no record, which is what a host install gets unless it asks.
RECORD="${PULSE_RECORD:-}"

# Shared with scripts/pulse-pin.sh: resolving an asset on a private release is
# fiddly enough (API indirection, 404-vs-error) that two copies would drift.
# Sourced this early because the source-build path below needs sha256_of for
# its install record too; the helpers read REPO/VERSION/TOKEN/tmp when called.
# shellcheck source=scripts/pulse-release-lib.sh
. "${SCRIPT_DIR}/pulse-release-lib.sh"

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

# The image keeps the binary, not the tarball, and the tarball's digest is the
# only one scripts/pulse-pinned.sha256 holds. This record is what ties the two
# together afterwards: which tarball, which check it passed, and what the
# installed binary hashes to. It is written by the same build it describes, so
# on its own it proves the image was not altered after that build, not that the
# build was honest -- scripts/verify-pulse-image.py --tarball is the check that
# does not rest on it.
write_record() {  # write_record <verified: pin|checksums|none|source> [<tarball> <sha256>]
  [[ -n "$RECORD" ]] || return 0
  mkdir -p "$(dirname "$RECORD")"
  {
    echo "# Pulse install record, written by scripts/install-pulse.sh (#340)."
    echo "# Checked by scripts/verify-pulse-image.py; see docs/release-contract.md."
    printf 'version=%s\n' "$VERSION"
    printf 'platform=%s\n' "${asset:-}"
    printf 'verified=%s\n' "$1"
    printf 'tarball=%s\n' "${2:-}"
    printf 'tarball_sha256=%s\n' "${3:-}"
    printf 'binary_sha256=%s\n' "$(sha256_of "$DEST")"
  } > "$RECORD"
  echo "==> install record: $RECORD"
}

if [[ -n "$LOCAL_REPO" || "$FROM_SOURCE" == "1" ]]; then
  if [[ -n "$LOCAL_REPO" ]]; then
    echo "==> building Pulse from $LOCAL_REPO"
    (cd "$LOCAL_REPO" && cargo build --release)
    install_bin "$LOCAL_REPO/target/release/pulse"
    write_record source
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
  write_record source
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

# The sha256 this repository pins for <version, platform>, or "" when the
# version is not pinned here. Comments and blank lines are skipped; the file is
# read with awk so a stray CR or extra whitespace cannot produce a partial hash
# that then fails to match for the wrong reason.
pinned_sha() {  # pinned_sha <version> <platform>
  [[ -r "$PINS" ]] || return 0
  awk -v v="$1" -v p="$2" '
    { sub(/\r$/, "") }
    /^[[:space:]]*(#|$)/ { next }
    $1 == v && $2 == p { print tolower($3); exit }
  ' "$PINS"
}

verify_pin() {  # verify_pin <file> <expected sha256>
  local actual
  actual="$(sha256_of "$1")"
  if [[ "$2" != "$actual" ]]; then
    echo "sha256 mismatch for $(basename "$1"): ${PINS} pins $2, the downloaded file is ${actual}." >&2
    echo "This is not a corrupted download to retry -- the bytes on the release are not the bytes this repository was reviewed against. Do not install it; check the release and the pin file." >&2
    return 1
  fi
  echo "==> sha256 verified against pinned digest in $(basename "$PINS"): $(basename "$1")"
}

PIN="$(pinned_sha "$VERSION" "$asset")"

if [[ -n "$PIN" ]]; then
  # Pinned: the digest comes from this repository, so the release's own
  # checksums.txt adds nothing and is not downloaded.
  if [[ "${PULSE_SKIP_CHECKSUM:-0}" == "1" ]]; then
    echo "==> PULSE_SKIP_CHECKSUM=1 ignored: ${VERSION} ${asset} is pinned in ${PINS} and that check is not optional" >&2
  fi
  echo "==> ${VERSION} ${asset} is pinned in $(basename "$PINS")"
else
  echo "==> WARNING: ${VERSION} ${asset} is not pinned in ${PINS}; falling back to the release's own checksums.txt, which only proves the download was not corrupted. Pin the version there before using it in a build you ship." >&2
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

if [[ -n "$PIN" ]]; then
  verify_pin "${tmp}/${name}" "$PIN"
  verified=pin
elif [[ "${PULSE_SKIP_CHECKSUM:-0}" != "1" ]]; then
  verify_checksum "${tmp}/${name}" "${tmp}/checksums.txt"
  verified=checksums
else
  verified=none
fi

tar -xzf "${tmp}/${name}" -C "$tmp"
install_bin "${tmp}/pulse"
write_record "$verified" "$name" "$(sha256_of "${tmp}/${name}")"
