#!/usr/bin/env bash
#
# install-cosign.sh: put the reviewed cosign binary into a directory (#313).
#
# The release pipelines sign Shapoclyack images with cosign, so the cosign they
# run is as much a part of the release as the key: a swapped binary could sign
# something other than the digest it was handed. The version and the sha256 of
# each platform's binary are committed here and reviewed, the same way
# scripts/pulse-pinned.sha256 pins Pulse; nothing fetched alongside the binary
# is trusted to vouch for it. The digests were taken from the release's
# cosign_checksums.txt after checking its signature (Sigstore keyless,
# keyless@projectsigstore.iam.gserviceaccount.com).
#
# Pinned to the 2.x line on purpose. cosign 3 writes signatures in the new
# bundle format as OCI referrers by default; Kyverno's `type: Cosign` and the
# Sigstore policy-controller examples in k8s/shapoclyack/examples/ read the
# classic `sha256-<digest>.sig` / `.att` layout that 2.x writes. Moving to 3.x
# is a decision about what customers' admission controllers can verify, not a
# routine bump.
#
# Usage: scripts/install-cosign.sh DEST_DIR     -> DEST_DIR/cosign
# An existing DEST_DIR/cosign with the pinned digest is kept, so a pipeline can
# call this on every run without downloading every time.
set -euo pipefail

COSIGN_VERSION="v2.6.5"

DEST_DIR="${1:-}"
if [[ -z "${DEST_DIR}" || $# -ne 1 ]]; then
  echo "Usage: $0 DEST_DIR" >&2
  exit 2
fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
machine="$(uname -m)"
case "${os}-${machine}" in
  linux-x86_64|linux-amd64) asset="cosign-linux-amd64"
    want="c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644" ;;
  linux-aarch64|linux-arm64) asset="cosign-linux-arm64"
    want="426193b4c5da4d4d643e822f48fe0cc8a476ca1782a272704831f5a0cef716d7" ;;
  darwin-arm64) asset="cosign-darwin-arm64"
    want="4d41cc18f0563907c0c785b51db76e1d1af10db4422b605ba876b1758e1771ab" ;;
  darwin-x86_64) asset="cosign-darwin-amd64"
    want="0f8a1a70c81de9740a2b62e91307ff396ce54e7dd80568d42411bb2d9d44269c" ;;
  *)
    echo "[cosign] no pinned ${COSIGN_VERSION} binary for ${os}-${machine}" >&2
    exit 1 ;;
esac

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

dest="${DEST_DIR}/cosign"
if [[ -f "${dest}" && "$(sha256_of "${dest}")" == "${want}" ]]; then
  echo "[cosign] ${dest} is already ${COSIGN_VERSION} (${asset})"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
url="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/${asset}"
echo "[cosign] downloading ${url}"
curl -fsSL --retry 3 -o "${tmp}/cosign" "${url}"

got="$(sha256_of "${tmp}/cosign")"
if [[ "${got}" != "${want}" ]]; then
  echo "[cosign] sha256 mismatch for ${asset} ${COSIGN_VERSION}:" >&2
  echo "[cosign]   expected ${want}" >&2
  echo "[cosign]   got      ${got}" >&2
  echo "[cosign] refusing to install a binary that is not the one pinned here." >&2
  exit 1
fi

mkdir -p "${DEST_DIR}"
install -m 0755 "${tmp}/cosign" "${dest}"
echo "[cosign] installed ${dest} (${COSIGN_VERSION}, sha256 ${got})"
