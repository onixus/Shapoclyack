#!/usr/bin/env bash
# Produce the lines for scripts/pulse-pinned.sha256 for a GenDec release, after
# verifying that the release was actually produced by GenDec's release workflow.
#
#   GITHUB_TOKEN=… scripts/pulse-pin.sh v1.2.0
#
# This is the one place a signature belongs. At install time the check is the
# pin itself -- a value committed in this repository and reviewed in a pull
# request, which is strictly stronger than anything fetched from the release
# being installed. What a signature adds is trust in the moment a *new* digest
# enters the repository, which is exactly here.
#
# What it proves: checksums.txt was signed by GenDec's release.yml running on
# this tag. What it does not prove: that what went into that release was
# reviewed. It closes "the assets on the release were swapped", not "a bad
# commit was merged".
#
# Releases up to and including v1.1.0 predate signing and have no bundle. Pin
# one of those with PULSE_PIN_ALLOW_UNSIGNED=1, knowing the digest you commit
# rests on nothing but the download.
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: $(basename "$0") <release tag, e.g. v1.2.0>" >&2
  exit 2
fi
VERSION="v${VERSION#v}"

REPO="${PULSE_GITHUB_REPO:-onixus/GenDec}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Pinned to the workflow AND the tag: cosign accepts a signature from anyone
# unless the identity is constrained, which would make this worth nothing.
IDENTITY="${PULSE_SIGNER_IDENTITY:-https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}}"
OIDC_ISSUER="${PULSE_SIGNER_ISSUER:-https://token.actions.githubusercontent.com}"
PLATFORMS=(linux-amd64 linux-arm64 darwin-amd64 darwin-arm64)

# stdout is the pin block and nothing else, so it can be piped or pasted
# straight in; every progress line below goes to stderr.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# shellcheck source=scripts/pulse-release-lib.sh
. "${SCRIPT_DIR}/pulse-release-lib.sh"

rc=0
fetch_asset "checksums.txt" "${tmp}/checksums.txt" >&2 || rc=$?
if [[ "$rc" != 0 ]]; then
  echo "could not fetch checksums.txt for ${VERSION} from ${REPO} (check the tag and GITHUB_TOKEN/GH_TOKEN)" >&2
  exit 1
fi

rc=0
fetch_asset "checksums.txt.cosign.bundle" "${tmp}/bundle" >&2 || rc=$?
if [[ "$rc" == "$RC_NO_ASSET" ]]; then
  if [[ "${PULSE_PIN_ALLOW_UNSIGNED:-0}" != "1" ]]; then
    echo "release ${VERSION} ships no checksums.txt.cosign.bundle, so there is nothing to verify and these digests would rest on the download alone." >&2
    echo "Releases up to v1.1.0 predate signing; to pin one anyway, re-run with PULSE_PIN_ALLOW_UNSIGNED=1." >&2
    exit 1
  fi
  echo "==> WARNING: ${VERSION} is unsigned and PULSE_PIN_ALLOW_UNSIGNED=1; the digests below are only as good as this download" >&2
elif [[ "$rc" != 0 ]]; then
  echo "downloading the signature bundle failed (curl exit ${rc}); this is a network/API error -- retry, do not pin unverified digests" >&2
  exit 1
else
  if ! command -v cosign >/dev/null 2>&1; then
    echo "release ${VERSION} is signed but cosign is not installed, so the signature cannot be checked: https://docs.sigstore.dev/cosign/installation/" >&2
    exit 1
  fi
  echo "==> verifying checksums.txt against ${IDENTITY}" >&2
  cosign verify-blob \
    --bundle "${tmp}/bundle" \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "${tmp}/checksums.txt" >&2
fi

# checksums.txt entries may carry a dist/ prefix (the per-job sidecars hash from
# their dist/ directory); match on the basename, as install-pulse.sh does.
echo >&2
echo "==> paste into scripts/pulse-pinned.sha256, replacing the previous version's lines:" >&2
for platform in "${PLATFORMS[@]}"; do
  name="pulse-${VERSION}-${platform}.tar.gz"
  sha="$(awk -v n="$name" '{ f = $2; sub(/^\*/, "", f); sub(/.*\//, "", f); if (f == n) { print $1; exit } }' "${tmp}/checksums.txt")"
  if [[ -z "$sha" ]]; then
    echo "checksums.txt on ${VERSION} has no entry for ${name}; the release is incomplete and must not be pinned" >&2
    exit 1
  fi
  printf '%s  %-13s %s\n' "$VERSION" "$platform" "$sha"
done
