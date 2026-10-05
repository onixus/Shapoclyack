#!/usr/bin/env bash
#
# build-sensor-bundle.sh: build the sensor bundle and sign its manifest with
# the release key (#363).
#
# The bundle is what `python -m agent.update` installs on a native sensor:
# the `agent` package as a reproducible tarball, and sensor-bundle.json naming
# its version, sha256 and size (scripts/sensor_bundle.py). The manifest is
# what gets signed -- not the tarball -- because the version has to be covered
# by the signature: a sensor refuses a downgrade by the signed version, and a
# signature over the bytes alone would let a server relabel an old release as
# a new one.
#
# Signed with `cosign sign-blob` and the same key that signs the release
# images (COSIGN_PRIVATE_KEY in Jenkins, cosign.pub in the repository), so one
# key, one rotation procedure, one public half customers already hold. The
# sensor pins that public half in agent/update.py and verifies offline, which
# is why the signature is not uploaded to Rekor (--tlog-upload=false): nothing
# on a sensor would look there. Then the signature is verified with --pubkey,
# as sign-release-image.sh does for images, which catches a pipeline
# credential that is not the key the sensors pin.
#
# Usage:
#   build-sensor-bundle.sh [--source DIR [--whole-tree]] [--out DIR] [--revision SHA] [--key REF --pubkey FILE]
#
#   --source DIR   the agent package to bundle (default: agent/ next to this script).
#                  Only the files git tracks in it go in: a working copy also
#                  holds what was never committed (an .env, editor leftovers)
#   --whole-tree   every file under --source instead, for a source that is
#                  not a git checkout
#   --out DIR      where the archive, manifest and signature go (default dist/sensor-bundle)
#   --revision SHA source revision recorded in the manifest
#   --key REF      cosign key file (password in COSIGN_PASSWORD) or KMS URI.
#                  Without it the bundle is built unsigned, and no sensor will
#                  install it -- what a DRY_RUN of the publish job does.
#   --pubkey FILE  the public half to verify the signature with (cosign.pub)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="${SCRIPT_DIR}/../agent"
out="dist/sensor-bundle"
revision=""
key=""
pubkey=""
whole_tree=""

die() {
  echo "[sensor-bundle] $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) source_dir="${2:?--source needs a value}"; shift 2 ;;
    --out) out="${2:?--out needs a value}"; shift 2 ;;
    --revision) revision="${2:?--revision needs a value}"; shift 2 ;;
    --key) key="${2:?--key needs a value}"; shift 2 ;;
    --pubkey) pubkey="${2:?--pubkey needs a value}"; shift 2 ;;
    --whole-tree) whole_tree="--whole-tree"; shift ;;
    *) die "unknown argument $1" ;;
  esac
done

[[ -z "${key}" || -n "${pubkey}" ]] || die "--key needs --pubkey"

# A stale signature next to a fresh manifest would read as signed.
rm -f "${out}/sensor-bundle.json.sig"
python3 "${SCRIPT_DIR}/sensor_bundle.py" build --source "${source_dir}" --out "${out}" \
  ${revision:+--revision "${revision}"} ${whole_tree:+"${whole_tree}"}

if [[ -z "${key}" ]]; then
  echo "[sensor-bundle] built ${out} UNSIGNED: no sensor will install it"
  exit 0
fi

[[ -s "${pubkey}" ]] || die "public key ${pubkey} is missing or empty"
command -v cosign >/dev/null 2>&1 || die "cosign not found; scripts/install-cosign.sh installs the pinned one"
pinned="$(sed -n 's/^COSIGN_VERSION="\(v[0-9.]*\)"$/\1/p' "${SCRIPT_DIR}/install-cosign.sh")"
running="$(cosign version --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["gitVersion"])')" \
  || die "could not read the cosign version"
[[ -n "${pinned}" && "${running}" == "${pinned}" ]] \
  || die "cosign ${running} is not the pinned ${pinned} (scripts/install-cosign.sh)"

# --use-signing-config/--new-bundle-format spelled out: cosign 3 defaults both
# to a Sigstore bundle, which is not the bare signature the sensor reads.
cosign sign-blob --yes --key "${key}" --tlog-upload=false \
  --use-signing-config=false --new-bundle-format=false \
  --output-signature "${out}/sensor-bundle.json.sig" "${out}/sensor-bundle.json"
cosign verify-blob --key "${pubkey}" --insecure-ignore-tlog \
  --signature "${out}/sensor-bundle.json.sig" "${out}/sensor-bundle.json" \
  || die "the bundle signature does not verify against ${pubkey}: sensors pinning it would refuse this bundle"
chmod 0644 "${out}/sensor-bundle.json.sig"
echo "[sensor-bundle] built and signed ${out}"
