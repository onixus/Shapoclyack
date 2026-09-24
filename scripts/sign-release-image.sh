#!/usr/bin/env bash
#
# sign-release-image.sh: sign a pushed release image by digest, attest its
# build provenance, verify both, and only then give it its tags (#313).
#
# Both publishers call this: Jenkinsfile.publish, the release path, with the
# release key; .github/workflows/docker-publish.yml keylessly, with that
# workflow's GitHub OIDC identity. What "a signed Shapoclyack image" means is
# written down once, here. The customer's side — verification commands and
# admission policies — is docs/supply-chain.md.
#
# The order is the point. The pipeline pushes the image by digest with no
# tag, so nobody pulls it by name yet. This script signs that digest (never a
# tag: a tag can be moved after signing, a digest cannot), attests the SLSA
# provenance BuildKit recorded for it, verifies both with exactly the identity
# a customer will use, and only then points the release tags at it. Anything
# failing on the way leaves an untagged, unsigned digest in the registry and a
# red build — never a tag on an image that is not signed.
#
# The signature covers more than the image: BuildKit writes its SBOM and
# provenance into the same image index, and the index digest is a hash over
# them, so the signed digest pins those in-index attestations as well. The
# provenance is attested separately so admission controllers, which only read
# cosign attestations, can require it.
#
# Usage:
#   sign-release-image.sh --key REF --pubkey FILE [options] IMAGE@sha256:DIGEST
#   sign-release-image.sh --keyless --identity URI --issuer URL [options] IMAGE@sha256:DIGEST
#   sign-release-image.sh --check-key --key REF --pubkey FILE
#
#   --key REF        a cosign key file (password in COSIGN_PASSWORD) or KMS URI
#   --pubkey FILE    the public half customers verify with (cosign.pub). The
#                    signature is checked against it, not against the private
#                    key, which is what catches a pipeline credential that is
#                    not the key this repository publishes.
#   --keyless        Fulcio certificate from the ambient OIDC token (GitHub
#                    Actions with id-token: write)
#   --identity URI   the certificate identity to verify, e.g. the workflow ref
#   --issuer URL     the OIDC issuer to verify
#   --release TAG    signed as the annotation release=TAG and required on verify,
#                    so the signature says which release this digest is
#   --tag REF        tag to point at the digest once verified (repeatable)
#   --check-key      only check that --key is the private half of --pubkey
#
# Needs cosign (the version pinned in scripts/install-cosign.sh), docker with
# buildx, and python3. Registry credentials come from the docker login.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() {
  echo "[sign] $*" >&2
  exit 1
}

mode=""
key=""
pubkey=""
identity=""
issuer=""
release=""
check_key=0
tags=()
refs=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) key="${2:?--key needs a value}"; mode="${mode:-key}"; shift 2 ;;
    --pubkey) pubkey="${2:?--pubkey needs a value}"; shift 2 ;;
    --keyless) [[ "${mode}" == "key" ]] && die "--key and --keyless are exclusive"; mode="keyless"; shift ;;
    --identity) identity="${2:?--identity needs a value}"; shift 2 ;;
    --issuer) issuer="${2:?--issuer needs a value}"; shift 2 ;;
    --release) release="${2:?--release needs a value}"; shift 2 ;;
    --tag) tags+=("${2:?--tag needs a value}"); shift 2 ;;
    --check-key) check_key=1; shift ;;
    -*) die "unknown option $1" ;;
    *) refs+=("$1"); shift ;;
  esac
done

case "${mode}" in
  key)
    [[ -n "${key}" && -n "${pubkey}" ]] || die "--key needs --pubkey"
    [[ -s "${pubkey}" ]] || die "public key ${pubkey} is missing or empty; see docs/supply-chain.md (release key)"
    [[ -z "${identity}${issuer}" ]] || die "--identity/--issuer are for --keyless"
    ;;
  keyless)
    [[ -n "${identity}" && -n "${issuer}" ]] || die "--keyless needs --identity and --issuer"
    [[ -z "${pubkey}" ]] || die "--pubkey is for --key"
    ;;
  *) die "choose --key REF --pubkey FILE or --keyless --identity URI --issuer URL" ;;
esac

command -v cosign >/dev/null 2>&1 || die "cosign not found; scripts/install-cosign.sh installs the pinned one"
pinned="$(sed -n 's/^COSIGN_VERSION="\(v[0-9.]*\)"$/\1/p' "${SCRIPT_DIR}/install-cosign.sh")"
running="$(cosign version --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["gitVersion"])')" \
  || die "could not read the cosign version"
[[ -n "${pinned}" && "${running}" == "${pinned}" ]] \
  || die "cosign ${running} is not the pinned ${pinned} (scripts/install-cosign.sh)"

if [[ "${check_key}" == "1" ]]; then
  [[ "${mode}" == "key" && ${#refs[@]} -eq 0 ]] || die "--check-key takes --key and --pubkey only"
  derived="$(cosign public-key --key "${key}")" || die "cosign could not read the signing key"
  # Compared as PEM bodies: whitespace and a trailing newline are not the key.
  if [[ "$(printf '%s' "${derived}" | tr -d ' \n\r')" != "$(tr -d ' \n\r' < "${pubkey}")" ]]; then
    die "the signing key is not the private half of ${pubkey}: releases signed with it would fail every customer's verification"
  fi
  echo "[sign] signing key matches ${pubkey}"
  exit 0
fi

[[ ${#refs[@]} -eq 1 ]] || die "exactly one IMAGE@sha256:DIGEST, got ${#refs[@]}"
ref="${refs[0]}"
repo="${ref%@*}"
digest="${ref#*@}"
[[ "${ref}" == *@* && "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "${ref} is not IMAGE@sha256:<digest>; only a digest is signed, never a tag"
[[ "${repo##*/}" != *:* ]] || die "${ref} carries a tag; pass the repository and digest only"

for tag in ${tags[@]+"${tags[@]}"}; do
  [[ "${tag%:*}" == "${repo}" && "${tag##*:}" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]] \
    || die "tag ${tag} is not ${repo}:<tag>"
done

if [[ "${mode}" == "key" ]]; then
  sign_id=(--key "${key}")
  verify_id=(--key "${pubkey}")
else
  sign_id=()
  verify_id=(--certificate-identity "${identity}" --certificate-oidc-issuer "${issuer}")
fi
annotations=()
if [[ -n "${release}" ]]; then
  annotations=(-a "release=${release}")
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# The provenance BuildKit attached to this digest, one predicate per platform.
# SLSA v1 only (the pipelines build with --provenance version=v1): the type
# attested and verified below, and required by the admission examples.
echo "[sign] ${ref}: reading build provenance"
docker buildx imagetools inspect "${ref}" --format '{{json .Provenance}}' > "${tmp}/provenance.json"
python3 - "${tmp}/provenance.json" "${tmp}" <<'PY' || die "${ref}: no usable SLSA v1 provenance; was it built with --provenance mode=max,version=v1?"
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text() or "null") or {}
# One platform: {"SLSA": {...}}; several: {"linux/amd64": {"SLSA": {...}}, ...}.
per_platform = {"image": data} if "SLSA" in data else data
written = 0
for platform, stub in sorted(per_platform.items()):
    predicate = (stub or {}).get("SLSA")
    if not predicate:
        continue
    if "buildDefinition" not in predicate or "runDetails" not in predicate:
        sys.exit(f"{platform}: provenance is not SLSA v1")
    name = platform.replace("/", "-")
    Path(sys.argv[2], f"provenance-{name}.json").write_text(json.dumps(predicate))
    written += 1
if not written:
    sys.exit("no provenance attached")
PY

echo "[sign] ${ref}: signing"
cosign sign --yes --recursive --tlog-upload=true \
  ${sign_id[@]+"${sign_id[@]}"} ${annotations[@]+"${annotations[@]}"} "${ref}"

for predicate in "${tmp}"/provenance-*.json; do
  echo "[sign] ${ref}: attesting $(basename "${predicate}" .json)"
  cosign attest --yes --tlog-upload=true --type slsaprovenance1 \
    ${sign_id[@]+"${sign_id[@]}"} --predicate "${predicate}" "${ref}"
done

# Verified the way a customer verifies, before any tag points here.
echo "[sign] ${ref}: verifying"
cosign verify "${verify_id[@]}" ${annotations[@]+"${annotations[@]}"} "${ref}" > /dev/null
cosign verify-attestation "${verify_id[@]}" --type slsaprovenance1 "${ref}" > /dev/null

for tag in ${tags[@]+"${tags[@]}"}; do
  echo "[sign] tagging ${tag}"
  docker buildx imagetools create --tag "${tag}" "${ref}"
  # imagetools create re-uses a single source index unchanged, so the tag has
  # to resolve to the digest just signed. If it ever re-wrapped it, the tag
  # would point at an unsigned index; stop rather than publish that.
  resolved="$(docker buildx imagetools inspect "${tag}" --format '{{json .Manifest}}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])')"
  [[ "${resolved}" == "${digest}" ]] \
    || die "${tag} resolves to ${resolved}, not the signed ${digest}"
done

echo "[sign] ${ref}: signed, provenance attested, verified${tags[0]+, tagged}"
