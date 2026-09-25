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
# tag: a tag can be moved after signing, a digest cannot) and each platform
# manifest in it, attests the SLSA provenance BuildKit recorded for every
# platform on both the index and that platform's manifest, verifies all of it
# with exactly the identity a customer will use, and only then points the
# release tags at it. Anything failing on the way leaves an untagged digest in
# the registry and a red build — never a tag on an image that is not signed.
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
    # Refused in either order: a --key that quietly lost to --keyless would
    # sign with an identity the caller did not ask for.
    --key) [[ "${mode}" == "keyless" ]] && die "--key and --keyless are exclusive"
      key="${2:?--key needs a value}"; mode="key"; shift 2 ;;
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

# The provenance BuildKit attached, one SLSA v1 predicate per platform, paired
# with that platform's manifest in the index. Every platform must have one: a
# platform without provenance would be signed and still fail every admission
# policy, and one platform's record says nothing about how the other was built.
# SLSA v1 only (the pipelines build with --provenance version=v1): the type
# attested and verified below, and required by the admission examples.
echo "[sign] ${ref}: reading the index and its build provenance"
docker buildx imagetools inspect "${ref}" --format '{{json .Manifest}}' > "${tmp}/index.json"
docker buildx imagetools inspect "${ref}" --format '{{json .Provenance}}' > "${tmp}/provenance.json"
python3 - "${tmp}/index.json" "${tmp}/provenance.json" "${tmp}" <<'PY' \
  || die "${ref}: no usable SLSA v1 provenance for every platform; was it built with --provenance mode=max,version=v1?"
import json
import sys
from pathlib import Path

index = json.loads(Path(sys.argv[1]).read_text() or "null") or {}
provenance = json.loads(Path(sys.argv[2]).read_text() or "null") or {}
out = Path(sys.argv[3])

# Platform manifests; BuildKit's attestation manifests are unknown/unknown.
platforms = {}
for entry in index.get("manifests") or []:
    platform = entry.get("platform") or {}
    annotations = entry.get("annotations") or {}
    if platform.get("os", "unknown") == "unknown":
        continue
    if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
        continue
    name = "/".join(p for p in (platform["os"], platform["architecture"], platform.get("variant")) if p)
    platforms[name] = entry["digest"]
if not platforms:
    sys.exit("not an image index with platform manifests, so no provenance can be attached")

# One platform: {"SLSA": {...}}; several: {"linux/amd64": {"SLSA": {...}}, ...}.
if "SLSA" in provenance:
    if len(platforms) != 1:
        sys.exit("one provenance record for an index of several platforms")
    provenance = {next(iter(platforms)): provenance}
extra = sorted(set(provenance) - set(platforms))
if extra:
    sys.exit(f"provenance for {', '.join(extra)}, which the index does not hold")
plan = []
for platform, digest in sorted(platforms.items()):
    predicate = (provenance.get(platform) or {}).get("SLSA")
    if not predicate:
        sys.exit(f"{platform}: no provenance attached")
    if "buildDefinition" not in predicate or "runDetails" not in predicate:
        sys.exit(f"{platform}: provenance is not SLSA v1")
    path = out / f"provenance-{platform.replace('/', '-')}.json"
    path.write_text(json.dumps(predicate))
    plan.append(f"{digest} {path}")
(out / "plan").write_text("\n".join(plan) + "\n")
PY

echo "[sign] ${ref}: signing"
cosign sign --yes --recursive --tlog-upload=true \
  ${sign_id[@]+"${sign_id[@]}"} ${annotations[@]+"${annotations[@]}"} "${ref}"

# Each platform's provenance is attested twice: on the index, which is what the
# manifests and admission policies name, and on that platform's own manifest,
# which --recursive has just signed and which a pod may name directly. On the
# index, the platform shows in the predicate itself (the ?platform= of the base
# images in resolvedDependencies), not in the subject.
platform_refs=()
while read -r platform_digest predicate; do
  platform_ref="${repo}@${platform_digest}"
  platform_refs+=("${platform_ref}")
  echo "[sign] attesting $(basename "${predicate}" .json) on the index and on ${platform_digest}"
  for subject in "${ref}" "${platform_ref}"; do
    cosign attest --yes --tlog-upload=true --type slsaprovenance1 \
      ${sign_id[@]+"${sign_id[@]}"} --predicate "${predicate}" "${subject}"
  done
done < "${tmp}/plan"

# Verified the way a customer verifies, before any tag points here — the index
# and every platform manifest, signature and provenance both.
echo "[sign] ${ref}: verifying"
for subject in "${ref}" "${platform_refs[@]}"; do
  cosign verify "${verify_id[@]}" ${annotations[@]+"${annotations[@]}"} "${subject}" > /dev/null
  cosign verify-attestation "${verify_id[@]}" --type slsaprovenance1 "${subject}" > /dev/null
done

# What each tag would point at is checked before any tag exists. imagetools
# create re-uses a single source index byte for byte, so the dry run must hash
# to the signed digest; if it ever re-wrapped the index, the tag would name an
# unsigned one. --dry-run prints the manifest it would push plus a newline.
for tag in ${tags[@]+"${tags[@]}"}; do
  docker buildx imagetools create --dry-run --tag "${tag}" "${ref}" > "${tmp}/would-push"
  would="$(python3 -c 'import hashlib, sys
data = open(sys.argv[1], "rb").read()
print("sha256:" + hashlib.sha256(data[:-1] if data.endswith(b"\n") else data).hexdigest())' "${tmp}/would-push")"
  [[ "${would}" == "${digest}" ]] \
    || die "${tag} would point at ${would}, not the signed ${digest}; nothing was tagged"
done

for tag in ${tags[@]+"${tags[@]}"}; do
  echo "[sign] tagging ${tag}"
  docker buildx imagetools create --tag "${tag}" "${ref}"
  # And read back: a registry that rewrote the manifest on push would show here.
  resolved="$(docker buildx imagetools inspect "${tag}" --format '{{json .Manifest}}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])')"
  [[ "${resolved}" == "${digest}" ]] \
    || die "${tag} resolves to ${resolved}, not the signed ${digest}"
done

echo "[sign] ${ref}: signed, provenance attested, verified${tags[0]+, tagged}"
