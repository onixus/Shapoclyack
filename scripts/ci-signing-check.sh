#!/usr/bin/env bash
# Run inside the local Jenkins controller (its docker.sock is the host daemon).
# Only the public key and a synthetic scratch image are used as public data.
# The production signer still records signatures/attestations in public Rekor.
set -euo pipefail
: "${WORKSPACE:?run from Jenkins}"
: "${BUILD_NUMBER:?run from Jenkins}"
: "${COSIGN_KEY:?bind the release key credential}"
: "${COSIGN_PASSWORD:?bind the release password credential}"
REGISTRY_IMAGE="${REGISTRY_IMAGE:-registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373}"
BUILDKIT_IMAGE="${BUILDKIT_IMAGE:-moby/buildkit:v0.32.2@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8}"
cd "$WORKSPACE"
rm -f signing-check-result.json
work="$(mktemp -d "$WORKSPACE/.signing-check.XXXXXX")"
registry="shapoclyack-signing-registry-${BUILD_NUMBER}"
builder="shapoclyack-signing-${BUILD_NUMBER}"
cleanup() {
  docker buildx rm "$builder" >/dev/null 2>&1 || true
  docker rm -f "$registry" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
scripts/install-cosign.sh "$work/tools"
export PATH="$work/tools:$PATH"
scripts/sign-release-image.sh --check-key --key "$COSIGN_KEY" --pubkey cosign.pub
# Fail closed when Jenkins and the repository disagree on the release identity.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null |
  openssl pkey -pubout > "$work/wrong.pub"
if scripts/sign-release-image.sh --check-key --key "$COSIGN_KEY" --pubkey "$work/wrong.pub" > "$work/wrong-key.log" 2>&1; then
  echo 'ERROR: mismatched public key was accepted' >&2
  exit 1
fi
grep -q 'not the private half' "$work/wrong-key.log"
echo '[signing-check] mismatched key correctly rejected'
# The registry and builder share Jenkins networking, with no host port exposed.
# Every caller sees the same loopback registry; other containers cannot reach it.
docker run -d --name "$registry" --network container:jenkins \
  -e REGISTRY_HTTP_ADDR=127.0.0.1:5500 "$REGISTRY_IMAGE"
ready=0
for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:5500/v2/ >/dev/null; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo 'registry did not start' >&2; exit 1; }
cat > "$work/buildkitd.toml" <<'TOML'
[registry."127.0.0.1:5500"]
  http = true
TOML
docker buildx create --name "$builder" --driver docker-container \
  --driver-opt "image=$BUILDKIT_IMAGE" --driver-opt network=container:jenkins \
  --buildkitd-config "$work/buildkitd.toml"
mkdir "$work/context"
printf 'Shapoclyack release signing validation\n' > "$work/context/probe.txt"
printf 'FROM scratch\nCOPY probe.txt /probe.txt\n' > "$work/context/Dockerfile"
repo='127.0.0.1:5500/shapoclyack-signing-check'
docker buildx build --builder "$builder" --platform linux/amd64,linux/arm64 \
  --provenance mode=max,version=v1 --metadata-file "$work/build.json" \
  --output "type=image,name=$repo,push-by-digest=true,name-canonical=true,push=true" "$work/context"
digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$work/build.json")"
scripts/sign-release-image.sh --key "$COSIGN_KEY" --pubkey cosign.pub \
  --release "jenkins-signing-check-${BUILD_NUMBER}" --tag "$repo:verified" "$repo@$digest"
python3 - "$digest" > signing-check-result.json <<'PY'
import hashlib, json, pathlib, sys
print(json.dumps({
    'passed': True,
    'image_digest': sys.argv[1],
    'public_key_pem_sha256': hashlib.sha256(pathlib.Path('cosign.pub').read_bytes()).hexdigest(),
    'platforms': ['linux/amd64', 'linux/arm64'],
    'mismatched_key_rejected': True,
    'signature_and_slsa_v1_verified': True,
    'registry': 'disposable loopback only',
}, indent=2))
PY
cat signing-check-result.json
