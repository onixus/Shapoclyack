# Supply chain: signed images, provenance and pinned inputs

This page covers what a Shapoclyack release image carries to prove where it
came from, how to check that yourself or at admission, and what the build
pins so that a release is built from reviewed inputs
([#313](https://github.com/onixus/Shapoclyack/issues/313)).

The GenDec/Pulse signature described in [third-party.md](third-party.md) is a
different thing: it covers one binary embedded in the scanner and all-in-one
images, not the images themselves.

## What is signed

Every image the release path pushes to `ghcr.io/onixus/shapoclyack-{scanner,api,aio}`
is:

- **signed by digest** with cosign — the image index and each platform
  manifest in it (`linux/amd64`, `linux/arm64`). A tag is never signed; tags
  are attached only after the digest's signature has been verified, so a tag
  never points at an unsigned image;
- **annotated** with `release=<tag>` inside the signed payload, so a signature
  says which release a digest is;
- **attested** with a signed [SLSA v1](https://slsa.dev/spec/v1.0/provenance)
  provenance statement per platform, recorded by BuildKit during the build
  (`--provenance mode=max,version=v1`) and attached with
  `cosign attest --type slsaprovenance1`.

BuildKit also writes an SPDX SBOM and the same provenance into the image index
itself. They are not signed separately: the index digest is a hash over them,
so once the digest is verified they are pinned too (see [SBOM](#sbom)).

Signatures are in cosign's classic layout (`sha256-<digest>.sig` / `.att` tags
next to the image), written by the cosign **2.x** that
`scripts/install-cosign.sh` pins. That is the layout Kyverno's `type: Cosign`
and the Sigstore policy-controller read by default; cosign 3 verifies it too.
Every signature and attestation is recorded in the public Rekor transparency
log.

### Two identities

| Publisher | When | Identity customers verify |
|---|---|---|
| `Jenkinsfile.publish` (the release path) | every release | the **release key**: `cosign.pub` at the root of this repository, at the release tag |
| `.github/workflows/docker-publish.yml` (manual fallback) | only if a release is published from GitHub Actions | **keyless**: certificate subject `https://github.com/onixus/Shapoclyack/.github/workflows/docker-publish.yml@refs/tags/<release tag>`, issuer `https://token.actions.githubusercontent.com` |

Keyless signing needs an OIDC token that Fulcio trusts; GitHub Actions has
one, the self-hosted Jenkins does not, so the release path signs with a key.
Trust either identity or both — the example policies accept either and are
easy to narrow to one.

Both publishers run the same script, `scripts/sign-release-image.sh`: push by
digest → sign → attest provenance → verify both with the customer's identity →
tag. Any failure fails the release and leaves only an untagged, unsigned
digest in the registry. There is no switch that skips it; a Jenkins
`DRY_RUN` build pushes nothing, signs nothing, and turns yellow if the signing
key is not set up.

## Verify an image

Install cosign ([docs](https://docs.sigstore.dev/cosign/system_config/installation/)).
Verify the reference you deploy — `tag@sha256:digest`, as the manifests in
`k8s/` do.

**Release key** (images from `Jenkinsfile.publish`):

```bash
TAG=shapoclyack-0.47-1001
curl -fsSLO "https://raw.githubusercontent.com/onixus/Shapoclyack/${TAG}/cosign.pub"
cosign verify --key cosign.pub -a "release=${TAG}" \
  "ghcr.io/onixus/shapoclyack-aio:${TAG}@sha256:<digest>"
```

Fetch `cosign.pub` from the release tag, not from `main`, and compare it with
the fingerprint published in the release notes (a second channel):
`openssl pkey -pubin -in cosign.pub -outform DER | sha256sum`.

**GitHub Actions keyless** (images from `docker-publish.yml`):

```bash
cosign verify \
  --certificate-identity "https://github.com/onixus/Shapoclyack/.github/workflows/docker-publish.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  -a "release=${TAG}" \
  "ghcr.io/onixus/shapoclyack-aio:${TAG}@sha256:<digest>"
```

Always pin the identity; `cosign verify` without one accepts a signature from
anybody.

### Build provenance

```bash
cosign verify-attestation --key cosign.pub --type slsaprovenance1 \
  "ghcr.io/onixus/shapoclyack-aio:${TAG}@sha256:<digest>" \
  | jq -r .payload | base64 -d | jq '.predicate.buildDefinition.externalParameters'
```

(or the keyless identity flags instead of `--key`). One statement per
platform; `internalParameters.builderPlatform` says which. The predicate is
BuildKit's: the Dockerfile, build arguments (`INSTALL_NMAP`, `PULSE_VERSION`,
`ENRICHMENT_STRICT`), resolved base images and the git source.

### SBOM

After verifying the digest, read the SPDX SBOM BuildKit stored in the same
index:

```bash
docker buildx imagetools inspect "ghcr.io/onixus/shapoclyack-aio:${TAG}@sha256:<digest>" \
  --format '{{ json (index .SBOM "linux/amd64").SPDX }}' > sbom.spdx.json
```

It is fetched by content address from the index you just verified, so it
needs no signature of its own. It is not attached as a separate cosign
attestation: a full-image SPDX document runs to megabytes, and uploading that
to the public Rekor log on every release is a failure mode, not a feature.

## Admission control

Two examples, equivalent in effect, live next to the other optional manifests:

- [`image-signature-kyverno.example.yaml`](../k8s/shapoclyack/examples/image-signature-kyverno.example.yaml)
  — Kyverno ≥ 1.13 `ClusterPolicy` with `verifyImages`;
- [`image-signature-policy-controller.example.yaml`](../k8s/shapoclyack/examples/image-signature-policy-controller.example.yaml)
  — Sigstore policy-controller `ClusterImagePolicy`.

Both require, for every `ghcr.io/onixus/shapoclyack-*` image: a digest in the
reference, a signature from one of the two identities above, and a SLSA v1
provenance attestation from the same identity. The release key is read from a
Secret created from `cosign.pub`; the header of each file has the command.
policy-controller only enforces in namespaces labelled
`policy.sigstore.dev/include=true`.

`tests/test_admission_policies.py` parses both files and fails if the keyless
subject stops matching the publish workflow at exactly the release tags
`Jenkinsfile.publish` accepts, if a published repository falls outside the
image globs, or if either policy stops requiring provenance. The examples were
also validated against the upstream Kyverno and policy-controller CRD schemas
when they were written.

A mirror (air-gapped registry) needs the signatures copied along with the
images — `cosign copy` does both — and the policies' image globs pointed at
the mirror.

## Release key: one-time setup and rotation (maintainers)

`Jenkinsfile.publish` refuses to publish until this is done.

1. Generate the pair on a trusted machine:
   `cosign generate-key-pair` (asks for a password; writes `cosign.key` and
   `cosign.pub`). A KMS-held key works the same way
   (`cosign generate-key-pair --kms awskms:///alias/shapoclyack-release`, or
   `gcpkms://`, `azurekms://`, `hashivault://`); `scripts/sign-release-image.sh`
   takes the URI as `--key` unchanged, and `Jenkinsfile.publish` then binds
   the KMS credentials instead of the key file.
2. In Jenkins → Credentials: `COSIGN_PRIVATE_KEY` (Secret file: `cosign.key`)
   and `COSIGN_PASSWORD` (Secret text).
3. Commit `cosign.pub` at the repository root through a reviewed PR and
   publish its fingerprint in the next release notes.
4. Keep an offline backup of `cosign.key`; no copy stays on the machine that
   generated it.

The `Signing key` stage checks, before anything is built, that the Jenkins
credential is the private half of the committed `cosign.pub` — a pipeline
signing with a key customers do not trust would fail every verification
downstream.

**Rotation:** generate a new pair, replace `cosign.pub` and the Jenkins
credentials in one change, and announce it. Releases signed before stay
verifiable with the `cosign.pub` at their own tag, which is why verification
always fetches the key from the release tag. **Compromise:** publish an
advisory naming the affected window; Rekor timestamps every signature, so the
set signed with the leaked key is enumerable.

## Pinned build inputs

**Base and build-stage images.** Every `FROM` in `Dockerfile*` — including the
`golang`, `debian` and `node` build stages — every `image:` in `k8s/`, and every
image the pipelines run (Jenkins stage images, Trivy, Syft, Semgrep, the
BuildKit daemon, the SBOM generator, QEMU, the e2e/load targets, the server
installer's Postgres) is `name:tag@sha256:<index digest>`.
`tests/test_image_pins.py` fails on a new reference without a digest; the only
exceptions are images the same job builds (`network-scan-cli:*`, the kind
`kind-dev` image), listed in the test with the reason.

**Python dependencies.** `requirements*.txt` are the human-edited inputs;
`scripts/lock-python-deps.sh` compiles them with `uv pip compile --universal
--generate-hashes` into `requirements*.lock`:

| Lock | Input | Installed by |
|---|---|---|
| `requirements-pip.lock` | `requirements-pip.txt` | every image, first (pip itself) |
| `requirements.lock` | `requirements.txt` | scanner image |
| `requirements-api.lock` | `requirements-api.txt` | api and all-in-one images |
| `requirements-dev.lock` | `requirements-dev.txt` | PR gate, full CI, Jenkins |

Installs use `pip install --require-hashes --only-binary=:all:`: every
transitive dependency is pinned, every file checked against its sha256, and no
sdist is built (its build dependencies would be fetched without a hash check).
One universal lock serves `linux/amd64` and `linux/arm64`, Python 3.11 and
3.12 — platform-only packages keep their markers, and the hashes cover every
wheel of each pinned version. After editing a `requirements*.txt`:

```bash
python -m pip install uv==0.12.18      # the version the script checks for
scripts/lock-python-deps.sh            # --upgrade-package NAME to move one transitive pin
```

`tests/test_python_locks.py` (in the PR gate) fails when a lock no longer
satisfies its input, still carries a direct dependency its input dropped, has
an unhashed entry, disagrees with another lock on a shared package's version,
or when any image or pipeline installs something other than a lock. A local
development environment may keep installing the `.txt` files.

The web console's `npm ci` already verifies every package against the sha512
integrity in `web-next/package-lock.json`, and Go modules built in the images
are verified against the Go checksum database.

## Automated updates

[Renovate](https://docs.renovatebot.com/) is configured in
[`.github/renovate.json5`](../.github/renovate.json5); it needs the Renovate
GitHub App installed on the repository. It was chosen over Dependabot because
it regenerates the hashed Python locks together with the `requirements*.txt`
bump (its pip-compile manager replays the `uv pip compile` command in each
lock's header), and because its regex managers reach the pinned images outside
Dockerfiles and manifests.

- One window a week (Monday before 06:00 Europe/Moscow), at most five open
  PRs and two new ones an hour; security fixes skip the window.
- A release must be three days old before it is proposed.
- Grouped: all image digest refreshes in one PR, image patch releases in one,
  Python minor/patch in one, web-next dependencies and dev dependencies in one
  each, recon Go modules in one, GitHub Actions monthly in one.
- Waiting on the Dependency Dashboard until someone approves: every major
  update, minor bumps of images (Python 3.12 → 3.13, Postgres 16 → 17,
  ClickHouse, NATS are platform changes), the interpreter versions CI runs,
  and the PR gate's actions (`tests/test_pr_gate.py` pins them exactly).
- Transitive pins (the Python locks, `web-next/package-lock.json`) are
  refreshed by a monthly lock-maintenance PR.
- The publish workflow's actions stay pinned to commit SHAs; that job can sign
  as the project.
- Shapoclyack's own images are not touched; releases re-pin them.

A PR that bumps an input without the lock (Renovate misconfigured, or a hand
edit) fails the PR gate on `tests/test_python_locks.py`.

## Not covered yet

- **First real release.** Signing, attestation and tagging were exercised end
  to end against a local registry with the real cosign 2.6.5; nothing has yet
  been signed against ghcr.io, Fulcio or the public Rekor log. The first
  release after this change also needs the one-time key setup above.
- **The sensor host installer and the console's deployment snippets** still
  default to a mutable `:latest` (`scripts/install-agent.sh`,
  `api/services/agents.py`); pinning them to the release digest belongs to the
  release process, like the `k8s/` pins.
- **pip's vendored copies.** The pip in the images vendors msgpack and
  setuptools versions with advisories; see `requirements-pip.txt`.
- **Debian packages** come from Debian's signed repositories at whatever
  version the pinned base image's sources resolve; they are not pinned
  individually.
