# Release contract

What a Shapoclyack release is, what it promises about the components it ships —
Pulse above all, the default service-probe engine — and how a customer checks
those promises from outside.

This page is authoritative for release identity, the Pulse support and update
policy, and customer-side verification. It does not repeat what other pages own:

| Subject | Authoritative page |
|---|---|
| Which release lines are supported, and how to report a vulnerability | [Security policy](../.github/SECURITY.md) |
| What changed in a release | [CHANGELOG.md](../CHANGELOG.md) |
| Every bundled tool and dataset, with its licence | [Third-party components](third-party.md) |
| How Pulse runs inside a scan | [Pulse backend](pulse-backend.md) |
| How Pulse will be distributed | [ADR 0001](adr/0001-pulse-distribution-model.md) — **proposed, not yet decided** |

## What a release is

A release is a git tag `shapoclyack-<MAJOR>.<MINOR>-<MMDD>`; a prerelease adds
`-alpha<N>`, `-beta<N>` or `-rc<N>`. [`Jenkinsfile.publish`](../Jenkinsfile.publish)
builds the images from that tag — not from a branch — for `linux/amd64` and
`linux/arm64` (its default `MULTIARCH=true`; a run with `MULTIARCH=false`
publishes `linux/arm64` only), and pushes:

| Image | Tags | Contains Pulse |
|---|---|---|
| `ghcr.io/onixus/shapoclyack-scanner` | `<tag>`, `<tag>-nmap` | yes |
| `ghcr.io/onixus/shapoclyack-aio` | `<tag>`, `<tag>-nmap` | yes |
| `ghcr.io/onixus/shapoclyack-api` | `<tag>` | no |

A stable release also moves `latest` / `latest-nmap`; a prerelease never does.
Each image index carries BuildKit build provenance (`mode=max`) and an SPDX SBOM
as attestations. Fixes ship as a new tag
([SECURITY.md](../.github/SECURITY.md#security-updates)). Deploy by
`tag@sha256:…`, as the Kubernetes manifests do.

**What the pipeline does not enforce yet:**

- **Signatures.** Neither the images nor their attestations are signed, and
  there is no admission policy that checks one
  ([#313](https://github.com/onixus/Shapoclyack/issues/313)). A digest proves you
  got the same bytes as everyone else who pulled that digest, not who built them.
- **Immutable tags.** "A published tag is not rebuilt" is a rule the release
  manager keeps, not one the pipeline refuses to break: `Jenkinsfile.publish`
  does not check whether `TAG` was published before, and a second run with the
  same `TAG` overwrites its images. Before a real publish, the release manager
  confirms the tag is new — `crane digest ghcr.io/onixus/shapoclyack-aio:<TAG>`
  must fail with `MANIFEST_UNKNOWN`. This is why a deployment pins the digest.
- **`latest` on an older line.** Every stable run moves `latest`, including a
  backport to an older line (below).

## Pulse in a release

### One Pulse version per release

Every Shapoclyack release ships exactly one Pulse version, and that version is
the only supported combination for that release. It is the same value in five
places — `PULSE_VERSION` in `scripts/install-pulse.sh`, both Dockerfiles,
`Jenkinsfile.publish` and the manually runnable
`.github/workflows/docker-publish.yml` — and has a per-platform tarball digest
in [`scripts/pulse-pinned.sha256`](../scripts/pulse-pinned.sha256).
[`tests/test_pulse_supply_chain.py`](../tests/test_pulse_supply_chain.py) fails
the build when they disagree or the version has no pin.

| Shapoclyack release | Pulse | How the image build checked it |
|---|---|---|
| `shapoclyack-0.45-0916` | `v1.1.0` | against the release's own `checksums.txt`; there is no pin file at this tag |
| `shapoclyack-0.46-0922` | `v1.1.0` | against the pinned digest; the pin itself was taken unsigned, because `v1.1.0` predates GenDec's release signing |
| next release (`main` today) | `v1.1.0` | against the pinned digest, and the image records it (below) |

A support window for a release line ([SECURITY.md](../.github/SECURITY.md#supported-versions))
covers its Pulse the same way it covers everything else in its images.

Running any other Pulse — a binary set with `OCTO_PULSE_BIN` or
`service_probe.pulse.bin`, or an image built with a `PULSE_VERSION` that has no
pin — is a local modification. It runs, but a problem report is reproduced on
the pinned version. `scripts/verify-pulse-image.py` reports an image built with
an unpinned version as not verified. A runtime override is not in the image;
each run records the *path* of the binary it ran in `pulse/raw.json`
(`adapter.pulse_bin`) — which file, not which bytes.

### How the Pulse version changes

A new Pulse enters Shapoclyack in one reviewed change and leaves in a release
tag, never any other way:

1. **Only from a signed GenDec release.** The pin is taken with
   `GITHUB_TOKEN=… scripts/pulse-pin.sh vX.Y.Z`, which verifies GenDec's cosign
   signature over `checksums.txt` against GenDec's `release.yml` **on that tag**
   before printing anything. `PULSE_PIN_ALLOW_UNSIGNED=1` is not used for a new
   version: `v1.1.0` is the last unsigned pin.
2. **One commit** replaces the pin lines and bumps `PULSE_VERSION` in all five
   places. The test above holds the five together.
3. **Reviewed as a security change**, not a version bump: the binary runs with
   `cap_net_raw,cap_net_admin` on every sensor. The pull request states what
   GenDec's release notes change in Pulse's output.
4. **Announced as a scan-semantics change.** Pulse produces the services, OS
   guesses and CVEs of every default scan, so a bump can change findings. The
   `CHANGELOG.md` entry (under *Changed*, or *Security* for a fix) names the old
   and new Pulse version and the expected effect on findings.
5. **Shipped in the next release tag.** An existing tag is never rebuilt with a
   new Pulse — a rule kept by the release manager, see above.

Rolling Pulse back means deploying the previous Shapoclyack release, with its
own pins — see [Upgrade and rollback](operations.md#upgrade-and-rollback) — not
mixing one release's scanner with another release's Pulse.

### Security fixes in Pulse

- **Where to report.** GenDec is private and has no public reporting channel, so
  a vulnerability in the Pulse shipped in the official images is reported to
  Shapoclyack through the channels in
  [SECURITY.md](../.github/SECURITY.md#reporting-a-vulnerability). It is in
  scope there as part of the images, not an out-of-scope upstream issue.
- **Timelines.** The same as for Shapoclyack's own code: acknowledgement within
  five business days, a remediation plan or status within 30 days for a
  confirmed issue. No faster promise is made for Pulse specifically; whether to
  make one is an open question in [ADR 0001](adr/0001-pulse-distribution-model.md).
- **How the fix ships.** A signed GenDec release, pinned by the procedure above,
  in a new Shapoclyack release tag for every line SECURITY.md lists as receiving
  security fixes. The `CHANGELOG.md` entry goes under *Security*.
- **Until a fix ships.** `OCTO_SERVICE_BACKEND=nmap` on a `-nmap` image takes
  Pulse out of the scan. It is an explicit switch with a different finding set,
  not an equivalent; it is also available per profile
  ([Pulse backend](pulse-backend.md#escape-hatch-full-nse)).

### Backporting a fix to an older line

A backport is the same pin change, cherry-picked onto a branch cut from the
older line's last tag, and released as a new tag of that line
(`shapoclyack-0.45-<MMDD>`). Two limits of `Jenkinsfile.publish` shape the
procedure:

- A stable run moves `latest` / `latest-nmap` to whatever it publishes, so a
  backport published last would point `latest` at the **older** line. Publish
  the older line first and the current line last. When only the backport is
  published, put `latest` back afterwards:

  ```bash
  CURRENT=shapoclyack-0.46-0922   # the newest release of the current line
  for image in shapoclyack-scanner shapoclyack-aio; do
    docker buildx imagetools create -t "ghcr.io/onixus/$image:latest" "ghcr.io/onixus/$image:$CURRENT"
    docker buildx imagetools create -t "ghcr.io/onixus/$image:latest-nmap" "ghcr.io/onixus/$image:$CURRENT-nmap"
  done
  docker buildx imagetools create -t ghcr.io/onixus/shapoclyack-api:latest "ghcr.io/onixus/shapoclyack-api:$CURRENT"
  ```

- The backport tag must be new (see *Immutable tags* above); a fix is never
  published by re-running an existing tag.

## What a customer can verify, and how

The verifier, `scripts/verify-pulse-image.py`, is newer than the releases
published so far, so it is run from `main` (or any release that contains it),
and it is given the pin file **of the release being verified**, taken from that
tag in your own clone:

```bash
git clone https://github.com/onixus/Shapoclyack.git
cd Shapoclyack                       # main: the verifier is here
TAG=shapoclyack-0.46-0922
git show "$TAG:scripts/pulse-pinned.sha256" > "pins-$TAG.sha256"
```

**`shapoclyack-0.45-0916` and earlier have no pin file at their tag.** 0.45 and
0.46 both ship Pulse `v1.1.0` — `PULSE_VERSION=v1.1.0` in both Dockerfiles and
`Jenkinsfile.publish` at both tags — so the `v1.1.0` pins first committed for
0.46 are the reference for 0.45 as well
(`git show shapoclyack-0.46-0922:scripts/pulse-pinned.sha256`). Whether the
0.45 image actually contains those bytes is what check 2 answers; its build
checked only the release's own `checksums.txt`.

### 0. The image, by a digest you trust

A tag can be moved; a digest cannot. Check the image **by digest** and compare
that digest with one you trust:

- Until #313 signs the images there is no signed statement of which digest a
  release is. The closest is a digest committed to this repository in a
  reviewed change after the release: the Kubernetes manifests on `main` pin the
  `aio` and `api` images as `tag@sha256:…` (for 0.46-0922, commit `7658817`).
  **The `scanner` image is not digest-pinned anywhere in the repository**;
  [k8s/README.md](../k8s/README.md) shows its digest only abbreviated.
- Otherwise, record the digest when you first pull and compare every later pull
  and every mirror against it (trust on first use).

```bash
crane digest "ghcr.io/onixus/shapoclyack-aio:$TAG"                  # what the tag points at now
IMAGE=ghcr.io/onixus/shapoclyack-aio@sha256:<the digest you trust>
docker buildx imagetools inspect "$IMAGE" --format '{{ json .Provenance }}' # build arguments, PULSE_VERSION among them
docker buildx imagetools inspect "$IMAGE" --format '{{ json .SBOM }}'       # SPDX SBOM of the image
```

The attestations are what the build says it was given; they are unsigned until
#313.

### 1. The Pulse binary in the image

The verifier (Python 3.9 or later, standard library only) copies three files
out of a **created, never started** container — removed afterwards together
with its anonymous volumes — and prints the image ID and repository digests the
engine resolved, which is what was actually checked:

```bash
python3 scripts/verify-pulse-image.py --pins "pins-$TAG.sha256" --image "$IMAGE" --platform linux/amd64
python3 scripts/verify-pulse-image.py --pins "pins-$TAG.sha256" --image "$IMAGE" --platform linux/arm64
```

Images built from this change on carry an install record,
`/usr/local/share/shapoclyack/pulse-install.txt`, written by
`scripts/install-pulse.sh` during the build: the tarball it installed, the check
that tarball passed (`verified=pin`, or what else happened), and the SHA-256 of
the binary it produced. The verifier requires `verified=pin`, the tarball digest
to equal your pin, the binary to equal the recorded digest, and the pin file
inside the image (`/app/scripts/pulse-pinned.sha256`) to exist and agree with
yours.

**What the record is worth.** It is unsigned and sits in the same image as the
binary. It catches a binary replaced *without* its record — a later layer, a
patched derived image — and it states that the build installed the pinned
tarball, by the build's own account. Whoever can replace the binary can rewrite
the record next to it, and the verifier would then say VERIFIED. Against
deliberate tampering it is therefore **only as good as the image digest you
verified** in step 0; check 2 does not rely on anything the image says about
itself. Images of
`shapoclyack-0.46-0922` and earlier have no record, and the verifier says so and
asks for check 2.

No Docker? Unpack the image as an unprivileged user into an empty directory
(for example `crane export --platform linux/amd64 "$IMAGE" - | tar -x -C rootfs`)
and pass `--rootfs rootfs`. Symlinks are never followed out of it. `--engine podman`
uses Podman instead of Docker.

### 2. The binary against the pinned tarball — independent of the image's own account

```bash
gh release download v1.1.0 --repo onixus/GenDec --pattern 'pulse-v1.1.0-linux-amd64.tar.gz'
python3 scripts/verify-pulse-image.py --pins "pins-$TAG.sha256" --image "$IMAGE" --platform linux/amd64 \
  --tarball pulse-v1.1.0-linux-amd64.tar.gz
```

The tarball is read once into memory; its digest must be in your pin file
before anything in it is parsed, and then the `pulse` inside it is hashed
(nothing is unpacked) and must equal the binary in the image. This works for
every published image, record or not. An image without its own pin file
(0.45-0916 and earlier) is reported as "not compared" on that point. **Today
this needs read access to GenDec**, which a customer does not have — that is the
gap [ADR 0001](adr/0001-pulse-distribution-model.md) exists to close.

### 3. The pin against GenDec's signature

For a Pulse released after `v1.1.0` — with the same access as check 2 — the
pin helper verifies the signature and prints the digests it would pin; they must
equal the lines at the release tag:

```bash
GITHUB_TOKEN=… scripts/pulse-pin.sh vX.Y.Z
# which runs, over the release's checksums.txt:
cosign verify-blob --bundle checksums.txt.cosign.bundle \
  --certificate-identity "https://github.com/onixus/GenDec/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

### What each check proves

| Check | Proves | Needs | Available to a customer today |
|---|---|---|---|
| 0. Digest and attestations | you are looking at the image you meant; what its build says it was given | a digest you trust | yes; attestations unsigned until #313 |
| 1. Install record | the binary was not replaced without its record, and the build reports the pinned tarball — against deliberate tampering, only as good as the digest in 0 | the image, the tag's pins | yes, for releases after `0.46-0922` |
| 2. Pinned tarball | the binary is the one inside the tarball this repository pinned | the tarball | no — GenDec access |
| 3. Signature | the pinned tarball came out of GenDec's release workflow on that tag | the release assets | no — GenDec access; none for `v1.1.0` |

None of these proves that the code that went into Pulse was reviewed by anyone
outside the organisation. That is the question the distribution decision
answers, not a check.

### Verifier exit status

| Exit | Meaning |
|---|---|
| `0` | verified; the output names the chain (install record, pinned tarball, or both) |
| `1` | not verified: a check failed, or nothing tied the binary to a pin |
| `2` | usage or environment error — an unreadable pin file, tarball or image file, no Docker, a daemon that did not answer, no temporary directory for `--image` |
| `3` | the image contains no `/usr/local/bin/pulse` (below) |

## When Pulse is absent

An image built with `--build-arg INSTALL_PULSE=0` contains no Pulse, needs no
GenDec token, and has **no service-probe backend of its own**. No published tag
is built that way.

- With the default `service_probe.backend: pulse`, a run that has TCP ports to
  probe **fails** with an error naming both fixes — install Pulse, or switch the
  backend to `nmap` on an image that has it. It never falls back to Nmap on its
  own and never completes as a scan with no services.
- Running such an image means choosing the engine explicitly:
  `OCTO_SERVICE_BACKEND=nmap` (or `service_probe.backend: nmap`) on an
  `INSTALL_NMAP=1` build.
- `GET /api/system` lists `pulse` as `not installed`; `verify-pulse-image.py`
  exits `3`.

The contract behind this: **the same release with the same configuration runs
the same engine, or the run fails.** The engine changes only when an operator
sets `service_probe.backend`, a profile's `service_backend`, or
`OCTO_SERVICE_BACKEND`.

A sensor installed on a host rather than from the image needs Pulse installed
separately (`scripts/install-pulse.sh`, which needs GenDec access). On a closed
network the practical route today is to copy `/usr/local/bin/pulse` out of an
image verified as above; `install-pulse.sh` has no input for a locally supplied
tarball yet.
