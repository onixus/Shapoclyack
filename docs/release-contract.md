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
`linux/arm64`, and pushes:

| Image | Tags | Contains Pulse |
|---|---|---|
| `ghcr.io/onixus/shapoclyack-scanner` | `<tag>`, `<tag>-nmap` | yes |
| `ghcr.io/onixus/shapoclyack-aio` | `<tag>`, `<tag>-nmap` | yes |
| `ghcr.io/onixus/shapoclyack-api` | `<tag>` | no |

A stable release also moves `latest` / `latest-nmap`; a prerelease never does.
Each image index carries BuildKit build provenance (`mode=max`) and an SPDX SBOM
as attestations. A published tag is not rebuilt or replaced: fixes ship as a new
tag ([SECURITY.md](../.github/SECURITY.md#security-updates)). Deploy by
`tag@sha256:…`, as the Kubernetes manifests do.

**Not yet part of the contract:** a signature on the Shapoclyack images and an
admission policy that checks it ([#313](https://github.com/onixus/Shapoclyack/issues/313)).
Until then, neither the images nor their attestations are signed; a digest
proves you got the same bytes as everyone else who pulled that digest, not who
built them.

## Pulse in a release

### One Pulse version per release

Every Shapoclyack release ships exactly one Pulse version, and that version is
the only supported combination for that release. It is the same value in four
places — `PULSE_VERSION` in `Jenkinsfile.publish`, both Dockerfiles and
`scripts/install-pulse.sh` — and has a per-platform tarball digest in
[`scripts/pulse-pinned.sha256`](../scripts/pulse-pinned.sha256).
[`tests/test_pulse_supply_chain.py`](../tests/test_pulse_supply_chain.py) fails
the build when they disagree or the version has no pin.

| Shapoclyack release | Pulse | How the image build checked it |
|---|---|---|
| `shapoclyack-0.45-0916` | `v1.1.0` | against the release's own `checksums.txt` (there was no pin file yet) |
| `shapoclyack-0.46-0922` | `v1.1.0` | against the pinned digest; the pin itself was taken unsigned, because `v1.1.0` predates GenDec's release signing |
| next release (`main` today) | `v1.1.0` | against the pinned digest, and the image records it (below) |

A support window for a release line ([SECURITY.md](../.github/SECURITY.md#supported-versions))
covers its Pulse the same way it covers everything else in its images.

Running any other Pulse — a binary set with `OCTO_PULSE_BIN` or
`service_probe.pulse.bin`, or an image built with a `PULSE_VERSION` that has no
pin — is a local modification. It runs, but a problem report is reproduced on
the pinned version. `scripts/verify-pulse-image.py` reports an image built with
an unpinned version as not verified; a runtime override is not in the image, and
each run records the binary it used in `pulse/raw.json` (`adapter.pulse_bin`).

### How the Pulse version changes

A new Pulse enters Shapoclyack in one reviewed change and leaves in a release
tag, never any other way:

1. **Only from a signed GenDec release.** The pin is taken with
   `GITHUB_TOKEN=… scripts/pulse-pin.sh vX.Y.Z`, which verifies GenDec's cosign
   signature over `checksums.txt` against GenDec's `release.yml` **on that tag**
   before printing anything. `PULSE_PIN_ALLOW_UNSIGNED=1` is not used for a new
   version: `v1.1.0` is the last unsigned pin.
2. **One commit** replaces the pin lines and bumps `PULSE_VERSION` in all four
   places. The test above holds the four together.
3. **Reviewed as a security change**, not a version bump: the binary runs with
   `cap_net_raw,cap_net_admin` on every sensor. The pull request states what
   GenDec's release notes change in Pulse's output.
4. **Announced as a scan-semantics change.** Pulse produces the services, OS
   guesses and CVEs of every default scan, so a bump can change findings. The
   `CHANGELOG.md` entry (under *Changed*, or *Security* for a fix) names the old
   and new Pulse version and the expected effect on findings.
5. **Shipped in the next release tag.** An existing tag is never rebuilt with a
   new Pulse.

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

## What a customer can verify, and how

Commands run from a checkout of this repository **at the release tag you are
verifying**: the pin file there is the reference, and it is public.

```bash
git clone https://github.com/onixus/Shapoclyack.git
cd Shapoclyack
git checkout shapoclyack-0.46-0922
cat scripts/pulse-pinned.sha256
```

### 1. The image and its attestations

```bash
IMAGE=ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.46-0922
docker buildx imagetools inspect "$IMAGE"                                   # index digest, platforms
docker buildx imagetools inspect "$IMAGE" --format '{{ json .Provenance }}' # build arguments, PULSE_VERSION among them
docker buildx imagetools inspect "$IMAGE" --format '{{ json .SBOM }}'       # SPDX SBOM of the image
```

### 2. The Pulse binary in the image

[`scripts/verify-pulse-image.py`](../scripts/verify-pulse-image.py) (Python 3
standard library only) copies three files out of a **created, never started**
container and checks them against your checkout's pin file:

```bash
python3 scripts/verify-pulse-image.py --image "$IMAGE" --platform linux/amd64
python3 scripts/verify-pulse-image.py --image "$IMAGE" --platform linux/arm64
```

Images built from this change on carry an install record,
`/usr/local/share/shapoclyack/pulse-install.txt`, written by
`scripts/install-pulse.sh` during the build: the tarball it installed, the check
that tarball passed (`verified=pin`, or what else happened), and the SHA-256 of
the binary it produced. The verifier requires `verified=pin`, the tarball digest
to equal your pin, the binary to equal the recorded digest, and the pin file
inside the image to agree with yours.

That record is **the build's own account**. It proves the binary was not
changed after the build and that the build says it installed the pinned
tarball. It does not prove the build was honest; for that, pair it with the
image signature once #313 ships, or with check 3. Images of
`shapoclyack-0.46-0922` and earlier have no record, and the verifier says so
and asks for check 3.

No Docker? Unpack the image as an unprivileged user into an empty directory
(for example `crane export --platform linux/amd64 "$IMAGE" - | tar -x -C rootfs`)
and pass `--rootfs rootfs`. Symlinks are never followed out of it. `--engine podman`
uses Podman instead of Docker.

### 3. The binary against the pinned tarball — independent of the build

```bash
gh release download v1.1.0 --repo onixus/GenDec --pattern 'pulse-v1.1.0-linux-amd64.tar.gz'
python3 scripts/verify-pulse-image.py --image "$IMAGE" --platform linux/amd64 \
  --tarball pulse-v1.1.0-linux-amd64.tar.gz
```

The tarball's digest must be in your pin file; the `pulse` inside it is hashed
in memory (nothing is unpacked) and must equal the binary in the image. This
works for every published image, record or not. **Today it needs read access to
GenDec**, which a customer does not have — that is the gap
[ADR 0001](adr/0001-pulse-distribution-model.md) exists to close.

### 4. The pin against GenDec's signature

For a Pulse released after `v1.1.0` — with the same access as check 3 — the
pin helper verifies the signature and prints the digests it would pin; they must
equal the committed lines:

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
| 1. Attestations | what the build says it was given, including `PULSE_VERSION` | the image | yes (unsigned until #313) |
| 2. Install record | binary unchanged since the build; the build reports the pinned tarball | the image, a checkout of the tag | yes, for releases after `0.46-0922` |
| 3. Pinned tarball | the binary is the one inside the tarball this repository pinned | the tarball | no — GenDec access |
| 4. Signature | the pinned tarball came out of GenDec's release workflow on that tag | the release assets | no — GenDec access; none for `v1.1.0` |

None of these proves that the code that went into Pulse was reviewed by anyone
outside the organisation. That is the question the distribution decision
answers, not a check.

### Verifier exit status

| Exit | Meaning |
|---|---|
| `0` | verified; the output names the chain (install record, pinned tarball, or both) |
| `1` | not verified: a check failed, or nothing tied the binary to a pin |
| `2` | usage or environment error — unreadable pin file, no Docker, a daemon that did not answer |
| `3` | the image contains no Pulse (below) |

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
