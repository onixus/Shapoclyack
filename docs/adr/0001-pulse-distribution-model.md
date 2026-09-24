# ADR 0001: Distribution model for the default Pulse backend

| | |
|---|---|
| **Status** | **Proposed — decision by the owner.** The choice between the options below is a product decision; this record prepares it and recommends one, and changes nothing that depends on the answer. |
| **Issue** | [#340](https://github.com/onixus/Shapoclyack/issues/340) |
| **Date** | 2026-09-24, against `main` at `1ed74b7` |
| **Related** | Release contract: [docs/release-contract.md](../release-contract.md). Not decided here: [#447](https://github.com/onixus/Shapoclyack/issues/447) (what Pulse does in the pipeline), [#452](https://github.com/onixus/Shapoclyack/issues/452) (the port backend), [#313](https://github.com/onixus/Shapoclyack/issues/313) (signing the Shapoclyack images), [#339](https://github.com/onixus/Shapoclyack/issues/339) (air-gap feeds and mirrors) |

## Context

### What the default scan depends on

- `service_probe.backend: pulse` is the default
  ([`scanner/config/default.yaml`](../../scanner/config/default.yaml)). On that
  path Pulse is the only source of services, OS guesses and version-matched
  CVEs; Nmap is not in the default images at all, because the Nmap Public Source
  License makes redistributing it a risk
  ([#97](https://github.com/onixus/Shapoclyack/issues/97),
  [third-party.md](../third-party.md#scanner-tools)).
- Pulse is built and released by **`onixus/GenDec`, a private repository**. Its
  source, its release tarballs, `checksums.txt`, the cosign signature bundle
  over that file, the per-release SPDX SBOM and the release notes are all
  reachable only with a token that can read GenDec.
- A missing Pulse is a loud failure, not a fallback:
  [`run_pulse_probe`](../../scanner/pipeline/pulse_probe.py) raises
  `FileNotFoundError` naming both fixes. That is deliberate — a silent switch to
  another engine would give two builds of the same Shapoclyack with the same
  configuration different finding sets — and every option below keeps it.

### What is already in place (and stays, under every option)

- A per-platform SHA-256 of each release tarball is committed in
  [`scripts/pulse-pinned.sha256`](../../scripts/pulse-pinned.sha256) and
  enforced by [`scripts/install-pulse.sh`](../../scripts/install-pulse.sh);
  `PULSE_SKIP_CHECKSUM=1` cannot bypass a pinned version.
- [`scripts/pulse-pin.sh`](../../scripts/pulse-pin.sh) takes a new pin only after
  `cosign verify-blob` of GenDec's keyless signature, constrained to GenDec's
  `release.yml` **on that tag**. The `v1.1.0` pins in use predate signing and
  were taken with `PULSE_PIN_ALLOW_UNSIGNED=1`.
- [`tests/test_pulse_supply_chain.py`](../../tests/test_pulse_supply_chain.py)
  fails on version/pin drift, a mismatch, or a bypass.
- `--build-arg INSTALL_PULSE=0` builds an image with no GenDec token and no
  Pulse.
- New with this record: the image build writes an **install record**
  (`/usr/local/share/shapoclyack/pulse-install.txt`) and
  [`scripts/verify-pulse-image.py`](../../scripts/verify-pulse-image.py) lets a
  customer tie the binary in an image back to the pin — see the
  [release contract](../release-contract.md#what-a-customer-can-verify-and-how).

### What the published images contain

[`Jenkinsfile.publish`](../../Jenkinsfile.publish) builds five images and never
passes `INSTALL_PULSE=0`; the Dockerfiles default it to `1`, and the stage fails
the build if no binary came out (`test -x`). So:

| Image | Pulse | Nmap |
|---|---|---|
| `ghcr.io/onixus/shapoclyack-scanner:<tag>` | yes, `v1.1.0`, with `cap_net_raw,cap_net_admin` | no |
| `ghcr.io/onixus/shapoclyack-scanner:<tag>-nmap` | yes | yes |
| `ghcr.io/onixus/shapoclyack-aio:<tag>` | yes | no |
| `ghcr.io/onixus/shapoclyack-aio:<tag>-nmap` | yes | yes |
| `ghcr.io/onixus/shapoclyack-api:<tag>` | no | no |

The registry serves these to anonymous clients: on 2026-09-24, from the
environment this record was written in, an unauthenticated request for
`shapoclyack-scanner:shapoclyack-0.46-0922` returned the image index (linux/amd64,
linux/arm64 and two BuildKit attestation manifests). The layer blobs could not
be downloaded from that environment (its egress policy), so the binary's
presence in that particular image is inferred from the build definition above,
not inspected.

**The consequence matters for every option: the Pulse binary is already
publicly redistributed.** Anyone can pull it out of a public image. What is
private is everything that would let them check it — the source, the signature,
the SBOM, the licence text and the release notes.

| Shapoclyack release | Pulse | Check at image build |
|---|---|---|
| `shapoclyack-0.45-0916` | `v1.1.0` | the release's own `checksums.txt` (no pin file yet) |
| `shapoclyack-0.46-0922` | `v1.1.0` | pinned digest (unsigned pin) |
| next release (`main`) | `v1.1.0` | pinned digest, plus the install record |

### What a customer can and cannot establish today

Without access to GenDec, a customer's review can confirm the image by digest,
read the image's BuildKit provenance and SBOM attestations (which name
`PULSE_VERSION` among the build arguments), and read the committed pins in this
public repository. It cannot obtain the pinned tarball to compare with the
binary, verify GenDec's signature, read Pulse's SBOM or licence, or read or
rebuild the source. A review of the default image ends at a repository the
reviewer cannot open.

### The certification roadmap

[fstec-certification.ru.md](../fstec-certification.ru.md) lists Pulse among the
components that must each be classified as inside the object of evaluation, as
its environment, or as an external integration (§3). Its certified release train
requires a source-code archive, SBOM, build provenance and signed artifacts
(§5), and for every Rust/Go binary a recorded version, source, licence, digest,
role and update policy (§6.2). Security invariant 8 requires updates only from a
trusted and verifiable source (§4).

Two points follow, and neither depends on the repository being public:

- Certification needs the **source available to the testing laboratory**, not
  to the world. The owner holds GenDec's source and can hand it over under any
  option here.
- It needs the **certified build to be produced from the source the laboratory
  analysed**. A binary downloaded from a release is tied to a commit only by
  provenance the laboratory has to trust; a binary compiled in the certified
  build from the archived source is tied by construction. Pulse produces the
  findings, so arguing it outside the object of evaluation would be hard.

Which way the laboratory reads this is decided in stages S0/S2 of that plan,
not here.

## Decision drivers

1. **Customer auditability** — what a customer's security team can establish
   about the default engine without being granted access to anything private.
2. **Supply-chain verification** — an unbroken chain from something public to
   the bytes that run with raw-socket capabilities on a sensor.
3. **FSTEC certification** — fit with the certified release train above.
4. **Licensing** — what may be redistributed, and whether the notices travel
   with it.
5. **Release engineering cost** — work now, and work at every Pulse bump.
6. **Air-gap** ([#339](https://github.com/onixus/Shapoclyack/issues/339)) — can
   a closed network build, mirror and verify it.
7. **What the published images contain.**
8. **Scan-semantics stability** — the same Shapoclyack release and configuration
   run the same engine, or fail.

## Options

### A. Public signed binary releases with SBOM and provenance

GenDec's release **artifacts** become public; its source may or may not.

- **A1** — make `onixus/GenDec` public. Releases inherit repository visibility
  on GitHub, so this is the one-step form; it also makes the source readable,
  which is most of option B's auditability at none of its build cost.
- **A2** — keep the source private and publish the release artifacts to a
  public channel: a public release-only repository, or the tarballs as a signed
  OCI artifact on `ghcr.io`. The signer stays GenDec's own `release.yml`.

**GenDec would have to publish, per release:** the four
`pulse-<v>-<platform>.tar.gz`, `checksums.txt` and
`checksums.txt.cosign.bundle` (all produced today); the SPDX SBOM (produced
today, private); a build-provenance attestation binding each tarball to its
source commit (new — e.g. GitHub artifact attestations); `LICENSE` and the
notices of the statically linked crates inside the tarball (new); release notes
with a security section; and a stable signer identity (workflow path and tag
ref) that is announced before it changes. The bytes of `v1.1.0` must be the
same bytes: re-uploading rebuilt tarballs would, correctly, fail the pins.

| Driver | Assessment |
|---|---|
| Auditability | Binary, signature, SBOM, provenance and licence for everyone. Source only under A1. |
| Supply chain | Complete for everyone: `cosign verify-blob` → `checksums.txt` → tarball → pin → `verify-pulse-image.py --tarball` → the binary in the image. |
| FSTEC | Unchanged from today: the laboratory still receives source privately, and a downloaded binary still needs provenance to be tied to it. A1 makes the component's origin public, which helps the borrowed-component inventory. |
| Licensing | Requires the licence to be published with the binary and a Pulse entry in `NOTICE` — owed today as well (below). |
| Cost | Low. GenDec already builds everything except the provenance attestation and the notices. Here: drop `GENDEC_READ_TOKEN` from `Jenkinsfile`, `Jenkinsfile.publish`, the workflows and the Dockerfiles' private-repo path; take the next pin from a signed release. |
| Air-gap | Release assets can be mirrored next to the images and verified before they enter the closed network. `install-pulse.sh` has no local-tarball input yet (follow-up). |
| Images | Identical content; they build without a token. |
| Scan semantics | Identical — the same bytes under the same pin. |

### B. Vendored or auditable source and build path

Pulse is compiled from source inside the Shapoclyack image build, the way the
`go-tools` stage already builds naabu, dnsx and nuclei.

- **B1** — vendor the source (and `cargo vendor` output) into this repository.
- **B2** — build from a public GenDec (which is A1) at a pinned commit, fetched
  by commit hash, with crates verified against `Cargo.lock` checksums — the Rust
  counterpart of what `GOSUMDB` does for the Go tools.

**GenDec would have to publish or provide:** the source at each release tag with
`Cargo.lock`; the cargo feature set and toolchain version the release binaries
are built with; a build recipe that is reproducible (`--locked`, pinned
toolchain, path remapping, fixed timestamps) so an independent rebuild matches;
the licences of all crates.

| Driver | Assessment |
|---|---|
| Auditability | Highest: source readable and rebuildable. |
| Supply chain | The pin moves from a tarball digest to a source commit plus `Cargo.lock`; the binary becomes our build output. An independent customer check needs reproducible builds, which nobody has measured for Pulse. |
| FSTEC | Best fit: the certified build compiles the source the laboratory received; the Rust toolchain joins the build-environment archive (§5). |
| Licensing | The licence travels with the source; the crate licences must be inventoried (cargo-about / cargo-deny). Under B1 a licence that is not Apache-2.0-compatible would block vendoring. |
| Cost | Highest, and recurring. A Rust stage in both Dockerfiles; multi-arch release builds on a host where amd64 is already emulated (`Jenkinsfile.publish`), with build time unmeasured; Trivy and the SBOM grow to cover the crates; a parity check against GenDec's own binary at the switch; under B1, a vendored tree to keep in step with GenDec. |
| Air-gap | B1 builds fully offline; B2 needs a crates mirror. |
| Images | The same engine built by us: a different binary digest from GenDec's release. |
| Scan semantics | Stable once switched, but the switch itself needs proof of parity (smoke plus the Pulse adapter fixtures, and a comparison run), and the cargo features must match GenDec's release build exactly. |

### C. Change the default distribution so a private dependency is not required

The advertised default stops depending on Pulse.

- **C1** — make `nmap` the default backend again: reintroduces the NPSL
  redistribution question #97 removed, and changes the default finding set.
- **C2** — a different, open engine as the default: a new product component; its
  choice would need comparative measurements of the kind #452 plans for the port
  backend.
- **C3** — Pulse becomes an opt-in add-on (a separate `-pulse` image or a
  customer-supplied binary), and the default image advertises less: ports,
  Nuclei and the TLS probe, without service/OS/CVE detection.

**GenDec would have to publish:** nothing for the default; for the add-on, the
same as option A, or nothing if Pulse is supplied under contract.

| Driver | Assessment |
|---|---|
| Auditability | Default image fully auditable; Pulse, where used, as opaque as today unless A is done too. |
| Supply chain | Default image carries no private component. |
| FSTEC | A certified configuration without Pulse has a smaller trusted base, but its detection is then whatever replaced Pulse, and that is what gets evaluated. |
| Licensing | C1 brings the NPSL back into the default image; C2 depends on the engine; C3 is clean. |
| Cost | C1 medium plus legal review; C2 high; C3 medium (another image variant, a changed default configuration, migration notes). All three cause finding churn in existing tenants: a CVE finding keeps its identity (`finding_key` is asset, CVE, port) only where the new engine reports the same CVE on the same port, and non-CVE findings are keyed by the engine's own script id (`pulse:<class>:<port>:<slug>`), so they close and reopen under new keys (evidence merging is #449's). |
| Air-gap | Default image self-contained. |
| Images | The default loses Pulse (C1/C3) or gains another engine (C1/C2). |
| Scan semantics | Changes by definition. Acceptable only as an explicit, versioned breaking change with a configuration value that names the new engine — never as a runtime fallback, which #340 rules out. |

### Side by side

| | A. Public signed releases | B. Source build path | C. Default without Pulse |
|---|---|---|---|
| Customer auditability | binary + evidence; source if A1 | source + rebuild | default: full; Pulse: none |
| Supply-chain verification | complete, for everyone | complete if reproducible | default: n/a |
| FSTEC | no change; A1 helps inventory | best fit | smaller TCB, different engine |
| Licensing | publish licence + notices | licence + crate inventory | C1: NPSL returns |
| Release engineering | low | high, recurring | medium to high |
| Air-gap | mirror assets | B1 offline | self-contained |
| Published images | unchanged | rebuilt by us | lose Pulse |
| Scan semantics | identical | stable after a proven switch | change |

## Recommendation

**Option A, preferably as A1 (make `onixus/GenDec` public). Keep a build-from-source
path (B) as a later decision for the certified configuration only. Do not take
option C for the default distribution.**

- The binary is already public in the images. A publishes the evidence that makes
  it checkable, which is the largest gain in auditability for the smallest
  amount of work, and GenDec already produces nearly all of it.
- A changes nothing a scan does: same bytes, same pin, same fail-loud behaviour.
- It removes `GENDEC_READ_TOKEN` from every build, so forks, customers and
  air-gapped mirrors can build the default image themselves.
- A1 over A2 because it also answers "can anyone read the code that produces
  the findings?" and is the prerequisite for B2, should the certification track
  need a source build.
- The certification track needs source for the laboratory and a build tied to
  it; the owner can supply the source privately under any option, and whether
  the certified build must compile Pulse itself is that track's S2/S3 decision,
  with measurements (build time, reproducibility) this record does not have.
- C is the only option that changes scan semantics, and it either brings the
  NPSL back or advertises less than the product does today.

If the source cannot be made public, **A2** keeps the recommendation's benefits
except source auditability, and the release contract says so plainly.

## Consequences

The release contract ([docs/release-contract.md](../release-contract.md)) already
states the policy that holds under every option: one Pulse version per
Shapoclyack release, how pins change, how security fixes ship, what a customer
can verify, and what happens without Pulse. Once an option is accepted:

| If accepted | Follow-up work |
|---|---|
| A (A1 or A2) | GenDec: publish the assets listed above, add provenance and notices. Here: drop the token from `Jenkinsfile`, `Jenkinsfile.publish`, the GitHub workflows and the Dockerfile comments; take the next pin from a signed release; add a `NOTICE` entry for Pulse; add a local-tarball input to `install-pulse.sh` for air-gapped host installs; move the release contract's GenDec-only checks to "everyone". |
| B | A Rust build stage in both Dockerfiles, a parity check against the GenDec binary at the switch, a source pin (commit + `Cargo.lock`) replacing the tarball pin, crate licences in `NOTICE`, and a measured build time for the release host. |
| C | A versioned breaking change: a new `service_probe.backend` default with release notes, a `-pulse` variant or documented add-on, updated `docs/third-party.md`, and a plan for the finding churn, aligned with #449. |

**Owed under every option, today:** docs/third-party.md records Pulse as MIT,
but that cannot be checked from outside GenDec, the installer copies only the
`pulse` binary out of the tarball, and `NOTICE` has no Pulse entry — so the
images redistribute a statically linked Rust binary without its licence or its
crates' notices. The owner holds the copyright on both projects, so this is a
gap for downstream redistributors rather than for the owner, but it has to be
closed with the verified licence text, not with a guess.

## Not decided here

- What Pulse probes and how its observations merge with Naabu and Nuclei —
  [#447](https://github.com/onixus/Shapoclyack/issues/447) and its children.
- Which engine discovers ports — [#452](https://github.com/onixus/Shapoclyack/issues/452).
- Signing and admission-verifying the Shapoclyack images — [#313](https://github.com/onixus/Shapoclyack/issues/313).
  GenDec's signature covers one embedded component, not the images.
- Mirrors and bundles for the enrichment feeds — [#339](https://github.com/onixus/Shapoclyack/issues/339).
