# dnsx, naabu and nuclei are all built from source here rather than taken from
# upstream release archives. Two accepted CRITICALs came out of those prebuilt
# binaries and neither had an upstream release carrying a fix: CVE-2025-68121
# is Go's own stdlib crypto/tls, fixed only by compiling on Go >= 1.24.13, and
# CVE-2026-56854 is golang.org/x/crypto below 0.55.0, an indirect dependency
# none of the three has bumped yet (dnsx 1.2.3 asks for 0.45.0, naabu 2.6.1 for
# 0.46.0, nuclei v3.11.1 for 0.53.0). Once we compile, both are ours to fix:
# the golang image supplies the toolchain and GO_SECURITY_PINS overrides every
# tool's own go.mod — that list also carries the go-git, x/mod and grpc fixes
# nuclei had not picked up.
#
# The sha256 pins on the release zips went with the downloads. Module downloads
# are verified against Go's checksum database (GOSUMDB, on by default) instead —
# the same trade this file already made for nuclei, and per-module rather than
# per-archive.
#
# Upstream builds all three with CGO_ENABLED=0 and -s -w (their .goreleaser.yml
# and Makefile), which is what we do below, so these binaries differ from the
# released ones only in the toolchain and the x/crypto bump. In particular
# naabu's SYN path stays exactly as upstream ships it. It dlopen()s libpcap at
# run time, and the runtime stage does not install libpcap0.8 on purpose: with
# it SYN recall was 0.57-0.85 in the speed farm, and ports.py only falls back to
# CONNECT on an empty SYN batch (#594). Until that gap is understood, SYN finds
# nothing here and the pipeline settles on CONNECT.
# Every stage is pinned by index digest, not only the final one (#313): a
# build stage's toolchain ends up in the binaries just as surely as the base
# ends up in the image. Renovate proposes the refresh as a reviewed PR.
FROM golang:1.26.10-bookworm@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51 AS go-tools

# v3.11.1 is the first release that pins kin-openapi >= 0.144.0
# (GHSA-r277-6w6q-xmqw); do not downgrade below it.
ARG NUCLEI_VERSION=v3.11.1
ARG DNSX_VERSION=v1.2.3
ARG NAABU_VERSION=v2.6.1

# Dependency versions forced over whatever the pinned tools ask for, because
# each closes a vulnerability none of them has picked up yet. Only ever raise
# these, and drop one only once every tool requires that version by itself:
#
#   x/crypto v0.57.0   CVE-2026-56854 (ssh source-address not enforced,
#                      CRITICAL) plus the 0.46-0.52 batch; all three tools;
#                      0.57.0 because x/net v0.60.0 requires it
#   go-git   v5.19.2   CVE-2026-71556 (arbitrary file read/write via symlink
#                      resolution); nuclei
#   x/mod    v0.41.0   CVE-2026-56864, CVE-2026-56865 (GOSUMDB / tlog
#                      verification bypass); nuclei
#   grpc     v1.83.2   CVE-2026-84304, CVE-2026-84445 (DoS); nuclei
#   utls     v1.8.2    CVE-2026-27017; dnsx
#   x/net    v0.60.0   CVE-2026-78669 (HTTP/2 SETTINGS flood DoS); all three
#                      tools. The stdlib half of it and CVE-2026-78667 need
#                      Go >= 1.26.9; the go-tools digest carries 1.26.10
#                      for CVE-2026-111943 (crypto/x509 CA trust mitigation)
#   kin-openapi v0.149.0
#                      CVE-2026-100349, -100351, -100352, -100353, -100354
#                      (HIGH: DoS and an auth bypass; fixed across 0.146.0-
#                      0.149.0) plus the MEDIUM -100347/-100348; nuclei, whose
#                      latest release (v3.11.1) still asks for 0.144.0
#   compress v1.18.7   CVE-2026-63209 (S2 dictionary integer overflow DoS);
#                      dnsx and naabu
#
# A pin must be >= what every tool already requires: `go get` refuses to
# downgrade a module a tool pins higher (naabu 2.6.1 requires utls v1.8.2)
# and fails the build outright rather than resolving around it.
#
# The list is applied to every tool, not only the one that reported the
# finding: a pin the binary does not link in costs nothing, and a tool that
# grows the dependency later inherits the fixed version rather than a fresh
# advisory.
ARG GO_SECURITY_PINS="golang.org/x/crypto@v0.57.0 github.com/go-git/go-git/v5@v5.19.2 golang.org/x/mod@v0.41.0 google.golang.org/grpc@v1.83.2 github.com/refraction-networking/utls@v1.8.2 golang.org/x/net@v0.60.0 github.com/getkin/kin-openapi@v0.149.0 github.com/klauspost/compress@v1.18.7"

# Keep builds on the reviewed, digest-pinned patched compiler. A dependency
# requiring a newer compiler must fail rather than download an unpinned toolchain.
ENV GOTOOLCHAIN=local

# One throwaway module per tool, not one shared module: a shared module would
# resolve a single dependency graph across all three and silently upgrade one
# tool's dependencies to another's.
#
# The tool and every pin go into a SINGLE `go get`. Getting them one at a time
# resolves the graph once per call and leaves go.sum missing entries for
# modules an earlier step had already settled (x/exp, via goflags), which the
# build then fails on.
#
# Each binary is then checked against the pin list: a pinned module that is
# linked in must be at the pinned version. "Not linked in at all" passes — a
# module absent from the binary carries no vulnerability into the image.
RUN set -eux; \
    build_tool() { \
      mkdir -p "/build/$1"; \
      cd "/build/$1"; \
      go mod init "shapoclyack.local/toolbuild/$1"; \
      go get "$2@$3" ${GO_SECURITY_PINS}; \
      CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "/out/$1" "$2"; \
      for pin in ${GO_SECURITY_PINS}; do \
        mod="${pin%@*}"; want="${pin#*@}"; \
        got="$(go version -m "/out/$1" | awk -v m="$mod" '$1=="dep" && $2==m {print $3}')"; \
        if [ -n "$got" ] && [ "$got" != "$want" ]; then \
          echo "$1: $mod resolved to $got, expected $want" >&2; \
          exit 1; \
        fi; \
      done; \
    }; \
    build_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx "${DNSX_VERSION}"; \
    build_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu "${NAABU_VERSION}"; \
    build_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei "${NUCLEI_VERSION}"; \
    rm -rf /build

# Pulse CLI from GenDec releases (not vendored source).
# Pin PULSE_VERSION to a GenDec release tag. Optional BuildKit secret
# github_token for private GenDec release assets. scripts/install-pulse.sh
# does the fetch and the checksums.txt check; see docs/pulse-backend.md.
# Docs: https://github.com/onixus/GenDec/blob/main/docs/release.md
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS pulse-bin
ARG PULSE_VERSION=v1.4.0
ARG PULSE_GITHUB_REPO=onixus/GenDec
# GenDec's release job treats checksums.txt as optional (docs/release.md);
# this lets a build opt out explicitly. Same knob as the installer script.
ARG PULSE_SKIP_CHECKSUM=0
# GenDec is a private repository, so the default build needs a token. Set
# INSTALL_PULSE=0 to build the image without Pulse and without a token:
#   docker build --build-arg INSTALL_PULSE=0 …
# The result has no service-probe backend: Pulse is the only one, and the
# scanner refuses to start a run with no binary rather than quietly producing a
# scan with no services (scanner/pipeline/pulse_probe.py). Such an image can run
# ports-only (`--skip-nse`) or be given a Pulse binary of your own.
ARG INSTALL_PULSE=1
# One implementation for host installs and images: the script resolves the
# asset (via the API when a token is present -- the plain releases/download
# URL 404s for private repos), checks it against the sha256 pinned in
# scripts/pulse-pinned.sha256, and installs it. Both files are copied into the
# same directory because the script looks for the pins next to itself.
# Anything about how Pulse is fetched belongs in the script.
COPY scripts/install-pulse.sh scripts/pulse-release-lib.sh scripts/pulse-pinned.sha256 /tmp/pulse/
# No `set -x`: the token would be traced into the build log (BuildKit keeps
# the unmasked trace in `docker buildx history logs`).
# /out mirrors /usr/local of the final stage: bin/pulse, plus the install
# record (#340) that scripts/verify-pulse-image.py reads back out of a
# published image to tie the binary to its pinned tarball. Both directories
# exist even with INSTALL_PULSE=0: the final stage copies each of them.
RUN --mount=type=secret,id=github_token,required=false \
    set -eu; \
    mkdir -p /out/bin /out/share; \
    if [ "${INSTALL_PULSE}" != "1" ]; then \
      echo "INSTALL_PULSE=0: building without the Pulse CLI"; \
      rm -rf /tmp/pulse; \
      exit 0; \
    fi; \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq; \
    if [ -s /run/secrets/github_token ]; then \
      GITHUB_TOKEN="$(cat /run/secrets/github_token)"; export GITHUB_TOKEN; \
    fi; \
    PULSE_DEST=/out/bin/pulse PULSE_RECORD=/out/share/shapoclyack/pulse-install.txt \
      PULSE_VERSION="${PULSE_VERSION}" \
      PULSE_GITHUB_REPO="${PULSE_GITHUB_REPO}" PULSE_SKIP_CHECKSUM="${PULSE_SKIP_CHECKSUM}" \
      bash /tmp/pulse/install-pulse.sh; \
    test -x /out/bin/pulse; \
    test -s /out/share/shapoclyack/pulse-install.txt; \
    rm -rf /tmp/pulse; \
    rm -rf /var/lib/apt/lists/*

# Enrichment data (GeoIP, CVSS4, EPSS, KEV, vendor advisories) is the same bytes
# on every architecture, so it is fetched once per build, on the build host's
# own platform, and the final stage copies the result in. Fetched inside the
# final stage it ran once per target platform, and the NVD walk alone is ~57
# pages: a multi-arch publish paged it four times in parallel and NVD throttled
# them into timeouts.
#
# This stage is byte-for-byte the same in Dockerfile and Dockerfile.allinone
# (tests/test_enrichment_stage.py holds them to it), so the second image of a
# build takes it from the BuildKit cache instead of fetching again. api/ and
# agent/ are here only for scripts/fetch-advisories.py; the scanner image ships
# the fetched advisories along with the rest rather than fork the stage. The
# fetch scripts are stdlib-only, so nothing is pip-installed here.
#
# Two failures live here and they are not the same (#246):
#   - a source was unreachable (exit 1). The previous data is still in place and
#     still usable; a foreign server having a bad day must not fail a build, so
#     this stays a warning in every build. The manifest the script writes records
#     which datasets were left behind, and GET /api/system reports it — that is
#     what stops a degraded image from looking identical to a fresh one.
#   - a required dataset is missing or is a stub (exit 2). The risk model would
#     be scoring blind. ENRICHMENT_STRICT=1 refuses to build such an image; the
#     release pipeline (Jenkinsfile.publish) sets it, because a published image
#     is the one that outlives the operator's memory of this build log. A dev or
#     branch build keeps warning, so nobody is blocked by a bad network.
#
# Uses the keyless DB-IP provider (no license key to leak into image layers).
FROM --platform=$BUILDPLATFORM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS enrichment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY scanner /app/scanner
# The seed floor fetch-enrichment.sh reads; each final stage keeps its own copy
# at the same path for the runtime refresh.
COPY scanner/data /opt/shapoclyack/seed-data
COPY api /app/api
COPY agent /app/agent
COPY scripts /app/scripts
ARG ENRICHMENT_STRICT=0
# Vendor advisories are the one enrichment source that is opt-in at runtime
# (api/services/advisories/fetch.py refuses without it), and an image build is
# exactly the place the opt-in belongs: the alternative is shipping the
# committed seeds, and a seed cannot assess a real host. It covers a handful of
# statements, so a Windows endpoint matched against it reads as far cleaner
# than it is -- which is the worst way for a security tool to be wrong.
#
# ADVISORY_FETCH=0 turns it back off for a build with no route to the vendors'
# feeds; the image then carries the seeds and says so on the System page.
ARG ADVISORY_FETCH=1
# Builds consume the parked, checksummed NVD snapshot, independent of layer cache.
# Runtime refresh remains enabled. Opt in only for a deliberate live build.
ARG NVD_FETCH=0
# Optional NVD key is available only to this enrichment step, never an image ENV.
RUN --mount=type=secret,id=nvd_api_key,required=false \
    set -eu; \
    if [ -s /run/secrets/nvd_api_key ]; then \
      NVD_API_KEY="$(cat /run/secrets/nvd_api_key)"; export NVD_API_KEY; \
    fi; \
    python3 scripts/nvd_snapshot.py verify /opt/shapoclyack/seed-data/cvss4/cvss4.json; \
    case "${NVD_FETCH}" in 0|1) ;; *) echo "NVD_FETCH must be 0 or 1" >&2; exit 2 ;; esac; \
    export OCTO_CVSS4_FETCH_ENABLED="${NVD_FETCH}"; \
    export OCTO_ADVISORY_FETCH_ENABLED="$( [ "${ADVISORY_FETCH}" = "1" ] && echo true || echo false )"; \
    status=0; bash scripts/fetch-enrichment.sh || status=$?; \
    if [ "$status" -ge 2 ]; then \
      if [ "${ENRICHMENT_STRICT}" = "1" ]; then \
        echo "ENRICHMENT_STRICT=1: refusing to publish an image whose enrichment data is missing or stubbed" >&2; \
        exit 1; \
      fi; \
      echo "warning: enrichment data is missing or stubbed; continuing (ENRICHMENT_STRICT=0)" >&2; \
    fi

# Shapoclyack scanner pipeline image.
# Pinned by multi-arch index digest for reproducible, supply-chain-safe builds.
# python:3.12-slim
# Refresh deliberately: the immutable digest is reproducible, not automatically
# current. Stable Debian packages without a vendor fix remain visible in the
# full Trivy report; the gate blocks every fixable HIGH and CRITICAL. Do not
# remove Essential system packages or introduce CVE exceptions to hide them.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

LABEL org.opencontainers.image.source="https://github.com/onixus/Shapoclyack" \
      org.opencontainers.image.title="shapoclyack-scanner" \
      org.opencontainers.image.description="Shapoclyack scanner pipeline image"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Nmap is not bundled and not used (NPSL licence, issue #97; docs/nmap-migration.md).
RUN set -eux; \
    apt-get update; \
    # iproute2: Pulse's ARP discovery (discovery.l2) reads neighbours through
    # `ip -4 neigh`. Without `ip` it reports 0 live hosts, prints nothing and
    # exits 0 (docs/pulse-backend.md#l2-discovery).
    PKGS="ca-certificates curl fping git iproute2 jq"; \
    apt-get install -y --no-install-recommends ${PKGS}; \
    # Security updates the pinned base digest does not carry yet: Debian has
    # published them, python:3.12-slim has not been rebuilt on top. Upgrade
    # only the named packages, and assert the version so a no-op upgrade fails
    # here rather than at the Trivy gate. Drop a line once a base bump covers it.
    apt-get install -y --no-install-recommends --only-upgrade libpcre2-8-0; \
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libpcre2-8-0)" ge '10.46-1~deb13u3'; \
    apt-get install -y --no-install-recommends --only-upgrade curl libcurl3t64-gnutls libcurl4t64; \
    for pkg in curl libcurl3t64-gnutls libcurl4t64; do \
        dpkg --compare-versions "$(dpkg-query -W -f='${Version}' "$pkg")" ge '8.14.1-2+deb13u7'; \
    done; \
    rm -rf /var/lib/apt/lists/*

# Pulse CLI for service_probe.backend=pulse|hybrid (GenDec release; see docs/pulse-backend.md).
# Copied as directories, not as /out/bin/pulse: with --build-arg INSTALL_PULSE=0
# the stage leaves both empty and this copies nothing, which is how the image
# builds at all without a token for the private GenDec repository. Otherwise
# it lands /usr/local/bin/pulse and /usr/local/share/shapoclyack/pulse-install.txt.
# One COPY per directory: a COPY also stamps its source directory's metadata
# onto the target, and /usr/local itself is not the pulse-bin stage's to set.
COPY --from=pulse-bin /out/bin/ /usr/local/bin/
COPY --from=pulse-bin /out/share/ /usr/local/share/

# Pin external scanner versions AND their artifact sha256 (per arch) so the
# downloaded bytes are verified against values committed in this repo.
# dnsx and naabu: built from source in the go-tools stage above, which is also
# where their versions are pinned — see the note there on why they are no
# longer fetched as release archives.
COPY --from=go-tools /out/dnsx /usr/local/bin/dnsx
COPY --from=go-tools /out/naabu /usr/local/bin/naabu

# Nuclei: template-based HTTP vulnerability/misconfig scanning (opt-in, see
# scanner/pipeline/nuclei_scan.py). Binary built in the go-tools stage
# above; templates pinned to a release tag for the same reproducible-build
# reason as the other pinned refs above.
COPY --from=go-tools /out/nuclei /usr/local/bin/nuclei
ARG NUCLEI_TEMPLATES_REF=v9.9.4
# Shallow-clone the tag directly: a full clone pulls years of history that the
# next line throws away, which took ~an hour and broke often enough on a flaky
# link to block the build entirely. --branch resolves the same tag, so the
# pinned tree is identical.
RUN set -eux; \
    git clone --depth 1 --branch "${NUCLEI_TEMPLATES_REF}" \
      https://github.com/projectdiscovery/nuclei-templates.git /usr/share/nuclei-templates; \
    rm -rf /usr/share/nuclei-templates/.git

# Grant raw-socket capabilities to the scanner binaries via file capabilities so
# host discovery / SYN scans / OS detection work as the non-root 'scanner' user.
# (A container-level --cap-add alone is NOT inherited by a non-root process on
# exec without this — the binary needs the file capability bit set too.)
# Both cap_net_raw and cap_net_admin are required for naabu SYN, Pulse SYN/OS.
# NET_ADMIN is NOT in Docker's default bounding set,
# so every place this image actually runs scans already grants it explicitly:
# docker-compose.yml's cap_add, tests/e2e/run.sh's --cap-add, and the k8s
# api/agent/job/cronjob manifests' capabilities.add. A file capability that
# exceeds the runtime bounding set fails the *entire* execve() with EPERM
# instead of being silently dropped (verified via a real CI regression), so
# don't run this image (or its smoke-test) with zero --cap-add at all.
# Do NOT `apt-get purge libcap2-bin` afterward: fping (installed above) Depends
# on libcap2-bin for its own postinst setcap call, so purging it cascades into
# silently removing fping too (apt exits 0; the binary just vanishes).
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends libcap2-bin; \
    setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/naabu; \
    if [ -x /usr/local/bin/pulse ]; then \
      setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/pulse; \
    fi; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Installed from the hash-pinned locks, not from requirements.txt (#313): every
# transitive dependency is pinned and every file checked against its sha256,
# and --only-binary keeps pip from building an sdist whose build dependencies
# it would fetch unchecked. pip itself is upgraded first, from its own lock;
# requirements-pip.txt says why that version. Regenerate the locks with
# scripts/lock-python-deps.sh.
# Package installers are build-only; remove pip and its bundled bootstrap wheel
# after the locked install so vendored tooling does not ship in runtime images.
COPY requirements-pip.lock requirements.lock /app/
RUN set -eux; \
    pip install --no-cache-dir --require-hashes --only-binary=:all: -r /app/requirements-pip.lock; \
    pip install --no-cache-dir --require-hashes --only-binary=:all: -r /app/requirements.lock; \
    python -m pip uninstall --yes pip; \
    python -c "import ensurepip, pathlib, shutil; shutil.rmtree(pathlib.Path(ensurepip.__file__).parent)"; \
    python -c "import importlib.util; assert importlib.util.find_spec('pip') is None; assert importlib.util.find_spec('ensurepip') is None"

# The images redistribute scanner/data, and the EPSS overlay in it is CC BY 4.0.
# The attribution has to travel with the bytes, not stay in the repository.
COPY LICENSE NOTICE /app/
COPY scanner /app/scanner
# Pristine copy of the committed enrichment seed. scripts/fetch-enrichment.sh
# uses this as its floor: the runtime target is /app/scanner/data itself, so
# when a shared enrichment volume is mounted there it shadows the baked seed
# and the floor would have nothing to copy from.
COPY scanner/data /opt/shapoclyack/seed-data
COPY agent /app/agent
COPY scripts /app/scripts

# Fetched once per build in the enrichment stage above; laid over the
# committed seed copied with scanner/.
COPY --from=enrichment /app/scanner/data /app/scanner/data

# Best-effort: refresh nuclei-templates beyond whatever was bundled at the
# pinned NUCLEI_TEMPLATES_REF above (nuclei's own -update-templates flag,
# same non-fatal build-step philosophy as the fetches above).
RUN bash scripts/fetch-nuclei-templates.sh /usr/share/nuclei-templates || true

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin scanner && \
    mkdir -p /app/scanner/output /app/scanner/state && \
    chown -R scanner:scanner /app

USER scanner

VOLUME ["/app/scanner/inputs", "/app/scanner/output", "/app/scanner/state", "/app/scanner/config"]

ENTRYPOINT ["python", "-m", "scanner.main"]
CMD ["--config", "scanner/config/default.yaml"]
