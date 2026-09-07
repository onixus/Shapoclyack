# dnsx, naabu and nuclei are all built from source here rather than taken from
# upstream release archives. Two accepted CRITICALs came out of those prebuilt
# binaries and neither had an upstream release carrying a fix: CVE-2025-68121
# is Go's own stdlib crypto/tls, fixed only by compiling on Go >= 1.24.13, and
# CVE-2026-56854 is golang.org/x/crypto below 0.55.0, an indirect dependency
# none of the three has bumped yet (dnsx 1.2.3 asks for 0.45.0, naabu 2.6.1 for
# 0.46.0, nuclei v3.11.1 for 0.53.0). Once we compile, both are ours to fix:
# the golang image supplies the toolchain and XCRYPTO_VERSION overrides every
# tool's own go.mod.
#
# The sha256 pins on the release zips went with the downloads. Module downloads
# are verified against Go's checksum database (GOSUMDB, on by default) instead —
# the same trade this file already made for nuclei, and per-module rather than
# per-archive.
#
# Upstream builds all three with CGO_ENABLED=0 and -s -w (their .goreleaser.yml
# and Makefile), which is what we do below, so these binaries differ from the
# released ones only in the toolchain and the x/crypto bump. In particular
# naabu's SYN path stays exactly as upstream ships it and needs no libpcap.
FROM golang:1.26-bookworm AS go-tools

# v3.11.1 is the first release that pins kin-openapi >= 0.144.0
# (GHSA-r277-6w6q-xmqw); do not downgrade below it.
ARG NUCLEI_VERSION=v3.11.1
ARG DNSX_VERSION=v1.2.3
ARG NAABU_VERSION=v2.6.1
# Forced over each tool's own, lower requirement — this is the CVE-2026-56854
# fix, and the build below fails if it does not land in the binary. Raise it,
# never lower it; drop the override only once every pinned tool asks for
# >= v0.55.0 by itself.
ARG XCRYPTO_VERSION=v0.56.0

# One throwaway module per tool, not one shared module: a shared module would
# resolve a single dependency graph across all three and silently upgrade one
# tool's dependencies to another's.
RUN set -eux; \
    build_tool() { \
      mkdir -p "/build/$1"; \
      cd "/build/$1"; \
      go mod init "shapoclyack.local/toolbuild/$1"; \
      go get "$2@$3"; \
      go get "golang.org/x/crypto@${XCRYPTO_VERSION}"; \
      CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "/out/$1" "$2"; \
      go version -m "/out/$1" \
        | grep -qE "golang.org/x/crypto[[:space:]]+${XCRYPTO_VERSION}([[:space:]]|$)"; \
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
FROM debian:bookworm-slim AS pulse-bin
ARG PULSE_VERSION=v1.1.0
ARG PULSE_GITHUB_REPO=onixus/GenDec
# GenDec's release job treats checksums.txt as optional (docs/release.md);
# this lets a build opt out explicitly. Same knob as the installer script.
ARG PULSE_SKIP_CHECKSUM=0
# One implementation for host installs and images: the script resolves the
# asset (via the API when a token is present -- the plain releases/download
# URL 404s for private repos), checks it against the release's checksums.txt,
# and installs it. Anything about how Pulse is fetched belongs in the script.
COPY scripts/install-pulse.sh /tmp/install-pulse.sh
# No `set -x`: the token would be traced into the build log (BuildKit keeps
# the unmasked trace in `docker buildx history logs`).
RUN --mount=type=secret,id=github_token,required=false \
    set -eu; \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq; \
    if [ -s /run/secrets/github_token ]; then \
      GITHUB_TOKEN="$(cat /run/secrets/github_token)"; export GITHUB_TOKEN; \
    fi; \
    PULSE_DEST=/out/pulse PULSE_VERSION="${PULSE_VERSION}" \
      PULSE_GITHUB_REPO="${PULSE_GITHUB_REPO}" PULSE_SKIP_CHECKSUM="${PULSE_SKIP_CHECKSUM}" \
      bash /tmp/install-pulse.sh; \
    test -x /out/pulse; \
    rm -f /tmp/install-pulse.sh; \
    rm -rf /var/lib/apt/lists/*

# Shapoclyack scanner pipeline image.
# Pinned by multi-arch index digest for reproducible, supply-chain-safe builds.
# python:3.12-slim
FROM python:3.12-slim@sha256:6c4dd321d176d61ea848dc8c73a4f7dbae8f70e0ee48bb411ea2f045b599fa8e

LABEL org.opencontainers.image.source="https://github.com/onixus/Shapoclyack" \
      org.opencontainers.image.title="shapoclyack-scanner" \
      org.opencontainers.image.description="Shapoclyack scanner pipeline image"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Phase 5: nmap is optional for the default Pulse path. Default INSTALL_NMAP=1
# keeps the full image (hybrid/vuln_legacy). Pulse-only lean builds:
#   docker build --build-arg INSTALL_NMAP=0 …
ARG INSTALL_NMAP=1
RUN set -eux; \
    apt-get update; \
    PKGS="ca-certificates curl fping git jq"; \
    if [ "${INSTALL_NMAP}" = "1" ]; then PKGS="${PKGS} nmap"; fi; \
    apt-get install -y --no-install-recommends ${PKGS}; \
    rm -rf /var/lib/apt/lists/*

# Pulse CLI for service_probe.backend=pulse|hybrid (GenDec release; see docs/pulse-backend.md).
COPY --from=pulse-bin /out/pulse /usr/local/bin/pulse

# Pin external scanner versions AND their artifact sha256 (per arch) so the
# downloaded bytes are verified against values committed in this repo.
# dnsx and naabu: built from source in the go-tools stage above, which is also
# where their versions are pinned — see the note there on why they are no
# longer fetched as release archives.
COPY --from=go-tools /out/dnsx /usr/local/bin/dnsx
COPY --from=go-tools /out/naabu /usr/local/bin/naabu

# Vulnerability NSE scripts (only when INSTALL_NMAP=1):
#  - nmap-vulners: maps service versions (-sV) to CVEs via the vulners.com API (needs egress).
#  - vulscan: offline CVE matching against bundled local databases (no internet required).
# Pinned to specific commits for reproducible, supply-chain-safe builds.
# Skipped for Pulse-only images (Phase 5); default CVE path is Pulse + Nuclei.
ARG NMAP_VULNERS_REF=0555294abe71857c581afc2ef62ea3ca5c7b7145
ARG VULSCAN_REF=bd642ed1bc9d96795a91cdf1acd8c93ceef2d07e
ARG INSTALL_NMAP=1
RUN set -eux; \
    if [ "${INSTALL_NMAP}" != "1" ]; then \
      echo "INSTALL_NMAP=0: skipping nmap-vulners/vulscan"; \
      exit 0; \
    fi; \
    git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/nmap-vulners; \
    git -C /usr/share/nmap/scripts/nmap-vulners checkout "${NMAP_VULNERS_REF}"; \
    git clone https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan; \
    git -C /usr/share/nmap/scripts/vulscan checkout "${VULSCAN_REF}"; \
    rm -rf /usr/share/nmap/scripts/nmap-vulners/.git /usr/share/nmap/scripts/vulscan/.git; \
    nmap --script-updatedb

# Nuclei: template-based HTTP vulnerability/misconfig scanning (opt-in, see
# scanner/pipeline/nuclei_scan.py). Binary built in the go-tools stage
# above; templates pinned to a release tag for the same reproducible-build
# reason as NMAP_VULNERS_REF/VULSCAN_REF above.
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
# Both cap_net_raw and cap_net_admin are required for naabu SYN, Pulse SYN/OS,
# and nmap -O (when present). NET_ADMIN is NOT in Docker's default bounding set,
# so every place this image actually runs scans already grants it explicitly:
# docker-compose.yml's cap_add, tests/e2e/run.sh's --cap-add, and the k8s
# api/agent/job/cronjob manifests' capabilities.add. A file capability that
# exceeds the runtime bounding set fails the *entire* execve() with EPERM
# instead of being silently dropped (verified via a real CI regression), so
# don't run this image (or its smoke-test) with zero --cap-add at all.
# Do NOT `apt-get purge libcap2-bin` afterward: fping (installed above) Depends
# on libcap2-bin for its own postinst setcap call, so purging it cascades into
# silently removing fping too (apt exits 0; the binary just vanishes).
ARG INSTALL_NMAP=1
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends libcap2-bin; \
    setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/naabu; \
    setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/pulse; \
    if [ "${INSTALL_NMAP}" = "1" ] && [ -x /usr/bin/nmap ]; then \
      setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap; \
    fi; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

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

# Bake real GeoIP/CVSS4/EPSS/KEV data into the image so a fresh deployment
# isn't limited to whatever the repo committed. Uses the keyless DB-IP provider
# (no license key to leak into image layers).
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
ARG ENRICHMENT_STRICT=0
RUN set -eu; \
    status=0; bash scripts/fetch-enrichment.sh || status=$?; \
    if [ "$status" -ge 2 ]; then \
      if [ "${ENRICHMENT_STRICT}" = "1" ]; then \
        echo "ENRICHMENT_STRICT=1: refusing to publish an image whose enrichment data is missing or stubbed" >&2; \
        exit 1; \
      fi; \
      echo "warning: enrichment data is missing or stubbed; continuing (ENRICHMENT_STRICT=0)" >&2; \
    fi

# Best-effort: refresh vulscan's offline CVE databases beyond whatever was
# bundled at the pinned VULSCAN_REF commit above, so "vuln-offline" scans use
# current data without needing a full image rebuild each time. Never fails
# the build — an offline/network-restricted build just keeps the
# pinned-commit CSVs, same as today.
RUN bash scripts/fetch-vulscan-db.sh -o /usr/share/nmap/scripts/vulscan || true

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
