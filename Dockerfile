# nuclei has no arch-specific prebuilt zip we can sha256-pin the way dnsx/naabu
# are below (see nuclei-build stage note); `go install` at a pinned version tag
# instead relies on Go's own module checksum database (GOSUMDB, on by default)
# to verify every downloaded module cryptographically — arguably stronger than
# a hand-copied release sha256, and needs no manual checksum bookkeeping here.
FROM golang:1.25-bookworm AS nuclei-build
ARG NUCLEI_VERSION=v3.9.0
RUN CGO_ENABLED=0 GOBIN=/out go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}"

# Shapoclyack scanner image (Octo-man product pipeline).
# Pinned by multi-arch index digest for reproducible, supply-chain-safe builds.
# python:3.12-slim
FROM python:3.12-slim@sha256:6c4dd321d176d61ea848dc8c73a4f7dbae8f70e0ee48bb411ea2f045b599fa8e

LABEL org.opencontainers.image.source="https://github.com/onixus/Shapoclyack" \
      org.opencontainers.image.title="shapoclyack-scanner" \
      org.opencontainers.image.description="Octo-man scanner pipeline image published by Shapoclyack"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    fping \
    git \
    jq \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Pin external scanner versions AND their artifact sha256 (per arch) so the
# downloaded bytes are verified against values committed in this repo.
ARG DNSX_VERSION=1.2.3
ARG NAABU_VERSION=2.6.1
ARG DNSX_SHA256_AMD64=f58d93f511c1e1f653eac2ae1d44be8ea1ee8eba0d95825ab54ca2be6b9d703d
ARG DNSX_SHA256_ARM64=e52b1dc48ea4713ad0fd0e731edbe2156e094c44623d7dade3735790c703c8f3
ARG NAABU_SHA256_AMD64=018c4c9884dea971eda860435ede3021d1150732f34cfd245498c6726d8cab90
ARG NAABU_SHA256_ARM64=3adc2bb2395c3efff89623499b20eea66ef54924c485d3ae86762393a31736ea

RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    case "${ARCH}" in \
      amd64) GOARCH="amd64"; DNSX_SHA="${DNSX_SHA256_AMD64}"; NAABU_SHA="${NAABU_SHA256_AMD64}" ;; \
      arm64) GOARCH="arm64"; DNSX_SHA="${DNSX_SHA256_ARM64}"; NAABU_SHA="${NAABU_SHA256_ARM64}" ;; \
      *) echo "Unsupported architecture: ${ARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${GOARCH}.zip" -o /tmp/dnsx.zip; \
    curl -fsSL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${GOARCH}.zip" -o /tmp/naabu.zip; \
    echo "${DNSX_SHA}  /tmp/dnsx.zip" | sha256sum -c -; \
    echo "${NAABU_SHA}  /tmp/naabu.zip" | sha256sum -c -; \
    apt-get update && apt-get install -y --no-install-recommends unzip; \
    unzip -q -o /tmp/dnsx.zip dnsx -d /usr/local/bin; \
    unzip -q -o /tmp/naabu.zip naabu -d /usr/local/bin; \
    chmod +x /usr/local/bin/dnsx /usr/local/bin/naabu; \
    rm -f /tmp/dnsx.zip /tmp/naabu.zip; \
    apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Vulnerability NSE scripts:
#  - nmap-vulners: maps service versions (-sV) to CVEs via the vulners.com API (needs egress).
#  - vulscan: offline CVE matching against bundled local databases (no internet required).
# Pinned to specific commits for reproducible, supply-chain-safe builds.
ARG NMAP_VULNERS_REF=0555294abe71857c581afc2ef62ea3ca5c7b7145
ARG VULSCAN_REF=bd642ed1bc9d96795a91cdf1acd8c93ceef2d07e
RUN set -eux; \
    git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/nmap-vulners; \
    git -C /usr/share/nmap/scripts/nmap-vulners checkout "${NMAP_VULNERS_REF}"; \
    git clone https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan; \
    git -C /usr/share/nmap/scripts/vulscan checkout "${VULSCAN_REF}"; \
    rm -rf /usr/share/nmap/scripts/nmap-vulners/.git /usr/share/nmap/scripts/vulscan/.git; \
    nmap --script-updatedb

# Nuclei: template-based HTTP vulnerability/misconfig scanning (opt-in, see
# scanner/pipeline/nuclei_scan.py). Binary built in the nuclei-build stage
# above; templates pinned to a release tag for the same reproducible-build
# reason as NMAP_VULNERS_REF/VULSCAN_REF above.
COPY --from=nuclei-build /out/nuclei /usr/local/bin/nuclei
ARG NUCLEI_TEMPLATES_REF=v9.9.4
RUN set -eux; \
    git clone https://github.com/projectdiscovery/nuclei-templates.git /usr/share/nuclei-templates; \
    git -C /usr/share/nuclei-templates checkout "${NUCLEI_TEMPLATES_REF}"; \
    rm -rf /usr/share/nuclei-templates/.git

# Grant the raw-socket capability to the scanner binaries via file capabilities so
# host discovery / SYN scans / OS detection work as the non-root 'scanner' user.
# (A container-level --cap-add is NOT inherited by a non-root process on its own.)
# Only cap_net_raw is used: it is in Docker's default bounding set (so the binaries
# still exec when run without extra --cap-add), and is sufficient for scanning.
# Do NOT add cap_net_admin here: a file capability that isn't in the runtime
# bounding set doesn't get silently dropped on exec — the kernel fails the
# *entire* execve() with EPERM (verified: this broke a plain `docker run` with
# no --cap-add in CI). Since Docker's default bounding set excludes NET_ADMIN,
# baking it into the binary would break the image for every user who doesn't
# explicitly grant it, which is worse than the OS-detection limitation.
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends libcap2-bin; \
    setcap cap_net_raw+eip /usr/local/bin/naabu; \
    setcap cap_net_raw+eip /usr/bin/nmap; \
    apt-get purge -y libcap2-bin && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY scanner /app/scanner
COPY agent /app/agent
COPY scripts /app/scripts

# Best-effort: bake real GeoIP/CVSS4/EPSS/KEV data into the image so a fresh
# deployment isn't limited to the committed seed stubs (a 5-IP GeoIP demo
# overlay, a handful of seed CVEs). Uses the keyless DB-IP provider (no
# license key to leak into image layers); never fails the build — an
# offline/network-restricted build just keeps the seed data, same as today.
RUN bash scripts/fetch-enrichment.sh || true

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
