# Security Policy

## Supported versions

Security fixes are applied to the **latest release** on [`main`](https://github.com/onixus/Shapoclyack/tree/main).
Published container images receive tags for the current semver release (see [Releases](https://github.com/onixus/Shapoclyack/releases)).

| Version   | Supported |
|-----------|-----------|
| `0.3.x` / `0.3.2.1` | Yes |
| `0.2.x`   | Yes (security fixes only; upgrade recommended) |
| `0.1.x`   | No        |
| `< 0.1.0` | No        |

We recommend always using the latest image tags, for example:

```bash
docker pull ghcr.io/onixus/shapoclyack-aio:0.3.2.1
docker pull ghcr.io/onixus/shapoclyack-scanner:0.3.2.1
docker pull ghcr.io/onixus/shapoclyack-api:0.3.2.1
```

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report issues in this repository (application code, Dockerfile, CI workflows, published GHCR image build) through one of these channels:

1. **[GitHub Private vulnerability reporting](https://github.com/onixus/Shapoclyack/security/advisories/new)** (preferred)
2. **Repository maintainer contact:** open a draft advisory or contact the [`onixus`](https://github.com/onixus) account owners via GitHub if private reporting is unavailable

Include as much detail as possible:

- Description and impact
- Affected version / image tag (`ghcr.io/onixus/shapoclyack-aio:…` or `-scanner` / `-api`)
- Steps to reproduce or proof-of-concept
- Suggested fix (if any)

We aim to acknowledge reports within **5 business days** and to provide a remediation plan or status update within **30 days** for confirmed issues, depending on severity and complexity.

## Scope

### In scope

- Python code under `scanner/` and `api/`
- React dashboard under `web/`
- Shell helpers under `scripts/` and `bench/` that ship with the repo
- `Dockerfile`, `Dockerfile.api`, `k8s/` manifests, and GitHub Actions workflows that build or publish images
- Misconfiguration or unsafe defaults in shipped YAML configs / demo credentials that lead to unintended exposure **of the scanner host or operator data**

### Out of scope

- **Findings produced by scans** (CVEs, misconfigurations, open ports on *your* targets). The tool is designed to report those; securing scanned infrastructure is the operator's responsibility.
- **Use of the scanner without authorization** on networks you do not own or lack written permission to test. Only scan systems you are explicitly allowed to assess.
- **Upstream tool vulnerabilities** (Nmap, naabu, dnsx, NSE scripts, base OS packages) unless we ship a clearly unsafe integration or fail to update pins after a fixed upstream release is available. Known accepted image exceptions are documented in [`.trivyignore`](../.trivyignore).
- Denial-of-service against third-party targets caused solely by running documented scan profiles at documented rates (operator responsibility to choose legal targets and rates).

## Safe harbor

We appreciate responsible disclosure. Good-faith research that:

- stays within the scope above,
- avoids privacy violations, data destruction, or service disruption beyond what is needed to demonstrate the issue, and
- gives us reasonable time to fix before public disclosure,

will not be pursued as a policy violation by the maintainers.

## How we secure releases

- **CI image gate:** Trivy fails the pipeline on fixable **CRITICAL** issues in the built image (`ignore-unfixed: true`; exceptions in `.trivyignore` are reviewed and time-bounded).
- **SBOM + provenance:** Release images on GHCR include SPDX SBOM and SLSA provenance attestations (see [docker-publish workflow](workflows/docker-publish.yml)).
- **Reproducible pins:** Base image digest, dnsx/naabu checksums, and NSE script commits are pinned in the `Dockerfile` (see README *Reproducible & Pinned Builds*).
- **Least privilege in containers:** Scanner runs as non-root UID `1000` (`scanner`); API as UID `1000` (`octo`). Raw sockets use file capabilities on `naabu`/`nmap` only.

## Operator security notes

- Grant **`NET_RAW` / `NET_ADMIN`** only to scanner Jobs/CronJobs; the API Deployment drops all capabilities.
- Do not expose the Docker socket to scanner or API pods.
- Treat PVC data under `output/` / `state/` as **sensitive** (banners, CVE findings, hostnames).
- Replace demo JWT secret and `*-change-me` API passwords before any shared or production use.
- Prefer cluster Secrets (`octo-man-api`, `octo-man-alerts`) over committing credentials to YAML.
- Pull images only from **`ghcr.io/onixus/shapoclyack-aio`**, **`shapoclyack-scanner`**, or **`shapoclyack-api`** and verify tags match [official releases](https://github.com/onixus/Shapoclyack/releases).

## Security updates

Subscribe to [Releases](https://github.com/onixus/Shapoclyack/releases) and [GitHub Security Advisories](https://github.com/onixus/Shapoclyack/security/advisories) for this repository.
Image rebuilds for dependency fixes are published under new patch/minor semver tags as needed.
