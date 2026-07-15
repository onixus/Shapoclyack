# Security Policy

## Supported versions

Security fixes are applied to the **latest release** on [`master`](https://github.com/onixus/Octo-man/tree/master).
Published container images receive tags for the current semver release (see [Releases](https://github.com/onixus/Octo-man/releases)).

| Version   | Supported |
|-----------|-----------|
| `0.2.x`   | Yes       |
| `0.1.x`   | Yes (security fixes only; upgrade to `0.2.x` recommended) |
| `< 0.1.0` | No        |

We recommend always using the latest image tag, for example:

```bash
docker pull ghcr.io/onixus/octo-man:0.2.0
```

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report issues in this repository (application code, Dockerfile, CI workflows, published GHCR image build) through one of these channels:

1. **[GitHub Private vulnerability reporting](https://github.com/onixus/Octo-man/security/advisories/new)** (preferred)
2. **Repository maintainer contact:** open a draft advisory or contact the [`onixus`](https://github.com/onixus) account owners via GitHub if private reporting is unavailable

Include as much detail as possible:

- Description and impact
- Affected version / image tag (`ghcr.io/onixus/octo-man:…`)
- Steps to reproduce or proof-of-concept
- Suggested fix (if any)

We aim to acknowledge reports within **5 business days** and to provide a remediation plan or status update within **30 days** for confirmed issues, depending on severity and complexity.

## Scope

### In scope

- Python code under `scanner/`
- Shell helpers under `scripts/` and `bench/` that ship with the repo
- `Dockerfile`, `docker-compose.yml`, and GitHub Actions workflows that build or publish the image
- Misconfiguration or unsafe defaults in shipped YAML configs that lead to unintended exposure **of the scanner host or operator data**

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
- **Least privilege in container:** Scanner runs as non-root user `scanner`; raw sockets use file capabilities on `naabu`/`nmap` only.

## Operator security notes

- Run the container with **`NET_RAW` / `NET_ADMIN`** only when needed for scanning; do not grant extra capabilities.
- Mount only required volumes (`inputs`, `output`, `config`, `state`); do not expose the Docker socket to the scanner container.
- Treat `scanner/output/` as **sensitive** (scan results, possible credentials in service banners, vulnerability data).
- Pull images only from **`ghcr.io/onixus/octo-man`** and verify tags match [official releases](https://github.com/onixus/Octo-man/releases).

## Security updates

Subscribe to [Releases](https://github.com/onixus/Octo-man/releases) and [GitHub Security Advisories](https://github.com/onixus/Octo-man/security/advisories) for this repository.
Image rebuilds for dependency fixes are published under new patch/minor semver tags as needed.
