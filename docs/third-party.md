# Third-party components

This page is an operational inventory, not legal advice. Verify the exact image
contents and license texts for the release you distribute.

## Scanner tools

**Nmap is not part of the default distribution.** The default
`ghcr.io/onixus/shapoclyack-scanner` and `...-aio` images (built with
`INSTALL_NMAP=0`) contain no Nmap binary, no NSE data, and no `nmap-vulners`/
`Vulscan` scripts — Pulse is the default `service_probe.backend` and covers
service/OS/CVE detection without Nmap. This removes the Nmap Public Source
License redistribution question for the images most people pull. A separate
`-nmap` tag (e.g. `shapoclyack-aio:latest-nmap`, built with `INSTALL_NMAP=1`)
is published alongside for anyone who explicitly wants classic NSE — review
the Nmap Public Source License's commercial/OEM redistribution restrictions
before distributing that tag further.

| Component | Documented pin/source | License family | Notes |
|---|---|---|---|
| Nmap | Debian package | Nmap Public Source License v0.95 | **Opt-in only** — `INSTALL_NMAP=1` / `-nmap` tag; review commercial/OEM redistribution restrictions before redistributing that tag |
| Naabu | `2.6.1` | MIT | ProjectDiscovery |
| DNSx | `1.2.3` | MIT | ProjectDiscovery |
| Pulse | GenDec release tag (`PULSE_VERSION`) | MIT | Default service-probe backend (banner/OS/CVE detection); replaces Nmap in the default image |
| Nuclei | Docker build argument | MIT | Pin tool and templates |
| Playwright / Chromium | not pinned; optional host install | Apache-2.0 (Playwright) | **Not in the default image.** P4.4 screenshots skip when the package or browser is missing |
| nuclei-templates | Git reference | MIT | Template content has its own provenance |
| nmap-vulners | Git reference | GPL-3.0 | **Opt-in only** — `INSTALL_NMAP=1` / `-nmap` tag; NSE vulnerability lookup |
| Vulscan | Git reference | GPL-3.0 | **Opt-in only** — `INSTALL_NMAP=1` / `-nmap` tag; NSE scripts and local data |

## Base runtime

The Python images derive from `python:3.12-slim` and include Debian packages.
Relevant license families include:

| Component | License |
|---|---|
| CPython | PSF License Agreement |
| ca-certificates | MPL-2.0 data bundle |
| curl | curl license |
| git | GPL-2.0 |
| jq | MIT |
| unzip | Info-ZIP |

## Application dependencies

Python and JavaScript dependencies are locked in requirement and package-lock
files. Generate an SBOM from the exact release image and treat that output as
authoritative for compliance and vulnerability review.

## Release checks

- use immutable source and image tags;
- verify published checksums/digests;
- generate SBOMs for all three images;
- scan the final image, not only manifests;
- retain third-party notices required by the actual dependency set;
- review data-source terms for GeoIP, EPSS, KEV, and any enabled passive
  discovery provider.
