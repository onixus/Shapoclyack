# Third-party components

This page is an operational inventory, not legal advice. Verify the exact image
contents and license texts for the release you distribute.

## Scanner tools

| Component | Documented pin/source | License family | Notes |
|---|---|---|---|
| Nmap | Debian package | Nmap Public Source License v0.95 | Review commercial/OEM redistribution restrictions |
| Naabu | `2.6.1` | MIT | ProjectDiscovery |
| DNSx | `1.2.3` | MIT | ProjectDiscovery |
| Nuclei | Docker build argument | MIT | Pin tool and templates |
| nuclei-templates | Git reference | MIT | Template content has its own provenance |
| nmap-vulners | Git reference | GPL-3.0 | NSE vulnerability lookup |
| Vulscan | Git reference | GPL-3.0 | NSE scripts and local data |

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
