# Third-party components

This page is an operational inventory, not legal advice. Verify the exact image
contents and license texts for the release you distribute.

## This project's own licence

Shapoclyack is licensed under the **Apache License 2.0** ([LICENSE](../LICENSE)).
Attributions that must travel with the source and with every image built from it
live in [NOTICE](../NOTICE) — keep that file with any redistribution, and add to
it rather than replacing it if you build derivative images.

Apache-2.0 covers the code in this repository. It says nothing about the
third-party components below, which keep their own terms: an image is an
aggregate, and the most restrictive component in it governs what you may do with
that image. The practical consequence is the `-nmap` tag, which is the only
artifact here carrying terms that restrict redistribution — see the next
section.

## Scanner tools

**Nmap is not part of the default distribution.** The published
`ghcr.io/onixus/shapoclyack-scanner` and `...-aio` images (built by
`Jenkinsfile.publish` with `INSTALL_NMAP=0`) contain no Nmap binary, no NSE data, and no `nmap-vulners`/
`Vulscan` scripts — Pulse is the default `service_probe.backend` and covers
service/OS/CVE detection without Nmap. This removes the Nmap Public Source
License redistribution question for the images most people pull. A separate
`-nmap` tag (e.g. `shapoclyack-aio:latest-nmap`, built with `INSTALL_NMAP=1`)
is published alongside for anyone who explicitly wants classic NSE — review
the Nmap Public Source License's commercial/OEM redistribution restrictions
before distributing that tag further. Note that the `Dockerfile` and
`Dockerfile.allinone` themselves default to `ARG INSTALL_NMAP=1`: a local
`docker build` without `--build-arg INSTALL_NMAP=0` produces the Nmap-bearing
variant, so an image built by hand is not the same artifact as the default
published tag. The sensor image (the remote scanning node, `agent/worker.py`)
is the scanner image, so the same choice applies to every sensor host.

| Component | Documented pin/source | License family | Notes |
|---|---|---|---|
| Nmap | Debian package | Nmap Public Source License v0.95 | **Opt-in only** — `INSTALL_NMAP=1` / `-nmap` tag; review commercial/OEM redistribution restrictions before redistributing that tag |
| Naabu | `v2.6.1` (`NAABU_VERSION`) | MIT | ProjectDiscovery |
| DNSx | `v1.2.3` (`DNSX_VERSION`) | MIT | ProjectDiscovery |
| Pulse | GenDec release tag (`PULSE_VERSION`, currently `v1.1.0`) | MIT | Default service-probe backend (banner/OS/CVE detection); replaces Nmap in the default image |
| Nuclei | `NUCLEI_VERSION` build argument (currently `v3.11.1`) | MIT | Pin tool and templates |
| DejaVu Sans | Debian package `fonts-dejavu-core` (API and all-in-one images); a 27 KB Latin+Cyrillic subset in `tests/fixtures/fonts/` | Bitstream Vera licence + public domain (DejaVu changes) | Unicode face for PDF reports (`api/services/reports/render.py`); without it the renderer falls back to fpdf2's Latin-1 core fonts. The subset is a test fixture only, not shipped in any image |
| Playwright / Chromium | not pinned; optional host install | Apache-2.0 (Playwright) | **Not in the default image.** P4.4 screenshots skip when the package or browser is missing |
| nuclei-templates | Git reference (`NUCLEI_TEMPLATES_REF`, currently `v9.9.4`) | MIT | Template content has its own provenance |
| nmap-vulners | Git reference | GPL-3.0 | **Opt-in only** — `INSTALL_NMAP=1` / `-nmap` tag; NSE vulnerability lookup |
| Vulscan | Git reference (`VULSCAN_REF`, pinned commit) | GPL-3.0 | **Opt-in only** — `INSTALL_NMAP=1` / `-nmap` tag; NSE scripts and local data |

**Vulscan's CVE databases no longer come from computec.ch.** Vulscan's own
`update.sh` downloads its eight CSV databases from `www.computec.ch`, which now
sits behind a Cloudflare managed challenge: every non-browser client gets
`HTTP 403` with a `cf-mitigated: challenge` header, regardless of User-Agent.
`scripts/fetch-vulscan-db.sh` therefore pulls them from `scipag/vulscan` on
GitHub — the same maintainer, the same files, at the same GPL-3.0 terms as the
pinned clone the images already ship. `VULSCAN_BASE_URLS` overrides the source
list for closed networks; computec.ch remains the second entry in the default.

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

## Bundled data

These datasets are committed to the repository under `scanner/data/` and baked
into the images as the seed set, so the product is redistributing them and not
merely downloading them at build time. Refresh them with the matching script in
`scripts/`; each script merges rather than truncates, so a failed fetch keeps
the previous copy instead of publishing an empty one.

| Dataset | Path | Source | Terms | What is extracted |
|---------|------|--------|-------|-------------------|
| CVSS v4 | `cvss4/cvss4.json` | NVD | US government work, public domain | Base vectors and scores per CVE |
| EPSS | `epss/epss-overlay.json` | [FIRST.org](https://www.first.org/epss/) | **CC BY 4.0 — attribution required** | Exploit-prediction score and percentile per CVE |
| KEV | `kev/kev-overlay.json` | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | US government work, public domain | The list of CVE ids in the catalog |
| Exploit maturity | `exploit/exploit-overlay.json` | Exploit-DB `files_exploits.csv`; Metasploit `modules_metadata_base.json` | GPL-2.0 (Exploit-DB), BSD-3-Clause (Metasploit Framework) | CVE ids only — which CVEs have public exploit code or a packaged module. No exploit code, titles or descriptions are copied |

**Attribution.** EPSS data is provided by FIRST.org under CC BY 4.0. Any
redistribution of this repository or its images carries that obligation; keep
this notice with it.

**Why identifiers only.** The exploit overlay stores CVE ids and a maturity
rung, never exploit content. That keeps the redistribution to a set of factual
identifiers and keeps the images free of exploit code — which also matters for
the scanners that would otherwise flag them.

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
