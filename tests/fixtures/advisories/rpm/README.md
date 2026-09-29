# Reduced vendor metadata fixtures

`rhel-reduced.json` retains selected binary/source RPM products, platform
relationships and CVE status fields from Red Hat RHSA-2025:23127.
`suse-reduced.json` retains product relationships and recommendation/vendor-fix
fields from SUSE-SU-2024:3307-1. Fetched on 2026-09-29; source URLs, original
byte digests and reduced fixture digests are in `provenance.json`.

Attribution: Red Hat Product Security, Red Hat Inc.; SUSE Product Security
Team, SUSE. Upstream publishes security data under CC BY 4.0. These fixtures
are modified structural extracts, not complete CSAF documents, production
feeds or signed vendor statements. Free-text narratives and boilerplate were
removed; factual product IDs, versions, CVEs, relationships and dates remain.

The test importer digests the reduced file as such, never claims that its bytes
equal the original. Fixtures are not application seeds. ALAS cases in
`test_rpm_advisories.py` are synthetic updateinfo XML, not live captures.
