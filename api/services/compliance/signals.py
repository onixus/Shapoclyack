"""Turning findings and estate facts into the vocabulary a control speaks.

A compliance control is not written about a CVE. PCI DSS 6.3.3 is about
*patching within a window*, ISO 27001:2022 A.8.24 is about *cryptography*, CIS
Safeguard 4.1 is about *secure configuration*. Mapping every finding to a
control directly would therefore mean one mapping table per framework, three
times over, kept in step by hand — and the first new framework would be a
fourth copy of the same judgements.

So findings are classified once, into a small closed vocabulary of **signals**,
and the frameworks are written against that vocabulary. Adding a framework is
then a catalogue entry, not a re-classification of the estate; changing how a
weak-TLS finding is recognised fixes it for all three at once.

Two things are deliberately *not* signals. There is no "compliant" signal — a
control passes because nothing failed it, which is the only claim the data
supports; and there is no severity-derived signal, because severity is an
attribute of the evidence a control weighs, not a category of failure.

Classification reads the denormalised fields on ``vulnerabilities`` — title,
``script_id``, ``port``, ``cve``, ``in_kev``, ``network_exposure`` — and never
the run artifacts: a control's status must not change because a run directory
was pruned.
"""

from __future__ import annotations

import re
from typing import Any

# The closed vocabulary. Framework catalogues may only reference these.
UNPATCHED_CVE = "unpatched_cve"
OVERDUE_REMEDIATION = "overdue_remediation"
KNOWN_EXPLOITED = "known_exploited"
INTERNET_EXPOSED = "internet_exposed_finding"
WEAK_CRYPTOGRAPHY = "weak_cryptography"
INSECURE_PROTOCOL = "insecure_protocol"
WEAK_CREDENTIALS = "default_or_weak_credentials"
MISCONFIGURATION = "misconfiguration"
EXPOSED_ADMIN_SERVICE = "exposed_admin_service"
INFORMATION_DISCLOSURE = "information_disclosure"
UNOWNED_ASSET = "unowned_asset"
UNCLASSIFIED_ASSET = "unclassified_asset"
STALE_ASSET = "stale_asset"
UNASSESSABLE_SOFTWARE = "unassessable_software"

SIGNALS: tuple[str, ...] = (
    UNPATCHED_CVE,
    OVERDUE_REMEDIATION,
    KNOWN_EXPLOITED,
    INTERNET_EXPOSED,
    WEAK_CRYPTOGRAPHY,
    INSECURE_PROTOCOL,
    WEAK_CREDENTIALS,
    MISCONFIGURATION,
    EXPOSED_ADMIN_SERVICE,
    INFORMATION_DISCLOSURE,
    UNOWNED_ASSET,
    UNCLASSIFIED_ASSET,
    STALE_ASSET,
    UNASSESSABLE_SOFTWARE,
)

SIGNAL_LABELS: dict[str, str] = {
    UNPATCHED_CVE: "Unpatched known vulnerability",
    OVERDUE_REMEDIATION: "Remediation past its SLA deadline",
    KNOWN_EXPLOITED: "Known-exploited vulnerability (CISA KEV)",
    INTERNET_EXPOSED: "Finding on an internet-facing service",
    WEAK_CRYPTOGRAPHY: "Weak or outdated cryptography",
    INSECURE_PROTOCOL: "Cleartext or deprecated protocol",
    WEAK_CREDENTIALS: "Default, weak or absent authentication",
    MISCONFIGURATION: "Insecure configuration",
    EXPOSED_ADMIN_SERVICE: "Administrative or database service reachable",
    INFORMATION_DISCLOSURE: "Unnecessary information disclosure",
    UNOWNED_ASSET: "Asset with no accountable owner",
    UNCLASSIFIED_ASSET: "Asset with no environment or data classification",
    STALE_ASSET: "Asset not observed by a recent scan",
    UNASSESSABLE_SOFTWARE: "Installed software that could not be assessed",
}

# Matched against the lower-cased "title | script_id" of a finding. Ordered
# tuples rather than a dict comprehension so the intent of each group stays
# readable next to the terms that produce it.
_CRYPTO_TERMS = (
    "ssl",
    "tls",
    "cipher",
    "certificate",
    "cert-expired",
    "self-signed",
    "sweet32",
    "poodle",
    "freak",
    "logjam",
    "heartbleed",
    "rc4",
    "md5",
    "sha1",
    "dh-params",
)
_INSECURE_PROTOCOL_TERMS = (
    "telnet",
    "ftp",
    "rlogin",
    "rsh",
    "tftp",
    "smbv1",
    "smb1",
    "snmp v1",
    "snmpv1",
    "cleartext",
    "plaintext",
    "http-only",
    "unencrypted",
)
_CREDENTIAL_TERMS = (
    "default-login",
    "default credential",
    "default password",
    "weak password",
    "anonymous",
    "no authentication",
    "unauthenticated",
    "brute",
    "guest login",
)
_MISCONFIGURATION_TERMS = (
    "misconfig",
    "directory listing",
    "debug",
    "open-redirect",
    "cors",
    "exposed panel",
    "backup file",
    "config file",
    "insecure header",
    "missing header",
)
_DISCLOSURE_TERMS = (
    "disclosure",
    "banner",
    "version leak",
    "phpinfo",
    "server-status",
    "verbose error",
    "exposed metadata",
)

# Ports whose service is administrative or a datastore. Reachability alone is
# not a vulnerability, which is why this signal never fails a control on its
# own — the catalogues pair it with exposure.
_ADMIN_PORTS = {
    "22",
    "23",
    "445",
    "1433",
    "1521",
    "2375",
    "2379",
    "3306",
    "3389",
    "5432",
    "5900",
    "5984",
    "6379",
    "9200",
    "11211",
    "27017",
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _haystack(finding: dict[str, Any]) -> str:
    parts = (finding.get("title") or "", finding.get("script_id") or "")
    return " | ".join(str(part) for part in parts).lower()


def _port(finding: dict[str, Any]) -> str:
    raw = str(finding.get("port") or "").strip()
    # "443/tcp" and "443" are both produced upstream depending on the source.
    return raw.split("/", 1)[0]


def classify_finding(finding: dict[str, Any], *, sla_reading: str | None = None) -> set[str]:
    """Signals raised by one tracked finding.

    ``sla_reading`` is ``api.services.vulnerabilities.sla_state``'s verdict. It
    is passed in rather than recomputed here because the deadline comparison
    needs a clock, and a classifier that reads the clock cannot be tested
    against a fixed estate.
    """

    signals: set[str] = set()
    cve = str(finding.get("cve") or "").strip()
    if _CVE_RE.match(cve):
        signals.add(UNPATCHED_CVE)
    if finding.get("in_kev"):
        signals.add(KNOWN_EXPLOITED)
    if sla_reading == "breached":
        signals.add(OVERDUE_REMEDIATION)
    if str(finding.get("network_exposure") or "") == "external":
        signals.add(INTERNET_EXPOSED)

    text = _haystack(finding)
    if any(term in text for term in _CRYPTO_TERMS):
        signals.add(WEAK_CRYPTOGRAPHY)
    if any(term in text for term in _INSECURE_PROTOCOL_TERMS):
        signals.add(INSECURE_PROTOCOL)
    if any(term in text for term in _CREDENTIAL_TERMS):
        signals.add(WEAK_CREDENTIALS)
    if any(term in text for term in _MISCONFIGURATION_TERMS):
        signals.add(MISCONFIGURATION)
    if any(term in text for term in _DISCLOSURE_TERMS):
        signals.add(INFORMATION_DISCLOSURE)
    if _port(finding) in _ADMIN_PORTS:
        signals.add(EXPOSED_ADMIN_SERVICE)
    return signals


def classify_asset(asset: dict[str, Any]) -> set[str]:
    """Signals raised by an asset's *context*, not by anything found on it.

    An estate where 45,000 of 50,000 assets have no owner fails an inventory
    control regardless of how few CVEs it has, and no finding-derived signal
    would ever say so.
    """

    signals: set[str] = set()
    if not (asset.get("owner_email") or "").strip():
        signals.add(UNOWNED_ASSET)
    if not (asset.get("environment") or "").strip() and not (
        asset.get("data_classification") or ""
    ).strip():
        signals.add(UNCLASSIFIED_ASSET)
    if str(asset.get("status") or "") != "active":
        signals.add(STALE_ASSET)
    return signals
