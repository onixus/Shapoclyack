"""Certificate name extraction and hostname matching (P4.1).

Pure functions over the ``cert`` dicts that ``tls_posture.py`` already builds
from its three sources (nmap ``ssl-cert`` NSE output, Pulse ``tls[]`` rows, and
the stdlib ``tls_probe`` handshake). No I/O, no network -- the certificate has
already been collected by the time anything here runs.

Two jobs:

  * ``cert_names`` -- pull the identities a certificate actually asserts:
    the subject commonName plus every ``subjectAltName`` entry, split into DNS
    names and IP addresses. The three sources format these differently (an
    nmap DN string, a bare Pulse CN, an OpenSSL-flattened DN), so extraction
    is deliberately tolerant of all three shapes.
  * ``hostname_mismatch`` -- compare those identities against the names the
    scan used to reach the endpoint, per RFC 6125 matching rules (a leftmost
    ``*`` wildcard covers exactly one label and never a bare public suffix).

WHY ONLY FORWARD NAMES: the expected-name set comes from the *forward* half of
``hostnames.json`` -- the FQDNs the operator put into the scan, which resolved
to this IP. PTR names are deliberately excluded: a reverse name is assigned by
whoever owns the address block, not by whoever owns the service, so
``ec2-1-2-3-4.compute.amazonaws.com`` failing to appear in a certificate is the
normal case and not a finding. Feeding PTR names in would make this check emit
a mismatch for most of the internet.

NO EXPECTATION, NO FINDING: an endpoint reached only by IP has nothing to
compare against, so it produces no finding rather than a mismatch. Absence of
evidence is not evidence of misconfiguration -- the same principle that keeps
``self_signed`` tagged as a heuristic in ``tls_posture.py``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# nmap and the stdlib both flatten the distinguished name; Pulse hands us the
# commonName on its own. This finds the CN in the first two shapes.
_COMMON_NAME_RE = re.compile(r"commonName=([^/,]+)")

# SAN entries are rendered as "<type>:<value>" by every source we read:
# nmap ("DNS:a.example.com"), the stdlib probe ("IP Address:10.0.0.1"), and
# Pulse when it carries typed entries. Untyped Pulse values are treated as DNS.
_SAN_DNS_PREFIXES = ("dns", "dns name")
_SAN_IP_PREFIXES = ("ip", "ip address", "ipaddress")


def _normalize_dns(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _split_san(raw: str) -> list[str]:
    """Split a SAN blob on commas -- every source joins entries that way."""
    return [part.strip() for part in re.split(r"[,\n]", raw) if part.strip()]


def _subject_common_name(cert: dict[str, Any]) -> str:
    """The subject CN, whichever way the source spelled it."""
    explicit = cert.get("subject_cn")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    subject = cert.get("subject")
    if isinstance(subject, str) and subject.strip():
        match = _COMMON_NAME_RE.search(subject)
        if match:
            return match.group(1).strip()
        # Pulse can hand back a bare name with no ``key=value`` structure at
        # all; treat it as the CN only when it looks like a name, not a DN.
        if "=" not in subject:
            return subject.strip()
    return ""


def cert_names(cert: dict[str, Any] | None) -> dict[str, list[str]]:
    """Extract the identities a certificate asserts.

    Returns ``{"dns": [...], "ip": [...], "common_name": [...]}`` -- DNS names
    lowercased and trailing-dot-stripped, IPs left verbatim, and the subject CN
    repeated under ``common_name`` so callers can tell a CN-only certificate
    (no SAN at all) from one that lists the name properly.
    """
    dns: list[str] = []
    ips: list[str] = []
    common: list[str] = []

    if not isinstance(cert, dict):
        return {"dns": [], "ip": [], "common_name": []}

    common_name = _subject_common_name(cert)
    if common_name:
        normalized = _normalize_dns(common_name)
        common.append(normalized)
        # A CN holding a literal IP is an IP identity, not a DNS one.
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            dns.append(normalized)
        else:
            ips.append(normalized)

    san = cert.get("san")
    if isinstance(san, list):
        entries = [str(item) for item in san]
    elif isinstance(san, str):
        entries = _split_san(san)
    else:
        entries = []

    for entry in entries:
        kind, _, value = entry.partition(":")
        if not value:
            kind, value = "dns", entry
        kind_norm = kind.strip().lower()
        value = value.strip()
        if not value:
            continue
        if kind_norm in _SAN_IP_PREFIXES:
            if value not in ips:
                ips.append(value)
            continue
        if kind_norm in _SAN_DNS_PREFIXES or ":" not in entry:
            normalized = _normalize_dns(value)
            if normalized and normalized not in dns:
                dns.append(normalized)
            continue
        # An unknown SAN type (email, URI, ...) is not a host identity; the
        # certificate is not misconfigured for carrying one, so it is ignored.

    return {"dns": dns, "ip": ips, "common_name": common}


def matches_name(cert_name: str, hostname: str) -> bool:
    """RFC 6125 name matching for one certificate name against one hostname.

    A leftmost ``*`` matches exactly one label and only in the leftmost
    position, so ``*.example.com`` covers ``a.example.com`` but neither
    ``example.com`` nor ``a.b.example.com``. Partial-label wildcards
    (``w*.example.com``) are not honoured -- they are rejected by modern
    clients, so treating them as a match would under-report.
    """
    cert_name = _normalize_dns(cert_name)
    hostname = _normalize_dns(hostname)
    if not cert_name or not hostname:
        return False
    if cert_name == hostname:
        return True
    if not cert_name.startswith("*."):
        return False

    suffix = cert_name[2:]
    if not suffix or "*" in suffix:
        return False
    # A wildcard must not stand in for a public-suffix-level label: "*.com"
    # is refused by clients, so it is not a match here either.
    if suffix.count(".") < 1:
        return False
    if not hostname.endswith("." + suffix):
        return False
    leftmost = hostname[: -(len(suffix) + 1)]
    return bool(leftmost) and "." not in leftmost


def covers_hostname(names: dict[str, list[str]], hostname: str) -> bool:
    """True when any DNS name in the certificate matches ``hostname``."""
    return any(matches_name(candidate, hostname) for candidate in names.get("dns", []))


def expected_names(entry: dict[str, Any] | None) -> list[str]:
    """The DNS names a scan legitimately expects in an endpoint's certificate.

    Takes one ``hostnames.json`` entry (``{"forward": [...], "reverse": [...],
    ...}``) and returns only the forward names -- see the module docstring for
    why PTR names are excluded.
    """
    if not isinstance(entry, dict):
        return []
    forward = entry.get("forward")
    if not isinstance(forward, list):
        return []
    out: list[str] = []
    for name in forward:
        normalized = _normalize_dns(str(name))
        if not normalized or normalized in out:
            continue
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            out.append(normalized)
    return out


def hostname_mismatch(
    cert: dict[str, Any] | None,
    hostnames: list[str],
) -> dict[str, Any] | None:
    """Build a ``cert_name_mismatch`` issue, or ``None`` when there is nothing to say.

    Returns ``None`` when the certificate asserts no DNS identity at all (a
    parse miss is not a finding), when no expected name is known, or when any
    expected name matches. A mismatch is reported only when *every* expected
    name fails against *every* certificate name -- a host answering for several
    names where one matches is serving a correct certificate for that name.
    """
    names = cert_names(cert)
    if not names["dns"]:
        return None

    checked = [_normalize_dns(name) for name in hostnames if _normalize_dns(name)]
    checked = sorted(dict.fromkeys(checked))
    if not checked:
        return None

    if any(covers_hostname(names, hostname) for hostname in checked):
        return None

    return {
        "kind": "cert_name_mismatch",
        "severity": "medium",
        "checked_names": checked,
        "cert_names": names["dns"],
        "cn_only": not [n for n in names["dns"] if n not in names["common_name"]],
        "detail": (
            f"certificate presents {', '.join(names['dns'])}; "
            f"endpoint was reached as {', '.join(checked)}"
        ),
    }
