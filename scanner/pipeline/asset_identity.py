"""Stable asset-identity keys (Phase 7) and IP↔FQDN↔certificate correlation (P4.2).

Pure functions only — no DB import; the scanner package stays storage-agnostic.
Mirrors the stable-hash idempotency convention already used by
``ingest_msg_id`` in api/services/nats_bus.py.

P4.2: an IP observation and a bare-FQDN observation used to stay two assets.
A certificate served on an IP that asserts an FQDN is evidence they are one
machine — but only together with forward-resolution agreement. Shared hosting
means one IP legitimately serves names that are not the same asset, so a
wrong merge is worse than two rows. PTR names are not evidence (same reason
as P4.1).
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from typing import Any

from scanner.pipeline.cert_names import cert_names, covers_hostname, expected_names, is_dns_name


def ip_identity_key(tenant_id: str, ip: str) -> str:
    raw = f"{tenant_id}:ip:{ip}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def fqdn_identity_key(tenant_id: str, fqdn: str) -> str:
    raw = f"{tenant_id}:fqdn:{fqdn.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class IdentityCandidate:
    identifier_type: str  # "ip" | "fqdn"
    identifier_value: str
    key: str


def identity_candidates_for_host(
    tenant_id: str, *, host_ip: str | None, hostnames: list[str] | None = None
) -> list[IdentityCandidate]:
    """Build identity candidates for one scanned host.

    ``host`` may be an IP or a bare FQDN (a domain-monitor / CT hit). A name
    is never stored as ``ip``. Correlation across *separate* host records is
    ``correlate_identities`` (P4.2), not this function: attaching every
    hostname on a shared-hosting certificate here would collapse tenants.
    """
    candidates: list[IdentityCandidate] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, key: str) -> None:
        token = (kind, value)
        if not value or token in seen:
            return
        seen.add(token)
        candidates.append(
            IdentityCandidate(identifier_type=kind, identifier_value=value, key=key)
        )

    raw = (host_ip or "").strip()
    if raw:
        if _is_ip(raw):
            add("ip", raw, ip_identity_key(tenant_id, raw))
        else:
            add("fqdn", raw.lower(), fqdn_identity_key(tenant_id, raw))
    for name in hostnames or []:
        value = (name or "").strip()
        if not value:
            continue
        if _is_ip(value):
            add("ip", value, ip_identity_key(tenant_id, value))
        else:
            add("fqdn", value.lower(), fqdn_identity_key(tenant_id, value))
    return candidates


FORWARD_DNS = "forward-dns"
CERTIFICATE = "certificate"
HIGH = "high"
LOW = "low"


@dataclass(frozen=True)
class IdentityCorrelation:
    """One IP↔FQDN pair and the evidence that they might be the same asset.

    ``mergeable`` is the only combination P4.2 will collapse: both sources,
    and this IP is not serving two such FQDNs (shared hosting).
    """

    ip: str
    fqdn: str
    sources: tuple[str, ...]
    shared: bool = False

    @property
    def confidence(self) -> str:
        return HIGH if FORWARD_DNS in self.sources and CERTIFICATE in self.sources else LOW

    @property
    def mergeable(self) -> bool:
        return self.confidence == HIGH and not self.shared


def forward_names_by_ip(*blobs: Any) -> dict[str, set[str]]:
    """ip → forward FQDNs from ``hostnames.json`` and/or ``dns_resolution.json``.

    PTR / reverse names are ignored: they belong to the address-block owner.
    """
    out: dict[str, set[str]] = {}

    def add(ip: str, fqdn: str) -> None:
        ip = (ip or "").strip()
        fqdn = (fqdn or "").strip().rstrip(".").lower()
        if not ip or not fqdn or not is_dns_name(fqdn):
            return
        out.setdefault(ip, set()).add(fqdn)

    for blob in blobs:
        if isinstance(blob, dict) and isinstance(blob.get("records"), list):
            for record in blob["records"]:
                if not isinstance(record, dict):
                    continue
                host = str(record.get("host") or "")
                for key in ("a", "aaaa"):
                    for ip in record.get(key) or []:
                        add(str(ip), host)
            continue
        if not isinstance(blob, dict):
            continue
        for ip, entry in blob.items():
            if ip in ("records", "version", "source"):
                continue
            for name in expected_names(entry if isinstance(entry, dict) else None):
                add(str(ip), name)
    return out


def cert_dns_by_ip(tls_posture: Any) -> dict[str, list[dict[str, list[str]]]]:
    """ip → certificate DNS-name sets from ``tls_posture.json`` findings."""
    out: dict[str, list[dict[str, list[str]]]] = {}
    if not isinstance(tls_posture, dict):
        return out
    findings = tls_posture.get("findings")
    if not isinstance(findings, list):
        return out
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        host = str(finding.get("host") or "").strip()
        if not host or not _is_ip(host):
            continue
        names = cert_names(finding.get("cert"))
        if names["dns"]:
            out.setdefault(host, []).append(names)
    return out


def correlate_identities(
    *,
    forward: dict[str, set[str]],
    certs_by_ip: dict[str, list[dict[str, list[str]]]] | None = None,
) -> list[IdentityCorrelation]:
    """Build IP↔FQDN correlations.

    A pair is ``high`` only when forward DNS *and* a certificate on that IP
    cover the FQDN (RFC 6125). If an IP has two or more high pairs, they are
    marked ``shared`` and none of them is mergeable.
    """
    certs_by_ip = certs_by_ip or {}
    pairs: dict[tuple[str, str], set[str]] = {}

    # Certificate names never introduce an FQDN. A CDN SAN list would otherwise
    # spawn assets we never resolved. The cert can only *confirm* a name that
    # already forward-resolves to this IP.
    for ip, names in forward.items():
        for fqdn in names:
            sources = {FORWARD_DNS}
            for cert in certs_by_ip.get(ip, []):
                if covers_hostname(cert, fqdn):
                    sources.add(CERTIFICATE)
                    break
            pairs[(ip, fqdn)] = sources

    high_by_ip: dict[str, list[str]] = {}
    for (ip, fqdn), sources in pairs.items():
        if FORWARD_DNS in sources and CERTIFICATE in sources:
            high_by_ip.setdefault(ip, []).append(fqdn)

    shared_ips = {ip for ip, fqdns in high_by_ip.items() if len(set(fqdns)) > 1}

    out: list[IdentityCorrelation] = []
    for (ip, fqdn), sources in sorted(pairs.items()):
        out.append(
            IdentityCorrelation(
                ip=ip,
                fqdn=fqdn,
                sources=tuple(sorted(sources)),
                shared=ip in shared_ips and FORWARD_DNS in sources and CERTIFICATE in sources,
            )
        )
    return out


# A tiny stand-in for a Public Suffix List. Bundling the PSL would add a
# dataset with its own staleness (same reason P4.1 refused it). Unknown
# two-label suffixes are treated as the registrable domain; a miss like
# ``foo.co.uk`` clustering as ``co.uk`` is possible and named as a limit.
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "com.br",
        "co.jp",
        "com.cn",
        "github.io",
    }
)


def registrable_domain(name: str) -> str:
    """eTLD+1 for clustering unowned names (P4.3). Empty when it is not a DNS name.

    ``app.payments.example.com`` → ``example.com``. ``shop.co.uk`` → ``shop.co.uk``.
    An IP, a wildcard, or a single label is not a domain we will pretend to own.
    """
    candidate = (name or "").strip().rstrip(".").lower()
    if not candidate or candidate.startswith("*.") or not is_dns_name(candidate):
        return ""
    labels = candidate.split(".")
    if len(labels) < 2:
        return ""
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two
