"""Stable asset-identity keys (Phase 7). Pure functions only — no DB import;
the scanner package stays storage-agnostic, matching every other pipeline
module. Mirrors the stable-hash idempotency convention already used by
``ingest_msg_id`` in api/services/nats_bus.py.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def ip_identity_key(tenant_id: str, ip: str) -> str:
    raw = f"{tenant_id}:ip:{ip}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def fqdn_identity_key(tenant_id: str, fqdn: str) -> str:
    raw = f"{tenant_id}:fqdn:{fqdn.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class IdentityCandidate:
    identifier_type: str  # "ip" | "fqdn"
    identifier_value: str
    key: str


def identity_candidates_for_host(
    tenant_id: str, *, host_ip: str | None, hostnames: list[str] | None = None
) -> list[IdentityCandidate]:
    """Build identity candidates for one scanned host.

    Phase 7 does not attempt IP<->FQDN correlation: an IP observation and a
    bare-FQDN-only observation with no matching IP in the same run produce
    separate candidates/assets. Cross-identifier correlation is deferred to a
    later phase (see ROADMAP.md Phase 9/11).
    """
    candidates: list[IdentityCandidate] = []
    ip = (host_ip or "").strip()
    if ip:
        candidates.append(
            IdentityCandidate(
                identifier_type="ip",
                identifier_value=ip,
                key=ip_identity_key(tenant_id, ip),
            )
        )
    for name in hostnames or []:
        fqdn = (name or "").strip()
        if not fqdn:
            continue
        candidates.append(
            IdentityCandidate(
                identifier_type="fqdn",
                identifier_value=fqdn.lower(),
                key=fqdn_identity_key(tenant_id, fqdn),
            )
        )
    return candidates
