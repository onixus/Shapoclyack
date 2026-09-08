"""How much of what a tenant approved for scanning is actually being scanned.

Adoption already answers "are findings being closed". This answers the question
underneath it, which is the one an estate can be quietly wrong about for a year:
*is the scanner looking at the whole of what it was allowed to look at?* A
remediation rate over an estate that is 12% enumerated is a number about 12% of
the company, and nothing on the page said so.

Two independent readings, deliberately not combined into one score:

* **Scan coverage** — of the assets the platform knows about, how many were
  reached by a scan run recently. Read from ``assets.last_scanned_at``, which is
  written only by the scan-ingest path, and never from ``last_seen``, which an
  endpoint agent's inventory check-in also moves.
* **Scope coverage** — of the addresses the tenant approved (``tenant_scan_scopes``),
  how many correspond to a known asset. This is the one that finds the subnet
  nobody ever pointed the scanner at, because its denominator comes from the
  approval rather than from what was discovered.

Both go to ``None`` rather than to a number whenever the denominator is not a
real denominator, and scope coverage has two such cases beyond an empty estate:

* a ``*`` wildcard or a ``domain`` entry has **no finite address space**, so
  there is nothing to be a share *of*. A domain suffix approval says nothing
  about how many hosts are behind it, and counting the ones already discovered
  against themselves would report 100% for an estate the scanner has never
  looked past the front of.
* an approval so large it is not a target list — a ``/8`` is 16.7 million
  addresses, and a real estate inside one produces a share indistinguishable
  from zero. ``MAX_SCOPE_ADDRESSES`` caps what is worth expressing as a share.

Split out of ``adoption.py`` rather than added to it: the arithmetic is about
scanning scope, it needs ``ipaddress`` and the scope table, and adoption's
``metrics()`` was already the largest read in the product.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from sqlalchemy import func, select

from api.db import models

#: Above this many approved addresses a share stops meaning anything — see the
#: module docstring. A /16 (65,536) is still a network an operator can reason
#: about; a /8 is not a target list.
MAX_SCOPE_ADDRESSES = 1 << 17


def _share(part: int, whole: int) -> float | None:
    if whole <= 0:
        return None
    return round(part / whole * 100.0, 1)


def scan_coverage(session: Any, *, tenant_id: str, since: datetime) -> dict[str, Any]:
    """Active assets reached by a scan run since ``since``.

    ``known`` is how many active assets have *ever* been scan-ingested since the
    columns existed. While it is zero the share is ``None``: migration
    ``0035_asset_scan_coverage`` has no backfill and cannot have one, so an
    installation that has not scanned since upgrading has no coverage data — not
    zero coverage. Reporting 0% there would raise an alarm about the upgrade
    rather than about the estate.
    """
    asset = models.Asset
    active, known, scanned, vuln_scanned = session.execute(
        select(
            func.count(),
            func.count(asset.last_scanned_at),
            func.count(1).filter(asset.last_scanned_at >= since),
            func.count(1).filter(asset.last_vuln_scan_at >= since),
        ).where(asset.tenant_id == tenant_id, asset.status == "active")
    ).one()
    return {
        "active_assets": active,
        "with_scan_history": known,
        "scanned_share": _share(scanned, active) if known else None,
        "vuln_scanned_share": _share(vuln_scanned, active) if known else None,
    }


def _allowed_networks(rows: list[tuple[str, str, str]]) -> tuple[list, list[str]]:
    """Allowed CIDRs, and the reasons the approved space has no finite size."""
    networks: list = []
    unbounded: list[str] = []
    for effect, kind, value in rows:
        if effect != "allow":
            continue
        if value == "*":
            unbounded.append("wildcard")
            continue
        if kind == "domain":
            # A suffix approval is a permission, not an address space: nothing
            # says how many hosts live behind it.
            unbounded.append("domain")
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:  # pragma: no cover - the table is written normalised
            continue
    return networks, sorted(set(unbounded))


def scope_coverage(session: Any, *, tenant_id: str) -> dict[str, Any]:
    """Approved addresses that correspond to a known asset.

    Deny entries are ignored on purpose. They subtract from what may be scanned,
    so counting them would *raise* the coverage of a tenant that approved a
    range and then carved holes in it — the reading would improve because less
    was allowed, which is the wrong direction for a metric about reach.
    """
    rows = session.execute(
        select(
            models.TenantScanScope.effect,
            models.TenantScanScope.kind,
            models.TenantScanScope.value,
        ).where(models.TenantScanScope.tenant_id == tenant_id)
    ).all()
    networks, unbounded = _allowed_networks(rows)

    result: dict[str, Any] = {
        "approved_entries": len(rows),
        "approved_addresses": None,
        "assets_in_scope": None,
        "covered_share": None,
        "unbounded_reason": unbounded[0] if unbounded else None,
    }
    if unbounded or not networks:
        # No finite denominator: either an entry has no address space, or the
        # tenant approved nothing at all. Both are `None`, and the reason is
        # carried so the console can say which rather than printing a dash.
        if not unbounded and not networks:
            result["unbounded_reason"] = "no_scope"
        return result

    total = sum(network.num_addresses for network in networks)
    if total > MAX_SCOPE_ADDRESSES:
        result["approved_addresses"] = total
        result["unbounded_reason"] = "too_large"
        return result

    addresses = {
        value
        for (value,) in session.execute(
            select(models.AssetIdentifier.identifier_value).where(
                models.AssetIdentifier.tenant_id == tenant_id,
                models.AssetIdentifier.identifier_type == "ip",
            )
        )
    }
    in_scope = 0
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:  # pragma: no cover - identifiers are normalised
            continue
        if any(address in network for network in networks):
            in_scope += 1

    result["approved_addresses"] = total
    result["assets_in_scope"] = in_scope
    result["covered_share"] = _share(in_scope, total)
    return result
