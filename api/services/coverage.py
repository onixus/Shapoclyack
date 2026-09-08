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
* **Scope coverage** — of the ranges the tenant approved (``tenant_scan_scopes``),
  how many contain an asset a scan has actually reached. This is the one that
  finds the subnet nobody ever pointed the scanner at, because its denominator
  comes from the approval rather than from what was discovered.

**Scope coverage counts approvals, not addresses.** It used to divide known IP
identifiers by ``sum(network.num_addresses)``, and that number could not be
read: a fully scanned ``/22`` with thirty live hosts reported "2.9% approved
scope covered", which is a statement about how empty IPv4 subnets are and not
about this estate. Worse, the two things an operator actually wants to tell
apart — a subnet that is mostly empty address space and a subnet nobody has
ever scanned — produced the same low number, and overlapping approvals
(``10.0.0.0/24`` plus ``10.0.0.128/25``) inflated the denominator by a third.
An approval is the unit somebody actually wrote down and can act on, so the
share is *how many approved ranges have been reached at all*, and the ranges
that have not been are listed by name. "Three of your eleven approved ranges
have never been scanned, here they are" is actionable; "2.9%" is not.

Every share is ``None`` rather than a number whenever the denominator is not a
real denominator:

* the estate has no scan history yet, or so little of it that a share would be
  a statement about the rollout rather than about the estate (see
  :data:`MIN_SCAN_HISTORY_SHARE`);
* an approval has **no finite address space** — a ``*`` wildcard or a ``domain``
  suffix. A domain approval says nothing about which hosts are behind it, so
  such rows are counted and reported apart rather than folded into a share they
  cannot belong to.

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

#: Below this share of the active estate carrying *any* scan history, the two
#: scan shares are withheld. Migration ``0035_asset_scan_coverage`` has no
#: backfill and cannot have one, so after an upgrade the columns fill one run at
#: a time: a tenant with 50,000 assets that has scanned one 500-host subnet
#: would otherwise read "Scanned in 30 days: 1%", which is indistinguishable
#: from scanning having collapsed. The guard used to be ``known > 0``, which
#: fires only on the single instant before the first run finishes — the
#: docstring's own scenario walked straight through it.
MIN_SCAN_HISTORY_SHARE = 0.1

#: How many never-reached approvals to name on the page. The count is exact;
#: this caps only the list, because an operator with sixty unscanned ranges
#: needs the number and the first few, not a wall.
UNCOVERED_SAMPLE = 10


def _share(part: int, whole: int) -> float | None:
    if whole <= 0:
        return None
    return round(part / whole * 100.0, 1)


def scan_coverage(session: Any, *, tenant_id: str, since: datetime) -> dict[str, Any]:
    """Active assets reached by a scan run since ``since``.

    ``known`` is how many active assets have *ever* been scan-ingested since the
    columns existed. While it is below :data:`MIN_SCAN_HISTORY_SHARE` of the
    estate both shares are ``None`` and ``history_reason`` says why: reporting a
    single-digit percentage there would raise an alarm about the upgrade rather
    than about the estate, which is the failure this block was added to stop
    making in the other direction.
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
    history_share = _share(known, active)
    if known == 0:
        reason = "no_scan_history"
    elif known < active * MIN_SCAN_HISTORY_SHARE:
        reason = "partial_scan_history"
    else:
        reason = None
    return {
        "active_assets": active,
        "with_scan_history": known,
        "scan_history_share": history_share,
        "history_reason": reason,
        "scanned_share": _share(scanned, active) if reason is None else None,
        "vuln_scanned_share": _share(vuln_scanned, active) if reason is None else None,
    }


def _allowed_networks(rows: list[tuple[str, str, str]]) -> tuple[list, list[str]]:
    """Approved CIDRs, and the approvals that have no address space at all."""
    networks: list = []
    unmeasurable: list[str] = []
    for effect, kind, value in rows:
        if effect != "allow":
            continue
        if value == "*":
            unmeasurable.append(value)
            continue
        if kind == "domain":
            # A suffix approval is a permission, not an address space: nothing
            # says which hosts live behind it, so it can be neither covered nor
            # uncovered here.
            unmeasurable.append(value)
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:  # pragma: no cover - the table is written normalised
            unmeasurable.append(value)
    return networks, unmeasurable


def scope_coverage(
    session: Any, *, tenant_id: str, since: datetime, history_reason: str | None = None
) -> dict[str, Any]:
    """Approved ranges that contain an asset a scan has actually reached.

    "Reached" is ``assets.last_scanned_at >= since`` on an **active** asset, and
    both halves of that are load-bearing. Without the timestamp the reading was
    about discovery, not coverage: a tenant that enumerated its estate once and
    never scanned again reported full reach, which is precisely the tenant this
    block exists to catch. Without the status filter, decommissioned assets went
    on covering the ranges they had been retired from.

    Deny entries are ignored on purpose. They subtract from what may be scanned,
    so counting them would *raise* the coverage of a tenant that approved a
    range and then carved holes in it — the reading would improve because less
    was allowed, which is the wrong direction for a metric about reach. They are
    reported as their own count so the page's "approved entries" is not silently
    a count of every row in the table.

    ``history_reason`` is :func:`scan_coverage`'s verdict on whether the columns
    this reads have enough data to divide by. It is threaded through rather than
    re-derived because the two blocks must not be able to disagree: a tenant
    whose scan history has not filled in yet has no scope coverage either, and
    answering 0% here while the neighbouring tile honestly says "n/a" would be
    the same lie wearing the other tile's clothes.
    """
    rows = session.execute(
        select(
            models.TenantScanScope.effect,
            models.TenantScanScope.kind,
            models.TenantScanScope.value,
        ).where(models.TenantScanScope.tenant_id == tenant_id)
    ).all()
    networks, unmeasurable = _allowed_networks(rows)
    denied = sum(1 for effect, _, _ in rows if effect != "allow")

    result: dict[str, Any] = {
        # Allow rows only: a deny row is not an approval, and counting it under
        # a heading that reads "approved" while the docstring above says deny is
        # ignored was two different claims about the same number.
        "approved_entries": len(networks) + len(unmeasurable),
        "denied_entries": denied,
        "measurable_entries": len(networks),
        # Wildcard and domain approvals, named so the page can say what it could
        # not measure instead of quietly narrowing the denominator.
        "unmeasurable_entries": sorted(set(unmeasurable))[:UNCOVERED_SAMPLE],
        "covered_entries": None,
        "covered_share": None,
        "uncovered_entries": [],
        "unbounded_reason": None,
    }
    if not networks:
        # No range to be covered: either nothing was approved at all, or every
        # approval is a permission rather than an address space. The two are
        # different answers and the console prints which.
        result["unbounded_reason"] = "no_scope" if not rows else "no_measurable_scope"
        return result
    if history_reason is not None:
        result["unbounded_reason"] = history_reason
        return result

    # Only the assets that can *make* a range covered: active, in this tenant,
    # and reached by a scan inside the window. On an estate of any size this is
    # a small fraction of the identifier table, which the previous version read
    # in full and unfiltered on every call to /api/adoption.
    addresses = session.execute(
        select(models.AssetIdentifier.identifier_value)
        .join(models.Asset, models.Asset.asset_id == models.AssetIdentifier.asset_id)
        .where(
            models.AssetIdentifier.tenant_id == tenant_id,
            models.AssetIdentifier.identifier_type == "ip",
            models.Asset.status == "active",
            models.Asset.last_scanned_at >= since,
        )
        .distinct()
    ).scalars()

    covered: set[Any] = set()
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:  # pragma: no cover - identifiers are normalised
            continue
        for network in networks:
            if address in network:
                covered.add(network)
        if len(covered) == len(networks):
            break

    uncovered = [str(network) for network in networks if network not in covered]
    result["covered_entries"] = len(covered)
    result["covered_share"] = _share(len(covered), len(networks))
    result["uncovered_entries"] = sorted(uncovered)[:UNCOVERED_SAMPLE]
    return result
