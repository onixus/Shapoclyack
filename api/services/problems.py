"""Aggregated problem list over tracked findings (#579, stage 1).

"Which shared problem do we fix first?" is a question about a *group* of
findings, and the findings list cannot answer it: a page of rows cannot be
summed into a fleet-wide count. This module groups the findings that match a
filter by :mod:`api.services.problem_identity` **in SQL**, so every number is
computed over the whole filtered selection and not over the page on screen.

It owns no state. A problem has no row; the findings do, and their lifecycle,
SLA, owners and exceptions are exactly what ``api.services.vulnerabilities``
already maintains. Filters are the findings list's own
(:func:`vulnerabilities.finding_filters`), which is what makes a drill-down —
``problem_key`` added to the same filter set — reproduce the restrictions the
aggregate row was computed under.

Semantics worth stating where they are used:

* ``severity`` / ``contextual_score`` are the **worst open instance** (a
  maximum, not an average; closed ones count only when none is open); ``cvss``
  is the highest over all instances. The response says so in ``semantics``.
* ``instances`` counts finding rows; ``assets`` counts distinct assets. Both
  are returned because 80 instances on 3 assets and 80 on 80 assets are
  different work.
* EPSS is not stored with findings; it comes from the EPSS overlay the risk
  scorer loads (``OCTO_EPSS_DATABASE``), looked up by the normalised CVE of a
  ``cve:`` problem. A CVE the overlay does not list, and every non-CVE problem,
  reads ``null`` (unknown), never zero; the overlay's source and feed date are
  returned with the page so the figure's freshness is visible.
* Exposure is reported per source with a ``basis`` (declared / measured /
  inferred / unknown); absent data is ``unknown``, not "not exposed".
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import and_, case, func, select

from api.db import models
from api.db.engine import get_session
from api.services import pagination
from api.services import problem_identity
from api.services import risk_scoring
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from api.settings import Settings

V = models.Vulnerability

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_RANK_SEVERITY = {rank: name for name, rank in SEVERITY_RANK.items()}

#: ``network_exposure_source`` (api/services/risk_scoring.py) -> how the value
#: was established. ``operator-set`` and ``scan-surface`` are declarations by a
#: person; ``finding`` is what the scanner measured on that observation;
#: ``address-space`` is inferred from the address range.
EXPOSURE_BASIS = {
    "operator-set": "declared",
    "scan-surface": "declared",
    "finding": "measured",
    "address-space": "inferred",
}

SEMANTICS = {
    "severity": "worst OPEN instance (maximum, not an average); the worst closed one only "
    "when no instance is open",
    "contextual_score": "highest contextual risk score among open instances (closed ones only "
    "when none is open)",
    "cvss": "highest CVSS among instances; null when none carries one",
    "epss": "EPSS of the problem's CVE from the scoring overlay (a problem is one CVE, so the "
    "maximum over CVEs is that value); null when the overlay has no entry (unknown, never 0) "
    "and always null for non-CVE problems; source and feed date in `enrichment.epss`",
    "instances": "tracked findings (one per asset/port) in the filtered selection",
    "assets": "distinct assets among those instances",
    "exposure": "counts per instance; basis is declared, measured, inferred or unknown",
}

SORT_KEYS = (
    "risk",
    "severity",
    "instances",
    "assets",
    "breached",
    "kev",
    "last_seen",
    "due",
)


def _sev_rank():
    return case(
        (V.severity == "critical", 4),
        (V.severity == "high", 3),
        (V.severity == "medium", 2),
        (V.severity == "low", 1),
        else_=0,
    )


def _count_if(condition: Any):
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


def _basis(source: str | None) -> str:
    return EXPOSURE_BASIS.get(source or "", "unknown")


def list_problems(
    settings: Settings,
    *,
    tenant_id: str,
    filters: dict[str, Any],
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    sort: str | None = None,
    order: str | None = None,
) -> dict[str, Any]:
    """One page of problems plus whole-selection aggregates.

    ``filters`` are the keyword arguments of :func:`vulnerabilities.finding_filters`
    (``tenant_id`` is forced to the caller's). Raises ``ValueError`` for an
    invalid filter, like the findings list.
    """
    now = vulns._now()
    predicates = vulns.finding_filters(**{**filters, "tenant_id": tenant_id, "now": now})
    key = problem_identity.problem_key_expr()
    breached = and_(*vulns._sla_filters("breached", now))
    due_soon = and_(*vulns._sla_filters("due_soon", now))
    active = V.state.in_(sorted(vuln_states.ACTIVE))

    grouped = (
        select(
            key.label("problem_key"),
            func.count().label("instances"),
            func.count(func.distinct(V.asset_id)).label("assets"),
            # Open instances decide when there are any: a closed critical next to
            # an open low is a low problem. All-closed selections fall back to
            # the closed ones (the sort keys use the same open-first values).
            func.coalesce(
                func.max(case((active, _sev_rank()), else_=None)), func.max(_sev_rank())
            ).label("sev_rank"),
            func.coalesce(
                func.max(case((active, V.contextual_score), else_=None)),
                func.max(V.contextual_score),
            ).label("score"),
            func.max(V.cvss).label("cvss"),
            _count_if(V.in_kev.is_(True)).label("kev"),
            func.max(V.last_seen_at).label("last_seen"),
            func.min(V.first_seen_at).label("first_seen"),
            _count_if(and_(active, V.assignee.is_(None))).label("unassigned"),
            _count_if(breached).label("breached"),
            _count_if(due_soon).label("due_soon"),
            func.min(case((active, V.due_at), else_=None)).label("due"),
            _count_if(V.network_exposure == "external").label("ext"),
            _count_if(V.network_exposure == "internal").label("int"),
            # Title of the most severe open instance (open flag, then severity
            # digit, prefix stripped in Python), not an arbitrary alphabetical one.
            func.max(
                case((active, "1"), else_="0")
                + case(
                    (V.severity == "critical", "4"), (V.severity == "high", "3"),
                    (V.severity == "medium", "2"), (V.severity == "low", "1"), else_="0",
                )
                + func.coalesce(V.title, "")
            ).label("title"),
            func.min(V.cve).label("cve"),
            _count_if(V.state == vuln_states.OPEN).label("s_open"),
            _count_if(V.state == vuln_states.ACKNOWLEDGED).label("s_ack"),
            _count_if(V.state == vuln_states.PLANNED).label("s_planned"),
            _count_if(V.state == vuln_states.FIXING).label("s_fixing"),
            _count_if(V.state == vuln_states.VERIFYING).label("s_verifying"),
            _count_if(V.state == vuln_states.CLOSED).label("s_closed"),
            _count_if(V.machine_verified.is_(True)).label("verified"),
        )
        .where(*predicates)
        .group_by(key)
        .subquery()
    )

    sort_columns = {
        "risk": grouped.c.score,
        "severity": grouped.c.sev_rank,
        "instances": grouped.c.instances,
        "assets": grouped.c.assets,
        "breached": grouped.c.breached,
        "kev": grouped.c.kev,
        "last_seen": grouped.c.last_seen,
        "due": grouped.c.due,
    }
    column = sort_columns.get(sort or "", grouped.c.score)
    ordering = column.asc() if (order or "").lower() == "asc" else column.desc()
    # Secondary keys make the page stable: equal scores are common (every
    # instance of one CVE shares one) and an unstable order repeats or skips
    # rows across pages.
    ordering_all = (ordering.nulls_last(), grouped.c.instances.desc(), grouped.c.problem_key)

    with get_session(settings.postgres_url) as session:
        total = session.execute(select(func.count()).select_from(grouped)).scalar_one()
        rows = session.execute(
            select(grouped).order_by(*ordering_all).offset(offset).limit(limit)
        ).all()
        keys = [row.problem_key for row in rows]
        facets = _facets(session, predicates, key, keys) if keys else {}
        overall = session.execute(
            select(
                func.count().label("instances"),
                func.count(func.distinct(V.asset_id)).label("assets"),
                _count_if(breached).label("breached"),
                _count_if(V.in_kev.is_(True)).label("kev"),
                _count_if(and_(active, V.assignee.is_(None))).label("unassigned"),
                _count_if(V.machine_verified.is_(True)).label("verified"),
            ).where(*predicates)
        ).one()

    items = [_item(row, facets.get(row.problem_key, {})) for row in rows]
    scorer = risk_scoring.get_scorer()
    for item in items:
        if item["cve"]:
            item["epss"] = scorer.epss_lookup(item["cve"])
    return {
        "items": items,
        "total": total,
        "aggregates": {
            "problems": total,
            "instances": overall.instances,
            "assets": overall.assets,
            "breached_instances": overall.breached,
            "kev_instances": overall.kev,
            "unassigned_instances": overall.unassigned,
            "machine_verified_instances": overall.verified,
        },
        "as_of": vulns._iso(now),
        "semantics": SEMANTICS,
        "enrichment": {"epss": epss_info(scorer)},
    }


def epss_info(scorer: Any) -> dict[str, Any]:
    """Where the EPSS figures came from and how old the feed is (``null`` fields
    when the overlay is absent)."""
    meta = scorer.epss_meta()
    return {"source": meta.get("source"), "updated": meta.get("updated")}


def _facets(session: Any, predicates: list[Any], key: Any, keys: list[str]) -> dict[str, dict]:
    """Owners and exposure sources for the page's problems: one grouped query
    per facet, bounded by the page size, never one per row."""
    out: dict[str, dict] = {k: {"assignees": {}, "teams": {}, "sources": {}} for k in keys}
    for column, bucket in (
        (V.assignee, "assignees"),
        (V.owner_team, "teams"),
        (V.network_exposure_source, "sources"),
    ):
        for problem, value, count in session.execute(
            select(key, column, func.count())
            .where(*predicates, key.in_(keys))
            .group_by(key, column)
        ):
            out[problem][bucket][value] = count
    return out


def _top(counter: dict[Any, int], n: int = 5) -> list[dict[str, Any]]:
    named = [(k, c) for k, c in counter.items() if k]
    named.sort(key=lambda kv: (-kv[1], str(kv[0])))
    return [{"name": k, "instances": c} for k, c in named[:n]]


def _item(row: Any, facet: dict[str, Any]) -> dict[str, Any]:
    sources = facet.get("sources", {})
    basis: dict[str, int] = {}
    for source, count in sources.items():
        label = _basis(source)
        basis[label] = basis.get(label, 0) + count
    unknown_exposure = row.instances - row.ext - row.int
    return {
        "problem_key": row.problem_key,
        "kind": problem_identity.kind_of(row.problem_key),
        "cve": row.cve if row.problem_key.startswith(problem_identity.CVE_PREFIX) else None,
        "title": (row.title or "")[2:],
        "instances": row.instances,
        "assets": row.assets,
        "severity": _RANK_SEVERITY.get(row.sev_rank, "unknown"),
        "contextual_score": row.score,
        "cvss": row.cvss,
        "epss": None,
        "kev_instances": row.kev,
        "in_kev": row.kev > 0,
        "first_seen_at": vulns._iso(_dt(row.first_seen)),
        "last_seen_at": vulns._iso(_dt(row.last_seen)),
        "states": {
            "OPEN": row.s_open,
            "ACKNOWLEDGED": row.s_ack,
            "PLANNED": row.s_planned,
            "FIXING": row.s_fixing,
            "VERIFYING": row.s_verifying,
            "CLOSED": row.s_closed,
        },
        "machine_verified": row.verified,
        "owners": {
            "unassigned_instances": row.unassigned,
            "assignees": _top(facet.get("assignees", {})),
            "teams": _top(facet.get("teams", {})),
        },
        "sla": {
            "breached": row.breached,
            "due_soon": row.due_soon,
            "earliest_due_at": vulns._iso(_dt(row.due)),
        },
        "exposure": {
            "external": row.ext,
            "internal": row.int,
            "unknown": unknown_exposure,
            "sources": {(k or "none"): v for k, v in sorted(sources.items(), key=lambda kv: str(kv[0]))},
            "basis": basis,
        },
    }


def _dt(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def problem_instances(
    settings: Settings,
    *,
    tenant_id: str,
    problem_key: str,
    filters: dict[str, Any],
    as_of: str | None = None,
    expected_instances: int | None = None,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    sort: str | None = None,
    order: str | None = None,
) -> dict[str, Any]:
    """Drill-down: the findings behind one problem under the same filters.

    ``as_of`` and ``expected_instances`` are what the aggregate row said when
    the caller loaded it. When the two disagree, ``drift`` says why in terms
    of data that changed since: how many of these findings were created or
    updated after ``as_of``. A mismatch is therefore explained, not hidden —
    and a mismatch with no later change is reported as such rather than
    invented.
    """
    items, total = vulns.list_vulnerabilities(
        settings,
        **{**filters, "tenant_id": tenant_id},
        problem_key=problem_key,
        offset=offset,
        limit=limit,
        sort=sort,
        order=order,
    )
    drift: dict[str, Any] | None = None
    if expected_instances is not None:
        changed = 0
        if as_of:
            cutoff = _dt(as_of)
            if cutoff is not None and cutoff.tzinfo is not None:
                cutoff = vulns._naive(cutoff)
            predicates = vulns.finding_filters(
                **{**filters, "tenant_id": tenant_id}, problem_key=problem_key
            )
            with get_session(settings.postgres_url) as session:
                changed = session.execute(
                    select(func.count()).select_from(V).where(
                        *predicates, V.updated_at > cutoff
                    )
                ).scalar_one()
        drift = {
            "expected_instances": expected_instances,
            "actual_instances": total,
            "differs": expected_instances != total,
            "changed_since_as_of": changed,
            "explanation": (
                None
                if expected_instances == total
                else (
                    f"{changed} of these findings changed after the list was loaded"
                    if changed
                    else "findings matching the filters were added or left the selection "
                    "after the list was loaded"
                )
            ),
        }
    # EPSS of the problem's CVE on every instance (the figure is per CVE, so it
    # is the same for all of them); null when the overlay has no entry.
    scorer = risk_scoring.get_scorer()
    for item in items:
        item["epss"] = scorer.epss_lookup(item["cve"]) if item.get("cve") else None
    return {
        "items": items,
        "total": total,
        "drift": drift,
        "problem_key": problem_key,
        "enrichment": {"epss": epss_info(scorer)},
    }
