"""Identity of an aggregated *problem* over tracked findings (#579).

A problem is a **view**, not a stored entity: the set of existing canonical
findings (``vulnerabilities`` rows) that share one typed key. Nothing here
changes ``Vulnerability.finding_key`` — the persisted per-asset identity that
owns the lifecycle, SLA and verification — and nothing reads source
observations (#449 owns that aggregation); two findings are one problem only
when the tracker already holds them as separate canonical rows.

The key is typed so that the namespaces cannot collide:

``cve:CVE-2024-0001``
    A normalised CVE identifier (trimmed, upper-cased). Every finding with that
    CVE on any asset, port or detector is one problem.
``tpl:<detector>:<template_id>``
    A non-CVE finding observed by a detector template (nuclei, pulse plugin).
    The detector is part of the key: the same template id under two detectors
    is not known to be the same check.
``script:<script_id>``
    A non-CVE finding with only a script id (NSE and the like).
``unknown:<vuln_id>``
    No CVE, no template, no script: the identity is unknown, so the finding is
    its own problem. Unknown identities are never merged into one bucket.

Deliberately *not* a key: the recommendation text. Two findings with identical
advice are not known to share a fix (docs/remediation-campaigns.md), and
package/advisory/fix grouping is only valid when that context is known — the
findings table does not hold it, so it is not offered.

The SQL expression and its Python twin below must agree; the tests compare them
on the same rows.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func

from api.db import models

CVE_PREFIX = "cve:"
TEMPLATE_PREFIX = "tpl:"
SCRIPT_PREFIX = "script:"
UNKNOWN_PREFIX = "unknown:"
KINDS = ("cve", "tpl", "script", "unknown")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def problem_key(
    *,
    vuln_id: str,
    cve: str | None,
    detector_source: str | None,
    template_id: str | None,
    script_id: str | None,
) -> str:
    """Python twin of :func:`problem_key_expr`."""
    normalised = _clean(cve).upper()
    if normalised.startswith("CVE-"):
        return f"{CVE_PREFIX}{normalised}"
    template = _clean(template_id)
    if template:
        return f"{TEMPLATE_PREFIX}{_clean(detector_source) or '-'}:{template}"
    script = _clean(script_id)
    if script:
        return f"{SCRIPT_PREFIX}{script}"
    return f"{UNKNOWN_PREFIX}{vuln_id}"


def problem_key_of(row: models.Vulnerability) -> str:
    return problem_key(
        vuln_id=row.vuln_id,
        cve=row.cve,
        detector_source=row.detector_source,
        template_id=row.template_id,
        script_id=row.script_id,
    )


def problem_key_expr() -> Any:
    """The same key as a SQL expression, for ``GROUP BY`` and drill-down."""
    V = models.Vulnerability
    cve = func.upper(func.trim(func.coalesce(V.cve, "")))
    template = func.trim(func.coalesce(V.template_id, ""))
    script = func.trim(func.coalesce(V.script_id, ""))
    return case(
        (cve.like("CVE-%"), CVE_PREFIX + cve),
        (
            template != "",
            TEMPLATE_PREFIX
            + case((func.trim(func.coalesce(V.detector_source, "")) == "", "-"),
                   else_=func.trim(V.detector_source))
            + ":"
            + template,
        ),
        (script != "", SCRIPT_PREFIX + script),
        else_=UNKNOWN_PREFIX + V.vuln_id,
    )


def kind_of(key: str) -> str:
    for kind in KINDS:
        if key.startswith(f"{kind}:"):
            return kind
    return "unknown"


def validate_key(key: str) -> str:
    """Refuse a key that is not in one of the typed namespaces."""
    key = (key or "").strip()
    if not key or len(key) > 400 or not any(key.startswith(f"{k}:") for k in KINDS):
        raise ValueError(f"invalid problem key {key[:80]!r}")
    return key
