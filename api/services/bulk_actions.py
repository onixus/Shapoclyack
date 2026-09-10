"""Applying one operator verb to many findings or assets (#346).

Triaging a scan's four hundred findings through the per-finding endpoints is
four hundred requests and four hundred clicks. This module is the other shape
of the same verbs: one request naming many ids, and an answer that says what
happened **to each one**.

**Per id, not per batch.** Every id is applied through the same service
function the single-finding route calls — ``vulnerabilities.transition``,
``assets.update_asset`` and friends — so a bulk assign and a hand assign are
the same write, produce the same ``vulnerability_events`` row, and reflect to
the same tracker. Nothing here re-implements a verb, which is the only way the
two paths cannot drift.

**A foreign id does not fail the batch.** An operator's selection may contain a
finding that has since closed, or (for a platform admin) one belonging to a
tenant they did not name. Refusing the whole request would make the console's
bulk bar unusable exactly when it is most needed, so each id gets its own
outcome:

* ``ok`` — applied;
* ``not_found`` — no such id *in the scope this caller writes in*. Identical to
  the single-id route's 404, and for the same reason: a 403 would confirm the
  id exists to somebody with no right to know;
* ``conflict`` — the verb is illegal from this row's current state (an
  ``InvalidVulnTransition``, an acceptance on a closed finding);
* ``invalid`` — the payload is not applicable to this row.

**One transaction per id, on purpose.** The alternative — one transaction for
the batch — would mean a single illegal transition rolling back the other
hundred and ninety-nine, which is the failure mode this endpoint exists to
avoid. The cost is that a batch is not atomic, and the report is the honest
statement of that: it says which ids were applied.

**A batch costs what its ids cost.** ``vulnerabilities.transition`` reflects a
state change to a linked tracker after its transaction closes, so a batch of
findings that all carry a Jira key makes one outbound call per finding, inside
the operator's request. That is the same work the single route does, done N
times, and it is the other reason :data:`MAX_BULK_IDS` is 200 rather than
5 000. A tenant whose tracker is slow should expect a bulk transition to take
proportionally long; nothing here runs it in the background, because a report
that says what happened cannot be written before it has.

**The role is the route's business** (``api/routes/vulnerabilities.py``), and it
is the role the *single* verb requires: ``exception`` and ``false_positive``
need tenant ``admin`` in bulk exactly as they do one at a time. Doing a hundred
of a thing must never be cheaper than doing one of it.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Iterable

from api.services import assets as assets_service
from api.services import metrics as metrics_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.bulk_actions")

#: Verbs ``POST /api/vulnerabilities/bulk`` accepts. ``false_positive`` is the
#: single route's ``/false-positive`` — underscored here because it is a value
#: in a JSON body, where every other enum in this API is snake_case.
VULN_ACTIONS = ("assign", "transition", "exception", "ticket", "false_positive")

#: Verbs ``POST /api/assets/bulk`` accepts. One, and it is ``PATCH /assets/{id}``
#: applied to many: the operator-set context (owner, criticality, environment,
#: exposure) is what a triage session needs to fix in bulk, and the asset has no
#: other write.
ASSET_ACTIONS = ("context",)

#: Ids one request may name. Two things set it, and the smaller wins:
#:
#: * the audit trail. #346 asks for one ``audit_events`` row **listing the
#:   ids**, and ``audit.record`` stores a document over 16 KiB as a marker that
#:   says a change happened but not what it was. Two hundred ids of at most
#:   :data:`MAX_BULK_ID_LENGTH` characters fit; the count alone does not
#:   guarantee it, which is what that ceiling and
#:   :data:`AUDIT_DOCUMENT_BUDGET_BYTES` are for.
#: * the request's own duration. Each id is its own transaction (see the module
#:   docstring), so the batch size is also how long somebody's HTTP request is.
#:
#: A console selection larger than this is two requests, which is a paging
#: problem and not a data-integrity one.
MAX_BULK_IDS = 200

#: Longest id a batch may name. Ids here are prefixed hex — ``vln_`` plus
#: sixteen characters, twenty in all — so this is more than twice what any of
#: them needs and refuses nothing real. It exists because :data:`MAX_BULK_IDS`
#: bounds the *count* while the audit row has to be bounded in *bytes*: two
#: hundred ids a client made 120 characters long were a 27 KiB document, which
#: is the "something happened" marker with not one id left in it. With this
#: ceiling, two hundred ids and their outcomes are at most ~13 KiB and the row
#: names every one of them.
MAX_BULK_ID_LENGTH = 48

#: What one bulk audit document may weigh. Under ``audit.record``'s own 16 KiB
#: cap on purpose: past that cap the document is replaced wholesale by a
#: truncation marker, so the row this endpoint owes has to be brought inside
#: the cap *here*, where what gives way can be chosen (see
#: :func:`audit_document`) instead of being everything at once.
AUDIT_DOCUMENT_BUDGET_BYTES = 15 * 1024

#: Longest a single ``payload`` value is carried into the audit document. The
#: bodies these verbs take are small, except the two that are not bounded by
#: their schema at all: ``false_positive``'s ``evidence`` is a free dict, and a
#: 20 KiB one turned the audit row into that marker on a batch of *two*
#: findings. A long string is truncated (the beginning of a reason is still
#: worth reading); anything else bulky is replaced by its size.
MAX_AUDIT_PAYLOAD_VALUE_CHARS = 512

OUTCOME_OK = "ok"
OUTCOME_NOT_FOUND = "not_found"
OUTCOME_CONFLICT = "conflict"
OUTCOME_INVALID = "invalid"


class BulkActionAborted(Exception):
    """A batch that died part-way, carrying the report of what it did reach.

    ``_apply_one`` classifies every refusal a verb is *expected* to produce, so
    reaching here means something else broke — a deadlock, a tracker call that
    timed out, the pool going away. The ids before it are already committed:
    each is its own transaction, which is what makes a batch a partial success
    in the first place. So the failure cannot be handed up bare, or the caller
    would have to answer 500 having no idea what changed — and would write no
    audit row for changes that happened, which is the one thing the trail may
    not do. ``report`` is that partial report; the failure it wrapped stays on
    ``__cause__``, so the 500 the route still answers carries both in its
    traceback.
    """

    def __init__(self, report: dict[str, Any]) -> None:
        super().__init__(
            f"bulk {report['action']} aborted after {report['succeeded']} of "
            f"{report['requested']} ids"
        )
        self.report = report


def _dedupe(ids: Iterable[str]) -> list[str]:
    """Trimmed, non-empty ids, first occurrence kept.

    A selection that names one id twice must not apply the verb twice — a
    double transition is a second ``vulnerability_events`` row for a change
    that happened once. Order is preserved so the report reads in the order the
    caller sent.
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in ids:
        value = (raw or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def validate_ids(ids: Iterable[str]) -> list[str]:
    """The ids a batch will act on. Raises ``ValueError`` for an unusable set.

    The size ceiling is checked here as well as by the request schema: the
    schema is the HTTP contract, this is the invariant, and a future caller
    reaching the service directly gets the same refusal.
    """
    cleaned = _dedupe(ids)
    if not cleaned:
        raise ValueError("no ids to act on")
    if len(cleaned) > MAX_BULK_IDS:
        raise ValueError(
            f"a bulk action may name at most {MAX_BULK_IDS} ids, got {len(cleaned)}"
        )
    if any(len(value) > MAX_BULK_ID_LENGTH for value in cleaned):
        # Request-level, like the count: an id longer than any id this
        # installation issues resolves to nothing anyway, and the reason to
        # refuse it rather than report it ``not_found`` is the audit row —
        # see :data:`MAX_BULK_ID_LENGTH`.
        raise ValueError(
            f"a bulk action id may be at most {MAX_BULK_ID_LENGTH} characters"
        )
    return cleaned


def _apply_one(
    endpoint: str, action: str, item_id: str, verb: Callable[[str], Any]
) -> dict[str, Any]:
    """Run one id's verb and classify what came back.

    The exception map is the same one the single-id routes translate to status
    codes, kept in one place so the two paths cannot disagree about what a
    refusal *is*: ``InvalidVulnTransition`` is the 409 there and ``conflict``
    here, ``ValueError`` is the 422 there and ``invalid`` here, and a service
    returning ``None`` is the 404 there and ``not_found`` here.
    """
    row: dict[str, Any] | None = None
    try:
        result = verb(item_id)
        row = result if isinstance(result, dict) else None
        outcome = OUTCOME_OK if result is not None else OUTCOME_NOT_FOUND
        error = None if result is not None else "not found in this tenant"
    except vuln_states.InvalidVulnTransition as exc:
        outcome, error = OUTCOME_CONFLICT, str(exc)
    except ValueError as exc:
        outcome, error = OUTCOME_INVALID, str(exc)
    metrics_service.BULK_ACTION_ITEMS_TOTAL.labels(
        endpoint=endpoint, action=action, outcome=outcome
    ).inc()
    return {
        "id": item_id,
        "ok": outcome == OUTCOME_OK,
        "outcome": outcome,
        "error": error,
        # The tenant the *row* lives in, which for a platform admin's batch is
        # not the tenant they resolved into: the audit trail is filed per
        # tenant touched (:func:`audit_rows`). Not part of the HTTP answer —
        # ``BulkActionItemResult`` does not carry it.
        "tenant_id": (row or {}).get("tenant_id"),
    }


def _report(
    action: str,
    results: list[dict[str, Any]],
    *,
    requested: int | None = None,
    aborted: bool = False,
) -> dict[str, Any]:
    """The report envelope. ``requested`` is the id count when it is not the
    number of results — a batch that aborted part-way reached fewer ids than it
    was given, and saying ``requested: 99`` of two hundred would hide that."""
    succeeded = sum(1 for item in results if item["ok"])
    report = {
        "action": action,
        "requested": len(results) if requested is None else requested,
        "succeeded": succeeded,
        "failed": len(results) - succeeded,
        "results": results,
    }
    if aborted:
        report["aborted"] = True
    return report


def _apply_each(
    endpoint: str,
    action: str,
    ids: list[str],
    verb: Callable[[str], Any],
) -> list[dict[str, Any]]:
    """Every id's outcome, or :class:`BulkActionAborted` holding what was done.

    The loop is where "one transaction per id" becomes visible: an unclassified
    failure on the hundredth id does not undo the ninety-nine before it, so it
    must not be raised as though nothing had happened either.
    """
    results: list[dict[str, Any]] = []
    for item_id in ids:
        try:
            results.append(_apply_one(endpoint, action, item_id, verb))
        except Exception as exc:
            LOG.exception(
                "bulk %s action=%s aborted on id=%s after %d applied",
                endpoint,
                action,
                item_id,
                sum(1 for item in results if item["ok"]),
            )
            raise BulkActionAborted(
                _report(action, results, requested=len(ids), aborted=True)
            ) from exc
    return results


def apply_vulnerability_action(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_ids: Iterable[str],
    action: str,
    payload: dict[str, Any],
    actor: str | None = None,
) -> dict[str, Any]:
    """Apply one lifecycle verb to many findings. Returns the per-id report.

    ``tenant_id`` is the scope every id is resolved in — ``None`` only for a
    platform admin, exactly as in the single-finding routes' ``_write_scope``,
    so a guessed id from another tenant comes back ``not_found`` instead of
    being mutated.

    ``payload`` is the already-validated body of the corresponding single-verb
    request (``VulnerabilityAssignRequest`` and friends, dumped). Raises
    ``ValueError`` for an unknown action or an unusable id set — those are
    request-level faults, not per-id ones, and the caller has nothing partial
    to report.
    """
    if action not in VULN_ACTIONS:
        raise ValueError(f"unknown bulk action {action!r}")
    ids = validate_ids(vuln_ids)
    verb = _vulnerability_verb(
        settings, tenant_id=tenant_id, action=action, payload=payload, actor=actor
    )
    results = _apply_each("vulnerabilities.bulk", action, ids, verb)
    report = _report(action, results)
    LOG.info(
        "bulk vulnerabilities action=%s tenant=%s requested=%d succeeded=%d failed=%d actor=%s",
        action,
        tenant_id or "*",
        report["requested"],
        report["succeeded"],
        report["failed"],
        actor,
    )
    return report


def _vulnerability_verb(
    settings: Settings,
    *,
    tenant_id: str | None,
    action: str,
    payload: dict[str, Any],
    actor: str | None,
) -> Callable[[str], Any]:
    """One-argument closure over the single-finding service call for ``action``."""
    if action == "assign":
        # Same ``fields`` contract as the single route: only the keys the
        # client actually sent, so ``{"assignee": null}`` unassigns a hundred
        # findings while ``{"owner_team": "x"}`` leaves their assignees alone.
        fields = set(payload) & {"assignee", "owner_team"}
        return lambda vuln_id: vulns_service.assign(
            settings,
            tenant_id=tenant_id,
            vuln_id=vuln_id,
            assignee=payload.get("assignee"),
            owner_team=payload.get("owner_team"),
            actor=actor,
            note=payload.get("note"),
            fields=fields,
        )
    if action == "transition":
        return lambda vuln_id: vulns_service.transition(
            settings,
            tenant_id=tenant_id,
            vuln_id=vuln_id,
            to_state=payload["state"],
            actor=actor,
            note=payload.get("note"),
        )
    if action == "exception":
        return lambda vuln_id: vulns_service.set_exception(
            settings,
            tenant_id=tenant_id,
            vuln_id=vuln_id,
            until=payload["until"],
            reason=payload["reason"],
            actor=actor,
        )
    if action == "ticket":
        return lambda vuln_id: vulns_service.set_ticket(
            settings,
            tenant_id=tenant_id,
            vuln_id=vuln_id,
            system=payload["system"],
            key=payload.get("key"),
            url=payload.get("url"),
            actor=actor,
            note=payload.get("note"),
        )
    # false_positive — the last of VULN_ACTIONS, guarded by the caller.
    return lambda vuln_id: vulns_service.mark_false_positive(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        reason=payload["reason"],
        suppress_days=payload.get("suppress_days", vulns_service.DEFAULT_FP_SUPPRESS_DAYS),
        evidence=payload.get("evidence") or {},
        actor=actor,
    )


def apply_asset_action(
    settings: Settings,
    *,
    tenant_id: str,
    asset_ids: Iterable[str],
    action: str,
    payload: dict[str, Any],
    actor: str | None = None,
) -> dict[str, Any]:
    """Apply one context update to many assets. Returns the per-id report.

    ``tenant_id`` is always a real tenant here, unlike the vulnerability side:
    ``PATCH /api/assets/{id}`` has never had a cross-tenant form
    (``assets.update_asset`` takes a required tenant), and bulk is not the place
    to invent one.
    """
    if action not in ASSET_ACTIONS:
        raise ValueError(f"unknown bulk action {action!r}")
    ids = validate_ids(asset_ids)
    if not payload:
        raise ValueError("a context update needs at least one field")

    def verb(asset_id: str) -> dict | None:
        # A fresh dict per id: ``update_asset`` is free to consume it, and one
        # shared mapping mutated by the first asset would silently change what
        # the rest of the batch is asked to apply.
        return assets_service.update_asset(
            settings, tenant_id, asset_id, dict(payload), actor=actor
        )

    results = _apply_each("assets.bulk", action, ids, verb)
    report = _report(action, results)
    LOG.info(
        "bulk assets action=%s tenant=%s requested=%d succeeded=%d failed=%d actor=%s",
        action,
        tenant_id,
        report["requested"],
        report["succeeded"],
        report["failed"],
        actor,
    )
    return report


def _audit_value(value: Any) -> Any:
    """One ``payload`` value, bounded. See :data:`MAX_AUDIT_PAYLOAD_VALUE_CHARS`."""
    if isinstance(value, str):
        if len(value) <= MAX_AUDIT_PAYLOAD_VALUE_CHARS:
            return value
        return value[:MAX_AUDIT_PAYLOAD_VALUE_CHARS] + "…[truncated]"
    encoded = json.dumps(value, default=str)
    if len(encoded) <= MAX_AUDIT_PAYLOAD_VALUE_CHARS:
        return value
    return f"[{len(encoded)} bytes omitted]"


def _document_bytes(document: dict[str, Any]) -> int:
    """What ``audit.record`` will weigh this document as."""
    return len(json.dumps(document, default=str).encode("utf-8"))


def audit_document(
    report: dict[str, Any],
    payload: dict[str, Any],
    *,
    write_scope: str | None = None,
    aborted: bool = False,
) -> dict[str, Any]:
    """The ``after`` document for the audit row a bulk request owes.

    #346 asks for one row per bulk operation, listing the ids — not one row per
    id, which would bury the fact that this was *one decision* under two
    hundred rows that look like hand edits. ``applied`` is the ids that changed
    and is the answer to "what did this act on"; ``rejected`` maps the rest to
    their outcome *code* rather than its message.

    **The ids are what the row owes, so everything else gives way first.** Past
    :data:`AUDIT_DOCUMENT_BUDGET_BYTES` the body goes, and only if that is not
    enough does the ``rejected`` map collapse to a count per outcome; each step
    says in the document that it happened. Two hundred ids of
    :data:`MAX_BULK_ID_LENGTH` never reach the second step, so in practice the
    row always names them. The alternative to giving something up is not a
    longer document — it is ``audit.record`` replacing the whole thing with
    ``{"truncated": true}``, a row that says a batch happened and not what to.

    ``write_scope`` is recorded because the row's own ``tenant_id`` is the
    tenant the *caller* resolved into, which for an unscoped platform admin is
    not the tenant every id belongs to. ``"*"`` says so rather than leaving a
    reader of the row to assume a batch was confined to one customer.
    """
    document: dict[str, Any] = {
        "action": report["action"],
        "requested": report["requested"],
        "succeeded": report["succeeded"],
        "failed": report["failed"],
        "write_scope": write_scope or "*",
        "applied": [item["id"] for item in report["results"] if item["ok"]],
        "rejected": {
            item["id"]: item["outcome"] for item in report["results"] if not item["ok"]
        },
        "payload": {key: _audit_value(value) for key, value in payload.items()},
    }
    if aborted or report.get("aborted"):
        # The batch stopped on something the per-id outcomes do not describe.
        # ``applied`` is still every id that changed, and ``requested`` still
        # the id count, so the two together say how far it got.
        document["aborted"] = True
    if _document_bytes(document) > AUDIT_DOCUMENT_BUDGET_BYTES:
        document["payload"] = "[omitted: the ids left no room for it]"
    if _document_bytes(document) > AUDIT_DOCUMENT_BUDGET_BYTES:
        counts: dict[str, int] = {}
        for outcome in document["rejected"].values():
            counts[outcome] = counts.get(outcome, 0) + 1
        document["rejected"] = counts
        document["rejected_collapsed"] = True
    return document


def audit_rows(
    report: dict[str, Any],
    payload: dict[str, Any],
    *,
    write_scope: str | None,
    caller_tenant: str,
    aborted: bool = False,
) -> list[tuple[str, dict[str, Any]]]:
    """The ``(tenant_id, document)`` pairs a batch's audit trail owes.

    One row for everyone pinned to a tenant, which is everyone but a platform
    admin: ``write_scope`` *is* the tenant every id was resolved in.

    A platform admin writes with no scope, so their two hundred ids may belong
    to two hundred tenants, and one row filed under the tenant *they* resolved
    into is a row the affected customer's trail never shows — nor their SIEM
    feed, which is filtered by tenant. So that batch is one row per tenant it
    actually touched, each naming only that tenant's ids. Ids that resolved to
    nothing have no tenant to be filed under and stay with the caller's, where
    a reader looking for "what did this admin do" finds them.
    """
    if write_scope is not None:
        return [
            (
                write_scope,
                audit_document(report, payload, write_scope=write_scope, aborted=aborted),
            )
        ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in report["results"]:
        grouped.setdefault(item.get("tenant_id") or caller_tenant, []).append(item)
    return [
        (
            tenant_id,
            audit_document(
                _report(report["action"], results, aborted=bool(report.get("aborted"))),
                payload,
                write_scope=None,
                aborted=aborted,
            ),
        )
        for tenant_id, results in grouped.items()
    ]
