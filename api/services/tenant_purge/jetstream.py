"""The JetStream half of a tenant purge (#325).

What the broker holds for one tenant (``api/services/nats_bus.py``):

* the durable consumers ``octo-agents-{tenant}[-{group}]`` on ``JOBS``, which
  its agents pulled offers through — deleted, matched by their *filter
  subject*, never by name: ``acme``'s consumer for group ``eu`` is called
  ``octo-agents-acme-eu``, which is also tenant ``acme-eu``'s ungrouped one;
* its subjects: ``jobs.scan.{tenant}`` and its group subjects, the results and
  endpoint inventory it sent (``ingest.results.{tenant}``,
  ``ingest.endpoint_inventory.{tenant}``), and the asset and workflow events
  about it (``events.asset.{tenant}.>``, ``events.workflow.{tenant}.>``) —
  purged;
* the deprecated ``ingest.raw_results`` copy of each of its results (#230), a
  subject every tenant shares. Each copy is published right after the tenant's
  own message with the same message id plus ``-legacy``, so it is looked for
  among the next few messages on that subject and deleted by sequence when its
  headers name this tenant. A copy not found there — already gone, or
  republished later by the outbox — ages out with the stream
  (``OCTO_NATS_INGEST_MAX_AGE_SECONDS``, seven days by default); the tombstone
  counts them.

``events.audit.{tenant}`` is left alone: it is the audit trail's feed to a SIEM
(#328), and the trail is exempt from the purge (#329).

Consumers first, so no agent is handed an offer while the rest goes; the legacy
copies before the tenant's own ingest subject, because finding them needs it.
Every call is preceded by a legal-hold check. ``OCTO_NATS_URL`` unset skips the
step.
"""

from __future__ import annotations

from typing import Any

from api.services import nats_bus
from api.services.tenant_purge.context import PurgeContext, StepSkipped

#: How many legacy messages after the tenant's own are examined for its copy.
LEGACY_PROBE = 16


def tenant_subjects(tenant_id: str) -> list[tuple[str, str, str]]:
    """``(tombstone key, stream, subject)`` for every subject that is the tenant's alone."""
    jobs = nats_bus.jobs_scan_subject(tenant_id)
    # The asset and workflow subjects end in a kind token; the prefix before it
    # is built by the same encoder, from a kind that cannot matter here.
    asset = nats_bus.asset_event_subject(tenant_id, "x").rsplit(".", 1)[0]
    workflow = nats_bus.workflow_event_subject(tenant_id, "x").rsplit(".", 1)[0]
    return [
        ("job_offers", nats_bus.STREAM_JOBS, jobs),
        ("job_offers", nats_bus.STREAM_JOBS, f"{jobs}.>"),
        ("ingest_results", nats_bus.STREAM_INGEST, nats_bus.ingest_results_subject(tenant_id)),
        (
            "endpoint_inventory",
            nats_bus.STREAM_INGEST,
            nats_bus.endpoint_inventory_subject(tenant_id),
        ),
        ("asset_events", nats_bus.STREAM_EVENTS, f"{asset}.>"),
        ("workflow_events", nats_bus.STREAM_EVENTS, f"{workflow}.>"),
    ]


def _serves_tenant(subjects: tuple[str, ...], tenant_subject: str) -> bool:
    return any(
        subject == tenant_subject or subject.startswith(f"{tenant_subject}.")
        for subject in subjects
    )


def _headers(message: Any) -> dict[str, str]:
    return dict(getattr(message, "headers", None) or {})


def _drop_legacy_copies(ctx: PurgeContext, bus: nats_bus.NatsBus) -> tuple[int, int]:
    own_subject = nats_bus.ingest_results_subject(ctx.tenant_id)
    deleted = unlocated = 0
    seq = 1
    while True:
        ctx.checkpoint()
        own = bus.next_message(nats_bus.STREAM_INGEST, own_subject, seq)
        if own is None:
            break
        seq = int(own.seq) + 1
        wanted = _headers(own).get("Nats-Msg-Id")
        found = False
        if wanted:
            cursor = int(own.seq) + 1
            for _ in range(LEGACY_PROBE):
                candidate = bus.next_message(
                    nats_bus.STREAM_INGEST, nats_bus.SUBJECT_INGEST_RAW, cursor
                )
                if candidate is None:
                    break
                cursor = int(candidate.seq) + 1
                headers = _headers(candidate)
                if headers.get("Nats-Msg-Id") != f"{wanted}-legacy":
                    continue
                found = True
                # The header is the publisher's statement of whose run this
                # is; a copy that says otherwise is left where it is.
                if headers.get("tenant_id") == ctx.tenant_id and bus.delete_message(
                    nats_bus.STREAM_INGEST, int(candidate.seq)
                ):
                    deleted += 1
                break
        if not found:
            unlocated += 1
    return deleted, unlocated


def run(ctx: PurgeContext) -> dict[str, Any]:
    url = (ctx.settings.nats_url or "").strip()
    if not url:
        raise StepSkipped("NATS is not configured (OCTO_NATS_URL)")
    bus = nats_bus.get_bus(url)
    if bus is None:
        # Configured and unreachable is a failure to retry, not a store to skip.
        raise RuntimeError("NATS is configured but the bus could not connect")

    def record(counts: dict[str, int]) -> None:
        # Per call, in a guard of its own: an attempt that fails half way
        # keeps the count of what it did remove.
        with ctx.guard() as session:
            ctx.add_counts(session, counts)

    jobs_subject = nats_bus.jobs_scan_subject(ctx.tenant_id)
    for name, subjects in bus.consumers(nats_bus.STREAM_JOBS):
        if not _serves_tenant(subjects, jobs_subject):
            continue
        ctx.checkpoint()
        if bus.delete_consumer(nats_bus.STREAM_JOBS, name):
            record({"consumers": 1})
    bus.forget_jobs_consumers(ctx.tenant_id)

    legacy_deleted, legacy_unlocated = _drop_legacy_copies(ctx, bus)
    record(
        {"legacy_ingest_copies": legacy_deleted, "legacy_ingest_unlocated": legacy_unlocated}
    )

    for key, stream, subject in tenant_subjects(ctx.tenant_id):
        ctx.checkpoint()
        purged = bus.purge_subject(stream, subject)
        if purged:
            record({key: purged})

    left = {
        subject: bus.subject_count(stream, subject)
        for _key, stream, subject in tenant_subjects(ctx.tenant_id)
    }
    left = {subject: count for subject, count in left.items() if count}
    still_serving = [
        name
        for name, subjects in bus.consumers(nats_bus.STREAM_JOBS)
        if _serves_tenant(subjects, jobs_subject)
    ]
    if left or still_serving:
        raise RuntimeError(
            f"JetStream still holds the tenant after the purge: subjects {left}, "
            f"consumers {still_serving}"
        )
    zero = {key: 0 for key, _stream, _subject in tenant_subjects(ctx.tenant_id)}
    return {**zero, "consumers": 0, "legacy_ingest_copies": 0, "legacy_ingest_unlocated": 0}
