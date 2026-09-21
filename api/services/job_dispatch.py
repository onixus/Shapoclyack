"""Dispatch notifications for queued agent jobs.

The database row is the queue. NATS is only a wake-up hint telling eligible
agents to claim sooner, so failures here never change queue state.
"""

from __future__ import annotations

import logging

from api.db import models
from api.db.engine import get_session
from api.services import nats_bus
from api.services import tenants as tenants_service
from api.settings import Settings

_log = logging.getLogger(__name__)


def publish_offer(settings: Settings, job_id: str) -> None:
    """Announce one queued job on the subject its entitled agents listen to.

    The offer is a notification, not a hand-out: it names the job and nothing
    about what the job reaches. ``inputs`` used to travel in it, which made the
    body of every offer a copy of the scan's target list — and since the body
    is read before the claim, an agent could read the targets of a job it was
    then refused (#361). The claim response carries them instead, to the one
    agent the API has just bound the job to.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return
        opts = dict(row.scan_options or {})
        payload = {
            "job_id": row.job_id,
            "run_id": row.run_id or "",
            "mode": row.mode or opts.get("mode") or "balanced",
            "delta": bool(opts.get("delta", False)),
            "skip_nse": bool(opts.get("skip_nse", False)),
            "notify": bool(opts.get("notify", False)),
            "export_defectdojo": bool(opts.get("export_defectdojo", False)),
            "tenant_id": row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
            # Decides the subject, so only the group's own agents are offered
            # it at all; repeated in the body so a subscriber can tell a
            # misrouted offer from one of its own.
            "agent_group": row.agent_group,
        }
    bus = nats_bus.get_bus(settings.nats_url)
    if bus is None:
        _log.warning(
            "NATS configured but unavailable; job %s stays queued for HTTP claim",
            job_id,
        )
        return
    subject = nats_bus.jobs_scan_subject(
        str(payload["tenant_id"]), payload["agent_group"]
    )
    if bus.publish_job_offer(payload):
        _log.info("Published %s offer for %s", subject, job_id)
    else:
        _log.warning(
            "Failed to publish %s for %s; HTTP claim still available",
            subject,
            job_id,
        )
