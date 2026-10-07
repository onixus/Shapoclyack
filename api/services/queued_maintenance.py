"""Calendar admission at the queued → claimed/running boundary (#516)."""

from __future__ import annotations

from api.db import models
from api.services import audit
from api.services import job_inputs
from api.services import maintenance
from api.settings import Settings


def evaluate(settings: Settings, session, row: models.Job) -> maintenance.Admission:
    options = row.scan_options or {}
    targets = options.get("maintenance_targets")
    if targets is None:
        # Jobs admitted before #516 have the executor's persisted input files.
        # Missing targets mean installation defaults: the calendar then applies
        # every group window conservatively, just as submission admission does.
        directory = job_inputs.ensure_local(settings, row.job_id)

        def read(name: str) -> str:
            path = directory / name
            return path.read_text(encoding="utf-8") if path.is_file() else ""

        ranges, domains = read("ranges.txt"), read("domains.txt")
        targets = {
            "ranges": ranges,
            "domains": (
                "\n".join([domains, read(job_inputs.PROMOTED_DOMAINS_INPUT)])
                if ranges.strip() or domains.strip() else ""
            ),
        }
    return maintenance.evaluate(
        settings, tenant_id=row.tenant_id, ranges_text=targets.get("ranges"),
        domains_text=targets.get("domains"), session=session,
    )


def admitted(settings: Settings, session, row: models.Job) -> bool:
    """Keep a blocked job queued and audit only changes in its waiting reason.

    Use the claim transaction for both the calendar read and the audit write;
    opening a second pooled session while holding the job lock could exhaust
    a small pool. No attempts, ownership or running lease are consumed here.
    """
    admission = evaluate(settings, session, row)
    options = dict(row.scan_options or {})
    previous = options.get("maintenance_wait")
    if admission.allowed:
        if previous is not None:
            options.pop("maintenance_wait", None)
            row.scan_options = options
        return True
    waiting = admission.as_dict()
    if waiting != previous:
        options["maintenance_wait"] = waiting
        row.scan_options = options
        audit.record(
            session, audit.system_context(actor=row.requested_by or "system"),
            action=audit.ACTION_SCAN_MAINTENANCE_BLOCK,
            resource_type="job", resource_id=row.job_id, tenant_id=row.tenant_id,
            after=waiting,
        )
    return False
