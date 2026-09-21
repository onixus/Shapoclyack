"""Scan submission orchestration.

This is the write-side boundary for creating jobs. It coordinates admission,
input materialization, intent resolution, idempotency and executor hand-off.
The public compatibility facade remains api.services.jobs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from api.db import models
from api.db.engine import get_session
from api.schemas import JobInfo, StartScanRequest
from api.services import agent_groups as agent_groups_service
from api.services import config_override as config_override_service
from api.services import job_inputs
from api.services import job_states
from api.services import job_store
from api.services import local_scan_executor
from api.services import metrics as metrics_service
from api.services import run_ids
from api.services import scan_admission
from api.services import scan_intents
from api.services import scan_scopes
from api.services import scan_surface
from api.settings import Settings

_log = logging.getLogger(__name__)

_IDEMPOTENCY_FIELDS = (
    "mode",
    "intent",
    "delta",
    "skip_nse",
    "notify",
    "export_defectdojo",
    "surface",
    "wordlist_id",
    "agent_group",
)
_IDEMPOTENCY_TARGET_FIELDS = (
    "ranges",
    "domains",
    "ports",
    "ports_udp",
)


class IdempotencyMismatch(Exception):
    """An idempotency key reused for a different scan request."""

    def __init__(self, job: JobInfo) -> None:
        super().__init__(
            "Idempotency-Key already used for a different scan request "
            f"(job {job.job_id})"
        )
        self.job = job


class IdempotentReplay(Exception):
    """A concurrent start whose key already created a job."""

    def __init__(self, job: JobInfo) -> None:
        super().__init__(
            f"Idempotency key already started job {job.job_id}"
        )
        self.job = job


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _normalised_target_text(text: str | None) -> str | None:
    if text is None:
        return None
    return "\n".join(
        line.strip() for line in text.splitlines() if line.strip()
    )


def idempotency_digest(request: StartScanRequest) -> str:
    payload: dict[str, Any] = {
        field: getattr(request, field)
        for field in _IDEMPOTENCY_FIELDS
    }
    payload.update(
        {
            field: _normalised_target_text(getattr(request, field))
            for field in _IDEMPOTENCY_TARGET_FIELDS
        }
    )
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def note_start_replay() -> None:
    metrics_service.JOB_IDEMPOTENT_REPLAYS_TOTAL.labels(
        operation="start"
    ).inc()


def find_by_idempotency_key(
    settings: Settings,
    *,
    tenant_id: str,
    key: str,
    request: StartScanRequest | None = None,
) -> JobInfo | None:
    if not key:
        return None
    with get_session(settings.postgres_url) as session:
        row = (
            session.execute(
                select(models.Job).where(
                    models.Job.tenant_id == tenant_id,
                    models.Job.idempotency_key == key,
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            return None
        info = job_store.to_info(row)

    if request is not None:
        stored = (row.scan_options or {}).get(
            "idempotency_digest"
        )
        if stored and stored != idempotency_digest(request):
            raise IdempotencyMismatch(info)
    return info


def start_scan(
    settings: Settings,
    request: StartScanRequest,
    *,
    username: str,
    build_command: Callable[..., list[str]],
    run_local_job: Callable[[Settings, str, list[str]], None],
    thread_factory: Callable[..., Any] = threading.Thread,
    publish_offer: Callable[[Settings, str], None],
    idempotency_key: str | None = None,
    quota_exempt: bool = False,
    widen_with_promoted: bool = True,
) -> JobInfo:
    """Admit, persist and dispatch one new scan job."""
    if not settings.allow_scan_start:
        raise RuntimeError(
            "Scan start disabled by OCTO_ALLOW_SCAN_START"
        )

    job_id = uuid.uuid4().hex[:12]
    execution = (
        "agent"
        if settings.job_execution_mode == "agent"
        else "local"
    )
    run_id = request.run_id
    if run_id:
        run_ids.validate(run_id)
    if execution == "agent" and not run_id:
        run_id = run_ids.mint()

    admission = scan_admission.admit_scan(
        settings,
        request,
        username=username,
        job_id=job_id,
        execution=execution,
        quota_exempt=quota_exempt,
        widen_with_promoted=widen_with_promoted,
    )
    tenant_id = admission.tenant_id
    scope = admission.scope
    promoted_admitted = list(admission.promoted_admitted)
    promoted_refused = list(admission.promoted_refused)
    policy_snapshot = admission.policy_snapshot
    agent_group = admission.agent_group
    group_has_live_agent = admission.group_has_live_agent

    try:
        _, target_counts, target_args = (
            job_inputs.prepare_target_inputs(
                settings,
                job_id,
                request,
                tenant_id=tenant_id,
                promoted=promoted_admitted,
                scope=scope,
                policy=policy_snapshot,
            )
        )
        job_inputs.publish(settings, job_id)
    except scan_scopes.ScanScopeDenied as denied:
        scan_scopes.record_denial(
            username=username, denied=denied
        )
        job_inputs.discard(settings, job_id)
        raise

    resolved = scan_intents.resolve_scan_options(
        intent=request.intent,
        mode=request.mode,
        delta=request.delta,
        skip_nse=request.skip_nse,
    )

    wordlist_options: dict[str, Any] = {}
    intent_extra = resolved.config_extra
    if execution == "local":
        selected = job_inputs.wordlist_overrides(
            settings,
            job_id,
            tenant_id,
            request.wordlist_id,
        )
        wordlist_extra: dict[str, Any] | None = None
        if selected:
            wordlist_extra, wordlist_options = selected
        extra = scan_intents.merge_config_extras(
            intent_extra, wordlist_extra
        )
        config_path = (
            config_override_service.effective_config_path(
                settings, job_id, extra
            )
        )
    else:
        if request.wordlist_id:
            raise ValueError(
                "wordlist_id is only supported in local execution "
                "mode, not with remote agents"
            )
        if intent_extra:
            _log.warning(
                "intent=%s config overlays (nuclei/top_ports) are "
                "skipped in agent mode; CLI flags delta=%s "
                "skip_nse=%s still apply",
                resolved.intent,
                resolved.delta,
                resolved.skip_nse,
            )
        config_path = str(settings.config_path)

    surface = scan_surface.resolve(
        request.surface, request.ranges, request.domains
    )
    skip_nse = resolved.skip_nse or bool(
        (policy_snapshot or {}).get("skip_service_probe")
    )
    command = build_command(
        settings,
        mode=resolved.mode,
        delta=resolved.delta,
        skip_nse=skip_nse,
        notify=request.notify,
        export_defectdojo=request.export_defectdojo,
        run_id=run_id,
        target_args=target_args,
        config_path=config_path,
    )

    row = models.Job(
        job_id=job_id,
        tenant_id=tenant_id,
        status=job_states.QUEUED,
        execution=execution,
        mode=resolved.mode,
        run_id=run_id,
        command=command,
        scan_options={
            "mode": resolved.mode,
            "intent": resolved.intent,
            "intent_summary": (
                resolved.summary if resolved.intent else None
            ),
            "delta": resolved.delta,
            **(
                {"promoted_domains": promoted_admitted}
                if promoted_admitted
                else {}
            ),
            **(
                {"promoted_domains_refused": promoted_refused}
                if promoted_refused
                else {}
            ),
            "skip_nse": skip_nse,
            **(
                {"scan_policy": policy_snapshot}
                if policy_snapshot
                else {}
            ),
            "surface": surface,
            "surface_source": (
                "operator"
                if request.surface
                else ("derived" if surface else None)
            ),
            "notify": request.notify,
            "export_defectdojo": request.export_defectdojo,
            **(
                {"agent_group": agent_group}
                if agent_group
                else {}
            ),
            **(
                {
                    "idempotency_digest": idempotency_digest(
                        request
                    )
                }
                if idempotency_key
                else {}
            ),
            **wordlist_options,
        },
        target_counts=target_counts,
        requested_by=username,
        agent_group=agent_group,
        assigned_agent_id=None,
        owner_id=(
            settings.instance_id
            if execution == "local"
            else None
        ),
        idempotency_key=(idempotency_key or None),
        quota_exempt=quota_exempt,
        queued_at=_now(),
    )

    try:
        with get_session(settings.postgres_url) as session:
            if agent_group:
                if not agent_groups_service.lock_existing_names(
                    session,
                    tenant_id=tenant_id,
                    names={agent_group},
                ):
                    raise ValueError(
                        "Unknown agent_group for tenant "
                        f"{tenant_id}: {agent_group}"
                    )
            session.add(row)
            session.flush()
            info = job_store.to_info(
                row,
                (
                    (
                        {(tenant_id, agent_group)}
                        if group_has_live_agent
                        else set()
                    )
                    if agent_group
                    else None
                ),
            )
    except ValueError:
        job_inputs.discard_wordlist(settings, job_id)
        job_inputs.discard(settings, job_id)
        raise
    except IntegrityError:
        job_inputs.discard_wordlist(settings, job_id)
        job_inputs.discard(settings, job_id)
        existing = find_by_idempotency_key(
            settings,
            tenant_id=tenant_id,
            key=idempotency_key or "",
            request=request,
        )
        if existing is None:
            raise
        _log.info(
            "Idempotent scan start: key already created job %s",
            existing.job_id,
        )
        raise IdempotentReplay(existing) from None

    job_store.refresh_job_gauges(settings)

    if execution == "local":
        thread = thread_factory(
            target=run_local_job,
            args=(settings, job_id, command),
            name=f"octo-scan-{job_id}",
            daemon=True,
        )
        local_scan_executor.register_thread(thread)
        thread.start()
    elif execution == "agent" and settings.nats_url:
        publish_offer(settings, job_id)

    return info
