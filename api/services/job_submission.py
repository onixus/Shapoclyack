"""Scan submission orchestration.

This is the write-side boundary for creating jobs. It coordinates admission,
input materialization, intent resolution, idempotency and executor hand-off.
The public compatibility facade remains api.services.jobs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
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


def build_command(
    settings: Settings,
    *,
    mode: str,
    delta: bool,
    skip_nse: bool,
    notify: bool,
    export_defectdojo: bool,
    run_id: str | None,
    target_args: list[str],
    config_path: str,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "scanner.main",
        "--config",
        config_path,
        "--mode",
        mode,
    ]
    if delta:
        command.append("--delta")
    if skip_nse:
        command.append("--skip-nse")
    if notify:
        command.append("--notify")
    if export_defectdojo:
        command.append("--export-defectdojo")
    if run_id:
        command.extend(["--run-id", run_id])
    command.extend(target_args)
    return command


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
    """Admit, persist and dispatch one new scan job.

    ``widen_with_promoted`` is whether this scan carries the related domains
    the tenant's operators promoted (org_profile M4) on top of its own
    targets. On by default — that is what promotion means — and off for a
    dispatch that is aimed at one thing, today the verification re-scan of
    #183. A separate switch from ``quota_exempt`` on purpose: billing and
    targeting are different policies that happen to coincide on that one
    caller.

    ``quota_exempt`` marks a scan the platform dispatched to close its own
    loop — today only the verification re-scan of #183. It is neither refused
    by the tenant's monthly quota nor counted against it, and it is a property
    of *this dispatch*: the requester's name is the analyst's on that path, so
    recognising the exemption by username would be both wrong and forgeable.

    ``build_command``, ``run_local_job`` and ``publish_offer`` are passed in
    rather than imported so that the jobs facade stays the seam existing tests
    replace, and so this module does not depend on the executor it starts.
    """
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

    # Admission already refused everything that can be refused, so what is
    # left here is file writing. Anything that escapes it is a half-written
    # scratch directory no job will ever own.
    try:
        _, target_counts, target_args = (
            job_inputs.prepare_target_inputs(
                settings,
                job_id,
                tenant_id=tenant_id,
                parsed=admission.parsed_targets,
                promoted=promoted_admitted,
                scope=scope,
                policy=policy_snapshot,
            )
        )
        job_inputs.publish(settings, job_id)
    except Exception:
        job_inputs.discard(settings, job_id)
        raise

    # Local scans run in this container, so apply the installation config
    # overrides by merging them into a job-specific config file. Agents run
    # their own mounted config, so overrides don't reach them — they keep the
    # base config (documented limitation). Intent nuclei/top_ports overlays
    # are local-only for the same reason.
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
            # A custom wordlist lives in the API's Postgres and is
            # materialized onto the API pod's filesystem; a remote agent runs
            # its own mounted config and never sees it. Rather than silently
            # ignore the request, refuse it — the same class of limitation as
            # installation overrides not reaching agents.
            raise ValueError(
                "wordlist_id is only supported in local execution "
                "mode, not with remote agents"
            )
        if intent_extra:
            # Agent workers do not receive the merged effective-config file;
            # surface that so operators do not think nuclei floors applied.
            _log.warning(
                "intent=%s config overlays (nuclei/top_ports) are "
                "skipped in agent mode; CLI flags delta=%s "
                "skip_nse=%s still apply",
                resolved.intent,
                resolved.delta,
                resolved.skip_nse,
            )
        config_path = str(settings.config_path)

    # Derived from the targets as the operator entered them, not from the
    # widened set: a promoted related domain rides along with every scan and
    # would turn an internal sweep into a "mixed" one it was never asked to be.
    surface = scan_surface.resolve(
        request.surface, request.ranges, request.domains
    )
    # A fragile (OT/ICS) policy turns the service-probe stage off: nmap's NSE
    # scripts and pulse's banner grabs are the packets that put a PLC into a
    # fault state, and the port inventory a fragile run is really asked for
    # does not need them. Expressed on the command line as well as in the
    # policy document the scanner applies, so a reader of the job — and the
    # ``--skip-nse`` the scanner sees — says the same thing.
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
        # Lost the race on (tenant_id, idempotency_key): another replica — or
        # this one, serving the client's retry concurrently — already created
        # the job. The caller wanted one scan for this key and there is one.
        # This job_id never became a row, so its materialized wordlist (and
        # the merged config beside it) and its input files would be read by
        # nobody — discarded first, so the mismatch below does not leak them.
        job_inputs.discard_wordlist(settings, job_id)
        job_inputs.discard(settings, job_id)
        # ``request=`` here too: the racing pair may not be the same scan, and
        # the loser of the race must hear that rather than be handed a job for
        # targets it never asked about.
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
        # Raised rather than returned so the caller can answer 200 here too:
        # this request accepted nothing, exactly like the sequential replay
        # the route detects before calling in.
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
