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
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from agent.runtime.invocation import ScanInvocation
from api.db import models
from api.db.engine import get_session
from api.schemas import JobInfo, StartScanRequest
from api.services import agent_groups as agent_groups_service
from api.services import config_override as config_override_service
from api.services import (
    job_control,
    job_inputs,
    job_sharding,
    job_states,
    job_store,
    licensing,
    local_scan_executor,
    run_ids,
    scan_admission,
    scan_intents,
    scan_surface,
)
from api.services import metrics as metrics_service
from api.services import tenants as tenants_service
from api.services.artifact_store import keys as artifact_keys
from api.services.artifact_store import workspace as artifact_workspace
from api.services.licensing import LicenseExpired, LicenseMissing  # noqa: F401 — raised by assert
from api.settings import Settings
from scanner.pipeline import config_overlay

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
    "shard_count",
    "stage2_enrichment",
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


def _annotate_shard_siblings(
    settings: Settings,
    job_id: str,
    sibling_ids: list[str],
    *,
    idempotency_digest_value: str | None = None,
) -> None:
    """Record the sibling set once every shard of the group exists.

    ``idempotency_digest_value`` is the digest of the *operator's* request,
    not of the narrowed child. A replay compares the key against that body;
    a digest of one shard would 409 the retry that asked for the group.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return
        options = dict(row.scan_options or {})
        options["shard_job_ids"] = list(sibling_ids)
        if idempotency_digest_value:
            options["idempotency_digest"] = idempotency_digest_value
        row.scan_options = options
        session.commit()


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
    input_paths: Mapping[str, str],
    config_path: str,
) -> list[str]:
    return ScanInvocation(
        config=config_path,
        mode=mode,
        delta=delta,
        skip_nse=skip_nse,
        notify=notify,
        export_defectdojo=export_defectdojo,
        run_id=run_id,
        inputs=input_paths,
    ).argv(sys.executable)


def _reserve_run_dir(settings: Settings, run_id: str) -> Path:
    """Claim ``runs/<run_id>`` for a local scan with a custom run id, atomically.

    The scanner writes that directory itself, into whatever is there, so two
    scans given one run id -- two tenants, submitted together -- would write
    one directory, and the first to finish would carry both into its tenant's
    subtree (#427). A check that the directory is free is a race between two
    requests; ``mkdir`` without ``exist_ok`` is the one step only one of them
    can win.
    """
    path = Path(settings.output_dir) / "runs" / run_id
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.mkdir()
    except FileExistsError:
        raise ValueError(f"run_id {run_id!r} is already in use by an existing run") from None
    return path


def _release_run_dir(path: Path | None) -> None:
    """Give back a reservation no job was created for. Only while it is empty."""
    if path is None:
        return
    try:
        path.rmdir()
    except OSError:
        _log.warning("Could not release the reserved run directory %s", path, exc_info=True)


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
    config_extra: dict[str, Any] | None = None,
    min_overlay_version: int = 1,
    verification_of: str | None = None,
    expected_admission_sha256: str | None = None,
    _shard_meta: dict[str, Any] | None = None,
    _stage2_meta: dict[str, Any] | None = None,
    _defer_dispatch: bool = False,
) -> JobInfo:
    """Admit, persist and dispatch one new scan job.

    When ``request.shard_count`` is set (and ``_shard_meta`` is absent), the
    request is admitted once and the *accepted* ranges and domains are
    partitioned into claimable sibling jobs (FTT-PULSE-2026-052). The caller
    receives the lowest shard; every sibling records ``shard_group_id`` and
    ``shard_job_ids`` in ``scan_options``. A repeat of the same
    ``Idempotency-Key`` raises ``IdempotentReplay`` of that shard rather than
    queueing a second group. Shard 0 spends the quota and the queue slot;
    its siblings are exempt, so one estate is one scan.

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

    ``config_extra`` is a per-job scanner setting the platform adds on top of
    the intent's — today the verification re-scan's pinned nuclei templates.
    It travels exactly where the intent's settings do (the local run's merged
    config, the sensor's overlay) and is merged after them. Never from a
    request body: it is held to the overlay allow-list here, and a job whose
    overlay needs a newer version than the console's settings asks its
    claimant for that version (``config_overlay.required_capability``).

    ``min_overlay_version`` raises that requirement for a job whose *purpose*
    needs a newer sensor whatever its overlay carries, and
    ``verification_of`` names the finding such a job re-checks (stored as
    ``scan_options.verification_of``): both are the verification re-scan's,
    whose closure is judged on evidence only an overlay-v2 build writes.

    ``build_command``, ``run_local_job`` and ``publish_offer`` are passed in
    rather than imported so that the jobs facade stays the seam existing tests
    replace, and so this module does not depend on the executor it starts.
    """
    if not settings.allow_scan_start:
        raise RuntimeError(
            "Scan start disabled by OCTO_ALLOW_SCAN_START"
        )
    # Product term / missing license when enforcement is on (ADR 0007).
    # LicenseExpired / LicenseMissing are PermissionError subclasses; the jobs
    # route maps them to 403 alongside the RuntimeError above.
    licensing.assert_new_scan_allowed(settings)
    if config_extra:
        # Before anything is admitted or written: a setting a sensor would
        # refuse is refused where the job is created, as the overlay is.
        config_overlay.check_config(config_extra)
    # The saved console overrides, too (#548): a leftover Nmap setting is
    # refused here, for every way a scan starts, not by the sensor afterwards.
    config_override_service.assert_runnable(settings, config_extra)

    # Horizontal scale: one estate → N claimable jobs (FTT-PULSE-2026-052).
    # Cut the *admitted* lines, never the raw text: scope, promoted domains
    # and the maintenance window are decided against the whole estate first,
    # then the accepted set is split. A retry of the same key finds shard 0
    # and replays it; it must not queue a second group.
    if request.shard_count and _shard_meta is None:
        if idempotency_key:
            existing = find_by_idempotency_key(
                settings,
                tenant_id=(request.tenant_id or tenants_service.DEFAULT_TENANT_ID).strip(),
                key=idempotency_key,
                request=request,
            )
            if existing is not None:
                raise IdempotentReplay(existing)
        preview_id = uuid.uuid4().hex[:12]
        execution = (
            "agent" if settings.job_execution_mode == "agent" else "local"
        )
        # Local mode starts a scanner thread per job. Spawning N of them on
        # the API pod (and being unable to cancel a running local job on
        # partial failure) is not an estate-scale path — require agent mode.
        job_sharding.require_agent_execution_for_shards(execution)
        admission = scan_admission.admit_scan(
            settings,
            request,
            username=username,
            job_id=preview_id,
            execution=execution,
            quota_exempt=quota_exempt,
            widen_with_promoted=widen_with_promoted,
        )
        if expected_admission_sha256 is not None and scan_admission.admission_digest(
                admission, execution=execution) != expected_admission_sha256:
            raise ValueError("Confirmed scan admission changed; prepare a new proposal")
        parsed = admission.parsed_targets
        admitted_ranges = list(parsed.ranges or []) if parsed else []
        admitted_domains = list(parsed.domains or []) if parsed else []
        # Promoted names ride with the estate, but each name belongs to one
        # shard. Copying the whole list onto every child would scan them N
        # times and could pull a name into a shard whose own targets never
        # justified it.
        admitted_domains.extend(admission.promoted_admitted)
        partitions = job_sharding.partition_targets(
            ranges="\n".join(admitted_ranges),
            domains="\n".join(admitted_domains),
            shard_count=request.shard_count,
        )
        group_id = uuid.uuid4().hex[:12]
        parent_digest = (
            idempotency_digest(request) if idempotency_key else None
        )
        created: list[JobInfo] = []
        try:
            for part in partitions:
                child = request.model_copy(
                    update={
                        "ranges": part.ranges or None,
                        "domains": part.domains or None,
                        "shard_count": None,
                        # The group's run id, if the operator named one, belongs
                        # to shard 0. A shared run id would collide on the
                        # local reservation and mix artifact trees.
                        "run_id": request.run_id if part.shard_index == partitions[0].shard_index else None,
                    }
                )
                is_primary = part.shard_index == partitions[0].shard_index
                shard_meta: dict[str, Any] = {
                    "shard_group_id": group_id,
                    "shard_index": part.shard_index,
                    "shard_count": part.shard_count,
                    "shard_of": len(partitions),
                }
                # Persist the operator digest on insert so a concurrent retry
                # of the same Idempotency-Key does not 409 against a child
                # digest during the multi-insert window.
                if is_primary and parent_digest:
                    shard_meta["idempotency_digest"] = parent_digest
                created.append(
                    start_scan(
                        settings,
                        child,
                        username=username,
                        build_command=build_command,
                        run_local_job=run_local_job,
                        thread_factory=thread_factory,
                        publish_offer=publish_offer,
                        # One key covers the group and lives on the shard the
                        # caller is handed, so a replay finds that job.
                        idempotency_key=(
                            idempotency_key if is_primary else None
                        ),
                        # Shard 0 spends the monthly scan and the queue slot.
                        # Siblings are the same estate, not N more scans, and
                        # must not trip the depth ceiling mid-group.
                        quota_exempt=(
                            quota_exempt or not is_primary
                        ),
                        # Already folded into the admitted lines above.
                        widen_with_promoted=False,
                        config_extra=config_extra,
                        min_overlay_version=min_overlay_version,
                        verification_of=verification_of,
                        expected_admission_sha256=None,
                        _shard_meta=shard_meta,
                        # Persist the whole group before any NATS offer: a
                        # mid-group failure must cancel queued siblings, not
                        # leave sensors already claiming partial work.
                        _defer_dispatch=True,
                    )
                )
        except Exception:
            # A sibling that already queued is not a scan anyone asked for
            # on its own: the group did not finish. Cancel what landed,
            # including after losing the idempotency race to a concurrent
            # start of the same key.
            for job in created:
                try:
                    job_control.cancel_job(
                        settings, job.job_id, username=username
                    )
                except Exception:
                    _log.warning(
                        "Could not cancel shard %s after the group failed",
                        job.job_id,
                        exc_info=True,
                    )
            raise
        sibling_ids = [job.job_id for job in created]
        primary = created[0]
        for job in created:
            _annotate_shard_siblings(
                settings,
                job.job_id,
                sibling_ids,
            )
        # Group is fully persisted and annotated — now wake sensors.
        if settings.nats_url:
            for job in created:
                publish_offer(settings, job.job_id)
        with get_session(settings.postgres_url) as session:
            row = session.get(models.Job, primary.job_id)
            if row is not None:
                return job_store.to_info(row)
        return primary

    job_id = uuid.uuid4().hex[:12]
    execution = (
        "agent"
        if settings.job_execution_mode == "agent"
        else "local"
    )
    run_id = request.run_id
    if run_id:
        run_ids.validate(run_id)
        if execution == "local" and artifact_workspace.run_exists(
            settings, artifact_keys.run_ref(run_id)
        ):
            # A local scan writes ``runs/<run_id>`` itself, into whatever is
            # already there: a flat run of another tenant, or the default's,
            # would get this scan's files mixed into it (#427).
            raise ValueError(f"run_id {run_id!r} is already in use by an existing run")
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
    if expected_admission_sha256 is not None and scan_admission.admission_digest(
            admission, execution=execution) != expected_admission_sha256:
        raise ValueError("Confirmed scan admission changed; prepare a new proposal")
    tenant_id = admission.tenant_id
    scope = admission.scope
    promoted_admitted = list(admission.promoted_admitted)
    promoted_refused = list(admission.promoted_refused)
    policy_snapshot = admission.policy_snapshot
    agent_group = admission.agent_group
    parsed_targets = admission.parsed_targets

    resolved = scan_intents.resolve_scan_options(
        intent=request.intent,
        mode=request.mode,
        delta=request.delta,
        skip_nse=request.skip_nse,
    )
    intent_extra = (
        scan_intents.merge_config_extras(resolved.config_extra, config_extra) or {}
    )
    # Brand Watch is a soft gate: without the entitlement, force the
    # domain-monitor stage off rather than refusing the whole scan (ADR 0007).
    intent_extra = licensing.brand_watch_overlay(settings, intent_extra)
    if execution == "agent" and request.wordlist_id:
        # A custom wordlist lives in the API's Postgres and is materialized
        # onto the API pod's filesystem; a remote agent never sees it. Refused
        # rather than ignored, and before any input file is written. Not
        # forwarded like the config overlay below because a wordlist is a file
        # of up to a few megabytes per job, not a handful of settings (#338).
        raise ValueError(
            "wordlist_id is only supported in local execution "
            "mode, not with remote agents"
        )
    # A local scan runs on a config file written for it below, with the
    # installation's overrides and the intent's settings merged in. A remote
    # executor runs on its own host's config, so the same two travel with the
    # job as its config overlay and the scanner merges them there (#338
    # review; scanner/pipeline/config_overlay.py). Before, they stopped here.
    overlay = (
        config_override_service.agent_overlay(settings, intent_extra)
        if execution == "agent"
        else None
    )

    # Admission already refused everything that can be refused, so what is
    # left here is file writing. Anything that escapes it is a half-written
    # scratch directory no job will ever own.
    try:
        _, target_counts, input_paths = (
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
        if overlay:
            input_paths[job_inputs.CONFIG_OVERLAY_INPUT] = (
                job_inputs.write_config_overlay_input(settings, job_id, overlay)
            )
        job_inputs.publish(settings, job_id)
    except Exception:
        job_inputs.discard(settings, job_id)
        raise

    wordlist_options: dict[str, Any] = {}
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
        config_path = str(settings.config_path)

    # Derived from the targets as the operator entered them, not from the
    # widened set: a promoted related domain rides along with every scan and
    # would turn an internal sweep into a "mixed" one it was never asked to be.
    surface = scan_surface.resolve(
        request.surface, request.ranges, request.domains
    )
    # A fragile (OT/ICS) policy turns the service-probe stage off: pulse's
    # banner grabs and plugins are the packets that put a PLC into a
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
        input_paths=input_paths,
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
            "maintenance_targets": {
                "ranges": "\n".join(parsed_targets.ranges or []) if parsed_targets else "",
                # Installation defaults can reach unknown groups even when
                # promoted domains accompany them. Keep that conservative gate.
                "domains": (
                    "\n".join([*(parsed_targets.domains or []), *promoted_admitted])
                    if parsed_targets and parsed_targets.ranges is not None else ""
                ),
            },
            "mode": resolved.mode,
            # The CLI only runs safe/balanced/fast. ``test`` is stored as
            # balanced; keep the mode the caller asked for on the job.
            "requested_mode": request.mode,
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
            # What the executor was sent, for the job record and for the claim:
            # a job carrying one is only handed to an agent that applies it.
            # Never holds a secret — ``agent_overlay`` leaves SECRET_PATHS out.
            **({"config_overlay": overlay} if overlay else {}),
            # And which overlay version that claimant has to apply: the
            # lowest that covers it, so a sensor that predates a setting is
            # refused only the jobs that use it (config_overlay.py).
            **(
                {
                    config_override_service.OVERLAY_CAPABILITY_OPTION: config_overlay.capability(
                        max(config_overlay.required_version(overlay), min_overlay_version)
                    )
                }
                if overlay
                else {}
            ),
            **({"verification_of": verification_of} if verification_of else {}),
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
            # Opt-in Stage2 fan-out after this job's run publishes
            # (FTT-PULSE-2026-054). Stage2 children pass ``_stage2_meta`` and
            # keep this false so they never recurse.
            **(
                {"stage2_enrichment": True}
                if request.stage2_enrichment and not _stage2_meta
                else {}
            ),
            # Shard meta last so a parent idempotency_digest on the primary
            # overrides the narrowed-child digest computed above.
            **(_shard_meta or {}),
            # Stage2 meta after shard meta: server-only keys (``stage2_of``,
            # ``stage2_group_id``, …) must win over any client-shaped overlap.
            **(_stage2_meta or {}),
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
        # Validated against the caller's authority by the route (#365); the
        # schedule dispatcher and the verification re-scans send the default.
        priority=request.priority,
        queued_at=_now(),
    )

    # Whether any sensor of the tenant would be handed this job: none online,
    # or none that declares what its policy and overlay need. Asked here, once
    # the overlay is known, and reported after the row exists (below).
    live_sensors = (
        agent_groups_service.live_sensors(settings, {tenant_id})
        if execution == "agent" and not agent_group
        else None
    )

    # Reserved last, just before the row: every refusal above is then one that
    # leaves nothing behind. Released on every way out below that creates no job.
    reserved = (
        _reserve_run_dir(settings, run_id)
        if execution == "local" and request.run_id
        else None
    )
    try:
        with get_session(settings.postgres_url) as session:
            # Admission read the tenant's status in a transaction of its own,
            # well before this one: a suspension committed in between found no
            # job to cancel, and this one would then sit queued until the
            # resume (#325). Re-read here under FOR SHARE, which conflicts with
            # the FOR UPDATE a status change takes — so either the suspension
            # waits for this insert and cancels the job, or this waits for the
            # suspension and refuses.
            tenant_status = session.execute(
                select(models.Tenant.status)
                .where(models.Tenant.tenant_id == tenant_id)
                .with_for_update(read=True)
            ).scalar_one_or_none()
            if tenant_status is not None and tenant_status != tenants_service.STATUS_ACTIVE:
                raise ValueError(f"Tenant is not active: {tenant_id}")
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
                    agent_groups_service.live_groups(settings, {tenant_id})
                    if agent_group
                    else None
                ),
                # So the start response can say it while the operator is
                # still looking (#338).
                live_sensors,
            )
    except ValueError:
        _release_run_dir(reserved)
        job_inputs.discard_wordlist(settings, job_id)
        job_inputs.discard(settings, job_id)
        raise
    except IntegrityError:
        _release_run_dir(reserved)
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

    if info.sensor_unavailable:
        # Warned, not refused: an executor rollout, a schedule firing during
        # one and the minutes between applying the manifests and enrolling the
        # executor are ordinary, and a refused scan is one somebody has to
        # notice was never run. The job answers ``sensor_unavailable`` for as
        # long as it is true (``job_store.to_info``). Logged only now that the
        # row exists, so the id it names is one that can be looked up.
        _log.warning(
            "Job %s (tenant %s) is queued for agent execution, and no active "
            "scanner agent of the tenant seen within OCTO_AGENT_STALE_SECONDS "
            "would be handed it (none online, or none declaring %s): it stays "
            "queued until one does",
            job_id,
            tenant_id,
            ", ".join(sorted(job_store.required_capabilities(row.scan_options))) or "-",
        )

    if not _defer_dispatch:
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
