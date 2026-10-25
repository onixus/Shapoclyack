"""Durable personal conversations and a fenced, non-replaying summary queue.

The provider is never called inside a transaction. Expired tasks are interrupted,
not requeued; a running cancellation retains its slot until worker cleanup.
"""

import json
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

from sqlalchemy import delete, func, select, text

from api.db import tenant_scope
from api.db.engine import get_session as get_session_db
from api.db.models import (
    OperatorMessage,
    OperatorProposal,
    OperatorSession,
    OperatorTask,
    SessionFamily,
    Tenant,
    User,
    UserTenant,
)
from api.services import audit, legal_hold, rbac
from api.services.leader_lock import LOCK_CLASS_ID, OPERATOR_QUEUE_LOCK_ID


class OperatorStoreError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


SAFE_FAILURE_CODES = frozenset(
    {
        "operator_access_revoked",
        "operator_disabled",
        "operator_unsupported_task",
        "operator_invalid_run",
        "operator_source_unavailable",
        "operator_storage_unavailable",
        "operator_source_too_large",
        "operator_source_invalid",
        "operator_source_incomplete",
        "operator_source_changed",
        "operator_invalid_model_output",
        "operator_input_too_large",
        "operator_response_too_large",
        "operator_upstream_rejected",
        "operator_invalid_response",
        "operator_incomplete_response",
        "operator_transport_failed",
        "operator_execution_failed",
        "operator_timeout",
        "operator_legal_hold",
        "operator_cancelled",
        "operator_result_too_large",
    }
)


def _now():
    return datetime.now(UTC).replace(tzinfo=None)


def _dict(row, *, internal=False):
    result = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    if not internal:
        result.pop("actor_token_version", None)
        result.pop("payload", None)
    return {
        k: v.isoformat() + "Z" if isinstance(v, datetime) else v
        for k, v in result.items()
    }


def _owned(model, tenant_id, username):
    return select(model).where(model.tenant_id == tenant_id, model.username == username)


def _lock_actor(db, settings, username, auth_session_id, *, writer=True):
    """Fence mutations against account deletion and stale authenticated requests.

    Readers take a share lock: it still fences deletion and revocation, without
    serializing polling against refresh rotation or other readers.
    """
    user = db.scalar(select(User).where(User.username == username).with_for_update(read=not writer))
    if user is None or user.disabled_at is not None or user.erased_at is not None:
        raise OperatorStoreError("access_revoked")
    if auth_session_id is not None:
        family = db.scalar(
            select(SessionFamily)
            .where(SessionFamily.family_id == auth_session_id)
            .with_for_update(read=not writer)
        )
        now = _now()
        idle = max(0, int(getattr(settings, "session_idle_minutes", 30)))
        if (
            family is None
            or family.username != username
            or family.revoked_at is not None
            or family.token_version != user.token_version
            or family.expires_at <= now
            or (idle and family.last_used_at + timedelta(minutes=idle) <= now)
        ):
            raise OperatorStoreError("access_revoked")
    return user


def _lock_tenant(db, tenant_id):
    row = db.scalar(
        select(Tenant).where(Tenant.tenant_id == tenant_id).with_for_update()
    )
    if row is None or row.status != "active":
        raise OperatorStoreError("not_found")


def resolve_role(db, user, tenant_id):
    """Current ``(role, rank)`` of ``user`` in ``tenant_id``, or None when revoked.

    The one grant resolution for console, evidence and queued work. All
    memberships matter: another tenant's grant disables the legacy
    no-membership default fallback. A deleted/unknown custom role keeps the
    route's coarse reader contract: rank 1, never operator authority.
    """
    if user.role == "admin":
        return "admin", 3
    grants = dict(db.execute(select(UserTenant.tenant_id, UserTenant.role).where(
        UserTenant.username == user.username)).all())
    role = grants.get(tenant_id)
    if role is None and not grants and tenant_id == "default":
        role = user.role
    if role is None:
        return None
    resolved = rbac.role_in_session(db, tenant_id, role)
    return role, (resolved.rank if resolved is not None else 1)


def _require_current_role(db, user, tenant_id, minimum_rank):
    # Resolve before narrowing this transaction.
    current = resolve_role(db, user, tenant_id)
    if current is None or current[1] < minimum_rank:
        raise OperatorStoreError("access_revoked")


@contextmanager
def _personal_db(settings, tenant_id, username, auth_session_id, *, writer=False):
    # SID-less calls are trusted internal callers, not console entry points.
    scope = (tenant_scope.system("operator current console authority")
             if auth_session_id is not None else nullcontext())
    with scope, get_session_db(settings.postgres_url) as db:
        if writer or auth_session_id is not None:
            user = _lock_actor(db, settings, username, auth_session_id, writer=writer)
        if writer:
            _lock_tenant(db, tenant_id)
        if auth_session_id is not None:
            _require_current_role(db, user, tenant_id, 2 if writer else 1)
            # Keep RLS on personal data, without a second connection or a commit
            # between the fresh authority check and the protected operation.
            tenant_scope.narrow_transaction(db, tenant_id)
        yield db


def _queue_lock(db):
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:class_id, :object_id)"),
            {"class_id": LOCK_CLASS_ID, "object_id": OPERATOR_QUEUE_LOCK_ID},
        )


def _provenance(source):
    # Credential hashes are correctly redacted by the shared audit writer.
    # Evidence digests use explicit SHA-256 names so they remain verifiable.
    renamed = {"prompt_hash": "prompt_sha256", "output_hash": "output_sha256"}
    result = {renamed.get(key, key): source[key] for key in (
        "provider", "model", "prompt_version", "tool_version", "prompt_hash", "output_hash") if key in source}
    if "source_references" in source:
        result["source_references"] = [
            {("source_sha256" if key == "source_hash" else key): ref[key]
             for key in ("source_id", "source_type", "source_hash", "snapshot_id", "observed_at", "status")
             if key in ref} for ref in source["source_references"]]
    return result


def _audit(db, row, action):
    # Keep the authenticated actor, but never raw prompts, answers or errors.
    metadata = {"status": getattr(row, "status", "created")}
    if action == "task.submit":
        args = {"kind": row.kind, "run_id": row.run_id, "language": row.language}
        metadata["arguments_sha256"] = sha256(
            json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    if action == "task.finish" and row.result:
        source = row.result.get("audit", {})
        metadata["inference"] = _provenance(source)
    audit.record(
        db,
        audit.AuditContext(actor=row.username),
        action=f"operator.{action}",
        resource_type="operator",
        resource_id=getattr(row, "task_id", None) or row.session_id,
        tenant_id=row.tenant_id,
        after=metadata,
    )


def create_session(settings, tenant_id, username, *, auth_session_id=None):
    with _personal_db(settings, tenant_id, username, auth_session_id, writer=True) as db:
        now = _now()
        row = OperatorSession(
            session_id=str(uuid4()),
            tenant_id=tenant_id,
            username=username,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        _audit(db, row, "session.create")
        db.flush()
        return _dict(row)


def list_sessions(
    settings, tenant_id, username, limit=20, offset=0, *, auth_session_id=None
):
    with _personal_db(settings, tenant_id, username, auth_session_id) as db:
        query = _owned(OperatorSession, tenant_id, username)
        total = db.scalar(select(func.count()).select_from(query.subquery()))
        rows = db.scalars(
            query.order_by(
                OperatorSession.created_at.desc(), OperatorSession.session_id
            )
            .limit(max(1, min(limit, 100)))
            .offset(max(0, offset))
        )
        return {"items": [_dict(row) for row in rows], "total": total}


def get_session(settings, tenant_id, username, session_id, *, auth_session_id=None):
    with _personal_db(settings, tenant_id, username, auth_session_id) as db:
        row = db.scalar(
            _owned(OperatorSession, tenant_id, username).where(
                OperatorSession.session_id == session_id
            )
        )
        if row is None:
            return None
        result = _dict(row)
        for model, key in ((OperatorMessage, "messages"), (OperatorTask, "tasks"), (OperatorProposal, "proposals")):
            rows = list(
                db.scalars(
                    _owned(model, tenant_id, username)
                    .where(model.session_id == session_id)
                    .order_by(model.created_at.desc())
                    .limit(100)
                )
            )
            if key == "proposals":
                from api.services.local_operator.actions import _view
                result[key] = [_view(item) for item in reversed(rows) if item.status != "reserved"]
            else:
                result[key] = [_dict(item) for item in reversed(rows)]
        return result


def submit_task(
    settings,
    tenant_id,
    username,
    session_id,
    run_id,
    language,
    idempotency_key,
    *,
    auth_session_id=None,
    kind="summarize_run",
    payload=None,
):
    if (
        kind not in {"summarize_run", "analyze_run", "plan_request"}
        or language not in {"ru", "en"}
        or not run_id
        or len(run_id) > 256
        or not idempotency_key
        or len(idempotency_key) > 128
    ):
        raise OperatorStoreError("invalid_input")
    if kind == "plan_request":
        from api.services.local_operator.planner import PlanRequest

        try:
            if set(payload) != {"request", "auth_session_id"} or payload["auth_session_id"] != auth_session_id or not auth_session_id:
                raise ValueError("invalid binding")
            payload = {"request": PlanRequest.model_validate(payload["request"]).model_dump(),
                       "auth_session_id": auth_session_id}
        except (ValueError, TypeError, KeyError):
            raise OperatorStoreError("invalid_input") from None
    elif payload is not None:
        raise OperatorStoreError("invalid_input")
    with _personal_db(settings, tenant_id, username, auth_session_id, writer=True) as db:
        conversation = db.scalar(
            _owned(OperatorSession, tenant_id, username)
            .where(OperatorSession.session_id == session_id)
            .with_for_update()
        )
        if conversation is None:
            raise OperatorStoreError("not_found")
        previous = db.scalar(
            _owned(OperatorTask, tenant_id, username).where(
                OperatorTask.idempotency_key == idempotency_key
            )
        )
        if previous is not None:
            if (previous.session_id, previous.run_id, previous.language, previous.kind) != (
                session_id,
                run_id,
                language,
                kind,
            ) or previous.payload != payload:
                raise OperatorStoreError("idempotency_conflict")
            return _dict(previous)
        pending = db.scalar(
            select(func.count())
            .select_from(OperatorTask)
            .where(
                OperatorTask.tenant_id == tenant_id,
                OperatorTask.status.in_(["queued", "running"]),
            )
        )
        if pending >= max(1, int(getattr(settings, "operator_queue_limit", 20))):
            raise OperatorStoreError("queue_full")
        user = db.get(User, username)
        now = _now()
        row = OperatorTask(
            task_id=str(uuid4()),
            tenant_id=tenant_id,
            username=username,
            session_id=session_id,
            actor_token_version=user.token_version if user else 0,
            kind=kind,
            payload=payload,
            run_id=run_id,
            language=language,
            idempotency_key=idempotency_key,
            status="queued",
            cancel_requested=False,
            created_at=now,
            updated_at=now,
        )
        conversation.updated_at = now
        db.add(row)
        db.flush()
        _audit(db, row, "task.submit")
        return _dict(row)


def get_task(settings, tenant_id, username, task_id, *, auth_session_id=None):
    with _personal_db(settings, tenant_id, username, auth_session_id) as db:
        row = db.scalar(
            _owned(OperatorTask, tenant_id, username).where(
                OperatorTask.task_id == task_id
            )
        )
        return _dict(row) if row else None


def cancel_task(settings, tenant_id, username, task_id, *, auth_session_id=None):
    with _personal_db(settings, tenant_id, username, auth_session_id, writer=True) as db:
        row = db.scalar(
            _owned(OperatorTask, tenant_id, username)
            .where(OperatorTask.task_id == task_id)
            .with_for_update()
        )
        if row is None:
            return None
        if row.status in {"queued", "running"} and not row.cancel_requested:
            row.cancel_requested = True
            if row.status == "queued":
                row.status = "cancelled"
            row.updated_at = _now()
            _audit(db, row, "task.cancel")
        return _dict(row)


def delete_session(settings, tenant_id, username, session_id, *, auth_session_id=None):
    with _personal_db(settings, tenant_id, username, auth_session_id, writer=True) as db:
        row = db.scalar(
            _owned(OperatorSession, tenant_id, username)
            .where(OperatorSession.session_id == session_id)
            .with_for_update()
        )
        if row is None:
            return False
        try:
            legal_hold.assert_not_on_hold(
                db, tenant_id, action="operator.session.delete"
            )
        except legal_hold.LegalHoldActive as exc:
            raise OperatorStoreError("legal_hold") from exc
        if db.scalar(
            select(OperatorTask.task_id)
            .where(
                OperatorTask.session_id == session_id,
                OperatorTask.status.in_(["queued", "running"]),
            )
            .limit(1)
        ):
            raise OperatorStoreError("active_tasks")
        _audit(db, row, "session.delete")
        if db.scalar(select(OperatorProposal.proposal_id).where(
            OperatorProposal.session_id == session_id,
            OperatorProposal.tenant_id == tenant_id,
            OperatorProposal.status.in_(["executing", "unknown"])).limit(1)):
            raise OperatorStoreError("active_tasks")
        # Preserve uncertainty evidence until explicit reconciliation.
        db.execute(
            delete(OperatorSession).where(
                OperatorSession.session_id == session_id,
                OperatorSession.tenant_id == tenant_id,
                OperatorSession.username == username,
            )
        )
        return True


def _recover(db):
    rows = list(
        db.scalars(
            select(OperatorTask)
            .where(OperatorTask.status == "running", OperatorTask.lease_until <= _now())
            .with_for_update()
        )
    )
    for row in rows:
        row.status = "interrupted"
        row.error = "operator_interrupted"
        row.updated_at = _now()
        row.lease_owner = None
        row.lease_until = None
        _audit(db, row, "task.interrupted")
    return len(rows)


def recover_expired(settings):
    """Only the leader calls recovery; provider deadlines must end before leases."""
    with get_session_db(settings.postgres_url) as db:
        _queue_lock(db)
        return _recover(db)


def claim_next(settings, owner, lease_seconds=180):
    if not owner or lease_seconds <= 0:
        raise OperatorStoreError("invalid_input")
    with get_session_db(settings.postgres_url) as db:
        _queue_lock(db)
        # Recovery is explicit: an expired lease is not proof its provider stopped.
        if db.scalar(
            select(OperatorTask.task_id)
            .where(OperatorTask.status == "running")
            .limit(1)
        ):
            return None
        row = db.scalar(
            select(OperatorTask)
            .join(Tenant, Tenant.tenant_id == OperatorTask.tenant_id)
            .where(OperatorTask.status == "queued", Tenant.status == "active")
            .order_by(OperatorTask.created_at, OperatorTask.task_id)
            .with_for_update(of=OperatorTask, skip_locked=True)
            .limit(1)
        )
        if row is None:
            return None
        row.status = "running"
        row.lease_owner = owner
        row.lease_until = _now() + timedelta(seconds=lease_seconds)
        row.updated_at = _now()
        _audit(db, row, "task.start")
        return _dict(row, internal=True)


def is_cancel_requested(settings, task_id, owner):
    with get_session_db(settings.postgres_url) as db:
        row = db.get(OperatorTask, task_id)
        return (
            row is None
            or row.status != "running"
            or row.lease_owner != owner
            or row.cancel_requested
            or row.lease_until is None
            or row.lease_until <= _now()
        )


def record_inference_attempt(settings, task, metadata):
    """Commit disclosure provenance before dispatch, including failed attempts."""
    with get_session_db(settings.postgres_url) as db:
        row = db.scalar(select(OperatorTask).where(
            OperatorTask.task_id == task["task_id"],
            OperatorTask.tenant_id == task["tenant_id"],
            OperatorTask.username == task["username"]).with_for_update())
        if (row is None or row.status != "running" or row.cancel_requested
                or row.lease_owner != task.get("lease_owner")
                or row.lease_until is None or row.lease_until <= _now()):
            return False
        audit.record(db, audit.AuditContext(actor=row.username), action="operator.inference.start",
                     resource_type="operator", resource_id=row.task_id, tenant_id=row.tenant_id,
                     after=_provenance(metadata))
        return True


def finish_task(settings, task_id, owner, result=None, error=None):
    with get_session_db(settings.postgres_url) as db:
        _queue_lock(db)
        row = db.scalar(
            select(OperatorTask)
            .where(OperatorTask.task_id == task_id)
            .with_for_update()
        )
        if row is None or row.status != "running" or row.lease_owner != owner:
            return False
        expired = row.lease_until is None or row.lease_until <= _now()
        if row.cancel_requested:
            row.status, row.error = "cancelled", "operator_cancelled"
        elif expired or error == "operator_interrupted":
            row.status, row.error = "interrupted", "operator_interrupted"
        elif error:
            row.status, row.error = (
                "failed",
                error if error in SAFE_FAILURE_CODES else "operator_failed",
            )
        else:
            row.status, row.result = "succeeded", result
            # Bounded output is supplied by the worker; persist it atomically.
            content = json.dumps(result, ensure_ascii=False) if result is not None else None
            if content is not None and len(content) > 65536:
                # Record a safe failure instead of raising out of the worker.
                row.status, row.error, row.result = "failed", "operator_result_too_large", None
            elif content is not None:
                db.add(
                    OperatorMessage(
                        message_id=str(uuid4()),
                        tenant_id=row.tenant_id,
                        username=row.username,
                        session_id=row.session_id,
                        task_id=row.task_id,
                        role="assistant",
                        content=content,
                        created_at=_now(),
                    )
                )
        row.lease_owner = None
        row.lease_until = None
        row.updated_at = _now()
        _audit(db, row, "task.finish")
        return True


def lock_owner_tenants(db, username, *, action):
    """Lock, in tenant order, every tenant holding the account's personal state
    and refuse while any is on hold; serializes with legal_hold.place_hold."""
    tenant_ids = set(
        db.scalars(
            select(OperatorSession.tenant_id)
            .where(OperatorSession.username == username)
            .distinct()
        )
    )
    if tenant_ids:
        list(
            db.scalars(
                select(Tenant)
                .where(Tenant.tenant_id.in_(tenant_ids))
                .order_by(Tenant.tenant_id)
                .with_for_update()
            )
        )
    for tenant_id in sorted(tenant_ids):
        legal_hold.assert_not_on_hold(db, tenant_id, action=action)
    return tenant_ids


def delete_owner_sessions(db, username):
    """Delete an account's personal state in its caller's deletion transaction.

    The username has no FK, so account recreation must not inherit old work.
    Tenant locks serialize legal-hold placement, including departed accounts.
    Running-task disappearance tells the worker to stop and fences late finish.
    """
    lock_owner_tenants(db, username, action="user.delete")
    return db.execute(
        delete(OperatorSession).where(OperatorSession.username == username)
    ).rowcount
