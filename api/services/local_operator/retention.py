"""Bounded operator-history retention using the tenant's scan-run window."""
from datetime import UTC, datetime

from sqlalchemy import delete, exists, select

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services import audit, legal_hold, retention_policy
from api.services.local_operator import retrieval


def sweep(settings, *, limit=20):
    moment = datetime.now(UTC).replace(tzinfo=None)
    with tenant_scope.system("operator history retention"):
        with get_session(settings.postgres_url) as db:
            plan = retention_policy.load_plan(settings, "runs", session=db)
            active = exists(select(models.OperatorTask.task_id).where(
                models.OperatorTask.session_id == models.OperatorSession.session_id,
                models.OperatorTask.status.in_(["queued", "running"])))
            candidates = db.execute(select(models.OperatorSession.session_id, models.OperatorSession.tenant_id)
                .join(models.Tenant, models.Tenant.tenant_id == models.OperatorSession.tenant_id)
                .where(retention_policy.expired_clause(plan, tenant_column=models.OperatorSession.tenant_id,
                    time_column=models.OperatorSession.updated_at, now=moment),
                    models.Tenant.status == "active", ~active)
                .order_by(models.OperatorSession.updated_at, models.OperatorSession.session_id)
                .limit(max(1, min(limit, 100)))).all()
        removed = 0
        for session_id, tenant_id in candidates:
            with get_session(settings.postgres_url) as db:
                tenant = db.scalar(select(models.Tenant).where(models.Tenant.tenant_id == tenant_id).with_for_update())
                if tenant is None or tenant.status != "active":
                    continue
                # Recheck hold and policy after acquiring the lock shared by hold placement.
                try:
                    legal_hold.assert_not_on_hold(db, tenant_id, action="operator.retention")
                except legal_hold.LegalHoldActive:
                    continue
                plan = retention_policy.load_plan(settings, "runs", session=db)
                active = exists(select(models.OperatorTask.task_id).where(
                    models.OperatorTask.session_id == models.OperatorSession.session_id,
                    models.OperatorTask.status.in_(["queued", "running"])))
                deleted = db.execute(delete(models.OperatorSession).where(
                    models.OperatorSession.session_id == session_id,
                    models.OperatorSession.tenant_id == tenant_id, ~active,
                    retention_policy.expired_clause(plan, tenant_column=models.OperatorSession.tenant_id,
                        time_column=models.OperatorSession.updated_at, now=moment))).rowcount
                if deleted:
                    audit.record(db, audit.system_context("operator-retention"), action="operator.session.expire",
                                 resource_type="operator", resource_id=session_id, tenant_id=tenant_id)
                    removed += int(deleted)
        # Derived scan chunks expire with their authoritative sources, even
        # when no personal conversation is old enough to expire. Keep the
        # return value specific to deleted personal sessions.
        retrieval.prune_invalid(settings, limit=20)
        return removed
