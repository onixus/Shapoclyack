"""Scan admission orchestration.

This module owns the decisions that answer whether a scan may enter the queue
and where it may run. Keeping those decisions out of jobs prevents the
queue/executor service from becoming the dependency hub for every new policy.

The boundary is deliberately narrow: admission is orchestration around existing
policy services. It does not create a job row, write target files, start a
process, or publish an offer.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from api.schemas import StartScanRequest
from api.services import agent_groups as agent_groups_service
from api.services import maintenance
from api.services import promoted_domains
from api.services import quotas
from api.services import scan_policy
from api.services import scan_scopes
from api.services import tenants as tenants_service
from api.settings import Settings

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanAdmission:
    """The decisions frozen at the moment a scan is admitted."""

    tenant_id: str
    scope: scan_scopes.ScanScope
    promoted_admitted: tuple[str, ...]
    promoted_refused: tuple[str, ...]
    policy_snapshot: dict[str, Any] | None
    agent_group: str | None
    group_has_live_agent: bool


def admit_scan(
    settings: Settings,
    request: StartScanRequest,
    *,
    username: str,
    job_id: str,
    execution: str,
    quota_exempt: bool = False,
    widen_with_promoted: bool = True,
) -> ScanAdmission:
    """Validate policy and placement before jobs creates any side effects.

    All callers, including scheduled and verification scans, pass through this
    boundary. The function intentionally performs no filesystem writes and no
    job insert, so a refusal cannot leave job-scoped scratch data behind.
    """
    tenant_id = (request.tenant_id or tenants_service.DEFAULT_TENANT_ID).strip()
    tenant = tenants_service.get_tenant(tenant_id)
    if tenant is None:
        raise ValueError(f"Unknown tenant_id: {tenant_id}")
    if tenant.get("status") != "active":
        raise ValueError(f"Tenant is not active: {tenant_id}")

    if not quota_exempt:
        quotas.assert_scan_quota(settings, tenant_id=tenant_id)

    scope = scan_scopes.load_scope(settings, tenant_id)

    promoted_admitted: list[str] = []
    promoted_refused: list[str] = []
    if widen_with_promoted:
        promoted_admitted, promoted_refused = promoted_domains.split_for_scan(
            settings, scope, promoted_domains.promoted_names(settings, tenant_id)
        )
        if promoted_refused:
            _log.warning(
                "Tenant %s: %d promoted domain(s) outside the approved scan scope "
                "dropped from job %s: %s",
                tenant_id,
                len(promoted_refused),
                job_id,
                ", ".join(promoted_refused[:8]),
            )

    try:
        maintenance.assert_scan_admitted(
            settings,
            tenant_id=tenant_id,
            ranges_text=request.ranges,
            domains_text="\n".join([request.domains or "", *promoted_admitted]),
        )
    except maintenance.MaintenanceBlocked as blocked:
        maintenance.record_block(username=username, blocked=blocked)
        raise

    try:
        policy = scan_policy.assert_scan_admitted(
            settings,
            tenant_id=tenant_id,
            mode=request.mode,
            ports_text=request.ports,
            ports_udp_text=request.ports_udp,
        )
    except scan_policy.ScanPolicyViolation as violation:
        scan_policy.record_block(username=username, violation=violation)
        raise
    policy_snapshot = scan_policy.snapshot(policy)

    try:
        scan_scopes.assert_scan_allowed(
            settings,
            tenant_id=tenant_id,
            ranges_text=request.ranges,
            domains_text=request.domains,
            scope=scope,
        )
    except scan_scopes.ScanScopeDenied as denied:
        scan_scopes.record_denial(username=username, denied=denied)
        raise

    try:
        required_groups = scan_scopes.required_agent_groups(
            settings,
            tenant_id=tenant_id,
            ranges_text=request.ranges,
            domains_text=request.domains,
        )
        agent_group = agent_groups_service.resolve_for_scan(
            settings,
            tenant_id=tenant_id,
            requested=request.agent_group,
            required=required_groups,
        )
    except scan_scopes.ScanScopeDenied as denied:
        scan_scopes.record_denial(username=username, denied=denied)
        raise

    if agent_group and execution != "agent":
        raise ValueError(
            f"agent_group {agent_group} requires a remote agent, but this "
            "installation runs scans locally (OCTO_JOB_EXECUTION_MODE=local)"
        )

    group_has_live_agent = not agent_group or bool(
        agent_groups_service.live_agent_count(
            settings, tenant_id=tenant_id, name=agent_group
        )
    )
    if agent_group and not group_has_live_agent:
        _log.warning(
            "Job %s (tenant %s) is addressed to agent group %s, which has no "
            "active agent seen within OCTO_AGENT_STALE_SECONDS: it stays queued "
            "until one registers",
            job_id,
            tenant_id,
            agent_group,
        )

    return ScanAdmission(
        tenant_id=tenant_id,
        scope=scope,
        promoted_admitted=tuple(promoted_admitted),
        promoted_refused=tuple(promoted_refused),
        policy_snapshot=policy_snapshot,
        agent_group=agent_group,
        group_has_live_agent=group_has_live_agent,
    )
