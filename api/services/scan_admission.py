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
from api.services.targets import ParsedTargets, parse_target_payload
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
    parsed_targets: ParsedTargets | None


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

    # Before any work is prepared: what the tenant bought (Track E, MSSP
    # operations). Placed here rather than in the route because the recurring
    # dispatcher and every other caller reach start_scan and none of them
    # reach the route — a quota only one entry point honours is not a quota.
    if not quota_exempt:
        quotas.assert_scan_quota(settings, tenant_id=tenant_id)

    # Loaded once here and handed to both barriers below: the scope cannot
    # change inside this call frame, and each load is a round trip.
    scope = scan_scopes.load_scope(settings, tenant_id)

    # Related domains the tenant's operators promoted (org_profile M4) ride
    # along with every ordinary scan — that is what promotion means. Held to
    # the approved scope as it stands *now*, suffix and resolve-time checks
    # both: a domain promoted under a wider scope is dropped and recorded,
    # not a reason to refuse the operator's own targets.
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

    # What the tenant consented to *right now* (#352): a blackout window or a
    # change freeze. Here rather than in the route for the same reason the
    # quota is here — the recurring dispatcher never touches a route, and a
    # blackout the scheduler walks through at 02:00 is not a blackout.
    #
    # Below the promoted-domain widening on purpose: a promoted related domain
    # is a target of every scan the tenant starts, so an asset-group window
    # covering it has to see it. Checking the operator's typed targets alone
    # would let a scan of an unrelated domain carry the promoted one straight
    # into the group the window was protecting.
    #
    # Deliberately not exempted for ``quota_exempt`` dispatches: a verification
    # re-scan still reaches the customer's network, and the calendar is about
    # the network rather than the invoice.
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

    # How hard this tenant may be scanned (#362). Here, beside the quota and
    # the calendar, for the same reason both are here: the recurring dispatcher
    # and the platform's own re-scans never touch a route, and a rate ceiling
    # the nightly sweep ignores is not a rate ceiling.
    #
    # ``request.mode`` rather than the resolved CLI mode, so the refusal lands
    # before any input file is written. The two agree on the only question
    # asked here — ``scan_intents`` maps the API's ``test`` onto ``balanced``
    # and leaves ``safe`` alone, so "the operator asked for safe" is the same
    # statement before and after that mapping.
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
    # The document the run is held to, frozen now: a policy edited while the
    # job sits in the queue must not change what was admitted, and the run has
    # to be answerable afterwards for the ceiling it actually ran under.
    policy_snapshot = scan_policy.snapshot(policy)

    # First barrier: the operator's targets, parsed against the approved scope.
    # It runs here rather than inside job_inputs so that a refusal costs no
    # job-scoped scratch directory — and it runs *before* assert_scan_allowed
    # because parse_target_payload answers syntax before entitlement (see the
    # comment in targets.py). Hoisting the entitlement check above the parse
    # turns a typo into "outside the approved scan scope" (403) instead of
    # "invalid scan targets" (422), which tells the operator to ask for access
    # they already have.
    try:
        parsed = parse_target_payload(
            scope=scope,
            ranges_text=request.ranges,
            domains_text=request.domains,
            ports_text=request.ports,
            ports_udp_text=request.ports_udp,
        )
    except scan_scopes.ScanScopeDenied as denied:
        scan_scopes.record_denial(username=username, denied=denied)
        raise

    # Second barrier, deliberately redundant. start_scan is also reached from
    # schedule_dispatcher, which replays targets stored days ago and never
    # passed through the check above, and the approved scope may have been
    # narrowed since the targets were entered — the moment that matters is the
    # moment the scan starts, not the moment it was typed.
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

    # Which of the tenant's agents may execute this scan (#361). Two inputs,
    # and the request's is the one that is not trusted: the scope decides which
    # groups these targets may be reached from, and a selector naming anything
    # else is refused rather than honoured.
    #
    # The operator's targets only — unlike the maintenance check above, which
    # does look at the promoted domains. A window is a statement about an
    # asset, so a scan that reaches a promoted domain has to respect it; a
    # group restriction is a statement about *this* scan, and letting a
    # promoted domain contribute to it meant an ordinary external scan of
    # ``www.customer.example`` inherited the ``pci`` requirement of a promoted
    # ``pci.customer.example`` and went out from the card-data segment — the
    # reverse of what the control is for. Two promoted domains restricted to
    # disjoint groups did worse: they intersected to nothing and refused every
    # scan the tenant started, with advice ("split into separate scans") the
    # operator had no way to follow, because the form cannot exclude them.
    if promoted_admitted:
        _log.debug(
            "Job %s: %d promoted domain(s) are scanned but excluded from the "
            "agent-group requirement (#361); it follows the requested targets",
            job_id,
            len(promoted_admitted),
        )
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
        # The group names remote workers, and a local scan runs in this
        # container, which is in no group. Refused rather than quietly
        # ignored: a scope entry that restricts targets to an agent group is
        # an instruction about where the packets come from, and running it
        # here anyway would be the control silently not applying.
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
        # A warning rather than a refusal: an agent that is restarting is back
        # in seconds, so refusing here would turn a blip into a failed scan.
        # Only a log line, though — nothing is written onto the job. What the
        # console shows next to a queued job is ``agent_group_unavailable``,
        # recomputed on every read (see ``job_store.to_info``), because the
        # answer this line gives is only true for as long as it takes the
        # operator to start the agent. See docs/operations.md.
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
        parsed_targets=parsed,
    )
