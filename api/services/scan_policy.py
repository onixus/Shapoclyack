"""How hard a tenant may be scanned, decided by the platform (#362).

The API used to tell a remote agent exactly one thing about aggressiveness:
``--mode``. Every number behind that word — 2000 packets per second for
``safe`` discovery, the host concurrency, the nmap timing — was read from the
``scanner/config/default.yaml`` on the *agent's own host*. Three consequences,
all of them the platform operator's problem and none of them theirs to fix:
the pace could not be set centrally, an agent installed by the customer's own
admin scanned at whatever that file said, and nothing recorded which of the two
had decided. The scanner also had no notion of a protocol that falls over when
probed — ``grep modbus`` over the repository returned nothing — so a sweep of a
plant network was one rate limit away from stopping a production line.

A policy is one row per tenant (:class:`api.db.models.TenantScanPolicy`) and it
travels with the job:

* **Admission.** :func:`assert_scan_admitted` runs inside
  ``jobs_service.start_scan``, beside the quota, the scope and the maintenance
  calendar, so the console, the recurring dispatcher and the platform's own
  re-scans are all held to it. A ``safe-only`` tenant whose operator asks for
  ``fast`` is *refused*, not quietly downgraded, and a scan naming an
  avoid-listed port is refused rather than silently filtered: an operator who
  asked to scan 502 should hear no, not receive results that omit it.
* **Execution.** :func:`snapshot` is stored on the job and handed to whoever
  executes it — written beside the job's inputs for a local scan, returned in
  the claim response for a remote one (never in the NATS offer, which is
  broadcast to agents that will not get the job, #361). The scanner applies it
  in ``scanner/pipeline/scan_policy.py``, where it can only ever *lower* what
  the local config says.
* **Refusal.** An agent that does not declare the ``scan_policy`` capability
  cannot honour a ceiling, so ``jobs_service.claim_job`` does not hand it a job
  that carries one; the route answers 426 and the agent's journal says why. A
  policy that only newer agents obey while older ones scan at 2000 pps would be
  worse than no policy, because it would read as enforced.

**The profile is a floor, not a default.** ``fragile`` is the OT/ICS profile,
and what it forces lives in :data:`PROFILE_FLOORS` — compiled in, not stored —
so the stored row can only make it stricter. An operator who sets
``profile=fragile`` and ``max_discover_rate=10000`` gets 100, and a request
that names a mode or a port list cannot reach around either.

**No row is the pre-#362 behaviour.** No ceilings are pushed, no capability is
demanded of the agent, the local ``default.yaml`` decides as it always did, and
every mode is allowed. That is every tenant on the day this ships.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import metrics as metrics_service
from api.services import tenants as tenants_service
from api.settings import Settings

_log = logging.getLogger(__name__)

#: Bumped when the shape of :func:`snapshot` changes in a way an executor has
#: to understand. The scanner refuses a snapshot it does not know rather than
#: applying the half of it that still parses.
POLICY_VERSION = 1

#: What an agent has to declare (``capabilities`` on register and heartbeat)
#: before the API will hand it a job carrying a policy. The agent's own claim
#: about itself, which is fine: it can only ever *lose* work by lying, and the
#: refusal below is what keeps an agent that cannot pace itself from being
#: handed a network that needs pacing.
AGENT_CAPABILITY = "scan_policy"

PROFILE_STANDARD = "standard"
PROFILE_FRAGILE = "fragile"
PROFILES: tuple[str, ...] = (PROFILE_STANDARD, PROFILE_FRAGILE)

#: The one speed profile a ``safe_only`` tenant may run. ``test`` is absent on
#: purpose: it is the smoke profile and its discovery rate is 4000 pps, so
#: admitting it "because it is only a test" would admit the traffic the flag
#: exists to forbid.
SAFE_MODE = "safe"

#: Fieldbus and building-automation ports that must not be probed on a fragile
#: estate. Not an exhaustive ICS port list and not meant as one — these are the
#: services where a single unexpected TCP connection or a malformed probe is
#: known to stall a PLC, an RTU or a controller, which is the class of failure
#: this profile exists to prevent. An operator may add to it per tenant
#: (``avoid_ports``); nobody can subtract from it.
OT_AVOID_PORTS: tuple[int, ...] = (
    102,  # S7comm / ISO-TSAP (Siemens)
    502,  # Modbus/TCP
    789,  # Red Lion / Crimson
    1911,  # Tridium Fox (Niagara)
    2222,  # EtherNet/IP implicit I/O
    2404,  # IEC 60870-5-104
    4000,  # Siemens / Emerson ROC
    4911,  # Tridium Niagara
    9600,  # OMRON FINS
    18245,  # GE SRTP
    20000,  # DNP3
    44818,  # EtherNet/IP explicit messaging (CIP)
    47808,  # BACnet/IP
)

#: What each profile forces, regardless of what the tenant's row says. A stored
#: value is taken only when it is *stricter*; see :func:`resolve`.
#:
#: The fragile numbers are deliberately low enough to be boring: 100 pps of
#: discovery across the batch and 25 pps at any one device is slower than the
#: housekeeping traffic on a typical control network, and one host at a time
#: means a stalled controller cannot take its neighbours' scan with it. A
#: fragile scan is meant to take hours; the alternative it is measured against
#: is not scanning the plant at all.
PROFILE_FLOORS: dict[str, dict[str, Any]] = {
    PROFILE_STANDARD: {},
    PROFILE_FRAGILE: {
        "safe_only": True,
        "max_discover_rate": 100,
        "max_port_rate": 50,
        "max_host_concurrency": 1,
        "per_host_rate": 25,
        # Service probing is the stage that sends protocol-specific payloads
        # (nmap NSE, pulse banner grabs). On an OT estate that is the single
        # most likely thing to put a device into a fault state, and the port
        # inventory a fragile run is really asked for does not need it.
        "skip_service_probe": True,
        "avoid_ports": OT_AVOID_PORTS,
    },
}

#: Bounds for what an operator may store. The rates mirror
#: ``scanner.pipeline.config_schema.ProfileConfig`` so a policy cannot describe
#: a configuration the scanner would refuse to validate.
_RATE_BOUNDS = (1, 100_000)
_CONCURRENCY_BOUNDS = (1, 64)
#: An avoid-list is a hand-written exception list. Past this it is a port
#: selection, which is what ``ports`` on the scan request is for.
MAX_AVOID_PORTS = 128

_CEILING_FIELDS = (
    "max_discover_rate",
    "max_port_rate",
    "max_host_concurrency",
    "per_host_rate",
)


class ScanPolicyViolation(PermissionError):
    """A scan refused because the tenant's policy does not allow it.

    A ``PermissionError`` for the reason ``ScanScopeDenied`` and
    ``MaintenanceBlocked`` are: the request is well-formed and the caller is
    authenticated, they are simply not entitled to *this* scan. Unlike the
    maintenance block it does not expire by itself, so the routes answer 403
    and offer no ``Retry-After`` — the way out is a narrower request or a
    different policy, both of which are somebody's decision.

    ``reason`` is machine-readable (``safe_only``, ``avoid_ports``) so the
    console and the audit trail can tell the two refusals apart without parsing
    the sentence.
    """

    def __init__(
        self,
        message: str,
        *,
        tenant_id: str,
        reason: str,
        profile: str = PROFILE_STANDARD,
    ) -> None:
        super().__init__(message)
        self.tenant_id = tenant_id
        self.reason = reason
        self.profile = profile


class AgentPolicyUnsupported(PermissionError):
    """This agent cannot honour the policy the job it would get carries.

    Raised by ``jobs_service.claim_job`` and answered 426 — the same status an
    agent below ``OCTO_AGENT_MIN_VERSION`` meets, and for the same reason: the
    fix is on the agent's host, the worker already knows to back off and keep
    heartbeating on it, and the fleet view keeps showing the agent so an
    operator can find the host that needs upgrading.
    """


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if dt else None


def _to_dict(row: models.TenantScanPolicy) -> dict[str, Any]:
    return {
        "tenant_id": row.tenant_id,
        "profile": row.profile,
        "safe_only": bool(row.safe_only),
        "max_discover_rate": row.max_discover_rate,
        "max_port_rate": row.max_port_rate,
        "max_host_concurrency": row.max_host_concurrency,
        "per_host_rate": row.per_host_rate,
        "avoid_ports": sorted(int(p) for p in (row.avoid_ports or [])),
        "note": row.note or "",
        "updated_at": _iso(row.updated_at),
        "updated_by": row.updated_by,
    }


def _int_in(value: Any, field: str, bounds: tuple[int, int]) -> int:
    lo, hi = bounds
    if not isinstance(value, int) or isinstance(value, bool) or not (lo <= value <= hi):
        raise ValueError(f"{field} must be an integer {lo}–{hi}")
    return value


def _validated_ports(value: Any) -> list[int]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("avoid_ports must be a list of port numbers")
    ports = sorted({_int_in(port, "avoid_ports entry", (1, 65535)) for port in value})
    if len(ports) > MAX_AVOID_PORTS:
        raise ValueError(
            f"avoid_ports holds {len(ports)} ports; at most {MAX_AVOID_PORTS} — past that "
            "it is a port selection rather than an exception list"
        )
    return ports


def get_policy(settings: Settings, tenant_id: str) -> dict[str, Any] | None:
    """The tenant's stored policy as an operator wrote it, or None.

    None is a meaningful answer and the common one: a tenant with no row is
    scanned exactly as it was before #362. What the *scan* is held to is
    :func:`resolve`, which folds the profile floor in on top of this.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantScanPolicy, tenant_id)
        return _to_dict(row) if row is not None else None


def replace_policy(
    settings: Settings,
    *,
    tenant_id: str,
    profile: str = PROFILE_STANDARD,
    safe_only: bool = False,
    max_discover_rate: int | None = None,
    max_port_rate: int | None = None,
    max_host_concurrency: int | None = None,
    per_host_rate: int | None = None,
    avoid_ports: list[int] | None = None,
    note: str = "",
    updated_by: str,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Write the tenant's policy, replacing whatever it had.

    A whole-document replacement rather than field edits, for the reason
    ``scan_scopes.replace_scope`` is one: a policy is read as a single ceiling,
    and applying a tightening in several requests would leave a window in which
    the intermediate document is the one enforced.

    Raises LookupError for an unknown tenant and ValueError for a value outside
    what the scanner would accept — a policy that stores cleanly and then fails
    the scanner's own validation would be a ceiling discovered at the first
    scan rather than here, where the operator can still fix it.
    """
    if tenants_service.get_tenant(tenant_id) is None:
        raise LookupError(f"tenant not found: {tenant_id}")
    if profile not in PROFILES:
        raise ValueError(f"unknown scan policy profile {profile!r}: one of {list(PROFILES)}")
    if not isinstance(safe_only, bool):
        raise ValueError("safe_only must be a boolean")

    values: dict[str, Any] = {
        "profile": profile,
        "safe_only": safe_only,
        "avoid_ports": _validated_ports(avoid_ports or []),
        "note": str(note or "")[:500],
    }
    for field, given, bounds in (
        ("max_discover_rate", max_discover_rate, _RATE_BOUNDS),
        ("max_port_rate", max_port_rate, _RATE_BOUNDS),
        ("max_host_concurrency", max_host_concurrency, _CONCURRENCY_BOUNDS),
        ("per_host_rate", per_host_rate, _RATE_BOUNDS),
    ):
        values[field] = None if given is None else _int_in(given, field, bounds)

    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantScanPolicy, tenant_id)
        before = _to_dict(row) if row is not None else None
        if row is None:
            row = models.TenantScanPolicy(tenant_id=tenant_id, updated_at=_now())
            session.add(row)
        for field, value in values.items():
            setattr(row, field, value)
        row.updated_at = _now()
        row.updated_by = updated_by
        session.flush()
        after = _to_dict(row)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_SCAN_POLICY_UPDATE,
            resource_type="scan_policy",
            resource_id=tenant_id,
            tenant_id=tenant_id,
            before=before,
            after=after,
        )
        return after


def clear_policy(
    settings: Settings,
    *,
    tenant_id: str,
    audit: "audit_service.AuditContext | None" = None,
) -> bool:
    """Delete the tenant's policy, putting it back to "no ceilings at all".

    Audited like the write it undoes, and with the removed document in
    ``before``: "who took the plant network's rate limit off, and what had it
    been" is the question this trail is asked afterwards.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantScanPolicy, tenant_id)
        if row is None:
            return False
        before = _to_dict(row)
        session.delete(row)
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_SCAN_POLICY_UPDATE,
            resource_type="scan_policy",
            resource_id=tenant_id,
            tenant_id=tenant_id,
            before=before,
            after=None,
        )
        return True


def _stricter(stored: int | None, floor: int | None) -> int | None:
    """The tighter of the tenant's ceiling and the profile's, or whichever exists."""
    if stored is None:
        return floor
    if floor is None:
        return stored
    return min(stored, floor)


def resolve(policy: dict[str, Any] | None) -> dict[str, Any] | None:
    """Fold the profile floor into a stored policy. None stays None.

    This is the only place the two are combined, and it is why an operator
    cannot raise their way out of ``fragile``: every ceiling is the stricter of
    the two, ``safe_only`` and ``skip_service_probe`` are ORed, and the
    avoid-lists are unioned. Pure — no database, no settings — so the same
    function answers for a stored row and for a policy carried on a job.
    """
    if policy is None:
        return None
    profile = policy.get("profile") or PROFILE_STANDARD
    floor = PROFILE_FLOORS.get(profile, {})
    resolved: dict[str, Any] = {
        "policy_version": POLICY_VERSION,
        "profile": profile,
        "safe_only": bool(policy.get("safe_only")) or bool(floor.get("safe_only")),
        "skip_service_probe": bool(floor.get("skip_service_probe")),
        "avoid_ports": sorted(
            {int(p) for p in (policy.get("avoid_ports") or [])}
            | {int(p) for p in floor.get("avoid_ports", ())}
        ),
    }
    for field in _CEILING_FIELDS:
        resolved[field] = _stricter(policy.get(field), floor.get(field))
    return resolved


def effective(settings: Settings, tenant_id: str) -> dict[str, Any] | None:
    """The resolved policy for one tenant, or None when it has no row."""
    return resolve(get_policy(settings, tenant_id))


def digest(resolved: dict[str, Any]) -> str:
    """A short, stable fingerprint of one resolved policy.

    Stored on the job and echoed by the agent on its results upload, so a run
    executed under a policy the job did not carry — an agent that failed to
    apply the overlay, or that was handed a stale one — is visible afterwards
    rather than indistinguishable from a compliant one. It is evidence, not a
    control: an agent that lies about the digest is inside the customer's
    network already (see docs/operations.md).
    """
    payload = {key: value for key, value in sorted(resolved.items()) if key != "digest"}
    blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def snapshot(resolved: dict[str, Any] | None) -> dict[str, Any] | None:
    """The resolved policy as it is stored on a job and handed to an executor.

    The snapshot rather than a fresh read at claim time: a job is admitted
    under the policy that stood when it was accepted, and a policy edited while
    it sat in the queue must not silently change what was approved. It is also
    what makes the run auditable — the document is on the job, not merely
    derivable from a table that has since moved on.
    """
    if resolved is None:
        return None
    return {**resolved, "digest": digest(resolved)}


def _forbidden_ports(text: str | None, avoid: set[int]) -> set[int]:
    """Which avoided ports a scan request's ``ports``/``ports_udp`` text names.

    Reads what ``api.services.targets.parse_target_payload`` reads — newline-
    or comma-separated entries, single ports or ``N-M`` ranges, with the
    ``u:``/``t:`` protocol markers the port files use — and ignores anything
    that is not a port, which the target preparation refuses on its own terms.

    Answers with the *intersection* rather than with the requested set, so a
    range is never expanded: ``1-65535`` is a legitimate sweep request and
    expanding it would build a 65 535-element set to learn that it covers 502.
    """
    named: set[int] = set()
    for chunk in str(text or "").replace(",", "\n").split():
        item = chunk.strip().lower().removeprefix("u:").removeprefix("t:")
        if not item:
            continue
        if "-" in item:
            lo, _, hi = item.partition("-")
            if lo.isdigit() and hi.isdigit():
                start, end = int(lo), int(hi)
                if 0 < start <= end <= 65535:
                    named.update(port for port in avoid if start <= port <= end)
            continue
        if item.isdigit() and int(item) in avoid:
            named.add(int(item))
    return named


def assert_scan_admitted(
    settings: Settings,
    *,
    tenant_id: str,
    mode: str,
    ports_text: str | None = None,
    ports_udp_text: str | None = None,
    resolved: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Refuse a scan the tenant's policy does not allow, and return the policy.

    Called from ``jobs_service.start_scan`` beside the quota, the scope and the
    maintenance calendar, so the recurring dispatcher is held to the same
    ceiling as the console — a policy only the route honoured would be a policy
    the scheduler walks through at 02:00.

    ``resolved`` is the already-loaded policy, so a caller that needs it again
    (to put it on the job) does not pay for a second round trip. Returns the
    resolved policy, or None when the tenant has none.
    """
    if resolved is None:
        resolved = effective(settings, tenant_id)
    if resolved is None:
        return None

    if resolved["safe_only"] and mode != SAFE_MODE:
        raise ScanPolicyViolation(
            f"tenant {tenant_id} is limited to the '{SAFE_MODE}' speed profile by its scan "
            f"policy (profile={resolved['profile']}), and this scan asks for '{mode}'",
            tenant_id=tenant_id,
            reason="safe_only",
            profile=resolved["profile"],
        )

    avoid = set(resolved["avoid_ports"])
    if avoid:
        # Both port lists, TCP and UDP: BACnet is 47808/udp and Modbus is
        # 502/tcp, and a list that only guarded one of them would guard the
        # wrong half of an OT estate.
        forbidden = sorted(
            _forbidden_ports(ports_text, avoid) | _forbidden_ports(ports_udp_text, avoid)
        )
        if forbidden:
            raise ScanPolicyViolation(
                f"tenant {tenant_id} may not scan port(s) "
                f"{', '.join(str(p) for p in forbidden[:8])}: they are on its scan policy's "
                f"avoid-list (profile={resolved['profile']})",
                tenant_id=tenant_id,
                reason="avoid_ports",
                profile=resolved["profile"],
            )
    return resolved


def note_refusal(reason: str) -> None:
    """Count one refusal (``octo_scan_policy_refusals_total``).

    Separate from :func:`record_block` because not every refusal has a person
    to tell: an agent turned away on claim because it cannot honour a policy
    leaves nothing in anybody's browser, and the counter is the only place that
    shows a queue standing still for that reason.
    """
    metrics_service.SCAN_POLICY_REFUSALS_TOTAL.labels(reason).inc()


def record_block(*, username: str, violation: ScanPolicyViolation) -> None:
    """Write the refusal to the administrative trail (``audit_events``).

    Best-effort, exactly like ``maintenance.record_block``: the scan has
    already been refused when this runs and losing the row must not turn a
    clean 403 into a 500 — but "the platform refused to scan the plant network
    last night, and which rule said so" is precisely what this feature is asked
    afterwards.
    """
    note_refusal(violation.reason)
    try:
        audit_service.record_standalone(
            audit_service.system_context(actor=username or "system"),
            action=audit_service.ACTION_SCAN_POLICY_BLOCK,
            resource_type="tenant",
            resource_id=violation.tenant_id,
            tenant_id=violation.tenant_id,
            after={
                "reason": violation.reason,
                "profile": violation.profile,
                "detail": str(violation)[:1000],
            },
        )
    except Exception:  # noqa: BLE001 - see docstring
        _log.warning(
            "Could not record the scan policy refusal for tenant %s",
            violation.tenant_id,
            exc_info=True,
        )
