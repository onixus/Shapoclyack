"""What a tenant is allowed to scan — the approved scope and its enforcement (#226).

Target validation used to be a syntax check: any well-formed CIDR or FQDN was
accepted, from any tenant. Nothing in the codebase expressed "this tenant may
scan this network", so a tenant operator could aim the platform's own address
at ``169.254.169.254/32``, at the provider's cluster range, or at a third
party — and afterwards the platform could not answer whether they had been
entitled to. In an MSSP that question is asked by lawyers, after the fact.

The scope is a list of allow/deny entries per tenant (``tenant_scan_scopes``,
migration 0025), each carrying who approved it and when. Three rules:

* **Deny beats allow**, always, and it beats it by *overlap*: a range is
  refused if it intersects a denied one at all, so ``10.0.0.0/8`` cannot be
  used to reach a denied ``10.1.2.3/32`` inside it.
* **Allow is containment.** A target range is permitted only if it fits
  entirely inside one allowed range; a range half of which is unapproved is
  not half-approved.
* **No entries means no scanning.** A tenant without an approved scope does
  not fall back to "anything", which is the failure this module exists to
  remove. Existing tenants were given an explicit, visibly grandfathered
  allow-all scope by migration 0025 instead of an implicit one in code.

Enforcement runs twice on purpose. ``parse_target_payload`` refuses the input
when it is submitted, and :func:`assert_scan_allowed` refuses it again inside
``jobs_service.start_scan`` — which is reached from paths that never touched
the first check (the schedule dispatcher replays targets stored days earlier)
and which runs at the moment the scan actually starts, when the approved scope
may no longer be the one the targets were typed against.

**Names are checked after resolution too, but only against deny entries.** A
FQDN that is inside the scope by suffix but resolves to a denied address is
the same bypass as typing the address, so :func:`assert_scan_allowed` resolves
the requested names and refuses on a denied answer. It is deliberately not an
*allow* check: a domain suffix approval is its own permission and does not
imply anything about the addresses behind it. The resolution here is the API's
own, at admission time — the scanner resolves again later, so a record that
changes in between is not covered by it (see docs/operations.md).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterable

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import auth_audit
from api.services import tenants as tenants_service
from api.services.targets import split_target_lines
from api.settings import Settings
from scanner.pipeline.utils import is_fqdn, is_ip_or_cidr

_log = logging.getLogger(__name__)

EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"
EFFECTS = (EFFECT_ALLOW, EFFECT_DENY)

KIND_CIDR = "cidr"
KIND_DOMAIN = "domain"
KINDS = (KIND_CIDR, KIND_DOMAIN)

#: The explicit any-value wildcard. Spelled out rather than implied by an
#: empty scope, so "this tenant may scan anything" is a decision someone made.
WILDCARD = "*"

# A name lookup must not become the thing that hangs a scan start: getaddrinfo
# has no timeout of its own, so it runs in a worker thread this long. A lookup
# that does not answer in time leaves the syntactic decision standing and is
# logged — see _denied_by_resolution.
_RESOLVE_TIMEOUT_SECONDS = 3.0

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScanScopeDenied(PermissionError):
    """A scan refused because the tenant's approved scope does not cover it.

    A ``PermissionError`` rather than a ``ValueError``: the targets are
    well-formed, the tenant is simply not entitled to them, and the routes
    answer 403 rather than 422.
    """

    def __init__(self, message: str, *, tenant_id: str, targets: Iterable[str] = ()) -> None:
        super().__init__(message)
        self.tenant_id = tenant_id
        self.targets = tuple(targets)


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _normalize_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _network(value: str) -> _Network:
    return ipaddress.ip_network(value.strip(), strict=False)


@dataclass(frozen=True)
class ScanScope:
    """One tenant's approved scope, resolved into a form that can be matched.

    Built by :func:`load_scope`; the matching below is pure so that
    ``api/services/targets.py`` can apply it without reaching for the database.
    """

    tenant_id: str
    allow_networks: tuple[_Network, ...] = ()
    deny_networks: tuple[_Network, ...] = ()
    allow_domains: tuple[str, ...] = ()
    deny_domains: tuple[str, ...] = ()
    #: Any entries at all. False is "nothing approved", not "nothing denied".
    approved: bool = False

    @property
    def has_deny_networks(self) -> bool:
        return bool(self.deny_networks)

    def require_approved(self) -> None:
        """Refuse a tenant that has no approved scope. Fail-closed entry point."""
        if not self.approved:
            raise ScanScopeDenied(
                f"tenant {self.tenant_id} has no approved scan scope: an admin must "
                f"approve one (PUT /api/tenants/{self.tenant_id}/scan-scope) before "
                "any scan can start",
                tenant_id=self.tenant_id,
            )

    def rejects_network(self, value: str) -> str | None:
        """Why this IP/CIDR target is out of scope, or None when it is inside it."""
        try:
            target = _network(value)
        except ValueError:
            # Syntax is the caller's business; an unparseable value cannot be
            # matched against anything, so it is out of scope here.
            return "not an IP or CIDR"
        for denied in self.deny_networks:
            if denied.version == target.version and target.overlaps(denied):
                return f"denied by {denied}"
        for allowed in self.allow_networks:
            if allowed.version == target.version and target.subnet_of(allowed):
                return None
        return "not inside any allowed range"

    def rejects_domain(self, value: str) -> str | None:
        """Why this domain target is out of scope, or None when it is inside it."""
        name = _normalize_domain(value)
        for denied in self.deny_domains:
            if _suffix_matches(name, denied):
                return f"denied by {denied}"
        for allowed in self.allow_domains:
            if _suffix_matches(name, allowed):
                return None
        return "not under any allowed domain"

    def rejections(self, *, ranges: Iterable[str], domains: Iterable[str]) -> list[str]:
        """``"<target> (<reason>)"`` for every target the scope refuses."""
        refused: list[str] = []
        for item in ranges:
            reason = self.rejects_network(item)
            if reason:
                refused.append(f"{item} ({reason})")
        for item in domains:
            reason = self.rejects_domain(item)
            if reason:
                refused.append(f"{item} ({reason})")
        return refused

    def check(self, *, ranges: Iterable[str], domains: Iterable[str]) -> None:
        """Raise :class:`ScanScopeDenied` unless every target is in scope."""
        self.require_approved()
        refused = self.rejections(ranges=ranges, domains=domains)
        if refused:
            raise ScanScopeDenied(
                f"targets outside the approved scan scope of tenant "
                f"{self.tenant_id}: {_sample(refused)}",
                tenant_id=self.tenant_id,
                targets=refused,
            )


def _suffix_matches(name: str, entry: str) -> bool:
    """Domain-suffix match: ``example.com`` covers itself and its subdomains."""
    if entry == WILDCARD:
        return True
    return name == entry or name.endswith("." + entry)


def _sample(values: list[str], limit: int = 8) -> str:
    """The same truncated rendering ``parse_target_payload`` uses for rejects."""
    more = f" (+{len(values) - limit} more)" if len(values) > limit else ""
    return ", ".join(values[:limit]) + more


def _to_dict(row: models.TenantScanScope) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "effect": row.effect,
        "kind": row.kind,
        "value": row.value,
        "note": row.note or "",
        "approved_by": row.approved_by or "",
        "approved_at": _iso(row.approved_at),
    }


def _rows(session, tenant_id: str) -> list[models.TenantScanScope]:
    return list(
        session.execute(
            select(models.TenantScanScope)
            .where(models.TenantScanScope.tenant_id == tenant_id)
            .order_by(
                models.TenantScanScope.effect,
                models.TenantScanScope.kind,
                models.TenantScanScope.value,
            )
        )
        .scalars()
        .all()
    )


def load_scope(settings: Settings, tenant_id: str) -> ScanScope:
    """The tenant's scope as a matchable value. Empty when nothing is approved."""
    with get_session(settings.postgres_url) as session:
        rows = _rows(session, tenant_id)

    allow_networks: list[_Network] = []
    deny_networks: list[_Network] = []
    allow_domains: list[str] = []
    deny_domains: list[str] = []
    for row in rows:
        if row.kind == KIND_CIDR:
            if row.value == WILDCARD:
                # Stored as the wildcard for symmetry with domains; matched as
                # "every address of both families".
                bucket = deny_networks if row.effect == EFFECT_DENY else allow_networks
                bucket.extend((_network("0.0.0.0/0"), _network("::/0")))
                continue
            try:
                network = _network(row.value)
            except ValueError:
                # A row that cannot be parsed is not silently permissive: an
                # allow entry is dropped, and a deny entry that cannot be
                # applied is loud, because it is a control that is not working.
                _log.error(
                    "Ignoring unparseable %s scan-scope entry %r for tenant %s",
                    row.effect,
                    row.value,
                    tenant_id,
                )
                continue
            (deny_networks if row.effect == EFFECT_DENY else allow_networks).append(network)
        else:
            name = _normalize_domain(row.value)
            (deny_domains if row.effect == EFFECT_DENY else allow_domains).append(name)

    return ScanScope(
        tenant_id=tenant_id,
        allow_networks=tuple(allow_networks),
        deny_networks=tuple(deny_networks),
        allow_domains=tuple(allow_domains),
        deny_domains=tuple(deny_domains),
        approved=bool(rows),
    )


def list_entries(settings: Settings, tenant_id: str) -> list[dict[str, Any]]:
    """Every entry of one tenant's scope, allow before deny, then by value."""
    with get_session(settings.postgres_url) as session:
        return [_to_dict(row) for row in _rows(session, tenant_id)]


def _validated(entry: dict[str, Any]) -> dict[str, str]:
    """One submitted entry, normalised. Raises ValueError with the offending value."""
    effect = str(entry.get("effect", "")).strip().lower()
    kind = str(entry.get("kind", "")).strip().lower()
    value = str(entry.get("value", "")).strip()
    if effect not in EFFECTS:
        raise ValueError(f"effect must be one of {', '.join(EFFECTS)}: {effect!r}")
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}: {kind!r}")
    if value == WILDCARD:
        normalized = WILDCARD
    elif kind == KIND_CIDR:
        if not is_ip_or_cidr(value):
            raise ValueError(f"not an IP or CIDR: {value!r}")
        normalized = str(_network(value))
    else:
        normalized = _normalize_domain(value)
        if not is_fqdn(normalized):
            raise ValueError(f"not a domain: {value!r}")
    return {
        "effect": effect,
        "kind": kind,
        "value": normalized,
        "note": str(entry.get("note", "") or "").strip()[:500],
    }


def replace_scope(
    settings: Settings,
    *,
    tenant_id: str,
    entries: list[dict[str, Any]],
    approved_by: str,
) -> list[dict[str, Any]]:
    """Replace a tenant's scope with ``entries``, in one transaction.

    A whole-scope replacement rather than per-entry edits: a scope is read as
    a set ("deny beats allow"), and applying a narrowing in several requests
    would leave a window in which the intermediate set is the one enforced.

    Every stored row is stamped with this approval, including entries carried
    over unchanged — the approver is answering for the resulting scope, not
    for the lines they happened to add.

    Raises LookupError for an unknown tenant and ValueError for a malformed
    entry; duplicates collapse rather than tripping the unique constraint.
    """
    if tenants_service.get_tenant(tenant_id) is None:
        raise LookupError(f"tenant not found: {tenant_id}")

    seen: dict[tuple[str, str, str], dict[str, str]] = {}
    for entry in entries:
        validated = _validated(entry)
        seen[(validated["effect"], validated["kind"], validated["value"])] = validated

    approved_at = _now()
    with get_session(settings.postgres_url) as session:
        session.query(models.TenantScanScope).filter(
            models.TenantScanScope.tenant_id == tenant_id
        ).delete()
        session.flush()
        for validated in seen.values():
            session.add(
                models.TenantScanScope(
                    tenant_id=tenant_id,
                    effect=validated["effect"],
                    kind=validated["kind"],
                    value=validated["value"],
                    note=validated["note"],
                    approved_by=approved_by,
                    approved_at=approved_at,
                )
            )
        session.flush()
        return [_to_dict(row) for row in _rows(session, tenant_id)]


def _resolve(host: str) -> list[str]:
    """Addresses ``host`` currently resolves to; empty when it does not resolve."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({str(info[4][0]).split("%", 1)[0] for info in infos})


def _denied_by_resolution(scope: ScanScope, domains: list[str]) -> list[str]:
    """Domains whose current addresses land inside a denied range.

    Only runs when the scope actually denies ranges — otherwise there is
    nothing a resolved address could be refused against, and a scan start must
    not pay for a DNS round trip to learn that.
    """
    if not domains or not scope.has_deny_networks:
        return []

    refused: list[str] = []
    # Not a ``with`` block: its exit joins the worker threads, which would give
    # back exactly the unbounded wait ``_RESOLVE_TIMEOUT_SECONDS`` is here to
    # prevent. A lookup still running is abandoned instead.
    pool = ThreadPoolExecutor(max_workers=min(8, len(domains)))
    try:
        futures = {pool.submit(_resolve, name): name for name in domains}
        for future, name in futures.items():
            try:
                addresses = future.result(timeout=_RESOLVE_TIMEOUT_SECONDS)
            except (FutureTimeout, OSError):
                # Not fail-closed on purpose: a name that does not answer in
                # time has not been shown to be out of scope, and refusing
                # every scan whenever DNS is slow is its own outage. The
                # syntactic decision stands and the gap is visible in the log.
                _log.warning(
                    "Scan-scope resolution check timed out for %s (tenant %s); "
                    "deny ranges were not applied to it",
                    name,
                    scope.tenant_id,
                )
                continue
            for address in addresses:
                reason = scope.rejects_network(address)
                if reason and reason.startswith("denied by"):
                    refused.append(f"{name} -> {address} ({reason})")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return refused


def assert_scan_allowed(
    settings: Settings,
    *,
    tenant_id: str,
    ranges_text: str | None,
    domains_text: str | None,
) -> None:
    """The second barrier: re-check a scan's targets at the moment it starts.

    Deliberately redundant with the check ``parse_target_payload`` already
    performed, and deliberately re-derived from the request text rather than
    from that call's output: this is the barrier for the paths that never ran
    the first one (``schedule_dispatcher`` replaying stored targets) and for
    a scope that was narrowed after the targets were entered.
    """
    scope = load_scope(settings, tenant_id)
    ranges = split_target_lines(ranges_text)
    domains = split_target_lines(domains_text)
    scope.check(ranges=ranges, domains=domains)

    if not settings.scan_scope_resolve_check:
        return
    refused = _denied_by_resolution(scope, [_normalize_domain(name) for name in domains])
    if refused:
        raise ScanScopeDenied(
            f"targets resolve into a denied range for tenant {tenant_id}: {_sample(refused)}",
            tenant_id=tenant_id,
            targets=refused,
        )


def record_denial(*, username: str, denied: ScanScopeDenied) -> None:
    """Write the refusal to the access-decision journal (``auth_events``).

    The same trail the login decisions go to (#157), read through
    ``GET /api/auth/events?outcome=denied``. Best-effort by design: the scan
    has already been refused when this runs, and losing the journal write must
    not turn a clean 403 into a 500 — but it is logged, because an
    access-control decision that left no trace is itself worth noticing.
    """
    try:
        auth_audit.record_denied(
            username=username,
            reason=auth_audit.REASON_SCAN_SCOPE,
            detail=f"tenant={denied.tenant_id} {denied}"[:1000],
        )
    except Exception:  # noqa: BLE001 - see docstring
        _log.exception(
            "Failed to record scan-scope denial for tenant %s in the audit trail",
            denied.tenant_id,
        )


def reset_for_tests(settings: Settings) -> None:
    """Clear every tenant's scope (test isolation only)."""
    with get_session(settings.postgres_url) as session:
        session.query(models.TenantScanScope).delete()
