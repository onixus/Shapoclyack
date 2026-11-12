"""Brand-watch control plane (M1).

Tenant source of truth for lookalike names. Candidates are never written into
scan jobs, scan targets or scan scope. Generation calls
``scanner.pipeline.lookalike.generate_brand_candidates`` when that module is
present; the import is behind :func:`_generate` so a missing generator fails
the call, not import of this module.

Quotas are enforced here against fixed defaults rather than a new
``tenant_quotas`` column. That table is a closed pair of integer columns
(migration 0030) and extending it would touch every quota test. Defaults:

* ``brand_watch_profiles`` <= 20
* ``brand_watch_candidates`` <= 5000
* ``brand_watch_http_per_day`` <= 200 names placed in ``http_allowed`` jobs

HTTP observation is a property of the *profile*, not of the quota: if
``approved_at`` is null or ``our_brand`` is false, every enqueued job is
``dns_only``. Disposition never auto-confirms and never starts a takedown.

Notifications are diffs only (new state, content-hash change, MX appearance).
A dismissed or whitelisted candidate still gets a daily DNS check, but does
not emit a diff.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from api.db import models
from api.db.engine import get_session
from api.settings import Settings

_log = logging.getLogger(__name__)

STATES = frozenset({
    "unregistered",
    "registered",
    "resolving",
    "http_live",
    "parked",
    "suspicious",
    "confirmed",
    "disappeared",
})
LIVE_STATES = frozenset({
    "registered",
    "resolving",
    "http_live",
    "parked",
    "suspicious",
    "confirmed",
})
DISPOSITIONS = frozenset({"open", "false_positive", "whitelisted", "confirmed"})
SILENT_DISPOSITIONS = frozenset({"false_positive", "whitelisted"})
MODES = frozenset({"dns_only", "http_allowed"})
JOB_STATUSES = frozenset({"queued", "claimed", "done", "failed"})

CAPABILITY = "brand_watch"

MAX_PROFILES = 20
MAX_CANDIDATES = 5000
MAX_HTTP_PER_DAY = 200

# A brand string this short, or one of these generics, matches half the web.
GENERIC_BRAND_STRINGS = frozenset({
    "bank", "pay", "paym", "card", "loan", "shop", "store", "mail", "login",
    "secure", "account", "online", "app", "web", "www", "com", "net", "org",
})
MIN_BRAND_STRING = 4

LEASE_SECONDS = 600
# A sensor that dies mid-batch is retried this many claims, then the job fails
# so the profile can be queued again.
MAX_ATTEMPTS = 3
DAILY = timedelta(days=1)
WEEKLY = timedelta(days=7)

# DNS keys. An HTTP pack's single dialled ``address`` is not one of them:
# copying it would replace the address set learned from DNS.
_DNS_NS_KEYS = ("ns", "has_ns", "has_soa")
_DNS_ADDR_KEYS = ("addresses", "a", "aaaa", "has_a", "has_aaaa")

# Keys a result document must not carry. Observations are not a page archive.
_HTML_KEYS = ("html", "body", "raw_html", "page", "pem", "peer_cert")


class BrandWatchError(ValueError):
    """A well-formed request the brand-watch rules refuse."""


class QuotaExceeded(BrandWatchError):
    """profiles / candidates / http-per-day ceiling."""


class LeaseDenied(BrandWatchError):
    """This sensor does not hold a live lease on the job."""


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def naive_utc(moment: datetime | None) -> datetime | None:
    """Naive UTC. An offset is converted, not stripped."""
    if moment is None or moment.tzinfo is None:
        return moment
    return moment.astimezone(UTC).replace(tzinfo=None)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _norm_name(value: str) -> str:
    text = (value or "").strip().lower().rstrip(".")
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return text


def _json_list(value: Any) -> list:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def validate_brand_strings(strings: list[str]) -> list[str]:
    """Reject a short or generic brand string. Returns the cleaned list."""
    cleaned: list[str] = []
    for raw in strings:
        item = (raw or "").strip()
        if not item:
            continue
        folded = item.casefold()
        if len(folded) < MIN_BRAND_STRING or folded in GENERIC_BRAND_STRINGS:
            raise BrandWatchError(
                f"brand string {item!r} is too short or generic; "
                "a word like 'bank' or 'pay' is not a brand"
            )
        cleaned.append(item)
    if not cleaned:
        raise BrandWatchError("at least one brand string is required")
    return cleaned


def watch_mode(profile: models.BrandProfile) -> str:
    """HTTP only after an admin approved a profile they marked as ours."""
    if profile.approved_at is None or not profile.our_brand:
        return "dns_only"
    return "http_allowed"


def sensor_may_claim(capabilities: list[str] | None) -> bool:
    """A sensor without the ``brand_watch`` capability is handed nothing."""
    return CAPABILITY in set(capabilities or [])


def normalize_observation(observation: dict[str, Any]) -> dict[str, Any]:
    """Fold a sensor row into the keys the state machine reads.

    DNS observe returns ``status``, ``a``/``aaaa`` and ``unicode``. HTTP
    observe returns ``live`` and ``address``. Callers may also post the
    already-flat form (``nxdomain``, ``addresses``, ``has_ns``). Both are
    accepted; HTML keys are dropped.
    """
    cleaned = _strip_html(dict(observation))
    status = str(cleaned.get("status") or "")
    addresses = list(cleaned.get("addresses") or [])
    for key in ("a", "aaaa"):
        for item in cleaned.get(key) or []:
            if item not in addresses:
                addresses.append(item)
    if cleaned.get("address") and cleaned.get("address") not in addresses:
        addresses.append(cleaned["address"])
    ns = list(cleaned.get("ns") or [])
    has_address = bool(addresses) or bool(cleaned.get("has_a") or cleaned.get("has_aaaa"))
    has_ns = bool(ns) or bool(cleaned.get("has_ns") or cleaned.get("has_soa"))
    nxdomain = bool(cleaned.get("nxdomain")) or status == "unregistered"
    if status == "resolving" or cleaned.get("live"):
        has_address = True
        nxdomain = False
    if status == "registered":
        has_ns = True
        nxdomain = False
    cleaned["addresses"] = addresses
    cleaned["ns"] = ns
    cleaned["nxdomain"] = nxdomain
    cleaned["has_a"] = has_address
    cleaned["has_ns"] = has_ns
    name = cleaned.get("name") or cleaned.get("name_punycode") or cleaned.get("unicode") or cleaned.get("punycode")
    if name and not cleaned.get("name"):
        cleaned["name"] = name
    return cleaned


def transition(previous: str, observation: dict[str, Any]) -> str:
    """M1 DNS state machine.

    unregistered → registered on NS/SOA or RDAP without A/AAAA.
    unregistered/registered → resolving on A/AAAA.
    A previously resolving (or otherwise live) name that is now NXDOMAIN
    becomes disappeared. A repeat of the same facts stays put.
    """
    observation = normalize_observation(observation)
    prev = previous if previous in STATES else "unregistered"
    nxdomain = bool(observation.get("nxdomain"))
    addresses = observation.get("addresses") or []
    has_address = bool(addresses) or bool(observation.get("has_a") or observation.get("has_aaaa"))
    ns = observation.get("ns") or []
    has_ns = bool(ns) or bool(observation.get("has_ns") or observation.get("has_soa"))
    has_rdap = bool(observation.get("rdap"))
    if nxdomain and prev in LIVE_STATES:
        return "disappeared"
    if nxdomain and prev == "disappeared":
        return "disappeared"
    if has_address:
        if prev in {"http_live", "parked", "suspicious", "confirmed"}:
            return prev
        return "resolving"
    if has_ns or has_rdap:
        if prev in {"resolving", "http_live", "parked", "suspicious", "confirmed"}:
            return prev
        if prev == "disappeared":
            return "registered"
        return "registered"
    return prev


def severity_for(state: str, observation: dict[str, Any] | None = None) -> str:
    """M1 severity. Registered-without-HTTP is informational.

    The ladder the task names (low live-without-brand, medium young+brand,
    high password/MX+young cert, critical plus favicon) is computed when the
    observation already carries those flags. M1 DNS results do not, and this
    function does not auto-confirm.
    """
    obs = observation or {}
    if obs.get("favicon_match") and (
        obs.get("password_form") or (obs.get("mx_present") and obs.get("young_cert"))
    ):
        return "critical"
    if obs.get("password_form") or (
        obs.get("mx_present") and obs.get("young_cert") and (obs.get("brand_in_title") or obs.get("brand_in_cert"))
    ):
        return "high"
    if obs.get("young_domain") and (obs.get("brand_in_title") or obs.get("brand_in_cert")):
        return "medium"
    if state in {"http_live", "resolving"} and not obs.get("brand_in_title"):
        if obs.get("http") or state == "http_live":
            return "low"
    if state in {"registered", "parked", "disappeared", "unregistered"}:
        return "informational"
    return "informational"


def _fingerprint(observation: dict[str, Any]) -> str:
    kept = {
        "nxdomain": bool(observation.get("nxdomain")),
        "ns": sorted(str(item) for item in (observation.get("ns") or [])),
        "addresses": sorted(str(item) for item in (observation.get("addresses") or [])),
        "mx_present": bool(observation.get("mx_present")),
        "rdap": bool(observation.get("rdap")),
    }
    raw = json.dumps(kept, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _strip_html(document: dict[str, Any]) -> dict[str, Any]:
    cleaned = {key: value for key, value in document.items() if key not in _HTML_KEYS}
    return cleaned


def diff_event(
    *,
    name: str,
    from_state: str | None,
    to_state: str,
    severity: str,
    reasons: list[str],
    candidate_id: str | None = None,
    profile_id: str | None = None,
    punycode: str | None = None,
    mx_present: bool | None = None,
    last_changed: str | None = None,
    disposition: str | None = None,
) -> dict[str, Any]:
    """The only notification payload: the transition, not the candidate list.

    Flat fields sit beside ``payload`` so the console can read a row without
    unwrapping the webhook envelope. ``id`` is the candidate, which is what
    disposition posts back.
    """
    return {
        "type": "brand_watch.diff",
        "id": candidate_id,
        "profile_id": profile_id,
        "name": name,
        "punycode": punycode,
        "previous_state": from_state,
        "new_state": to_state,
        "severity": severity,
        "mx_present": mx_present,
        "last_changed": last_changed,
        "disposition": disposition,
        "payload": {
            "name": name,
            "from_state": from_state,
            "to_state": to_state,
            "severity": severity,
            "reasons": reasons,
        },
    }


def _generate(profile: models.BrandProfile) -> list[dict[str, Any]]:
    """Import the generator at call time. Do not edit that module from here.

    Prefers ``generate_brand_candidates`` when that name exists. The module
    that landed exposes ``generate(domain, max_candidates, exclude=...)``;
    this wrapper calls that per official domain and tags each row with the
    fields the candidate table stores.
    """
    import scanner.pipeline.lookalike as lookalike

    named = getattr(lookalike, "generate_brand_candidates", None)
    if named is not None:
        return list(named(
            official_domains=list(profile.official_domains or []),
            brand_strings=list(profile.brand_strings or []),
            whitelist=list(profile.whitelist or []),
        ))
    generate = lookalike.generate
    exclude = set(profile.official_domains or []) | set(profile.whitelist or [])
    rows: list[dict[str, Any]] = []
    # One profile shares the candidate cap across every official domain.
    # The first domains fill it; later domains are not generated past the cap.
    for domain in profile.official_domains or []:
        room = MAX_CANDIDATES - len(rows)
        if room <= 0:
            break
        for item in generate(domain, room, exclude=exclude):
            name = str(item.get("name") or item.get("name_unicode") or "")
            rows.append({
                "name": name,
                "name_unicode": name,
                "name_punycode": str(item.get("punycode") or item.get("name_punycode") or name),
                "generator_class": str(item.get("generator") or item.get("generator_class") or ""),
                "seed": domain,
                "reason": str(item.get("generator") or ""),
            })
            if len(rows) >= MAX_CANDIDATES:
                break
    return rows


def _profile_dict(row: models.BrandProfile) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "approved": row.approved_at is not None and bool(row.our_brand),
        "official_domains": list(row.official_domains or []),
        "brand_strings": list(row.brand_strings or []),
        "whitelist": list(row.whitelist or []),
        "reference": dict(row.reference or {}),
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "approved_by": row.approved_by,
        "our_brand": bool(row.our_brand),
        "mode": watch_mode(row),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _candidate_dict(row: models.BrandCandidate) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "profile_id": row.profile_id,
        "name_unicode": row.name_unicode,
        "name_punycode": row.name_punycode,
        "seed": row.seed,
        "generator_class": row.generator_class,
        "reason": row.reason,
        "state": row.state,
        "previous_state": row.previous_state,
        "severity": row.severity,
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_checked": row.last_checked.isoformat() if row.last_checked else None,
        "last_changed": row.last_changed.isoformat() if row.last_changed else None,
        "ns": list(row.ns or []),
        "addresses": list(row.addresses or []),
        "mx_present": bool(row.mx_present),
        "rdap": row.rdap,
        "http": row.http,
        "score": row.score,
        "reasons": list(row.reasons or []),
        "disposition": row.disposition,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def create_profile(
    settings: Settings,
    *,
    tenant_id: str,
    name: str,
    official_domains: list[str],
    brand_strings: list[str],
    whitelist: list[str] | None = None,
    reference: dict | None = None,
    our_brand: bool = False,
) -> dict[str, Any]:
    strings = validate_brand_strings(brand_strings)
    domains = [_norm_name(item) for item in official_domains if (item or "").strip()]
    if not domains:
        raise BrandWatchError("at least one official domain is required")
    now = _now()
    with get_session(settings.postgres_url) as session:
        count = session.scalar(
            select(func.count()).select_from(models.BrandProfile).where(
                models.BrandProfile.tenant_id == tenant_id
            )
        ) or 0
        if count >= MAX_PROFILES:
            raise QuotaExceeded(f"brand_watch_profiles limit is {MAX_PROFILES}")
        row = models.BrandProfile(
            id=_new_id("bwp"),
            tenant_id=tenant_id,
            name=name.strip(),
            official_domains=domains,
            brand_strings=strings,
            whitelist=[_norm_name(item) for item in (whitelist or []) if (item or "").strip()],
            reference=reference or {},
            approved_at=None,
            approved_by=None,
            our_brand=bool(our_brand),
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        session.flush()
        return _profile_dict(row)


def list_profiles(settings: Settings, tenant_id: str) -> list[dict[str, Any]]:
    with get_session(settings.postgres_url) as session:
        rows = session.scalars(
            select(models.BrandProfile)
            .where(models.BrandProfile.tenant_id == tenant_id)
            .order_by(models.BrandProfile.created_at)
        ).all()
        return [_profile_dict(row) for row in rows]


def get_profile(settings: Settings, tenant_id: str, profile_id: str) -> dict[str, Any] | None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.BrandProfile, profile_id)
        if row is None or row.tenant_id != tenant_id:
            return None
        return _profile_dict(row)


def approve_profile(
    settings: Settings,
    *,
    tenant_id: str,
    profile_id: str,
    approved_by: str,
    our_brand: bool,
) -> dict[str, Any]:
    """Approve only when the caller confirms the brand is theirs.

    ``our_brand`` false leaves the profile unapproved for HTTP: the checkbox
    is required, and a profile that is not ours never leaves ``dns_only``.
    """
    if not our_brand:
        raise BrandWatchError("our_brand must be confirmed before approve")
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.BrandProfile, profile_id)
        if row is None or row.tenant_id != tenant_id:
            raise LookupError("profile not found")
        row.our_brand = True
        row.approved_at = now
        row.approved_by = approved_by
        row.updated_at = now
        session.flush()
        return _profile_dict(row)


def list_candidates(
    settings: Settings, tenant_id: str, profile_id: str
) -> list[dict[str, Any]]:
    with get_session(settings.postgres_url) as session:
        profile = session.get(models.BrandProfile, profile_id)
        if profile is None or profile.tenant_id != tenant_id:
            raise LookupError("profile not found")
        rows = session.scalars(
            select(models.BrandCandidate)
            .where(
                models.BrandCandidate.tenant_id == tenant_id,
                models.BrandCandidate.profile_id == profile_id,
            )
            .order_by(models.BrandCandidate.name_punycode)
        ).all()
        return [_candidate_dict(row) for row in rows]


def set_disposition(
    settings: Settings,
    *,
    tenant_id: str,
    candidate_id: str,
    disposition: str,
) -> dict[str, Any]:
    if disposition not in DISPOSITIONS:
        raise BrandWatchError(f"disposition must be one of {sorted(DISPOSITIONS)}")
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.BrandCandidate, candidate_id)
        if row is None or row.tenant_id != tenant_id:
            raise LookupError("candidate not found")
        row.disposition = disposition
        row.updated_at = now
        session.flush()
        return _candidate_dict(row)


def _own_names(profile: models.BrandProfile) -> set[str]:
    own = {_norm_name(item) for item in (profile.official_domains or [])}
    own |= {_norm_name(item) for item in (profile.whitelist or [])}
    return {item for item in own if item}


def rebuild_candidates(
    settings: Settings,
    *,
    tenant_id: str,
    profile_id: str,
    generated: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Replace the candidate list deterministically.

    Names that remain keep their disposition and DNS state. Names that the
    generator no longer emits are deleted. Official domains and whitelist
    entries are never stored, even if a generator returns them.

    Does not insert a scan job.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        profile = session.get(models.BrandProfile, profile_id)
        if profile is None or profile.tenant_id != tenant_id:
            raise LookupError("profile not found")
        produced = generated if generated is not None else _generate(profile)
        own = _own_names(profile)
        existing = {
            row.name_punycode: row
            for row in session.scalars(
                select(models.BrandCandidate).where(
                    models.BrandCandidate.tenant_id == tenant_id,
                    models.BrandCandidate.profile_id == profile_id,
                )
            ).all()
        }
        seen: set[str] = set()
        ordered: list[tuple[str, dict[str, Any]]] = []
        for item in produced:
            puny = _norm_name(str(item.get("name_punycode") or item.get("name") or ""))
            if not puny or puny in own or puny in seen:
                continue
            seen.add(puny)
            ordered.append((puny, item))
        removed = 0
        for puny, row in list(existing.items()):
            if puny not in seen:
                session.delete(row)
                del existing[puny]
                removed += 1
        # Names the generator still emits stay, disposition included. New names
        # fill whatever room the cap has left and the rest are left off this
        # rebuild instead of rolling the kept rows back.
        room = MAX_CANDIDATES - len(existing)
        created = 0
        for puny, item in ordered:
            if puny in existing:
                continue
            if created >= room:
                break
            session.add(models.BrandCandidate(
                id=_new_id("bwc"),
                tenant_id=tenant_id,
                profile_id=profile_id,
                name_unicode=str(item.get("name_unicode") or item.get("name") or puny),
                name_punycode=puny,
                seed=str(item.get("seed") or ""),
                generator_class=str(item.get("generator_class") or item.get("klass") or ""),
                reason=str(item.get("reason") or ""),
                state="unregistered",
                ns=[],
                addresses=[],
                mx_present=False,
                reasons=[],
                disposition="open",
                created_at=now,
                updated_at=now,
            ))
            created += 1
        profile.last_rebuilt_at = now
        profile.updated_at = now
        session.flush()
        return {"created": created, "removed": removed, "kept": len(existing)}


def diff_since(
    settings: Settings,
    tenant_id: str,
    *,
    since: datetime | None,
) -> list[dict[str, Any]]:
    """Transitions since ``since``. Not the candidate list."""
    with get_session(settings.postgres_url) as session:
        query = select(models.BrandCandidate).where(
            models.BrandCandidate.tenant_id == tenant_id,
            models.BrandCandidate.last_changed.is_not(None),
            models.BrandCandidate.disposition.notin_(tuple(SILENT_DISPOSITIONS)),
        )
        if since is not None:
            query = query.where(models.BrandCandidate.last_changed >= since)
        rows = session.scalars(query.order_by(models.BrandCandidate.last_changed)).all()
        events = []
        for row in rows:
            events.append(diff_event(
                name=row.name_unicode,
                from_state=row.previous_state,
                to_state=row.state,
                severity=row.severity or severity_for(row.state, {"mx_present": row.mx_present}),
                reasons=list(row.reasons or [])[:8],
                candidate_id=row.id,
                profile_id=row.profile_id,
                punycode=row.name_punycode,
                mx_present=bool(row.mx_present),
                last_changed=row.last_changed.isoformat() if row.last_changed else None,
                disposition=row.disposition,
            ))
        return events


def _http_names_used(session: Session, tenant_id: str, since: datetime) -> int:
    """Names already placed in ``http_allowed`` jobs since ``since``.

    The daily cap is a name budget. Counting jobs would let one profile's
    full candidate list through, because a tenant never has 200 profiles.
    """
    payloads = session.scalars(
        select(models.BrandWatchJob.payload).where(
            models.BrandWatchJob.tenant_id == tenant_id,
            models.BrandWatchJob.mode == "http_allowed",
            models.BrandWatchJob.created_at >= since,
        )
    ).all()
    used = 0
    for payload in payloads:
        names = payload.get("names") if isinstance(payload, dict) else None
        if isinstance(names, list):
            used += len(names)
    return used


def _add_watch_job(
    session: Session,
    profile: models.BrandProfile,
    *,
    moment: datetime,
    mode: str,
    names: list[str],
) -> models.BrandWatchJob:
    job = models.BrandWatchJob(
        id=_new_id("bwj"),
        tenant_id=profile.tenant_id,
        profile_id=profile.id,
        status="queued",
        mode=mode,
        payload={"names": names, "mode": mode},
        attempts=0,
        created_at=moment,
    )
    session.add(job)
    return job


def _fail_expired(session: Session, profile_id: str, moment: datetime) -> None:
    """Drop claims whose lease has ended so a new day is not a second copy."""
    expired = session.scalars(
        select(models.BrandWatchJob).where(
            models.BrandWatchJob.profile_id == profile_id,
            models.BrandWatchJob.status == "claimed",
            models.BrandWatchJob.lease_until.is_not(None),
            models.BrandWatchJob.lease_until <= moment,
        )
    ).all()
    for row in expired:
        row.status = "failed"
        row.finished_at = moment
        row.lease_owner = None
        row.lease_until = None


def enqueue_for_profile(
    session: Session,
    profile: models.BrandProfile,
    *,
    now: datetime | None = None,
    force: bool = False,
) -> models.BrandWatchJob | None:
    """Queue today's watch. Never a scan job, never ``http_allowed`` unless
    the profile is approved and marked ours.

    A live queued or claimed job is left alone. A claim whose lease has
    ended does not block the next day; it is failed and replaced. When HTTP
    is on, only the remaining name budget goes into the ``http_allowed``
    job. The rest of the list is a ``dns_only`` job.
    """
    moment = now or _now()
    mode = watch_mode(profile)
    if not force and profile.last_dispatched_at and (
        moment - profile.last_dispatched_at < DAILY
    ):
        return None
    open_job = session.scalar(
        select(models.BrandWatchJob.id).where(
            models.BrandWatchJob.profile_id == profile.id,
            or_(
                models.BrandWatchJob.status == "queued",
                and_(
                    models.BrandWatchJob.status == "claimed",
                    or_(
                        models.BrandWatchJob.lease_until.is_(None),
                        models.BrandWatchJob.lease_until > moment,
                    ),
                ),
            ),
        )
    )
    if open_job:
        return None
    _fail_expired(session, profile.id, moment)
    names = [
        row.name_punycode
        for row in session.scalars(
            select(models.BrandCandidate).where(
                models.BrandCandidate.profile_id == profile.id
            )
        ).all()
    ]
    http_names: list[str] = []
    dns_names = names
    if mode == "http_allowed":
        used = _http_names_used(session, profile.tenant_id, moment - DAILY)
        remaining = max(0, MAX_HTTP_PER_DAY - used)
        http_names = names[:remaining]
        dns_names = names[remaining:]
    job: models.BrandWatchJob | None = None
    if http_names:
        job = _add_watch_job(session, profile, moment=moment, mode="http_allowed", names=http_names)
    if dns_names or job is None:
        dns_job = _add_watch_job(
            session, profile, moment=moment, mode="dns_only", names=dns_names if job else names
        )
        job = job or dns_job
    profile.last_dispatched_at = moment
    profile.updated_at = moment
    return job


def due_profiles(session: Session, now: datetime) -> list[models.BrandProfile]:
    cutoff = now - DAILY
    return list(session.scalars(
        select(models.BrandProfile).where(
            (models.BrandProfile.last_dispatched_at.is_(None))
            | (models.BrandProfile.last_dispatched_at <= cutoff)
        )
    ).all())


def _for_update(query, session: Session, *, skip_locked: bool = False):
    """Row lock on Postgres. SQLite tests run the same statement without it."""
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return query
    if skip_locked:
        return query.with_for_update(skip_locked=True)
    return query.with_for_update()


def claim_job(
    settings: Settings,
    *,
    tenant_id: str,
    agent_id: str,
    capabilities: list[str] | None,
) -> dict[str, Any] | None:
    """Claim one brand-watch job for this tenant.

    A sensor that did not present ``brand_watch`` gets nothing. Queued jobs
    and claims whose lease has ended are both eligible. A row that has
    already been claimed ``MAX_ATTEMPTS`` times is failed and skipped. This
    never selects from ``jobs`` (scan jobs).
    """
    if not sensor_may_claim(capabilities):
        return None
    now = _now()
    lease_until = now + timedelta(seconds=LEASE_SECONDS)
    with get_session(settings.postgres_url) as session:
        while True:
            row = session.scalars(
                _for_update(
                    select(models.BrandWatchJob)
                    .where(
                        models.BrandWatchJob.tenant_id == tenant_id,
                        or_(
                            models.BrandWatchJob.status == "queued",
                            and_(
                                models.BrandWatchJob.status == "claimed",
                                models.BrandWatchJob.lease_until.is_not(None),
                                models.BrandWatchJob.lease_until <= now,
                            ),
                        ),
                    )
                    .order_by(models.BrandWatchJob.created_at)
                    .limit(1),
                    session,
                    skip_locked=True,
                )
            ).first()
            if row is None:
                return None
            if (row.attempts or 0) >= MAX_ATTEMPTS:
                row.status = "failed"
                row.finished_at = now
                row.lease_owner = None
                row.lease_until = None
                session.flush()
                continue
            row.status = "claimed"
            row.lease_owner = agent_id
            row.lease_until = lease_until
            row.attempts = (row.attempts or 0) + 1
            session.flush()
            return {
                "id": row.id,
                "tenant_id": row.tenant_id,
                "profile_id": row.profile_id,
                "mode": row.mode,
                "payload": row.payload,
                "lease_until": lease_until.isoformat(),
            }


def _carried(raw: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return any(key in raw for key in keys)


def apply_result(
    settings: Settings,
    *,
    tenant_id: str,
    job_id: str,
    observations: list[dict[str, Any]],
    agent_id: str,
    capabilities: list[str] | None,
) -> dict[str, Any]:
    """Apply a sensor result. Repeating the same job id is a no-op.

    The caller must hold ``brand_watch`` and be the current lease owner,
    with the lease still running and the job ``claimed``. The job row is
    locked before the ``applied_at`` check. Idempotency is ``applied_at``:
    a second post does not move candidate state and does not emit another diff.
    """
    if not sensor_may_claim(capabilities):
        raise LeaseDenied("brand_watch capability is required")
    fingerprint = hashlib.sha256(
        json.dumps(observations, sort_keys=True, default=str).encode()
    ).hexdigest()
    now = _now()
    events: list[dict[str, Any]] = []
    with get_session(settings.postgres_url) as session:
        job = session.scalars(
            _for_update(
                select(models.BrandWatchJob).where(models.BrandWatchJob.id == job_id),
                session,
            )
        ).first()
        if job is None or job.tenant_id != tenant_id:
            raise LookupError("job not found")
        if job.applied_at is not None:
            return {
                "id": job.id,
                "status": job.status,
                "idempotent": True,
                "events": [],
            }
        if job.status != "claimed" or job.lease_owner != agent_id:
            raise LeaseDenied("job is not leased to this sensor")
        if job.lease_until is None or job.lease_until <= now:
            raise LeaseDenied("lease expired")
        by_name = {
            row.name_punycode: row
            for row in session.scalars(
                select(models.BrandCandidate).where(
                    models.BrandCandidate.profile_id == job.profile_id,
                    models.BrandCandidate.tenant_id == tenant_id,
                )
            ).all()
        }
        for raw in observations:
            if not isinstance(raw, dict):
                continue
            cleaned = normalize_observation(raw)
            name = _norm_name(str(cleaned.get("name") or cleaned.get("name_punycode") or cleaned.get("punycode") or ""))
            candidate = by_name.get(name)
            if candidate is None:
                continue
            previous = candidate.state
            new_state = transition(previous, cleaned)
            previous_hash = candidate.content_hash
            mx_was = bool(candidate.mx_present)
            unanswered = str(raw.get("status") or "") == "unanswered"
            http_summary = None
            if job.mode == "http_allowed" and (
                cleaned.get("http") or cleaned.get("live") or cleaned.get("status_code") is not None
            ):
                http_summary = _http_hook(cleaned, previous_state=previous)
                if http_summary is not None:
                    candidate.http = http_summary.get("evidence")
                    scored = http_summary.get("score") or {}
                    scored_state = scored.get("state")
                    if scored_state in STATES and scored_state != "confirmed":
                        new_state = scored_state
            if not unanswered:
                if _carried(raw, _DNS_NS_KEYS):
                    candidate.ns = list(cleaned.get("ns") or [])
                if _carried(raw, _DNS_ADDR_KEYS):
                    candidate.addresses = list(cleaned.get("addresses") or [])
                if "mx_present" in raw:
                    candidate.mx_present = bool(cleaned.get("mx_present"))
                if cleaned.get("rdap") is not None:
                    candidate.rdap = (
                        cleaned.get("rdap") if isinstance(cleaned.get("rdap"), dict) else {"present": True}
                    )
            mx_now = bool(candidate.mx_present)
            content = _fingerprint({
                "nxdomain": False if unanswered else bool(cleaned.get("nxdomain")),
                "ns": candidate.ns,
                "addresses": candidate.addresses,
                "mx_present": mx_now,
                "rdap": candidate.rdap,
            })
            if unanswered:
                changed = new_state != previous
            else:
                changed = (
                    new_state != previous
                    or (previous_hash is not None and content != previous_hash)
                    or ("mx_present" in raw and mx_now != mx_was)
                )
                candidate.content_hash = content
            reasons = _change_reasons(previous, new_state, content, previous_hash, mx_was, mx_now)
            event_severity = severity_for(new_state, cleaned)
            if http_summary is not None:
                scored = http_summary.get("score") or {}
                if scored.get("severity"):
                    event_severity = str(scored["severity"])
                    reasons = list(scored.get("reasons") or reasons)
            candidate.state = new_state
            candidate.last_checked = now
            candidate.updated_at = now
            if candidate.first_seen is None and new_state != "unregistered":
                candidate.first_seen = now
            if changed:
                candidate.last_changed = now
                candidate.previous_state = previous
                candidate.severity = event_severity
                candidate.reasons = reasons
            session.add(models.BrandObservation(
                id=_new_id("bwo"),
                tenant_id=tenant_id,
                candidate_id=candidate.id,
                job_id=job.id,
                checked_at=now,
                mode=job.mode,
                result=cleaned,
            ))
            if changed and candidate.disposition not in SILENT_DISPOSITIONS:
                event = diff_event(
                    name=candidate.name_unicode,
                    from_state=previous,
                    to_state=new_state,
                    severity=event_severity,
                    reasons=reasons,
                    candidate_id=candidate.id,
                    profile_id=candidate.profile_id,
                    punycode=candidate.name_punycode,
                    mx_present=mx_now,
                    last_changed=now.isoformat(),
                    disposition=candidate.disposition,
                )
                events.append(event)
        job.status = "done"
        job.result_hash = fingerprint
        job.applied_at = now
        job.finished_at = now
        session.flush()
        return {"id": job.id, "status": job.status, "idempotent": False, "events": events}


def _change_reasons(
    previous: str,
    new_state: str,
    content: str,
    previous_hash: str | None,
    mx_was: bool,
    mx_now: bool,
) -> list[str]:
    reasons: list[str] = []
    if new_state != previous:
        reasons.append("state")
    if previous_hash and content != previous_hash:
        reasons.append("hash")
    if mx_now and not mx_was:
        reasons.append("mx")
    return reasons


def _http_hook(observation: dict[str, Any], *, previous_state: str | None) -> dict[str, Any] | None:
    """Call M2 scoring when that module is importable. Never rewrite it."""
    try:
        from api.services.brand_watch_http import apply_http_observation
    except ImportError:
        return None
    try:
        return apply_http_observation(observation, previous_state=previous_state)
    except Exception:
        _log.warning("brand-watch HTTP hook failed", exc_info=True)
        return None
