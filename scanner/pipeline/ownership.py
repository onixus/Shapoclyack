"""Domain ownership via RDAP (org_profile M1, EPIC #182).

Answers "whose domain is this" from the registry's own RDAP object: registrar,
registrant organization, abuse contact, lifecycle dates, EPP statuses, DNSSEC
delegation and the delegated nameservers. Passive and keyless, one HTTPS GET
per domain plus one cached bootstrap fetch -- the same "free public API,
fail-soft per call, opt-in" posture as ``asn_discovery.py``.

Lookup path: the IANA bootstrap file (RFC 7484) maps the TLD to its registry
RDAP base URL; ``rdap.org`` is the fallback for TLDs the bootstrap does not
cover. Both are reached through ``safe_http.py``, not ``httpx`` -- this is the
first scanner stage whose next hop is named by a remote party, so the address
is validated and pinned on this side (see that module's docstring).

PII: only ``org_name``, ``registrar``, ``abuse_email``, dates, statuses, the
DNSSEC flag and the nameservers are written. The raw ``entities[]`` / vCard
block -- postal address, phone, natural-person name, tech and admin contacts --
is parsed in memory and **never** written to disk, the same rule as
``screenshots.py``'s "unredacted bytes are never written". The artifact is
still a restricted class in the API (``api/services/runs.py``
``is_restricted_artifact``) because ``abuse_email`` alone is operator-grade.

HONESTY: most gTLD registries return a GDPR-masked object, and many domains
belong to a private person rather than to a company. ``registrant_status``
keeps those apart instead of collapsing them into "no owner": ``public`` (an
organization name was recorded), ``redacted`` (the registry masked it),
``natural_person`` (an explicit ``kind: individual`` -- the name is deliberately
not recorded), ``unidentified`` (a registrant exists but nothing in it is
identifiable as an organization) and ``unknown`` (no registrant at all). And
per the module invariant of #182, a domain with no RDAP answer gets
``status: "not_checked"`` or ``"error"`` with a reason, never ``"ok"``.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from . import safe_http
from .config_schema import OwnershipConfig
from .safe_http import SAFE_HTTP_ERRORS
from .utils import load_json, save_json, write_lines

LOG = logging.getLogger("shapoclyack.ownership")

IANA_DNS_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_ORG_FALLBACK = "https://rdap.org/domain/"
USER_AGENT = "shapoclyack/ownership"
BOOTSTRAP_CACHE_FILE = "rdap_dns_bootstrap.json"
#: IANA serves the bootstrap document with ``max-age=86400``; match it rather
#: than inventing a second number.
BOOTSTRAP_CACHE_TTL_SECONDS = 86_400

#: rdap.org answers with a 302 to the registry server, so zero redirects would
#: break the fallback entirely. Three is enough for bootstrap -> registry ->
#: registrar without being a chain worth walking.
_MAX_REDIRECTS = 3
#: RDAP domain objects are a few KiB; the bootstrap file is ~200 KiB.
_MAX_RESPONSE_BYTES = 256 * 1024

#: Fixed per-source confidence weights, documented here rather than in config
#: so the numbers stay comparable between runs and between organizations. A
#: registry's own registrant record is the strongest domain-level claim there
#: is; an abuse address is published by the same registry but may belong to the
#: registrar rather than the org, hence the small discount.
_CONFIDENCE = {
    "org_name": 0.9,
    "registrar": 0.8,
    "abuse_email": 0.7,
}

#: Values registries substitute for a masked field. Compared case-folded
#: against the whole value: a real organization named "Privacy International"
#: must not be classified as redacted.
_REDACTION_MARKERS = frozenset(
    {
        "redacted for privacy",
        "redacted",
        "data redacted",
        "not disclosed",
        "non-public data",
        "gdpr masked",
        "statutory masking enabled",
        "privacy service provided by withheld for privacy ehf",
        "withheld for privacy",
        "domains by proxy, llc",
        "private registration",
        "whois privacy",
    }
)


def _vcard_field(entity: dict[str, Any], name: str) -> str | None:
    """One jCard field of an RDAP entity (RFC 7095 ``vcardArray``).

    The shape is ``["vcard", [[name, params, type, value], ...]]``; anything
    that does not match is a registry quirk, not an error worth raising.
    """
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for field in vcard[1]:
        if not isinstance(field, list) or len(field) < 4 or field[0] != name:
            continue
        value = field[3]
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _walk_entities(entities: Any, depth: int = 0) -> list[dict[str, Any]]:
    """Flatten the entity tree. Registrar abuse contacts are nested one level
    below the registrar entity, and some registries nest deeper."""
    collected: list[dict[str, Any]] = []
    if depth > 3 or not isinstance(entities, list):
        return collected
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        collected.append(entity)
        collected.extend(_walk_entities(entity.get("entities"), depth + 1))
    return collected


def _has_role(entity: dict[str, Any], role: str) -> bool:
    roles = entity.get("roles")
    return isinstance(roles, list) and role in roles


def _registrant_org(entity: dict[str, Any]) -> str | None:
    """The registrant's *organization* name, or ``None`` if there is not one.

    ``fn`` is accepted only when the entity declares ``kind: org``. On a domain
    registered by a private person ``fn`` **is** that person's name, and the
    module contract is that a natural-person name never reaches disk -- so an
    ``fn`` that is not backed by an explicit ``kind`` is dropped rather than
    guessed at.

    That is a deliberate false-negative bias: a registry that puts a company
    name in ``fn`` and omits ``kind`` loses the identifier, and losing an
    identifier is the cheaper of the two mistakes. It also keeps
    ``registrant_status`` meaningful -- a module that exists to tell "hidden"
    apart from "absent" must not quietly conflate "organization" with "human".
    """
    org = _vcard_field(entity, "org")
    if org:
        return org
    if (_vcard_field(entity, "kind") or "").casefold() == "org":
        return _vcard_field(entity, "fn")
    return None


def _is_redacted_value(value: str | None) -> bool:
    return value is not None and value.strip().casefold() in _REDACTION_MARKERS


def _object_is_redacted(payload: dict[str, Any]) -> bool:
    """True when the registry says it withheld data.

    Two signals: RFC 9537 ``redacted[]`` (the modern, explicit one) and the
    older convention of a ``remarks`` entry titled "REDACTED FOR PRIVACY".
    """
    if isinstance(payload.get("redacted"), list) and payload["redacted"]:
        return True
    for remark in payload.get("remarks") or []:
        if not isinstance(remark, dict):
            continue
        title = str(remark.get("title") or "")
        if "redact" in title.casefold() or "privacy" in title.casefold():
            return True
    return False


def _event_date(payload: dict[str, Any], action: str) -> str | None:
    for event in payload.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == action:
            date = event.get("eventDate")
            if isinstance(date, str) and date.strip():
                return date.strip()
    return None


def _parse_rdap_domain(payload: dict[str, Any]) -> dict[str, Any]:
    """Project an RDAP domain object onto the minimal record we persist.

    Everything not named here -- addresses, phone numbers, natural-person
    names, tech/admin contacts -- is dropped on the floor by construction:
    this function returns a fresh dict rather than filtering the input.
    """
    entities = _walk_entities(payload.get("entities"))

    registrar: str | None = None
    org_name: str | None = None
    abuse_email: str | None = None
    registrant_seen = False
    registrant_redacted = False
    registrant_is_individual = False
    for entity in entities:
        if registrar is None and _has_role(entity, "registrar"):
            registrar = _vcard_field(entity, "fn")
        if _has_role(entity, "registrant"):
            registrant_seen = True
            if (_vcard_field(entity, "kind") or "").casefold() == "individual":
                registrant_is_individual = True
            if _is_redacted_value(_vcard_field(entity, "fn")) or _is_redacted_value(
                _vcard_field(entity, "org")
            ):
                registrant_redacted = True
            if org_name is None:
                org_name = _registrant_org(entity)
        if abuse_email is None and _has_role(entity, "abuse"):
            abuse_email = _vcard_field(entity, "email")

    if _is_redacted_value(registrar):
        registrar = None
    if _is_redacted_value(org_name):
        registrant_redacted = True
        org_name = None
    registrant_redacted = registrant_redacted or _object_is_redacted(payload)

    if org_name:
        registrant_status = "public"
    elif registrant_redacted:
        registrant_status = "redacted"
    elif registrant_is_individual:
        registrant_status = "natural_person"
    elif registrant_seen:
        registrant_status = "unidentified"
    else:
        registrant_status = "unknown"

    secure_dns = payload.get("secureDNS")
    dnssec: bool | None = None
    if isinstance(secure_dns, dict) and isinstance(secure_dns.get("delegationSigned"), bool):
        dnssec = secure_dns["delegationSigned"]

    nameservers = sorted(
        {
            str(ns["ldhName"]).strip().rstrip(".").lower()
            for ns in payload.get("nameservers") or []
            if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str) and ns["ldhName"].strip()
        }
    )
    statuses = sorted(
        {str(status).strip() for status in payload.get("status") or [] if str(status).strip()}
    )

    return {
        "status": "ok",
        "reason": None,
        "registrar": registrar,
        "org_name": org_name,
        "abuse_email": abuse_email,
        "registrant_status": registrant_status,
        "created": _event_date(payload, "registration"),
        "updated": _event_date(payload, "last changed"),
        "expires": _event_date(payload, "expiration"),
        "domain_statuses": statuses,
        "dnssec": dnssec,
        "nameservers": nameservers,
    }


#: Why a lookup produced nothing, and how that maps onto the control status of
#: #182. "not_checked" is "nobody could tell us"; "error" is "we tried and the
#: attempt itself failed". Neither is ever "ok".
_REASON_STATUS = {
    "rdap_not_found": "not_checked",
    "rdap_unavailable": "error",
    "rdap_blocked_target": "error",
}


def _no_answer(reason: str) -> dict[str, Any]:
    """A domain with no usable RDAP answer. Never ``ok`` -- see module docstring."""
    return {
        "status": _REASON_STATUS.get(reason, "error"),
        "reason": reason,
        "registrar": None,
        "org_name": None,
        "abuse_email": None,
        "registrant_status": "unknown",
        "created": None,
        "updated": None,
        "expires": None,
        "domain_statuses": [],
        "dnssec": None,
        "nameservers": [],
    }


def _get_json(
    url: str,
    timeout: float,
    max_retries: int = 2,
    *,
    deadline: float | None = None,
) -> Any:
    """One RDAP GET with the retry ladder from ``asn_discovery.py``.

    Response bodies are never logged: an RDAP object is exactly the PII this
    module exists to keep off disk, and a log line is disk.

    ``deadline`` is the stage-wide budget. Without it one unresponsive registry
    costs up to ``(urls x attempts) * timeout`` plus the backoff sleeps, which
    is how a 300 s stage deadline turns into ~400 s of wall clock: checking the
    clock only *between* domains bounds the gap, not the domain.
    """
    for attempt in range(max_retries + 1):
        request_timeout = timeout
        if deadline is not None:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise safe_http.SafeHttpError("stage deadline exceeded")
            request_timeout = min(timeout, remaining)
        try:
            resp = safe_http.get(
                url,
                timeout_seconds=request_timeout,
                max_bytes=_MAX_RESPONSE_BYTES,
                headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT},
                max_redirects=_MAX_REDIRECTS,
            )
            if resp.status in (429, 502, 503, 504) and attempt < max_retries:
                if not _sleep_within(0.5 * (2**attempt), deadline):
                    raise safe_http.SafeHttpError(f"HTTP {resp.status}, stage deadline exceeded")
                continue
            if resp.status == 404:
                return None
            if resp.status >= 400:
                raise safe_http.SafeHttpError(f"HTTP {resp.status}")
            return safe_http.json_body(resp)
        except safe_http.UnsafeTargetError:
            # A blocked address is policy, not a transient failure: retrying
            # the same URL can only reach the same address.
            raise
        except SAFE_HTTP_ERRORS as exc:
            if attempt < max_retries and _sleep_within(0.5 * (2**attempt), deadline):
                continue
            raise safe_http.SafeHttpError(str(exc)) from exc
    return None


def _cache_is_fresh(cache: Path) -> bool:
    """Whether the cached bootstrap document is still inside its TTL."""
    try:
        age = time.time() - cache.stat().st_mtime
    except OSError:
        return False
    return 0 <= age < BOOTSTRAP_CACHE_TTL_SECONDS


def _sleep_within(seconds: float, deadline: float | None) -> bool:
    """Back off, unless that would spend budget the stage no longer has."""
    if deadline is None:
        time.sleep(seconds)
        return True
    remaining = deadline - time.perf_counter()
    if remaining <= 0:
        return False
    time.sleep(min(seconds, remaining))
    return deadline - time.perf_counter() > 0


def _load_bootstrap(state_dir: Path, timeout: float) -> dict[str, str]:
    """TLD -> registry RDAP base URL, cached in ``state_dir``.

    Cached rather than fetched per domain: a 50k-asset estate collapses to tens
    of TLDs, and IANA should see one request, not one per domain.

    The cache carries a one-day TTL because ``state_dir`` is not always per-run:
    under ``runtime.per_run_output: false`` it is the shared state base, and a
    cache with no TTL would then be written once and believed forever -- a new
    TLD or a registry that moved its RDAP server would never be picked up, and
    every such domain would silently fall through to ``rdap.org``. One day is
    what IANA itself serves the document with (``max-age=86400``).
    """
    cache = state_dir / BOOTSTRAP_CACHE_FILE
    payload = load_json(cache, fallback=None) if _cache_is_fresh(cache) else None
    if payload is None:
        try:
            payload = _get_json(IANA_DNS_BOOTSTRAP, timeout)
        except SAFE_HTTP_ERRORS as exc:
            LOG.warning("ownership: RDAP bootstrap fetch failed: %s", exc)
            return {}
        if not isinstance(payload, dict):
            LOG.warning("ownership: RDAP bootstrap returned an unexpected document")
            return {}
        save_json(cache, payload)

    services: dict[str, str] = {}
    for entry in (payload.get("services") if isinstance(payload, dict) else None) or []:
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        base = next(
            (str(u) for u in urls if isinstance(u, str) and u.startswith("https://")),
            None,
        )
        if not base:
            continue
        for tld in tlds if isinstance(tlds, list) else []:
            services[str(tld).strip().lower()] = base if base.endswith("/") else base + "/"
    return services


def _rdap_urls(domain: str, services: dict[str, str]) -> list[str]:
    """Candidate RDAP URLs for one domain, registry first, ``rdap.org`` last."""
    urls: list[str] = []
    labels = domain.split(".")
    # Longest-match first: "co.uk" is a bootstrap key of its own in some zones.
    for index in range(1, len(labels)):
        base = services.get(".".join(labels[index:]))
        if base:
            urls.append(f"{base}domain/{domain}")
            break
    urls.append(f"{RDAP_ORG_FALLBACK}{domain}")
    return urls


def _lookup_domain(
    domain: str,
    services: dict[str, str],
    timeout: float,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Query RDAP for one domain, fail-soft. Never raises."""
    # _rdap_urls always yields at least the rdap.org fallback, so the loop below
    # always runs and always overwrites this. It is a defensive initializer, not
    # a reachable outcome -- do not document it as a status an operator can see.
    last_reason = "rdap_unavailable"
    for url in _rdap_urls(domain, services):
        try:
            payload = _get_json(url, timeout, deadline=deadline)
        except safe_http.UnsafeTargetError as exc:
            LOG.warning("ownership: RDAP target rejected for %s: %s", domain, exc)
            last_reason = "rdap_blocked_target"
            continue
        except SAFE_HTTP_ERRORS as exc:
            LOG.warning("ownership: RDAP lookup failed for %s: %s", domain, exc)
            last_reason = "rdap_unavailable"
            continue
        if payload is None:
            last_reason = "rdap_not_found"
            continue
        if not isinstance(payload, dict):
            last_reason = "rdap_unavailable"
            continue
        return _parse_rdap_domain(payload)
    return _no_answer(last_reason)


def _identifiers(records: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Owner identifiers with their source and fixed weight (input to M2).

    ASN-org and certificate ``O=`` identifiers named in the design document
    come from stages M1 does not own yet; they are added when those stages land.
    """
    seen: set[tuple[str, str]] = set()
    identifiers: list[dict[str, Any]] = []
    for domain in sorted(records):
        record = records[domain]
        for kind in ("org_name", "registrar", "abuse_email"):
            value = record.get(kind)
            if not value or (kind, value) in seen:
                continue
            seen.add((kind, value))
            identifiers.append(
                {
                    "kind": kind,
                    "value": value,
                    "source": "rdap_domain",
                    "domain": domain,
                    "confidence": _CONFIDENCE[kind],
                }
            )
    return identifiers


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / "ownership.json", result)
    lines: list[str] = []
    for domain, record in (result.get("domains") or {}).items():
        lines.append(
            f"{domain}:{record['status']}:registrant={record['registrant_status']}"
            f":registrar={record['registrar'] or '-'}"
        )
    write_lines(output_dir / "ownership_findings.txt", lines)


def resolve_ownership(
    domains: list[str],
    config: OwnershipConfig,
    output_dir: Path,
    state_dir: Path,
) -> dict[str, Any]:
    """Resolve RDAP ownership for the seed domains, capped at max_domains."""
    result: dict[str, Any] = {
        "seed_domains": [],
        "domains": {},
        "identifiers": [],
        "truncated": False,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "ownership.disabled"
        _persist(output_dir, result)
        return result

    seeds = [d.strip().lower().rstrip(".") for d in (config.domains or domains) if d.strip()]
    seeds = sorted(set(seeds))
    if not seeds:
        result["skipped_reason"] = "no_domains"
        _persist(output_dir, result)
        return result

    truncated = False
    if len(seeds) > config.max_domains:
        truncated = True
        LOG.warning(
            "ownership: %d seed domain(s) exceed max_domains=%s; raise "
            "org_profile.ownership.max_domains if this is intentional",
            len(seeds),
            config.max_domains,
        )
        seeds = seeds[: config.max_domains]
    result["seed_domains"] = seeds

    timeout = float(config.timeout_seconds)
    deadline = time.perf_counter() + float(config.deadline_seconds)
    services = _load_bootstrap(state_dir, min(timeout, float(config.deadline_seconds)))

    records: dict[str, dict[str, Any]] = {}
    for domain in seeds:
        if time.perf_counter() >= deadline:
            truncated = True
            LOG.warning(
                "ownership: stage deadline of %ss reached after %d/%d domain(s); raise "
                "org_profile.ownership.deadline_seconds if this is intentional",
                config.deadline_seconds,
                len(records),
                len(seeds),
            )
            break
        records[domain] = _lookup_domain(domain, services, timeout, deadline)

    result["domains"] = records
    result["identifiers"] = _identifiers(records)
    result["truncated"] = truncated
    _persist(output_dir, result)
    LOG.info(
        "ownership: %d/%d domain(s) resolved via RDAP -> %d identifier(s)%s",
        sum(1 for record in records.values() if record["status"] == "ok"),
        len(seeds),
        len(result["identifiers"]),
        " [truncated]" if truncated else "",
    )
    return result
