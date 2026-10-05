"""Subdomain-takeover fingerprints: the catalogue and the HTTP confirmation.

``domain_monitor`` used to flag any in-scope name whose CNAME ended in one of
fourteen hard-coded suffixes. That cannot tell a live, correctly claimed
GitHub Pages site from an unclaimed one, and five of the fourteen services do
not allow a takeover at all. This module holds the two things that replace the
suffix list:

1. **The catalogue** (``takeover_fingerprints.json`` next to this file). One
   entry per service: the CNAME targets it hands out, whether an unclaimed
   resource shows as NXDOMAIN of that target or as a page the provider serves,
   the strings that page carries, and a status -- ``vulnerable``,
   ``edge_case`` (claimable only under conditions the note names) or
   ``not_vulnerable``. A ``not_vulnerable`` entry is kept on purpose: it is
   what stops a CNAME into CloudFront or Zendesk from being reported. Each
   entry names its sources and the date it was checked; the statuses are
   other people's research (``sources`` in the file), not something this
   scanner measured. The file lives beside the module rather than under
   ``scanner/data`` for the reason ``public_suffix.py`` gives: that directory
   is where the images mount the enrichment volume, which would hide it.

2. **The confirmation**: one bounded GET per scheme to the org's own name,
   pinned to the address the stage's own DNS lookup returned, with that name
   as both ``Host`` and TLS SNI -- the request a browser would send, landing
   on the provider's infrastructure. No redirect is followed, nothing is read
   past ``BODY_MAX_BYTES``, every attempt has a hard deadline, and the
   environment's proxy settings are ignored (a proxy would resolve the name
   again and the pin would mean nothing). TLS is not verified: an unclaimed
   resource is exactly the case where the provider has no certificate for the
   name. ``safe_http`` is deliberately not used -- it refuses private
   addresses, and an in-scope name on a split-horizon network legitimately
   resolves to one. The address is one the run already resolved for a name in
   the tenant's scope and port-scans anyway; ``domain_monitor`` additionally
   drops any address the approved scope denies.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import httpx

from .protocol import is_ipv6

LOG = logging.getLogger("shapoclyack.takeover")

CATALOGUE_PATH = Path(__file__).with_name("takeover_fingerprints.json")
SCHEMA_VERSION = 1
STATUSES = ("vulnerable", "edge_case", "not_vulnerable")

USER_AGENT = "shapoclyack/domain-monitor"
#: Error pages put their marker near the top; a large body is a live site.
BODY_MAX_BYTES = 64 * 1024

_ID_RE = re.compile(r"^[a-z0-9_]+$")
_FINGERPRINT_ID_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_SUFFIX_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
_SERVICE_KEYS = {
    "id", "name", "status", "cname", "cname_regex", "nxdomain_required",
    "fingerprints", "source", "checked", "note",
}
_REQUIRED_SERVICE_KEYS = _SERVICE_KEYS - {"cname_regex", "note"}
_FINGERPRINT_KEYS = {"id", "body", "header", "status"}


class CatalogueError(ValueError):
    """The takeover catalogue is malformed. A packaging error, not a scan result."""


@dataclass(frozen=True)
class Fingerprint:
    """What an unclaimed resource's response looks like. Every part must hold."""

    id: str
    #: Substrings of the decoded body, case-sensitive, all required.
    body: tuple[str, ...] = ()
    #: Substrings of the ``name: value`` header lines, case-insensitive, all required.
    header: tuple[str, ...] = ()
    #: Acceptable status codes; empty means any.
    status: tuple[int, ...] = ()

    def matches(self, status: int, headers: httpx.Headers, body: str) -> bool:
        if self.status and status not in self.status:
            return False
        if any(needle not in body for needle in self.body):
            return False
        if self.header:
            blob = "\n".join(f"{key}: {value}" for key, value in headers.multi_items()).lower()
            if any(needle.lower() not in blob for needle in self.header):
                return False
        return True


@dataclass(frozen=True)
class Service:
    id: str
    name: str
    status: str
    cname: tuple[str, ...]
    cname_regex: tuple[re.Pattern[str], ...]
    nxdomain_required: bool
    fingerprints: tuple[Fingerprint, ...]
    source: tuple[str, ...]
    checked: str
    note: str

    @property
    def claimable(self) -> bool:
        return self.status != "not_vulnerable"

    def match(self, name: str) -> str | None:
        """The suffix or pattern ``name`` matched, or None.

        A suffix matches at a label boundary only: ``github.io`` covers
        ``org.github.io`` and not ``evilgithub.io``.
        """
        for suffix in self.cname:
            if name == suffix or name.endswith("." + suffix):
                return suffix
        for pattern in self.cname_regex:
            if pattern.search(name):
                return pattern.pattern
        return None


@dataclass(frozen=True)
class Catalogue:
    checked: str
    services: tuple[Service, ...]

    def match(self, name: str) -> tuple[Service, str] | None:
        """The service whose CNAME target ``name`` is, with what matched."""
        normalized = (name or "").strip().rstrip(".").lower()
        if not normalized:
            return None
        for service in self.services:
            matched = service.match(normalized)
            if matched is not None:
                return service, matched
        return None


def _fail(where: str, problem: str) -> CatalogueError:
    return CatalogueError(f"takeover catalogue: {where}: {problem}")


def _string_list(value: Any, where: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise _fail(where, "must be a list of non-empty strings")
    if not allow_empty and not value:
        raise _fail(where, "must not be empty")
    return tuple(value)


def _iso_date(value: Any, where: str) -> str:
    try:
        date.fromisoformat(str(value))
    except ValueError:
        raise _fail(where, f"{value!r} is not a YYYY-MM-DD date") from None
    return str(value)


def _parse_fingerprint(raw: Any, where: str) -> Fingerprint:
    if not isinstance(raw, dict):
        raise _fail(where, "must be an object")
    unknown = set(raw) - _FINGERPRINT_KEYS
    if unknown:
        raise _fail(where, f"unknown key(s) {sorted(unknown)}")
    fingerprint_id = raw.get("id")
    if not isinstance(fingerprint_id, str) or not _FINGERPRINT_ID_RE.match(fingerprint_id):
        raise _fail(where, "id must look like '<service>.<name>'")
    body = _string_list(raw.get("body", []), f"{where}.body")
    header = _string_list(raw.get("header", []), f"{where}.header")
    statuses = raw.get("status", [])
    if not isinstance(statuses, list) or not all(
        isinstance(code, int) and 100 <= code <= 599 for code in statuses
    ):
        raise _fail(where, "status must be a list of HTTP status codes")
    # A status code alone is every 404 page on the internet.
    if not body and not header:
        raise _fail(where, "needs a body or header marker, not a status code alone")
    return Fingerprint(fingerprint_id, body, header, tuple(statuses))


def _parse_service(raw: Any, where: str, sources: dict[str, Any]) -> Service:
    if not isinstance(raw, dict):
        raise _fail(where, "must be an object")
    unknown = set(raw) - _SERVICE_KEYS
    if unknown:
        raise _fail(where, f"unknown key(s) {sorted(unknown)}")
    missing = _REQUIRED_SERVICE_KEYS - set(raw)
    if missing:
        raise _fail(where, f"missing key(s) {sorted(missing)}")
    service_id = raw["id"]
    if not isinstance(service_id, str) or not _ID_RE.match(service_id):
        raise _fail(where, "id must be lower-case letters, digits and '_'")
    where = f"service {service_id!r}"
    if not isinstance(raw["name"], str) or not raw["name"].strip():
        raise _fail(where, "name must be a non-empty string")
    if raw["status"] not in STATUSES:
        raise _fail(where, f"status must be one of {list(STATUSES)}")
    cname = _string_list(raw["cname"], f"{where}.cname")
    for suffix in cname:
        if not _SUFFIX_RE.match(suffix):
            raise _fail(where, f"cname {suffix!r} is not a lower-case domain suffix without a leading dot")
    patterns: list[re.Pattern[str]] = []
    for text in _string_list(raw.get("cname_regex", []), f"{where}.cname_regex"):
        if not text.endswith("$"):
            raise _fail(where, f"cname_regex {text!r} must be anchored at the end with '$'")
        try:
            patterns.append(re.compile(text))
        except re.error as exc:
            raise _fail(where, f"cname_regex {text!r} does not compile: {exc}") from None
    if not cname and not patterns:
        raise _fail(where, "needs at least one cname suffix or cname_regex")
    if not isinstance(raw["nxdomain_required"], bool):
        raise _fail(where, "nxdomain_required must be true or false")
    if not isinstance(raw["fingerprints"], list):
        raise _fail(where, "fingerprints must be a list")
    fingerprints = tuple(
        _parse_fingerprint(item, f"{where}.fingerprints[{index}]")
        for index, item in enumerate(raw["fingerprints"])
    )
    for fingerprint in fingerprints:
        if not fingerprint.id.startswith(f"{service_id}."):
            raise _fail(where, f"fingerprint {fingerprint.id!r} must start with '{service_id}.'")
    # One way of confirming per service, so a finding can say which one ran.
    if raw["nxdomain_required"] and fingerprints:
        raise _fail(where, "an NXDOMAIN service is confirmed by DNS and carries no HTTP fingerprints")
    if raw["status"] == "not_vulnerable" and fingerprints:
        raise _fail(where, "a not_vulnerable service is never probed, so it carries no fingerprints")
    source = _string_list(raw["source"], f"{where}.source", allow_empty=False)
    for source_id in source:
        if source_id not in sources:
            raise _fail(where, f"source {source_id!r} is not listed under 'sources'")
    note = raw.get("note", "")
    if not isinstance(note, str):
        raise _fail(where, "note must be a string")
    return Service(
        id=service_id,
        name=raw["name"],
        status=raw["status"],
        cname=cname,
        cname_regex=tuple(patterns),
        nxdomain_required=raw["nxdomain_required"],
        fingerprints=fingerprints,
        source=source,
        checked=_iso_date(raw["checked"], f"{where}.checked"),
        note=note,
    )


def parse_catalogue(raw: Any) -> Catalogue:
    """Validate one catalogue document and return it. Raises :class:`CatalogueError`."""
    if not isinstance(raw, dict):
        raise _fail("document", "must be an object")
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise _fail("document", f"schema_version must be {SCHEMA_VERSION}")
    checked = _iso_date(raw.get("checked"), "document.checked")
    sources = raw.get("sources")
    if not isinstance(sources, dict) or not sources or not all(
        isinstance(text, str) and text for text in sources.values()
    ):
        raise _fail("document", "sources must map source ids to descriptions")
    if not isinstance(raw.get("services"), list) or not raw["services"]:
        raise _fail("document", "services must be a non-empty list")

    services: list[Service] = []
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()
    owner_of_suffix: dict[str, str] = {}
    for index, item in enumerate(raw["services"]):
        service = _parse_service(item, f"services[{index}]", sources)
        if service.id in seen_ids:
            raise _fail(f"service {service.id!r}", "duplicate id")
        seen_ids.add(service.id)
        for fingerprint in service.fingerprints:
            if fingerprint.id in seen_fingerprints:
                raise _fail(f"service {service.id!r}", f"duplicate fingerprint id {fingerprint.id!r}")
            seen_fingerprints.add(fingerprint.id)
        # Two services claiming the same name would make the verdict depend on
        # file order. A suffix nested in another service's suffix is the same
        # ambiguity one label further down.
        for suffix in service.cname:
            for other_suffix, other_id in owner_of_suffix.items():
                if other_id == service.id:
                    continue
                if (
                    suffix == other_suffix
                    or suffix.endswith("." + other_suffix)
                    or other_suffix.endswith("." + suffix)
                ):
                    raise _fail(
                        f"service {service.id!r}",
                        f"cname {suffix!r} overlaps {other_suffix!r} of service {other_id!r}",
                    )
            owner_of_suffix[suffix] = service.id
        services.append(service)
    return Catalogue(checked=checked, services=tuple(services))


@functools.lru_cache(maxsize=1)
def load_catalogue(path: Path = CATALOGUE_PATH) -> Catalogue:
    """The shipped catalogue, validated once per process.

    A broken file raises, the way a truncated Public Suffix List does: it is
    a packaging error the schema test exists to catch, and reporting
    "nothing found" from a catalogue that did not load would be a lie.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CatalogueError(f"takeover catalogue {path} is unreadable: {exc}") from exc
    return parse_catalogue(raw)


# --- HTTP confirmation -------------------------------------------------------


@dataclass(frozen=True)
class HttpProbe:
    """One in-scope name to confirm, pinned to one address."""

    fqdn: str
    address: str
    fingerprints: tuple[Fingerprint, ...]


def _url(scheme: str, address: str, port: int) -> str:
    host = f"[{address}]" if is_ipv6(address) else address
    return f"{scheme}://{host}:{port}/"


async def _fetch(
    client: httpx.AsyncClient, scheme: str, address: str, port: int, fqdn: str, timeout: float
) -> tuple[int, httpx.Headers, str]:
    extensions = {"sni_hostname": fqdn} if scheme == "https" else {}
    async with client.stream(
        "GET",
        _url(scheme, address, port),
        headers={"Host": fqdn},
        extensions=extensions,
        timeout=timeout,
    ) as resp:
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= BODY_MAX_BYTES:
                break
        body = b"".join(chunks)[:BODY_MAX_BYTES].decode("utf-8", errors="ignore")
        return resp.status_code, resp.headers, body


async def _confirm_one(
    client: httpx.AsyncClient,
    probe: HttpProbe,
    ports: Sequence[tuple[str, int]],
    timeout: float,
) -> dict[str, Any]:
    """Try each scheme in turn and stop at the first fingerprint match.

    ``outcome`` is ``matched``, ``not_matched`` (the provider answered with
    something else: the resource is claimed, or at least not the unclaimed
    page) or ``inconclusive`` (no scheme produced a response at all).
    """
    attempts: list[dict[str, Any]] = []
    answered = False
    for scheme, port in ports:
        attempt: dict[str, Any] = {"scheme": scheme, "port": port, "http_status": None, "error": None}
        attempts.append(attempt)
        try:
            # httpx's timeout is per read, so a server dripping one byte at a
            # time would never trip it; the deadline covers the whole exchange.
            status, headers, body = await asyncio.wait_for(
                _fetch(client, scheme, probe.address, port, probe.fqdn, timeout), timeout
            )
        except (httpx.HTTPError, TimeoutError) as exc:
            attempt["error"] = type(exc).__name__
            LOG.debug("takeover: %s via %s:%s failed: %s", probe.fqdn, scheme, port, exc)
            continue
        answered = True
        attempt["http_status"] = status
        for fingerprint in probe.fingerprints:
            if fingerprint.matches(status, headers, body):
                return {
                    "outcome": "matched",
                    "fingerprint_id": fingerprint.id,
                    "http_status": status,
                    "http_scheme": scheme,
                    "attempts": attempts,
                }
    return {
        "outcome": "not_matched" if answered else "inconclusive",
        "fingerprint_id": None,
        "http_status": next(
            (a["http_status"] for a in attempts if a["http_status"] is not None), None
        ),
        "http_scheme": None,
        "attempts": attempts,
    }


async def _confirm_all(
    probes: Sequence[HttpProbe],
    ports: Sequence[tuple[str, int]],
    concurrency: int,
    timeout: float,
) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        verify=False,
        follow_redirects=False,
        trust_env=False,
    ) as client:

        async def _guarded(probe: HttpProbe) -> dict[str, Any]:
            async with semaphore:
                return await _confirm_one(client, probe, ports, timeout)

        return list(await asyncio.gather(*(_guarded(probe) for probe in probes)))


def confirm_over_http(
    probes: Sequence[HttpProbe],
    *,
    ports: Sequence[tuple[str, int]],
    concurrency: int,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    """Sync entry point: one outcome per probe, in the order given."""
    if not probes:
        return []
    return asyncio.run(_confirm_all(probes, ports, concurrency, float(timeout_seconds)))
