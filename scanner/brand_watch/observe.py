"""DNS-only observation of brand-watch candidate names.

One name is asked about, never contacted. A and AAAA are separate dnsx runs,
and NS, SOA and MX are separate runs again: measured on dnsx 1.2.3, mixing
record types in one run reports the rcode of the last type only, so an A
that exists can be hidden behind an AAAA NXDOMAIN. This module does not open
HTTP, does not call nuclei, does not scan ports and does not brute paths.

Status hint, from the records that came back:

- ``resolving`` -- an A or AAAA answer;
- ``registered`` -- NS or SOA, and no address (a registered name with no A
  is not silence);
- ``unregistered`` -- every asked type came back NXDOMAIN;
- ``unanswered`` -- dnsx was missing, a run failed, or no row distinguished
  the name. The batch is not failed for that.

``mx_present`` is a bool. Mailbox contents are not stored. The resolver list
is the caller's (the tenant sensor's resolvers); this module does not bake
in a platform resolver of its own. dnsx still receives ``-r`` from
:func:`scanner.pipeline.dnsx.command`, which falls back to the sensor's own
resolvers only when the caller passed none.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from scanner.pipeline.dnsx import DnsxError, query as dnsx_query
from scanner.pipeline.lookalike import punycode_form

LOG = logging.getLogger("shapoclyack.brand-watch")

STAGE = "brand_watch"
MODE_DNS_ONLY = "dns_only"

#: A and AAAA stay apart. Address queries never share a run with NS/SOA/MX.
_ADDRESS_QUERIES: tuple[tuple[str, str], ...] = (("a", "-a"), ("aaaa", "-aaaa"))
#: NS, SOA and MX stay apart from each other and from the address queries.
_META_QUERIES: tuple[tuple[str, str], ...] = (("ns", "-ns"), ("soa", "-soa"), ("mx", "-mx"))

_UNANSWERED = "unanswered"
_REGISTERED = "registered"
_RESOLVING = "resolving"
_UNREGISTERED = "unregistered"


def _blank(name: str, *, status: str = _UNANSWERED, rcode: str | None = None) -> dict[str, Any]:
    text = name.strip().rstrip(".").lower()
    return {
        "unicode": text,
        "punycode": punycode_form(text) if text else "",
        "ns": [],
        "a": [],
        "aaaa": [],
        "mx_present": False,
        "rcode": rcode,
        "status": status,
    }


def _names(row: dict[str, Any] | None, key: str) -> list[str]:
    if not row:
        return []
    out: list[str] = []
    for value in row.get(key) or []:
        item = str(value).strip().rstrip(".").lower()
        if item and item not in out:
            out.append(item)
    return out


def _addresses(row: dict[str, Any] | None, key: str) -> list[str]:
    if not row:
        return []
    out: list[str] = []
    for value in row.get(key) or []:
        item = str(value).strip()
        if item and item not in out:
            out.append(item)
    return out


def _rcode(row: dict[str, Any] | None) -> str | None:
    if not row:
        return None
    raw = row.get("status_code")
    if raw is None or str(raw).strip() == "":
        return None
    return str(raw).strip().upper()


def _lookup(
    names: list[str],
    output_dir: Path,
    *,
    kind: str,
    flag: str,
    timeout: int,
    retries: int,
    resolvers: Sequence[str],
) -> dict[str, dict[str, Any]] | None:
    """One record type. None means this type was not answered (dnsx missing
    or the run failed); an empty dict means dnsx ran and wrote nothing."""
    if not names:
        return {}
    try:
        return dnsx_query(
            names,
            output_dir,
            stage=STAGE,
            kind=kind,
            flags=[flag],
            timeout=timeout,
            retries=retries,
            resolvers=resolvers,
        )
    except DnsxError as exc:
        LOG.warning("brand_watch: %s lookup unanswered (%s)", kind, exc)
        return None
    except FileNotFoundError as exc:
        LOG.warning("brand_watch: dnsx missing for %s (%s)", kind, exc)
        return None
    except OSError as exc:
        LOG.warning("brand_watch: %s lookup unanswered (%s)", kind, exc)
        return None


def _status(rcodes: dict[str, str | None], *, has_address: bool, has_ns_or_soa: bool) -> str:
    if has_address:
        return _RESOLVING
    if has_ns_or_soa:
        return _REGISTERED
    asked = [code for code in rcodes.values() if code is not None]
    if asked and all(code == "NXDOMAIN" for code in asked) and len(asked) == len(rcodes):
        return _UNREGISTERED
    return _UNANSWERED


def _summarise_rcode(rcodes: dict[str, str | None]) -> str | None:
    """One rcode for the row: the address rcode when it disagrees with
    silence, otherwise the first rcode that was actually written.

    A and AAAA are preferred so a name that resolves is not labelled with
    the MX NXDOMAIN that often sits beside a live A.
    """
    for key in ("a", "aaaa", "ns", "soa", "mx"):
        code = rcodes.get(key)
        if code is not None:
            return code
    return None


def observe_dns(
    names: Sequence[str],
    output_dir: Path,
    *,
    resolvers: Sequence[str],
    timeout: int = 30,
    retries: int = 0,
) -> list[dict[str, Any]]:
    """Observe ``names`` by DNS only and return one row per input name.

    Input order is kept. A blank name is skipped. The same name twice yields
    the same row twice (the lookup is batched, the result is not deduped
    against the caller's list). ``resolvers`` is passed through to every
    dnsx run; pass the tenant sensor's resolvers, not a platform default.

    Fail-soft: a missing dnsx, or a failed run, leaves the names that run
    would have answered as ``unanswered`` and does not raise.
    """
    ordered: list[str] = []
    for raw in names:
        text = str(raw).strip().rstrip(".").lower()
        if text:
            ordered.append(text)
    if not ordered:
        return []

    unique = list(dict.fromkeys(ordered))
    rows: dict[str, dict[str, Any] | None] = {}
    failed = False
    for kind, flag in _ADDRESS_QUERIES + _META_QUERIES:
        found = _lookup(
            unique,
            output_dir,
            kind=kind,
            flag=flag,
            timeout=timeout,
            retries=retries,
            resolvers=resolvers,
        )
        if found is None:
            failed = True
        rows[kind] = found

    results: list[dict[str, Any]] = []
    for name in ordered:
        if failed and all(found is None for found in rows.values()):
            results.append(_blank(name))
            continue
        per_type = {kind: (found or {}).get(name) for kind, found in rows.items()}
        rcodes = {kind: _rcode(row) for kind, row in per_type.items()}
        ns = _names(per_type["ns"], "ns")
        soa = per_type["soa"]
        has_soa = bool(soa) and (_rcode(soa) == "NOERROR" or bool(soa.get("soa")))
        addresses_a = _addresses(per_type["a"], "a")
        addresses_aaaa = _addresses(per_type["aaaa"], "aaaa")
        mx = _names(per_type["mx"], "mx")
        has_address = bool(addresses_a or addresses_aaaa)
        has_ns_or_soa = bool(ns) or has_soa
        results.append({
            "unicode": name,
            "punycode": punycode_form(name),
            "ns": ns,
            "a": addresses_a,
            "aaaa": addresses_aaaa,
            "mx_present": bool(mx),
            "rcode": _summarise_rcode(rcodes),
            "status": _status(rcodes, has_address=has_address, has_ns_or_soa=has_ns_or_soa),
        })
    return results
