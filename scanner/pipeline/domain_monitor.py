"""Typosquat / domain monitoring (Phase 8.4).

Two independent, opt-in, findings-only sub-checks:

1. Typosquat / look-alike domains: generate look-alike candidates of the
   org's seed domains (omission, adjacent transposition, keyboard-adjacent
   substitution, doubling/de-doubling, homoglyph substitution, TLD swap; the
   Public Suffix List decides what is label and what is suffix, so for
   ``bbc.co.uk`` only ``bbc`` is mutated and ``co.uk`` is swapped whole),
   DNS-resolve them (A/AAAA only), and report the ones that resolve as
   findings. A candidate that resolves means *someone* has registered it --
   these domains are never owned by the org and are never merged into scan
   scope. Resolution is passive DNS only (a single A/AAAA lookup per
   candidate) -- same risk class as ct.brute_force's DNS brute force: no
   traffic reaches the candidate domain's actual owner/registrant beyond an
   ordinary DNS query.

2. Dangling CNAME / subdomain takeover: for the org's own already-in-scope
   FQDNs (scope_fqdns), resolve the CNAME chain with its addresses and DNS
   status, look the chain up in the takeover catalogue (``takeover.py``) and
   report one of:

   - ``subdomain_takeover``, ``confidence: confirmed``: the service's own
     unclaimed-resource signal was observed -- NXDOMAIN of the target for a
     service whose resource names are claimable (Azure, Elastic Beanstalk),
     asked twice, and for App Service with no ``asuid`` verification record;
     or the provider's "nothing here" page for the org's name over HTTP(S).
     High for a ``vulnerable`` service, medium for an ``edge_case`` one;
   - ``subdomain_takeover``, ``confidence: heuristic``: the chain points at a
     claimable service and the name has no address, so nothing could be
     confirmed. Medium, or low for an ``edge_case`` service;
   - ``dangling_cname_nxdomain`` (high): the chain ends at an uncatalogued
     name that does not exist, and its registrable domain -- by the ICANN
     section of the Public Suffix List, under a TLD that exists and is not
     special-use -- does not exist either, twice: whoever registers that
     domain controls the org's name;
   - ``dangling_cname`` (low, heuristic): the chain ends at a non-existent
     name under a hosting platform's suffix (the PSL's private section) that
     the catalogue does not know -- whether a stranger can re-create it is
     exactly what is unknown.

   A chain into a ``not_vulnerable`` service, a live resource that answered
   without the fingerprint, an HTTP check that got no answer, a sinkholed or
   scope-denied address, and any name whose DNS answer was not a clean
   NOERROR/NXDOMAIN are not findings; they are listed under ``not_reported``
   with the reason, and unanswered names under ``dns_unanswered``.

The chain is resolved with two dnsx runs, ``-a`` and ``-aaaa``, and never
``-cname``. Measured on dnsx 1.2.3: ``-cname`` alone returns the first hop of
a chain and no addresses (so "no A/AAAA" held for every name and every match
was reported), and with several record types in one run ``status_code`` is the
rcode of the *last* query only -- ``-a -aaaa`` reports a name with an A record
as NXDOMAIN when its AAAA query said so, and hides an A NXDOMAIN behind an
AAAA NOERROR. So each type is asked on its own, an address from either means
the name resolves, and NXDOMAIN needs both. ``cname`` keeps the answer
section's order, which need not be the chain's; the chain is walked from the
name through the CNAME records in ``all``.

A resolver that answers NXDOMAIN for names it blocks (RPZ, filtering DNS)
makes a blocked provider look unclaimed. The repeat query catches a flapping
answer, not a consistent policy -- ``dns.resolvers`` should be a plain
recursive resolver for this stage.

ACTIVE PART: the HTTP confirmation is the only traffic here that is not a DNS
query -- one bounded GET per scheme to the org's own name, pinned to the
address just resolved, landing on the provider (``takeover.py`` has the
limits). ``takeover_http_confirm`` turns it off and the tenant scan policy's
``skip_service_probe`` does too; without it every resolving candidate is
listed as unconfirmed rather than guessed at. An address the approved scope
denies is never contacted (and is recorded with the run's other scope
refusals), nor is a sinkhole answer (0.0.0.0/8, 127.0.0.0/8, ::, ::1) or any
other non-public address -- a walled garden or split-horizon answer, where
the request would not reach the provider. Nothing is ever claimed or
registered.

Both sub-checks are findings-only and non-scope-expanding: a discovered
typosquat domain or a flagged dangling CNAME is reported for human review,
never merged into scan scope and never acted upon. Disabled by default
(discovery.domain_monitor.enabled = false).
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import takeover
from .config_schema import DomainMonitorConfig
from .dnsx import command as dnsx_command
from .dnsx import query as dnsx_query
from .public_suffix import has_icann_tld, is_special_use, registrable_domain
from .safe_http import is_public_address
from .utils import run_command, save_json, write_lines

LOG = logging.getLogger("shapoclyack.domain-monitor")

_KEYBOARD_ADJACENCY = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij",
    "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdz", "d": "serfx", "f": "drtgc",
    "g": "ftyhv", "h": "gyujb", "j": "hikun", "k": "jiolm", "l": "kop", "z": "asx",
    "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
_HOMOGLYPH_SUBS = (
    ("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("0", "o"), ("o", "0"),
    ("1", "l"), ("l", "1"), ("5", "s"), ("s", "5"),
)
_TLD_SWAP_LIST = ("com", "net", "org", "co", "io", "info", "biz", "cc", "xyz")

#: Where the takeover confirmation knocks, in order. HTTPS first because that
#: is what a visitor gets; plain HTTP only when HTTPS produced no fingerprint
#: match, since S3 website endpoints and several hosted-page products answer
#: the unclaimed page on one scheme only.
_TAKEOVER_HTTP_PORTS: tuple[tuple[str, int], ...] = (("https", 443), ("http", 80))


def _split_domain(domain: str) -> tuple[str, str]:
    """Split a seed into (registrable label, public suffix) by the Public
    Suffix List: "example.com" -> ("example", "com"), "bbc.co.uk" ->
    ("bbc", "co.uk"), "x.github.io" -> ("x", "github.io"). A subdomain seed
    is cut to its registrable domain first, so "shop.example.com.ru" ->
    ("example", "com.ru"): the generators then mutate the one label a
    squatter would register and never a dot or a suffix label.

    A name with no registrable domain (a public suffix itself, an IP literal,
    a bare label) keeps the old split at the last dot -- "co.uk" ->
    ("co", "uk") -- so such a seed still yields what it did before."""
    registrable = registrable_domain(domain)
    if registrable:
        label, _, suffix = registrable.partition(".")
        return label, suffix
    parts = domain.split(".")
    if len(parts) < 2:
        return domain, ""
    return ".".join(parts[:-1]), parts[-1]


def _omission_candidates(label: str, tld: str) -> list[str]:
    out = []
    for i in range(len(label)):
        new_label = label[:i] + label[i + 1 :]
        if new_label:
            out.append(f"{new_label}.{tld}")
    return out


def _transposition_candidates(label: str, tld: str) -> list[str]:
    out = []
    chars = list(label)
    for i in range(len(chars) - 1):
        swapped = chars.copy()
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        out.append(f"{''.join(swapped)}.{tld}")
    return out


def _keyboard_adjacent_candidates(label: str, tld: str) -> list[str]:
    out = []
    for i, ch in enumerate(label):
        for adj in _KEYBOARD_ADJACENCY.get(ch.lower(), ""):
            new_label = label[:i] + adj + label[i + 1 :]
            out.append(f"{new_label}.{tld}")
    return out


def _doubling_candidates(label: str, tld: str) -> list[str]:
    out = []
    for i, ch in enumerate(label):
        out.append(f"{label[:i] + ch + ch + label[i + 1:]}.{tld}")
    for i in range(len(label) - 1):
        if label[i] == label[i + 1]:
            new_label = label[:i] + label[i + 1 :]
            out.append(f"{new_label}.{tld}")
    return out


def _homoglyph_candidates(label: str, tld: str) -> list[str]:
    out = []
    for old, new in _HOMOGLYPH_SUBS:
        if old in label:
            out.append(f"{label.replace(old, new)}.{tld}")
    return out


def _tld_swap_candidates(label: str, tld: str) -> list[str]:
    """Replace the whole public suffix, never just its last label.

    ``tld`` is everything ``_split_domain`` put right of the label, so
    "bbc" + "co.uk" gives "bbc.com", "bbc.co", ... and not "bbc.co.com". A
    multi-label suffix also contributes its own TLD, first: "bbc.uk" for
    "co.uk", "example.ru" for "com.ru" -- the nearest look-alike of such a
    seed, and one the fixed list does not carry. For a private-section
    suffix the platform is swapped away too ("x.github.io" -> "x.io",
    "x.com"): the same name under a registry, not a neighbour on the
    platform, which the label mutations already cover."""
    swaps = list(_TLD_SWAP_LIST)
    if "." in tld:
        swaps.insert(0, tld.rsplit(".", 1)[1])
    return [f"{label}.{new_tld}" for new_tld in dict.fromkeys(swaps) if new_tld != tld]


def _round_robin(class_lists: list[list[str]]) -> list[str]:
    """Interleave several candidate-class lists round-robin (one from each
    class in turn, cycling back), deduping case-insensitively."""
    result: list[str] = []
    seen: set[str] = set()
    for item in itertools.chain.from_iterable(itertools.zip_longest(*class_lists)):
        if item is None:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _generate_typosquat_candidates(domain: str, max_candidates: int) -> list[str]:
    """Generate look-alike domain candidates for ``domain`` via six classes
    of typo/homoglyph generators, interleaved round-robin and capped at
    ``max_candidates``."""
    domain = domain.strip().lower().rstrip(".")
    label, tld = _split_domain(domain)
    if not label or not tld:
        return []

    class_lists = [
        _omission_candidates(label, tld),
        _transposition_candidates(label, tld),
        _keyboard_adjacent_candidates(label, tld),
        _doubling_candidates(label, tld),
        _homoglyph_candidates(label, tld),
        _tld_swap_candidates(label, tld),
    ]

    # The seed itself and, for a subdomain seed, its registrable domain: a
    # transposition of "bbc" is "bbc" again, and "www.bbc.co.uk" must not
    # report "bbc.co.uk" as somebody else's look-alike.
    own = {domain, f"{label}.{tld}"}
    candidates = _round_robin(class_lists)
    candidates = [c for c in candidates if c.lower() not in own]
    return candidates[:max_candidates]


def _run_dnsx_a_aaaa(
    domains: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
    resolvers: Sequence[str],
) -> dict[str, dict[str, list[str]]]:
    """Resolve A/AAAA records for a list of candidate domains via dnsx."""
    if not domains:
        return {}

    batch_dir = output_dir / "domain_monitor"
    batch_dir.mkdir(parents=True, exist_ok=True)
    targets_file = batch_dir / "typosquat_targets.txt"
    json_out = batch_dir / "typosquat_records.jsonl"
    write_lines(targets_file, sorted(set(domains)))

    run_command(
        dnsx_command(targets_file, ["-a", "-aaaa"], json_out, resolvers=resolvers),
        timeout=timeout,
        retries=retries,
    )

    mapping: dict[str, dict[str, list[str]]] = {}
    if not json_out.exists():
        return mapping
    for line in json_out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parsed = json.loads(line)
        host = (parsed.get("host") or "").strip().rstrip(".").lower()
        if not host:
            continue
        mapping[host] = {
            "a": parsed.get("a") or [],
            "aaaa": parsed.get("aaaa") or [],
        }
    return mapping


def _row_status(row: dict[str, Any] | None) -> str | None:
    """The rcode dnsx reported for one query type, or None when it wrote no row."""
    if row is None:
        return None
    return str(row.get("status_code") or "UNKNOWN").upper()


def _ordered_chain(host: str, row: dict[str, Any]) -> list[str]:
    """The CNAME chain of ``host`` in resolution order.

    dnsx lists ``cname`` -- and ``all`` -- in the order of the answer section,
    and a resolver may put the hops in any order (measured on dnsx 1.2.3 with a
    reversed answer). So the chain is walked from ``host`` through the CNAME
    records in ``all``; a row without ``all`` keeps ``cname`` as given.
    """
    links: dict[str, str] = {}
    for record in row.get("all") or []:
        fields = str(record).split()
        if len(fields) >= 5 and fields[3].upper() == "CNAME":
            links[fields[0].rstrip(".").lower()] = fields[4].rstrip(".").lower()
    chain: list[str] = []
    current = host
    while current in links and links[current] not in chain and links[current] != host:
        current = links[current]
        chain.append(current)
    if chain:
        return chain
    return [
        name
        for name in (str(hop).strip().rstrip(".").lower() for hop in row.get("cname") or [])
        if name
    ]


def _run_dnsx_cname(
    fqdns: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
    resolvers: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """CNAME chain, addresses and the rcode of each query type, per FQDN.

    Separate runs for ``-a`` and ``-aaaa``, never one with both and never
    ``-cname``: dnsx reports the rcode of the *last* query type it asked (see
    the module docstring). The AAAA run asks only the names the A run did not
    settle -- an IPv4 address already means the name resolves, and asking AAAA
    for every IPv4-only name again was half as many queries on top. Every name
    asked about is in the result; ``status`` holds None for a query type that
    produced no row (what a timeout looks like) and ``NOT_ASKED`` for an AAAA
    query that was not needed.
    """
    rows_a = dnsx_query(
        fqdns,
        output_dir,
        stage="domain_monitor",
        kind="cname",
        flags=["-a"],
        timeout=timeout,
        retries=retries,
        resolvers=resolvers,
    )
    # An A answer settles the name only with an address the confirmation could
    # use; a fake-IP or walled-garden A (198.18.0.0/15, RFC 1918) may sit next
    # to a real AAAA.
    unsettled = [
        fqdn
        for fqdn in fqdns
        if all(
            _undialable_reason(str(address)) is not None
            for address in (rows_a.get(fqdn) or {}).get("a") or []
        )
    ]
    rows_aaaa = dnsx_query(
        unsettled,
        output_dir,
        stage="domain_monitor",
        kind="cname_aaaa",
        flags=["-aaaa"],
        timeout=timeout,
        retries=retries,
        resolvers=resolvers,
    )
    records: dict[str, dict[str, Any]] = {}
    for fqdn in fqdns:
        row_a = rows_a.get(fqdn)
        row_aaaa = rows_aaaa.get(fqdn)
        chain = _ordered_chain(fqdn, row_a) if row_a is not None else []
        if not chain and row_aaaa is not None:
            chain = _ordered_chain(fqdn, row_aaaa)
        records[fqdn] = {
            "cname": chain,
            "a": list((row_a or {}).get("a") or []),
            "aaaa": list((row_aaaa or {}).get("aaaa") or []),
            "status": {
                "A": _row_status(row_a),
                "AAAA": _row_status(row_aaaa) if fqdn in unsettled else "NOT_ASKED",
            },
        }
    return records


def _run_dnsx_followup(
    names: list[str],
    output_dir: Path,
    *,
    kind: str,
    flags: list[str],
    timeout: int,
    retries: int,
    resolvers: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """One follow-up lookup: every name asked about, with its rcode and row."""
    rows = dnsx_query(
        names,
        output_dir,
        stage="domain_monitor",
        kind=kind,
        flags=flags,
        timeout=timeout,
        retries=retries,
        resolvers=resolvers,
    )
    return {name: {"status": _row_status(rows.get(name)), "row": rows.get(name) or {}} for name in names}


def _classify_typosquat(seed: str, candidate: str, record: dict) -> dict | None:
    a = record.get("a") or []
    aaaa = record.get("aaaa") or []
    if not a and not aaaa:
        return None
    return {
        "kind": "typosquat_registered",
        "seed": seed,
        "candidate": candidate,
        "a": a,
        "aaaa": aaaa,
    }


#: Answers a filtering resolver gives in place of the real address. The
#: confirmation GET is never sent to one: it would land on the sensor itself, or
#: nowhere, and say nothing about the provider.
_SINKHOLE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(network) for network in ("0.0.0.0/8", "127.0.0.0/8", "::/128", "::1/128")
)


#: not_reported reasons that leave a resolving takeover candidate undecided:
#: the fingerprint check did not run or got no answer. (``fingerprint_not_matched``
#: is an answer -- the provider served something else.)
_HTTP_UNDECIDED = frozenset({
    "http_inconclusive",
    "http_confirm_disabled",
    "http_target_cap",
    "sinkholed",
    "private_address",
    "address_refused_by_scope",
})

_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
#: Deprecated IPv6 site-local space (RFC 3879). ``ipaddress`` and therefore
#: ``safe_http.is_public_address`` call it global; it is not routed on the
#: internet, so for this gate it is private. safe_http's own rule is left as
#: is here -- the same gap there is a separate change.
_SITE_LOCAL = ipaddress.IPv6Network("fec0::/10")


def _undialable_reason(address: str) -> str | None:
    """Why the confirmation GET must not go to ``address``, or None when it may.

    ``sinkholed`` for what a blocking resolver answers; ``private_address``
    for anything else that is not public -- an RPZ walled garden, or a
    split-horizon view that maps the provider's name inside the network. In
    neither case would the request reach the provider, so it would prove
    nothing about the provider. Public means ``safe_http.is_public_address``,
    which also reads the IPv4 inside a NAT64 or IPv4-mapped IPv6 address.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "sinkholed"  # not an address at all: never dial it
    embedded = getattr(ip, "ipv4_mapped", None)
    if embedded is None and ip in _NAT64_WELL_KNOWN:
        embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    inner = embedded if embedded is not None else ip
    if any(inner.version == network.version and inner in network for network in _SINKHOLE_NETWORKS):
        return "sinkholed"
    if not is_public_address(ip) or ip in _SITE_LOCAL:
        return "private_address"
    return None


def _combined_status(addresses: Sequence[str], status: dict[str, Any]) -> str:
    """``NOERROR``, ``NXDOMAIN``, ``NO_ANSWER`` or ``INCONCLUSIVE`` for one name.

    An address from either query means the name resolves, whatever the other
    query said: some servers answer AAAA with NXDOMAIN for a name that has an A
    record (RFC 4074, section 4.2). NXDOMAIN needs both queries to say so.
    Anything else -- SERVFAIL, REFUSED, one query unanswered, the two
    disagreeing -- is not an answer this check can build a verdict on.
    """
    if addresses:
        return "NOERROR"
    statuses = {status.get("A"), status.get("AAAA")}
    if statuses == {"NXDOMAIN"}:
        return "NXDOMAIN"
    if statuses == {"NOERROR"}:
        return "NOERROR"
    if statuses == {None}:
        return "NO_ANSWER"
    return "INCONCLUSIVE"


def _severity(service_status: str, confidence: str) -> str:
    """vulnerable: high when confirmed, medium on a heuristic; edge_case one step lower."""
    if confidence == "confirmed":
        return "high" if service_status == "vulnerable" else "medium"
    return "medium" if service_status == "vulnerable" else "low"


@dataclass(frozen=True)
class _Candidate:
    """One in-scope name whose CNAME chain needs a verdict."""

    fqdn: str
    chain: tuple[str, ...]
    addresses: tuple[str, ...]
    dns_status: str
    #: The hop the verdict is about: the matched one, or the last for NXDOMAIN.
    target: str
    service: takeover.Service | None = None
    matched: str | None = None
    #: The rcode of the A and of the AAAA query (None: no answer).
    status_by_type: tuple[tuple[str, str | None], ...] = ()


@dataclass(frozen=True)
class _Verdict:
    """What the DNS answer alone decides about a candidate.

    ``action`` is ``finding`` (``finding`` is set), ``not_reported``
    (``reason`` is set), ``http`` (needs the fingerprint check),
    ``nxdomain_service`` (a catalogued service whose unclaimed signal is
    NXDOMAIN: needs the repeat query) or ``unknown_nxdomain`` (the chain ends
    at an uncatalogued name that does not exist).
    """

    action: str
    candidate: _Candidate
    finding: dict[str, Any] | None = None
    reason: str | None = None


@dataclass(frozen=True)
class _NxdomainPending:
    """A confirmation that rests on NXDOMAIN and waits for the repeat query."""

    candidate: _Candidate
    #: Every name whose NXDOMAIN the verdict needs, asked again.
    recheck: tuple[str, ...]
    registrable_domain: str | None = None


def _evidence(candidate: _Candidate, **overrides: Any) -> dict[str, Any]:
    """The evidence block every dangling-CNAME finding and non-finding carries."""
    service = candidate.service
    evidence: dict[str, Any] = {
        "cname_chain": list(candidate.chain),
        "dns_status": candidate.dns_status or None,
        "dns_status_by_type": dict(candidate.status_by_type),
        "addresses": list(candidate.addresses),
        "service_name": service.name if service else None,
        "service_status": service.status if service else None,
        "check": None,
        "fingerprint_id": None,
        "http_status": None,
        "http_scheme": None,
        "address": None,
        "attempts": [],
        "nxdomain_names": [],
        "registrable_domain": None,
        "recheck": {},
        "unconfirmed_reason": None,
    }
    evidence.update(overrides)
    return evidence


def _takeover_finding(
    candidate: _Candidate,
    service: takeover.Service,
    *,
    confidence: str,
    detail: str,
    **evidence: Any,
) -> dict[str, Any]:
    if service.status == "edge_case" and service.note:
        # The unclaimed signal is real; whether it can be claimed depends on this.
        detail = f"{detail}. Edge case: {service.note}"
    return {
        "kind": "subdomain_takeover",
        "confidence": confidence,
        "severity": _severity(service.status, confidence),
        "fqdn": candidate.fqdn,
        "cname_target": candidate.target,
        "matched_suffix": candidate.matched,
        "service": service.id,
        "detail": detail,
        "evidence": _evidence(candidate, **evidence),
    }


def _not_reported(candidate: _Candidate, reason: str, **evidence: Any) -> dict[str, Any]:
    return {
        "fqdn": candidate.fqdn,
        "cname_target": candidate.target,
        "service": candidate.service.id if candidate.service else None,
        "reason": reason,
        "evidence": _evidence(candidate, **evidence),
    }


def _classify_dangling_cname(
    fqdn: str, record: dict, catalogue: takeover.Catalogue
) -> _Verdict | None:
    """The verdict DNS alone can give, or None when there is nothing to judge."""
    chain = tuple(
        name
        for name in (str(hop).strip().rstrip(".").lower() for hop in record.get("cname") or [])
        if name
    )
    addresses = tuple(str(a) for a in (record.get("a") or []) + (record.get("aaaa") or []))
    by_type = record.get("status") or {}
    status_by_type = (("A", by_type.get("A")), ("AAAA", by_type.get("AAAA")))
    dns_status = _combined_status(addresses, by_type)
    target = chain[-1] if chain else fqdn

    def candidate_for(hop: str, matched: tuple[takeover.Service, str] | None = None) -> _Candidate:
        service, pattern = matched if matched is not None else (None, None)
        return _Candidate(fqdn, chain, addresses, dns_status, hop, service, pattern, status_by_type)

    if dns_status in ("NO_ANSWER", "INCONCLUSIVE"):
        # Whatever the chain reached before the answer broke off says whether
        # this was a takeover candidate left undecided, or just a name.
        reached = next(
            (
                (hop, matched)
                for hop in chain
                if (matched := catalogue.match(hop)) is not None and matched[0].claimable
            ),
            None,
        )
        candidate = candidate_for(*reached) if reached else candidate_for(target)
        reason = "dns_no_answer" if dns_status == "NO_ANSWER" else "dns_inconclusive"
        return _Verdict("not_reported", candidate, reason=reason)
    if not chain:
        return None

    if dns_status == "NXDOMAIN":
        # The resolver followed the chain to its end; NXDOMAIN is about the
        # last name in it, so that is the one whose owner matters.
        matched = catalogue.match(target)
        if matched is None:
            return _Verdict("unknown_nxdomain", candidate_for(target))
        service = matched[0]
        candidate = candidate_for(target, matched)
        if not service.claimable:
            return _Verdict("not_reported", candidate, reason="service_not_vulnerable")
        if service.nxdomain_required:
            return _Verdict("nxdomain_service", candidate)
        return _Verdict(
            "finding",
            candidate,
            finding=_takeover_finding(
                candidate,
                service,
                confidence="heuristic",
                detail=(
                    f"{fqdn} is a CNAME to {target} ({service.name}), which does not exist; "
                    "the provider page could not be checked"
                ),
                check="cname_pattern",
                nxdomain_names=[target],
                unconfirmed_reason="no_address",
            ),
        )

    for hop in chain:
        matched = catalogue.match(hop)
        if matched is not None:
            break
    else:
        return None
    service = matched[0]
    candidate = candidate_for(hop, matched)
    if not service.claimable:
        return _Verdict("not_reported", candidate, reason="service_not_vulnerable")
    if service.nxdomain_required:
        # The service's only unclaimed signal is NXDOMAIN, and this name
        # exists: the resource behind it is there.
        return _Verdict("not_reported", candidate, reason="target_exists")
    if not addresses:
        return _Verdict(
            "finding",
            candidate,
            finding=_takeover_finding(
                candidate,
                service,
                confidence="heuristic",
                detail=(
                    f"{fqdn} is a CNAME to {hop} ({service.name}) and has no address; "
                    "the provider page could not be checked"
                ),
                check="cname_pattern",
                unconfirmed_reason="no_address",
            ),
        )
    if not service.fingerprints:
        return _Verdict("not_reported", candidate, reason="no_fingerprint")
    return _Verdict("http", candidate)


def _confirm_over_http(
    candidates: list[_Candidate],
    config: DomainMonitorConfig,
    address_allowed: Callable[[str], bool] | None,
    findings: list[dict[str, Any]],
    not_reported: list[dict[str, Any]],
) -> tuple[int, bool]:
    """Fingerprint-check resolving candidates; return (probed, truncated)."""
    if not config.takeover_http_confirm:
        for candidate in candidates:
            not_reported.append(
                _not_reported(candidate, "http_confirm_disabled", unconfirmed_reason="http_confirm_disabled")
            )
        return 0, False

    cap = config.takeover_http_max_targets
    for candidate in candidates[cap:]:
        not_reported.append(
            _not_reported(candidate, "http_target_cap", unconfirmed_reason="http_target_cap")
        )
    probes: list[tuple[_Candidate, takeover.HttpProbe]] = []
    for candidate in candidates[:cap]:
        refusals = [_undialable_reason(address) for address in candidate.addresses]
        usable = [a for a, why in zip(candidate.addresses, refusals, strict=True) if why is None]
        if not usable:
            reason = "sinkholed" if "sinkholed" in refusals else "private_address"
            not_reported.append(_not_reported(candidate, reason, unconfirmed_reason=reason))
            continue
        address = next(
            (a for a in usable if address_allowed is None or address_allowed(a)),
            None,
        )
        if address is None:
            not_reported.append(
                _not_reported(
                    candidate, "address_refused_by_scope", unconfirmed_reason="address_refused_by_scope"
                )
            )
            continue
        fingerprints = candidate.service.fingerprints if candidate.service else ()
        probes.append((candidate, takeover.HttpProbe(candidate.fqdn, address, fingerprints)))

    outcomes = takeover.confirm_over_http(
        [probe for _, probe in probes],
        ports=_TAKEOVER_HTTP_PORTS,
        concurrency=config.takeover_http_concurrency,
        timeout_seconds=config.takeover_http_timeout_seconds,
    )
    for (candidate, probe), outcome in zip(probes, outcomes, strict=True):
        http_evidence = {
            "check": "http_fingerprint",
            "address": probe.address,
            "fingerprint_id": outcome["fingerprint_id"],
            "http_status": outcome["http_status"],
            "http_scheme": outcome["http_scheme"],
            "attempts": outcome["attempts"],
        }
        if outcome["outcome"] == "matched" and candidate.service is not None:
            findings.append(
                _takeover_finding(
                    candidate,
                    candidate.service,
                    confidence="confirmed",
                    detail=(
                        f"{candidate.fqdn} is a CNAME to {candidate.target} and "
                        f"{candidate.service.name} answers for it with its unclaimed-resource page "
                        f"({outcome['fingerprint_id']}, HTTP {outcome['http_status']} over "
                        f"{outcome['http_scheme']})"
                    ),
                    **http_evidence,
                )
            )
            continue
        # Either the provider served something else -- the resource is claimed --
        # or nothing answered. Neither is evidence of a takeover.
        reason = "fingerprint_not_matched" if outcome["outcome"] == "not_matched" else "http_inconclusive"
        not_reported.append(_not_reported(candidate, reason, unconfirmed_reason=reason, **http_evidence))
    return len(probes), len(candidates) > cap


def _followup_outcome(answer: dict[str, Any]) -> str:
    """``nxdomain``, ``noerror``, ``dns_no_answer`` or ``dns_inconclusive``.

    A follow-up lookup that timed out or erred decides nothing, and neither
    does an NXDOMAIN that came with an address: an answer contradicting
    itself is not the "does not exist" a takeover verdict rests on.
    """
    status = answer["status"]
    if status is None:
        return "dns_no_answer"
    if status == "NXDOMAIN":
        return "dns_inconclusive" if answer["row"].get("a") else "nxdomain"
    if status == "NOERROR":
        return "noerror"
    return "dns_inconclusive"


def _triage_unknown_nxdomain(
    candidates: list[_Candidate],
    findings: list[dict[str, Any]],
    not_reported: list[dict[str, Any]],
) -> list[tuple[_Candidate, str]]:
    """Sort uncatalogued NXDOMAIN ends; return those whose domain must be asked about.

    Only a name under a registry's suffix (the PSL's ICANN section, or a public
    registry's private-section block such as ``com.ru`` or ``uk.com``) and a
    delegated, non-special TLD has a registrable domain anybody could buy.
    Under any other private-section suffix the "registrable domain" is a
    hosting platform's tenant name, and whether the platform lets a stranger
    create it is exactly what is not known.
    """
    to_query: list[tuple[_Candidate, str]] = []
    for candidate in candidates:
        target = candidate.target
        if is_special_use(target) or not has_icann_tld(target):
            not_reported.append(_not_reported(candidate, "target_not_registrable", nxdomain_names=[target]))
            continue
        registry_domain = registrable_domain(target, registries_only=True)
        if not registry_domain:
            not_reported.append(_not_reported(candidate, "no_registrable_domain", nxdomain_names=[target]))
            continue
        platform_name = registrable_domain(target)
        if platform_name != registry_domain:
            findings.append(
                {
                    "kind": "dangling_cname",
                    "confidence": "heuristic",
                    "severity": "low",
                    "fqdn": candidate.fqdn,
                    "cname_target": target,
                    "matched_suffix": None,
                    "service": None,
                    "detail": (
                        f"{candidate.fqdn} points at {target}, a non-existent resource at a "
                        f"provider we don't know (under the hosting suffix of {registry_domain}); "
                        "check whether the name can be re-created"
                    ),
                    "evidence": _evidence(
                        candidate,
                        check="dns_nxdomain",
                        nxdomain_names=[target],
                        registrable_domain=registry_domain,
                        unconfirmed_reason="unknown_provider",
                    ),
                }
            )
            continue
        to_query.append((candidate, registry_domain))
    return to_query


def _check_dangling_cnames(
    fqdns: list[str],
    records: dict[str, dict[str, Any]],
    catalogue: takeover.Catalogue,
    config: DomainMonitorConfig,
    output_dir: Path,
    *,
    resolvers: Sequence[str],
    address_allowed: Callable[[str], bool] | None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    not_reported: list[dict[str, Any]] = []
    unanswered: list[str] = []
    #: Candidates whose follow-up lookup (registrable domain, asuid, repeat
    #: query) went unanswered: a takeover nobody could rule in or out.
    candidates_unanswered: list[str] = []
    http_candidates: list[_Candidate] = []
    service_nxdomain: list[_Candidate] = []
    unknown_nxdomain: list[_Candidate] = []
    for fqdn in fqdns:
        # A name the lookup wrapper did not return was not answered either.
        record = records.get(fqdn) or {}
        verdict = _classify_dangling_cname(fqdn, record, catalogue)
        if verdict is None:
            continue
        if verdict.finding is not None:
            findings.append(verdict.finding)
        elif verdict.reason is not None:
            not_reported.append(_not_reported(verdict.candidate, verdict.reason))
            if verdict.reason in ("dns_no_answer", "dns_inconclusive"):
                unanswered.append(fqdn)
                if verdict.candidate.service is not None:
                    # The chain reached a claimable service before the answer
                    # broke off: a takeover nobody could rule in or out.
                    candidates_unanswered.append(fqdn)
        elif verdict.action == "http":
            http_candidates.append(verdict.candidate)
        elif verdict.action == "nxdomain_service":
            service_nxdomain.append(verdict.candidate)
        else:
            unknown_nxdomain.append(verdict.candidate)

    probed, truncated = _confirm_over_http(
        http_candidates, config, address_allowed, findings, not_reported
    )

    pending: list[_NxdomainPending] = []
    to_query = _triage_unknown_nxdomain(unknown_nxdomain, findings, not_reported)
    if to_query:
        answers = _run_dnsx_followup(
            sorted({domain for _, domain in to_query}),
            output_dir,
            kind="registrable",
            flags=["-a"],
            timeout=config.timeout_seconds,
            retries=config.retries,
            resolvers=resolvers,
        )
        for candidate, domain in to_query:
            outcome = _followup_outcome(answers[domain])
            evidence = {"check": "dns_nxdomain", "nxdomain_names": [candidate.target], "registrable_domain": domain}
            if outcome == "nxdomain":
                pending.append(_NxdomainPending(candidate, (candidate.fqdn, domain), domain))
            elif outcome == "noerror":
                not_reported.append(_not_reported(candidate, "registrable_domain_exists", **evidence))
            else:
                not_reported.append(_not_reported(candidate, outcome, **evidence))
                candidates_unanswered.append(candidate.fqdn)

    # App Service lets a custom domain be bound only with the asuid TXT record
    # the owner created; with one in place a free app name is not a takeover.
    app_service = [c for c in service_nxdomain if c.service is not None and c.service.id == "azure_app_service"]
    verified: set[str] = set()
    if app_service:
        answers = _run_dnsx_followup(
            [f"asuid.{c.fqdn}" for c in app_service],
            output_dir,
            kind="asuid",
            flags=["-txt"],
            timeout=config.timeout_seconds,
            retries=config.retries,
            resolvers=resolvers,
        )
        for candidate in app_service:
            answer = answers[f"asuid.{candidate.fqdn}"]
            outcome = _followup_outcome(answer)
            if outcome == "noerror" and answer["row"].get("txt"):
                not_reported.append(_not_reported(candidate, "domain_verified", check="dns_txt_asuid"))
                verified.add(candidate.fqdn)
            elif outcome in ("dns_no_answer", "dns_inconclusive"):
                not_reported.append(_not_reported(candidate, outcome, check="dns_txt_asuid"))
                candidates_unanswered.append(candidate.fqdn)
                verified.add(candidate.fqdn)
            # NXDOMAIN, or NOERROR without a TXT record (NODATA): no verification.
    pending.extend(
        _NxdomainPending(candidate, (candidate.fqdn,))
        for candidate in service_nxdomain
        if candidate.fqdn not in verified
    )

    if pending:
        # One NXDOMAIN from one resolver is one answer; a verdict of "free to
        # register" has to survive being asked again.
        rechecked = _run_dnsx_followup(
            sorted({name for item in pending for name in item.recheck}),
            output_dir,
            kind="nxdomain_recheck",
            flags=["-a"],
            timeout=config.timeout_seconds,
            retries=config.retries,
            resolvers=resolvers,
        )
        for item in pending:
            recheck = {name: rechecked[name]["status"] for name in item.recheck}
            outcomes = {_followup_outcome(rechecked[name]) for name in item.recheck}
            is_finding, entry = _nxdomain_verdict(item, recheck, outcomes)
            (findings if is_finding else not_reported).append(entry)
            if entry.get("reason") in ("dns_no_answer", "dns_inconclusive"):
                candidates_unanswered.append(item.candidate.fqdn)

    return {
        "checked": len(fqdns),
        "catalogue_checked": catalogue.checked,
        "catalogue_services": len(catalogue.services),
        "http_confirm": config.takeover_http_confirm,
        "http_probed": probed,
        "truncated": truncated,
        "dns_unanswered": sorted(set(unanswered) | set(candidates_unanswered)),
        "candidates_unanswered": sorted(set(candidates_unanswered)),
        # Resolving candidates the HTTP check could not decide either way.
        "candidates_unconfirmed": sorted(
            {entry["fqdn"] for entry in not_reported if entry["reason"] in _HTTP_UNDECIDED}
        ),
        "findings": sorted(findings, key=lambda f: (f["fqdn"], f["kind"])),
        "not_reported": sorted(not_reported, key=lambda n: (n["fqdn"], n["reason"])),
    }


def _nxdomain_verdict(
    item: _NxdomainPending, recheck: dict[str, str | None], outcomes: set[str]
) -> tuple[bool, dict[str, Any]]:
    """(is_finding, entry) for one NXDOMAIN-backed confirmation after the repeat query."""
    candidate = item.candidate
    # The chain's end, and the registrable domain when the verdict rests on it too.
    names = list(dict.fromkeys([candidate.target, *item.recheck[1:]]))
    evidence = {
        "check": "dns_nxdomain",
        "nxdomain_names": names,
        "registrable_domain": item.registrable_domain,
        "recheck": recheck,
    }
    # A repeat query that got no usable answer says nothing either way; only a
    # name that came back existing is an NXDOMAIN that did not repeat.
    for unusable in ("dns_no_answer", "dns_inconclusive"):
        if unusable in outcomes:
            return False, _not_reported(candidate, unusable, unconfirmed_reason=unusable, **evidence)
    if outcomes != {"nxdomain"}:
        return False, _not_reported(
            candidate, "nxdomain_not_repeated", unconfirmed_reason="nxdomain_not_repeated", **evidence
        )
    service = candidate.service
    if service is not None:
        return True, _takeover_finding(
            candidate,
            service,
            confidence="confirmed",
            detail=(
                f"{candidate.fqdn} is a CNAME to {candidate.target} ({service.name}), which does "
                "not exist (NXDOMAIN on A and AAAA, and again when asked a second time); the "
                "resource name is free to create"
            ),
            **evidence,
        )
    domain = item.registrable_domain
    return True, {
        "kind": "dangling_cname_nxdomain",
        "confidence": "confirmed",
        "severity": "high",
        "fqdn": candidate.fqdn,
        "cname_target": candidate.target,
        "matched_suffix": None,
        "service": None,
        "detail": (
            f"{candidate.fqdn} is a CNAME to {candidate.target}, and {domain} does not exist "
            "(NXDOMAIN, twice): whoever registers it controls the name. A domain on registry "
            "hold answers NXDOMAIN too -- check RDAP before acting"
        ),
        "evidence": _evidence(candidate, **evidence),
    }


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / "domain_monitor.json", result)
    lines: list[str] = []
    typosquat = result.get("typosquat") or {}
    for finding in typosquat.get("findings") or []:
        ips = ",".join((finding.get("a") or []) + (finding.get("aaaa") or []))
        lines.append(f"typosquat:{finding['seed']}:{finding['candidate']}:{ips}")
    dangling = result.get("dangling_cname") or {}
    for finding in dangling.get("findings") or []:
        lines.append(
            f"{finding['kind']}:{finding['confidence']}:{finding['fqdn']}:{finding['cname_target']}"
        )
    write_lines(output_dir / "domain_monitor_findings.txt", lines)


def monitor_domains(
    domains: list[str],
    scope_fqdns: list[str],
    config: DomainMonitorConfig,
    output_dir: Path,
    *,
    resolvers: Sequence[str],
    address_allowed: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """Sync entry point: typosquat candidate resolution + dangling-CNAME /
    takeover check over the org's seed domains / in-scope FQDNs.

    ``address_allowed`` is the run's approved-scope deny filter; an address
    it refuses is never sent the takeover confirmation request.
    """
    result: dict[str, Any] = {
        "seed_domains": [],
        "typosquat": None,
        "dangling_cname": None,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "domain_monitor.disabled"
        _persist(output_dir, result)
        return result

    seeds = sorted({d.strip().lower().rstrip(".") for d in domains if d.strip()})
    if not seeds and not scope_fqdns:
        result["skipped_reason"] = "no_domains"
        _persist(output_dir, result)
        return result
    result["seed_domains"] = seeds

    if config.typosquat_enabled and seeds:
        candidate_seed_pairs: list[tuple[str, str]] = []
        all_candidates: list[str] = []
        for seed in seeds:
            candidates = _generate_typosquat_candidates(seed, config.max_candidates)
            all_candidates.extend(candidates)
            candidate_seed_pairs.extend((candidate, seed) for candidate in candidates)
        records = _run_dnsx_a_aaaa(
            all_candidates,
            output_dir,
            timeout=config.timeout_seconds,
            retries=config.retries,
            resolvers=resolvers,
        )
        findings = []
        for candidate, seed in candidate_seed_pairs:
            record = records.get(candidate.lower())
            if record is None:
                continue
            finding = _classify_typosquat(seed, candidate, record)
            if finding is not None:
                findings.append(finding)
        result["typosquat"] = {
            "candidates_checked": len(all_candidates),
            "findings": findings,
        }

    if config.dangling_cname_enabled and scope_fqdns:
        # Loaded before any lookup: a broken catalogue fails the run at once
        # (StageFailureError) instead of after a round of DNS.
        catalogue = takeover.load_catalogue()
        fqdns = sorted({f.strip().lower().rstrip(".") for f in scope_fqdns if f.strip()})
        records = _run_dnsx_cname(
            fqdns,
            output_dir,
            timeout=config.timeout_seconds,
            retries=config.retries,
            resolvers=resolvers,
        )
        result["dangling_cname"] = _check_dangling_cnames(
            fqdns,
            records,
            catalogue,
            config,
            output_dir,
            resolvers=resolvers,
            address_allowed=address_allowed,
        )

    _persist(output_dir, result)
    typosquat_count = len((result.get("typosquat") or {}).get("findings") or [])
    dangling = (result.get("dangling_cname") or {}).get("findings") or []
    LOG.info(
        "domain_monitor: %d seed domain(s) -> %d typosquat finding(s), "
        "%d dangling-CNAME finding(s) (%d confirmed)",
        len(seeds),
        typosquat_count,
        len(dangling),
        sum(1 for finding in dangling if finding.get("confidence") == "confirmed"),
    )
    return result
