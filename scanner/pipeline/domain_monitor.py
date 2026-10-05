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

   - ``subdomain_takeover``, ``confidence: confirmed`` (high): the service's
     own unclaimed-resource signal was observed -- NXDOMAIN of the target for
     a service whose resource names are claimable (Azure, Elastic Beanstalk),
     or the provider's "nothing here" page for the org's name over HTTP(S);
   - ``subdomain_takeover``, ``confidence: heuristic`` (medium): the chain
     points at a claimable service and the name has no address, so nothing
     could be confirmed -- the check this module always made;
   - ``dangling_cname_nxdomain`` (high): the chain ends at a name that does
     not exist, on no catalogued service, and its registrable domain (Public
     Suffix List) does not exist either -- whoever registers that domain
     controls the org's name.

   A chain into a ``not_vulnerable`` service, a live resource that answered
   without the fingerprint, and an HTTP check that got no answer are not
   findings; they are listed under ``not_reported`` with the reason.

The lookup is ``-a -aaaa`` and never ``-cname``: measured on dnsx 1.2.3,
``-cname`` alone returns the first hop of a chain and no addresses (so "no
A/AAAA" held for every name and every match was reported), and adding it to
``-a`` overwrites the NXDOMAIN of the A query with the CNAME query's NOERROR.
An A query returns the whole chain, the addresses and the status of the last
name in it.

ACTIVE PART: the HTTP confirmation is the only traffic here that is not a DNS
query -- one bounded GET per scheme to the org's own name, pinned to the
address just resolved, landing on the provider (``takeover.py`` has the
limits). ``takeover_http_confirm`` turns it off and the tenant scan policy's
``skip_service_probe`` does too; without it every resolving candidate is
listed as unconfirmed rather than guessed at. An address the approved scope
denies is never contacted. Nothing is ever claimed or registered.

Both sub-checks are findings-only and non-scope-expanding: a discovered
typosquat domain or a flagged dangling CNAME is reported for human review,
never merged into scan scope and never acted upon. Disabled by default
(discovery.domain_monitor.enabled = false).
"""

from __future__ import annotations

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
from .public_suffix import registrable_domain
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


def _run_dnsx_cname(
    fqdns: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
    resolvers: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """Resolve CNAME chains, addresses and DNS status for the org's own FQDNs.

    ``-a -aaaa`` on purpose, never ``-cname`` -- see the module docstring.
    """
    records = dnsx_query(
        fqdns,
        output_dir,
        stage="domain_monitor",
        kind="cname",
        flags=["-a", "-aaaa"],
        timeout=timeout,
        retries=retries,
        resolvers=resolvers,
    )
    return {
        host: {
            "cname": parsed.get("cname") or [],
            "a": parsed.get("a") or [],
            "aaaa": parsed.get("aaaa") or [],
            "status_code": str(parsed.get("status_code") or "").upper(),
        }
        for host, parsed in records.items()
    }


def _run_dnsx_registrable(
    domains: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
    resolvers: Sequence[str],
) -> dict[str, str]:
    """DNS status of each registrable domain a dangling chain ended under."""
    records = dnsx_query(
        domains,
        output_dir,
        stage="domain_monitor",
        kind="registrable",
        flags=["-a"],
        timeout=timeout,
        retries=retries,
        resolvers=resolvers,
    )
    return {host: str(parsed.get("status_code") or "").upper() for host, parsed in records.items()}


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


@dataclass(frozen=True)
class _Verdict:
    """What the DNS answer alone decides about a candidate.

    ``action`` is ``finding`` (``finding`` is set), ``not_reported``
    (``reason`` is set), ``http`` (needs the fingerprint check) or
    ``registrable`` (needs the NXDOMAIN check of the target's domain).
    """

    action: str
    candidate: _Candidate
    finding: dict[str, Any] | None = None
    reason: str | None = None


def _evidence(candidate: _Candidate, **overrides: Any) -> dict[str, Any]:
    """The evidence block every dangling-CNAME finding and non-finding carries."""
    service = candidate.service
    evidence: dict[str, Any] = {
        "cname_chain": list(candidate.chain),
        "dns_status": candidate.dns_status or None,
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
        "severity": "high" if confidence == "confirmed" else "medium",
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
    if not chain:
        return None
    addresses = tuple(str(a) for a in (record.get("a") or []) + (record.get("aaaa") or []))
    dns_status = str(record.get("status_code") or "").upper()

    if dns_status == "NXDOMAIN":
        # The resolver followed the chain to its end; NXDOMAIN is about the
        # last name in it, so that is the one whose owner matters.
        target = chain[-1]
        matched = catalogue.match(target)
        if matched is None:
            candidate = _Candidate(fqdn, chain, addresses, dns_status, target)
            return _Verdict("registrable", candidate)
        service, pattern = matched
        candidate = _Candidate(fqdn, chain, addresses, dns_status, target, service, pattern)
        if not service.claimable:
            return _Verdict("not_reported", candidate, reason="service_not_vulnerable")
        if service.nxdomain_required:
            return _Verdict(
                "finding",
                candidate,
                finding=_takeover_finding(
                    candidate,
                    service,
                    confidence="confirmed",
                    detail=(
                        f"{fqdn} is a CNAME to {target} ({service.name}), which does not "
                        "exist; the resource name is free to create"
                    ),
                    check="dns_nxdomain",
                    nxdomain_names=[target],
                ),
            )
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
    service, pattern = matched
    candidate = _Candidate(fqdn, chain, addresses, dns_status, hop, service, pattern)
    if not service.claimable:
        return _Verdict("not_reported", candidate, reason="service_not_vulnerable")
    if service.nxdomain_required:
        # The service's only unclaimed signal is NXDOMAIN, and this name
        # exists: the resource behind it is there.
        return _Verdict(
            "not_reported",
            candidate,
            reason="target_exists" if dns_status == "NOERROR" else "dns_inconclusive",
        )
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
        address = next(
            (a for a in candidate.addresses if address_allowed is None or address_allowed(a)),
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


def _check_unregistered_targets(
    candidates: list[_Candidate],
    config: DomainMonitorConfig,
    output_dir: Path,
    resolvers: Sequence[str],
    findings: list[dict[str, Any]],
    not_reported: list[dict[str, Any]],
) -> None:
    """NXDOMAIN chains on no catalogued service: does the target's domain exist?"""
    registrable = {c.target: registrable_domain(c.target) for c in candidates}
    # A target that is itself a registrable domain already answered NXDOMAIN.
    to_query = sorted({domain for target, domain in registrable.items() if domain and domain != target})
    statuses = _run_dnsx_registrable(
        to_query,
        output_dir,
        timeout=config.timeout_seconds,
        retries=config.retries,
        resolvers=resolvers,
    )
    for candidate in candidates:
        domain = registrable[candidate.target]
        if not domain:
            not_reported.append(_not_reported(candidate, "no_registrable_domain"))
            continue
        status = "NXDOMAIN" if domain == candidate.target else statuses.get(domain)
        nxdomain_names = list(dict.fromkeys([candidate.target, domain]))
        if status == "NXDOMAIN":
            findings.append(
                {
                    "kind": "dangling_cname_nxdomain",
                    "confidence": "confirmed",
                    "severity": "high",
                    "fqdn": candidate.fqdn,
                    "cname_target": candidate.target,
                    "matched_suffix": None,
                    "service": None,
                    "detail": (
                        f"{candidate.fqdn} is a CNAME to {candidate.target}, and {domain} does "
                        "not exist (NXDOMAIN): whoever registers it controls the name. A "
                        "domain on registry hold answers NXDOMAIN too -- check RDAP before acting"
                    ),
                    "evidence": _evidence(
                        candidate,
                        check="dns_nxdomain",
                        nxdomain_names=nxdomain_names,
                        registrable_domain=domain,
                    ),
                }
            )
            continue
        reason = "registrable_domain_unanswered" if status is None else "registrable_domain_exists"
        not_reported.append(
            _not_reported(
                candidate,
                reason,
                check="dns_nxdomain",
                nxdomain_names=[candidate.target],
                registrable_domain=domain,
            )
        )


def _check_dangling_cnames(
    fqdns: list[str],
    records: dict[str, dict[str, Any]],
    config: DomainMonitorConfig,
    output_dir: Path,
    *,
    resolvers: Sequence[str],
    address_allowed: Callable[[str], bool] | None,
) -> dict[str, Any]:
    catalogue = takeover.load_catalogue()
    findings: list[dict[str, Any]] = []
    not_reported: list[dict[str, Any]] = []
    http_candidates: list[_Candidate] = []
    nxdomain_candidates: list[_Candidate] = []
    for fqdn in fqdns:
        record = records.get(fqdn)
        if record is None:
            continue
        verdict = _classify_dangling_cname(fqdn, record, catalogue)
        if verdict is None:
            continue
        if verdict.finding is not None:
            findings.append(verdict.finding)
        elif verdict.reason is not None:
            not_reported.append(_not_reported(verdict.candidate, verdict.reason))
        elif verdict.action == "http":
            http_candidates.append(verdict.candidate)
        else:
            nxdomain_candidates.append(verdict.candidate)

    probed, truncated = _confirm_over_http(
        http_candidates, config, address_allowed, findings, not_reported
    )
    if nxdomain_candidates:
        _check_unregistered_targets(
            nxdomain_candidates, config, output_dir, resolvers, findings, not_reported
        )
    return {
        "checked": len(fqdns),
        "catalogue_checked": catalogue.checked,
        "catalogue_services": len(catalogue.services),
        "http_confirm": config.takeover_http_confirm,
        "http_probed": probed,
        "truncated": truncated,
        "findings": sorted(findings, key=lambda f: (f["fqdn"], f["kind"])),
        "not_reported": sorted(not_reported, key=lambda n: (n["fqdn"], n["reason"])),
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
