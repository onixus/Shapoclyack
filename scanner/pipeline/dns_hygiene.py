"""Zone hygiene for the org's own domains (org_profile M2, EPIC #182).

Answers "is this zone put together properly" for every base domain in scope:
the nameserver set and how concentrated it is, delegations that point at names
that do not resolve, SOA sanity, DNSSEC delegation, CAA, a wildcard record
(which quietly invalidates every subdomain brute force the platform runs), and
-- opt-in only -- whether a nameserver will hand out the whole zone.

Everything except the AXFR probe is an ordinary DNS query through ``dnsx``,
the same risk class as ``domain_monitor.py``. It is findings-only: the stage
adds neither FQDNs nor IPs to scope, and M3's control matrix is what turns
these findings into a status.

AXFR is the exception and the only active check in the whole module. Three
gates, all mandatory:

1. **Config.** ``axfr_probe`` is ``false`` by default and lives only in the
   config file, i.e. it is a deployment decision. It is deliberately absent
   from ``EDITABLE_PATHS`` in ``api/services/config_override.py`` (those
   overrides are installation-wide, not per-tenant, so a platform admin would
   switch AXFR on for every tenant's scans at once) and equally absent from
   ``StartScanRequest`` (that would move the decision onto ``operator``, the
   role that starts a scan rather than the one that authorizes the target).
2. **Scope.** Only domains from this run's own seed/scope are probed, never an
   attribution candidate from M4: an active query against a wrongly attributed
   domain is an active query against somebody else's infrastructure.
3. **Address.** Every address of a nameserver must pass
   ``safe_http.is_public_address``. An NS record is written by the scanned
   party, so ``ns1.target.example -> 10.0.0.5`` would turn the probe into a
   TCP/53 connection inside the agent's own network.

And the transfer never reaches a log or an artifact. ``utils.run_command``
logs both the command line and the child's stdout into the run log, which
outlives the artifacts and is not a restricted class -- a successful transfer
would put the target's entire zone in ``scan.log``. The probe therefore drives
``subprocess`` directly, keeps the output in memory, and records only the fact
of the transfer and the number of records.

HONESTY about sources, per the module invariant of #182:

- **DNSSEC** is taken from the RDAP ``secureDNS.delegationSigned`` flag that
  M1 already wrote to ``ownership.json`` (``source: rdap_registry``), never
  from a resolver's ``AD`` bit -- ``AD`` is the resolver's opinion, not a
  validated chain. Without ``ownership.json`` the sub-check is ``not_checked``.
  ``ds_without_rrsig`` is **not** emitted: dnsx 1.2.3 has no DS/RRSIG flag and
  ``dnspython`` is not a dependency, so a broken chain cannot be told apart
  from an unsigned one here. Claiming it would be inventing a fact.
- **NS concentration** is not an ASN check. No ASN lookup happens in this
  stage; concentration is judged by the nameservers' parent domain and their
  address prefixes (``source: ns_parent_domain_and_ip_prefix``).

Absence of data never yields ``ok``: a domain nothing answered for is
``not_checked``, a domain whose lookups failed is ``error``.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import secrets
import subprocess
import time
from pathlib import Path
from typing import Any

from . import safe_http
from .config_schema import DnsHygieneConfig
from .dnsx import DnsxError, query as dnsx_query
from .utils import load_json, save_json, write_lines

LOG = logging.getLogger("shapoclyack.dns-hygiene")

STAGE = "dns_hygiene"

#: Both sets are written by the scanned party, so both are capped on this side.
#: Ten is already generous -- RFC 1912 recommends two to seven nameservers.
MAX_NS_PER_DOMAIN = 10
#: Fixed number of random labels used to detect a wildcard. Fixed, not a loop
#: "until we are sure": every extra label is another query against the target.
WILDCARD_PROBE_LABELS = 2

#: RFC 1912 section 2.2 recommended SOA timer ranges, in seconds.
_SOA_TIMER_RANGES = {
    "refresh": (1_200, 43_200),
    "retry": (120, 7_200),
    "expire": (1_209_600, 2_419_200),
    "minttl": (300, 86_400),
}

_CAA_RE = re.compile(r'^\s*(\d+)\s+([a-z0-9]+)\s+"?([^"]*)"?\s*$', re.IGNORECASE)


def _finding(kind: str, severity: str, domain: str, **extra: Any) -> dict[str, Any]:
    """One finding in the shape ``tls_posture.py`` uses (kind + severity)."""
    return {"kind": kind, "severity": severity, "domain": domain, **extra}


def _run_dnsx_ns(
    domains: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
) -> dict[str, dict[str, Any]]:
    """NS records for each domain."""
    return dnsx_query(
        domains, output_dir, stage=STAGE, kind="ns", flags=["-ns"], timeout=timeout, retries=retries
    )


def _run_dnsx_soa(
    domains: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
) -> dict[str, dict[str, Any]]:
    """SOA records for each domain."""
    return dnsx_query(
        domains,
        output_dir,
        stage=STAGE,
        kind="soa",
        flags=["-soa"],
        timeout=timeout,
        retries=retries,
    )


def _run_dnsx_caa(
    domains: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
) -> dict[str, dict[str, Any]]:
    """CAA records for each domain."""
    return dnsx_query(
        domains,
        output_dir,
        stage=STAGE,
        kind="caa",
        flags=["-caa"],
        timeout=timeout,
        retries=retries,
    )


def _run_dnsx_a_aaaa(
    names: list[str],
    output_dir: Path,
    *,
    kind: str,
    timeout: int,
    retries: int,
) -> dict[str, dict[str, Any]]:
    """A/AAAA for nameserver names and for the wildcard probe labels.

    ``kind`` keeps the two uses in separate target/output files -- the same
    reason ``domain_monitor.py`` gives its two dnsx runs separate names.
    """
    return dnsx_query(
        names,
        output_dir,
        stage=STAGE,
        kind=kind,
        flags=["-a", "-aaaa"],
        timeout=timeout,
        retries=retries,
    )


def _addresses(record: dict[str, Any]) -> list[str]:
    values = list(record.get("a") or []) + list(record.get("aaaa") or [])
    return [str(value).strip() for value in values if str(value).strip()]


def _names(record: dict[str, Any], key: str) -> list[str]:
    out: list[str] = []
    for value in record.get(key) or []:
        name = str(value).strip().rstrip(".").lower()
        if name and name not in out:
            out.append(name)
    return out


def _parse_soa(record: dict[str, Any]) -> dict[str, Any] | None:
    """The first SOA of a dnsx record, normalised.

    dnsx emits ``soa`` as a list of objects; older builds emit a plain string.
    Anything that is not an object carries no timers, so it is reported as a
    present-but-unparsed SOA rather than dropped.
    """
    entries = record.get("soa")
    if not isinstance(entries, list) or not entries:
        return None
    first = entries[0]
    if not isinstance(first, dict):
        return {"mname": str(first).strip().rstrip(".").lower() or None, "timers": {}}
    timers: dict[str, int] = {}
    for field in ("refresh", "retry", "expire", "minttl"):
        value = first.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            timers[field] = value
    mname = str(first.get("ns") or first.get("name") or "").strip().rstrip(".").lower()
    return {"mname": mname or None, "serial": first.get("serial"), "timers": timers}


def _parse_caa(record: dict[str, Any]) -> dict[str, Any]:
    """Split a CAA record set into issuers, wildcard issuers and iodef."""
    issuers: list[str] = []
    wildcard_issuers: list[str] = []
    iodef: list[str] = []
    entries = [str(value).strip() for value in record.get("caa") or [] if str(value).strip()]
    for entry in entries:
        match = _CAA_RE.match(entry)
        if not match:
            continue
        tag = match.group(2).lower()
        value = match.group(3).strip()
        if tag == "issue":
            issuers.append(value)
        elif tag == "issuewild":
            wildcard_issuers.append(value)
        elif tag == "iodef":
            iodef.append(value)
    return {
        "present": bool(entries),
        "issuers": issuers,
        "wildcard_issuers": wildcard_issuers,
        "iodef": iodef,
    }


def _ns_parent(nameserver: str) -> str:
    """The provider-ish parent of an NS name: ``ns1.a.example`` -> ``a.example``."""
    labels = nameserver.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else nameserver


def _address_group(address: str) -> str | None:
    """A coarse network the address belongs to (/24 for v4, /48 for v6)."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    prefix = 24 if parsed.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _classify_ns(
    domain: str,
    nameservers: list[str],
    ns_addresses: dict[str, list[str]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Nameserver concentration plus lame delegation.

    Concentration is judged by parent domain and address prefix, **not** by
    ASN: this stage performs no ASN lookup, and naming the weaker source is
    the point (see the module docstring).
    """
    findings: list[dict[str, Any]] = []
    if not nameservers:
        return (
            {"count": 0, "parents": [], "networks": [], "source": "ns_parent_domain_and_ip_prefix"},
            [_finding("ns_missing", "high", domain)],
        )

    parents = sorted({_ns_parent(ns) for ns in nameservers})
    networks = sorted(
        {
            group
            for ns in nameservers
            for group in (_address_group(addr) for addr in ns_addresses.get(ns, []))
            if group
        }
    )
    unresolved = sorted(ns for ns in nameservers if not ns_addresses.get(ns))

    # "One provider" is only claimable when every nameserver resolved: with a
    # half-resolved set a single network is an artefact of the missing half,
    # and that case is already reported as a lame delegation below.
    fully_resolved = bool(nameservers) and not unresolved
    if len(nameservers) == 1:
        findings.append(_finding("ns_single_point", "medium", domain, reason="single_ns"))
    elif len(parents) == 1 or (fully_resolved and len(networks) == 1):
        findings.append(
            _finding(
                "ns_single_point",
                "medium",
                domain,
                reason="single_provider",
                parents=parents,
                networks=networks,
            )
        )
    if unresolved:
        findings.append(
            _finding("ns_lame_delegation", "medium", domain, nameservers=unresolved)
        )

    return (
        {
            "count": len(nameservers),
            "parents": parents,
            "networks": networks,
            "unresolved": unresolved,
            "source": "ns_parent_domain_and_ip_prefix",
        },
        findings,
    )


def _classify_soa(
    domain: str, soa: dict[str, Any] | None, nameservers: list[str]
) -> list[dict[str, Any]]:
    if soa is None:
        return [_finding("soa_missing", "high", domain)]
    findings: list[dict[str, Any]] = []
    mname = soa.get("mname")
    if mname and nameservers and mname not in nameservers:
        findings.append(_finding("soa_mname_not_in_ns", "low", domain, mname=mname))
    out_of_range = {
        field: value
        for field, value in (soa.get("timers") or {}).items()
        if field in _SOA_TIMER_RANGES
        and not (_SOA_TIMER_RANGES[field][0] <= value <= _SOA_TIMER_RANGES[field][1])
    }
    if out_of_range:
        findings.append(
            _finding("soa_timers_out_of_range", "low", domain, timers=dict(sorted(out_of_range.items())))
        )
    return findings


def _classify_caa(domain: str, caa: dict[str, Any]) -> list[dict[str, Any]]:
    if not caa["present"]:
        return [_finding("caa_missing", "low", domain)]
    findings: list[dict[str, Any]] = []
    if caa["issuers"] and not caa["wildcard_issuers"]:
        # RFC 8659: with no issuewild, issuewild inherits issue -- every listed
        # CA may also mint wildcards. Narrowing that is a one-record change.
        findings.append(_finding("caa_wildcard_unrestricted", "low", domain))
    return findings


def _load_registry_dnssec(output_dir: Path) -> dict[str, Any]:
    """``domain -> RDAP record`` from M1's artifact, or empty when M1 was off.

    Cross-artifact read rather than a second DNSSEC probe: ``ownership.py``
    already asked the registry, and the registry's ``secureDNS`` flag is the
    only DNSSEC statement this module can make honestly.
    """
    payload = load_json(output_dir / "ownership.json", fallback=None)
    if not isinstance(payload, dict):
        return {}
    domains = payload.get("domains")
    return domains if isinstance(domains, dict) else {}


def _classify_dnssec(
    domain: str, ownership: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    record = ownership.get(domain)
    signed = record.get("dnssec") if isinstance(record, dict) else None
    if not isinstance(signed, bool):
        return (
            {
                "status": "not_checked",
                "delegation_signed": None,
                "source": None,
                "reason": "no_rdap_secure_dns",
            },
            [],
        )
    block = {
        "status": "ok" if signed else "absent",
        "delegation_signed": signed,
        "source": "rdap_registry",
        "reason": None,
    }
    findings = [] if signed else [_finding("dnssec_absent", "medium", domain, source="rdap_registry")]
    return block, findings


def _wildcard_probe_names(domain: str) -> list[str]:
    """``WILDCARD_PROBE_LABELS`` random labels under ``domain``."""
    return [f"{secrets.token_hex(8)}.{domain}" for _ in range(WILDCARD_PROBE_LABELS)]


def _classify_wildcard(
    domain: str, probes: list[str], records: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """A wildcard is claimed only when *every* probe resolved.

    One resolving label could be an unlucky collision with a real name; all of
    them resolving cannot be.
    """
    resolved = [name for name in probes if _addresses(records.get(name, {}))]
    present = bool(probes) and len(resolved) == len(probes)
    block = {"checked": bool(probes), "probes": len(probes), "present": present}
    findings = [_finding("wildcard_a_record", "medium", domain)] if present else []
    return block, findings


def _probe_axfr(
    domain: str,
    nameserver: str,
    addresses: list[str],
    *,
    timeout: int,
) -> dict[str, Any]:
    """Try one zone transfer against one nameserver. Never raises, never logs
    the zone.

    ``subprocess`` is driven directly instead of ``utils.run_command`` for one
    reason: ``run_command`` logs the child's stdout into the run log, and on a
    successful transfer that stdout *is* the target's entire zone. Nothing but
    the record count leaves this function, and no ``-o`` file is written, so
    the zone reaches neither ``scan.log`` nor the artifact directory.

    The nameserver is dialled by validated IP literal, so the address checked
    here is the address used -- the same pinning rule as ``safe_http``.
    """
    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for address in addresses:
        try:
            parsed.append(ipaddress.ip_address(address))
        except ValueError:
            continue
    if not parsed:
        return {"nameserver": nameserver, "status": "skipped", "reason": "ns_unresolved", "records": 0}
    rejected = [str(address) for address in parsed if not safe_http.is_public_address(address)]
    if rejected:
        LOG.warning(
            "dns_hygiene: refusing AXFR against %s for %s, non-public address(es) %s",
            nameserver,
            domain,
            ",".join(sorted(rejected)),
        )
        return {
            "nameserver": nameserver,
            "status": "refused",
            "reason": "ns_address_not_public",
            "records": 0,
        }

    resolver = str(parsed[0])
    try:
        completed = subprocess.run(
            ["dnsx", "-axfr", "-resolver", f"{resolver}:53", "-json", "-silent"],
            input=f"{domain}\n",
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        # Deliberately logs the exception type and not the output: a transfer
        # that partially succeeded before the timeout would otherwise print.
        LOG.warning(
            "dns_hygiene: AXFR probe against %s for %s failed: %s",
            nameserver,
            domain,
            type(exc).__name__,
        )
        return {"nameserver": nameserver, "status": "error", "reason": "probe_failed", "records": 0}

    records = _count_axfr_records(completed.stdout)
    if records <= 0:
        return {"nameserver": nameserver, "status": "closed", "reason": None, "records": 0}
    LOG.warning(
        "dns_hygiene: zone transfer succeeded for %s at %s (%d record(s))",
        domain,
        nameserver,
        records,
    )
    return {"nameserver": nameserver, "status": "open", "reason": None, "records": records}


def _count_axfr_records(stdout: str) -> int:
    """How many records a transfer returned. The records themselves are dropped.

    dnsx has changed the shape of its ``-axfr`` JSON between releases, so every
    list-valued field of the object is counted rather than one hard-coded key,
    and a non-JSON line counts as one record. The count is the only thing this
    module is allowed to keep, so it is worth being liberal about finding it.
    """
    total = 0
    for line in (stdout or "").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            total += 1
            continue
        if not isinstance(parsed, dict):
            total += 1
            continue
        counted = False
        for key in ("axfr", "all", "raw", "records"):
            value = parsed.get(key)
            if isinstance(value, list):
                total += len(value)
                counted = True
            elif isinstance(value, dict) and isinstance(value.get("records"), list):
                total += len(value["records"])
                counted = True
        if not counted:
            total += 1
    return total


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / f"{STAGE}.json", result)
    lines = [
        f"{finding['domain']}:{finding['kind']}:{finding['severity']}"
        for finding in result.get("findings") or []
    ]
    write_lines(output_dir / f"{STAGE}_findings.txt", lines)


def check_dns_hygiene(
    domains: list[str],
    config: DnsHygieneConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Zone hygiene for the seed domains, capped by max_domains/deadline."""
    result: dict[str, Any] = {
        "seed_domains": [],
        "domains": {},
        "findings": [],
        "axfr_probe": bool(config.axfr_probe),
        "truncated": False,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "dns_hygiene.disabled"
        _persist(output_dir, result)
        return result

    seeds = sorted({d.strip().lower().rstrip(".") for d in (config.domains or domains) if d.strip()})
    if not seeds:
        result["skipped_reason"] = "no_domains"
        _persist(output_dir, result)
        return result

    truncated = False
    if len(seeds) > config.max_domains:
        truncated = True
        LOG.warning(
            "dns_hygiene: %d seed domain(s) exceed max_domains=%s; raise "
            "org_profile.dns_hygiene.max_domains if this is intentional",
            len(seeds),
            config.max_domains,
        )
        seeds = seeds[: config.max_domains]
    result["seed_domains"] = seeds

    timeout = int(config.timeout_seconds)
    retries = int(config.retries)
    deadline = time.perf_counter() + float(config.deadline_seconds)

    try:
        ns_records = _run_dnsx_ns(seeds, output_dir, timeout=timeout, retries=retries)
        soa_records = _run_dnsx_soa(seeds, output_dir, timeout=timeout, retries=retries)
        caa_records = _run_dnsx_caa(seeds, output_dir, timeout=timeout, retries=retries)
    except DnsxError as exc:
        # Fail-soft: the control reports error, the run keeps going.
        LOG.warning("dns_hygiene: DNS lookups failed: %s", exc)
        result["skipped_reason"] = "dns_lookup_failed"
        result["domains"] = {
            domain: {"status": "error", "reason": "dns_lookup_failed"} for domain in seeds
        }
        _persist(output_dir, result)
        return result

    nameservers: dict[str, list[str]] = {}
    ns_truncated: set[str] = set()
    for domain in seeds:
        found = _names(ns_records.get(domain, {}), "ns")
        if len(found) > MAX_NS_PER_DOMAIN:
            ns_truncated.add(domain)
            truncated = True
            LOG.warning(
                "dns_hygiene: %s publishes %d nameservers, keeping MAX_NS_PER_DOMAIN=%d",
                domain,
                len(found),
                MAX_NS_PER_DOMAIN,
            )
            found = found[:MAX_NS_PER_DOMAIN]
        nameservers[domain] = found

    probe_names = {domain: _wildcard_probe_names(domain) for domain in seeds}
    try:
        ns_addresses_raw = _run_dnsx_a_aaaa(
            sorted({ns for names in nameservers.values() for ns in names}),
            output_dir,
            kind="ns_addresses",
            timeout=timeout,
            retries=retries,
        )
        wildcard_records = _run_dnsx_a_aaaa(
            sorted({name for names in probe_names.values() for name in names}),
            output_dir,
            kind="wildcard",
            timeout=timeout,
            retries=retries,
        )
    except DnsxError as exc:
        LOG.warning("dns_hygiene: address lookups failed: %s", exc)
        ns_addresses_raw = {}
        wildcard_records = {}

    ownership = _load_registry_dnssec(output_dir)
    findings: list[dict[str, Any]] = []
    records: dict[str, dict[str, Any]] = {}

    for domain in seeds:
        domain_findings: list[dict[str, Any]] = []
        ns_list = nameservers[domain]
        ns_addresses = {ns: _addresses(ns_addresses_raw.get(ns, {})) for ns in ns_list}
        ns_block, ns_findings = _classify_ns(domain, ns_list, ns_addresses)
        domain_findings.extend(ns_findings)

        soa = _parse_soa(soa_records.get(domain, {}))
        domain_findings.extend(_classify_soa(domain, soa, ns_list))

        caa = _parse_caa(caa_records.get(domain, {}))
        domain_findings.extend(_classify_caa(domain, caa))

        dnssec, dnssec_findings = _classify_dnssec(domain, ownership)
        domain_findings.extend(dnssec_findings)

        wildcard, wildcard_findings = _classify_wildcard(
            domain, probe_names[domain], wildcard_records
        )
        domain_findings.extend(wildcard_findings)

        axfr = _axfr_for_domain(domain, ns_list, ns_addresses, config, deadline)
        for probe in axfr["nameservers"]:
            if probe["status"] == "open":
                domain_findings.append(
                    _finding(
                        "axfr_open",
                        "critical",
                        domain,
                        nameserver=probe["nameserver"],
                        records=probe["records"],
                    )
                )

        answered = bool(ns_list) or soa is not None or caa["present"]
        records[domain] = {
            "status": "ok" if answered else "not_checked",
            "reason": None if answered else "no_dns_answer",
            "nameservers": ns_list,
            "nameservers_truncated": domain in ns_truncated,
            "ns_addresses": ns_addresses,
            "ns_diversity": ns_block,
            "soa": soa,
            "caa": caa,
            "dnssec": dnssec,
            "wildcard": wildcard,
            "axfr": axfr,
        }
        findings.extend(domain_findings)

    result["domains"] = records
    result["findings"] = findings
    result["truncated"] = truncated
    _persist(output_dir, result)
    LOG.info(
        "dns_hygiene: %d domain(s) checked -> %d finding(s)%s",
        len(seeds),
        len(findings),
        " [truncated]" if truncated else "",
    )
    return result


def _axfr_for_domain(
    domain: str,
    nameservers: list[str],
    ns_addresses: dict[str, list[str]],
    config: DnsHygieneConfig,
    deadline: float,
) -> dict[str, Any]:
    """The AXFR block for one domain, honouring the config gate and deadline."""
    if not config.axfr_probe:
        return {"status": "disabled", "reason": "axfr_probe.disabled", "nameservers": []}
    if not nameservers:
        return {"status": "not_checked", "reason": "no_nameservers", "nameservers": []}

    probes: list[dict[str, Any]] = []
    for nameserver in nameservers:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            LOG.warning(
                "dns_hygiene: stage deadline reached before probing %s for %s; raise "
                "org_profile.dns_hygiene.deadline_seconds if this is intentional",
                nameserver,
                domain,
            )
            probes.append(
                {
                    "nameserver": nameserver,
                    "status": "skipped",
                    "reason": "deadline_exceeded",
                    "records": 0,
                }
            )
            continue
        probes.append(
            _probe_axfr(
                domain,
                nameserver,
                ns_addresses.get(nameserver, []),
                timeout=int(min(float(config.axfr_timeout_seconds), remaining)) or 1,
            )
        )
    return {"status": "checked", "reason": None, "nameservers": probes}
