"""Mail authentication posture for the org's own domains (org_profile M2, #182).

Audits what the *target* publishes -- MX, SPF, DMARC, DKIM, MTA-STS and
TLS-RPT -- as opposed to ``alerts.py::check_dkim_record``, which is the
scanner checking its own sender before it notifies anybody. Findings-only:
nothing here expands scope, and M3's control matrix turns these findings into
the "Почтовая защита" status.

Every check is a DNS query through ``dnsx``. The single exception is the
MTA-STS policy document, and it is the reason this module touches
``safe_http.py`` at all:

``https://mta-sts.<domain>/.well-known/mta-sts.txt`` is fetched from a host
whose A record **the scanned party writes**, while the scanner frequently runs
as an agent inside the customer's own network. That is textbook SSRF from a
trusted network position, so the fetch goes through ``safe_http`` -- address
validated and pinned, HTTPS only, a 64 KiB body cap (a policy is a handful of
lines), and ``max_redirects=0`` because RFC 8461 section 3.3 requires that
policies are not fetched through a redirect: "HTTP 3xx redirects MUST NOT be
followed". ``httpx``/``urllib``/``requests`` are not used here.

``alerts.py::lookup_txt_records`` is deliberately **not** reused. It is a
DNS-over-HTTPS call on the run's notification path -- one lookup per run -- and
making it this module's hot path would put an unbounded read on a per-domain
loop. Mail posture resolves TXT with dnsx, like every other record type in M2.

Invariant of #182, and it matters most for DKIM: absence of data never yields
``ok``. DKIM selectors are arbitrary strings chosen by whoever set up signing,
so "none of the selectors we know about answered" is ``not_checked`` with a
reason -- it is **not** "this domain has no DKIM". Same rule as the "no
expectation, no finding" stance in ``cert_names.py``.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from . import safe_http
from .config_schema import MailPostureConfig
from .dnsx import DnsxError, query as dnsx_query
from .safe_http import SAFE_HTTP_ERRORS
from .utils import save_json, write_lines

LOG = logging.getLogger("shapoclyack.mail-posture")

STAGE = "mail_posture"

#: MX sets are written by the scanned party, so they are capped on this side.
MAX_MX_PER_DOMAIN = 10
#: RFC 7208 section 4.6.4 caps a policy evaluation at ten DNS-querying terms.
#: Enforced as a *stop*, not as a finding written after the fact: two domains
#: that ``include:`` each other would otherwise recurse forever.
SPF_MAX_LOOKUPS = 10
SPF_MAX_DEPTH = 10
#: Absolute ceiling on DKIM queries for the whole stage, independent of how
#: many domains and selectors are configured. Hundreds of base domains times a
#: handful of selectors is tens of thousands of queries -- self-DoS on the way
#: out and an abuse signal on the way in.
MAX_DKIM_QUERIES = 500
#: An MTA-STS policy is version/mode/mx/max_age -- a dozen lines. 64 KiB is
#: room to spare and still a bound.
MTA_STS_MAX_BYTES = 64 * 1024
MTA_STS_USER_AGENT = "shapoclyack/mail-posture"

#: Mechanisms and modifiers that cost a DNS lookup under RFC 7208.
_SPF_LOOKUP_TERMS = frozenset({"a", "mx", "ptr", "exists", "include"})
_ALL_QUALIFIERS = {"-": "-all", "~": "~all", "?": "?all", "+": "+all"}


def _finding(kind: str, severity: str, domain: str, **extra: Any) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "domain": domain, **extra}


def _run_dnsx_mx(
    domains: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
) -> dict[str, dict[str, Any]]:
    """MX records for each domain."""
    return dnsx_query(
        domains, output_dir, stage=STAGE, kind="mx", flags=["-mx"], timeout=timeout, retries=retries
    )


def _run_dnsx_txt(
    names: list[str],
    output_dir: Path,
    *,
    kind: str,
    timeout: int,
    retries: int,
) -> dict[str, dict[str, Any]]:
    """TXT records for a batch of names (policy names, DKIM selectors, SPF
    includes). ``kind`` keeps each batch in its own target/output file."""
    return dnsx_query(
        names, output_dir, stage=STAGE, kind=kind, flags=["-txt"], timeout=timeout, retries=retries
    )


def _txt_values(record: dict[str, Any]) -> list[str]:
    """TXT strings of one dnsx record, unquoted and whitespace-normalised."""
    values: list[str] = []
    for value in record.get("txt") or []:
        text = str(value).strip()
        if text.startswith('"') and text.endswith('"') and len(text) >= 2:
            text = text[1:-1]
        text = text.strip()
        if text:
            values.append(text)
    return values


def _mx_entries(record: dict[str, Any]) -> list[dict[str, Any]]:
    """MX entries as ``{preference, host}``.

    dnsx emits ``mx`` as ``"10 mail.example.com"`` strings; some builds emit
    objects. Both are accepted -- the shape of somebody else's JSON is not
    worth failing a control over.
    """
    entries: list[dict[str, Any]] = []
    for value in record.get("mx") or []:
        preference: int | None = None
        host = ""
        if isinstance(value, dict):
            host = str(value.get("host") or value.get("name") or "").strip()
            raw_preference = value.get("preference", value.get("pref"))
            if isinstance(raw_preference, int) and not isinstance(raw_preference, bool):
                preference = raw_preference
        else:
            parts = str(value).strip().split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                preference, host = int(parts[0]), parts[1].strip()
            else:
                host = str(value).strip()
        host = host.rstrip(".").lower() or "."
        entries.append({"preference": preference, "host": host})
    return entries


def _is_null_mx(entries: list[dict[str, Any]]) -> bool:
    """RFC 7505: exactly one MX, a zero preference and an empty target."""
    return len(entries) == 1 and entries[0]["host"] == "." and entries[0]["preference"] in (0, None)


def _spf_records(values: list[str]) -> list[str]:
    return [value for value in values if value.lower().startswith("v=spf1")]


def _spf_terms(record: str) -> list[str]:
    return record.split()[1:]


def _spf_term_name(term: str) -> tuple[str, str]:
    """``(name, value)`` of one SPF term, qualifier stripped."""
    body = term[1:] if term[:1] in _ALL_QUALIFIERS else term
    if "=" in body and ":" not in body.split("=", 1)[0]:
        name, _, value = body.partition("=")
    else:
        name, _, value = body.partition(":")
    return name.strip().lower(), value.strip().lower()


def _spf_all_qualifier(record: str) -> str | None:
    """The ``all`` mechanism of one record, e.g. ``-all``, or ``None``."""
    for term in _spf_terms(record):
        name, _ = _spf_term_name(term)
        if name == "all":
            return _ALL_QUALIFIERS.get(term[:1], "+all")
    return None


def _evaluate_spf(
    domain: str,
    record: str,
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
) -> dict[str, Any]:
    """Walk ``include:``/``redirect=`` and count the DNS-querying terms.

    Breadth-first with a visited set and a depth ceiling, so ``a.example
    include:b.example`` / ``b.example include:a.example`` terminates on the
    second visit instead of recursing. One dnsx batch per level, not per name.
    """
    visited = {domain}
    lookups = 0
    cycles: list[str] = []
    depth_reached = 0
    frontier = {domain: record}

    for depth in range(SPF_MAX_DEPTH):
        depth_reached = depth + 1
        next_names: list[str] = []
        for terms_owner, text in frontier.items():
            for term in _spf_terms(text):
                name, value = _spf_term_name(term)
                if name not in _SPF_LOOKUP_TERMS and name != "redirect":
                    continue
                lookups += 1
                if name not in ("include", "redirect") or not value:
                    continue
                if value in visited:
                    cycles.append(f"{terms_owner}->{value}")
                    continue
                visited.add(value)
                next_names.append(value)
        if not next_names or lookups > SPF_MAX_LOOKUPS:
            break
        try:
            records = _run_dnsx_txt(
                next_names, output_dir, kind="spf_include", timeout=timeout, retries=retries
            )
        except DnsxError as exc:
            LOG.warning("mail_posture: SPF include lookup failed for %s: %s", domain, exc)
            break
        frontier = {}
        for name in next_names:
            found = _spf_records(_txt_values(records.get(name, {})))
            if found:
                frontier[name] = found[0]
        if not frontier:
            break

    return {
        "lookups": lookups,
        "lookup_limit_exceeded": lookups > SPF_MAX_LOOKUPS,
        "depth": depth_reached,
        "depth_limit_reached": depth_reached >= SPF_MAX_DEPTH,
        "cycles": sorted(set(cycles)),
        "visited": sorted(visited),
    }


def _classify_spf(
    domain: str,
    records: list[str],
    evaluation: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not records:
        return (
            {"status": "missing", "records": [], "all": None, "ptr": False, "evaluation": None},
            [_finding("spf_missing", "high", domain)],
        )

    findings: list[dict[str, Any]] = []
    if len(records) > 1:
        # RFC 7208 section 4.5: more than one v=spf1 record is a permerror --
        # receivers stop evaluating, so the policy is effectively absent.
        findings.append(_finding("spf_multiple_records", "high", domain, count=len(records)))

    record = records[0]
    qualifier = _spf_all_qualifier(record)
    has_ptr = any(_spf_term_name(term)[0] == "ptr" for term in _spf_terms(record))
    if qualifier == "+all":
        findings.append(_finding("spf_all_permissive", "critical", domain, mechanism=qualifier))
    elif qualifier in ("?all", None):
        findings.append(
            _finding("spf_all_neutral", "medium", domain, mechanism=qualifier or "absent")
        )
    if has_ptr:
        findings.append(_finding("spf_ptr_mechanism", "low", domain))
    if evaluation and evaluation["lookup_limit_exceeded"]:
        findings.append(
            _finding(
                "spf_too_many_lookups",
                "medium",
                domain,
                lookups=evaluation["lookups"],
                limit=SPF_MAX_LOOKUPS,
            )
        )
    if evaluation and evaluation["cycles"]:
        findings.append(_finding("spf_include_cycle", "medium", domain, cycles=evaluation["cycles"]))

    return (
        {
            "status": "present",
            "records": records,
            "all": qualifier,
            "ptr": has_ptr,
            "evaluation": evaluation,
        },
        findings,
    )


def _parse_tag_value(text: str) -> dict[str, str]:
    """``v=DMARC1; p=none; pct=50`` -> ``{"v": "DMARC1", "p": "none", ...}``."""
    tags: dict[str, str] = {}
    for part in text.split(";"):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        name = key.strip().lower()
        if name:
            tags[name] = value.strip()
    return tags


def _classify_dmarc(
    domain: str, values: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    records = [value for value in values if value.lower().startswith("v=dmarc1")]
    if not records:
        return (
            {"status": "missing", "policy": None, "subdomain_policy": None, "pct": None, "rua": []},
            [_finding("dmarc_missing", "high", domain)],
        )

    findings: list[dict[str, Any]] = []
    if len(records) > 1:
        findings.append(_finding("dmarc_multiple_records", "medium", domain, count=len(records)))
    tags = _parse_tag_value(records[0])
    policy = (tags.get("p") or "").lower() or None
    subdomain_policy = (tags.get("sp") or "").lower() or None
    rua = [value.strip() for value in (tags.get("rua") or "").split(",") if value.strip()]
    pct: int | None = None
    raw_pct = tags.get("pct")
    if raw_pct and raw_pct.strip().isdigit():
        pct = int(raw_pct.strip())

    if policy == "none":
        findings.append(_finding("dmarc_policy_none", "high", domain, policy=policy))
    elif policy == "quarantine":
        findings.append(_finding("dmarc_policy_quarantine", "medium", domain, policy=policy))
    elif policy != "reject":
        findings.append(_finding("dmarc_policy_invalid", "high", domain, policy=policy or "absent"))
    if subdomain_policy == "none":
        findings.append(_finding("dmarc_subdomain_policy_none", "medium", domain))
    if pct is not None and pct < 100:
        findings.append(_finding("dmarc_pct_partial", "medium", domain, pct=pct))
    if not rua:
        findings.append(_finding("dmarc_no_rua", "low", domain))

    return (
        {
            "status": "present",
            "policy": policy,
            "subdomain_policy": subdomain_policy,
            "pct": pct,
            "rua": rua,
        },
        findings,
    )


def _classify_dkim(
    domain: str,
    selectors: list[str],
    records: dict[str, dict[str, Any]],
    *,
    queried: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """DKIM for one domain. Never reports "absent" -- see the module docstring."""
    if not queried:
        return (
            {"status": "not_checked", "reason": "selector_budget_exhausted", "selectors": {}},
            [],
        )

    found: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    for selector in selectors:
        values = [
            value
            for value in _txt_values(records.get(f"{selector}._domainkey.{domain}", {}))
            if "v=dkim1" in value.lower() or "p=" in value.lower()
        ]
        if not values:
            continue
        tags = _parse_tag_value(values[0])
        revoked = "p" in tags and not tags["p"].strip()
        found[selector] = {"revoked": revoked}
        if revoked:
            findings.append(_finding("dkim_key_revoked", "low", domain, selector=selector))
    if not found:
        # Selectors are arbitrary. "None of the ones we know about answered"
        # is not evidence that the domain does not sign its mail.
        return (
            {"status": "not_checked", "reason": "no_known_selector", "selectors": {}},
            [],
        )
    return ({"status": "present", "reason": None, "selectors": found}, findings)


def _fetch_mta_sts_policy(domain: str, timeout: float) -> dict[str, Any]:
    """Fetch and parse ``mta-sts.<domain>/.well-known/mta-sts.txt``. Never raises.

    ``max_redirects=0``: RFC 8461 section 3.3 states that HTTP 3xx redirects
    MUST NOT be followed when retrieving a policy, and a redirect here is also
    the exact primitive an SSRF would need.
    """
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        response = safe_http.get(
            url,
            timeout_seconds=timeout,
            max_bytes=MTA_STS_MAX_BYTES,
            headers={"Accept": "text/plain", "User-Agent": MTA_STS_USER_AGENT},
            max_redirects=0,
        )
    except safe_http.UnsafeTargetError as exc:
        LOG.warning("mail_posture: MTA-STS policy target rejected for %s: %s", domain, exc)
        return {"status": "error", "reason": "blocked_target", "mode": None}
    except SAFE_HTTP_ERRORS as exc:
        LOG.warning("mail_posture: MTA-STS policy fetch failed for %s: %s", domain, exc)
        return {"status": "error", "reason": "unreachable", "mode": None}

    if response.status != 200:
        return {"status": "error", "reason": f"http_{response.status}", "mode": None}
    if response.truncated:
        LOG.warning(
            "mail_posture: MTA-STS policy for %s exceeded MTA_STS_MAX_BYTES=%d",
            domain,
            MTA_STS_MAX_BYTES,
        )
        return {"status": "error", "reason": "policy_too_large", "mode": None, "truncated": True}

    mode: str | None = None
    for line in response.body.decode("utf-8", errors="replace").splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() == "mode":
            mode = value.strip().lower()
            break
    return {"status": "ok", "reason": None, "mode": mode, "truncated": False}


def _classify_mta_sts(
    domain: str, values: list[str], policy: dict[str, Any] | None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    announced = any(value.lower().startswith("v=stsv1") for value in values)
    if not announced:
        return (
            {"status": "missing", "policy": None},
            [_finding("mta_sts_missing", "low", domain)],
        )
    if policy is None:
        return ({"status": "announced", "policy": None}, [])
    findings: list[dict[str, Any]] = []
    if policy["status"] != "ok":
        findings.append(
            _finding("mta_sts_policy_unreachable", "medium", domain, reason=policy["reason"])
        )
    elif policy.get("mode") != "enforce":
        findings.append(
            _finding("mta_sts_mode_not_enforce", "low", domain, mode=policy.get("mode") or "absent")
        )
    return ({"status": "announced", "policy": policy}, findings)


def _classify_tls_rpt(domain: str, values: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    present = any(value.lower().startswith("v=tlsrptv1") for value in values)
    if present:
        return ({"status": "present"}, [])
    return ({"status": "missing"}, [_finding("tls_rpt_missing", "low", domain)])


def _classify_spoofable(
    domain: str, has_mx: bool, null_mx: bool, spf: dict[str, Any], dmarc: dict[str, Any]
) -> list[dict[str, Any]]:
    """A domain that receives no mail must still refuse to *send* it.

    Without ``SPF -all`` and ``DMARC p=reject`` a parked or infrastructure-only
    domain can be spoofed by anyone. Called out separately because it is the
    cheapest finding in the module to fix: two records, no mail flow to break.
    """
    if has_mx and not null_mx:
        return []
    if spf.get("all") == "-all" and dmarc.get("policy") == "reject":
        return []
    return [
        _finding(
            "no_mx_domain_spoofable",
            "high",
            domain,
            spf_all=spf.get("all") or "absent",
            dmarc_policy=dmarc.get("policy") or "absent",
            null_mx=null_mx,
        )
    ]


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / f"{STAGE}.json", result)
    lines = [
        f"{finding['domain']}:{finding['kind']}:{finding['severity']}"
        for finding in result.get("findings") or []
    ]
    write_lines(output_dir / f"{STAGE}_findings.txt", lines)


def check_mail_posture(
    domains: list[str],
    config: MailPostureConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Mail authentication posture for the seed domains."""
    result: dict[str, Any] = {
        "seed_domains": [],
        "domains": {},
        "findings": [],
        "truncated": False,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "mail_posture.disabled"
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
            "mail_posture: %d seed domain(s) exceed max_domains=%s; raise "
            "org_profile.mail_posture.max_domains if this is intentional",
            len(seeds),
            config.max_domains,
        )
        seeds = seeds[: config.max_domains]
    result["seed_domains"] = seeds

    timeout = int(config.timeout_seconds)
    retries = int(config.retries)
    deadline = time.perf_counter() + float(config.deadline_seconds)

    selectors = list(config.dkim_selectors)
    dkim_budget = MAX_DKIM_QUERIES // max(len(selectors), 1)
    dkim_domains = seeds[:dkim_budget]
    if len(dkim_domains) < len(seeds):
        truncated = True
        LOG.warning(
            "mail_posture: %d domain(s) x %d selector(s) exceed MAX_DKIM_QUERIES=%d; "
            "DKIM checked for the first %d domain(s), shorten "
            "org_profile.mail_posture.dkim_selectors to cover more",
            len(seeds),
            len(selectors),
            MAX_DKIM_QUERIES,
            len(dkim_domains),
        )

    policy_names = [
        name
        for domain in seeds
        for name in (domain, f"_dmarc.{domain}", f"_mta-sts.{domain}", f"_smtp._tls.{domain}")
    ]
    dkim_names = [
        f"{selector}._domainkey.{domain}" for domain in dkim_domains for selector in selectors
    ]

    try:
        mx_records = _run_dnsx_mx(seeds, output_dir, timeout=timeout, retries=retries)
        txt_records = _run_dnsx_txt(
            policy_names, output_dir, kind="policy", timeout=timeout, retries=retries
        )
    except DnsxError as exc:
        LOG.warning("mail_posture: DNS lookups failed: %s", exc)
        result["skipped_reason"] = "dns_lookup_failed"
        result["domains"] = {
            domain: {"status": "error", "reason": "dns_lookup_failed"} for domain in seeds
        }
        _persist(output_dir, result)
        return result

    try:
        dkim_records = _run_dnsx_txt(
            dkim_names, output_dir, kind="dkim", timeout=timeout, retries=retries
        )
    except DnsxError as exc:
        LOG.warning("mail_posture: DKIM lookups failed: %s", exc)
        dkim_records = {}
        dkim_domains = []

    findings: list[dict[str, Any]] = []
    records: dict[str, dict[str, Any]] = {}

    for domain in seeds:
        domain_findings: list[dict[str, Any]] = []

        mx_entries = _mx_entries(mx_records.get(domain, {}))
        mx_truncated = len(mx_entries) > MAX_MX_PER_DOMAIN
        if mx_truncated:
            truncated = True
            LOG.warning(
                "mail_posture: %s publishes %d MX records, keeping MAX_MX_PER_DOMAIN=%d",
                domain,
                len(mx_entries),
                MAX_MX_PER_DOMAIN,
            )
            mx_entries = mx_entries[:MAX_MX_PER_DOMAIN]
        null_mx = _is_null_mx(mx_entries)
        has_mx = bool(mx_entries) and not null_mx

        domain_txt = _txt_values(txt_records.get(domain, {}))
        spf_records = _spf_records(domain_txt)
        evaluation = None
        if spf_records and time.perf_counter() < deadline:
            evaluation = _evaluate_spf(
                domain, spf_records[0], output_dir, timeout=timeout, retries=retries
            )
        spf, spf_findings = _classify_spf(domain, spf_records, evaluation)
        domain_findings.extend(spf_findings)

        dmarc, dmarc_findings = _classify_dmarc(
            domain, _txt_values(txt_records.get(f"_dmarc.{domain}", {}))
        )
        domain_findings.extend(dmarc_findings)

        dkim, dkim_findings = _classify_dkim(
            domain, selectors, dkim_records, queried=domain in dkim_domains
        )
        domain_findings.extend(dkim_findings)

        mta_sts_txt = _txt_values(txt_records.get(f"_mta-sts.{domain}", {}))
        policy = None
        if (
            config.mta_sts_http
            and any(value.lower().startswith("v=stsv1") for value in mta_sts_txt)
            and time.perf_counter() < deadline
        ):
            policy = _fetch_mta_sts_policy(
                domain,
                min(float(config.mta_sts_timeout_seconds), deadline - time.perf_counter()),
            )
        mta_sts, mta_sts_findings = _classify_mta_sts(domain, mta_sts_txt, policy)
        domain_findings.extend(mta_sts_findings)

        tls_rpt, tls_rpt_findings = _classify_tls_rpt(
            domain, _txt_values(txt_records.get(f"_smtp._tls.{domain}", {}))
        )
        domain_findings.extend(tls_rpt_findings)
        domain_findings.extend(_classify_spoofable(domain, has_mx, null_mx, spf, dmarc))

        answered = bool(mx_entries) or bool(domain_txt) or dmarc["status"] == "present"
        records[domain] = {
            "status": "ok" if answered else "not_checked",
            "reason": None if answered else "no_dns_answer",
            "mx": {
                "entries": mx_entries,
                "has_mx": has_mx,
                "null_mx": null_mx,
                "truncated": mx_truncated,
            },
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "mta_sts": mta_sts,
            "tls_rpt": tls_rpt,
        }
        findings.extend(domain_findings)

    result["domains"] = records
    result["findings"] = findings
    result["truncated"] = truncated
    _persist(output_dir, result)
    LOG.info(
        "mail_posture: %d domain(s) checked -> %d finding(s)%s",
        len(seeds),
        len(findings),
        " [truncated]" if truncated else "",
    )
    return result
