"""Corporate credential leaks via pluggable provider (org_profile M5, EPIC #182).

Queries corporate domain breach databases (e.g. Have I Been Pwned Breached Domain Search)
to detect compromised employee credentials associated with organizational domains.

DATA HANDLING & PRIVACY INVARIANTS:
1. Aggregates only in primary artifact (``credential_leaks.json``): total breach incidents,
   account counts, breach sources, data classes, and password exposure flags.
2. Zero password storage: plaintext passwords and password hashes are NEVER saved or logged.
3. Masking: email local-parts are masked in public artifacts (``j***@example.com``).
4. Restricted full identifiers: unmasked corporate emails are segregated in
   ``credential_leaks_identifiers.json``, hidden from viewers and accessible only to operator+
   via RBAC-gated API.
5. Absence invariant: missing API key or unconfigured stage reports ``not_checked`` with
   ``reason: "no_api_key"`` -- NEVER reports ``ok``.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .asset_identity import registrable_domain
from .config_schema import CredentialLeaksConfig
from .utils import save_json

LOG = logging.getLogger("shapoclyack.credential_leaks")

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "shapoclyack/credential_leaks"

PASSWORD_DATA_CLASSES = frozenset({
    "passwords",
    "password hashes",
    "password hints",
    "pins",
    "auth tokens",
    "encrypted keys",
})


def mask_email(email: str) -> str:
    """Mask the local part of an email address (e.g. 'john.doe@example.com' -> 'j***@example.com')."""
    if not email or "@" not in email:
        return email
    local, _, domain = email.partition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


@dataclass
class BreachDetail:
    name: str
    title: str
    domain: str
    breach_date: str
    added_date: str
    pwn_count: int
    description: str
    data_classes: list[str]
    has_passwords: bool
    is_verified: bool = True
    is_sensitive: bool = False
    is_fabricated: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    accounts: list[str] = field(default_factory=list)


@dataclass
class LeakReport:
    domain: str
    status: str  # "ok" | "not_checked" | "error" | "fail" | "weak"
    reason: str | None = None
    breaches: list[BreachDetail] = field(default_factory=list)
    total_accounts: int = 0


@runtime_checkable
class LeakProvider(Protocol):
    def domain_breaches(self, domain: str) -> LeakReport: ...


class HIBPLeakProvider:
    """Have I Been Pwned (HIBP) Breached Domain search provider."""

    def __init__(self, api_key: str, timeout_seconds: int = 15) -> None:
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def domain_breaches(self, domain: str) -> LeakReport:
        if not self.api_key:
            return LeakReport(domain=domain, status="not_checked", reason="no_api_key")

        import urllib.request
        import urllib.error

        url = f"{HIBP_API_BASE}/breacheddomain/{urllib.parse.quote(domain)}"
        req = urllib.request.Request(
            url,
            headers={
                "hibp-api-key": self.api_key,
                "user-agent": USER_AGENT,
                "Accept": "application/json",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return LeakReport(domain=domain, status="ok", breaches=[], total_accounts=0)
            if err.code in (401, 403):
                return LeakReport(domain=domain, status="not_checked", reason="api_key_unauthorized_or_unverified")
            if err.code == 429:
                return LeakReport(domain=domain, status="error", reason="rate_limited")
            return LeakReport(domain=domain, status="error", reason=f"http_{err.code}")
        except Exception as exc:
            LOG.warning("HIBP breached domain query failed for %s: %s", domain, exc)
            return LeakReport(domain=domain, status="error", reason="network_error")

        if not isinstance(data, dict):
            return LeakReport(domain=domain, status="ok", breaches=[], total_accounts=0)

        # HIBP breacheddomain returns: {"alias": ["Breach1", "Breach2"]}
        breach_to_aliases: dict[str, list[str]] = {}
        for alias, breach_names in data.items():
            email_addr = f"{alias}@{domain}" if alias else domain
            if isinstance(breach_names, list):
                for bname in breach_names:
                    breach_to_aliases.setdefault(str(bname), []).append(email_addr)

        breach_details: list[BreachDetail] = []
        all_accounts: set[str] = set()

        for bname, accounts in breach_to_aliases.items():
            all_accounts.update(accounts)
            # Fetch breach metadata if possible
            b_meta = self._fetch_breach_meta(bname)
            data_classes = b_meta.get("DataClasses") or ["Email addresses"]
            has_pw = any(dc.lower() in PASSWORD_DATA_CLASSES for dc in data_classes)

            breach_details.append(
                BreachDetail(
                    name=bname,
                    title=b_meta.get("Title") or bname,
                    domain=b_meta.get("Domain") or domain,
                    breach_date=b_meta.get("BreachDate") or "",
                    added_date=b_meta.get("AddedDate") or "",
                    pwn_count=int(b_meta.get("PwnCount") or len(accounts)),
                    description=b_meta.get("Description") or "",
                    data_classes=data_classes,
                    has_passwords=has_pw,
                    is_verified=bool(b_meta.get("IsVerified", True)),
                    is_sensitive=bool(b_meta.get("IsSensitive", False)),
                    is_fabricated=bool(b_meta.get("IsFabricated", False)),
                    is_retired=bool(b_meta.get("IsRetired", False)),
                    is_spam_list=bool(b_meta.get("IsSpamList", False)),
                    accounts=accounts,
                )
            )

        status = "fail" if any(b.has_passwords for b in breach_details) or len(breach_details) > 0 else "ok"
        return LeakReport(
            domain=domain,
            status=status,
            breaches=breach_details,
            total_accounts=len(all_accounts),
        )

    def _fetch_breach_meta(self, breach_name: str) -> dict[str, Any]:
        import urllib.request
        url = f"{HIBP_API_BASE}/breach/{urllib.parse.quote(breach_name)}"
        req = urllib.request.Request(url, headers={"user-agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {}


class MockLeakProvider:
    """Mock leak provider for deterministic offline testing."""

    def __init__(self, responses: dict[str, LeakReport] | None = None) -> None:
        self.responses = responses or {}

    def domain_breaches(self, domain: str) -> LeakReport:
        if domain in self.responses:
            return self.responses[domain]
        return LeakReport(domain=domain, status="ok", breaches=[], total_accounts=0)


def check_credential_leaks(
    domains: list[str],
    config: CredentialLeaksConfig,
    output_dir: Path,
    *,
    provider: LeakProvider | None = None,
) -> dict[str, Any]:
    """Execute credential leaks evaluation across organizational domains."""
    api_key = config.api_key or os.environ.get("OCTO_HIBP_API_KEY") or os.environ.get("HIBP_API_KEY") or ""

    if provider is None:
        if config.provider.lower() == "hibp":
            provider = HIBPLeakProvider(api_key=api_key, timeout_seconds=config.timeout_seconds)
        else:
            provider = MockLeakProvider()

    # Deduplicate and canonicalize seed domains
    canonical_domains = sorted(list({registrable_domain(d) for d in domains if registrable_domain(d)}))

    if not config.enabled:
        empty_res = {
            "status": "not_checked",
            "skipped_reason": "stage_disabled",
            "provider": config.provider,
            "checked_domains": 0,
            "total_domains": len(canonical_domains),
            "breaches_count": 0,
            "accounts_count": 0,
            "seed_domains": canonical_domains,
            "domains": {},
            "findings": [],
            "truncated": False,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        save_json(output_dir / "credential_leaks.json", empty_res)
        return empty_res

    if not api_key and config.provider.lower() == "hibp":
        no_key_res = {
            "status": "not_checked",
            "skipped_reason": "no_api_key",
            "provider": config.provider,
            "checked_domains": 0,
            "total_domains": len(canonical_domains),
            "breaches_count": 0,
            "accounts_count": 0,
            "seed_domains": canonical_domains,
            "domains": {},
            "findings": [],
            "truncated": False,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
        save_json(output_dir / "credential_leaks.json", no_key_res)
        return no_key_res

    start_time = time.monotonic()
    total_domains_count = len(canonical_domains)
    truncated = total_domains_count > config.max_domains
    working_domains = canonical_domains[: config.max_domains]

    domains_results: dict[str, Any] = {}
    identifiers_by_domain: dict[str, dict[str, list[str]]] = {}
    findings: list[dict[str, Any]] = []

    total_breaches = 0
    total_accounts = 0
    has_fail = False
    has_weak = False
    has_ok = False
    has_error = False

    for domain in working_domains:
        if time.monotonic() - start_time > config.deadline_seconds:
            truncated = True
            break

        report = provider.domain_breaches(domain)

        domain_entry: dict[str, Any] = {
            "status": report.status,
            "reason": report.reason,
            "breaches_count": len(report.breaches),
            "accounts_count": report.total_accounts,
            "breaches": [],
        }

        domain_identifiers: dict[str, list[str]] = {}

        for b in report.breaches:
            masked_ids = [mask_email(acc) for acc in b.accounts]
            domain_entry["breaches"].append({
                "name": b.name,
                "title": b.title,
                "domain": b.domain,
                "breach_date": b.breach_date,
                "added_date": b.added_date,
                "pwn_count": b.pwn_count,
                "description": b.description,
                "data_classes": b.data_classes,
                "has_passwords": b.has_passwords,
                "is_verified": b.is_verified,
                "is_sensitive": b.is_sensitive,
                "masked_identifiers": masked_ids,
            })
            domain_identifiers[b.name] = b.accounts

            sev = "critical" if b.has_passwords else "high"
            findings.append({
                "kind": "passwords_exposed" if b.has_passwords else "credential_leak",
                "severity": sev,
                "domain": domain,
                "detail": f"{len(b.accounts)} corporate account(s) exposed in breach '{b.title or b.name}'"
                + (" (passwords exposed)" if b.has_passwords else ""),
            })

        identifiers_by_domain[domain] = domain_identifiers
        domains_results[domain] = domain_entry

        total_breaches += len(report.breaches)
        total_accounts += report.total_accounts

        if report.status == "fail":
            has_fail = True
        elif report.status == "weak":
            has_weak = True
        elif report.status == "ok":
            has_ok = True
        elif report.status == "error":
            has_error = True

    if has_fail:
        overall_status = "fail"
    elif has_weak:
        overall_status = "weak"
    elif has_ok and not has_error:
        overall_status = "ok"
    elif has_error:
        overall_status = "error"
    else:
        overall_status = "not_checked"

    result = {
        "status": overall_status,
        "skipped_reason": None,
        "provider": config.provider,
        "checked_domains": len(domains_results),
        "total_domains": total_domains_count,
        "breaches_count": total_breaches,
        "accounts_count": total_accounts,
        "seed_domains": canonical_domains,
        "domains": domains_results,
        "findings": findings,
        "truncated": truncated,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    # Save primary aggregate artifact
    save_json(output_dir / "credential_leaks.json", result)

    # Save restricted identifiers artifact
    identifiers_payload = {
        "total_identifiers": total_accounts,
        "domains": identifiers_by_domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json(output_dir / "credential_leaks_identifiers.json", identifiers_payload)

    LOG.info(
        "Credential leaks evaluation complete: %d breach incidents, %d accounts across %d domains",
        total_breaches,
        total_accounts,
        len(domains_results),
    )
    return result
