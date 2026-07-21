"""Cloud storage bucket enumeration (Phase 8.3).

Seed org token(s) (derived from scan domains) -> candidate bucket/container
names -> unauthenticated HEAD/GET checks against S3, GCS, and Azure Blob's
public REST endpoints. No cloud SDK / credentials involved -- same class of
technique as hostnames.py's DNS brute force, but against cloud object-
storage namespaces instead of a target's own DNS.

SAFETY: candidate generation combines org tokens x wordlist entries x naming
patterns, which grows combinatorially. max_candidates hard-caps the
generated list (like ct.brute_force.max_candidates) and concurrency bounds
in-flight requests -- against shared third-party cloud infrastructure, not
the target's own hosts, so defaults here are more conservative than DNS
brute force. Disabled by default (discovery.cloud.enabled = false).
Findings are reported, never merged into scan scope: a discovered bucket is
an asset-inventory / data-exposure finding, not a port-scan target.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from pathlib import Path
from typing import Any

import httpx

from .config_schema import CloudDiscoveryConfig
from .utils import save_json, write_lines

LOG = logging.getLogger("octo-man.cloud-discovery")

USER_AGENT = "shapoclyack-octo-man/cloud-discovery"
DEFAULT_WORDLIST_PATH = (
    Path(__file__).resolve().parents[2] / "scanner" / "data" / "wordlists" / "bucket-names-small.txt"
)


def _load_wordlist(wordlist_file: str) -> list[str]:
    path = Path(wordlist_file) if wordlist_file else DEFAULT_WORDLIST_PATH
    if not path.is_file():
        LOG.warning("cloud_discovery: wordlist not found at %s", path)
        return []
    words: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        word = line.strip().lower()
        if word and not word.startswith("#"):
            words.append(word)
    return words


def _org_tokens_from_domains(domains: list[str]) -> list[str]:
    """Reduce base domains (e.g. "example.com") to a bare org label ("example")."""
    tokens: list[str] = []
    seen: set[str] = set()
    for domain in domains:
        name = domain.strip().lower().rstrip(".")
        if not name:
            continue
        label = name.split(".")[0]
        if label and label not in seen:
            seen.add(label)
            tokens.append(label)
    return tokens


def _valid_bucket_name(name: str) -> bool:
    """S3/GCS naming rules: 3-63 chars, lowercase alnum/hyphen/dot, must start/end alnum."""
    if not (3 <= len(name) <= 63):
        return False
    if not (name[0].isalnum() and name[-1].isalnum()):
        return False
    return all(ch.isalnum() or ch in "-." for ch in name)


def _valid_azure_account_name(name: str) -> bool:
    """Azure storage account naming rules: 3-24 chars, lowercase alphanumeric only."""
    return 3 <= len(name) <= 24 and name.isalnum()


def _bucket_candidates(tokens: list[str], words: list[str], max_candidates: int) -> list[str]:
    """Candidate S3/GCS bucket names: token/word combined with common separators."""
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> bool:
        if name in seen or not _valid_bucket_name(name):
            return False
        seen.add(name)
        candidates.append(name)
        return len(candidates) >= max_candidates

    for token in tokens:
        if _add(token):
            return candidates
        for word in words:
            for candidate in (
                f"{token}-{word}",
                f"{word}-{token}",
                f"{token}.{word}",
                f"{word}.{token}",
                f"{token}{word}",
                f"{word}{token}",
            ):
                if _add(candidate):
                    return candidates
    return candidates


def _azure_account_candidates(tokens: list[str], words: list[str], max_candidates: int) -> list[str]:
    """Candidate Azure storage account names: no hyphen/dot allowed, so plain concatenation only."""
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> bool:
        if name in seen or not _valid_azure_account_name(name):
            return False
        seen.add(name)
        candidates.append(name)
        return len(candidates) >= max_candidates

    for token in tokens:
        if _add(token):
            return candidates
        for word in words:
            for candidate in (f"{token}{word}", f"{word}{token}"):
                if _add(candidate):
                    return candidates
    return candidates


async def _check_s3(client: httpx.AsyncClient, name: str, timeout: float) -> dict[str, Any] | None:
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        resp = await client.head(url, timeout=timeout)
    except httpx.HTTPError as exc:
        LOG.debug("cloud_discovery: s3 check failed for %s: %s", name, exc)
        return None
    if resp.status_code == 200:
        return {"provider": "s3", "name": name, "container": None, "url": url, "status": "public", "http_status": 200}
    if resp.status_code == 403:
        return {"provider": "s3", "name": name, "container": None, "url": url, "status": "private", "http_status": 403}
    return None  # 404 or anything else -> not found / inconclusive


async def _check_gcs(client: httpx.AsyncClient, name: str, timeout: float) -> dict[str, Any] | None:
    url = f"https://{name}.storage.googleapis.com/"
    try:
        resp = await client.head(url, timeout=timeout)
    except httpx.HTTPError as exc:
        LOG.debug("cloud_discovery: gcs check failed for %s: %s", name, exc)
        return None
    if resp.status_code == 200:
        return {"provider": "gcs", "name": name, "container": None, "url": url, "status": "public", "http_status": 200}
    if resp.status_code == 403:
        return {"provider": "gcs", "name": name, "container": None, "url": url, "status": "private", "http_status": 403}
    return None


async def _check_azure_account(name: str, timeout: float) -> bool:
    host = f"{name}.blob.core.windows.net"
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        await asyncio.to_thread(socket.getaddrinfo, host, None)
        return True
    except (socket.gaierror, OSError):
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)


async def _check_azure_container(
    client: httpx.AsyncClient, account: str, container: str, timeout: float
) -> dict[str, Any] | None:
    url = (
        f"https://{account}.blob.core.windows.net/{container}"
        "?restype=container&comp=list&maxresults=1"
    )
    try:
        resp = await client.get(url, timeout=timeout)
    except httpx.HTTPError as exc:
        LOG.debug("cloud_discovery: azure check failed for %s/%s: %s", account, container, exc)
        return None
    if resp.status_code == 200:
        return {
            "provider": "azure",
            "name": account,
            "container": container,
            "url": url,
            "status": "public",
            "http_status": 200,
        }
    # Azure conflates not-found and exists-but-private across several error
    # codes (ContainerNotFound / PublicAccessNotPermitted / ResourceNotFound)
    # -- cannot reliably distinguish without auth, so treat every other
    # status as not-found / inconclusive rather than guessing.
    return None


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / "cloud_discovery.json", result)
    lines = []
    for finding in result["public_findings"]:
        target = finding["name"]
        if finding.get("container"):
            target = f"{target}/{finding['container']}"
        lines.append(f"{finding['provider']}:{target}:{finding['url']}")
    write_lines(output_dir / "cloud_discovery_public.txt", lines)


async def discover_cloud_buckets(
    domains: list[str],
    config: CloudDiscoveryConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Async cloud bucket/container discovery across configured providers."""
    result: dict[str, Any] = {
        "seed_domains": [],
        "org_tokens": [],
        "providers": [],
        "candidates_generated": 0,
        "checked_count": 0,
        "findings": [],
        "public_findings": [],
        "truncated": False,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "cloud.disabled"
        _persist(output_dir, result)
        return result

    seeds = [d.strip().lower() for d in domains if d.strip()]
    seeds = sorted(set(seeds))
    tokens = _org_tokens_from_domains(seeds)
    if not tokens:
        result["skipped_reason"] = "no_domains"
        _persist(output_dir, result)
        return result

    result["seed_domains"] = seeds
    result["org_tokens"] = tokens
    result["providers"] = list(config.providers)

    words = _load_wordlist(config.wordlist_file)
    timeout = float(config.timeout_seconds)
    semaphore = asyncio.Semaphore(config.concurrency)
    findings: list[dict[str, Any]] = []
    checked = 0

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:

        async def _guarded(coro: Any) -> Any:
            async with semaphore:
                return await coro

        truncated = False

        if "s3" in config.providers or "gcs" in config.providers:
            bucket_candidates = _bucket_candidates(tokens, words, config.max_candidates)
            truncated = truncated or len(bucket_candidates) >= config.max_candidates
            result["candidates_generated"] += len(bucket_candidates)
            checks: list[Any] = []
            for name in bucket_candidates:
                if "s3" in config.providers:
                    checks.append(_guarded(_check_s3(client, name, timeout)))
                if "gcs" in config.providers:
                    checks.append(_guarded(_check_gcs(client, name, timeout)))
            checked += len(checks)
            for outcome in await asyncio.gather(*checks):
                if outcome is not None:
                    findings.append(outcome)

        if "azure" in config.providers:
            account_candidates = _azure_account_candidates(tokens, words, config.max_candidates)
            truncated = truncated or len(account_candidates) >= config.max_candidates
            result["candidates_generated"] += len(account_candidates)
            resolved = await asyncio.gather(
                *(_guarded(_check_azure_account(name, timeout)) for name in account_candidates)
            )
            containers = words[: config.azure_container_probes] or ["$root"]
            container_checks = []
            for account, exists in zip(account_candidates, resolved):
                checked += 1
                if not exists:
                    continue
                for container in containers:
                    container_checks.append(
                        _guarded(_check_azure_container(client, account, container, timeout))
                    )
            checked += len(container_checks)
            for outcome in await asyncio.gather(*container_checks):
                if outcome is not None:
                    findings.append(outcome)

    result["checked_count"] = checked
    result["findings"] = findings
    result["public_findings"] = [f for f in findings if f["status"] == "public"]
    result["truncated"] = truncated

    _persist(output_dir, result)
    LOG.info(
        "cloud_discovery: %d org token(s) -> %d candidate(s) checked -> %d finding(s) (%d public)%s",
        len(tokens),
        result["candidates_generated"],
        len(findings),
        len(result["public_findings"]),
        " [truncated]" if truncated else "",
    )
    return result


def discover_cloud_buckets_sync(
    domains: list[str],
    config: CloudDiscoveryConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Sync wrapper for pipeline stages (uses ``asyncio.run``)."""
    return asyncio.run(discover_cloud_buckets(domains, config, output_dir))
