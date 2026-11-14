"""Claim and run one brand-watch job. Never starts a scan.

The sensor advertises ``brand_watch``, then polls
``POST /api/brand-watch/jobs/claim`` only when the scan queue handed it
nothing. DNS observation uses the resolvers already configured for this
sensor (``dns.resolvers``). An empty list is passed through so
``observe_dns`` fails soft to ``unanswered`` rather than this module
picking a public resolver. HTTP is opened only for a ``http_allowed`` job,
and only for a name DNS marked ``resolving`` with a public address.
``dns_only`` never calls the HTTP observer.

A failed observe is posted as ``unanswered``. Nothing here raises into the
poll loop: claim, observe and result post are all caught.
"""

from __future__ import annotations

import logging
import tempfile
import threading
from types import SimpleNamespace
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

LOG = logging.getLogger("octo-agent")

CAPABILITY = "brand_watch"
MODE_HTTP_ALLOWED = "http_allowed"
MODE_DNS_ONLY = "dns_only"
STATUS_RESOLVING = "resolving"
STATUS_UNANSWERED = "unanswered"

ObserveDns = Callable[..., list[dict[str, Any]]]
ObserveHttp = Callable[..., dict[str, Any]]
RefuseReason = Callable[[str], str | None]


def _unanswered(name: str) -> dict[str, Any]:
    text = str(name).strip().rstrip(".").lower()
    return {
        "unicode": text,
        "punycode": text,
        "ns": [],
        "a": [],
        "aaaa": [],
        "mx_present": False,
        "rcode": None,
        "status": STATUS_UNANSWERED,
    }


def sensor_resolvers(config_path: Path) -> list[str]:
    """Resolvers this worker already has. Never a baked-in public resolver.

    Reads ``dns.resolvers`` from the worker YAML directly. The scanner package
    is not part of the sensor install, so this must not import it. Missing
    config, a config that does not parse, or an empty list all yield ``[]``.
    """
    try:
        import yaml
    except ImportError:
        LOG.warning("brand_watch: PyYAML is not importable; observing with no resolvers")
        return []
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — a bad config must not kill the poll loop
        LOG.warning("brand_watch: could not read resolvers from %s (%s)", config_path, exc)
        return []
    dns = raw.get("dns") if isinstance(raw, dict) else None
    resolvers = dns.get("resolvers") if isinstance(dns, dict) else None
    if not isinstance(resolvers, list):
        return []
    return [str(item) for item in resolvers if str(item).strip()]


def _names_of(job: dict[str, Any]) -> list[str]:
    payload = job.get("payload")
    raw = payload.get("names") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return []
    names: list[str] = []
    for item in raw:
        text = str(item).strip()
        if text:
            names.append(text)
    return names


def _public_address(row: dict[str, Any], refuse_reason: RefuseReason) -> str | None:
    """First A/AAAA that DNS returned and the HTTP observer may dial."""
    for key in ("a", "aaaa"):
        values = row.get(key) or []
        if isinstance(values, str):
            values = [values]
        for value in values:
            address = str(value).strip()
            if not address:
                continue
            try:
                refused = refuse_reason(address)
            except Exception:  # noqa: BLE001
                LOG.warning("brand_watch: refuse check failed for %s", address, exc_info=True)
                continue
            if refused is None:
                return address
    return None


def _http_rows(
    dns_rows: list[dict[str, Any]],
    *,
    observe_http: ObserveHttp,
    refuse_reason: RefuseReason,
) -> list[dict[str, Any]]:
    """HTTP only for names DNS marked resolving with a public address."""
    merged: list[dict[str, Any]] = []
    for row in dns_rows:
        if str(row.get("status") or "") != STATUS_RESOLVING:
            merged.append(row)
            continue
        address = _public_address(row, refuse_reason)
        if address is None:
            merged.append(row)
            continue
        name = str(row.get("unicode") or row.get("punycode") or "")
        try:
            request = SimpleNamespace(
                name=name,
                address=address,
                brand="",
                mx_present=bool(row.get("mx_present")),
                registered=True,
            )
            pack = observe_http(request)
        except Exception as exc:  # noqa: BLE001 — a failed observe is unanswered, not a raise
            LOG.warning("brand_watch: HTTP observe failed for %s (%s)", name, type(exc).__name__)
            merged.append({**row, "status": STATUS_UNANSWERED})
            continue
        if not isinstance(pack, dict):
            merged.append({**row, "status": STATUS_UNANSWERED})
            continue
        merged.append({**row, **pack, "unicode": row.get("unicode"), "punycode": row.get("punycode")})
    return merged


def run_claimed_job(
    job: dict[str, Any],
    *,
    config_path: Path,
    observe_dns: ObserveDns,
    observe_http: ObserveHttp,
    refuse_reason: RefuseReason,
    resolvers: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Observe one claimed job. Does not post, does not scan.

    ``resolvers is None`` reads the worker config. An explicit empty list
    is passed through unchanged so tests (and a sensor with no configured
    resolvers) do not fall back to a public resolver.
    """
    names = _names_of(job)
    if not names:
        return []
    chosen = list(resolvers) if resolvers is not None else sensor_resolvers(config_path)
    try:
        with tempfile.TemporaryDirectory(prefix="octo-brand-watch-") as tmp:
            rows = observe_dns(names, Path(tmp), resolvers=chosen)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("brand_watch: DNS observe failed (%s); posting unanswered", exc)
        return [_unanswered(name) for name in names]
    if not isinstance(rows, list):
        return [_unanswered(name) for name in names]
    by_name = {
        str(row.get("unicode") or "").strip().rstrip(".").lower(): row
        for row in rows
        if isinstance(row, dict)
    }
    ordered: list[dict[str, Any]] = []
    for name in names:
        key = name.strip().rstrip(".").lower()
        row = by_name.get(key)
        ordered.append(row if row is not None else _unanswered(name))
    mode = str(job.get("mode") or MODE_DNS_ONLY)
    if mode != MODE_HTTP_ALLOWED:
        return ordered
    return _http_rows(ordered, observe_http=observe_http, refuse_reason=refuse_reason)


def poll_once(
    client: Any,
    agent_id: str,
    *,
    config_path: Path,
    observe_dns: ObserveDns | None = None,
    observe_http: ObserveHttp | None = None,
    refuse_reason: RefuseReason | None = None,
    resolvers: Sequence[str] | None = None,
) -> bool:
    """Claim at most one brand-watch job and post its observations.

    Returns True when a job was claimed. Never raises: the poll loop must
    keep claiming scan jobs after a brand-watch failure. Never starts a scan.
    """
    if observe_dns is None or observe_http is None or refuse_reason is None:
        LOG.warning("brand_watch: observers are not injected; nothing is claimed")
        return False
    try:
        job = client.claim_brand_watch(agent_id)
    except Exception:  # noqa: BLE001
        LOG.warning("brand_watch: claim failed", exc_info=True)
        return False
    if not isinstance(job, dict) or not job.get("id"):
        return False
    job_id = str(job["id"])
    try:
        observations = run_claimed_job(
            job,
            config_path=config_path,
            observe_dns=observe_dns,
            observe_http=observe_http,
            refuse_reason=refuse_reason,
            resolvers=resolvers,
        )
    except Exception:  # noqa: BLE001
        LOG.warning("brand_watch: observe failed for %s", job_id, exc_info=True)
        observations = [_unanswered(name) for name in _names_of(job)]
    try:
        client.post_brand_watch_result(job_id, observations)
    except Exception:  # noqa: BLE001
        LOG.warning("brand_watch: result post failed for %s; releasing the claim", job_id, exc_info=True)
        release = getattr(client, "release_brand_watch", None)
        if release is None:
            return True
        try:
            release(job_id)
        except Exception:  # noqa: BLE001
            LOG.warning("brand_watch: release failed for %s", job_id, exc_info=True)
    return True


_inflight = threading.Lock()


def poll_in_background(
    client: Any,
    agent_id: str,
    *,
    config_path: Path,
    observe_dns: ObserveDns,
    observe_http: ObserveHttp,
    refuse_reason: RefuseReason,
) -> None:
    """Start one observation without holding the scan poll.

    A second call while the first is still running does nothing: two claims
    at once would spend two leases on one sensor. The thread is a daemon so
    a process exit does not wait on DNS.
    """
    if not _inflight.acquire(blocking=False):
        return

    def _run() -> None:
        try:
            poll_once(
                client,
                agent_id,
                config_path=config_path,
                observe_dns=observe_dns,
                observe_http=observe_http,
                refuse_reason=refuse_reason,
            )
        finally:
            _inflight.release()

    threading.Thread(target=_run, name="octo-brand-watch", daemon=True).start()
