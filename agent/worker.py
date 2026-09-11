"""Poll the Shapoclyack API for agent jobs and run the local scanner.

When OCTO_NATS_URL is set, jobs are pulled from JetStream subject
``jobs.scan.{tenant}`` (durable consumer ``octo-agents-{tenant}``) via a
long-lived connection instead of HTTP claim polling. The tenant comes from the
API — the provisioning-key exchange, or the registration response for a legacy
shared token — so an agent never binds a consumer outside its own tenant.
An agent an operator put in an agent group also binds
``jobs.scan.{tenant}.{group}`` (durable ``octo-agents-{tenant}-{group}``); the
group likewise comes from the API, on every register and heartbeat, and an
offer names only a job id, never its targets (#361).
Register, heartbeat, and results upload remain HTTP.

TLS for the NATS connection is configured with OCTO_NATS_TLS_CA,
OCTO_NATS_TLS_CERT, OCTO_NATS_TLS_KEY and OCTO_NATS_TLS_HOSTNAME; a ``tls://``
URL with none of them set verifies against the system trust store. ``wss://``
reaches the same broker over a WebSocket on 443, for a network whose egress
firewall knows one port.

Every HTTP call above leaves through ``agent.egress``: OCTO_HTTP_PROXY,
OCTO_HTTPS_PROXY, OCTO_NO_PROXY and OCTO_CA_BUNDLE. NATS does not — no HTTP
proxy carries it — so an agent whose only way out is the proxy leaves
OCTO_NATS_URL unset and polls the HTTP claim instead
(docs/network-requirements.md).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import signal
import re
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from agent import __version__, egress
from agent import logging_setup

LOG = logging.getLogger("octo-agent")

# Well under the server's OCTO_JOB_LEASE_SECONDS default (300): the lease has
# to survive a few missed heartbeats, not just one.
HEARTBEAT_INTERVAL_SECONDS = 60.0

# What this build promises the API it can honour, reported on register and on
# every heartbeat. ``scan_policy`` means: when a claim carries a
# ``scan_policy.json`` input, this worker passes it to the scanner as
# ``--scan-policy``, where the tenant's rate ceilings and port avoid-list are
# applied on top of the local config (#362). The API refuses to hand a job
# whose tenant has a policy to an agent that does not declare this — a ceiling
# an older worker silently ignores would read as enforced and would not be.
# Kept equal to api/services/scan_policy.AGENT_CAPABILITY.
CAPABILITIES: tuple[str, ...] = ("scan_policy",)

SUBJECT_JOBS_SCAN_PREFIX = "jobs.scan"
STREAM_JOBS = "JOBS"
CONSUMER_AGENTS_PREFIX = "octo-agents"
DEFAULT_TENANT_ID = "default"
# Kept equal to api/services/nats_bus.JOBS_MAX_DELIVER: whichever side creates
# the consumer first decides, and a mismatch would be an attempt budget that
# depends on which one won the race.
JOBS_MAX_DELIVER = 5

# Subject-token encoding, kept byte-for-byte identical to
# api/services/nats_bus.py. The agent is deployed on its own (no api package on
# the box), so this is a copy rather than an import; tests assert the two agree,
# because an agent that encodes a tenant id differently from the API binds a
# consumer that no offer is ever filtered onto.
_SUBJECT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ENCODED_TOKEN_PREFIX = "h_"


def _subject_token(value: str, fallback: str = DEFAULT_TENANT_ID) -> str:
    """Encode one subject token injectively (see api/services/nats_bus.py)."""
    value = value or ""
    if _SUBJECT_TOKEN_RE.match(value) and not value.startswith(_ENCODED_TOKEN_PREFIX):
        return value
    if not value:
        return fallback
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    return f"{_ENCODED_TOKEN_PREFIX}{digest}"


def jobs_scan_subject(tenant_id: str, agent_group: str | None = None) -> str:
    """NATS subject this agent may consume (see api/services/nats_bus.py).

    ``jobs.scan.{tenant}`` carries the tenant's ungrouped jobs, which every
    agent of the tenant may claim; ``jobs.scan.{tenant}.{group}`` carries the
    jobs addressed to one group, and only the agents an operator put in that
    group bind to it.
    """
    subject = f"{SUBJECT_JOBS_SCAN_PREFIX}.{_subject_token(tenant_id)}"
    if agent_group:
        subject = f"{subject}.{_subject_token(agent_group, 'ungrouped')}"
    return subject


def jobs_consumer_name(tenant_id: str, agent_group: str | None = None) -> str:
    """Durable consumer name ``octo-agents-{tenant_id}[-{group}]`` for this agent."""
    name = f"{CONSUMER_AGENTS_PREFIX}-{_subject_token(tenant_id)}"
    if agent_group:
        name = f"{name}-{_subject_token(agent_group, 'ungrouped')}"
    return name


def tls_connect_options() -> dict[str, Any]:
    """``nats.connect`` TLS kwargs from OCTO_NATS_TLS_* (mirrors the API side).

    OCTO_CA_BUNDLE is added on top of whatever OCTO_NATS_TLS_CA (or the system
    store) already trusts, so an installation with one internal root names it
    once for HTTP and NATS both. It is additive, never a replacement: a broker
    with a publicly issued certificate keeps verifying.
    """
    ca = os.environ.get("OCTO_NATS_TLS_CA", "").strip()
    cert = os.environ.get("OCTO_NATS_TLS_CERT", "").strip()
    key = os.environ.get("OCTO_NATS_TLS_KEY", "").strip()
    hostname = os.environ.get("OCTO_NATS_TLS_HOSTNAME", "").strip()
    bundle = egress.ca_bundle()
    if not (ca or cert or hostname or bundle):
        return {}
    context = ssl.create_default_context(cafile=ca or None)
    if bundle:
        context.load_verify_locations(cafile=bundle)
    if cert:
        context.load_cert_chain(certfile=cert, keyfile=key or None)
    options: dict[str, Any] = {"tls": context}
    if hostname:
        options["tls_hostname"] = hostname
    return options


def check_nats_transport(nats_url: str) -> None:
    """Refuse a NATS URL this build cannot dial, while the message still helps.

    ``wss://`` is the answer for a network that lets 443 out and nothing else,
    and nats-py speaks it — but only through ``aiohttp``, which the agent image
    does not carry by default. Without this the failure is an ImportError from
    inside a background event-loop thread, minutes after start and nowhere near
    the setting that caused it.
    """
    scheme = urllib.parse.urlsplit((nats_url or "").strip()).scheme
    if scheme not in ("ws", "wss"):
        return
    try:
        import aiohttp  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            f"OCTO_NATS_URL uses {scheme}:// (NATS over WebSocket), which nats-py "
            "implements with aiohttp. Install it on this host (pip install aiohttp), "
            "or use tls:// through a TCP ingress on 443 — see "
            "docs/network-requirements.md"
        ) from exc


def _collect_system_metrics() -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    try:
        import platform
        metrics["os"] = platform.system()
        metrics["release"] = platform.release()
        metrics["arch"] = platform.machine()
    except Exception:
        pass

    try:
        import psutil
        metrics["cpu_percent"] = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        metrics["memory_used_mb"] = round((mem.total - mem.available) / (1024 * 1024), 1)
        metrics["memory_total_mb"] = round(mem.total / (1024 * 1024), 1)
        metrics["memory_percent"] = mem.percent
        disk = psutil.disk_usage("/")
        metrics["disk_free_gb"] = round(disk.free / (1024 * 1024 * 1024), 1)
        metrics["disk_total_gb"] = round(disk.total / (1024 * 1024 * 1024), 1)
        metrics["disk_percent"] = disk.percent
        metrics["uptime_seconds"] = int(time.time() - psutil.boot_time())
    except ImportError:
        try:
            import os
            load1, load5, _ = os.getloadavg()
            metrics["load_1m"] = round(load1, 2)
            metrics["load_5m"] = round(load5, 2)
        except Exception:
            pass
        try:
            import shutil
            total, _, free = shutil.disk_usage("/")
            metrics["disk_free_gb"] = round(free / (1024 * 1024 * 1024), 1)
            metrics["disk_total_gb"] = round(total / (1024 * 1024 * 1024), 1)
        except Exception:
            pass
    return metrics


class TokenBucket:
    """Bytes-per-second cap on a stream, refilled continuously.

    ``kbps <= 0`` disables it entirely and :meth:`consume` never sleeps, which
    is the default: shaping is opt-in because most agents sit on a link where
    the archive is the least of the traffic. Where it is on, the bucket holds
    one second's worth, so a burst up to the rate goes out immediately and only
    a sustained stream is held back — the shape a link actually needs.

    ``monotonic`` and ``sleep`` are injectable so the tests can assert what was
    waited for instead of waiting for it.
    """

    def __init__(
        self,
        kbps: float,
        *,
        monotonic: Any = time.monotonic,
        sleep: Any = time.sleep,
    ) -> None:
        self.rate = max(0.0, float(kbps)) * 1024.0
        self._monotonic = monotonic
        self._sleep = sleep
        self._capacity = self.rate
        self._tokens = self.rate
        self._updated = monotonic()

    @property
    def enabled(self) -> bool:
        return self.rate > 0

    def consume(self, count: int) -> None:
        """Block until ``count`` bytes may be sent."""
        if not self.enabled or count <= 0:
            return
        remaining = float(count)
        while remaining > 0:
            now = self._monotonic()
            self._tokens = min(
                self._capacity, self._tokens + (now - self._updated) * self.rate
            )
            self._updated = now
            taken = min(remaining, self._tokens)
            self._tokens -= taken
            remaining -= taken
            if remaining <= 0:
                return
            # Drained in instalments rather than granted whole: a chunk larger
            # than one bucketful would otherwise never be granted at all, and
            # the upload would hang instead of going slowly.
            self._sleep(min(remaining, self._capacity) / self.rate)


class _ThrottledBody:
    """The results multipart as a file-like stream, shaped by a token bucket.

    Streamed rather than assembled in memory for two reasons: the archive is
    the one part of this request that has no bound, and a rate limit applied to
    a buffer that was already read is a limit on nothing. ``read`` is the only
    method ``http.client`` calls on a body object.
    """

    def __init__(
        self,
        prefix: bytes,
        archive_path: Path | None,
        suffix: bytes,
        *,
        bucket: TokenBucket,
        chunk_size: int = 65536,
    ) -> None:
        self._prefix = prefix
        self._archive_path = archive_path
        self._suffix = suffix
        self._bucket = bucket
        self._chunk_size = chunk_size
        self._archive_size = (
            archive_path.stat().st_size if archive_path is not None else 0
        )
        self._handle: Any = None
        self._offset = 0

    def __len__(self) -> int:
        return len(self._prefix) + self._archive_size + len(self._suffix)

    def reset(self) -> None:
        self.close()
        self._offset = 0

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def _slice(self, size: int) -> bytes:
        """The next ``size`` bytes of prefix + archive + suffix, unthrottled."""
        prefix_end = len(self._prefix)
        archive_end = prefix_end + self._archive_size
        if self._offset < prefix_end:
            return self._prefix[self._offset : self._offset + size]
        if self._offset < archive_end:
            if self._handle is None:
                self._handle = self._archive_path.open("rb")
                self._handle.seek(self._offset - prefix_end)
            return self._handle.read(min(size, archive_end - self._offset))
        start = self._offset - archive_end
        return self._suffix[start : start + size]

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._chunk_size
        size = min(size, self._chunk_size)
        if self._offset >= len(self):
            self.close()
            return b""
        chunk = self._slice(size)
        if not chunk:  # pragma: no cover - a truncated archive mid-upload
            self.close()
            return b""
        self._bucket.consume(len(chunk))
        self._offset += len(chunk)
        return chunk


class AgentTokenRejected(RuntimeError):
    """The API refused this agent's bearer token (401).

    Its own class so the run loop can tell "this credential is no longer
    accepted" from every other failure and re-exchange the provisioning key
    immediately. Rotating ``OCTO_AGENT_JWT_SECRET`` (or the operator secret it
    is derived from, #312) invalidates every token in the fleet at once, and
    waiting out ``--jwt-refresh-seconds`` would idle every agent for up to half
    an hour after an otherwise instant server-side change.
    """


class AgentDisabled(RuntimeError):
    """An operator disabled or quarantined this agent server-side (#308).

    Distinguished from every other 403 because the answer is to wait, not to
    retry: the state is changed by a person in the console, so polling at the
    normal interval would fill the journal with one refusal per second and put
    a pointless request per second on the API for however long the agent stays
    disabled. The loop backs off to
    ``DISABLED_BACKOFF_SECONDS`` and keeps heartbeating, which is what keeps it
    visible in the fleet view — and what lets it notice being re-enabled.
    """


# Five minutes: long enough that a quarantined fleet is not a load source,
# short enough that re-enabling an agent from the console is felt while the
# operator is still looking at the page.
DISABLED_BACKOFF_SECONDS = 300.0

# How often an agent pulling from NATS also asks the API directly, when no
# offer arrived. The offer is not a guarantee: a job is published once when it
# is queued (and again only if a lease expires), the durable consumer is shared
# by every agent in the (tenant, group), and a NAK — which is what an agent
# refused the job returns, for instance one without the ``scan_policy``
# capability (#362) — burns one of the few delivery attempts the offer has. An
# offer that runs out of attempts leaves the consumer for good, and before this
# the NATS path had no other way to find work: the job sat ``queued`` for ever
# while a capable agent idled next to it. One claim a minute is cheaper than
# that by any measure, and it is the same request the HTTP-mode fleet makes
# every poll interval.
NATS_FALLBACK_CLAIM_SECONDS = 60.0

# Substrings of the API's own refusal (api/services/agents.py::lifecycle_message).
# Matched on the message because a 403 also covers cross-tenant access and the
# agent-id binding, and those two are misconfiguration to be logged loudly, not
# a state to wait out.
_DISABLED_MARKERS = ("is disabled by an operator", "is quarantined by an operator")


class AgentUpgradeRequired(RuntimeError):
    """The API refused the claim because this agent is below its version floor.

    Not retried faster than the poll interval and not fatal: the agent keeps
    registering and heartbeating so it stays visible in the fleet view, which
    is where an operator finds the hosts that need the upgrade (#363).
    """


class AgentClient:
    """Every HTTP call this agent makes, over one proxy-aware opener (#359).

    ``upload_rate_limit_kbps`` is 0 for "as fast as the link goes". Anything
    above that shapes the results upload: a run archive is the largest thing an
    agent sends, and on a branch office's uplink an unshaped one is the reason
    the site's voice traffic stutters for two minutes after every scan.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 60.0,
        upload_rate_limit_kbps: float = 0.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.upload_rate_limit_kbps = max(0.0, upload_rate_limit_kbps)
        # Built once from the base URL: the proxy decision depends on the host
        # and scheme, and every path this client opens shares both.
        self._opener = egress.build_opener(self.base_url)

    def set_token(self, token: str) -> None:
        self.token = token

    def exchange_provisioning_key(
        self,
        provisioning_key: str,
        *,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """POST /api/auth/agent/token — no bearer required.

        ``agent_id`` is sent on every exchange, including the periodic refresh
        (#308). Omitting it makes the server mint a *fresh* random id and put
        it in the token, after which registering or heartbeating as the id this
        process already has is refused as impersonation — an agent that
        re-exchanged on a timer used to lose its own identity that way.
        """
        url = f"{self.base_url}/api/auth/agent/token"
        payload: dict[str, Any] = {"provisioning_key": provisioning_key}
        if agent_id:
            payload["agent_id"] = agent_id
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            # The exchange refuses a disabled or quarantined agent_id too, so
            # it needs the same classification the bearer calls get: without
            # it, the state an operator set would reach the run loop as a bare
            # RuntimeError and be retried at the poll interval forever.
            if exc.code == 403 and any(m in detail for m in _DISABLED_MARKERS):
                raise AgentDisabled(
                    f"POST /api/auth/agent/token -> 403: {detail}"
                ) from exc
            raise RuntimeError(f"POST /api/auth/agent/token -> {exc.code}: {detail}") from exc

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | _ThrottledBody | None = None,
        content_type: str | None = "application/json",
        expect_json: bool = True,
        max_retries: int = 2,
    ) -> Any:
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {self.token}"}
        if body is not None and content_type:
            headers["Content-Type"] = content_type
        if isinstance(body, _ThrottledBody):
            # A streamed body has no len(), and without this urllib falls back
            # to chunked transfer — which the results route answers 411 to,
            # because it checks Content-Length before buffering the multipart.
            headers["Content-Length"] = str(len(body))

        for attempt in range(max_retries + 1):
            if isinstance(body, _ThrottledBody):
                # A retry re-sends from the beginning; a stream already read to
                # its end would otherwise post an empty body and look like the
                # scan produced nothing.
                body.reset()
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    if resp.status == 204 or not raw:
                        return None
                    if expect_json:
                        return json.loads(raw.decode("utf-8"))
                    return raw
            except urllib.error.HTTPError as exc:
                # 413 is absent from the retry list on purpose: the API refuses
                # on Content-Length, before it reads a byte, so the same body
                # gets the same answer — and on a shaped uplink resending it is
                # minutes of the site's bandwidth spent to be told twice more.
                if exc.code in (429, 502, 503, 504) and attempt < max_retries:
                    time.sleep(0.5 * (2**attempt))
                    continue
                detail = exc.read().decode("utf-8", errors="replace")
                if exc.code == 401:
                    raise AgentTokenRejected(f"{method} {path} -> 401: {detail}") from exc
                if exc.code == 426:
                    raise AgentUpgradeRequired(f"{method} {path} -> 426: {detail}") from exc
                if exc.code == 403 and any(m in detail for m in _DISABLED_MARKERS):
                    raise AgentDisabled(f"{method} {path} -> 403: {detail}") from exc
                raise RuntimeError(f"{method} {path} -> {exc.code}: {detail}") from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                # urllib wraps a socket error from the write side in URLError,
                # so the refusal is one attribute down.
                cause = getattr(exc, "reason", exc)
                if isinstance(body, _ThrottledBody) and isinstance(
                    cause, (BrokenPipeError, ConnectionResetError)
                ):
                    # The API stopped reading while the multipart was still
                    # going out. That is what a 413 looks like from this side:
                    # it answers on Content-Length, never drains the body, and
                    # the status line is lost with the socket. Re-reading the
                    # archive off disk and re-shaping it through the token
                    # bucket only spends the site's uplink on the same refusal.
                    raise RuntimeError(
                        f"{method} {path} -> the API closed the connection while the body "
                        f"was being sent ({cause}); a body over "
                        "OCTO_AGENT_RESULTS_MAX_BODY_BYTES is refused this way, so this "
                        "is not retried"
                    ) from exc
                if attempt < max_retries:
                    time.sleep(0.5 * (2**attempt))
                    continue
                raise RuntimeError(f"{method} {path} -> network error: {exc}") from exc

    def register(
        self,
        *,
        agent_id: str | None,
        hostname: str,
        labels: dict[str, str],
    ) -> dict[str, Any]:
        payload = {
            "agent_id": agent_id,
            "hostname": hostname,
            "version": __version__,
            "labels": labels,
            # Sent at registration as well as on every heartbeat: a job whose
            # tenant has a scan policy is refused to an agent that has not
            # declared it can apply one (#362), and this process claims before
            # its first beat.
            "capabilities": list(CAPABILITIES),
        }
        return self._request(
            "POST",
            "/api/agent/register",
            body=json.dumps(payload).encode("utf-8"),
        )

    def heartbeat(
        self,
        agent_id: str,
        *,
        status: str = "idle",
        current_job_id: str | None = None,
        detail: str | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "agent_id": agent_id,
            "status": status,
            "current_job_id": current_job_id,
            "detail": detail,
            "metrics": metrics or _collect_system_metrics(),
            # On *every* heartbeat, not only the first: the API stores the list
            # it was last told, so a beat that omitted it would clear this
            # agent's capabilities and cost it the jobs that need one (#362).
            "capabilities": list(CAPABILITIES),
        }
        return self._request(
            "POST",
            "/api/agent/heartbeat",
            body=json.dumps(payload).encode("utf-8"),
        )

    def claim(self, agent_id: str, *, job_id: str | None = None) -> dict[str, Any] | None:
        query = urllib.parse.urlencode(
            {"agent_id": agent_id, **({"job_id": job_id} if job_id else {})}
        )
        return self._request("POST", f"/api/agent/jobs/claim?{query}")

    def upload_results(
        self,
        job_id: str,
        *,
        agent_id: str,
        exit_code: int,
        run_id: str | None,
        error: str | None,
        archive_path: Path | None,
        attempt: int | None = None,
        cancelled: bool = False,
    ) -> dict[str, Any]:
        boundary = f"----octoagent{int(time.time() * 1000)}"
        parts: list[bytes] = []

        def add_field(name: str, value: str) -> None:
            parts.append(
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                    f"{value}\r\n"
                ).encode("utf-8")
            )

        add_field("agent_id", agent_id)
        add_field("exit_code", str(exit_code))
        # Identifies this completion (server-side ROADMAP P1.5). Derived rather
        # than random so a retry — including one from a restarted process —
        # computes the same key and is recognised as a replay instead of
        # colliding with the upload that already landed.
        add_field(
            "idempotency_key",
            f"{agent_id}:{job_id}:{run_id or ''}:{exit_code}",
        )
        # Fencing token from the claim response: the server rejects an upload
        # from an attempt whose lease has already expired and been reissued.
        if attempt is not None:
            add_field("attempt", str(attempt))
        # Only when it is true: an older API ignores a form field it does not
        # know, but sending it on every upload would be noise (#360).
        if cancelled:
            add_field("cancelled", "true")
        if run_id:
            add_field("run_id", run_id)
        if error:
            add_field("error", error[:2000])

        archive = archive_path if archive_path is not None and archive_path.is_file() else None
        if archive is not None:
            parts.append(
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="archive"; filename="run.tar.gz"\r\n'
                    f"Content-Type: application/gzip\r\n\r\n"
                ).encode("utf-8")
            )

        # The archive sits between the two, read from disk as the socket takes
        # it rather than buffered here — see _ThrottledBody.
        prefix = b"".join(parts)
        suffix = (b"\r\n" if archive is not None else b"") + f"--{boundary}--\r\n".encode("utf-8")
        body = _ThrottledBody(
            prefix,
            archive,
            suffix,
            bucket=TokenBucket(self.upload_rate_limit_kbps),
        )
        try:
            return self._request(
                "POST",
                f"/api/agent/jobs/{job_id}/results",
                body=body,
                content_type=f"multipart/form-data; boundary={boundary}",
            )
        finally:
            body.close()


def _write_inputs(workdir: Path, inputs: dict[str, str]) -> list[str]:
    args: list[str] = []
    if "ranges.txt" in inputs or "domains.txt" in inputs:
        ranges_path = workdir / "ranges.txt"
        domains_path = workdir / "domains.txt"
        ranges_path.write_text(inputs.get("ranges.txt", ""), encoding="utf-8")
        domains_path.write_text(inputs.get("domains.txt", ""), encoding="utf-8")
        args.extend(["--ranges", str(ranges_path), "--domains", str(domains_path)])
    if "ports.txt" in inputs:
        ports_path = workdir / "ports.txt"
        ports_path.write_text(inputs["ports.txt"], encoding="utf-8")
        args.extend(["--ports-file", str(ports_path)])
    if "ports_udp.txt" in inputs:
        ports_udp_path = workdir / "ports_udp.txt"
        ports_udp_path.write_text(inputs["ports_udp.txt"], encoding="utf-8")
        args.extend(["--ports-udp-file", str(ports_udp_path)])
    if "scan_scope.json" in inputs:
        # The tenant's approved scope (#244). Handed through unread: this worker
        # has no opinion about it, and the pipeline that resolves the names is
        # the only place that can hold the resulting addresses to it.
        scope_path = workdir / "scan_scope.json"
        scope_path.write_text(inputs["scan_scope.json"], encoding="utf-8")
        args.extend(["--scan-scope", str(scope_path)])
    if "scan_policy.json" in inputs:
        # The tenant's scan policy (#362): rate ceilings, host concurrency and
        # the ports this run must not touch, decided by the API. Handed through
        # unread like the scope above — the pipeline applies it onto the local
        # config, where it can only ever lower a rate, and this worker has no
        # opinion about it. The ``scan_policy`` capability this agent declares
        # is the promise to pass it on; an agent that did not would be refused
        # the job on claim.
        policy_path = workdir / "scan_policy.json"
        policy_path.write_text(inputs["scan_policy.json"], encoding="utf-8")
        args.extend(["--scan-policy", str(policy_path)])
    if "promoted_domains.txt" in inputs:
        # Related domains the tenant promoted (org_profile M4). Also handed
        # through unread: the pipeline merges them into its name scope and
        # holds them to the scope above like every other name.
        promoted_path = workdir / "promoted_domains.txt"
        promoted_path.write_text(inputs["promoted_domains.txt"], encoding="utf-8")
        args.extend(["--promoted-domains", str(promoted_path)])
    return args


def _tar_directory(source: Path, archive_path: Path) -> None:
    with tarfile.open(archive_path, "w:gz") as tf:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                tf.add(path, arcname=str(path.relative_to(source)))


def _detect_current_stage(output_dir: Path | None, run_id: str | None) -> str | None:
    if output_dir is None or run_id is None:
        return None
    run_dir = output_dir / "runs" / run_id
    if not run_dir.is_dir():
        return None
    # 1. Inspect stage_timings.json for completed stages
    timings_file = run_dir / "stage_timings.json"
    if timings_file.is_file():
        try:
            data = json.loads(timings_file.read_text(encoding="utf-8"))
            stages = data.get("stages") or []
            if stages:
                last_stage = stages[-1].get("name")
                if last_stage:
                    return str(last_stage)
        except Exception:
            pass
    # 2. Inspect checkpoint.json
    checkpoint_file = run_dir / "checkpoint.json"
    if checkpoint_file.is_file():
        try:
            data = json.loads(checkpoint_file.read_text(encoding="utf-8"))
            completed = data.get("completed_stages") or []
            if completed:
                return str(completed[-1])
        except Exception:
            pass
    return None


#: How often the scan wait wakes up to look at ``cancel_event``. Short enough
#: that a stop requested on one heartbeat is acted on within a second of the
#: response arriving, cheap enough to do for two hours: it is one ``poll()`` on
#: a pipe, not a syscall storm.
_CANCEL_POLL_SECONDS = 1.0


def _terminate_process_group(proc: "subprocess.Popen[str]", *, use_session: bool) -> None:
    """Put down the scanner and everything it started.

    The process group rather than the process: a scan is ``scanner.main``
    shelling out to nmap, httpx and nuclei, and killing only the parent would
    leave the tool that is actually touching the target running with no one to
    report it. SIGTERM first so the pipeline can close its files, SIGKILL five
    seconds later for whatever ignored it.
    """
    if not use_session:
        proc.kill()
        proc.wait()
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5.0)
    except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5.0)


def _run_scan(
    *,
    config: Path,
    job: dict[str, Any],
    workdir: Path,
    output_dir: Path,
    timeout: float | None = 7200.0,
    cancel_event: threading.Event | None = None,
) -> tuple[int, str | None, Path | None]:
    target_args = _write_inputs(workdir, dict(job.get("inputs") or {}))
    run_id = str(job["run_id"])
    command = [
        sys.executable,
        "-m",
        "scanner.main",
        "--config",
        str(config),
        "--mode",
        str(job.get("mode") or "balanced"),
        "--run-id",
        run_id,
    ]
    if job.get("delta"):
        command.append("--delta")
    if job.get("skip_nse"):
        command.append("--skip-nse")
    if job.get("notify"):
        command.append("--notify")
    if job.get("export_defectdojo"):
        command.append("--export-defectdojo")
    command.extend(target_args)

    LOG.info("Running: %s", " ".join(command))

    use_session = sys.platform != "win32"
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=use_session,
        )
    except Exception as exc:
        return 1, f"failed to spawn scan process: {exc}", None

    # Waited on in short slices rather than one long ``communicate(timeout=…)``
    # so the cancellation the heartbeat thread may set is noticed while the
    # scan runs, not two hours later (#360). Retrying ``communicate`` after a
    # TimeoutExpired is the documented way to keep waiting on the same pipes.
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        try:
            stdout, stderr = proc.communicate(timeout=_CANCEL_POLL_SECONDS)
            break
        except subprocess.TimeoutExpired:
            if cancel_event is not None and cancel_event.is_set():
                LOG.warning("Scan run %s cancelled by the API; terminating process group", run_id)
                _terminate_process_group(proc, use_session=use_session)
                # Whatever the pipeline had written before the signal is still
                # this scan's output, and the operator who stopped it asked for
                # a stop, not for the partial findings to be thrown away. The
                # archive is best-effort: a run killed early may have no
                # directory at all.
                return 143, "cancelled on the operator's request", _archive_run(
                    output_dir, workdir, run_id
                )
            if deadline is not None and time.monotonic() >= deadline:
                LOG.warning(
                    "Scan run %s timed out after %ss; terminating process group", run_id, timeout
                )
                _terminate_process_group(proc, use_session=use_session)
                return 124, f"scan timed out after {timeout}s", None

    if proc.returncode != 0:
        err = (stderr or stdout or f"exit {proc.returncode}")[:2000]
        return proc.returncode, err, None

    run_dir = output_dir / "runs" / run_id
    if not run_dir.is_dir():
        return 1, f"expected run directory missing: {run_dir}", None

    archive_path = workdir / f"{run_id}.tar.gz"
    _tar_directory(run_dir, archive_path)
    return 0, None, archive_path


def _archive_run(output_dir: Path, workdir: Path, run_id: str) -> Path | None:
    """Tar whatever the run wrote, or ``None`` if it wrote nothing usable.

    Only the cancelled path uses this: a finished run is archived above and its
    missing directory is an error worth reporting, while a scan that was put
    down half-way legitimately may not have created one yet. A failure to pack
    is logged and swallowed — the cancellation must still be reported.
    """
    run_dir = output_dir / "runs" / run_id
    if not run_dir.is_dir():
        return None
    archive_path = workdir / f"{run_id}.tar.gz"
    try:
        _tar_directory(run_dir, archive_path)
    except OSError:
        LOG.warning("Could not archive the partial results of run %s", run_id, exc_info=True)
        return None
    return archive_path


@contextlib.contextmanager
def _busy_heartbeats(
    client: AgentClient,
    *,
    agent_id: str,
    job_id: str,
    run_id: str | None = None,
    output_dir: Path | None = None,
    interval: float,
    cancel_event: threading.Event | None = None,
) -> Iterator[None]:
    """Keep reporting this job for as long as the scan runs with live telemetry.

    The server leases in-flight jobs and treats a lapsed lease as a dead worker
    (ROADMAP P1.4), and the heartbeat is what renews it. One heartbeat at the
    start would therefore have any scan longer than the lease requeued and
    handed to a second agent while the first is still scanning the same
    targets. Failures are logged and retried on the next tick — a blip in the
    control plane must not abort a running scan.

    It is also the channel the other way (#360): the response says whether an
    operator has asked for this job to stop, and setting ``cancel_event`` is
    what tells the scan wait to put the process group down. A failed heartbeat
    therefore delays a cancellation by one interval rather than losing it — the
    API keeps answering ``cancel_requested`` until the agent confirms.
    """
    stop = threading.Event()
    t0 = time.perf_counter()

    def _loop() -> None:
        while not stop.wait(interval):
            try:
                elapsed_sec = int(time.perf_counter() - t0)
                stage = _detect_current_stage(output_dir, run_id)
                detail = f"stage={stage or 'running'} elapsed={elapsed_sec}s"
                beat = client.heartbeat(
                    agent_id, status="busy", current_job_id=job_id, detail=detail
                )
                if cancel_event is not None and (beat or {}).get("cancel_requested"):
                    LOG.warning("API requested cancellation of job %s", job_id)
                    cancel_event.set()
                    # Nothing left to report: the scan wait acts on the event
                    # and the result upload is the next thing the API hears.
                    return
            except Exception:  # noqa: BLE001
                LOG.warning("Heartbeat failed for job %s", job_id, exc_info=True)

    thread = threading.Thread(target=_loop, name=f"octo-heartbeat-{job_id}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=2.0)


def _execute_job(
    client: AgentClient,
    *,
    agent_id: str,
    job: dict[str, Any],
    config: Path,
    output_dir: Path,
    heartbeat_interval: float = HEARTBEAT_INTERVAL_SECONDS,
    scan_timeout: float | None = 7200.0,
) -> None:
    LOG.info("Claimed job %s run_id=%s", job["job_id"], job["run_id"])
    cancel_event = threading.Event()
    beat = client.heartbeat(
        agent_id,
        status="busy",
        current_job_id=job["job_id"],
        detail=f"stage=starting run_id={job['run_id']}",
    )
    # A stop requested between the claim and this line is already waiting in
    # the first response, and starting the scan only to kill it a minute later
    # would put the targets through a sweep nobody wants (#360).
    if (beat or {}).get("cancel_requested"):
        LOG.warning("Job %s was cancelled before the scan started", job["job_id"])
        cancel_event.set()
    with tempfile.TemporaryDirectory(prefix="octo-agent-") as tmp:
        workdir = Path(tmp)
        if cancel_event.is_set():
            exit_code, error, archive = 143, "cancelled before the scan started", None
        else:
            with _busy_heartbeats(
                client,
                agent_id=agent_id,
                job_id=job["job_id"],
                run_id=str(job["run_id"]),
                output_dir=output_dir,
                interval=heartbeat_interval,
                cancel_event=cancel_event,
            ):
                exit_code, error, archive = _run_scan(
                    config=config,
                    job=job,
                    workdir=workdir,
                    output_dir=output_dir,
                    timeout=scan_timeout,
                    cancel_event=cancel_event,
                )
        cancelled = cancel_event.is_set() and exit_code != 0
        client.upload_results(
            job["job_id"],
            agent_id=agent_id,
            attempt=job.get("attempt"),
            exit_code=exit_code,
            run_id=str(job["run_id"]),
            error=error,
            archive_path=archive,
            # ...and a clean exit is reported as one even here: the scan can
            # finish by itself in the second between the stop being set and the
            # wait noticing it, and calling a completed run cancelled would
            # throw away a whole sweep's findings to match the request (#360).
            cancelled=cancelled,
        )
    LOG.info(
        "Job %s finished exit=%s%s", job["job_id"], exit_code, " (cancelled)" if cancelled else ""
    )


class AgentNatsSession:
    """Long-lived JetStream pull session for the subjects this agent may consume.

    ``tenant_id`` is the tenant the API told this agent it belongs to, and
    ``agent_group`` is the group the API says an operator put it in — neither
    is the agent's to choose, and both come back on every register and
    heartbeat. Together they decide the subjects and the durable names, so the
    session never sees, and cannot bind to, another tenant's or another
    group's offers.

    An ungrouped agent binds one subject, ``jobs.scan.{tenant}``. A grouped one
    binds that plus ``jobs.scan.{tenant}.{group}``: putting an agent into a
    group narrows what it may reach without taking away the tenant-wide queue
    it already served, which is exactly what ``claim_job``'s SQL filter says.
    """

    def __init__(
        self,
        nats_url: str,
        *,
        tenant_id: str = DEFAULT_TENANT_ID,
        agent_group: str | None = None,
        connect_timeout: float = 5.0,
    ) -> None:
        self._nats_url = nats_url
        self._tenant_id = tenant_id or DEFAULT_TENANT_ID
        self._agent_group = agent_group or None
        # Ungrouped subject first: the tenant-wide queue is the one every agent
        # shares, and draining it before the group's keeps a busy group from
        # starving jobs nobody restricted.
        self._bindings: list[tuple[str, str]] = [
            (jobs_scan_subject(self._tenant_id), jobs_consumer_name(self._tenant_id))
        ]
        if self._agent_group:
            self._bindings.append(
                (
                    jobs_scan_subject(self._tenant_id, self._agent_group),
                    jobs_consumer_name(self._tenant_id, self._agent_group),
                )
            )
        self._connect_timeout = connect_timeout
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name="octo-agent-nats", daemon=True
        )
        self._nc: Any = None
        self._subs: list[Any] = []
        self._started = False
        self._lock = threading.Lock()

    @property
    def agent_group(self) -> str | None:
        """The group this session was bound for; see ``run_loop`` for rebinding."""
        return self._agent_group

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._thread.start()
            fut = asyncio.run_coroutine_threadsafe(self._connect(), self._loop)
            fut.result(timeout=self._connect_timeout + 10)
            self._started = True
            LOG.info(
                "NATS agent session connected (%s) subjects=%s group=%s",
                self._nats_url,
                ", ".join(subject for subject, _ in self._bindings),
                self._agent_group or "-",
            )

    async def _connect(self) -> None:
        import nats
        from nats.js.api import AckPolicy, ConsumerConfig

        self._nc = await nats.connect(
            self._nats_url,
            name="shapoclyack-agent",
            connect_timeout=self._connect_timeout,
            max_reconnect_attempts=-1,
            reconnect_time_wait=1,
            **tls_connect_options(),
        )
        js = self._nc.jetstream()
        self._subs = []
        for subject, durable in self._bindings:
            try:
                sub = await js.pull_subscribe(subject, durable=durable, stream=STREAM_JOBS)
            except Exception:
                await js.add_consumer(
                    STREAM_JOBS,
                    ConsumerConfig(
                        durable_name=durable,
                        ack_policy=AckPolicy.EXPLICIT,
                        filter_subject=subject,
                        max_deliver=JOBS_MAX_DELIVER,
                    ),
                )
                sub = await js.pull_subscribe(subject, durable=durable, stream=STREAM_JOBS)
            self._subs.append(sub)

    async def _close_connection(self) -> None:
        """Let nats-py stop its own background tasks before the loop is closed."""
        connection = self._nc
        if connection is None:
            return
        try:
            if not connection.is_closed:
                await connection.drain()
        except Exception:  # noqa: BLE001
            LOG.debug("Failed to drain NATS agent connection", exc_info=True)
        try:
            if not connection.is_closed:
                await connection.close()
        except Exception:  # noqa: BLE001
            LOG.debug("Failed to close NATS agent connection", exc_info=True)
        # Give nats-py's completion callbacks one final event-loop turn. The old
        # implementation cancelled every task in the loop, including the
        # client's flusher, which produced GeneratorExit/Event-loop-closed
        # warnings during Python 3.11 CI teardown.
        await asyncio.sleep(0)

    def close(self) -> None:
        with self._lock:
            loop = self._loop
            if self._nc is not None and loop.is_running():
                try:
                    fut = asyncio.run_coroutine_threadsafe(self._close_connection(), loop)
                    fut.result(timeout=5)
                except Exception:  # noqa: BLE001
                    LOG.debug("Failed to shut down NATS agent session cleanly", exc_info=True)

            if loop.is_running():
                loop.call_soon_threadsafe(loop.stop)

            self._nc = None
            self._subs = []

            if self._thread.is_alive() and threading.current_thread() is not self._thread:
                self._thread.join(timeout=5)
            if self._thread.is_alive():
                LOG.warning("NATS agent event-loop thread did not stop within timeout")
            elif not loop.is_running() and not loop.is_closed():
                loop.close()
            self._started = False

    def _ensure_ready(self) -> None:
        if self._started and self._nc is not None and self._subs:
            try:
                if self._nc.is_connected:
                    return
            except Exception:  # noqa: BLE001
                pass
        self.close()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name="octo-agent-nats", daemon=True
        )
        self._started = False
        self.start()

    def pull_and_claim(
        self,
        client: AgentClient,
        agent_id: str,
        *,
        timeout: float = 5.0,
    ) -> dict[str, Any] | None:
        """Fetch one offer, HTTP-claim it, then ACK/TERM. Reconnects if the session drops.

        The offer carries no targets: the claim response does, and only the
        agent the API bound the job to gets one (#361).
        """
        self._ensure_ready()

        async def _one_sub(sub: Any, per_sub_timeout: float) -> dict[str, Any] | None:
            from nats.errors import TimeoutError as NatsTimeout

            try:
                msgs = await sub.fetch(1, timeout=per_sub_timeout)
            except NatsTimeout:
                return None
            if not msgs:
                return None
            msg = msgs[0]
            try:
                payload = json.loads(msg.data.decode("utf-8"))
            except json.JSONDecodeError:
                await msg.term()
                return None
            if not isinstance(payload, dict) or not payload.get("job_id"):
                await msg.term()
                return None
            # Terminate rather than NAK on anything this agent is not entitled
            # to run: a NAK puts the message back for redelivery and burns one
            # of its max_deliver attempts, so an agent that cannot run the job
            # would be deciding how many attempts its rightful owner has left —
            # and once the attempts are gone the offer leaves the consumer and
            # the job's own agents never see it. The subject filters should
            # make both checks unreachable; they are the second barrier.
            offer_tenant = str(payload.get("tenant_id") or DEFAULT_TENANT_ID)
            if _subject_token(offer_tenant) != _subject_token(self._tenant_id):
                LOG.warning(
                    "Discarding offer %s for tenant %s on tenant %s subject",
                    payload.get("job_id"),
                    offer_tenant,
                    self._tenant_id,
                )
                await msg.term()
                return None
            offer_group = str(payload.get("agent_group") or "") or None
            if offer_group is not None and offer_group != self._agent_group:
                LOG.warning(
                    "Discarding offer %s addressed to agent group %s; this agent is in %s",
                    payload.get("job_id"),
                    offer_group,
                    self._agent_group or "no group",
                )
                await msg.term()
                return None
            job_id = str(payload["job_id"])
            try:
                claimed = await asyncio.to_thread(client.claim, agent_id, job_id=job_id)
            except (AgentDisabled, AgentUpgradeRequired, AgentTokenRejected):
                # This agent cannot take the offer, but another one entitled to
                # the same subject can: NAK now rather than hold the message
                # until ack_wait expires, and let the run loop decide what to
                # do about the refusal (#308).
                await msg.nak()
                raise
            if claimed is None:
                # 204: the job is no longer queued — another agent on this same
                # subject won the race, or it was cancelled. TERM rather than
                # NAK, because a redelivery cannot make an already-claimed job
                # claimable again; a job that goes back to ``queued`` when its
                # lease expires is re-offered by the API, as a new message.
                LOG.info("NATS offer %s already taken; discarding", job_id)
                await msg.term()
                return None
            await msg.ack()
            return claimed

        async def _once() -> dict[str, Any] | None:
            subs = list(self._subs)
            if not subs:
                return None
            share = max(1.0, timeout / len(subs))
            for sub in subs:
                claimed = await _one_sub(sub, share)
                if claimed is not None:
                    return claimed
            return None

        try:
            fut = asyncio.run_coroutine_threadsafe(_once(), self._loop)
            return fut.result(timeout=timeout + 30)
        except (AgentDisabled, AgentUpgradeRequired, AgentTokenRejected):
            # Raised by the HTTP claim above, not by NATS. Swallowing these as
            # "will reconnect" tore down a healthy session on every poll and
            # cost the agent the backoff and the token re-exchange the HTTP
            # path gets — the NATS half of the fleet never had either (#308).
            raise
        except Exception:  # noqa: BLE001
            LOG.exception("NATS pull/claim failed; will reconnect")
            self.close()
            return None


def run_loop(args: argparse.Namespace) -> int:
    client = AgentClient(
        args.api_url,
        args.token or "pending",
        timeout=args.timeout,
        upload_rate_limit_kbps=getattr(args, "upload_rate_limit_kbps", 0.0),
    )
    # Logged once at start because "the agent cannot reach the API" is answered
    # by this line and by nothing else on the box.
    LOG.info("Egress to %s: %s", args.api_url, egress.describe(args.api_url))
    if args.nats_url:
        check_nats_transport(args.nats_url)
    # The provisioning-key exchange itself happens inside the run loop below,
    # where a refusal is backed off instead of killing the process (#308).
    if not args.provisioning_key and not args.token:
        LOG.error("OCTO_AGENT_TOKEN / --token or OCTO_AGENT_PROVISIONING_KEY is required")
        return 2

    labels = {}
    if args.label:
        for item in args.label:
            if "=" in item:
                key, value = item.split("=", 1)
                labels[key.strip()] = value.strip()

    hostname = args.hostname or socket.gethostname()

    # The identity this process keeps for the rest of its life. Seeded from
    # OCTO_AGENT_ID when the installer wrote one, adopted from the first
    # exchange when it did not, and from then on sent with *every* exchange —
    # a refresh that omitted it used to hand the process a token for a
    # different agent, after which its own heartbeat was 403 (#308).
    agent_id: str = (args.agent_id or "").strip()
    tenant_id = ""
    # The group an operator put this agent in, as the API reports it on every
    # register and heartbeat. Never read from ``labels``: an agent that could
    # declare its own group would be granting itself the jobs of a segment it
    # does not sit in (#361).
    agent_group: str | None = None
    nats_session: AgentNatsSession | None = None
    # When the NATS path next double-checks the queue over HTTP. Due at once,
    # so an agent starting up next to a job whose offer has already been burned
    # picks it up rather than waiting out the first interval.
    nats_fallback_claim_at = 0.0
    registered = False
    # Due immediately with a provisioning key (the bootstrap exchange happens
    # inside the loop, so a refusal is backed off instead of killing the
    # process); never with a legacy shared token, which is not exchanged.
    token_refresh_at = 0.0 if args.provisioning_key else float("inf")

    shutdown_event = threading.Event()
    last_upgrade_message = ""
    last_lifecycle_message = ""
    last_backoff_message = ""

    def _sig_handler(signum: int, frame: Any) -> None:
        LOG.info("Received signal %s, initiating graceful shutdown", signum)
        shutdown_event.set()

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _sig_handler)
            except (ValueError, AttributeError):
                pass

    def _exchange() -> None:
        nonlocal agent_id, tenant_id, token_refresh_at, registered
        exchanged = client.exchange_provisioning_key(
            args.provisioning_key, agent_id=agent_id or None
        )
        client.set_token(str(exchanged["access_token"]))
        expires = int(exchanged.get("expires_in") or 3600)
        token_refresh_at = time.time() + max(
            60, args.jwt_refresh_seconds or (expires // 2)
        )
        tenant_id = str(exchanged.get("tenant_id") or "") or tenant_id
        minted = str(exchanged.get("agent_id") or "")
        if minted and minted != agent_id:
            # Only reachable on the bootstrap exchange of an agent with no
            # OCTO_AGENT_ID: the server minted one, and this process is that
            # agent from here on.
            agent_id = minted
            registered = False
        LOG.info(
            "Exchanged provisioning key for agent JWT (agent=%s tenant=%s expires_in=%ss)",
            agent_id,
            exchanged.get("tenant_id"),
            exchanged.get("expires_in"),
        )

    def _register() -> None:
        nonlocal agent_id, tenant_id, agent_group, registered
        info = client.register(
            agent_id=agent_id or None,
            hostname=hostname,
            labels=labels,
        )
        agent_id = str(info["agent_id"])
        # The registration response is authoritative for the legacy shared
        # token, which is exchanged for nothing and whose tenant the agent
        # cannot know on its own (api.auth.LEGACY_AGENT_TENANT_ID = "default").
        tenant_id = tenant_id or str(info.get("tenant_id") or DEFAULT_TENANT_ID)
        agent_group = str(info.get("agent_group") or "") or None
        registered = True
        LOG.info(
            "Registered agent %s (%s) tenant=%s group=%s",
            agent_id,
            info.get("hostname"),
            info.get("tenant_id"),
            agent_group or "-",
        )

    try:
        while not shutdown_event.is_set():
            try:
                if args.provisioning_key and time.time() >= token_refresh_at:
                    _exchange()
                if not registered:
                    # Inside the loop, and inside the same handlers as every
                    # other call: a quarantined agent is refused *here*, and
                    # before #308 that refusal escaped run_loop and killed the
                    # process — which systemd Restart=always then repeated
                    # every five seconds for the whole fleet.
                    _register()
                if (
                    nats_session is not None
                    and nats_session.agent_group != agent_group
                ):
                    # An operator moved this agent between groups. The bindings
                    # are decided at connect time, so the session is rebuilt
                    # rather than left listening on the subjects of a group the
                    # agent is no longer in.
                    LOG.info(
                        "Agent group changed to %s; rebinding the NATS session",
                        agent_group or "none",
                    )
                    nats_session.close()
                    nats_session = None
                if nats_session is None and args.nats_url:
                    LOG.info(
                        "NATS pull enabled (%s) subject=%s group=%s",
                        args.nats_url,
                        jobs_scan_subject(tenant_id),
                        agent_group or "-",
                    )
                    nats_session = AgentNatsSession(
                        args.nats_url, tenant_id=tenant_id, agent_group=agent_group
                    )
                    nats_session.start()

                beat = client.heartbeat(agent_id, status="idle")
                message = str((beat or {}).get("upgrade_message") or "")
                if message and message != last_upgrade_message:
                    # Logged on change only: the API repeats it on every
                    # heartbeat, and an agent that cannot claim work would
                    # otherwise fill its journal with one line per poll.
                    LOG.error("%s", message)
                last_upgrade_message = message
                # The heartbeat is answered even while an agent is disabled or
                # quarantined (#308), so this is where it finds out — before
                # the claim below is refused, and with the operator's reason.
                # The group can change while the process runs; the heartbeat
                # response is where it finds out, and the rebinding above acts
                # on it at the top of the next iteration.
                agent_group = str((beat or {}).get("agent_group") or "") or None
                lifecycle_message = str((beat or {}).get("lifecycle_message") or "")
                if lifecycle_message and lifecycle_message != last_lifecycle_message:
                    LOG.error("%s", lifecycle_message)
                last_lifecycle_message = lifecycle_message
                job: dict[str, Any] | None = None
                if nats_session is not None:
                    job = nats_session.pull_and_claim(
                        client, agent_id, timeout=max(1.0, args.poll_interval)
                    )
                    if job is None and time.time() >= nats_fallback_claim_at:
                        # The safety net, not the normal path: see
                        # NATS_FALLBACK_CLAIM_SECONDS. Queued work whose offer
                        # is gone is found here, and nowhere else.
                        nats_fallback_claim_at = time.time() + NATS_FALLBACK_CLAIM_SECONDS
                        job = client.claim(agent_id)
                else:
                    job = client.claim(agent_id)

                if job is None:
                    if nats_session is None:
                        time.sleep(args.poll_interval)
                    continue

                _execute_job(
                    client,
                    agent_id=agent_id,
                    job=job,
                    config=Path(args.config),
                    output_dir=Path(args.output_dir),
                    scan_timeout=getattr(args, "scan_timeout", 7200.0),
                )
            except KeyboardInterrupt:
                LOG.info("Shutting down")
                return 0
            except AgentTokenRejected as exc:
                if not args.provisioning_key:
                    LOG.error("Agent token rejected and no provisioning key to re-exchange: %s", exc)
                    time.sleep(args.poll_interval)
                    continue
                # Due now, not at the next scheduled refresh: the token is
                # already worthless, so every poll until then would fail.
                token_refresh_at = 0.0
                LOG.warning("Agent token rejected; re-exchanging the provisioning key: %s", exc)
                time.sleep(min(args.poll_interval, 5.0))
            except AgentUpgradeRequired as exc:
                LOG.error("Job claim refused: %s", exc)
                time.sleep(args.poll_interval)
            except AgentDisabled as exc:
                # Logged on change only, for the reason upgrade_message is: the
                # API repeats the refusal on every poll, and at the normal
                # interval that is one journal line per second for as long as
                # an operator leaves the agent disabled.
                message = str(exc)
                if message != last_backoff_message:
                    LOG.error(
                        "Refused by the control plane; backing off %.0fs: %s",
                        DISABLED_BACKOFF_SECONDS,
                        message,
                    )
                last_backoff_message = message
                # Interruptible, so SIGTERM still stops the agent promptly
                # instead of after however much of the backoff is left.
                shutdown_event.wait(DISABLED_BACKOFF_SECONDS)
            except Exception:  # noqa: BLE001
                LOG.exception("Agent loop error")
                time.sleep(args.poll_interval)
    finally:
        if nats_session is not None:
            nats_session.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Shapoclyack remote scanner agent")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("OCTO_API_URL", "http://127.0.0.1:8080"),
        help="API base URL (or OCTO_API_URL)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("OCTO_AGENT_TOKEN", ""),
        help="Legacy shared agent bearer token (or OCTO_AGENT_TOKEN)",
    )
    parser.add_argument(
        "--provisioning-key",
        default=os.environ.get("OCTO_AGENT_PROVISIONING_KEY", ""),
        help="Phase 2 provisioning key (exchanged for agent JWT); or OCTO_AGENT_PROVISIONING_KEY",
    )
    parser.add_argument(
        "--jwt-refresh-seconds",
        type=int,
        default=int(os.environ.get("OCTO_AGENT_JWT_REFRESH_SECONDS", "0")),
        help="Override JWT refresh interval when using provisioning key (0 = half of expires_in)",
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("OCTO_CONFIG", "scanner/config/default.yaml"),
        help="Local scanner config path",
    )
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("OCTO_OUTPUT_DIR", "scanner/output"),
        help="Local scanner output dir (run artifacts are read from here)",
    )
    parser.add_argument(
        "--scan-timeout",
        type=float,
        default=float(os.environ.get("OCTO_AGENT_SCAN_TIMEOUT_SECONDS", "7200")),
        help="Maximum duration for a single scan execution in seconds (default: 7200)",
    )
    parser.add_argument("--agent-id", default=os.environ.get("OCTO_AGENT_ID"), help="Stable agent id")
    parser.add_argument("--hostname", default=os.environ.get("OCTO_AGENT_HOSTNAME"), help="Agent hostname")
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="Label key=value (repeatable)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.environ.get("OCTO_AGENT_POLL_INTERVAL", "5")),
    )
    parser.add_argument(
        "--nats-url",
        default=os.environ.get("OCTO_NATS_URL", ""),
        help=(
            "NATS JetStream URL for job pull (or OCTO_NATS_URL); nats://, tls:// or "
            "wss://. Empty = HTTP claim poll, which is the only mode that goes "
            "through an HTTP proxy"
        ),
    )
    parser.add_argument(
        "--upload-rate-limit-kbps",
        type=float,
        default=float(os.environ.get("OCTO_AGENT_UPLOAD_RATE_LIMIT_KBPS", "0")),
        help=(
            "Shape the results upload to this many KiB/s (or "
            "OCTO_AGENT_UPLOAD_RATE_LIMIT_KBPS); 0 = no limit"
        ),
    )
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # --verbose still wins over OCTO_LOG_LEVEL: it is the flag an operator
    # reaches for while watching one run, and having the environment override
    # it would make the flag look broken (#330).
    logging_setup.configure_logging(level=logging.DEBUG if args.verbose else None)
    if not args.token and not args.provisioning_key:
        LOG.error("OCTO_AGENT_TOKEN / --token or OCTO_AGENT_PROVISIONING_KEY is required")
        return 2
    return run_loop(args)


# `python -m agent.worker` used to import this module as __main__, define
# main(), and exit 0 without ever calling it — a silent no-op that looked like
# a clean start, and that systemd then restarted forever under Restart=always.
# `python -m agent` (agent/__main__.py) remains the documented entry point;
# this guard makes the other spelling do the same thing instead of nothing.
if __name__ == "__main__":
    raise SystemExit(main())
