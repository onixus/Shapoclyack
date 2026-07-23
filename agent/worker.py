"""Poll the Octo-man API for agent jobs and run the local scanner.

When OCTO_NATS_URL is set, jobs are pulled from JetStream subject ``jobs.scan``
(durable consumer ``octo-agents``) via a long-lived connection instead of HTTP
claim polling. Register, heartbeat, and results upload remain HTTP.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from agent import __version__

LOG = logging.getLogger("octo-agent")

SUBJECT_JOBS_SCAN = "jobs.scan"
STREAM_JOBS = "JOBS"
CONSUMER_AGENTS = "octo-agents"


class AgentClient:
    def __init__(self, base_url: str, token: str, *, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def set_token(self, token: str) -> None:
        self.token = token

    def exchange_provisioning_key(self, provisioning_key: str) -> dict[str, Any]:
        """POST /api/auth/agent/token — no bearer required."""
        url = f"{self.base_url}/api/auth/agent/token"
        body = json.dumps({"provisioning_key": provisioning_key}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"POST /api/auth/agent/token -> {exc.code}: {detail}") from exc

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        content_type: str | None = "application/json",
        expect_json: bool = True,
    ) -> Any:
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {self.token}"}
        if body is not None and content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if resp.status == 204 or not raw:
                    return None
                if expect_json:
                    return json.loads(raw.decode("utf-8"))
                return raw
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} -> {exc.code}: {detail}") from exc

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
    ) -> dict[str, Any]:
        payload = {
            "agent_id": agent_id,
            "status": status,
            "current_job_id": current_job_id,
            "detail": detail,
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
        if run_id:
            add_field("run_id", run_id)
        if error:
            add_field("error", error[:2000])

        if archive_path is not None and archive_path.is_file():
            data = archive_path.read_bytes()
            parts.append(
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="archive"; filename="run.tar.gz"\r\n'
                    f"Content-Type: application/gzip\r\n\r\n"
                ).encode("utf-8")
            )
            parts.append(data)
            parts.append(b"\r\n")

        parts.append(f"--{boundary}--\r\n".encode("utf-8"))
        body = b"".join(parts)
        return self._request(
            "POST",
            f"/api/agent/jobs/{job_id}/results",
            body=body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )


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
    return args


def _tar_directory(source: Path, archive_path: Path) -> None:
    with tarfile.open(archive_path, "w:gz") as tf:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                tf.add(path, arcname=str(path.relative_to(source)))


def _run_scan(
    *,
    config: Path,
    job: dict[str, Any],
    workdir: Path,
    output_dir: Path,
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
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or f"exit {completed.returncode}")[:2000]
        return completed.returncode, err, None

    run_dir = output_dir / "runs" / run_id
    if not run_dir.is_dir():
        return 1, f"expected run directory missing: {run_dir}", None

    archive_path = workdir / f"{run_id}.tar.gz"
    _tar_directory(run_dir, archive_path)
    return 0, None, archive_path


def _execute_job(
    client: AgentClient,
    *,
    agent_id: str,
    job: dict[str, Any],
    config: Path,
    output_dir: Path,
) -> None:
    LOG.info("Claimed job %s run_id=%s", job["job_id"], job["run_id"])
    client.heartbeat(agent_id, status="busy", current_job_id=job["job_id"])
    with tempfile.TemporaryDirectory(prefix="octo-agent-") as tmp:
        workdir = Path(tmp)
        exit_code, error, archive = _run_scan(
            config=config,
            job=job,
            workdir=workdir,
            output_dir=output_dir,
        )
        client.upload_results(
            job["job_id"],
            agent_id=agent_id,
            exit_code=exit_code,
            run_id=str(job["run_id"]),
            error=error,
            archive_path=archive,
        )
    LOG.info("Job %s finished exit=%s", job["job_id"], exit_code)


class AgentNatsSession:
    """Long-lived JetStream pull session for ``jobs.scan`` (durable ``octo-agents``)."""

    def __init__(self, nats_url: str, *, connect_timeout: float = 5.0) -> None:
        self._nats_url = nats_url
        self._connect_timeout = connect_timeout
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name="octo-agent-nats", daemon=True
        )
        self._nc: Any = None
        self._sub: Any = None
        self._started = False
        self._lock = threading.Lock()

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
            LOG.info("NATS agent session connected (%s)", self._nats_url)

    async def _connect(self) -> None:
        import nats
        from nats.js.api import AckPolicy, ConsumerConfig

        self._nc = await nats.connect(
            self._nats_url,
            name="octo-man-agent",
            connect_timeout=self._connect_timeout,
            max_reconnect_attempts=-1,
            reconnect_time_wait=1,
        )
        js = self._nc.jetstream()
        try:
            self._sub = await js.pull_subscribe(
                SUBJECT_JOBS_SCAN,
                durable=CONSUMER_AGENTS,
                stream=STREAM_JOBS,
            )
        except Exception:
            await js.add_consumer(
                STREAM_JOBS,
                ConsumerConfig(
                    durable_name=CONSUMER_AGENTS,
                    ack_policy=AckPolicy.EXPLICIT,
                    filter_subject=SUBJECT_JOBS_SCAN,
                    max_deliver=5,
                ),
            )
            self._sub = await js.pull_subscribe(
                SUBJECT_JOBS_SCAN,
                durable=CONSUMER_AGENTS,
                stream=STREAM_JOBS,
            )

    def close(self) -> None:
        with self._lock:
            if self._nc is not None and self._loop.is_running():
                async def _shutdown() -> None:
                    if self._nc is not None:
                        try:
                            if not self._nc.is_closed:
                                await self._nc.drain()
                        except Exception:  # noqa: BLE001
                            pass
                        try:
                            if not self._nc.is_closed:
                                await self._nc.close()
                        except Exception:  # noqa: BLE001
                            pass
                        await asyncio.sleep(0.05)
                    asyncio.get_running_loop().stop()

                try:
                    fut = asyncio.run_coroutine_threadsafe(_shutdown(), self._loop)
                    fut.result(timeout=5)
                except Exception:  # noqa: BLE001
                    if self._loop.is_running():
                        self._loop.call_soon_threadsafe(self._loop.stop)
                self._nc = None
                self._sub = None
            elif self._loop.is_running():
                self._loop.call_soon_threadsafe(self._loop.stop)
            self._started = False

    def _ensure_ready(self) -> None:
        if self._started and self._nc is not None and self._sub is not None:
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
        """Fetch one offer, HTTP-claim it, then ACK/NAK. Reconnects if the session drops."""
        self._ensure_ready()

        async def _once() -> dict[str, Any] | None:
            from nats.errors import TimeoutError as NatsTimeout

            assert self._sub is not None
            try:
                msgs = await self._sub.fetch(1, timeout=timeout)
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
            job_id = str(payload["job_id"])
            claimed = await asyncio.to_thread(client.claim, agent_id, job_id=job_id)
            if claimed is None:
                LOG.warning("NATS offer %s not claimable; NAK", job_id)
                await msg.nak()
                return None
            await msg.ack()
            return claimed

        try:
            fut = asyncio.run_coroutine_threadsafe(_once(), self._loop)
            return fut.result(timeout=timeout + 30)
        except Exception:  # noqa: BLE001
            LOG.exception("NATS pull/claim failed; will reconnect")
            self.close()
            return None


async def _nats_pull_and_claim(
    nats_url: str,
    client: AgentClient,
    agent_id: str,
    *,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """One-shot pull (tests / legacy); prefer :class:`AgentNatsSession` in the agent loop."""
    session = AgentNatsSession(nats_url)
    try:
        session.start()
        return session.pull_and_claim(client, agent_id, timeout=timeout)
    finally:
        session.close()


def _pull_nats_job(
    nats_url: str,
    client: AgentClient,
    agent_id: str,
    *,
    timeout: float = 5.0,
    session: AgentNatsSession | None = None,
) -> dict[str, Any] | None:
    if session is not None:
        return session.pull_and_claim(client, agent_id, timeout=timeout)
    return asyncio.run(
        _nats_pull_and_claim(nats_url, client, agent_id, timeout=timeout)
    )


def run_loop(args: argparse.Namespace) -> int:
    client = AgentClient(args.api_url, args.token or "pending", timeout=args.timeout)
    if args.provisioning_key:
        exchanged = client.exchange_provisioning_key(args.provisioning_key)
        client.set_token(str(exchanged["access_token"]))
        LOG.info(
            "Exchanged provisioning key for agent JWT (tenant=%s expires_in=%ss)",
            exchanged.get("tenant_id"),
            exchanged.get("expires_in"),
        )
    elif not args.token:
        LOG.error("OCTO_AGENT_TOKEN / --token or OCTO_AGENT_PROVISIONING_KEY is required")
        return 2

    labels = {}
    if args.label:
        for item in args.label:
            if "=" in item:
                key, value = item.split("=", 1)
                labels[key.strip()] = value.strip()

    info = client.register(
        agent_id=args.agent_id,
        hostname=args.hostname or socket.gethostname(),
        labels=labels,
    )
    agent_id = str(info["agent_id"])
    LOG.info(
        "Registered agent %s (%s) tenant=%s",
        agent_id,
        info.get("hostname"),
        info.get("tenant_id"),
    )

    nats_session: AgentNatsSession | None = None
    if args.nats_url:
        LOG.info("NATS pull enabled (%s) subject=%s", args.nats_url, SUBJECT_JOBS_SCAN)
        nats_session = AgentNatsSession(args.nats_url)
        nats_session.start()

    token_refresh_at = time.time() + max(60, (args.jwt_refresh_seconds or 1800))

    try:
        while True:
            try:
                if args.provisioning_key and time.time() >= token_refresh_at:
                    exchanged = client.exchange_provisioning_key(args.provisioning_key)
                    client.set_token(str(exchanged["access_token"]))
                    expires = int(exchanged.get("expires_in") or 3600)
                    token_refresh_at = time.time() + max(60, expires // 2)
                    LOG.info("Refreshed agent JWT (tenant=%s)", exchanged.get("tenant_id"))

                client.heartbeat(agent_id, status="idle")
                job: dict[str, Any] | None = None
                if nats_session is not None:
                    job = _pull_nats_job(
                        args.nats_url,
                        client,
                        agent_id,
                        timeout=max(1.0, args.poll_interval),
                        session=nats_session,
                    )
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
                )
            except KeyboardInterrupt:
                LOG.info("Shutting down")
                return 0
            except Exception:  # noqa: BLE001
                LOG.exception("Agent loop error")
                time.sleep(args.poll_interval)
    finally:
        if nats_session is not None:
            nats_session.close()



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Octo-man remote scanner agent")
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
        help="NATS JetStream URL for job pull (or OCTO_NATS_URL); empty = HTTP claim poll",
    )
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not args.token and not args.provisioning_key:
        LOG.error("OCTO_AGENT_TOKEN / --token or OCTO_AGENT_PROVISIONING_KEY is required")
        return 2
    return run_loop(args)
