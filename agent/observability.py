"""Optional ``/healthz`` and ``/metrics`` for the sensor (#366).

Off unless ``OCTO_AGENT_METRICS_ADDR`` is set (``host:port``, e.g.
``127.0.0.1:9108``). The listener is separate from anything the sensor does
for the API: it only serves two read-only GET paths from in-process counters
and never touches the scan, the workdir or the network egress rules.

Exposure rules, because a monitoring port is a free reconnaissance gift:

* a loopback address needs nothing else;
* any other address is refused at start-up unless ``OCTO_AGENT_METRICS_TOKEN``
  is set, in which case ``/metrics`` requires ``Authorization: Bearer <token>``
  (constant-time compare). ``/healthz`` stays open on purpose, so an
  orchestrator probe needs no secret, and it answers only ``ok``/``unhealthy``
  plus a short reason -- no version, id or job.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOG = logging.getLogger("octo-agent")

ADDR_VAR = "OCTO_AGENT_METRICS_ADDR"
TOKEN_VAR = "OCTO_AGENT_METRICS_TOKEN"

#: Healthy while the last successful heartbeat is no older than this many
#: poll intervals (never less than ``MIN_HEALTH_WINDOW_SECONDS``).
HEALTH_POLL_FACTOR = 3.0
MIN_HEALTH_WINDOW_SECONDS = 120.0


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class SensorTelemetry:
    """Thread-safe counters behind ``/metrics`` and the verdict behind ``/healthz``."""

    def __init__(self, version: str = "", *, window_seconds: float = MIN_HEALTH_WINDOW_SECONDS) -> None:
        self._lock = threading.Lock()
        self.version = version
        self.window_seconds = max(MIN_HEALTH_WINDOW_SECONDS, window_seconds)
        self.started_at = time.time()
        self.registered = False
        self.busy = False
        self.signing_enabled = False
        self.last_heartbeat_ok_at: float | None = None
        self.heartbeat_failures = 0
        self.jobs: dict[str, int] = {}
        self.uploads: dict[str, int] = {}
        self.upload_bytes = 0

    def configure(self, *, version: str, poll_interval: float, signing_enabled: bool) -> None:
        with self._lock:
            self.version = version
            self.window_seconds = max(MIN_HEALTH_WINDOW_SECONDS, HEALTH_POLL_FACTOR * poll_interval)
            self.signing_enabled = signing_enabled

    def mark_registered(self) -> None:
        with self._lock:
            self.registered = True

    def heartbeat_ok(self) -> None:
        with self._lock:
            self.last_heartbeat_ok_at = time.time()

    def heartbeat_failed(self) -> None:
        with self._lock:
            self.heartbeat_failures += 1

    def job_started(self) -> None:
        with self._lock:
            self.busy = True

    def job_finished(self, outcome: str) -> None:
        with self._lock:
            self.busy = False
            self.jobs[outcome] = self.jobs.get(outcome, 0) + 1

    def upload_finished(self, outcome: str, size: int = 0) -> None:
        with self._lock:
            self.uploads[outcome] = self.uploads.get(outcome, 0) + 1
            if outcome == "ok":
                self.upload_bytes += max(0, int(size))

    def health(self, now: float | None = None) -> tuple[bool, str]:
        now = time.time() if now is None else now
        with self._lock:
            if not self.registered:
                return False, "not registered"
            if self.last_heartbeat_ok_at is None:
                return False, "no heartbeat answered yet"
            age = now - self.last_heartbeat_ok_at
            if age > self.window_seconds:
                return False, f"last heartbeat {int(age)}s ago"
            return True, "ok"

    def render(self) -> str:
        with self._lock:
            lines: list[str] = []

            def emit(name: str, kind: str, help_text: str, samples: list[tuple[str, float]]) -> None:
                lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} {kind}")
                for labels, value in samples:
                    lines.append(f"{name}{labels} {value:g}")

            emit("octo_sensor_info", "gauge", "Sensor build.", [(f'{{version="{_label(self.version)}"}}', 1)])
            emit("octo_sensor_start_time_seconds", "gauge", "Process start time.", [("", self.started_at)])
            emit("octo_sensor_registered", "gauge", "1 once the API accepted the registration.", [("", int(self.registered))])
            emit("octo_sensor_busy", "gauge", "1 while a scan is running or uploading.", [("", int(self.busy))])
            emit(
                "octo_sensor_result_signing_enabled",
                "gauge",
                "1 when run archives are signed with the sensor's key.",
                [("", int(self.signing_enabled))],
            )
            emit(
                "octo_sensor_heartbeat_last_success_timestamp_seconds",
                "gauge",
                "Unix time of the last heartbeat the API answered (0 = none yet).",
                [("", self.last_heartbeat_ok_at or 0)],
            )
            emit(
                "octo_sensor_heartbeat_failures_total",
                "counter",
                "Heartbeats that failed.",
                [("", self.heartbeat_failures)],
            )
            emit(
                "octo_sensor_jobs_total",
                "counter",
                "Jobs this sensor ran, by outcome (succeeded, failed, cancelled).",
                [(f'{{outcome="{_label(k)}"}}', v) for k, v in sorted(self.jobs.items())],
            )
            emit(
                "octo_sensor_result_uploads_total",
                "counter",
                "Result uploads, by outcome (ok, rejected, error).",
                [(f'{{outcome="{_label(k)}"}}', v) for k, v in sorted(self.uploads.items())],
            )
            emit(
                "octo_sensor_result_upload_bytes_total",
                "counter",
                "Archive bytes the API accepted.",
                [("", self.upload_bytes)],
            )
            return "\n".join(lines) + "\n"


#: The process-wide instance the worker updates.
TELEMETRY = SensorTelemetry()


class ObservabilityConfigError(ValueError):
    pass


def parse_addr(raw: str) -> tuple[str, int]:
    """``host:port`` (``[::1]:9108`` for IPv6) -> ``(host, port)``."""
    value = raw.strip()
    host, sep, port_text = value.rpartition(":")
    if not sep or not port_text.isdigit() or int(port_text) > 65535:
        raise ObservabilityConfigError(f"{ADDR_VAR}={raw!r} is not host:port")
    return host.strip("[]") or "127.0.0.1", int(port_text)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _handler(telemetry: SensorTelemetry, token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "octo-sensor"

        def _send(self, code: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                ok, reason = telemetry.health()
                self._send(200 if ok else 503, ("ok" if ok else f"unhealthy: {reason}") + "\n")
                return
            if path == "/metrics":
                if token:
                    presented = self.headers.get("Authorization", "")
                    expected = f"Bearer {token}"
                    if not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
                        self._send(401, "unauthorized\n")
                        return
                self._send(200, telemetry.render(), "text/plain; version=0.0.4; charset=utf-8")
                return
            self._send(404, "not found\n")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            LOG.debug("observability: " + format, *args)

    return Handler


class ObservabilityServer:
    def __init__(self, host: str, port: int, telemetry: SensorTelemetry, token: str = "") -> None:
        self.telemetry = telemetry
        self._httpd = ThreadingHTTPServer((host, port), _handler(telemetry, token))
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="octo-observability", daemon=True)

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def start_from_env(telemetry: SensorTelemetry = TELEMETRY) -> ObservabilityServer | None:
    """Start the listener when ``OCTO_AGENT_METRICS_ADDR`` asks for one.

    A bad address, a non-loopback address without a token, or a port that
    cannot be bound is logged and the sensor carries on without the endpoint:
    monitoring that cannot start must not stop scanning.
    """
    raw = os.environ.get(ADDR_VAR, "").strip()
    if not raw:
        return None
    token = os.environ.get(TOKEN_VAR, "").strip()
    try:
        host, port = parse_addr(raw)
        if not _is_loopback(host) and not token:
            raise ObservabilityConfigError(
                f"{ADDR_VAR}={raw} is reachable from the network; set {TOKEN_VAR} or bind a loopback address"
            )
        server = ObservabilityServer(host, port, telemetry, token)
    except (ObservabilityConfigError, OSError) as exc:
        LOG.error("Sensor /metrics and /healthz not started: %s", exc)
        return None
    server.start()
    LOG.info("Sensor /healthz and /metrics listening on %s:%s", host, server.port)
    return server
