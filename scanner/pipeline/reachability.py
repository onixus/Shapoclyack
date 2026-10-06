"""Explicit TCP refusal evidence for a verification re-scan (#451).

naabu reports open ports only: a port that answered with a RST and a port a
firewall silently dropped look the same in its output — absent. A verification
that closes a finding because its port is closed has to tell the two apart,
because "dropped" is exactly the firewalled-during-the-window case the tracker
must not forgive. So a verification run makes one bounded TCP connect probe
per (target, port) it was sent to re-check and records what came back:

``open``
    the connection was accepted on some attempt;
``refused``
    every attempt was refused (``ECONNREFUSED``: a RST, or an ICMP
    port-unreachable, from the address *or from anything on the path* —
    an iptables/kube-proxy ``REJECT``, a fail2ban ban — in front of a port
    that may well be listening) — the only outcome an
    ``endpoint_unreachable`` closure may rest on, and the reason that
    closure says "not reachable from this vantage" and is never counted as
    machine-verified;
``timeout`` / ``unreachable`` / ``error:<errno>``
    nothing conclusive: dropped, routed nowhere, or something else.

Mixed outcomes are not ``refused``: one lost answer among refusals reads as
"a filter is in the way some of the time", which is no proof of anything.

Off unless ``reachability.enabled`` — only a verification job turns it on
(api/services/vulnerabilities.py). It makes at most ``attempts`` connects per
endpoint, ``attempt_interval_seconds`` apart (an accepting port gets a
handshake and an immediate close, no payload), and is a secondary active
stage under the tenant scan policy (``skip_service_probe``
turns it off, a host-concurrency ceiling lowers it).
"""

from __future__ import annotations

import errno
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .config_schema import ReachabilityConfig
from .protocol import is_ipv6
from .utils import save_json

LOG = logging.getLogger("shapoclyack.reachability")

ARTIFACT = "reachability.json"


def _attempt(host: str, port: int, timeout: float) -> str:
    family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        return "refused"
    except (TimeoutError, socket.timeout):
        return "timeout"
    except OSError as exc:
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return "unreachable"
        return f"error:{errno.errorcode.get(exc.errno or 0, exc.errno)}"
    finally:
        sock.close()
    return "open"


def _verdict(attempts: list[str]) -> str:
    if "open" in attempts:
        return "open"
    if attempts and all(outcome == "refused" for outcome in attempts):
        return "refused"
    return next((outcome for outcome in reversed(attempts) if outcome != "refused"), "error")


def probe(host: str, port: int, config: ReachabilityConfig) -> dict[str, Any]:
    attempts: list[str] = []
    for index in range(config.attempts):
        if index and config.attempt_interval_seconds:
            time.sleep(config.attempt_interval_seconds)
        outcome = _attempt(host, port, config.timeout_seconds)
        attempts.append(outcome)
        if outcome == "open":
            break
    return {"host": host, "port": port, "result": _verdict(attempts), "attempts": attempts}


def run_reachability_probe(
    hosts: list[str],
    ports: set[int],
    config: ReachabilityConfig,
    output_dir: Path,
    *,
    exclude_ports: list[int] | None = None,
) -> dict[str, Any]:
    """Probe every (host, port), bounded; write ``reachability.json``. Never raises."""
    result: dict[str, Any] = {
        "enabled": config.enabled,
        "attempts": config.attempts,
        "timeout_seconds": config.timeout_seconds,
        "attempt_interval_seconds": config.attempt_interval_seconds,
        "probes": [],
        "truncated": False,
    }
    if not config.enabled:
        save_json(output_dir / ARTIFACT, result)
        return result
    excluded = set(exclude_ports or [])
    endpoints = [(host, port) for host in sorted(set(hosts)) for port in sorted(ports - excluded)]
    if len(endpoints) > config.max_probes:
        result["truncated"] = True
        endpoints = endpoints[: config.max_probes]
    try:
        with ThreadPoolExecutor(max_workers=max(1, config.concurrency)) as pool:
            result["probes"] = list(pool.map(lambda e: probe(e[0], e[1], config), endpoints))
    except Exception:  # noqa: BLE001 - evidence missing reads as "not refused", never as a fix
        LOG.warning("reachability probe failed; no refusal evidence recorded", exc_info=True)
        result["probes"] = []
        result["error"] = True
    save_json(output_dir / ARTIFACT, result)
    refused = sum(1 for p in result["probes"] if p["result"] == "refused")
    LOG.info("reachability: %d endpoint(s) probed, %d refused", len(result["probes"]), refused)
    return result
