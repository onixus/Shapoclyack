"""Pulse service/OS probe stage (nmap alternative for enrichment).

Invokes the Pulse CLI (https://github.com/onixus/GenDec) against hosts that
already have open ports from naabu, writes canonical artifacts:

  output_dir/pulse/raw.json       — merged pulse JSON (+ ``adapter`` block)
  output_dir/pulse/tls.json       — octo.pulse_tls.v1 (tls[] + tls-class findings)
  output_dir/services.json        — octo.service.v1 list
  output_dir/os.json              — octo.os.v1 list
  output_dir/pulse_cves.json      — optional CVE findings from pulse

Hosts with identical TCP port sets are probed in chunks of ``chunk_hosts``;
no invocation introduces host/port combinations absent from the input.
Pulse's own ``--checkpoint`` is
deliberately not used: Shapoclyack already tracks per-host progress in its
CheckpointStore, a chunk is cheap to rescan, and a pulse checkpoint that
outlives one invocation is a liability -- pulse trusts the file over
``--targets-file`` and *replays* a finished (or all-hosts-completed) one
without OS detection, CVE correlation or the TLS probe. See ``chunk_key``.
Exact planning, resume and diagnostic contracts: docs/pulse-endpoints.md.

``--os`` needs raw sockets. When pulse refuses for that reason the stage does
not fail: it drops ``--os`` for the rest of the run and keeps services,
banners and CVEs (mirrors nse.py, which drops nmap ``-O`` when not root).

Does **not** replace NSE scripts (ssl-enum-ciphers, vulners, …). Use
``service_probe.backend: hybrid`` or ``nmap`` when those are required.

Does **not** invoke Pulse product features that duplicate Shapoclyack:
``pulse monitor``, ``--server``, ``--alert-*``, ``--scripts``, ``--inventory``.

Environment:
  OCTO_PULSE_BIN     — path to pulse binary (default: ``pulse`` on PATH)
  NVD_API_KEY        — optional; pulse also reads ~/.pulse/nvd_api_key
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from .protocol import parse_endpoint
from .pulse_plan import plan_tcp_probe
from .pulse_progress import (
    completed_hosts,
    completion_manifest,
    normalize_host,
    retain_completed_payload,
)
from .service_schema import (
    FINDING_CLASSES,
    CveRecord,
    OsMatchRank,
    OsRecord,
    ServiceRecord,
    cves_to_extra_vulnerabilities,
    os_to_report_matches,
    services_to_report_findings,
)
from .utils import run_command, save_json, write_lines


#: pulse's ruleset id: ``YYYY.MM.DD`` with an optional ``-hN`` hotfix
#: (pulse 1.1.0 prints ``2026.07.29-h1``).
_RULESET = re.compile(r"(\d{4})\.(\d{1,2})\.(\d{1,2})(?:-h(\d+))?")


def parse_ruleset(value: str | None) -> tuple[int, int, int, int] | None:
    """``(year, month, day, hotfix)`` of a pulse ruleset id, or ``None``.

    Case and surrounding space do not matter, and a missing hotfix is hotfix
    0 (``2026.07.29`` == ``2026.07.29-h0``). Anything else is ``None``: a
    verification must not decide "older or newer" about an id it cannot read
    (#451 review — ``2026-08-02`` used to sort oldest, so any dated run
    "covered" it).
    """
    match = _RULESET.fullmatch(str(value or "").strip().lower())
    if match is None:
        return None
    year, month, day, hotfix = match.groups()
    return int(year), int(month), int(day), int(hotfix or 0)


def ruleset_order(value: str | None) -> tuple:
    """Sort key, oldest first; an unreadable id sorts before every readable one."""
    parsed = parse_ruleset(value)
    return (0, (), str(value or "")) if parsed is None else (1, parsed, "")


def resolve_pulse_bin(configured: str = "") -> str:
    env = os.environ.get("OCTO_PULSE_BIN", "").strip()
    if env:
        return env
    if configured:
        return configured
    found = shutil.which("pulse")
    if found:
        return found
    # Common release / image locations
    for candidate in (
        "/usr/local/bin/pulse",
        "/usr/bin/pulse",
        "/opt/pulse/pulse",
    ):
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return "pulse"


def _pulse_available(bin_path: str) -> bool:
    """True when ``bin_path`` is an executable file or resolves on PATH."""
    path = Path(bin_path)
    if path.is_file():
        return os.access(path, os.X_OK)
    return shutil.which(bin_path) is not None


def chunk_key(hosts: Iterable[str], ports: Iterable[int], mode: str = "connect") -> str:
    """Stable id of one (hosts, ports, scan mode) chunk; names its hosts file.

    Chunks are re-cut from the pending hosts on ``--resume``, so a position
    (``chunk_0000``) means a different host set every time; a content key keeps
    each chunk's ``hosts.txt`` and its ``chunks[]`` record in ``pulse/raw.json``
    attributable across runs. ``mode`` (``connect``/``syn``) is part of the
    identity for the same reason pulse puts it in its own job fingerprint.

    History: this key once also named a per-chunk pulse ``--checkpoint``. It
    does not any more -- pulse trusts an existing checkpoint file over
    ``--targets-file`` and replays a finished one without OS/CVE/TLS, and both
    ``run_command``'s timeout retry and the settle retry re-run the same
    command, so no naming scheme could make a surviving checkpoint safe. A
    chunk that dies is simply rescanned.
    """
    digest = hashlib.sha256()
    for host in sorted(set(hosts)):
        digest.update(host.encode("utf-8"))
        digest.update(b"\n")
    digest.update(b"|")
    digest.update(",".join(str(p) for p in sorted(set(ports))).encode("ascii"))
    digest.update(b"|")
    digest.update(mode.encode("ascii"))
    return digest.hexdigest()[:16]


#: Consecutive chunks that may end in a pulse exit without JSON before the
#: stage gives up. A crash that repeats across chunks is a broken binary or a
#: bad flag, not weather; sleeping and re-spawning it once per chunk for the
#: rest of a large run only delays the same empty result by hours.
MAX_CONSECUTIVE_CRASHED_CHUNKS = 3


class PulseCrashLoopError(RuntimeError):
    """pulse exited without JSON for MAX_CONSECUTIVE_CRASHED_CHUNKS chunks in a row."""


def _is_os_raw_socket_failure(stderr: str) -> bool:
    """pulse ``ensure_os_capable`` refused: ``--os`` cannot open raw sockets.

    GenDec ``src/scanner/osdetect.rs`` aborts the whole run with "OS detection
    needs raw sockets (run as root/sudo, or setcap cap_net_raw+ep on Linux)".
    Matched loosely on both halves so a reworded hint still counts; ``--syn``
    has its own capability check and is deliberately not matched -- SYN is an
    explicit opt-in, silently downgrading it to connect would change what the
    operator asked for.
    """
    text = (stderr or "").lower()
    return "os detection" in text and "raw socket" in text


def _merge_stats(acc: dict[str, Any], new: dict[str, Any]) -> None:
    """Sum one chunk's pulse ``stats`` into ``acc`` (rate is recomputed, not summed)."""
    for key, value in new.items():
        if key == "rate_pps" or isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        acc[key] = acc.get(key, 0) + value
    total = acc.get("total")
    elapsed_ms = acc.get("elapsed_ms")
    if isinstance(total, (int, float)) and isinstance(elapsed_ms, (int, float)) and elapsed_ms > 0:
        acc["rate_pps"] = round(total / (elapsed_ms / 1000.0), 1)


def _group_tcp_ports(open_ports: list[str]) -> dict[str, list[int]]:
    """host → sorted unique TCP ports (UDP skipped for pulse connect path)."""
    grouped: dict[str, list[int]] = defaultdict(list)
    for entry in open_ports:
        parsed = parse_endpoint(entry)
        if parsed is None:
            continue
        if parsed.protocol != "tcp":
            continue
        try:
            port = int(parsed.port)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            grouped[normalize_host(parsed.host)].append(port)
    return {h: sorted(set(ports)) for h, ports in grouped.items() if ports}


def _port_spec(ports: list[int]) -> str:
    return ",".join(str(p) for p in ports)


def build_pulse_command(
    *,
    bin_path: str,
    hosts_file: Path,
    ports: list[int],
    concurrency: int,
    rate: int,
    adaptive: bool,
    host_parallel: int,
    timeout_ms: int,
    banner: bool,
    os_detect: bool,
    os_mode: str,
    cve: bool,
    cve_online: bool,
    syn: bool,
    checkpoint: Path | None,
    max_hosts: int,
) -> list[str]:
    cmd = [
        bin_path,
        "--targets-file",
        str(hosts_file),
        "-p",
        _port_spec(ports) if ports else "1-1024",
        "-c",
        str(max(1, concurrency)),
        "-t",
        str(max(50, timeout_ms)),
        "--max-hosts",
        str(max(1, max_hosts)),
        "-f",
        "json",
        "-q",
    ]
    if rate > 0:
        cmd += ["--rate", str(rate)]
    if adaptive:
        cmd.append("--adaptive")
    if host_parallel > 0:
        cmd += ["--host-parallel", str(host_parallel)]
    else:
        # Ordered completion when not parallelizing hosts
        cmd.append("--host-first")
    if banner:
        cmd.append("-b")
    if os_detect:
        cmd += ["--os", "--os-mode", os_mode]
    if cve:
        cmd.append("--cve")
    if cve_online:
        cmd.append("--cve-online")
    if syn:
        cmd += ["--syn", "--syn-retries", "1"]
    if checkpoint is not None:
        cmd += ["--checkpoint", str(checkpoint)]
    return cmd


def parse_pulse_json(payload: dict[str, Any]) -> tuple[list[ServiceRecord], list[OsRecord], list[CveRecord]]:
    services: list[ServiceRecord] = []
    for row in payload.get("open") or []:
        if not isinstance(row, dict):
            continue
        try:
            port = int(row.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port < 1:
            continue
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        proto = str(row.get("protocol") or "tcp").lower()
        if proto in ("tcpsyn", "syn"):
            proto = "tcp"
        banner = row.get("banner")
        product = str(row.get("product") or "").strip()
        version = str(row.get("version") or "").strip()
        state = str(row.get("state") or "open").strip().lower() or "open"
        services.append(
            ServiceRecord(
                ip=ip,
                port=port,
                protocol=proto if proto in ("tcp", "udp") else "tcp",
                state=state,
                service=str(row.get("service") or "unknown"),
                product=product,
                version=version,
                banner=str(banner) if banner else "",
                source="pulse",
                host=str(row.get("host") or ip),
            )
        )

    os_records: list[OsRecord] = []
    for row in payload.get("os") or []:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        matches_raw = row.get("matches") or []
        ranks: list[OsMatchRank] = []
        if isinstance(matches_raw, list):
            for m in matches_raw:
                if not isinstance(m, dict):
                    continue
                ranks.append(
                    OsMatchRank(
                        name=str(m.get("name") or ""),
                        accuracy=float(m.get("accuracy") or 0.0),
                        family=str(m.get("family") or ""),
                    )
                )
        conf = row.get("confidence")
        try:
            confidence = int(conf) if conf is not None else 0
        except (TypeError, ValueError):
            confidence = 0
        ttl_v = row.get("ttl")
        try:
            ttl = int(ttl_v) if ttl_v is not None else None
        except (TypeError, ValueError):
            ttl = None
        os_records.append(
            OsRecord(
                ip=ip,
                family=str(row.get("family") or "Unknown"),
                detail=str(row.get("detail") or ""),
                confidence=max(0, min(100, confidence)),
                source=str(row.get("source") or "pulse"),
                ttl=ttl,
                matches=ranks,
                host=str(row.get("host") or ip),
            )
        )

    cves: list[CveRecord] = []
    # Prefer full findings array; fall back to cves key.
    cve_rows = payload.get("findings") or payload.get("cves") or []
    for row in cve_rows:
        if not isinstance(row, dict):
            continue
        cve_id = str(row.get("cve_id") or "").strip()
        finding_class = str(row.get("finding_class") or "").strip().lower()
        # CVE-less classes (exposure / tls) used to be dropped here, which threw
        # away every "this service is reachable" observation Pulse makes. Keep
        # them when Pulse labelled them; a row with neither a CVE nor a class is
        # still unusable and skipped.
        #
        # tls_posture is opt-in and writes a separate artifact; it does not
        # merge into extra_vulnerabilities. Dropping finding_class=tls here
        # would hide cert expiry / weak-protocol on the default path.
        if not cve_id and finding_class not in FINDING_CLASSES:
            continue
        if not finding_class:
            finding_class = "version_cve"
        try:
            port = int(row.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        cvss_raw = row.get("cvss")
        try:
            cvss = float(cvss_raw) if cvss_raw is not None else None
        except (TypeError, ValueError):
            cvss = None
        refs = row.get("refs") or []
        if not isinstance(refs, list):
            refs = []
        epss_raw = row.get("epss")
        try:
            epss = float(epss_raw) if epss_raw is not None else None
        except (TypeError, ValueError):
            epss = None
        try:
            confidence = int(row.get("confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0
        cves.append(
            CveRecord(
                cve_id=cve_id,
                ip=str(row.get("ip") or ""),
                port=port,
                service=str(row.get("service") or ""),
                cvss=cvss,
                severity=str(row.get("severity") or "unknown"),
                title=str(row.get("title") or cve_id),
                summary=str(row.get("summary") or ""),
                match_reason=str(row.get("match_reason") or ""),
                source=str(row.get("source") or "pulse"),
                refs=[str(r) for r in refs],
                finding_class=finding_class,
                confidence=max(0, min(100, confidence)),
                requires_confirmation=bool(row.get("requires_confirmation")),
                evidence=str(row.get("evidence") or ""),
                ruleset_version=str(row.get("ruleset_version") or ""),
                epss=epss,
                in_kev=bool(row.get("in_kev")),
            )
        )

    return services, os_records, cves


def extract_pulse_tls(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return TLS endpoint rows from a Pulse scan JSON payload."""
    out: list[dict[str, Any]] = []
    for row in payload.get("tls") or []:
        if isinstance(row, dict):
            out.append(row)
    return out


def write_pulse_artifacts(
    output_dir: Path,
    services: list[ServiceRecord],
    os_records: list[OsRecord],
    cves: list[CveRecord],
    raw: dict[str, Any] | None = None,
) -> Path:
    """Write canonical JSON files; return pulse/ directory."""
    pulse_dir = output_dir / "pulse"
    pulse_dir.mkdir(parents=True, exist_ok=True)
    if raw is not None:
        save_json(pulse_dir / "raw.json", raw)
        tls_rows = extract_pulse_tls(raw)
        save_json(
            pulse_dir / "tls.json",
            {
                "schema": "octo.pulse_tls.v1",
                "count": len(tls_rows),
                "tls": tls_rows,
                "findings": [
                    f
                    for f in (raw.get("findings") or raw.get("cves") or [])
                    if isinstance(f, dict)
                    and str(f.get("finding_class") or "").lower() == "tls"
                ],
            },
        )
    save_json(output_dir / "services.json", [s.model_dump(mode="json") for s in services])
    save_json(output_dir / "os.json", [o.model_dump(mode="json") for o in os_records])
    save_json(output_dir / "pulse_cves.json", [c.model_dump(mode="json") for c in cves])
    # Convenience: report-shaped findings for debugging
    save_json(
        pulse_dir / "findings_report_shape.json",
        {
            "services": services_to_report_findings(services),
            "os_matches": os_to_report_matches(os_records),
            "vulnerabilities": cves_to_extra_vulnerabilities(cves),
        },
    )
    return pulse_dir


def load_pulse_tls_artifact(output_dir: Path) -> dict[str, Any] | None:
    """Load ``pulse/tls.json`` or extract tls from ``pulse/raw.json``.

    Returns dict with keys ``tls`` / optional ``findings``, or None if missing.
    """
    tls_path = output_dir / "pulse" / "tls.json"
    if tls_path.is_file():
        try:
            data = json.loads(tls_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict) and (data.get("tls") or data.get("findings")):
            return data

    raw_path = output_dir / "pulse" / "raw.json"
    if not raw_path.is_file():
        return None
    try:
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    tls_rows = extract_pulse_tls(raw)
    findings = [
        f
        for f in (raw.get("findings") or raw.get("cves") or [])
        if isinstance(f, dict) and str(f.get("finding_class") or "").lower() == "tls"
    ]
    if not tls_rows and not findings:
        return None
    return {"schema": "octo.pulse_tls.v1", "tls": tls_rows, "findings": findings}


def load_service_artifacts(
    output_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]] | None:
    """Load services/os/cves if Pulse artifacts exist.

    Returns (services, os_matches, extra_vulnerabilities) in report.py shapes,
    or None if artifacts are missing.
    """
    services_path = output_dir / "services.json"
    if not services_path.exists():
        return None
    try:
        raw_services = json.loads(services_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw_services, list):
        return None

    services: list[ServiceRecord] = []
    for row in raw_services:
        try:
            services.append(ServiceRecord.model_validate(row))
        except Exception:  # noqa: BLE001
            continue

    os_records: list[OsRecord] = []
    os_path = output_dir / "os.json"
    if os_path.exists():
        try:
            raw_os = json.loads(os_path.read_text(encoding="utf-8"))
            if isinstance(raw_os, list):
                for row in raw_os:
                    try:
                        os_records.append(OsRecord.model_validate(row))
                    except Exception:  # noqa: BLE001
                        continue
        except (OSError, json.JSONDecodeError):
            pass

    cves: list[CveRecord] = []
    cve_path = output_dir / "pulse_cves.json"
    if cve_path.exists():
        try:
            raw_cve = json.loads(cve_path.read_text(encoding="utf-8"))
            if isinstance(raw_cve, list):
                for row in raw_cve:
                    try:
                        cves.append(CveRecord.model_validate(row))
                    except Exception:  # noqa: BLE001
                        continue
        except (OSError, json.JSONDecodeError):
            pass

    return (
        services_to_report_findings(services),
        os_to_report_matches(os_records),
        cves_to_extra_vulnerabilities(cves),
    )


def sync_report_primary_marker(pulse_dir: Path, report_primary: bool | None) -> None:
    """Write or remove ``pulse/REPORT_PRIMARY`` to match ``report_primary``.

    When ``report_primary`` is None, falls back to ``OCTO_SERVICE_BACKEND`` in
    {pulse, hybrid}. Callers that already know the resolved backend (e.g.
    scanner/main.py) should always pass an explicit bool.
    """
    if report_primary is None:
        backend = os.environ.get("OCTO_SERVICE_BACKEND", "").strip().lower()
        report_primary = backend in ("pulse", "hybrid")
    marker = pulse_dir / "REPORT_PRIMARY"
    if report_primary:
        marker.write_text("pulse\n", encoding="utf-8")
    elif marker.exists():
        try:
            marker.unlink()
        except OSError:
            pass


def _probe_chunk(
    cmd: list[str], *, timeout_seconds: int, retries: int, idx: int
) -> tuple[dict[str, Any], int, str]:
    """Run one pulse invocation; return (parsed payload, exit code, stderr)."""
    completed = run_command(
        cmd,
        timeout=timeout_seconds,
        retries=retries,
        check=False,
        capture_output=True,
    )
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        logging.warning(
            "pulse exited %s for chunk %s: %s",
            completed.returncode,
            idx,
            (stderr or stdout)[:500],
        )
    payload: dict[str, Any] = {}
    if stdout:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            # pulse may print logs on stdout in some builds; try last JSON object
            start = stdout.rfind("{")
            if start >= 0:
                try:
                    payload = json.loads(stdout[start:])
                except json.JSONDecodeError:
                    logging.warning("pulse_probe: could not parse JSON for chunk %s", idx)
                    payload = {}
    return payload, completed.returncode, stderr


def run_pulse_probe(
    open_ports: list[str],
    *,
    output_dir: Path,
    bin_path: str = "",
    concurrency: int = 500,
    rate: int = 2000,
    adaptive: bool = True,
    host_parallel: int = 8,
    timeout_ms: int = 800,
    banner: bool = True,
    os_detect: bool = True,
    os_mode: str = "auto",
    cve: bool = True,
    cve_online: bool = False,
    syn: bool = False,
    max_hosts: int = 65536,
    timeout_seconds: int = 600,
    retries: int = 1,
    done_hosts: Iterable[str] | None = None,
    on_host_done: Callable[[str], None] | None = None,
    chunk_hosts: int = 64,
    report_primary: bool | None = None,
    retry_settle_seconds: int = 15,
    on_unresolved: Callable[[list[str]], None] | None = None,
    on_resume_validated: Callable[[set[str]], None] | None = None,
) -> Path:
    """Run Pulse against hosts derived from open_ports; write artifacts.

    Returns ``output_dir / "pulse"``. Empty open_ports → empty artifacts, still OK.

    ``report_primary``: when True, write ``pulse/REPORT_PRIMARY`` so report.py
    prefers services.json/os.json. When None, fall back to
    ``OCTO_SERVICE_BACKEND`` in {pulse, hybrid}.

    Raises ``FileNotFoundError`` when there is work to do and no pulse binary:
    Pulse is the default backend and the only source of services on that path,
    so a missing binary is a deployment error to surface, not a stage to skip.
    Deliberately not a silent fallback to nmap -- an image built with
    ``--build-arg INSTALL_PULSE=0`` would then produce a scan with a different
    finding set under the same profile, and nobody would see it happen. The
    message names both fixes instead.
    Raises ``PulseCrashLoopError`` after ``MAX_CONSECUTIVE_CRASHED_CHUNKS``
    chunks in a row end in a pulse exit without JSON.
    """
    pulse_bin = resolve_pulse_bin(bin_path)
    grouped = _group_tcp_ports(open_ports)
    requested_done = {normalize_host(host) for host in (done_hosts or ())}
    done: set[str] = set()
    cached: dict[str, Any] = {}
    if requested_done:
        try:
            previous = json.loads((output_dir / "pulse" / "raw.json").read_text(encoding="utf-8"))
            if not isinstance(previous, dict):
                raise ValueError("expected an object")
            done, cached = retain_completed_payload(grouped, requested_done, previous)
            # Validate reusable canonical data before honoring any checkpoint.
            parse_pulse_json(cached)
        except (OSError, ValueError, TypeError):
            logging.warning("pulse_probe: persisted checkpoint evidence unavailable; re-probing approved endpoints")
            done, cached = set(), {}
    # Reconcile the coarse and per-host checkpoint before any replay/spawn.
    # A callback failure aborts the stage rather than running with stale progress.
    if on_resume_validated:
        on_resume_validated(set(done))
    size = max(1, chunk_hosts)
    chunks = plan_tcp_probe(grouped, chunk_hosts=size, done_hosts=done)
    planned_endpoints = sum(chunk.endpoint_count for chunk in chunks)
    diagnostics = {
        "input_unique_tcp_endpoints": sum(len(ports) for ports in grouped.values()),
        "pending_unique_tcp_endpoints": sum(len(ports) for host, ports in grouped.items() if host not in done),
        "planned_tcp_combinations": planned_endpoints,
        "planned_chunks": len(chunks),
        # These are adapter calls, NOT packets/connections or subprocess counts:
        # run_command may retry timeouts internally with the same exact argv.
        "chunk_probe_calls": 0,
        "adapter_retry_calls": 0,
        "adapter_retry_tcp_combinations": 0,
        "command_retries": retries,
        "resumed_hosts": len(done),
        "replayed_checkpoint_hosts": len((requested_done & grouped.keys()) - done),
    }

    all_services, all_os, all_cves = parse_pulse_json(cached)
    merged_raw: dict[str, Any] = {
        "open": list(cached.get("open") or []),
        "os": list(cached.get("os") or []),
        "cves": list(cached.get("cves") or []),
        "findings": list(cached.get("findings") or cached.get("cves") or []),
        "tls": list(cached.get("tls") or []),
        "stats": {},
        "chunks": [],
        "completion": completion_manifest({host: grouped[host] for host in done}),
        "adapter": {
            "chunk_hosts": size,
            "cve": cve,
            "cve_online": cve_online,
            "ruleset": None,
            "pulse_version": None,
            **diagnostics,
        },
    }

    pulse_dir = output_dir / "pulse"
    pulse_dir.mkdir(parents=True, exist_ok=True)

    if not chunks:
        logging.info("pulse_probe: no TCP open ports to probe")
        write_pulse_artifacts(output_dir, all_services, all_os, all_cves, raw=merged_raw)
        sync_report_primary_marker(pulse_dir, report_primary)
        return pulse_dir

    if not _pulse_available(pulse_bin):
        raise FileNotFoundError(
            f"pulse binary not found ({pulse_bin!r}) and service_probe.backend "
            "asks for it, so this run would report no services at all. Either "
            "install it (scripts/install-pulse.sh, or point OCTO_PULSE_BIN / "
            "service_probe.pulse.bin at an existing binary), or switch the "
            "backend to nmap (OCTO_SERVICE_BACKEND=nmap / service_probe."
            "backend: nmap) on an image that has nmap. An image built with "
            "--build-arg INSTALL_PULSE=0 ships no pulse by design and must be "
            "configured that way; see docs/pulse-backend.md."
        )

    # Effective --os for this run. Flipped off once pulse refuses it for lack
    # of raw sockets; every later chunk then skips the doomed attempt.
    os_detect_effective = os_detect
    os_detect_degraded: str | None = None
    # pulse's offline CVE ruleset (``meta.ruleset``, e.g. ``2026.07.29-h1``) and
    # its own version, from every chunk that answered. Recorded because a
    # verification run matching with an older ruleset than the one that found
    # a CVE proves nothing about it (api/services/verification_coverage.py).
    rulesets: set[str] = set()
    pulse_versions: set[str] = set()
    consecutive_crashes = 0
    scan_mode = "syn" if syn else "connect"

    logging.info(
        "pulse_probe plan: %s unique input TCP endpoints, %s pending, "
        "%s planned combinations in %s chunks",
        diagnostics["input_unique_tcp_endpoints"],
        diagnostics["pending_unique_tcp_endpoints"],
        planned_endpoints,
        len(chunks),
    )

    for idx, chunk in enumerate(chunks):
        host_chunk = list(chunk.hosts)
        ports_list = list(chunk.ports)
        probe_calls = 0

        def _probe(command: list[str]) -> tuple[dict[str, Any], int, str]:
            nonlocal probe_calls
            if probe_calls:
                diagnostics["adapter_retry_calls"] += 1
                diagnostics["adapter_retry_tcp_combinations"] += chunk.endpoint_count
            probe_calls += 1
            diagnostics["chunk_probe_calls"] += 1
            return _probe_chunk(command, timeout_seconds=timeout_seconds, retries=retries, idx=idx)

        key = chunk_key(host_chunk, ports_list, scan_mode)
        hosts_file = pulse_dir / f"chunk_{key}.hosts.txt"
        write_lines(hosts_file, host_chunk)

        def _command(*, with_os: bool) -> list[str]:
            return build_pulse_command(
                bin_path=pulse_bin,
                hosts_file=hosts_file,
                ports=ports_list,
                concurrency=concurrency,
                rate=rate,
                adaptive=adaptive,
                host_parallel=host_parallel,
                timeout_ms=timeout_ms,
                banner=banner,
                os_detect=with_os,
                os_mode=os_mode,
                cve=cve,
                cve_online=cve_online,
                syn=syn,
                checkpoint=None,
                max_hosts=max(max_hosts, len(host_chunk) + 1),
            )

        cmd = _command(with_os=os_detect_effective)

        logging.info(
            "pulse_probe chunk %s/%s (%s): %s hosts, %s ports",
            idx + 1,
            len(chunks),
            key,
            len(host_chunk),
            len(ports_list),
        )
        payload, returncode, stderr = _probe(cmd)

        # pulse aborts the whole invocation -- not just OS detection -- when
        # --os cannot open raw sockets (unprivileged host install, a pod
        # without NET_RAW). Losing services, banners and CVEs over a missing
        # OS guess is the wrong trade, and nse.py already makes the same call
        # for nmap -O. Drop --os for the rest of the run and ask again now.
        if (
            returncode != 0
            and not payload
            and os_detect_effective
            and _is_os_raw_socket_failure(stderr)
        ):
            os_detect_effective = False
            # Keep pulse's own sentence, not anyhow's "Caused by:" tail.
            os_detect_degraded = next(
                (line.strip() for line in stderr.splitlines() if "raw socket" in line.lower()),
                "raw sockets unavailable",
            )[:200]
            logging.warning(
                "pulse_probe: OS detection needs raw sockets and this process has none "
                "(%s); continuing without --os for the rest of the run -- services, "
                "banners and CVEs still run. Grant cap_net_raw/cap_net_admin to the "
                "pulse binary or the pod (docs/pulse-backend.md) to get OS guesses back.",
                os_detect_degraded,
            )
            cmd = _command(with_os=False)
            payload, returncode, stderr = _probe(cmd)

        crashed = returncode != 0 and not payload
        if crashed:
            # A crash is not weather: re-run at once, no settle pause. The
            # pause below exists for a saturated network path, which has
            # nothing to do with exit 2 or a panic.
            logging.warning(
                "pulse_probe chunk %s: pulse exited %s without JSON (%s); re-probing now",
                idx,
                returncode,
                stderr[:300] or "no stderr",
            )
            payload, returncode, stderr = _probe(cmd)
            crashed = returncode != 0 and not payload
        elif not payload.get("open") and retry_settle_seconds:
            # Every host here reached this stage because naabu proved a port
            # open on it moments ago, so an all-closed chunk is a contradiction
            # rather than a finding: the ports burst saturates the path and the
            # probe lands before it recovers. Pause and ask once more.
            logging.warning(
                "pulse_probe chunk %s: 0 services across %s host(s) with known-open "
                "ports; re-probing in %ss",
                idx,
                len(host_chunk),
                retry_settle_seconds,
            )
            time.sleep(retry_settle_seconds)
            payload, returncode, stderr = _probe(cmd)

        # A settle retry can itself crash; classify the final attempt.
        crashed = returncode != 0 and not payload
        if crashed:
            consecutive_crashes += 1
            if consecutive_crashes >= MAX_CONSECUTIVE_CRASHED_CHUNKS:
                raise PulseCrashLoopError(
                    f"pulse exited {returncode} without JSON for "
                    f"{consecutive_crashes} chunks in a row; last stderr: "
                    f"{stderr[:500] or 'empty'}. Fix the binary/flags "
                    f"({pulse_bin}) and re-run with --resume."
                )
        else:
            consecutive_crashes = 0


        resolved_hosts = completed_hosts({host: ports_list for host in host_chunk}, payload, returncode)
        unresolved_hosts = [host for host in host_chunk if host not in resolved_hosts]
        resolved = not unresolved_hosts
        if unresolved_hosts and on_unresolved:
            on_unresolved(unresolved_hosts)

        if payload:
            meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
            if meta.get("ruleset"):
                rulesets.add(str(meta["ruleset"]))
            if meta.get("version"):
                pulse_versions.add(str(meta["version"]))
            services, os_recs, cves = parse_pulse_json(payload)
            all_services.extend(services)
            all_os.extend(os_recs)
            all_cves.extend(cves)
            merged_raw["open"].extend(payload.get("open") or [])
            merged_raw["os"].extend(payload.get("os") or [])
            merged_raw["cves"].extend(payload.get("cves") or [])
            merged_raw["findings"].extend(
                payload.get("findings") or payload.get("cves") or []
            )
            merged_raw["tls"].extend(payload.get("tls") or [])
            if isinstance(payload.get("stats"), dict):
                _merge_stats(merged_raw["stats"], payload["stats"])
        # Every chunk is on the record, failed ones included -- an artifact
        # that lists only the chunks that answered looks like a clean run.
        merged_raw["chunks"].append(
            {
                "index": idx,
                "key": key,
                "hosts": host_chunk,
                "ports": ports_list,
                "returncode": returncode,
                "resolved": resolved,
                "unresolved_hosts": unresolved_hosts,
                "probe_calls": probe_calls,
            }
        )

        merged_raw["completion"]["hosts"].update(
            completion_manifest({host: ports_list for host in resolved_hosts})["hosts"]
        )
        for host in host_chunk:
            if host in resolved_hosts and on_host_done:
                on_host_done(host)

    # Dedupe services by ip:port:proto
    seen: set[tuple[str, int, str]] = set()
    deduped: list[ServiceRecord] = []
    for s in all_services:
        key = (s.ip, s.port, s.protocol)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(s)

    # Dedupe TLS by ip:port
    tls_seen: set[tuple[str, int]] = set()
    tls_deduped: list[dict[str, Any]] = []
    for row in merged_raw.get("tls") or []:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").strip()
        try:
            port = int(row.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not ip or port < 1:
            continue
        key = (ip, port)
        if key in tls_seen:
            continue
        tls_seen.add(key)
        tls_deduped.append(row)
    merged_raw["tls"] = tls_deduped
    merged_raw["adapter"] = {
        "pulse_bin": pulse_bin,
        "os_detect": os_detect_effective,
        "os_detect_degraded": os_detect_degraded,
        # Whether CVE matching was asked of pulse at all. Together with the
        # ``completion`` receipts this is what lets the API say a verification
        # run re-checked a pulse finding (api/services/verification_coverage.py):
        # a receipt alone proves the endpoint was probed, not that its banner
        # was matched against anything.
        "cve": cve,
        "cve_online": cve_online,
        # The oldest ruleset any chunk matched with: one binary has one, and
        # if two ever answered, the claim made for the run is the weaker one.
        "ruleset": min(rulesets, key=ruleset_order) if rulesets else None,
        "pulse_version": min(pulse_versions) if pulse_versions else None,
        "chunk_hosts": size,
        **diagnostics,
    }

    write_pulse_artifacts(output_dir, deduped, all_os, all_cves, raw=merged_raw)

    # Mark report preference: explicit flag, else OCTO_SERVICE_BACKEND env.
    sync_report_primary_marker(pulse_dir, report_primary)

    logging.info(
        "pulse_probe done: %s services, %s os, %s cves, %s tls%s",
        len(deduped),
        len(all_os),
        len(all_cves),
        len(tls_deduped),
        " (OS detection skipped: no raw sockets)" if os_detect_degraded else "",
    )
    return pulse_dir
