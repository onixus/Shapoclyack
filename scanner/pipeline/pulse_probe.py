"""Pulse service/OS probe stage (nmap alternative for enrichment).

Invokes the Pulse CLI (https://github.com/onixus/GenDec) against hosts that
already have open ports from naabu, writes canonical artifacts:

  output_dir/pulse/raw.json       — full pulse JSON
  output_dir/services.json        — octo.service.v1 list
  output_dir/os.json              — octo.os.v1 list
  output_dir/pulse_cves.json      — optional CVE findings from pulse

Does **not** replace NSE scripts (ssl-enum-ciphers, vulners, …). Use
``service_probe.backend: hybrid`` or ``nmap`` when those are required.

Environment:
  OCTO_PULSE_BIN     — path to pulse binary (default: ``pulse`` on PATH)
  NVD_API_KEY        — optional; pulse also reads ~/.pulse/nvd_api_key
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from .protocol import parse_endpoint
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
            grouped[parsed.host].append(port)
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
        str(max(100, timeout_ms)),
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
        services.append(
            ServiceRecord(
                ip=ip,
                port=port,
                protocol=proto if proto in ("tcp", "udp") else "tcp",
                state="open",
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
) -> tuple[dict[str, Any], int]:
    """Run one pulse invocation and return its parsed payload and exit code."""
    completed = run_command(
        cmd,
        timeout=timeout_seconds,
        retries=retries,
        check=False,
        capture_output=True,
    )
    stdout = (completed.stdout or "").strip()
    if completed.returncode != 0:
        logging.warning(
            "pulse exited %s for chunk %s: %s",
            completed.returncode,
            idx,
            (completed.stderr or stdout)[:500],
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
    return payload, completed.returncode


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
) -> Path:
    """Run Pulse against hosts derived from open_ports; write artifacts.

    Returns ``output_dir / "pulse"``. Empty open_ports → empty artifacts, still OK.

    ``report_primary``: when True, write ``pulse/REPORT_PRIMARY`` so report.py
    prefers services.json/os.json. When None, fall back to
    ``OCTO_SERVICE_BACKEND`` in {pulse, hybrid}.
    """
    pulse_bin = resolve_pulse_bin(bin_path)
    grouped = _group_tcp_ports(open_ports)
    done = set(done_hosts or ())
    pending_hosts = sorted(h for h in grouped if h not in done)

    all_services: list[ServiceRecord] = []
    all_os: list[OsRecord] = []
    all_cves: list[CveRecord] = []
    merged_raw: dict[str, Any] = {
        "open": [],
        "os": [],
        "cves": [],
        "findings": [],
        "tls": [],
        "stats": {},
        "chunks": [],
    }

    pulse_dir = output_dir / "pulse"
    pulse_dir.mkdir(parents=True, exist_ok=True)

    if not pending_hosts:
        logging.info("pulse_probe: no TCP open ports to probe")
        write_pulse_artifacts(output_dir, [], [], [], raw=merged_raw)
        sync_report_primary_marker(pulse_dir, report_primary)
        return pulse_dir

    # Global port union keeps one pulse invocation simpler; overscans closed
    # ports on hosts that don't share the full set — acceptable for MVP.
    # Chunk by hosts for timeout/resume.
    size = max(1, chunk_hosts)
    chunks = [pending_hosts[i : i + size] for i in range(0, len(pending_hosts), size)]

    for idx, host_chunk in enumerate(chunks):
        ports_union: set[int] = set()
        for h in host_chunk:
            ports_union.update(grouped.get(h, []))
        ports_list = sorted(ports_union)
        if not ports_list:
            continue

        hosts_file = pulse_dir / f"chunk_{idx:04d}.hosts.txt"
        write_lines(hosts_file, host_chunk)
        ckpt = pulse_dir / f"chunk_{idx:04d}.ckpt"
        cmd = build_pulse_command(
            bin_path=pulse_bin,
            hosts_file=hosts_file,
            ports=ports_list,
            concurrency=concurrency,
            rate=rate,
            adaptive=adaptive,
            host_parallel=host_parallel,
            timeout_ms=timeout_ms,
            banner=banner,
            os_detect=os_detect,
            os_mode=os_mode,
            cve=cve,
            cve_online=cve_online,
            syn=syn,
            checkpoint=ckpt,
            max_hosts=max(max_hosts, len(host_chunk) + 1),
        )

        logging.info(
            "pulse_probe chunk %s/%s: %s hosts, %s ports",
            idx + 1,
            len(chunks),
            len(host_chunk),
            len(ports_list),
        )
        payload, returncode = _probe_chunk(
            cmd, timeout_seconds=timeout_seconds, retries=retries, idx=idx
        )

        # Every host here reached this stage because naabu proved a port open on
        # it moments ago, so an all-closed chunk is a contradiction rather than a
        # finding: the ports burst saturates the path and the probe lands before
        # it recovers. Pause and ask once more. The checkpoint has to go first --
        # pulse honours its own "status: done" and would replay the same zero
        # without touching the network.
        if not (payload.get("open") if payload else None) and retry_settle_seconds:
            logging.warning(
                "pulse_probe chunk %s: 0 services across %s host(s) with known-open "
                "ports; re-probing in %ss",
                idx,
                len(host_chunk),
                retry_settle_seconds,
            )
            ckpt.unlink(missing_ok=True)
            time.sleep(retry_settle_seconds)
            payload, returncode = _probe_chunk(
                cmd, timeout_seconds=timeout_seconds, retries=retries, idx=idx
            )

        resolved = bool(payload.get("open") if payload else None)
        if not resolved:
            # Leave nothing behind that records this chunk as finished-and-closed.
            # Dropping pulse's own checkpoint is not enough on its own: the hosts
            # would still be marked done below and the caller would still mark the
            # whole stage done, so --resume would skip the stage outright and keep
            # the false-empty result the retry above exists to recover from.
            ckpt.unlink(missing_ok=True)
            if on_unresolved:
                on_unresolved(list(host_chunk))

        if payload:
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
            merged_raw["chunks"].append(
                {"index": idx, "hosts": host_chunk, "returncode": returncode}
            )
            if isinstance(payload.get("stats"), dict):
                merged_raw["stats"] = payload["stats"]

        if resolved:
            for h in host_chunk:
                if on_host_done:
                    on_host_done(h)

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

    write_pulse_artifacts(output_dir, deduped, all_os, all_cves, raw=merged_raw)

    # Mark report preference: explicit flag, else OCTO_SERVICE_BACKEND env.
    sync_report_primary_marker(pulse_dir, report_primary)

    logging.info(
        "pulse_probe done: %s services, %s os, %s cves, %s tls",
        len(deduped),
        len(all_os),
        len(all_cves),
        len(tls_deduped),
    )
    return pulse_dir
