"""Transform NATS ingest archives into ClickHouse rows (Phase 3)."""

from __future__ import annotations

import base64
import io
import ipaddress
import json
import logging
import tarfile
import uuid
from datetime import UTC, datetime
from typing import Any

from api.services.risk_scoring import SCORING_MODEL_VERSION, get_scorer

LOG = logging.getLogger("octo-man.ch-transform")

TENANT_UUID_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace


def tenant_to_uuid(tenant_id: str) -> uuid.UUID:
    """Map string tenant ids (e.g. ten_acme / default) to stable UUIDs."""
    return uuid.uuid5(TENANT_UUID_NS, tenant_id or "default")


def _parse_timestamp(raw: Any) -> datetime:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo is None else raw.astimezone(UTC).replace(tzinfo=None)
    if isinstance(raw, str) and raw.strip():
        text = raw.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is not None:
                dt = dt.astimezone(UTC).replace(tzinfo=None)
            return dt
        except ValueError:
            pass
    return datetime.now(UTC).replace(tzinfo=None)


def _is_ipv4(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    except ValueError:
        return False


def extract_archive_members(archive_bytes: bytes) -> dict[str, bytes]:
    """Return {arcname: file_bytes} from a gzip tar archive."""
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            out[member.name.replace("\\", "/")] = extracted.read()
    return out


def archive_bytes_from_payload(payload: dict[str, Any]) -> bytes | None:
    b64 = payload.get("archive_b64")
    if isinstance(b64, str) and b64:
        return base64.b64decode(b64)
    return None


def _load_json_member(members: dict[str, bytes], name: str) -> Any:
    raw = members.get(name)
    if raw is None:
        # Allow nested paths like runs/.../vulnerabilities.json
        for key, value in members.items():
            if key.endswith("/" + name) or key == name:
                raw = value
                break
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def vulnerabilities_to_rows(
    payload: dict[str, Any],
    members: dict[str, bytes],
) -> list[list[Any]]:
    """Map vulnerabilities.json → shapoclyack_vulnerabilities rows."""
    tenant_id = str(payload.get("tenant_id") or "default")
    tenant_uuid = tenant_to_uuid(tenant_id)
    meta = _load_json_member(members, "run_meta.json") or {}
    ts = _parse_timestamp(meta.get("started_at") if isinstance(meta, dict) else None)
    vulns = _load_json_member(members, "vulnerabilities.json")
    if not isinstance(vulns, list):
        return []

    scorer = get_scorer()
    rows: list[list[Any]] = []
    for item in vulns:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").strip()
        if not host or not _is_ipv4(host):
            continue
        cve = item.get("cve") or item.get("script_id") or ""
        scored = scorer.score_vulnerability(item)
        rows.append(
            [
                tenant_uuid,
                host,
                str(cve),
                float(scored["base_cvss"]),
                float(scored["epss_score"]),
                int(scored["asset_criticality"]),
                int(scored["exploit_active"]),
                str(scored["cisa_decision"]),
                float(scored["contextual_score"]),
                str(scored["scoring_model_version"]),
                ts,
            ]
        )
    return rows


def open_ports_to_rows(
    payload: dict[str, Any],
    members: dict[str, bytes],
) -> list[list[Any]]:
    """Map open_ports.txt / findings.json → shapoclyack_open_ports rows.

    ORDER BY (tenant_id, target_ip, port) per roadmap 3.3.
    """
    tenant_id = str(payload.get("tenant_id") or "default")
    tenant_uuid = tenant_to_uuid(tenant_id)
    run_id = str(payload.get("run_id") or "")
    meta = _load_json_member(members, "run_meta.json") or {}
    ts = _parse_timestamp(meta.get("started_at") if isinstance(meta, dict) else None)

    seen: set[tuple[str, int, str]] = set()
    rows: list[list[Any]] = []

    def add(host: str, port: int, protocol: str) -> None:
        if not _is_ipv4(host) or port < 1 or port > 65535:
            return
        key = (host, port, protocol)
        if key in seen:
            return
        seen.add(key)
        rows.append([tenant_uuid, host, port, protocol, run_id, ts])

    ports_raw = members.get("open_ports.txt")
    if ports_raw is None:
        for key, value in members.items():
            if key.endswith("open_ports.txt"):
                ports_raw = value
                break
    if ports_raw:
        for line in ports_raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            # host:port/tcp
            host_part, _, rest = line.partition(":")
            port_s, _, proto = rest.partition("/")
            try:
                add(host_part.strip(), int(port_s), (proto or "tcp").lower())
            except ValueError:
                continue

    findings = _load_json_member(members, "findings.json")
    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or "").strip()
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError):
                continue
            proto = str(item.get("protocol") or "tcp").lower()
            add(host, port, proto)

    return rows


def transform_ingest_payload(payload: dict[str, Any]) -> tuple[list[list[Any]], list[list[Any]]]:
    """Return (vuln_rows, port_rows) from a NATS ingest message body."""
    archive = archive_bytes_from_payload(payload)
    if archive is None:
        if payload.get("archive_inline") is False:
            LOG.warning(
                "Skipping ingest job=%s run=%s: archive not inlined",
                payload.get("job_id"),
                payload.get("run_id"),
            )
        return [], []
    try:
        members = extract_archive_members(archive)
    except Exception:  # noqa: BLE001
        LOG.exception("Failed to extract ingest archive job=%s", payload.get("job_id"))
        return [], []
    return vulnerabilities_to_rows(payload, members), open_ports_to_rows(payload, members)
