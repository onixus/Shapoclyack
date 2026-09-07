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

from api.services import assets as assets_service
from api.services.risk_scoring import FOOTHOLD, LOCAL, get_scorer, index_cdn_waf, path_role
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.ch-transform")

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
    *,
    settings: Settings | None = None,
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
    cdn_waf = index_cdn_waf(_load_json_member(members, "fingerprint.json"))
    db_enabled = settings is not None and bool(settings.postgres_url.strip())
    criticality_cache: dict[str, int | None] = {}
    exposure_cache: dict[str, str | None] = {}

    def _criticality_override(host_ip: str) -> int | None:
        if host_ip not in criticality_cache:
            criticality_cache[host_ip] = assets_service.get_asset_criticality_by_ip(
                settings, tenant_id, host_ip
            )
        return criticality_cache[host_ip]

    def _operator_exposure(host_ip: str) -> str | None:
        if host_ip not in exposure_cache:
            exposure_cache[host_ip] = assets_service.get_asset_exposure_by_ip(
                settings, tenant_id, host_ip
            )
        return exposure_cache[host_ip]

    foothold_hosts = {
        str(item.get("host") or "").strip()
        for item in vulns
        if isinstance(item, dict) and path_role(item) == FOOTHOLD
    }
    rows: list[list[Any]] = []
    for item in vulns:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").strip()
        if not host or not _is_ipv4(host):
            continue
        cve = item.get("cve") or item.get("script_id") or ""
        override = _criticality_override(host) if db_enabled else None
        scored = scorer.score_vulnerability(
            item,
            asset_criticality_override=override,
            operator_exposure=_operator_exposure(host) if db_enabled else None,
            cdn_waf_index=cdn_waf,
            same_asset_foothold=path_role(item) == LOCAL and host in foothold_hosts,
        )
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


# Status/impact/risk vocabularies from scanner/pipeline/controls.py. Rows land in
# ClickHouse for the control trend over time (EPIC #182, M3), so a value the
# scanner does not emit must not silently widen the enum on the ClickHouse side:
# anything unrecognised is normalised to an explicit "we do not know" bucket
# (`not_checked`, `unassessed`, `unknown`), never to a reassuring or a least
# severe one.
# "partial" is a matrix-level verdict only (some controls passed, others were
# never evaluated); an individual control never carries it.
_CONTROL_STATUSES = frozenset({"ok", "weak", "fail", "not_checked", "error"})
_OVERALL_VERDICTS = _CONTROL_STATUSES | {"partial"}
_CONTROL_IMPACTS = frozenset({"critical", "high", "medium", "low"})
_CONTROL_RISK_LEVELS = frozenset(
    {"very_high", "high", "moderate", "low", "very_low", "unassessed"}
)


def _severity_count(counts: Any, key: str) -> int:
    if not isinstance(counts, dict):
        return 0
    try:
        value = int(counts.get(key) or 0)
    except (TypeError, ValueError):
        return 0
    return max(value, 0)


def controls_to_rows(
    payload: dict[str, Any],
    members: dict[str, bytes],
) -> list[list[Any]]:
    """Map controls.json -> shapoclyack_controls rows (one per control per run).

    The controls matrix is a per-run snapshot, so the trend lives in the rows,
    not in the artifact: ORDER BY (tenant_id, control, timestamp, run_id) lets a
    dashboard read how one control moved across runs.
    """
    tenant_id = str(payload.get("tenant_id") or "default")
    tenant_uuid = tenant_to_uuid(tenant_id)
    run_id = str(payload.get("run_id") or "")
    summary = _load_json_member(members, "controls.json")
    if not isinstance(summary, dict):
        return []
    controls = summary.get("controls")
    if not isinstance(controls, list):
        return []

    # The controls stage stamps its own evaluated_at; fall back to the run start
    # so a run whose artifact predates that field still lands on the timeline.
    meta = _load_json_member(members, "run_meta.json") or {}
    raw_ts = summary.get("evaluated_at") or (
        meta.get("started_at") if isinstance(meta, dict) else None
    )
    ts = _parse_timestamp(raw_ts)

    overall_verdict = str(summary.get("overall_verdict") or "not_checked").lower()
    if overall_verdict not in _OVERALL_VERDICTS:
        overall_verdict = "not_checked"
    overall_risk = str(summary.get("overall_risk") or "unassessed").lower()
    if overall_risk not in _CONTROL_RISK_LEVELS:
        overall_risk = "unassessed"

    seen: set[str] = set()
    rows: list[list[Any]] = []
    for item in controls:
        if not isinstance(item, dict):
            continue
        control = str(item.get("control") or "").strip()
        if not control or control in seen:
            continue
        seen.add(control)

        status = str(item.get("status") or "not_checked").lower()
        if status not in _CONTROL_STATUSES:
            status = "not_checked"
        impact = str(item.get("impact") or "").lower()
        if impact not in _CONTROL_IMPACTS:
            # Not "low": impact is a fixed weight per control, and silently
            # filing an unrecognised rating under the least severe one would
            # understate the control in every query that reads the column.
            # "unknown" is the honest bucket, and it is visible as such.
            impact = "unknown"
        risk_level = str(item.get("risk_level") or "unassessed").lower()
        if risk_level not in _CONTROL_RISK_LEVELS:
            risk_level = "unassessed"

        coverage = item.get("coverage")
        checked = _severity_count(coverage, "checked")
        total = _severity_count(coverage, "total")
        severities = item.get("findings_by_severity")

        rows.append(
            [
                tenant_uuid,
                run_id,
                control,
                str(item.get("title") or ""),
                status,
                impact,
                risk_level,
                checked,
                total,
                _severity_count(severities, "critical"),
                _severity_count(severities, "high"),
                _severity_count(severities, "medium"),
                _severity_count(severities, "low"),
                overall_verdict,
                overall_risk,
                ts,
            ]
        )
    return rows


def transform_ingest_payload(
    payload: dict[str, Any], *, settings: Settings | None = None
) -> tuple[list[list[Any]], list[list[Any]], list[list[Any]]]:
    """Return (vuln_rows, port_rows, control_rows) from a NATS ingest body."""
    archive = archive_bytes_from_payload(payload)
    if archive is None:
        if payload.get("archive_inline") is False:
            LOG.warning(
                "Skipping ingest job=%s run=%s: archive not inlined",
                payload.get("job_id"),
                payload.get("run_id"),
            )
        return [], [], []
    try:
        members = extract_archive_members(archive)
    except Exception:  # noqa: BLE001
        LOG.exception("Failed to extract ingest archive job=%s", payload.get("job_id"))
        return [], [], []
    return (
        vulnerabilities_to_rows(payload, members, settings=settings),
        open_ports_to_rows(payload, members),
        controls_to_rows(payload, members),
    )
