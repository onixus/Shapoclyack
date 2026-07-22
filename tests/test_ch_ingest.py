"""Phase 3: archive → ClickHouse row transforms (no live CH/NATS required)."""

from __future__ import annotations

import base64
import io
import json
import tarfile
from datetime import datetime

from api.services import ch_transform
from api.services.clickhouse_client import _parse_url
from tests.conftest import POSTGRES_URL, requires_postgres


def _archive(**files: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_transform_vulnerabilities_and_ports(monkeypatch):
    from api.services.risk_scoring import RiskScoring, reset_scorer_for_tests

    reset_scorer_for_tests(
        RiskScoring(epss={"CVE-2020-1": 0.4}, kev=set())
    )
    vulns = [
        {"host": "10.0.0.1", "port": "22", "cve": "CVE-2020-1", "cvss": 7.5, "severity": "high"},
        {"host": "not-an-ip", "port": "80", "cve": "CVE-2020-2", "cvss": 5.0},
        {"host": "10.0.0.2", "port": "443", "cve": None, "script_id": "ssl-enum", "cvss": None},
    ]
    findings = [
        {"host": "10.0.0.1", "port": 22, "protocol": "tcp"},
        {"host": "10.0.0.1", "port": 22, "protocol": "tcp"},  # dedupe
    ]
    meta = {"started_at": "2026-07-17T10:00:00Z"}
    archive = _archive(
        **{
            "vulnerabilities.json": json.dumps(vulns).encode(),
            "findings.json": json.dumps(findings).encode(),
            "open_ports.txt": b"10.0.0.2:443/tcp\n",
            "run_meta.json": json.dumps(meta).encode(),
        }
    )
    payload = {
        "tenant_id": "ten_acme",
        "run_id": "run1",
        "job_id": "job1",
        "archive_b64": base64.b64encode(archive).decode(),
    }
    vuln_rows, port_rows = ch_transform.transform_ingest_payload(payload)
    assert len(vuln_rows) == 2  # invalid host skipped
    assert vuln_rows[0][2] == "CVE-2020-1"
    assert vuln_rows[0][3] == 7.5
    assert vuln_rows[0][4] == 0.4  # epss
    assert vuln_rows[0][5] >= 3  # asset_criticality high + ssh boost
    assert vuln_rows[0][7] in ("Attend", "Act", "Immediate")
    assert vuln_rows[0][8] > 0  # contextual_score
    assert vuln_rows[0][9] == "mvp-1"
    assert isinstance(vuln_rows[0][10], datetime)
    assert vuln_rows[1][2] == "ssl-enum"
    # ports from findings + open_ports.txt
    assert len(port_rows) == 2
    ports = {(r[1], r[2], r[3]) for r in port_rows}
    assert ("10.0.0.1", 22, "tcp") in ports
    assert ("10.0.0.2", 443, "tcp") in ports
    reset_scorer_for_tests(None)


def test_tenant_uuid_stable():
    a = ch_transform.tenant_to_uuid("ten_acme")
    b = ch_transform.tenant_to_uuid("ten_acme")
    c = ch_transform.tenant_to_uuid("ten_other")
    assert a == b
    assert a != c


def test_parse_clickhouse_url():
    host, port, db, user, password = _parse_url(
        "http://ch:8123/shapoclyack",
        default_db="default",
    )
    assert host == "ch"
    assert port == 8123
    assert db == "shapoclyack"
    assert user == "default"


def test_skip_when_archive_not_inlined():
    vulns, ports = ch_transform.transform_ingest_payload(
        {"tenant_id": "t", "archive_inline": False}
    )
    assert vulns == []
    assert ports == []


def _settings_with_tenant(tmp_path):
    from api.services import tenants as tenants_service
    from api.settings import Settings

    settings = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        postgres_url=POSTGRES_URL,
    )
    settings.output_dir.mkdir(parents=True)
    settings.state_dir.mkdir(parents=True)
    tenants_service.load_tenants(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    return settings, tenants_service.DEFAULT_TENANT_ID


def _seed_asset(settings, tenant_id: str, host_ip: str, criticality: int | None):
    from datetime import UTC, datetime

    from api.db import models
    from api.db.engine import get_session
    from scanner.pipeline.asset_identity import ip_identity_key

    asset_id = ip_identity_key(tenant_id, host_ip)
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Asset(
                asset_id=asset_id,
                tenant_id=tenant_id,
                status="active",
                first_seen=now,
                last_seen=now,
                asset_criticality=criticality,
            )
        )
    return asset_id


@requires_postgres
def test_vulnerabilities_to_rows_uses_stored_asset_criticality(tmp_path):
    from api.services.risk_scoring import RiskScoring, reset_scorer_for_tests

    settings, tenant_id = _settings_with_tenant(tmp_path)
    # Low severity/base-CVSS, non-high-value port: the heuristic alone would
    # not produce a criticality of 4, so this proves the override is used.
    _seed_asset(settings, tenant_id, "10.0.2.1", 4)

    reset_scorer_for_tests(RiskScoring())
    try:
        vulns = [
            {"host": "10.0.2.1", "port": "8080", "cve": "CVE-2020-9", "cvss": 2.0, "severity": "low"},
        ]
        archive = _archive(
            **{
                "vulnerabilities.json": json.dumps(vulns).encode(),
                "run_meta.json": json.dumps({"started_at": "2026-07-17T10:00:00Z"}).encode(),
            }
        )
        payload = {
            "tenant_id": tenant_id,
            "run_id": "run1",
            "job_id": "job1",
            "archive_b64": base64.b64encode(archive).decode(),
        }
        vuln_rows, _ = ch_transform.transform_ingest_payload(payload, settings=settings)
        assert len(vuln_rows) == 1
        assert vuln_rows[0][5] == 4
    finally:
        reset_scorer_for_tests(None)


@requires_postgres
def test_vulnerabilities_to_rows_falls_back_when_asset_unset(tmp_path):
    from api.services.risk_scoring import RiskScoring, reset_scorer_for_tests

    settings, tenant_id = _settings_with_tenant(tmp_path)
    item = {"host": "10.0.2.2", "port": "22", "cve": "CVE-2018-15473", "cvss": 5.3, "severity": "medium"}

    reset_scorer_for_tests(RiskScoring())
    try:
        expected = RiskScoring().score_vulnerability(item)["asset_criticality"]

        archive = _archive(
            **{
                "vulnerabilities.json": json.dumps([item]).encode(),
                "run_meta.json": json.dumps({"started_at": "2026-07-17T10:00:00Z"}).encode(),
            }
        )
        payload = {
            "tenant_id": tenant_id,
            "run_id": "run1",
            "job_id": "job1",
            "archive_b64": base64.b64encode(archive).decode(),
        }
        # No asset row seeded for this host at all — falls back cleanly.
        vuln_rows, _ = ch_transform.transform_ingest_payload(payload, settings=settings)
        assert vuln_rows[0][5] == expected

        # An asset row that exists but has no criticality set also falls back.
        _seed_asset(settings, tenant_id, "10.0.2.2", None)
        vuln_rows2, _ = ch_transform.transform_ingest_payload(payload, settings=settings)
        assert vuln_rows2[0][5] == expected
    finally:
        reset_scorer_for_tests(None)


@requires_postgres
def test_vulnerabilities_to_rows_batches_lookup_per_host(tmp_path):
    from unittest.mock import patch

    from api.services.risk_scoring import RiskScoring, reset_scorer_for_tests

    settings, tenant_id = _settings_with_tenant(tmp_path)
    _seed_asset(settings, tenant_id, "10.0.2.3", 3)

    reset_scorer_for_tests(RiskScoring())
    try:
        vulns = [
            {"host": "10.0.2.3", "port": "80", "cve": "CVE-1", "cvss": 3.0},
            {"host": "10.0.2.3", "port": "443", "cve": "CVE-2", "cvss": 4.0},
            {"host": "10.0.2.3", "port": "8080", "cve": "CVE-3", "cvss": 5.0},
        ]
        archive = _archive(
            **{
                "vulnerabilities.json": json.dumps(vulns).encode(),
                "run_meta.json": json.dumps({"started_at": "2026-07-17T10:00:00Z"}).encode(),
            }
        )
        payload = {
            "tenant_id": tenant_id,
            "run_id": "run1",
            "job_id": "job1",
            "archive_b64": base64.b64encode(archive).decode(),
        }
        with patch(
            "api.services.ch_transform.assets_service.get_asset_criticality_by_ip",
            wraps=ch_transform.assets_service.get_asset_criticality_by_ip,
        ) as spy:
            vuln_rows, _ = ch_transform.transform_ingest_payload(payload, settings=settings)
        assert len(vuln_rows) == 3
        assert all(row[5] == 3 for row in vuln_rows)
        assert spy.call_count == 1
    finally:
        reset_scorer_for_tests(None)
