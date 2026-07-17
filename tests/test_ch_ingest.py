"""Phase 3: archive → ClickHouse row transforms (no live CH/NATS required)."""

from __future__ import annotations

import base64
import io
import json
import tarfile
from datetime import datetime

from api.services import ch_transform
from api.services.clickhouse_client import _parse_url


def _archive(**files: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_transform_vulnerabilities_and_ports():
    vulns = [
        {"host": "10.0.0.1", "port": "22", "cve": "CVE-2020-1", "cvss": 7.5},
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
    assert isinstance(vuln_rows[0][10], datetime)
    assert vuln_rows[1][2] == "ssl-enum"
    # ports from findings + open_ports.txt
    assert len(port_rows) == 2
    ports = {(r[1], r[2], r[3]) for r in port_rows}
    assert ("10.0.0.1", 22, "tcp") in ports
    assert ("10.0.0.2", 443, "tcp") in ports


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
