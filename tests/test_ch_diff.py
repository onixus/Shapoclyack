"""Phase 10.1: normalized event helpers in the ClickHouse-backed diff path."""

from __future__ import annotations

from unittest.mock import patch

from api.services import ch_diff


def test_cve_key_to_event():
    assert ch_diff._cve_key_to_event("10.0.0.1|CVE-2020-1") == {
        "kind": "new_cve",
        "host": "10.0.0.1",
        "cve": "CVE-2020-1",
    }


def test_port_key_to_event():
    assert ch_diff._port_key_to_event("10.0.0.1:443/tcp") == {
        "kind": "new_open_port",
        "host": "10.0.0.1",
        "port": "443",
        "protocol": "tcp",
    }


def test_compute_clickhouse_diff_emits_events_for_added_only():
    with (
        patch.object(ch_diff, "fetch_tenant_cves", return_value={"10.0.0.1|CVE-2020-1", "10.0.0.2|CVE-2020-2"}),
        patch.object(ch_diff, "fetch_tenant_ports", return_value={"10.0.0.1:443/tcp"}),
    ):
        diff = ch_diff.compute_clickhouse_diff(
            "http://ch:8123",
            tenant_id="ten_acme",
            previous_cves={"10.0.0.2|CVE-2020-2"},
            previous_ports=set(),
        )
    assert diff["has_changes"] is True
    kinds = {(e["kind"], e.get("cve") or e.get("port")) for e in diff["events"]}
    assert kinds == {("new_cve", "CVE-2020-1"), ("new_open_port", "443")}
    assert diff["counts"]["events"] == 2
    # Removed-only deltas (none here) would not produce an event — matches
    # report_diff.py's convention of events being new/positive occurrences only.
