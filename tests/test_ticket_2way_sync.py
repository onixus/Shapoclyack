"""Tests for two-way ticket synchronization (Jira, ServiceNow, DefectDojo) (Sprint 2)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from api.services.integrations import ticket_sync


def test_map_jira_remote_status():
    # Test Done -> CLOSED
    suggested, raw = ticket_sync.map_remote_status_to_vuln_state(
        "jira", {"fields": {"status": {"name": "Done"}}}
    )
    assert suggested == "CLOSED"
    assert raw == "Done"

    # Test In Progress -> FIXING
    suggested, raw = ticket_sync.map_remote_status_to_vuln_state(
        "jira", {"fields": {"status": {"name": "In Progress"}}}
    )
    assert suggested == "FIXING"

    # Test In Review -> VERIFYING
    suggested, raw = ticket_sync.map_remote_status_to_vuln_state(
        "jira", {"fields": {"status": {"name": "In Review"}}}
    )
    assert suggested == "VERIFYING"


def test_map_servicenow_remote_status():
    # State 6 = Resolved -> CLOSED
    suggested, raw = ticket_sync.map_remote_status_to_vuln_state(
        "servicenow", {"result": {"incident_state": "6", "state": "6"}}
    )
    assert suggested == "CLOSED"

    # State 2 = In Progress -> FIXING
    suggested, raw = ticket_sync.map_remote_status_to_vuln_state(
        "servicenow", {"result": {"incident_state": "2", "state": "2"}}
    )
    assert suggested == "FIXING"


def test_map_defectdojo_remote_status():
    # is_mitigated = True -> CLOSED
    suggested, raw = ticket_sync.map_remote_status_to_vuln_state(
        "defectdojo", {"active": False, "is_mitigated": True}
    )
    assert suggested == "CLOSED"
    assert raw == "Mitigated"

    # active = True -> FIXING
    suggested, raw = ticket_sync.map_remote_status_to_vuln_state(
        "defectdojo", {"active": True, "is_mitigated": False}
    )
    assert suggested == "FIXING"
    assert raw == "Active"


@patch("httpx.Client")
def test_fetch_ticket_status_jira(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"fields": {"status": {"name": "Resolved"}}}
    mock_client.get.return_value = mock_resp

    suggested, raw, data = ticket_sync.fetch_ticket_status(
        transport="jira",
        base_url="https://jira.example.com",
        ticket_key="SEC-101",
        secret="token123",
    )

    assert suggested == "CLOSED"
    assert raw == "Resolved"


@patch("httpx.Client")
def test_push_status_update_defectdojo(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_client.patch.return_value = mock_resp

    ok = ticket_sync.push_status_update(
        transport="defectdojo",
        base_url="https://dojo.example.com",
        ticket_key="42",
        to_state="CLOSED",
        secret="apikey123",
    )

    assert ok is True
    mock_client.patch.assert_called_once()
