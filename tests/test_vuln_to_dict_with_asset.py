"""Unit coverage for vulnerability primary_fqdn/ip enrichment on write paths."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from api.services import vulnerabilities as vulns


def test_to_dict_with_asset_passes_loaded_asset_names():
    row = SimpleNamespace(asset_id="ast_1")
    session = MagicMock()
    asset = {"fqdn": "app.example.com", "ip": "8.8.8.8"}
    with patch.object(vulns, "_asset_names", return_value={"ast_1": asset}) as names:
        with patch.object(
            vulns,
            "_to_dict",
            return_value={
                "vuln_id": "vln_1",
                "primary_fqdn": "app.example.com",
                "primary_ip": "8.8.8.8",
            },
        ) as to_dict:
            payload = vulns._to_dict_with_asset(session, row, now="NOW")

    names.assert_called_once_with(session, ["ast_1"])
    to_dict.assert_called_once_with(row, now="NOW", asset=asset)
    assert payload["primary_fqdn"] == "app.example.com"
    assert payload["primary_ip"] == "8.8.8.8"


def test_to_dict_with_asset_handles_missing_asset():
    row = SimpleNamespace(asset_id="ast_missing")
    session = MagicMock()
    with patch.object(vulns, "_asset_names", return_value={}) as names:
        with patch.object(vulns, "_to_dict", return_value={"primary_fqdn": None}) as to_dict:
            vulns._to_dict_with_asset(session, row)

    names.assert_called_once_with(session, ["ast_missing"])
    to_dict.assert_called_once_with(row, now=None, asset=None)
