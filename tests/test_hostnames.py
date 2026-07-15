from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.config_schema import DiscoveryConfig, HostnameResolveConfig
from scanner.pipeline.hostnames import (
    build_hostnames_map,
    enrich_discovery_hostnames,
    forward_map_from_resolution,
    merge_name_lists,
    primary_hostname,
)


def test_merge_name_lists_deduplicates():
    assert merge_name_lists(["App.Example.com.", "app.example.com"], ["other.example.com"]) == [
        "app.example.com",
        "other.example.com",
    ]


def test_forward_map_from_resolution(tmp_path: Path):
    (tmp_path / "dns_resolution.json").write_text(
        json.dumps(
            {
                "records": [
                    {"host": "app.example.com", "a": ["10.0.0.5", "10.0.0.6"]},
                    {"host": "db.example.com", "aaaa": ["2001:db8::1"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    mapping = forward_map_from_resolution(tmp_path)
    assert mapping["10.0.0.5"] == ["app.example.com"]
    assert mapping["2001:db8::1"] == ["db.example.com"]


def test_build_hostnames_map_merges_forward_and_reverse():
    hostnames = build_hostnames_map(
        ["10.0.0.5", "10.0.0.9"],
        forward={"10.0.0.5": ["app.example.com"]},
        reverse={"10.0.0.9": ["host9.internal."]},
    )
    assert hostnames["10.0.0.5"]["primary"] == "app.example.com"
    assert hostnames["10.0.0.9"]["primary"] == "host9.internal"
    assert hostnames["10.0.0.5"]["names"] == ["app.example.com"]


def test_primary_hostname_fallback():
    hostnames = {"10.0.0.1": {"names": ["a.example.com", "b.example.com"]}}
    assert primary_hostname(hostnames, "10.0.0.1") == "a.example.com"
    assert primary_hostname(hostnames, "10.0.0.2") == ""


def test_enrich_discovery_hostnames_forward_only(tmp_path: Path, monkeypatch):
    (tmp_path / "dns_resolution.json").write_text(
        json.dumps({"records": [{"host": "web.local", "a": ["10.0.0.10"]}]}),
        encoding="utf-8",
    )

    discovery = DiscoveryConfig(hostnames=HostnameResolveConfig(forward=True, reverse=False))
    called = {"ptr": False}

    def fake_ptr(*args, **kwargs):
        called["ptr"] = True
        return {}

    monkeypatch.setattr("scanner.pipeline.hostnames.reverse_map_from_ptr", fake_ptr)
    result = enrich_discovery_hostnames(
        ["10.0.0.10"],
        tmp_path,
        discovery,
        timeout=30,
        retries=1,
    )
    assert called["ptr"] is False
    assert result["10.0.0.10"]["primary"] == "web.local"
    assert json.loads((tmp_path / "hostnames.json").read_text(encoding="utf-8"))["10.0.0.10"]["primary"] == "web.local"
