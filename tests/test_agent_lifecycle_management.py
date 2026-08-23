"""Tests for Agent Fleet Monitoring, Health Metrics, Deployment, and Update Lifecycle."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


def test_agent_telemetry_heartbeat_and_fleet_summary(tmp_path: Path, monkeypatch):
    settings = make_settings(tmp_path, agent_stale_seconds=10)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")

    # 1. Register two agents
    reg1 = client.post(
        "/api/agent/register",
        json={
            "agent_id": "agent-alpha",
            "hostname": "srv-scan-01",
            "version": "0.42.0",
            "labels": {"zone": "eu-west-1", "tier": "production"},
        },
        headers={"Authorization": f"Bearer {settings.agent_token}"},
    )
    assert reg1.status_code == 200
    assert reg1.json()["agent_id"] == "agent-alpha"

    reg2 = client.post(
        "/api/agent/register",
        json={
            "agent_id": "agent-beta",
            "hostname": "srv-scan-02",
            "version": "0.40.0",  # Outdated version
            "labels": {"zone": "us-east-1", "tier": "staging"},
        },
        headers={"Authorization": f"Bearer {settings.agent_token}"},
    )
    assert reg2.status_code == 200
    assert reg2.json()["is_outdated"] is True

    # 2. Send heartbeat with system metrics
    hb_resp = client.post(
        "/api/agent/heartbeat",
        json={
            "agent_id": "agent-alpha",
            "status": "busy",
            "current_job_id": "job-101",
            "detail": "Scanning 10.0.0.0/24",
            "metrics": {
                "cpu_percent": 34.5,
                "memory_used_mb": 512.0,
                "memory_total_mb": 4096.0,
                "disk_free_gb": 42.0,
                "uptime_seconds": 3600,
            },
            "capabilities": ["pulse", "nuclei", "nmap"],
        },
        headers={"Authorization": f"Bearer {settings.agent_token}"},
    )
    assert hb_resp.status_code == 200
    hb_data = hb_resp.json()
    assert hb_data["status"] == "busy"
    assert hb_data["metrics"]["cpu_percent"] == 34.5
    assert hb_data["metrics"]["uptime_seconds"] == 3600
    assert hb_data["capabilities"] == ["pulse", "nuclei", "nmap"]

    # 3. Fleet Summary API Check
    summary_resp = client.get("/api/agents/summary", headers=admin_hdrs)
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert summary["total_agents"] == 2
    assert summary["online_agents"] == 2
    assert summary["busy_agents"] == 1
    assert summary["outdated_agents"] == 1
    assert summary["latest_version"] == "0.42.0"

    # 4. Get Agent Detail API
    detail_resp = client.get("/api/agents/agent-alpha", headers=admin_hdrs)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["agent_id"] == "agent-alpha"
    assert detail["hostname"] == "srv-scan-01"
    assert detail["metrics"]["cpu_percent"] == 34.5
    assert detail["online"] is True
    assert detail["is_outdated"] is False

    # 5. Remote Upgrade Request Trigger
    upgrade_resp = client.post("/api/agents/agent-beta/upgrade", headers=admin_hdrs)
    assert upgrade_resp.status_code == 200
    assert upgrade_resp.json()["status"] == "upgrade_queued"

    # Check detail confirms upgrade_requested
    detail_beta = client.get("/api/agents/agent-beta", headers=admin_hdrs).json()
    assert detail_beta["upgrade_requested"] is True
    assert detail_beta["is_outdated"] is True

    # 6. Delete / Deregister Agent
    del_resp = client.delete("/api/agents/agent-beta", headers=admin_hdrs)
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"

    # Confirm 404
    assert client.get("/api/agents/agent-beta", headers=admin_hdrs).status_code == 404


def test_agent_installer_and_deployment_snippets(tmp_path: Path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")

    # 1. Download install.sh
    sh_resp = client.get("/api/agent/install.sh")
    assert sh_resp.status_code == 200
    assert "#!/usr/bin/env bash" in sh_resp.text
    assert "Shapoclyack Remote Agent Universal Installer" in sh_resp.text

    # 2. Get Deployment Snippets
    snip_resp = client.get("/api/agent/deployment-command", headers=admin_hdrs)
    assert snip_resp.status_code == 200
    snips = snip_resp.json()
    assert snips["provisioning_key"].startswith("octo-pk-")
    assert "curl -sSL" in snips["systemd_oneliner"]
    assert "docker run -d --name shapoclyack-agent" in snips["docker_run"]
    assert "apiVersion: apps/v1" in snips["kubernetes_yaml"]


def test_remote_ssh_deployer_flow(tmp_path: Path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")

    # Mock SSH execution to simulate successful connection and install
    def fake_ssh_cmd(req, cmd, timeout=120):
        if "uname" in cmd:
            return 0, "Linux x86_64 0\n", ""
        if "install.sh" in cmd:
            return 0, "Agent installed successfully\n", ""
        return 0, "ok\n", ""

    monkeypatch.setattr("api.services.agent_deployer._execute_ssh_command", fake_ssh_cmd)

    deploy_payload = {
        "host": "192.168.10.50",
        "port": 22,
        "username": "admin",
        "password": "secret-ssh-password",
        "tenant_id": "default",
        "agent_id": "agent-remote-50",
    }

    start_resp = client.post("/api/agent/deploy/ssh", json=deploy_payload, headers=admin_hdrs)
    assert start_resp.status_code == 200
    deploy_data = start_resp.json()
    deploy_id = deploy_data["deploy_id"]
    assert deploy_id.startswith("dep_")
    assert deploy_data["status"] in ("queued", "connecting", "installing")

    # Poll status
    status_resp = client.get(f"/api/agent/deploy/{deploy_id}/status", headers=admin_hdrs)
    assert status_resp.status_code == 200
    assert len(status_resp.json()["logs"]) >= 1
