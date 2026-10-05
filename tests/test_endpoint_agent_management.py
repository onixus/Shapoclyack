"""Remote management of the Lariska endpoint agents (#358).

Covers the three things that only exist because an endpoint agent is not a
scanning agent: it is not judged against the scanner's version line, it cannot
claim scan work, and it can be told — over the heartbeat, the only channel that
reaches a running agent — what settings to use and which build to move to.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from api.core import permissions as permission_catalog
from api.services import agents as agents_service
from api.services import endpoint_agent_mgmt
from api.services import tenants as tenants_service
from tests.conftest import (
    auth_headers,
    bearer,
    configured_client,
    make_settings,
    requires_postgres,
)
from tests.test_api_mfa import Clock, enrol
from tests.test_tenant_lifecycle import _audit, _member

pytestmark = requires_postgres

BUILD = b"MZ\x90\x00 not really a PE, but bytes are bytes"
PLATFORM = "x86_64-pc-windows-msvc"


def _setup(tmp_path: Path, monkeypatch, tenant: str = "acme"):
    settings = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
    )
    client = configured_client(tmp_path, monkeypatch)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    agents_service.configure(settings)
    endpoint_agent_mgmt.configure(settings)
    endpoint_agent_mgmt.reset_for_tests()
    tenants_service.create_tenant(tenant_id=tenant, name=tenant.title())
    key = tenants_service.create_provisioning_key(tenant_id=tenant, label="lariska")["key"]
    return settings, client, key


def _agent_token(client, key: str, agent_id: str) -> dict[str, str]:
    resp = client.post(
        "/api/auth/agent/token",
        json={"provisioning_key": key, "agent_id": agent_id},
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _register(client, headers, agent_id: str, *, kind: str, version: str = "0.2.0"):
    resp = client.post(
        "/api/agent/register",
        json={
            "agent_id": agent_id,
            "hostname": "workstation-01",
            "version": version,
            "agent_kind": kind,
            "labels": {"agent.platform": PLATFORM},
        },
        headers=headers,
    )
    assert resp.status_code in (200, 201), resp.text
    return resp.json()


def test_endpoint_agent_is_not_measured_against_the_scanner_release_line(
    tmp_path: Path, monkeypatch
) -> None:
    """The defect this kind exists for.

    Lariska reports 0.2.0; the platform compared that against the *API's*
    version and told an operator every endpoint was outdated, with an offer to
    upgrade it to a build that is a different program entirely.
    """
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "lariska-01")
    body = _register(client, headers, "lariska-01", kind="endpoint")

    assert body["agent_kind"] == "endpoint"
    assert body["is_outdated"] is False
    assert body["latest_version"] == ""
    assert body["upgrade_required"] is False

    scanner_headers = _agent_token(client, key, "scanner-01")
    scanner = _register(client, scanner_headers, "scanner-01", kind="scanner")
    # The same reported version, judged — because for a scanner it means
    # something.
    assert scanner["agent_kind"] == "scanner"
    assert scanner["is_outdated"] is True
    assert scanner["latest_version"] != ""


def test_endpoint_agent_cannot_claim_scan_work(tmp_path: Path, monkeypatch) -> None:
    """A workstation that could claim a scan is a workstation that scans."""
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "lariska-01")
    _register(client, headers, "lariska-01", kind="endpoint")

    resp = client.post("/api/agent/jobs/claim?agent_id=lariska-01", headers=headers)
    assert resp.status_code == 403, resp.text
    assert "do not run scan jobs" in resp.json()["detail"]


def test_registering_as_endpoint_cannot_be_walked_back(tmp_path: Path, monkeypatch) -> None:
    """The correction runs one way only.

    An endpoint agent upgraded from a build predating the kind registers as a
    scanner because that is all it can say, so re-registration must be allowed
    to correct it. The reverse would let a host that is already recorded as an
    endpoint talk itself into the scanning fleet, where it becomes eligible for
    another tenant's work.
    """
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "lariska-01")
    _register(client, headers, "lariska-01", kind="scanner")
    promoted = _register(client, headers, "lariska-01", kind="endpoint")
    assert promoted["agent_kind"] == "endpoint"

    demoted = _register(client, headers, "lariska-01", kind="scanner")
    assert demoted["agent_kind"] == "endpoint"


def test_policy_reaches_the_agent_on_its_heartbeat(tmp_path: Path, monkeypatch) -> None:
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "lariska-01")
    _register(client, headers, "lariska-01", kind="endpoint")
    admin = auth_headers(client, username="admin")

    # Nothing set: the heartbeat says nothing rather than saying "defaults",
    # which the agent would apply as a reset.
    beat = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "lariska-01", "status": "idle", "platform": PLATFORM},
        headers=headers,
    )
    assert beat.status_code == 200, beat.text
    assert beat.json()["managed_settings"] is None
    assert beat.json()["managed_revision"] is None

    put = client.put(
        "/api/endpoint/agent/policy",
        json={"settings": {"inventory_interval_secs": 900, "log_level": "debug"}},
        headers=admin,
        params={"tenant_id": "acme"},
    )
    assert put.status_code == 200, put.text
    first_revision = put.json()["revision"]

    beat = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "lariska-01", "status": "idle", "platform": PLATFORM},
        headers=headers,
    ).json()
    assert beat["managed_settings"] == {
        "inventory_interval_secs": 900,
        "log_level": "debug",
    }
    assert beat["managed_revision"] == first_revision

    # An override merges over the default rather than replacing it, and the
    # revision moves so the agent knows to look again.
    client.put(
        "/api/endpoint/agent/policy/lariska-01",
        json={"settings": {"log_level": "trace"}},
        headers=admin,
        params={"tenant_id": "acme"},
    )
    beat = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "lariska-01", "status": "idle", "platform": PLATFORM},
        headers=headers,
    ).json()
    assert beat["managed_settings"] == {
        "inventory_interval_secs": 900,
        "log_level": "trace",
    }
    assert beat["managed_revision"] > first_revision


def test_a_scanning_agent_is_told_nothing(tmp_path: Path, monkeypatch) -> None:
    """The fleet of scanners pays nothing for a feature it cannot use."""
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "scanner-01")
    _register(client, headers, "scanner-01", kind="scanner")
    admin = auth_headers(client, username="admin")
    client.put(
        "/api/endpoint/agent/policy",
        json={"settings": {"inventory_interval_secs": 900}},
        headers=admin,
        params={"tenant_id": "acme"},
    )

    beat = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "scanner-01", "status": "idle"},
        headers=headers,
    ).json()
    assert beat["managed_settings"] is None
    assert beat["managed_update"] is None


@pytest.mark.parametrize(
    ("settings", "fragment"),
    [
        ({"server_url": "http://attacker.example"}, "not a setting"),
        ({"provisioning_key_file": "C:\\x"}, "not a setting"),
        ({"allow_plain_http": True}, "not a setting"),
        ({"inventory_interval_secs": 3}, "between"),
        ({"inventory_interval_secs": 100000}, "between"),
        ({"log_level": "shout"}, "log_level must be one of"),
    ],
)
def test_a_policy_cannot_repoint_or_cripple_an_agent(
    tmp_path: Path, monkeypatch, settings, fragment
) -> None:
    """Where the agent reports is not an operator's setting, and not this channel's.

    Out-of-range values are refused here too: the agent would reject them and
    keep running its previous configuration, which is indistinguishable from
    the policy never having arrived.
    """
    _setup(tmp_path, monkeypatch)
    _, client, _key = _setup(tmp_path, monkeypatch, tenant="acme2")
    admin = auth_headers(client, username="admin")
    resp = client.put(
        "/api/endpoint/agent/policy",
        json={"settings": settings},
        headers=admin,
        params={"tenant_id": "acme2"},
    )
    assert resp.status_code == 422, resp.text
    assert fragment in resp.json()["detail"]


def test_an_upgrade_is_offered_only_when_the_build_exists(
    tmp_path: Path, monkeypatch
) -> None:
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "lariska-01")
    _register(client, headers, "lariska-01", kind="endpoint", version="0.2.0")
    admin = auth_headers(client, username="admin")

    client.put(
        "/api/endpoint/agent/policy",
        json={"settings": {}, "desired_version": "0.3.0"},
        headers=admin,
        params={"tenant_id": "acme"},
    )

    # Asked for, but nobody uploaded it: the agent is told nothing it cannot
    # act on, and the reason is carried so it lands in the agent's own log.
    beat = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "lariska-01", "status": "idle", "platform": PLATFORM},
        headers=headers,
    ).json()
    assert beat["managed_update"] is None
    assert "no build is stored" in beat["managed_update_blocked"]

    upload = client.post(
        "/api/endpoint/agent/releases",
        data={"version": "0.3.0", "platform": PLATFORM},
        files={"binary": ("lariska.exe", BUILD, "application/octet-stream")},
        headers=admin,
        params={"tenant_id": "acme"},
    )
    assert upload.status_code == 201, upload.text
    # The digest is the API's, computed from what it stored.
    assert upload.json()["sha256"] == hashlib.sha256(BUILD).hexdigest()

    beat = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "lariska-01", "status": "idle", "platform": PLATFORM},
        headers=headers,
    ).json()
    update = beat["managed_update"]
    assert update["version"] == "0.3.0"
    assert update["sha256"] == hashlib.sha256(BUILD).hexdigest()
    assert beat["managed_update_blocked"] is None

    # And the agent can fetch it with the token it heartbeats with, so the
    # digest and the bytes come from one channel.
    download = client.get(update["url"], headers=headers)
    assert download.status_code == 200
    assert download.content == BUILD
    assert download.headers["X-Content-SHA256"] == hashlib.sha256(BUILD).hexdigest()


def test_an_agent_already_on_the_version_is_not_told_to_upgrade(
    tmp_path: Path, monkeypatch
) -> None:
    """Otherwise every heartbeat is an instruction to reinstall what is running."""
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "lariska-01")
    _register(client, headers, "lariska-01", kind="endpoint", version="0.3.0")
    admin = auth_headers(client, username="admin")
    client.post(
        "/api/endpoint/agent/releases",
        data={"version": "0.3.0", "platform": PLATFORM},
        files={"binary": ("lariska.exe", BUILD, "application/octet-stream")},
        headers=admin,
        params={"tenant_id": "acme"},
    )
    client.put(
        "/api/endpoint/agent/policy",
        json={"settings": {}, "desired_version": "0.3.0"},
        headers=admin,
        params={"tenant_id": "acme"},
    )

    beat = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "lariska-01", "status": "idle", "platform": PLATFORM},
        headers=headers,
    ).json()
    assert beat["managed_update"] is None


def test_an_agent_without_a_platform_is_not_handed_someone_elses_binary(
    tmp_path: Path, monkeypatch
) -> None:
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "lariska-01")
    _register(client, headers, "lariska-01", kind="endpoint", version="0.2.0")
    admin = auth_headers(client, username="admin")
    client.post(
        "/api/endpoint/agent/releases",
        data={"version": "0.3.0", "platform": PLATFORM},
        files={"binary": ("lariska.exe", BUILD, "application/octet-stream")},
        headers=admin,
        params={"tenant_id": "acme"},
    )
    client.put(
        "/api/endpoint/agent/policy",
        json={"settings": {}, "desired_version": "0.3.0"},
        headers=admin,
        params={"tenant_id": "acme"},
    )

    beat = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "lariska-01", "status": "idle"},
        headers=headers,
    ).json()
    assert beat["managed_update"] is None
    assert "reports no platform" in beat["managed_update_blocked"]


# --------------------------------------------------------------------------- #
# Who may write a build (#510)
# --------------------------------------------------------------------------- #

EVIL_BUILD = b"MZ\x90\x00 somebody else's idea of the agent"
#: Spelled out rather than read from the catalogue, so the refusal is checked
#: against the name an operator greps the audit trail and the docs for.
RELEASE_PERMISSION = "platform.endpoint_agent_release.manage"


def _upload(client, headers, tenant: str, content: bytes = BUILD, version: str = "0.3.0"):
    return client.post(
        "/api/endpoint/agent/releases",
        data={"version": version, "platform": PLATFORM},
        files={"binary": ("lariska.exe", content, "application/octet-stream")},
        headers=headers,
        params={"tenant_id": tenant},
    )


def _delete(client, headers, tenant: str, version: str = "0.3.0"):
    return client.delete(
        f"/api/endpoint/agent/releases/{version}/{PLATFORM}",
        headers=headers,
        params={"tenant_id": tenant},
    )


def test_the_release_permission_is_the_platform_admins_alone() -> None:
    assert RELEASE_PERMISSION in permission_catalog.PLATFORM_ADMIN_PERMISSIONS
    # Not grantable by a tenant either, built-in or custom role.
    assert RELEASE_PERMISSION not in permission_catalog.TENANT_GRANTABLE_PERMISSIONS


def test_a_tenant_admin_cannot_replace_the_build_every_tenant_downloads(
    tmp_path: Path, monkeypatch
) -> None:
    """The defect: the table is installation-wide, the gate was a tenant's.

    ``(version, platform)`` is the key, so an upload by one tenant's admin
    replaced the bytes every other tenant's endpoints were told to run, and a
    delete by it stopped every tenant's upgrade.
    """
    settings, client, key = _setup(tmp_path, monkeypatch)
    tenants_service.create_tenant(tenant_id="evil", name="Evil")
    admin = auth_headers(client, username="admin")
    evil_admin = _member(client, admin, "evil-admin", "evil", role="admin")

    assert _upload(client, admin, "acme").status_code == 201

    refused = _upload(client, evil_admin, "evil", EVIL_BUILD)
    assert refused.status_code == 403, refused.text
    assert RELEASE_PERMISSION in refused.json()["detail"]
    refused = _delete(client, evil_admin, "evil")
    assert refused.status_code == 403, refused.text
    assert RELEASE_PERMISSION in refused.json()["detail"]
    # Nor a build of its own under a version nobody has uploaded yet.
    assert _upload(client, evil_admin, "evil", EVIL_BUILD, version="9.9.9").status_code == 403

    # The victim's endpoint, told by its own admin to move to 0.3.0, is handed
    # the platform's bytes under the platform's digest.
    headers = _agent_token(client, key, "lariska-01")
    _register(client, headers, "lariska-01", kind="endpoint", version="0.2.0")
    client.put(
        "/api/endpoint/agent/policy",
        json={"settings": {}, "desired_version": "0.3.0"},
        headers=admin,
        params={"tenant_id": "acme"},
    )
    update = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "lariska-01", "status": "idle", "platform": PLATFORM},
        headers=headers,
    ).json()["managed_update"]
    assert update["sha256"] == hashlib.sha256(BUILD).hexdigest()
    download = client.get(update["url"], headers=headers)
    assert download.status_code == 200
    assert download.content == BUILD
    assert client.get(
        f"/api/endpoint/agent/releases/9.9.9/{PLATFORM}/download", headers=headers
    ).status_code == 404

    # And the platform admin still removes it.
    assert _delete(client, admin, "acme").status_code == 204
    assert endpoint_agent_mgmt.list_releases() == []
    # Both on the installation's record, not on whichever tenant the console
    # was looking at: the build was never that tenant's.
    for action in ("endpoint_agent.release.upload", "endpoint_agent.release.delete"):
        last = _audit(settings, action)[-1]
        assert (last.actor, last.tenant_id) == ("admin", None), action


def test_a_tenant_admin_keeps_its_policy_and_the_list_without_the_uploader(
    tmp_path: Path, monkeypatch
) -> None:
    """``endpoint_agent.manage`` still decides which build the tenant runs."""
    _, client, _key = _setup(tmp_path, monkeypatch)
    admin = auth_headers(client, username="admin")
    acme_admin = _member(client, admin, "acme-admin", "acme", role="admin")
    assert _upload(client, admin, "acme").status_code == 201

    policy = client.put(
        "/api/endpoint/agent/policy",
        json={"settings": {}, "desired_version": "0.3.0"},
        headers=acme_admin,
        params={"tenant_id": "acme"},
    )
    assert policy.status_code == 200, policy.text

    listed = client.get(
        "/api/endpoint/agent/releases", headers=acme_admin, params={"tenant_id": "acme"}
    )
    assert listed.status_code == 200, listed.text
    (row,) = listed.json()
    assert row["sha256"] == hashlib.sha256(BUILD).hexdigest()
    # Which platform account uploaded it is not the tenant's to know.
    assert row["uploaded_by"] is None
    (row,) = client.get(
        "/api/endpoint/agent/releases", headers=admin, params={"tenant_id": "acme"}
    ).json()
    assert row["uploaded_by"] == "admin"


def test_an_admin_service_token_cannot_write_a_build(tmp_path: Path, monkeypatch) -> None:
    """An admin-role token administers its tenant, not the installation."""
    _, client, _key = _setup(tmp_path, monkeypatch)
    admin = auth_headers(client, username="admin")
    minted = client.post(
        "/api/tenants/acme/service-tokens",
        headers=admin,
        json={"name": "ci", "role": "admin", "scopes": ["*"], "ttl_days": 1},
    )
    assert minted.status_code == 201, minted.text
    token = bearer(minted.json()["token"])
    assert _upload(client, token, "acme").status_code == 403
    assert endpoint_agent_mgmt.list_releases() == []


def test_writing_a_build_needs_a_recent_second_factor(tmp_path: Path, monkeypatch) -> None:
    clock = Clock()
    monkeypatch.setattr("api.services.mfa._now", clock)
    _, client, _key = _setup(tmp_path, monkeypatch)
    admin = auth_headers(client, username="admin")
    enrol(client, admin, clock)

    refused = _upload(client, admin, "acme")
    assert refused.status_code == 403 and "multi-factor" in refused.json()["detail"]
    refused = _delete(client, admin, "acme")
    assert refused.status_code == 403 and "multi-factor" in refused.json()["detail"]
    # Reading is not a change.
    assert client.get(
        "/api/endpoint/agent/releases", headers=admin, params={"tenant_id": "acme"}
    ).status_code == 200
