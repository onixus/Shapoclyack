"""Agent version: one source of truth, and the OCTO_AGENT_MIN_VERSION floor (#363).

The fleet used to compare every reported version against a literal ``0.42.0``
in ``api/services/agents.py`` while the agent itself shipped ``0.3.2.1``. Every
agent in every installation was therefore permanently ``is_outdated``, the
summary's ``outdated_agents`` equalled the fleet size, and ``upgrade_requested``
could never clear — ``register_agent`` clears it only when the reported version
*changes*, and no upgrade could ever reach a version the constant agreed with.

The two ``__version__`` literals cannot be collapsed into one module: the
scanner image copies ``agent`` without ``api`` and the API image copies ``api``
without ``agent``, so neither package can import the other. The first test here
is what holds them together instead.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import agent as agent_pkg
import api as api_pkg
from api.services import version_compare
from api.services.agents import LATEST_AGENT_VERSION
from api.settings import Settings
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres

pytestmark = requires_postgres


# Agent mode with the legacy shared token, as in test_api_agents.py.
SETTINGS = {"job_execution_mode": "agent"}


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return make_settings(tmp_path, **{**SETTINGS, **overrides})


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    return configured_client(tmp_path, monkeypatch, **{**SETTINGS, **overrides})


def _agent_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-agent-token"}


def _register(client: TestClient, version: str) -> str:
    response = client.post(
        "/api/agent/register",
        headers=_agent_headers(),
        json={"hostname": "edge-1", "version": version},
    )
    assert response.status_code == 200, response.text
    return response.json()["agent_id"]


# --------------------------------------------------------------------------
# One source of truth
# --------------------------------------------------------------------------


def test_agent_and_api_ship_the_same_version():
    """The drift guard. Bumping one literal without the other fails here."""
    assert agent_pkg.__version__ == api_pkg.__version__
    assert LATEST_AGENT_VERSION == api_pkg.__version__


def test_a_current_agent_is_not_reported_outdated(tmp_path, monkeypatch):
    """The user-visible half of the same bug: an agent on the shipped version
    must not be marked for upgrade, and the summary must not count it."""
    client = _client(tmp_path, monkeypatch)
    registered = _register(client, agent_pkg.__version__)
    assert registered

    summary = client.get("/api/agents/summary", headers=auth_headers(client, "operator")).json()
    assert summary["latest_version"] == agent_pkg.__version__
    assert summary["outdated_agents"] == 0


def test_upgrade_requested_clears_once_the_agent_reports_a_new_version(tmp_path, monkeypatch):
    """``upgrade_requested`` used to be permanent, because the version it waited
    for was one no release ever produced."""
    client = _client(tmp_path, monkeypatch)
    agent_id = _register(client, "0.3.2.1")
    admin = auth_headers(client, "admin")

    queued = client.post(f"/api/agents/{agent_id}/upgrade", headers=admin)
    assert queued.status_code == 200
    assert queued.json()["target_version"] == agent_pkg.__version__
    assert client.get(f"/api/agents/{agent_id}", headers=admin).json()["upgrade_requested"] is True

    re_registered = client.post(
        "/api/agent/register",
        headers=_agent_headers(),
        json={"agent_id": agent_id, "hostname": "edge-1", "version": agent_pkg.__version__},
    )
    assert re_registered.status_code == 200
    assert re_registered.json()["upgrade_requested"] is False


# --------------------------------------------------------------------------
# OCTO_AGENT_MIN_VERSION
# --------------------------------------------------------------------------


def test_version_ordering_handles_the_release_and_agent_formats():
    """Releases are ``0.44-0907`` (a date suffix), agent builds ``0.3.2.1``.
    PEP 440 reads the first as a post-release of ``0.44``; dpkg ordering, which
    this codebase already carries for package matching, reads both correctly."""
    assert version_compare.compare_dpkg_version("0.3.2.1", "0.44-0907") < 0
    assert version_compare.compare_dpkg_version("0.44-0907", "0.44-0907") == 0
    # A prerelease of the required version is not below it: the floor exists to
    # keep genuinely old agents out, not to refuse the build being rolled.
    assert version_compare.compare_dpkg_version("0.44-0907-beta1", "0.44-0907") >= 0


def test_no_minimum_admits_an_old_agent(tmp_path, monkeypatch):
    """The default. An empty floor must not fence off an existing fleet — 204
    is "nothing queued", i.e. the claim was accepted."""
    client = _client(tmp_path, monkeypatch, agent_min_version="")
    agent_id = _register(client, "0.3.2.1")

    claim = client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers())
    assert claim.status_code == 204

    detail = client.get(f"/api/agents/{agent_id}", headers=auth_headers(client, "operator")).json()
    assert detail["upgrade_required"] is False
    assert detail["upgrade_message"] is None


def test_agent_below_the_minimum_cannot_claim(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, agent_min_version="0.44-0907")
    agent_id = _register(client, "0.3.2.1")

    claim = client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers())
    assert claim.status_code == 426
    assert "0.44-0907" in claim.json()["detail"]


def test_agent_at_the_minimum_still_claims(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, agent_min_version="0.3.2.1")
    agent_id = _register(client, "0.3.2.1")

    claim = client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers())
    assert claim.status_code == 204


def test_a_refused_agent_still_registers_and_is_told_why(tmp_path, monkeypatch):
    """A gated agent must stay visible and keep heartbeating: the fleet view is
    where an operator finds the hosts that need upgrading, and the heartbeat
    response is the only channel that reaches the running process."""
    client = _client(tmp_path, monkeypatch, agent_min_version="0.44-0907")
    agent_id = _register(client, "0.3.2.1")

    heartbeat = client.post(
        "/api/agent/heartbeat",
        headers=_agent_headers(),
        json={"agent_id": agent_id, "status": "idle"},
    )
    assert heartbeat.status_code == 200
    body = heartbeat.json()
    assert body["upgrade_required"] is True
    assert body["min_version"] == "0.44-0907"
    assert "0.44-0907" in (body["upgrade_message"] or "")

    summary = client.get("/api/agents/summary", headers=auth_headers(client, "operator")).json()
    assert summary["total_agents"] == 1
    assert summary["min_version"] == "0.44-0907"


def test_an_agent_reporting_no_version_is_refused_once_a_floor_exists(tmp_path, monkeypatch):
    """An agent too old to report a version is exactly what a floor is for."""
    client = _client(tmp_path, monkeypatch, agent_min_version="0.44-0907")
    agent_id = _register(client, "")

    claim = client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers())
    assert claim.status_code == 426
