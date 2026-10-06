"""What a job asks for has to reach the executor that runs it (#338 review).

Agent execution became the Kubernetes default with #338, and the executor runs
``scanner.main`` with its own mounted config. Before this, two things an
operator sets in the console stopped at the API in that mode:

* the scan intent's config half — ``inventory`` recorded "nuclei off, top 100
  ports" on the job while the executor ran nuclei against the top 1000;
* the installation's config overrides — ``PUT /api/config`` accepted a 50 pps
  port rate, ``GET /api/config`` and the System page reported it as effective,
  and the executor scanned at the ConfigMap's 2000.

The job now carries both as a ``config_overlay.json`` input, which the worker
hands to the scanner as ``--config-overlay``. Each test below pins one half of
that: what is forwarded, what is deliberately not (the NVD key), the agent that
cannot apply it being refused rather than silently ignoring it, the scanner's
own allow-list, and the tenant scan policy staying the last word on rates.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from api.services import config_override
from api.services import scan_intents
from tests.conftest import auth_headers, configured_client, requires_postgres

K8S_CONFIG = Path("k8s/shapoclyack/base/config/k8s.yaml")
AGENT = {"Authorization": "Bearer test-agent-token"}
#: Spelled out rather than imported: they are wire names an agent built from
#: another release has to agree on, not implementation details.
OVERLAY_INPUT = "config_overlay.json"
CAPABILITY = "config_overlay.v1"
#: What an agent built from this tree reports.
CURRENT_AGENT = ["scan_policy", CAPABILITY]


def _client(tmp_path, monkeypatch):
    return configured_client(
        tmp_path, monkeypatch, job_execution_mode="agent", config_path=K8S_CONFIG
    )


def _register(client, hostname: str, capabilities: list[str] | None) -> str:
    body: dict[str, object] = {"hostname": hostname}
    if capabilities is not None:
        body["capabilities"] = capabilities
    response = client.post("/api/agent/register", headers=AGENT, json=body)
    assert response.status_code == 200, response.text
    return response.json()["agent_id"]


def _start(client, **body):
    response = client.post(
        "/api/jobs",
        headers=auth_headers(client, "operator"),
        json={"mode": "balanced", "ranges": "127.0.0.1\n", "domains": "\n", **body},
    )
    assert response.status_code == 202, response.text
    return response.json()


def _claim(client, agent_id: str):
    return client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=AGENT)


def _executor_run_config(tmp_path: Path, claim: dict, *, scan_policy: dict | None = None):
    """The config the executor's scanner runs with, assembled as ``main`` does.

    The executor's own file is ``K8S_CONFIG`` (the ``scanner-config``
    ConfigMap); the claim's inputs are written the way the worker writes them.
    """
    from scanner import main as scanner_main

    overlay_path = None
    if OVERLAY_INPUT in claim["inputs"]:
        overlay_path = tmp_path / "overlay.json"
        overlay_path.write_text(claim["inputs"][OVERLAY_INPUT], encoding="utf-8")
    policy_path = None
    if scan_policy is not None:
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(scan_policy), encoding="utf-8")
    args = argparse.Namespace(
        config=str(K8S_CONFIG),
        config_overlay=str(overlay_path) if overlay_path else None,
        scan_policy=str(policy_path) if policy_path else None,
        mode=claim["mode"],
        delta=bool(claim.get("delta")),
    )
    config, profile_name, _preset = scanner_main._config_for_run(args)
    return config, profile_name


# ---------------------------------------------------------------------------
# The two things the review found stopping at the API
# ---------------------------------------------------------------------------


@requires_postgres
def test_the_inventory_intent_reaches_the_executor(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    job = _start(client, mode="test", intent="inventory")
    assert job["scan_options"]["intent_summary"] == "inventory: ports-only, nuclei off, top 100 ports"

    claimed = _claim(client, _register(client, "exec", CURRENT_AGENT))
    assert claimed.status_code == 200, claimed.text
    claim = claimed.json()
    assert OVERLAY_INPUT in claim["inputs"]

    config, profile = _executor_run_config(tmp_path, claim)
    # What the job said it would do is what the executor does.
    assert config.nuclei.enabled is False
    assert config.profiles[profile].top_ports == 100
    assert claim["skip_nse"] is True


@requires_postgres
def test_console_overrides_reach_the_executor(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    put = client.put(
        "/api/config",
        headers=admin,
        json={"overrides": {"profiles.balanced.port_rate": 50, "nuclei.enabled": False}},
    )
    assert put.status_code == 200, put.text

    _start(client)
    claimed = _claim(client, _register(client, "exec", CURRENT_AGENT))
    assert claimed.status_code == 200, claimed.text
    config, profile = _executor_run_config(tmp_path, claimed.json())
    assert profile == "balanced"
    assert config.profiles["balanced"].port_rate == 50
    assert config.nuclei.enabled is False


@requires_postgres
def test_the_intent_wins_over_an_override_it_contradicts(tmp_path, monkeypatch):
    """Local mode merges base → overrides → intent; the forwarded overlay keeps
    that order, so an ``inventory`` job is ports-only even on an installation
    whose override turned nuclei on."""
    client = _client(tmp_path, monkeypatch)
    put = client.put(
        "/api/config",
        headers=auth_headers(client, "admin"),
        json={"overrides": {"nuclei.enabled": True, "profiles.balanced.top_ports": 1000}},
    )
    assert put.status_code == 200, put.text
    _start(client, intent="inventory")
    claimed = _claim(client, _register(client, "exec", CURRENT_AGENT))
    config, profile = _executor_run_config(tmp_path, claimed.json())
    assert config.nuclei.enabled is False
    assert config.profiles[profile].top_ports == 100


# ---------------------------------------------------------------------------
# What is deliberately not forwarded
# ---------------------------------------------------------------------------


@requires_postgres
def test_the_nvd_key_stays_on_the_api(tmp_path, monkeypatch):
    """The one secret the configurator holds is not something a scan needs
    (the executor's ``cve_online`` is off by default), and the claim response
    is an API payload that lands on an executor in somebody else's network."""
    client = _client(tmp_path, monkeypatch)
    secret = "nvd-key-that-must-stay-home"
    put = client.put(
        "/api/config",
        headers=auth_headers(client, "admin"),
        json={"overrides": {"enrichment.cvss4.nvd_api_key": secret, "nuclei.retries": 2}},
    )
    assert put.status_code == 200, put.text
    job = _start(client)
    assert secret not in json.dumps(job)

    claimed = _claim(client, _register(client, "exec", CURRENT_AGENT))
    assert claimed.status_code == 200, claimed.text
    assert secret not in claimed.text
    document = json.loads(claimed.json()["inputs"][OVERLAY_INPUT])
    assert "enrichment" not in document["config"]
    assert document["config"]["nuclei"]["retries"] == 2


@requires_postgres
def test_a_job_with_nothing_to_forward_carries_no_overlay(tmp_path, monkeypatch):
    """No override and no intent: nothing to forward, so an agent that predates
    the overlay still takes the job — the upgrade must not strand a fleet that
    never used either."""
    client = _client(tmp_path, monkeypatch)
    job = _start(client)
    assert "config_overlay" not in (job["scan_options"] or {})
    claimed = _claim(client, _register(client, "old-agent", None))
    assert claimed.status_code == 200, claimed.text
    assert OVERLAY_INPUT not in claimed.json()["inputs"]


# ---------------------------------------------------------------------------
# An agent that cannot apply it is refused, not handed a job it would misrun
# ---------------------------------------------------------------------------


@requires_postgres
def test_an_agent_that_cannot_apply_the_overlay_is_refused_the_job(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    job = _start(client, intent="inventory")

    old_agent = _register(client, "old-agent", ["scan_policy"])
    refused = _claim(client, old_agent)
    assert refused.status_code == 426, refused.text
    assert CAPABILITY in refused.json()["detail"]

    operator = auth_headers(client, "operator")
    assert client.get(f"/api/jobs/{job['job_id']}", headers=operator).json()["status"] == "queued"

    claimed = _claim(client, _register(client, "new-agent", CURRENT_AGENT))
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job_id"] == job["job_id"]


def test_this_agent_declares_the_capability_the_api_requires():
    from agent import worker
    from scanner.pipeline import config_overlay

    assert config_override.AGENT_CAPABILITY == CAPABILITY
    assert config_overlay.INPUT_NAME == OVERLAY_INPUT
    assert CAPABILITY in worker.CAPABILITIES
    # Every version this build applies, spelled out: a job asks for the one
    # its overlay needs, and the claim matches that string.
    assert set(config_overlay.CAPABILITIES) <= set(worker.CAPABILITIES)
    assert config_overlay.CAPABILITY in worker.CAPABILITIES


def test_the_worker_hands_the_overlay_to_the_scanner(tmp_path):
    from agent import worker

    body = json.dumps({"overlay_version": 1, "config": {"nuclei": {"enabled": False}}})
    args = worker._write_inputs(tmp_path, {OVERLAY_INPUT: body})
    assert args[:1] == ["--config-overlay"]
    assert Path(args[1]).read_text(encoding="utf-8") == body


# ---------------------------------------------------------------------------
# The scanner's side: an allow-list, and the policy still has the last word
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "overlay.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "config",
    [
        # Where alerts go and with which credentials is the executor host's
        # business, not something the platform may rewrite per job.
        {"alerts": {"enabled": True, "webhook_url": "https://example.invalid/hook"}},
        {"enrichment": {"cvss4": {"nvd_api_key": "x"}}},
        {"runtime": {"output_dir": "/etc"}},
        {"profiles": {"balanced": {"nmap_extra_args": "--script=all"}}},
    ],
)
def test_the_scanner_refuses_a_path_outside_its_allow_list(tmp_path, config):
    from scanner.pipeline import config_overlay

    path = _write(tmp_path, {"overlay_version": 1, "config": config})
    with pytest.raises(config_overlay.ConfigOverlayError):
        config_overlay.load_overlay(path)


def test_the_scanner_refuses_an_overlay_version_it_does_not_know(tmp_path):
    from scanner.pipeline import config_overlay

    path = _write(tmp_path, {"overlay_version": config_overlay.OVERLAY_VERSION + 1, "config": {}})
    with pytest.raises(config_overlay.ConfigOverlayError, match="version"):
        config_overlay.load_overlay(path)


def test_every_path_the_api_can_forward_is_one_the_scanner_accepts():
    """The two lists live on two sides of a network hop and in two packages;
    one drifting from the other would fail every scan of an installation that
    set the drifted path, on the executor, at run time."""
    from scanner.pipeline import config_overlay

    forwardable = set(config_override.EDITABLE_PATHS) - set(config_override.HOST_ONLY_PATHS)
    for intent in scan_intents.INTENTS:
        for mode in ("safe", "balanced", "fast", "test"):
            resolved = scan_intents.resolve_scan_options(
                intent=intent, mode=mode, delta=False, skip_nse=False
            )
            forwardable |= set(config_override._flatten(resolved.config_extra))
    refused = sorted(forwardable - config_overlay.OVERLAY_PATHS)
    assert not refused, f"the scanner would refuse: {refused}"


def test_the_scan_policy_still_caps_a_forwarded_rate(tmp_path):
    """Overlay first, policy last: an installation override can shape a scan
    but can never lift it above the tenant's ceiling (#362)."""
    claim = {
        "mode": "balanced",
        "inputs": {
            OVERLAY_INPUT: json.dumps(
                {
                    "overlay_version": 1,
                    "config": {"profiles": {"balanced": {"port_rate": 90_000}}},
                }
            )
        },
    }
    policy = {
        "policy_version": 1,
        "profile": "standard",
        "safe_only": False,
        "skip_service_probe": False,
        "avoid_ports": [],
        "max_discover_rate": None,
        "max_port_rate": 40,
        "max_host_concurrency": None,
        "per_host_rate": None,
    }
    config, _ = _executor_run_config(tmp_path, claim, scan_policy=policy)
    assert config.profiles["balanced"].port_rate == 40


# ---------------------------------------------------------------------------
# Review round 2
# ---------------------------------------------------------------------------


def _overlay_claim(config: dict, mode: str = "balanced") -> dict:
    return {
        "mode": mode,
        "inputs": {OVERLAY_INPUT: json.dumps({"overlay_version": 1, "config": config})},
    }


@requires_postgres
def test_an_old_sensor_still_takes_the_jobs_it_can_run(tmp_path, monkeypatch):
    """The claim used to take the head of the queue and refuse it: a job with
    nothing to forward, queued behind one with an overlay, was out of reach
    of every sensor that predates the overlay."""
    client = _client(tmp_path, monkeypatch)
    overlay_job = _start(client, intent="inventory")
    plain_job = _start(client)
    old_agent = _register(client, "old-agent", ["scan_policy"])

    first = _claim(client, old_agent)
    assert first.status_code == 200, first.text
    assert first.json()["job_id"] == plain_job["job_id"]
    # Only the job it cannot run is left: refused, visibly, and still queued.
    second = _claim(client, old_agent)
    assert second.status_code == 426, second.text
    operator = auth_headers(client, "operator")
    assert client.get(f"/api/jobs/{overlay_job['job_id']}", headers=operator).json()["status"] == "queued"


@requires_postgres
def test_a_refused_claim_is_counted(tmp_path, monkeypatch):
    from api.services import metrics as metrics_service

    series = metrics_service.SCAN_POLICY_REFUSALS_TOTAL.labels("config_overlay_unsupported")
    before = series._value.get()
    client = _client(tmp_path, monkeypatch)
    _start(client, intent="inventory")
    assert _claim(client, _register(client, "old-agent", ["scan_policy"])).status_code == 426
    assert series._value.get() == before + 1


@requires_postgres
def test_a_sensor_declaring_the_unversioned_capability_is_refused(tmp_path, monkeypatch):
    """A later release that adds a setting bumps the version; a sensor that
    only knows an older set must be refused on claim, not fail at run time."""
    client = _client(tmp_path, monkeypatch)
    _start(client, intent="inventory")
    claimed = _claim(client, _register(client, "agent", ["scan_policy", "config_overlay"]))
    assert claimed.status_code == 426, claimed.text


# sha256 of the sorted overlay paths, per version. Adding or removing a path
# without bumping the version fails here: a sensor on the old version would
# accept the claim and then refuse the run. A released version's set never
# changes, which is what the earlier entries pin.
OVERLAY_PATHS_DIGEST = {
    1: "e32112da7d251a59295b425ed27fd5851cb0d679746ae4b1ba40e9aeb004a1fe",
    2: "dca9190574a775d5e18afbeb967152792674c22e797557dcdffffc6a4be9743e",
}


def test_the_overlay_version_moves_with_its_settings():
    import hashlib

    from scanner.pipeline import config_overlay

    versions = sorted(config_overlay.PATHS_BY_VERSION)
    assert versions == list(range(1, config_overlay.OVERLAY_VERSION + 1))
    for version, paths in config_overlay.PATHS_BY_VERSION.items():
        digest = hashlib.sha256("\n".join(sorted(paths)).encode()).hexdigest()
        assert OVERLAY_PATHS_DIGEST.get(version) == digest, (version, digest)
    assert config_overlay.OVERLAY_PATHS == config_overlay.PATHS_BY_VERSION[versions[-1]]
    assert config_overlay.CAPABILITY == f"config_overlay.v{config_overlay.OVERLAY_VERSION}"
    # Each version takes everything the one before it took.
    for older, newer in zip(versions, versions[1:]):
        assert config_overlay.PATHS_BY_VERSION[older] <= config_overlay.PATHS_BY_VERSION[newer]


@requires_postgres
def test_a_path_on_the_api_host_is_not_sent(tmp_path, monkeypatch):
    """``nuclei.templates_dir`` names a directory on the API's filesystem; on a
    sensor it is missing, and nuclei was skipped without a word."""
    client = _client(tmp_path, monkeypatch)
    put = client.put(
        "/api/config",
        headers=auth_headers(client, "admin"),
        json={"overrides": {"nuclei.templates_dir": "/opt/api-only/templates", "nuclei.retries": 2}},
    )
    assert put.status_code == 200, put.text
    _start(client)
    claimed = _claim(client, _register(client, "exec", CURRENT_AGENT))
    document = json.loads(claimed.json()["inputs"][OVERLAY_INPUT])
    assert "templates_dir" not in document["config"]["nuclei"]


def test_the_scanner_refuses_a_templates_dir():
    from scanner.pipeline import config_overlay

    with pytest.raises(config_overlay.ConfigOverlayError):
        config_overlay.check_config({"nuclei": {"templates_dir": "/tmp"}})


def test_an_overlay_cannot_drop_the_hosts_nuclei_exclusions(tmp_path):
    """One installation-wide override reaches every tenant's sensors now; an
    empty ``exclude_tags`` there would have turned on intrusive, fuzz and dos
    templates on hosts whose own file excludes them."""
    config, _ = _executor_run_config(tmp_path, _overlay_claim({"nuclei": {"exclude_tags": ["cve-2099"]}}))
    assert {"intrusive", "fuzz", "dos", "cve-2099"} <= set(config.nuclei.exclude_tags)
    config, _ = _executor_run_config(tmp_path, _overlay_claim({"nuclei": {"exclude_tags": []}}))
    assert {"intrusive", "fuzz", "dos"} <= set(config.nuclei.exclude_tags)


def test_an_overlay_can_slow_a_sensor_down_but_not_speed_it_up(tmp_path):
    """The sensor's own file is its ceiling for rates and timing: a tenant
    with no scan policy was otherwise one console override away from T5 and
    100k pps on a network whose owner configured 2000."""
    fast = _overlay_claim(
        {
            "profiles": {"balanced": {"port_rate": 90_000, "discover_rate": 90_000, "nmap_timing": "T5"}},
            "nuclei": {"rate_limit": 10_000, "concurrency": 100},
        }
    )
    host, _ = _executor_run_config(tmp_path, {"mode": "balanced", "inputs": {}})
    config, _ = _executor_run_config(tmp_path, fast)
    assert config.profiles["balanced"].port_rate == host.profiles["balanced"].port_rate
    assert config.profiles["balanced"].discover_rate == host.profiles["balanced"].discover_rate
    assert config.profiles["balanced"].nmap_timing == host.profiles["balanced"].nmap_timing
    assert config.nuclei.rate_limit == host.nuclei.rate_limit
    assert config.nuclei.concurrency == host.nuclei.concurrency

    slow = _overlay_claim(
        {"profiles": {"balanced": {"port_rate": 50, "nmap_timing": "T2"}}, "nuclei": {"rate_limit": 5}}
    )
    config, _ = _executor_run_config(tmp_path, slow)
    assert config.profiles["balanced"].port_rate == 50
    assert config.profiles["balanced"].nmap_timing == "T2"
    assert config.nuclei.rate_limit == 5


def test_screenshots_stay_the_sensors_decision(tmp_path):
    """A headless browser visiting every web service is something a sensor's
    operator turns on, not something the platform turns on for them."""
    host, _ = _executor_run_config(tmp_path, {"mode": "balanced", "inputs": {}})
    assert host.screenshots.enabled is False
    config, _ = _executor_run_config(tmp_path, _overlay_claim({"screenshots": {"enabled": True}}))
    assert config.screenshots.enabled is False


@requires_postgres
def test_a_job_another_claim_holds_is_not_handed_out_again(tmp_path, monkeypatch):
    """The skip-ahead above looks again, without the lock, for a job the agent
    cannot run so it can say 426. That second look must never return a job
    another claim is holding: it would be claimed twice."""
    import threading

    from sqlalchemy import select

    from api.db import models
    from api.db.engine import get_session
    from tests.conftest import make_settings

    settings = make_settings(tmp_path, job_execution_mode="agent", config_path=K8S_CONFIG)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    job = _start(client)
    old_agent = _register(client, "old-agent", [])  # declares nothing at all
    locked, release = threading.Event(), threading.Event()

    def hold() -> None:
        with get_session(settings.postgres_url) as session:
            session.execute(
                select(models.Job).where(models.Job.job_id == job["job_id"]).with_for_update()
            ).scalars().first()
            locked.set()
            release.wait(10)
            session.rollback()

    holder = threading.Thread(target=hold)
    holder.start()
    try:
        assert locked.wait(10)
        timer = threading.Timer(3, release.set)
        timer.start()
        claimed = _claim(client, old_agent)
        timer.cancel()
    finally:
        release.set()
        holder.join(10)
    assert claimed.status_code == 204, claimed.text


# ---------------------------------------------------------------------------
# Overlay v2: nuclei.template_ids, asked of the claimant per job (#451)
# ---------------------------------------------------------------------------

PINNED = {"nuclei": {"template_ids": ["CVE-2021-44228"]}}


def test_a_document_is_written_at_the_lowest_version_that_covers_it():
    """So an inventory job queued by an upgraded API is still one a v1
    sensor's scanner applies, and only a pinned job is a v2 document."""
    from scanner.pipeline import config_overlay

    assert config_overlay.to_document({"nuclei": {"enabled": False}})["overlay_version"] == 1
    assert config_overlay.required_capability({"nuclei": {"enabled": False}}) == CAPABILITY
    assert config_overlay.to_document(PINNED)["overlay_version"] == 2
    assert config_overlay.required_capability(PINNED) == "config_overlay.v2"


def test_a_v1_document_cannot_carry_a_v2_setting(tmp_path):
    """Held to the version it names: an API that wrote ``overlay_version: 1``
    did not know what ``template_ids`` meant, so it did not send it."""
    from scanner.pipeline import config_overlay

    with pytest.raises(config_overlay.ConfigOverlayError, match="template_ids"):
        config_overlay.load_overlay(_write(tmp_path, {"overlay_version": 1, "config": PINNED}))
    document = {"overlay_version": 2, "config": PINNED}
    assert config_overlay.load_overlay(_write(tmp_path, document)) == PINNED


def test_a_pinned_template_reaches_the_executor_config(tmp_path):
    document = json.dumps({"overlay_version": 2, "config": PINNED})
    config, _ = _executor_run_config(tmp_path, {"mode": "balanced", "inputs": {OVERLAY_INPUT: document}})
    assert config.nuclei.template_ids == ["CVE-2021-44228"]


def _agent_settings(tmp_path):
    from tests.conftest import make_settings

    return make_settings(tmp_path, job_execution_mode="agent", config_path=K8S_CONFIG)


def _pinned_job(settings):
    from api.schemas import StartScanRequest
    from api.services import jobs as jobs_service

    return jobs_service.start_scan(
        settings,
        StartScanRequest(mode="safe", intent="vuln", ranges="127.0.0.1\n", ports="443"),
        username="system:verification",
        config_extra=PINNED,
    )


@requires_postgres
def test_a_sensor_that_predates_template_ids_is_refused_only_the_jobs_that_pin_them(
    tmp_path, monkeypatch
):
    """The capability is the job's, not the newest one: an API upgraded ahead
    of its fleet keeps the v1 sensors busy, and a verification re-scan that
    pins templates waits for a sensor that will load them — refused visibly,
    never handed to a scanner that would refuse the overlay on the host."""
    settings = _agent_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    pinned = _pinned_job(settings)
    assert pinned.scan_options["config_overlay_capability"] == "config_overlay.v2"
    assert pinned.scan_options["config_overlay"]["nuclei"]["template_ids"] == ["CVE-2021-44228"]
    plain = _start(client, intent="inventory")
    assert plain["scan_options"]["config_overlay_capability"] == CAPABILITY

    old_sensor = _register(client, "v1-sensor", ["scan_policy", CAPABILITY])
    first = _claim(client, old_sensor)
    assert first.status_code == 200, first.text
    assert first.json()["job_id"] == plain["job_id"]
    refused = _claim(client, old_sensor)
    assert refused.status_code == 426, refused.text
    assert "config_overlay.v2" in refused.json()["detail"]

    new_sensor = _register(client, "v2-sensor", ["scan_policy", CAPABILITY, "config_overlay.v2"])
    claimed = _claim(client, new_sensor)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job_id"] == pinned.job_id
    assert json.loads(claimed.json()["inputs"][OVERLAY_INPUT])["overlay_version"] == 2
    config, _ = _executor_run_config(tmp_path, claimed.json())
    assert config.nuclei.template_ids == ["CVE-2021-44228"]


@requires_postgres
def test_a_verification_job_needs_v2_whatever_its_overlay_carries(tmp_path, monkeypatch):
    """A pulse-only verification pins nothing, so its overlay is a v1 one; it
    still has to go to a build that writes the coverage evidence its closure
    is judged on. Asked for explicitly, not through a setting it happens to
    carry."""
    from api.schemas import StartScanRequest
    from api.services import jobs as jobs_service

    settings = _agent_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    job = jobs_service.start_scan(
        settings,
        StartScanRequest(mode="safe", intent="vuln", ranges="127.0.0.1\n", ports="443"),
        username="system:verification",
        min_overlay_version=2,
        verification_of="vln_1",
    )
    assert "template_ids" not in job.scan_options["config_overlay"]["nuclei"]
    assert job.scan_options["config_overlay_capability"] == "config_overlay.v2"
    assert job.scan_options["verification_of"] == "vln_1"

    refused = _claim(client, _register(client, "v1-sensor", ["scan_policy", CAPABILITY]))
    assert refused.status_code == 426, refused.text
    detail = refused.json()["detail"]
    assert "config_overlay.v2" in detail and "verification re-scan" in detail
    assert "console's config overrides" not in detail

    claimed = _claim(client, _register(client, "v2-sensor", ["scan_policy", CAPABILITY, "config_overlay.v2"]))
    assert claimed.status_code == 200, claimed.text
    # The document itself stays the lowest version that covers it.
    assert json.loads(claimed.json()["inputs"][OVERLAY_INPUT])["overlay_version"] == 1


@requires_postgres
def test_a_pinned_job_waits_visibly_while_only_v1_sensors_are_live(tmp_path, monkeypatch):
    settings = _agent_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    _register(client, "v1-sensor", ["scan_policy", CAPABILITY])
    assert _pinned_job(settings).sensor_unavailable is True
    assert _start(client, intent="inventory")["sensor_unavailable"] is False


@requires_postgres
def test_a_job_queued_before_the_capability_key_needs_v1(tmp_path, monkeypatch):
    """A job written by the previous release has an overlay and no
    ``config_overlay_capability``: its overlay is a v1 one, and a v1 sensor
    takes it."""
    from api.db import models
    from api.db.engine import get_session

    settings = _agent_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    job = _start(client, intent="inventory")
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job["job_id"])
        options = dict(row.scan_options)
        options.pop("config_overlay_capability")
        row.scan_options = options
    claimed = _claim(client, _register(client, "v1-sensor", ["scan_policy", CAPABILITY]))
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job_id"] == job["job_id"]


def test_the_platform_may_not_pin_a_setting_outside_the_allow_list(tmp_path):
    """``config_extra`` is checked where the job is made, like the overlay."""
    from api.schemas import StartScanRequest
    from api.services import jobs as jobs_service
    from scanner.pipeline import config_overlay

    with pytest.raises(config_overlay.ConfigOverlayError):
        jobs_service.start_scan(
            _agent_settings(tmp_path),
            StartScanRequest(mode="safe", ranges="127.0.0.1\n"),
            username="x",
            config_extra={"nuclei": {"templates_dir": "/tmp"}},
        )
