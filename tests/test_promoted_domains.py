"""Promoted related domains become scope for the tenant's later scans (org_profile M4).

Before this, ``POST /runs/{id}/related-domains/{domain}/promote`` wrote a file
into the run directory that nothing ever read: the operator pressed "add to
scope" and the next scan did not know. The decision now lives on the tenant
and every ordinary scan carries it — held to the approved scope (#226) both
when it is made and when it is used.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent import worker as agent_worker
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import auth_audit
from api.services import jobs as jobs_service
from api.services import promoted_domains
from api.services import runs as runs_service
from api.services import scan_scopes
from api.services import tenants as tenants_service
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres

ALLOW_EXAMPLE = {"effect": "allow", "kind": "domain", "value": "example.com"}
ALLOW_PARTNER = {"effect": "allow", "kind": "domain", "value": "acme-partner.com"}
DENY_PARTNER = {"effect": "deny", "kind": "domain", "value": "acme-partner.com"}


@pytest.fixture()
def settings(tmp_path: Path):
    base = make_settings(tmp_path, state_dir=tmp_path / "state", output_dir=tmp_path / "output")
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    auth_audit.configure(base)
    auth_audit.reset_for_tests()
    promoted_domains.reset_for_tests(base)
    return base


@pytest.fixture()
def agent_settings(settings):
    settings.job_execution_mode = "agent"
    agents_service.configure(settings)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    return settings


def _scope(settings, *entries: dict) -> None:
    scan_scopes.replace_scope(
        settings, tenant_id="default", entries=list(entries), approved_by="admin"
    )


def _run_with_candidates(settings, run_id: str, *candidates: str, tenant_id: str = "default") -> None:
    run_dir = settings.output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "tenant.json").write_text(json.dumps({"tenant_id": tenant_id}), encoding="utf-8")
    (run_dir / "related_domains.json").write_text(
        json.dumps(
            {
                "seed_domains": ["example.com"],
                "candidates": [
                    {"domain": name, "status": "confirmed", "confidence": 0.9, "sources": ["cert_san"]}
                    for name in candidates
                ],
            }
        ),
        encoding="utf-8",
    )


def _promoted_file(settings, job) -> Path:
    return jobs_service.job_inputs_dir(settings, job.job_id) / jobs_service.PROMOTED_DOMAINS_INPUT


# --- the decision ------------------------------------------------------------


def test_promote_is_stored_on_the_tenant_not_in_the_run(settings):
    _scope(settings, ALLOW_EXAMPLE, ALLOW_PARTNER)
    _run_with_candidates(settings, "run-1", "acme-partner.com")

    res = runs_service.promote_related_domain(
        settings, "run-1", "Acme-Partner.com.", username="operator"
    )

    assert res == {
        "domain": "acme-partner.com",
        "promoted": True,
        "message": res["message"],
        "promoted_at": res["promoted_at"],
    }
    rows = promoted_domains.list_promoted(settings, "default")
    assert [(r.domain, r.source_run_id, r.promoted_by) for r in rows] == [
        ("acme-partner.com", "run-1", "operator")
    ]
    assert not (settings.output_dir / "runs" / "run-1" / "promoted_domains.txt").exists()

    # The run's org profile reads the decision back from the tenant.
    profile = runs_service.get_org_profile(settings, "run-1", allow_restricted=True)
    assert profile["promoted_domains"] == ["acme-partner.com"]


def test_promote_is_idempotent_and_keeps_the_first_attribution(settings):
    _scope(settings, ALLOW_PARTNER)
    _run_with_candidates(settings, "run-1", "acme-partner.com")
    _run_with_candidates(settings, "run-2", "acme-partner.com")

    runs_service.promote_related_domain(settings, "run-1", "acme-partner.com", username="alice")
    runs_service.promote_related_domain(settings, "run-2", "acme-partner.com", username="bob")

    rows = promoted_domains.list_promoted(settings, "default")
    assert [(r.source_run_id, r.promoted_by) for r in rows] == [("run-1", "alice")]


def test_promote_outside_the_approved_scope_is_refused_and_not_stored(settings):
    """Attribution is the operator's call; authorization is the admin's."""
    _scope(settings, ALLOW_EXAMPLE, DENY_PARTNER)
    _run_with_candidates(settings, "run-1", "acme-partner.com")

    with pytest.raises(scan_scopes.ScanScopeDenied):
        runs_service.promote_related_domain(settings, "run-1", "acme-partner.com", username="operator")

    assert promoted_domains.list_promoted(settings, "default") == []


def test_promote_refuses_a_domain_the_run_never_proposed(settings):
    _scope(settings, ALLOW_PARTNER)
    _run_with_candidates(settings, "run-1", "acme-partner.com")

    with pytest.raises(runs_service.PromoteDomainError):
        runs_service.promote_related_domain(settings, "run-1", "other.example", username="operator")


def test_withdraw_removes_the_promotion(settings):
    _scope(settings, ALLOW_PARTNER)
    _run_with_candidates(settings, "run-1", "acme-partner.com")
    runs_service.promote_related_domain(settings, "run-1", "acme-partner.com", username="operator")

    res = runs_service.withdraw_related_domain(settings, "run-1", "acme-partner.com")
    assert res["promoted"] is False
    assert promoted_domains.list_promoted(settings, "default") == []

    again = runs_service.withdraw_related_domain(settings, "run-1", "acme-partner.com")
    assert "was not promoted" in again["message"]


# --- the consumer ------------------------------------------------------------


def test_a_later_scan_carries_the_promoted_domain(agent_settings):
    _scope(agent_settings, ALLOW_EXAMPLE, ALLOW_PARTNER)
    _run_with_candidates(agent_settings, "run-1", "acme-partner.com")
    runs_service.promote_related_domain(agent_settings, "run-1", "acme-partner.com", username="operator")

    job = jobs_service.start_scan(
        agent_settings,
        StartScanRequest(mode="balanced", domains="www.example.com"),
        username="operator",
    )

    assert job.target_counts == {"ranges": 0, "domains": 1, "promoted_domains": 1}
    assert "--promoted-domains" in job.command
    assert _promoted_file(agent_settings, job).read_text(encoding="utf-8").split() == [
        "acme-partner.com"
    ]
    # Its own target list is untouched: the run is widened, not retargeted.
    domains_file = jobs_service.job_inputs_dir(agent_settings, job.job_id) / "domains.txt"
    assert domains_file.read_text(encoding="utf-8").split() == ["www.example.com"]
    assert job.scan_options["promoted_domains"] == ["acme-partner.com"]
    assert "promoted_domains_refused" not in job.scan_options


def test_a_scan_on_the_default_target_files_is_widened_too(agent_settings):
    """The case that made a separate file necessary: no target override at
    all means the run reads the installation's own files, and appending to
    ``domains.txt`` would have replaced them."""
    _scope(agent_settings, ALLOW_PARTNER)
    _run_with_candidates(agent_settings, "run-1", "acme-partner.com")
    runs_service.promote_related_domain(agent_settings, "run-1", "acme-partner.com", username="operator")

    job = jobs_service.start_scan(
        agent_settings, StartScanRequest(mode="balanced"), username="operator"
    )

    assert job.target_counts == {"promoted_domains": 1}
    assert "--domains" not in job.command
    assert "--promoted-domains" in job.command


def test_a_domain_the_scope_no_longer_covers_is_dropped_and_recorded(agent_settings):
    """The scope was narrowed after the promotion: the promoted domain goes,
    the operator's own targets stay, and the job says what happened."""
    _scope(agent_settings, ALLOW_EXAMPLE, ALLOW_PARTNER)
    _run_with_candidates(agent_settings, "run-1", "acme-partner.com")
    runs_service.promote_related_domain(agent_settings, "run-1", "acme-partner.com", username="operator")
    _scope(agent_settings, ALLOW_EXAMPLE, DENY_PARTNER)

    job = jobs_service.start_scan(
        agent_settings,
        StartScanRequest(mode="balanced", domains="www.example.com"),
        username="operator",
    )

    assert job.target_counts == {"ranges": 0, "domains": 1}
    assert "--promoted-domains" not in job.command
    assert "promoted_domains" not in job.scan_options
    assert job.scan_options["promoted_domains_refused"] == [
        "acme-partner.com (denied by acme-partner.com)"
    ]


def test_a_verification_rescan_is_not_widened(agent_settings):
    """A re-check aimed at one finding must stay aimed at it (#183)."""
    _scope(agent_settings, ALLOW_EXAMPLE, ALLOW_PARTNER)
    _run_with_candidates(agent_settings, "run-1", "acme-partner.com")
    runs_service.promote_related_domain(agent_settings, "run-1", "acme-partner.com", username="operator")

    job = jobs_service.start_scan(
        agent_settings,
        StartScanRequest(mode="safe", intent="vuln", domains="www.example.com", ports="8443"),
        username="system:verification",
        quota_exempt=True,
    )

    assert "--promoted-domains" not in job.command
    assert "promoted_domains" not in job.scan_options
    assert not _promoted_file(agent_settings, job).exists()


def test_the_claim_hands_the_promoted_domains_to_the_worker(agent_settings, tmp_path):
    _scope(agent_settings, ALLOW_EXAMPLE, ALLOW_PARTNER)
    _run_with_candidates(agent_settings, "run-1", "acme-partner.com")
    runs_service.promote_related_domain(agent_settings, "run-1", "acme-partner.com", username="operator")
    jobs_service.start_scan(
        agent_settings,
        StartScanRequest(mode="balanced", domains="www.example.com"),
        username="operator",
    )

    claim = jobs_service.claim_job(agent_settings, "agent-1")
    assert claim is not None
    assert claim.inputs[jobs_service.PROMOTED_DOMAINS_INPUT] == "acme-partner.com\n"

    workdir = tmp_path / "workdir"
    workdir.mkdir()
    args = agent_worker._write_inputs(workdir, dict(claim.inputs))  # noqa: SLF001

    handed = Path(args[args.index("--promoted-domains") + 1])
    assert handed.read_text(encoding="utf-8").split() == ["acme-partner.com"]
