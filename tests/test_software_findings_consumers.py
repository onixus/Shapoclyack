"""Who else counts a software finding once it exists (Track E, M3).

Every consumer of ``vulnerabilities`` filters on ``state`` and not on
``source``, so folding endpoint matches into that table put them into the
compliance evidence pass, the cross-tenant posture list, the assets page's
per-asset counters and the risk-history snapshots at the same moment. That is
deliberate — a finding found by looking inside a host is the same kind of
object as one found by looking at it from outside, which is the whole premise
of M3 — but it was deliberate only in a commit message. This module is the
statement of intent that a future ``source == "scan"`` filter has to argue
with, and the reason the migration's release note warns operators that
compliance status, ``estate_risk`` and the risk-history chart all step at once
when it lands.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import requires_postgres
from tests.test_software_findings import (  # noqa: F401 - `client`/`settings` fixtures
    client,
    seed,
    settings,
    software_findings_of,
)

pytestmark = requires_postgres


@pytest.fixture()
def seeded(client: TestClient, settings):
    """One endpoint with two tracked software findings and no scan findings."""
    device_id = seed(client)
    findings = software_findings_of(client)
    assert len(findings) == 2, findings
    assert all(item["source"] == "endpoint_software" for item in findings)
    return device_id, findings


def test_the_tenant_summary_counts_software_findings(seeded, settings) -> None:
    from api.services import vulnerabilities as vulns_service

    summary = vulns_service.summary(settings, tenant_id="default")
    assert summary["open_total"] == 2
    # And therefore ``estate_risk``, which is what the dashboard headline and
    # every risk snapshot are.
    assert summary["estate_risk"] is not None


def test_risk_history_steps_when_software_findings_arrive(seeded, settings) -> None:
    from api.services import risk_snapshots

    snapshot = risk_snapshots.take_snapshot(settings, tenant_id="default", source="test")
    assert snapshot["open_total"] == 2
    assert snapshot["estate_risk"] is not None


def test_the_assets_page_counts_them_against_the_endpoint_s_asset(
    seeded, settings
) -> None:
    from api.services import assets as assets_service

    rows, _total = assets_service.list_assets(settings, "default")
    assert sum(row["open_findings"] for row in rows) == 2


def test_cross_tenant_posture_counts_them(seeded, settings) -> None:
    from api.services import tenant_posture

    rows = tenant_posture.list_posture(settings, tenant_ids=["default"])
    assert [row["open_total"] for row in rows] == [2]


def test_compliance_evidence_counts_them(seeded, settings) -> None:
    """A tenant whose only findings come from the inventory has been assessed.

    Reporting every finding-based control as "not assessed" there would read as
    "we never looked" at an estate we looked inside of.
    """
    from api.services.compliance import service as compliance_service

    posture = compliance_service.assess_all(settings, tenant_id="default")
    assert posture, "no frameworks assessed"
    assert all(item["open_findings"] == 2 for item in posture)
