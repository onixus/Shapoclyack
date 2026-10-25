"""Aggregated problem list (#579, stage 1): identity, server-side aggregates,
drill-down, tenant isolation, and a bounded query count.

Findings are inserted directly so each test controls exactly which rows share a
CVE, a template or nothing at all; the registration path has its own tests.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import event, select

from api.db import models
from api.db.engine import get_engine, get_session
from api.services import problem_identity
from api.services import tenants as tenants_service
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def ensure_asset(session, tenant_id: str, asset_id: str) -> None:
    if session.get(models.Asset, asset_id) is None:
        now = _now()
        session.add(
            models.Asset(
                asset_id=asset_id, tenant_id=tenant_id, status="active", first_seen=now, last_seen=now
            )
        )
        session.flush()


def add_finding(session, tenant_id: str, asset_id: str, **fields: Any) -> str:
    """One tracked finding. Defaults are an OPEN, unassigned, medium CVE-less row."""
    ensure_asset(session, tenant_id, asset_id)
    now = _now()
    vuln_id = fields.pop("vuln_id", None) or f"vln_{uuid.uuid4().hex[:16]}"
    row = dict(
        vuln_id=vuln_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        finding_key=uuid.uuid4().hex,
        state="OPEN",
        state_changed_at=now,
        severity="medium",
        title="finding",
        first_seen_at=now - timedelta(days=3),
        last_seen_at=now,
        sla_started_at=now - timedelta(days=3),
        due_at=now + timedelta(days=30),
        created_at=now,
        updated_at=now,
    )
    row.update(fields)
    session.add(models.Vulnerability(**row))
    session.flush()
    return vuln_id


def seed_fleet(settings, tenant_id: str) -> dict[str, list[str]]:
    """The shared fixture of this file.

    * CVE-2024-1111: 4 findings on 3 assets (one asset has two ports); the
      spellings differ (case, padding) and must still be one problem.
    * CVE-2024-2222: 2 findings on 2 assets (a different CVE).
    * a nuclei template without a CVE: 2 findings on 2 assets.
    * two findings with no identity at all: two separate problems.
    """
    ids: dict[str, list[str]] = {"c1": [], "c2": [], "tpl": [], "unknown": []}
    with get_session(settings.postgres_url) as session:
        for asset, port, spelling, sev, score, cvss, kev, src in [
            ("a1", "443", "CVE-2024-1111", "critical", 9.1, 9.8, True, "operator-set"),
            ("a1", "8443", "cve-2024-1111", "high", 7.0, 7.5, False, "finding"),
            ("a2", "443", " CVE-2024-1111 ", "high", 8.0, None, False, "address-space"),
            ("a3", "443", "CVE-2024-1111", "medium", 5.0, 5.0, False, None),
        ]:
            ids["c1"].append(
                add_finding(
                    session, tenant_id, asset, cve=spelling, port=port, severity=sev,
                    contextual_score=score, cvss=cvss, in_kev=kev, title="openssl",
                    network_exposure="external" if src else None, network_exposure_source=src,
                )
            )
        for asset in ("a1", "a2"):
            ids["c2"].append(
                add_finding(session, tenant_id, asset, cve="CVE-2024-2222", severity="low",
                            contextual_score=2.0, cvss=3.1, port="22", title="libssh")
            )
        for asset in ("a2", "a3"):
            ids["tpl"].append(
                add_finding(session, tenant_id, asset, template_id="exposed-panel",
                            detector_source="nuclei", finding_type="exposure", severity="medium",
                            contextual_score=4.0, title="Exposed panel", port="8080")
            )
        for asset in ("a3", "a4"):
            ids["unknown"].append(
                add_finding(session, tenant_id, asset, severity="low", title="mystery")
            )
    return ids


@pytest.fixture(autouse=True)
def pinned_epss():
    """A scorer with a known EPSS overlay, so the figures do not depend on the
    feed shipped in the repository."""
    from api.services import risk_scoring

    risk_scoring.reset_scorer_for_tests(
        risk_scoring.RiskScoring(
            epss={"CVE-2024-1111": 0.42, "CVE-2024-3333": 0.0},
            epss_meta={"source": "first-epss", "updated": "2026-10-20"},
        )
    )
    yield
    risk_scoring.reset_scorer_for_tests(None)


@pytest.fixture
def env(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    settings = make_settings(tmp_path)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    ids = seed_fleet(settings, tenant_id)
    return client, settings, tenant_id, ids


def _problems(client, headers, **params) -> dict:
    response = client.get("/api/problems", params=params, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _by_key(body: dict) -> dict[str, dict]:
    return {item["problem_key"]: item for item in body["items"]}


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def test_cve_spellings_are_one_problem_and_unknown_identities_are_not_merged(env):
    client, _, _, ids = env
    body = _problems(client, auth_headers(client, "viewer"), limit=100)
    keys = _by_key(body)

    assert "cve:CVE-2024-1111" in keys
    assert keys["cve:CVE-2024-1111"]["instances"] == 4
    assert keys["cve:CVE-2024-2222"]["instances"] == 2
    assert keys["tpl:nuclei:exposed-panel"]["instances"] == 2
    unknown = [k for k in keys if k.startswith("unknown:")]
    # Two findings with no CVE/template/script are two problems, not one bucket.
    assert len(unknown) == 2
    assert all(keys[k]["instances"] == 1 for k in unknown)
    assert body["total"] == 5
    assert keys["cve:CVE-2024-1111"]["kind"] == "cve"
    assert keys["tpl:nuclei:exposed-panel"]["kind"] == "tpl"


def test_the_sql_key_and_its_python_twin_agree_on_every_shape(env):
    _, settings, tenant_id, _ = env
    with get_session(settings.postgres_url) as session:
        extra = [
            add_finding(session, tenant_id, "a9", script_id="http-vuln-x", severity="low"),
            add_finding(session, tenant_id, "a9", template_id="t", detector_source=None),
            add_finding(session, tenant_id, "a9", cve="not-a-cve", script_id="s2"),
            add_finding(session, tenant_id, "a9", cve="", template_id="  ", script_id=""),
            add_finding(session, tenant_id, "a9", cve="CVE-2024-1111\n"),
            add_finding(session, tenant_id, "a9", cve="\tcve-2024-1111\xa0"),
            add_finding(session, tenant_id, "a9", template_id="\nt2\t", detector_source="\xa0nuclei "),
            add_finding(session, tenant_id, "a9", script_id="\r\nssl\x0b"),
        ]
        key = problem_identity.problem_key_expr()
        rows = session.execute(
            select(models.Vulnerability, key).where(models.Vulnerability.tenant_id == tenant_id)
        ).all()
        assert len(rows) >= 9 + len(extra) - 1
        for row, sql_key in rows:
            assert problem_identity.problem_key_of(row) == sql_key, row.vuln_id
        by_id = {row.vuln_id: sql_key for row, sql_key in rows}
    assert by_id[extra[0]] == "script:http-vuln-x"
    assert by_id[extra[1]] == "tpl:-:t"
    # A non-CVE string in the cve column does not become a CVE problem.
    assert by_id[extra[2]] == "script:s2"
    assert by_id[extra[3]] == f"unknown:{extra[3]}"
    # Padding other than a plain space no longer splits a problem in two.
    assert by_id[extra[4]] == by_id[extra[5]] == "cve:CVE-2024-1111"
    assert by_id[extra[6]] == "tpl:nuclei:t2"
    assert by_id[extra[7]] == "script:ssl"


# --------------------------------------------------------------------------
# Aggregates over the whole selection
# --------------------------------------------------------------------------


def test_instances_and_assets_are_separate_and_semantics_are_explicit(env):
    client, _, _, _ = env
    body = _problems(client, auth_headers(client, "viewer"))
    row = _by_key(body)["cve:CVE-2024-1111"]

    assert (row["instances"], row["assets"]) == (4, 3)
    assert row["severity"] == "critical"  # worst instance
    assert row["contextual_score"] == 9.1  # highest, not an average
    assert row["cvss"] == 9.8
    assert row["epss"] == 0.42  # from the EPSS overlay, by normalised CVE
    assert body["enrichment"]["epss"] == {"source": "first-epss", "updated": "2026-10-20"}
    assert row["in_kev"] is True and row["kev_instances"] == 1
    assert row["last_seen_at"].endswith("Z")
    assert "worst OPEN instance" in body["semantics"]["severity"]
    assert body["as_of"].endswith("Z")


def test_severity_and_title_come_from_open_instances_when_there_are_any(env):
    client, settings, tenant_id, _ = env
    with get_session(settings.postgres_url) as session:
        add_finding(session, tenant_id, "a1", cve="CVE-2030-0100", severity="critical",
                    contextual_score=9.9, state="CLOSED", closed_at=_now(), title="closed critical")
        add_finding(session, tenant_id, "a2", cve="CVE-2030-0100", severity="low",
                    contextual_score=1.0, title="open low")
        add_finding(session, tenant_id, "a3", cve="CVE-2030-0100", severity="medium",
                    contextual_score=4.0, title="open medium")
        add_finding(session, tenant_id, "a4", cve="CVE-2030-0200", severity="high",
                    contextual_score=7.0, state="CLOSED", closed_at=_now(), title="only closed")
    headers = auth_headers(client, "viewer")
    # Without open_only the closed critical is in the selection, yet not the verdict.
    row = _by_key(_problems(client, headers, limit=100))["cve:CVE-2030-0100"]
    assert (row["severity"], row["contextual_score"], row["title"]) == ("medium", 4.0, "open medium")
    assert row["instances"] == 3
    # Nothing open: the closed instances speak.
    only = _by_key(_problems(client, headers, limit=100))["cve:CVE-2030-0200"]
    assert (only["severity"], only["title"]) == ("high", "only closed")


def test_missing_cvss_is_null_not_zero(env):
    client, settings, tenant_id, _ = env
    with get_session(settings.postgres_url) as session:
        add_finding(session, tenant_id, "a1", cve="CVE-2030-0001", severity="low")
    row = _by_key(_problems(client, auth_headers(client, "viewer"), limit=100))["cve:CVE-2030-0001"]
    assert row["cvss"] is None and row["contextual_score"] is None and row["epss"] is None


def test_epss_is_unknown_when_absent_zero_when_listed_and_unknown_for_non_cve(env):
    client, settings, tenant_id, _ = env
    with get_session(settings.postgres_url) as session:
        add_finding(session, tenant_id, "a1", cve="CVE-2024-3333", severity="low")
    keys = _by_key(_problems(client, auth_headers(client, "viewer"), limit=100))
    assert keys["cve:CVE-2024-3333"]["epss"] == 0.0  # listed with probability 0: a real value
    assert keys["cve:CVE-2024-2222"]["epss"] is None  # not in the overlay: unknown
    assert keys["tpl:nuclei:exposed-panel"]["epss"] is None  # non-CVE: unknown
    drill = client.get(
        "/api/problems/instances",
        params={"problem_key": "cve:CVE-2024-1111"},
        headers=auth_headers(client, "viewer"),
    ).json()
    assert {item["epss"] for item in drill["items"]} == {0.42}
    assert drill["enrichment"]["epss"]["updated"] == "2026-10-20"
    other = client.get(
        "/api/problems/instances",
        params={"problem_key": "cve:CVE-2024-2222"},
        headers=auth_headers(client, "viewer"),
    ).json()
    assert {item["epss"] for item in other["items"]} == {None}


def test_exposure_is_counted_with_its_source_and_basis_and_unknown_is_unknown(env):
    client, _, _, _ = env
    row = _by_key(_problems(client, auth_headers(client, "viewer"), limit=100))["cve:CVE-2024-1111"]
    exposure = row["exposure"]
    assert exposure["external"] == 3
    # The fourth carries no observation at all: unknown, not "not exposed".
    assert exposure["unknown"] == 1
    assert exposure["sources"]["operator-set"] == 1
    assert exposure["sources"]["none"] == 1
    assert exposure["basis"] == {"declared": 1, "measured": 1, "inferred": 1, "unknown": 1}


def test_aggregates_cover_the_whole_selection_not_the_page(env):
    client, _, _, _ = env
    headers = auth_headers(client, "viewer")
    page = _problems(client, headers, limit=1, offset=0)
    full = _problems(client, headers, limit=100)

    assert len(page["items"]) == 1 and page["has_more"] is True
    # 4 + 2 + 2 + 1 + 1 findings on 4 distinct assets, whatever the page size.
    for body in (page, full):
        assert body["total"] == 5
        assert body["aggregates"]["problems"] == 5
        assert body["aggregates"]["instances"] == 10
        assert body["aggregates"]["assets"] == 4
        assert body["aggregates"]["kev_instances"] == 1
        assert body["aggregates"]["unassigned_instances"] == 10


def test_filters_change_the_aggregates_and_invalid_values_are_422(env):
    client, settings, tenant_id, ids = env
    headers = auth_headers(client, "viewer")
    with get_session(settings.postgres_url) as session:
        for vuln_id in ids["c1"][:2]:
            session.get(models.Vulnerability, vuln_id).assignee = "ada"
    critical = _problems(client, headers, severity="critical")
    assert critical["total"] == 1 and critical["aggregates"]["instances"] == 1

    owned = _problems(client, headers, assignee="ada")
    assert owned["aggregates"]["instances"] == 2
    assert _problems(client, headers, unassigned=True)["aggregates"]["instances"] == 8

    for params in ({"severity": "spicy"}, {"sla": "whenever"}, {"unassigned": True, "assignee": "ada"}):
        assert client.get("/api/problems", params=params, headers=headers).status_code == 422
    assert client.get("/api/problems", params={"sort": "nonsense"}, headers=headers).status_code == 200


def test_sorting_is_stable_across_pages(env):
    client, _, _, _ = env
    headers = auth_headers(client, "viewer")
    seen: list[str] = []
    for offset in range(0, 5):
        body = _problems(client, headers, sort="instances", order="desc", limit=1, offset=offset)
        seen.extend(item["problem_key"] for item in body["items"])
    assert len(seen) == len(set(seen)) == 5
    assert seen[0] == "cve:CVE-2024-1111"
    ascending = _problems(client, headers, sort="instances", order="asc", limit=100)["items"]
    assert [i["instances"] for i in ascending] == sorted(i["instances"] for i in ascending)


def test_sla_breach_and_open_only_are_counted_per_problem(env):
    client, settings, tenant_id, ids = env
    headers = auth_headers(client, "viewer")
    with get_session(settings.postgres_url) as session:
        late = session.get(models.Vulnerability, ids["c2"][0])
        late.due_at = _now() - timedelta(days=2)
        closed = session.get(models.Vulnerability, ids["c2"][1])
        closed.state = "CLOSED"
        closed.closed_at = _now()
    body = _problems(client, headers, open_only=True)
    c2 = _by_key(body)["cve:CVE-2024-2222"]
    assert c2["instances"] == 1 and c2["sla"]["breached"] == 1
    assert body["aggregates"]["breached_instances"] == 1
    # Without open_only the closed instance is part of the selection.
    assert _by_key(_problems(client, headers))["cve:CVE-2024-2222"]["instances"] == 2


# --------------------------------------------------------------------------
# Drill-down
# --------------------------------------------------------------------------


def test_drill_down_reproduces_the_row_under_the_same_filters(env):
    client, settings, tenant_id, ids = env
    headers = auth_headers(client, "viewer")
    filters = {"severity": "high"}
    row = _by_key(_problems(client, headers, **filters))["cve:CVE-2024-1111"]
    assert row["instances"] == 2

    drill = client.get(
        "/api/problems/instances",
        params={
            **filters,
            "problem_key": "cve:CVE-2024-1111",
            "as_of": _problems(client, headers, **filters)["as_of"],
            "expected_instances": row["instances"],
        },
        headers=headers,
    ).json()
    assert drill["total"] == row["instances"]
    assert {i["vuln_id"] for i in drill["items"]} <= set(ids["c1"])
    assert drill["drift"]["differs"] is False

    # The findings list takes the same key and agrees.
    listed = client.get(
        "/api/vulnerabilities",
        params={**filters, "problem_key": "cve:CVE-2024-1111"},
        headers=headers,
    ).json()
    assert listed["total"] == drill["total"]


def test_the_findings_route_itself_filters_by_problem_key(env):
    """Through the real route: an unknown query parameter is silently ignored by
    FastAPI, which once made the console's drill-down show every finding."""
    client, _, _, ids = env
    headers = auth_headers(client, "viewer")
    everything = client.get("/api/vulnerabilities", params={"limit": 100}, headers=headers).json()
    assert everything["total"] == 10
    narrowed = client.get(
        "/api/vulnerabilities",
        params={"problem_key": "cve:CVE-2024-2222", "limit": 100},
        headers=headers,
    ).json()
    assert narrowed["total"] == 2
    assert {i["vuln_id"] for i in narrowed["items"]} == set(ids["c2"])
    bad = client.get("/api/vulnerabilities", params={"problem_key": "nope"}, headers=headers)
    assert bad.status_code == 422


def test_drill_down_explains_a_difference_caused_by_later_changes(env):
    client, settings, tenant_id, _ = env
    headers = auth_headers(client, "viewer")
    listing = _problems(client, headers)
    row = _by_key(listing)["cve:CVE-2024-2222"]
    # Between loading the list and clicking the row a new instance arrives and
    # an existing one is re-observed.
    with get_session(settings.postgres_url) as session:
        add_finding(session, tenant_id, "a7", cve="CVE-2024-2222", severity="low")
    drill = client.get(
        "/api/problems/instances",
        params={"problem_key": "cve:CVE-2024-2222", "as_of": listing["as_of"],
                "expected_instances": row["instances"]},
        headers=headers,
    ).json()
    assert drill["total"] == row["instances"] + 1
    drift = drill["drift"]
    assert drift["differs"] is True
    assert drift["changed_since_as_of"] == 1
    assert "changed after the list was loaded" in drift["explanation"]


def test_a_malformed_problem_key_is_rejected(env):
    client, _, _, _ = env
    headers = auth_headers(client, "viewer")
    response = client.get("/api/problems/instances", params={"problem_key": "nope"}, headers=headers)
    assert response.status_code == 422


# --------------------------------------------------------------------------
# Tenants and roles
# --------------------------------------------------------------------------


def test_another_tenants_findings_never_reach_counts_filters_or_drill_down(env):
    client, settings, tenant_id, _ = env
    other = tenants_service.create_tenant(tenant_id="ten_b", name="B")["tenant_id"]
    with get_session(settings.postgres_url) as session:
        for asset in ("b1", "b2", "b3"):
            add_finding(session, other, asset, cve="CVE-2024-1111", severity="critical",
                        contextual_score=10.0, in_kev=True, assignee="mallory")
        add_finding(session, other, "b1", cve="CVE-2099-0001", severity="critical")
    headers = auth_headers(client, "viewer")

    body = _problems(client, headers, limit=100)
    # Same CVE in both tenants: the default tenant's row still counts 4.
    assert _by_key(body)["cve:CVE-2024-1111"]["instances"] == 4
    assert "cve:CVE-2099-0001" not in _by_key(body)
    assert body["aggregates"]["instances"] == 10
    assert body["aggregates"]["assets"] == 4
    assert body["aggregates"]["kev_instances"] == 1
    # A filter value that exists only in the other tenant matches nothing.
    assert _problems(client, headers, assignee="mallory")["total"] == 0
    assert _problems(client, headers, asset_id="b1")["total"] == 0
    drill = client.get(
        "/api/problems/instances", params={"problem_key": "cve:CVE-2099-0001"}, headers=headers
    ).json()
    assert drill["total"] == 0 and drill["items"] == []
    owners = _by_key(body)["cve:CVE-2024-1111"]["owners"]["assignees"]
    assert owners == []

    # The tenant's own member sees only its own data.
    admin = auth_headers(client, "admin")
    granted = client.put("/api/tenants/ten_b/members/viewer", headers=admin, json={"role": "viewer"})
    assert granted.status_code == 200, granted.text
    theirs = client.get("/api/problems", params={"tenant_id": "ten_b", "limit": 100}, headers=headers)
    assert theirs.status_code == 200
    assert theirs.json()["aggregates"]["instances"] == 4
    assert _by_key(theirs.json())["cve:CVE-2024-1111"]["instances"] == 3


def test_a_non_member_cannot_ask_for_another_tenant_and_anonymous_is_refused(env):
    client, _, _, _ = env
    tenants_service.create_tenant(tenant_id="ten_c", name="C")
    viewer = auth_headers(client, "viewer")
    assert client.get("/api/problems", params={"tenant_id": "ten_c"}, headers=viewer).status_code == 403
    assert client.get("/api/problems").status_code == 401
    assert client.get("/api/problems/instances", params={"problem_key": "cve:CVE-1-1"}).status_code == 401


def test_the_service_scopes_by_tenant_on_its_own_not_only_through_row_security(env):
    """No request context here, so Postgres row-level security has no tenant to
    apply: only the service's own predicate stands between tenants."""
    from api.services import problems as problems_service

    _, settings, tenant_id, _ = env
    other = tenants_service.create_tenant(tenant_id="ten_b", name="B")["tenant_id"]
    with get_session(settings.postgres_url) as session:
        for asset in ("b1", "b2"):
            add_finding(session, other, asset, cve="CVE-2024-1111", severity="critical",
                        assignee="mallory", in_kev=True)
    mine = problems_service.list_problems(settings, tenant_id=tenant_id, filters={}, limit=100)
    theirs = problems_service.list_problems(settings, tenant_id=other, filters={}, limit=100)
    assert mine["aggregates"]["instances"] == 10 and theirs["aggregates"]["instances"] == 2
    assert {i["problem_key"] for i in theirs["items"]} == {"cve:CVE-2024-1111"}
    assert mine["aggregates"]["kev_instances"] == 1
    drill = problems_service.problem_instances(
        settings, tenant_id=tenant_id, problem_key="cve:CVE-2024-1111", filters={}
    )
    assert drill["total"] == 4
    assert all(item["tenant_id"] == tenant_id for item in drill["items"])


# --------------------------------------------------------------------------
# No N+1
# --------------------------------------------------------------------------


def _count_statements(settings, call) -> int:
    engine = get_engine(settings.postgres_url)
    seen: list[str] = []

    def before(conn, cursor, statement, parameters, context, executemany):
        seen.append(statement)

    event.listen(engine, "before_cursor_execute", before)
    try:
        call()
    finally:
        event.remove(engine, "before_cursor_execute", before)
    return len(seen)


def test_the_query_count_does_not_grow_with_the_number_of_problems(env):
    client, settings, tenant_id, _ = env
    headers = auth_headers(client, "viewer")

    def listing():
        assert client.get("/api/problems", params={"limit": 200}, headers=headers).status_code == 200

    listing()  # warm-up: one-time lookups (first login, caches) are not the list's
    small = _count_statements(settings, listing)
    with get_session(settings.postgres_url) as session:
        for index in range(60):
            add_finding(session, tenant_id, f"bulk{index % 7}", cve=f"CVE-2031-{index:04d}",
                        severity="high", assignee=f"user{index % 5}", owner_team=f"team{index % 3}",
                        network_exposure_source="finding", network_exposure="external")
    large = _count_statements(settings, listing)
    # 65 problems cost the same number of statements as 5 (auth included).
    assert large == small, (small, large)
