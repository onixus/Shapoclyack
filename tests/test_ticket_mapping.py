"""Ticket field mapping, templates, routing and GitHub/GitLab transports (#353)."""

from __future__ import annotations

import json

import pytest

from api.services.integrations import ticket_mapping, ticket_sync, tickets
from api.services.integrations.delivery import DeliveryResult


def _payload(severity="critical", **extra):
    event = {
        "kind": "new_cve",
        "host": "10.0.0.1",
        "port": 443,
        "run_id": "run-1",
        "data": {"cve": "CVE-2026-1", "severity": severity, "cvss": 9.8},
    }
    event.update(extra)
    return {"event": event}


class _Recorder:
    def __init__(self, body='{"key": "SEC-1"}'):
        self.calls = []
        self.body = body

    def __call__(self, url, body, headers, **kwargs):
        self.calls.append((url, json.loads(body), headers))
        return DeliveryResult(
            ok=True, status_code=201, error=None, retryable=False, body=self.body
        )


def _deliver(transport, config, payload, post_fn, asset=None, secret="tok"):
    return tickets.deliver(
        transport=transport,
        base_url="https://tracker.example",
        payload=payload,
        secret=secret,
        extra_headers=None,
        config=config,
        timeout_seconds=5,
        allow_private=False,
        post_fn=post_fn,
        asset=asset,
    )


# --- templates -------------------------------------------------------------


def test_unknown_placeholder_is_refused_when_saving():
    with pytest.raises(tickets.TicketSpecError, match=r"unknown placeholder.*\{secret\}"):
        tickets.validate_transport_config(
            "jira", {"project_key": "SEC", "summary_template": "{host} {secret}"}
        )


def test_template_is_substitution_only_never_evaluated():
    # Attribute access / format specs are not tokens: they are left as text.
    cfg = tickets.validate_transport_config(
        "jira",
        {"project_key": "SEC", "summary_template": "{host.__class__} {host!r} {0}"},
    )
    body = json.loads(tickets.build_body("jira", _payload(), cfg))
    assert body["fields"]["summary"] == "{host.__class__} {host!r} {0}"


def test_substituted_values_are_stripped_of_control_characters_and_capped():
    cfg = tickets.validate_transport_config(
        "github", {"repository": "acme/sec", "summary_template": "{script_id}"}
    )
    payload = _payload()
    payload["event"]["data"]["script_id"] = "a\x00b\x1bc" + "x" * 2000
    body = json.loads(tickets.build_body("github", payload, cfg))
    assert "\x00" not in body["title"] and "\x1b" not in body["title"]
    assert len(body["title"]) <= 256


def test_default_texts_are_unchanged_without_templates():
    cfg = tickets.validate_transport_config("jira", {"project_key": "SEC"})
    body = json.loads(tickets.build_body("jira", _payload(), cfg))
    assert body["fields"]["summary"] == "CVE-2026-1 on 10.0.0.1:443"
    assert "not confirmation" in body["fields"]["description"]
    assert set(body["fields"]) == {"project", "issuetype", "summary", "description"}


# --- jira mapping ----------------------------------------------------------


def test_jira_priority_labels_components_custom_fields():
    cfg = tickets.validate_transport_config(
        "jira",
        {
            "project_key": "SEC",
            "summary_template": "[{severity}] {cve} on {where}",
            "description_template": "BU {business_unit}, crit {criticality}",
            "labels": ["shapoclyack", "net scan"],
            "components": ["Infra"],
            "custom_fields": {"customfield_10010": "{host}", "customfield_10011": 3},
            "severity_rules": {"critical": {"priority": "Highest", "labels": ["sla-1d"]}},
        },
    )
    asset = {"business_unit": "Payments", "criticality": 5}
    body = json.loads(tickets.build_body("jira", _payload(), cfg, asset))
    fields = body["fields"]
    assert fields["summary"] == "[critical] CVE-2026-1 on 10.0.0.1:443"
    assert fields["description"] == "BU Payments, crit 5"
    assert fields["priority"] == {"name": "Highest"}
    assert fields["labels"] == ["shapoclyack", "net_scan", "sla-1d"]
    assert fields["components"] == [{"name": "Infra"}]
    assert fields["customfield_10010"] == "10.0.0.1"
    assert fields["customfield_10011"] == 3


def test_custom_fields_cannot_overwrite_reserved_jira_fields():
    with pytest.raises(tickets.TicketSpecError, match="custom_fields"):
        tickets.validate_transport_config(
            "jira", {"project_key": "SEC", "custom_fields": {"project": "X"}}
        )


def test_servicenow_urgency_from_severity_rule():
    cfg = tickets.validate_transport_config(
        "servicenow", {"severity_rules": {"high": {"priority": "1"}}}
    )
    body = json.loads(tickets.build_body("servicenow", _payload("high"), cfg))
    assert body["urgency"] == "1"
    # no rule for this severity: the old default
    body = json.loads(tickets.build_body("servicenow", _payload("medium"), cfg))
    assert body["urgency"] == "2"


def test_priority_rule_refused_where_the_tracker_has_none():
    with pytest.raises(tickets.TicketSpecError, match="priority"):
        tickets.validate_transport_config(
            "github",
            {"repository": "a/b", "severity_rules": {"low": {"priority": "P3"}}},
        )


# --- routing ---------------------------------------------------------------


def test_low_severity_creates_no_ticket_and_does_not_post():
    rec = _Recorder()
    cfg = {"project_key": "SEC", "severity_rules": {"low": {"create": False}}}
    result = _deliver("jira", cfg, _payload("low"), rec)
    assert result.ok and result.ticket_key is None
    assert rec.calls == []
    # other severities still go out
    result = _deliver("jira", cfg, _payload("high"), rec)
    assert result.ticket_key == "SEC-1" and len(rec.calls) == 1


def test_target_rule_routes_by_business_unit_and_criticality():
    cfg = {
        "project_key": "DEF",
        "target_rules": [
            {"business_unit": "Payments", "min_criticality": 4, "target": "PAY", "labels": ["pci"]},
            {"business_unit": "Payments", "target": "PAYLOW"},
        ],
    }
    rec = _Recorder()
    _deliver("jira", cfg, _payload(), rec, asset={"business_unit": "payments", "criticality": 5})
    assert rec.calls[-1][1]["fields"]["project"]["key"] == "PAY"
    assert rec.calls[-1][1]["fields"]["labels"] == ["pci"]
    _deliver("jira", cfg, _payload(), rec, asset={"business_unit": "Payments", "criticality": 2})
    assert rec.calls[-1][1]["fields"]["project"]["key"] == "PAYLOW"
    # unknown asset: base project
    _deliver("jira", cfg, _payload(), rec, asset=None)
    assert rec.calls[-1][1]["fields"]["project"]["key"] == "DEF"
    # a missing criticality never satisfies a criticality bound
    _deliver("jira", cfg, _payload(), rec, asset={"business_unit": "Payments"})
    assert rec.calls[-1][1]["fields"]["project"]["key"] == "PAYLOW"


def test_target_rule_without_condition_is_refused():
    with pytest.raises(tickets.TicketSpecError, match="condition"):
        tickets.validate_transport_config(
            "jira", {"project_key": "SEC", "target_rules": [{"target": "X"}]}
        )


def test_target_rule_target_is_validated_like_the_base_target():
    with pytest.raises(tickets.TicketSpecError, match="owner/repo"):
        tickets.validate_transport_config(
            "github",
            {
                "repository": "a/b",
                "target_rules": [{"environment": "prod", "target": "../../evil"}],
            },
        )


def test_needs_asset_context_only_when_something_reads_it():
    assert not ticket_mapping.needs_asset_context({"summary_template": "{host}"})
    assert ticket_mapping.needs_asset_context({"summary_template": "{business_unit}"})
    assert ticket_mapping.needs_asset_context({"target_rules": [{"environment": "prod"}]})


# --- auth mode regression --------------------------------------------------


def test_deliver_honours_configured_auth_mode():
    rec = _Recorder()
    _deliver(
        "jira",
        {"project_key": "SEC", "auth_mode": "basic"},
        _payload(),
        rec,
        secret="me@example.com:api",
    )
    assert rec.calls[0][2]["Authorization"].startswith("Basic ")


# --- github / gitlab -------------------------------------------------------


def test_github_create_issue_and_key():
    rec = _Recorder('{"number": 12, "html_url": "https://github.com/acme/sec/issues/12"}')
    result = _deliver(
        "github",
        {"repository": "acme/sec", "labels": ["vuln"], "severity_rules": {"critical": {"labels": ["p0"]}}},
        _payload(),
        rec,
    )
    url, body, headers = rec.calls[0]
    assert url == "https://tracker.example/repos/acme/sec/issues"
    assert body["title"] == "CVE-2026-1 on 10.0.0.1:443"
    assert body["labels"] == ["vuln", "p0"]
    assert headers["Authorization"] == "Bearer tok"
    assert headers["Accept"] == "application/vnd.github+json"
    assert result.ticket_key == "acme/sec#12"
    assert result.ticket_url == "https://github.com/acme/sec/issues/12"


def test_gitlab_create_issue_and_key():
    rec = _Recorder('{"iid": 7, "web_url": "https://gl.example/grp/proj/-/issues/7"}')
    result = _deliver(
        "gitlab",
        {"project": "grp/proj", "labels": ["vuln", "a,b"], "confidential": True},
        _payload(),
        rec,
    )
    url, body, _ = rec.calls[0]
    assert url == "https://tracker.example/api/v4/projects/grp%2Fproj/issues"
    assert body["labels"] == "vuln,a b"
    assert body["confidential"] is True
    assert result.ticket_key == "grp/proj#7"


def test_non_http_ticket_link_from_tracker_is_dropped():
    key, url = tickets.parse_created(
        "github", "https://x", '{"number": 1, "html_url": "javascript:alert(1)"}',
        {"repository": "a/b"},
    )
    assert key == "a/b#1" and url is None


@pytest.mark.parametrize(
    "transport,cfg",
    [
        ("github", {}),
        ("github", {"repository": "just-a-name"}),
        ("github", {"repository": "a/b/c"}),
        ("github", {"repository": "../b"}),
        ("gitlab", {}),
        ("gitlab", {"project": "../x/y"}),
        ("gitlab", {"project": "x?y/z"}),
    ],
)
def test_bad_github_gitlab_targets_are_refused(transport, cfg):
    with pytest.raises(tickets.TicketSpecError):
        tickets.validate_transport_config(transport, cfg)


def test_github_gitlab_are_known_transports():
    assert tickets.validate_transport("GitHub") == "github"
    assert tickets.validate_transport("gitlab") == "gitlab"
    assert {"github", "gitlab"} <= set(tickets.TICKET_TRANSPORTS)


# --- sync ------------------------------------------------------------------


class _Req:
    def __init__(self, body="{}"):
        self.calls = []
        self.body = body

    def __call__(self, method, url, body, headers, **kwargs):
        self.calls.append((method, url, body))
        return DeliveryResult(
            ok=True, status_code=200, error=None, retryable=False, body=self.body
        )


@pytest.mark.parametrize(
    "transport,key,url",
    [
        ("github", "acme/sec#12", "https://t.example/repos/acme/sec/issues/12"),
        ("gitlab", "grp/sub/proj#7", "https://t.example/api/v4/projects/grp%2Fsub%2Fproj/issues/7"),
    ],
)
def test_fetch_status_closed_issue(transport, key, url):
    req = _Req('{"state": "closed"}')
    state, raw, _ = ticket_sync.fetch_ticket_status(
        transport=transport, base_url="https://t.example", ticket_key=key, request_fn=req
    )
    assert req.calls[0][:2] == ("GET", url)
    assert (state, raw) == ("CLOSED", "closed")


def test_fetch_status_open_issue_asserts_nothing():
    req = _Req('{"state": "open"}')
    state, raw, _ = ticket_sync.fetch_ticket_status(
        transport="github", base_url="https://t.example", ticket_key="a/b#1", request_fn=req
    )
    assert state is None and raw == "open"


@pytest.mark.parametrize("key", ["12", "a/b#x", "../b#1", "#1"])
def test_issue_key_is_rechecked_before_it_reaches_a_url(key):
    with pytest.raises(tickets.TicketSpecError):
        ticket_sync.fetch_ticket_status(
            transport="github", base_url="https://t.example", ticket_key=key, request_fn=_Req()
        )


def test_push_close_and_reopen():
    req = _Req()
    assert ticket_sync.push_status_update(
        transport="github", base_url="https://t.example", ticket_key="a/b#1",
        to_state="CLOSED", request_fn=req,
    )
    assert req.calls[-1][0] == "PATCH" and json.loads(req.calls[-1][2]) == {"state": "closed"}
    assert ticket_sync.push_status_update(
        transport="gitlab", base_url="https://t.example", ticket_key="g/p#2",
        to_state="OPEN", request_fn=req,
    )
    assert req.calls[-1][0] == "PUT"
    assert json.loads(req.calls[-1][2]) == {"state_event": "reopen"}
    # VERIFYING has no tracker equivalent: nothing is pushed
    n = len(req.calls)
    assert not ticket_sync.push_status_update(
        transport="github", base_url="https://t.example", ticket_key="a/b#1",
        to_state="VERIFYING", request_fn=req,
    )
    assert len(req.calls) == n
