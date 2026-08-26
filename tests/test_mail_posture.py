"""Mail authentication posture for the org's own domains (org_profile M2, #182)."""

from __future__ import annotations

import io
import ipaddress
from pathlib import Path

from scanner.pipeline import mail_posture, safe_http
from scanner.pipeline.config_schema import MailPostureConfig
from scanner.pipeline.mail_posture import (
    _classify_dmarc,
    _classify_spf,
    _fetch_mta_sts_policy,
    _is_null_mx,
    _mx_entries,
    _spf_all_qualifier,
    check_mail_posture,
)

PUBLIC_IP = "93.184.216.34"


# --- dnsx fakes -------------------------------------------------------------


def _patch_dnsx(monkeypatch, *, mx: dict | None = None, txt: dict | None = None) -> list[str]:
    """Answer the two dnsx wrappers from canned records.

    Same convention as ``test_domain_monitor.py``: module attributes are
    replaced and the fakes repeat the keyword-only signatures exactly.
    Returns the log of TXT batch kinds so a test can count the batches.
    """
    kinds: list[str] = []

    def fake_mx(domains, output_dir, *, timeout, retries):
        return {domain: dict((mx or {}).get(domain, {})) for domain in domains}

    def fake_txt(names, output_dir, *, kind, timeout, retries):
        kinds.append(kind)
        return {name: dict((txt or {}).get(name, {})) for name in names if name in (txt or {})}

    monkeypatch.setattr(mail_posture, "_run_dnsx_mx", fake_mx)
    monkeypatch.setattr(mail_posture, "_run_dnsx_txt", fake_txt)
    return kinds


def _kinds(result: dict) -> set[str]:
    return {finding["kind"] for finding in result["findings"]}


# --- safe_http fakes (same shape as tests/test_safe_http.py) ----------------


class _FakeFp(io.BytesIO):
    class _Raw:
        class _Sock:
            def settimeout(self, value):  # noqa: D401 - assertion target only
                self.timeout = value

        def __init__(self):
            self._sock = _FakeFp._Raw._Sock()

    def __init__(self, data: bytes):
        super().__init__(data)
        self.raw = _FakeFp._Raw()


class _FakeResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes):
        self.status = status
        self._headers = headers
        self.fp = _FakeFp(body)

    def getheaders(self):
        return list(self._headers.items())

    def read(self, amount: int) -> bytes:
        return self.fp.read(amount)


def _serve(monkeypatch, responses: list[_FakeResponse]) -> list[str]:
    """Answer each request with the next canned response; log the hostnames."""
    hosts: list[str] = []
    queue = list(responses)

    monkeypatch.setattr(
        safe_http, "_resolve", lambda hostname: [ipaddress.ip_address(PUBLIC_IP)]
    )

    def fake_request_once(target, address, headers, *, deadline, max_bytes):
        hosts.append(target.hostname)
        response = queue.pop(0)
        body, truncated = safe_http._read_body(response, deadline=deadline, max_bytes=max_bytes)
        return response.status, {k.lower(): v for k, v in response.getheaders()}, body, truncated

    monkeypatch.setattr(safe_http, "_request_once", fake_request_once)
    return hosts


# --- stage plumbing ---------------------------------------------------------


def test_mail_posture_disabled(tmp_path: Path):
    result = check_mail_posture(["example.com"], MailPostureConfig(enabled=False), tmp_path)
    assert result["skipped_reason"] == "mail_posture.disabled"
    assert (tmp_path / "mail_posture.json").exists()
    assert (tmp_path / "mail_posture_findings.txt").exists()


def test_mail_posture_no_domains(tmp_path: Path):
    result = check_mail_posture([], MailPostureConfig(enabled=True), tmp_path)
    assert result["skipped_reason"] == "no_domains"
    assert (tmp_path / "mail_posture.json").exists()


def test_mail_posture_truncates_at_max_domains(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch)
    result = check_mail_posture(
        ["a.example", "b.example"],
        MailPostureConfig(enabled=True, max_domains=1, mta_sts_http=False),
        tmp_path,
    )
    assert result["truncated"] is True
    assert result["seed_domains"] == ["a.example"]


def test_dkim_query_budget_truncates_the_domain_list(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch)
    selectors = ["default", "google"]
    domains = [f"d{index}.example" for index in range(mail_posture.MAX_DKIM_QUERIES)]
    result = check_mail_posture(
        domains,
        MailPostureConfig(
            enabled=True,
            max_domains=len(domains),
            dkim_selectors=selectors,
            mta_sts_http=False,
        ),
        tmp_path,
    )
    assert result["truncated"] is True
    checked = [
        domain
        for domain, record in result["domains"].items()
        if record["dkim"]["reason"] != "selector_budget_exhausted"
    ]
    assert len(checked) == mail_posture.MAX_DKIM_QUERIES // len(selectors)


def test_mx_set_is_capped_per_domain(tmp_path: Path, monkeypatch):
    many = [f"{index} mx{index}.example.com" for index in range(mail_posture.MAX_MX_PER_DOMAIN + 3)]
    _patch_dnsx(monkeypatch, mx={"example.com": {"mx": many}})
    result = check_mail_posture(
        ["example.com"], MailPostureConfig(enabled=True, mta_sts_http=False), tmp_path
    )
    mx = result["domains"]["example.com"]["mx"]
    assert len(mx["entries"]) == mail_posture.MAX_MX_PER_DOMAIN
    assert mx["truncated"] is True
    assert result["truncated"] is True


# --- MX / SPF / DMARC -------------------------------------------------------


def test_mx_entries_and_null_mx():
    assert _mx_entries({"mx": ["10 Mail.Example.com."]}) == [
        {"preference": 10, "host": "mail.example.com"}
    ]
    assert _mx_entries({"mx": [{"preference": 5, "host": "mx.example.com"}]}) == [
        {"preference": 5, "host": "mx.example.com"}
    ]
    assert _is_null_mx(_mx_entries({"mx": ["0 ."]})) is True
    assert _is_null_mx(_mx_entries({"mx": ["10 mail.example.com"]})) is False


def test_spf_all_qualifiers():
    assert _spf_all_qualifier("v=spf1 include:x.example -all") == "-all"
    assert _spf_all_qualifier("v=spf1 +all") == "+all"
    assert _spf_all_qualifier("v=spf1 all") == "+all"
    assert _spf_all_qualifier("v=spf1 include:x.example") is None


def test_spf_permissive_and_clean():
    _, findings = _classify_spf("example.com", ["v=spf1 ip4:198.51.100.0/24 +all"], None)
    assert [f["kind"] for f in findings] == ["spf_all_permissive"]
    assert findings[0]["severity"] == "critical"

    _, findings = _classify_spf("example.com", ["v=spf1 ip4:198.51.100.0/24 -all"], None)
    assert findings == []

    _, findings = _classify_spf("example.com", ["v=spf1 -all", "v=spf1 ~all"], None)
    assert "spf_multiple_records" in {f["kind"] for f in findings}

    _, findings = _classify_spf("example.com", ["v=spf1 ptr -all"], None)
    assert [f["kind"] for f in findings] == ["spf_ptr_mechanism"]


def test_spf_include_cycle_stops_and_is_reported(tmp_path: Path, monkeypatch):
    txt = {
        "a.example": {"txt": ["v=spf1 include:b.example -all"]},
        "b.example": {"txt": ["v=spf1 include:a.example -all"]},
        "_dmarc.a.example": {"txt": ["v=DMARC1; p=reject; rua=mailto:d@a.example"]},
    }
    kinds = _patch_dnsx(monkeypatch, mx={"a.example": {"mx": ["10 mx.a.example"]}}, txt=txt)

    result = check_mail_posture(
        ["a.example"], MailPostureConfig(enabled=True, mta_sts_http=False), tmp_path
    )

    # Terminates: without the visited set this recurses until the process dies.
    assert kinds.count("spf_include") <= mail_posture.SPF_MAX_DEPTH
    evaluation = result["domains"]["a.example"]["spf"]["evaluation"]
    assert evaluation["cycles"] == ["b.example->a.example"]
    assert evaluation["lookups"] == 2
    assert "spf_include_cycle" in _kinds(result)


def test_spf_lookup_limit_is_a_finding(tmp_path: Path, monkeypatch):
    record = "v=spf1 " + " ".join(f"include:i{index}.example" for index in range(12)) + " -all"
    evaluation = mail_posture._evaluate_spf(
        "example.com", record, tmp_path, timeout=5, retries=0
    )
    assert evaluation["lookup_limit_exceeded"] is True
    _, findings = _classify_spf("example.com", [record], evaluation)
    assert "spf_too_many_lookups" in {f["kind"] for f in findings}


def test_dmarc_policies():
    block, findings = _classify_dmarc("example.com", [])
    assert block["status"] == "missing"
    assert [f["kind"] for f in findings] == ["dmarc_missing"]

    _, findings = _classify_dmarc("example.com", ["v=DMARC1; p=none; rua=mailto:d@example.com"])
    assert [f["kind"] for f in findings] == ["dmarc_policy_none"]

    _, findings = _classify_dmarc(
        "example.com", ["v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:d@example.com"]
    )
    assert {f["kind"] for f in findings} == {"dmarc_subdomain_policy_none", "dmarc_pct_partial"}

    block, findings = _classify_dmarc("example.com", ["v=DMARC1; p=reject; rua=mailto:d@x.example"])
    assert findings == []
    assert block["policy"] == "reject"


# --- DKIM -------------------------------------------------------------------


def test_dkim_unknown_selector_is_not_checked_not_a_failure(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch, mx={"example.com": {"mx": ["10 mx.example.com"]}})
    result = check_mail_posture(
        ["example.com"], MailPostureConfig(enabled=True, mta_sts_http=False), tmp_path
    )
    dkim = result["domains"]["example.com"]["dkim"]
    # Selectors are arbitrary: silence is not evidence of absence.
    assert dkim["status"] == "not_checked"
    assert dkim["reason"] == "no_known_selector"
    assert not [kind for kind in _kinds(result) if kind.startswith("dkim")]


def test_dkim_found_selector_and_revoked_key(tmp_path: Path, monkeypatch):
    txt = {
        "default._domainkey.example.com": {"txt": ["v=DKIM1; k=rsa; p=MIIBjQ"]},
        "google._domainkey.example.com": {"txt": ["v=DKIM1; k=rsa; p="]},
    }
    _patch_dnsx(monkeypatch, mx={"example.com": {"mx": ["10 mx.example.com"]}}, txt=txt)
    result = check_mail_posture(
        ["example.com"],
        MailPostureConfig(
            enabled=True, dkim_selectors=["default", "google"], mta_sts_http=False
        ),
        tmp_path,
    )
    dkim = result["domains"]["example.com"]["dkim"]
    assert dkim["status"] == "present"
    assert dkim["selectors"] == {"default": {"revoked": False}, "google": {"revoked": True}}
    assert "dkim_key_revoked" in _kinds(result)


# --- MTA-STS ----------------------------------------------------------------


def test_mta_sts_policy_does_not_follow_a_redirect(monkeypatch):
    hosts = _serve(
        monkeypatch,
        [
            _FakeResponse(302, {"Location": "https://evil.example/policy"}, b""),
            _FakeResponse(200, {}, b"version: STSv1\nmode: enforce\n"),
        ],
    )

    policy = _fetch_mta_sts_policy("example.com", timeout=5)

    # RFC 8461 section 3.3: a policy fetch MUST NOT follow 3xx. Exactly one
    # request, and the redirect target is never dialled.
    assert hosts == ["mta-sts.example.com"]
    assert policy["status"] == "error"
    assert policy["mode"] is None


def test_mta_sts_policy_is_capped(monkeypatch):
    body = b"mode: enforce\n" + b"x" * (mail_posture.MTA_STS_MAX_BYTES + 4096)
    _serve(monkeypatch, [_FakeResponse(200, {}, body)])

    policy = _fetch_mta_sts_policy("example.com", timeout=5)

    assert policy["status"] == "error"
    assert policy["reason"] == "policy_too_large"
    assert policy["truncated"] is True


def test_mta_sts_policy_mode_is_parsed(monkeypatch):
    _serve(monkeypatch, [_FakeResponse(200, {}, b"version: STSv1\nmode: testing\nmax_age: 604800\n")])
    assert _fetch_mta_sts_policy("example.com", timeout=5) == {
        "status": "ok",
        "reason": None,
        "mode": "testing",
        "truncated": False,
    }


def test_mta_sts_http_is_skipped_without_the_txt_record(tmp_path: Path, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("no policy fetch without an announced _mta-sts record")

    _patch_dnsx(monkeypatch, mx={"example.com": {"mx": ["10 mx.example.com"]}})
    monkeypatch.setattr(mail_posture, "_fetch_mta_sts_policy", explode)

    result = check_mail_posture(["example.com"], MailPostureConfig(enabled=True), tmp_path)
    assert result["domains"]["example.com"]["mta_sts"]["status"] == "missing"
    assert "mta_sts_missing" in _kinds(result)


# --- the cheap finding ------------------------------------------------------


def test_domain_without_mx_needs_spf_reject_and_dmarc_reject(tmp_path: Path, monkeypatch):
    txt = {
        "parked.example": {"txt": ["v=spf1 -all"]},
        "_dmarc.parked.example": {"txt": ["v=DMARC1; p=none; rua=mailto:d@parked.example"]},
    }
    _patch_dnsx(monkeypatch, txt=txt)
    result = check_mail_posture(
        ["parked.example"], MailPostureConfig(enabled=True, mta_sts_http=False), tmp_path
    )
    finding = next(f for f in result["findings"] if f["kind"] == "no_mx_domain_spoofable")
    assert finding["severity"] == "high"
    assert finding["spf_all"] == "-all"
    assert finding["dmarc_policy"] == "none"


def test_domain_without_mx_that_is_locked_down_has_no_finding(tmp_path: Path, monkeypatch):
    txt = {
        "parked.example": {"txt": ["v=spf1 -all"]},
        "_dmarc.parked.example": {"txt": ["v=DMARC1; p=reject; rua=mailto:d@parked.example"]},
    }
    _patch_dnsx(monkeypatch, txt=txt)
    result = check_mail_posture(
        ["parked.example"], MailPostureConfig(enabled=True, mta_sts_http=False), tmp_path
    )
    assert "no_mx_domain_spoofable" not in _kinds(result)


def test_null_mx_domain_is_still_required_to_be_unspoofable(tmp_path: Path, monkeypatch):
    txt = {"parked.example": {"txt": ["v=spf1 ~all"]}}
    _patch_dnsx(monkeypatch, mx={"parked.example": {"mx": ["0 ."]}}, txt=txt)
    result = check_mail_posture(
        ["parked.example"], MailPostureConfig(enabled=True, mta_sts_http=False), tmp_path
    )
    assert result["domains"]["parked.example"]["mx"]["null_mx"] is True
    assert "no_mx_domain_spoofable" in _kinds(result)


def test_domain_with_no_dns_answer_is_not_checked(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch)
    result = check_mail_posture(
        ["example.com"], MailPostureConfig(enabled=True, mta_sts_http=False), tmp_path
    )
    record = result["domains"]["example.com"]
    assert record["status"] == "not_checked"
    assert record["reason"] == "no_dns_answer"
