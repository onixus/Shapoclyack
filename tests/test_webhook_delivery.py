"""Phase 10.3: webhook signing, headers and the SSRF delivery boundary."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress

import pytest

from api.services import outbound_targets
from api.services.integrations import delivery


def test_canonical_body_is_stable_across_key_order():
    a = delivery.canonical_body({"b": 1, "a": {"y": 2, "x": 1}})
    b = delivery.canonical_body({"a": {"x": 1, "y": 2}, "b": 1})
    assert a == b == b'{"a":{"x":1,"y":2},"b":1}'


def test_signature_matches_receiver_side_recomputation():
    body = delivery.canonical_body({"kind": "new_cve"})
    signature = delivery.sign("s3cret", "1760000000", body)
    expected = hmac.new(b"s3cret", b"1760000000." + body, hashlib.sha256).hexdigest()
    assert signature == f"sha256={expected}"


def test_signature_covers_the_timestamp():
    body = delivery.canonical_body({"kind": "new_cve"})
    assert delivery.sign("s3cret", "1760000000", body) != delivery.sign(
        "s3cret", "1760000060", body
    )


def test_build_request_sets_signature_and_event_headers():
    body, headers = delivery.build_request(
        payload={"kind": "new_cve"},
        secret="s3cret",
        extra_headers={"X-Team": "soc"},
        delivery_id="whd_1",
        tenant_id="acme",
        event_kind="new_cve",
        event_id="ev1",
    )
    assert headers[delivery.EVENT_HEADER] == "new_cve"
    assert headers[delivery.EVENT_ID_HEADER] == "ev1"
    assert headers[delivery.DELIVERY_HEADER] == "whd_1"
    assert headers[delivery.TENANT_HEADER] == "acme"
    assert headers["X-Team"] == "soc"
    assert headers[delivery.SIGNATURE_HEADER] == delivery.sign(
        "s3cret", headers[delivery.TIMESTAMP_HEADER], body
    )


def test_build_request_without_secret_is_unsigned():
    _, headers = delivery.build_request(
        payload={"kind": "new_asset"},
        secret=None,
        extra_headers=None,
        delivery_id="whd_1",
        tenant_id="acme",
        event_kind="new_asset",
        event_id="ev1",
    )
    assert delivery.SIGNATURE_HEADER not in headers


def test_sanitize_headers_drops_reserved_names():
    cleaned = delivery.sanitize_headers(
        {
            "X-Shapoclyack-Signature": "sha256=forged",
            "Content-Type": "text/plain",
            "Host": "evil.example",
            "X-Api-Key": "k",
        }
    )
    assert cleaned == {"X-Api-Key": "k"}


def test_sanitize_headers_rejects_header_injection():
    with pytest.raises(ValueError, match="illegal characters"):
        delivery.sanitize_headers({"X-Api-Key": "k\r\nX-Admin: true"})


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/hook",
        "file:///etc/passwd",
        "://nope",
        "",
        "https://user:pass@example.com/hook",
    ],
)
def test_validate_url_rejects_illegal_targets(url):
    with pytest.raises(delivery.WebhookTargetError):
        delivery.validate_url(url)


def test_validate_url_rejects_malformed_port():
    with pytest.raises(delivery.WebhookTargetError, match="invalid port"):
        delivery.validate_url("https://example.com:notaport/hook")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/hook",
        "http://10.0.0.5/hook",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/hook",
    ],
)
def test_validate_url_blocks_internal_targets_by_default(url):
    with pytest.raises(delivery.WebhookTargetError, match="non-public"):
        delivery.validate_url(url)


def test_validate_url_allows_internal_targets_when_opted_in():
    url = "http://127.0.0.1:8080/hook"
    assert delivery.validate_url(url, allow_private=True) == url


def test_validate_url_allows_public_literal():
    assert delivery.validate_url("https://93.184.216.34/hook").endswith("/hook")


def test_post_refuses_internal_target_before_wire_call(monkeypatch):
    def _boom(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("wire call reached for blocked target")

    monkeypatch.setattr(delivery, "_send_to_address", _boom)
    result = delivery.post("http://127.0.0.1/hook", b"{}", {})
    assert result.ok is False
    assert result.retryable is False
    assert "non-public" in (result.error or "")


def test_post_pins_connection_to_the_validated_address(monkeypatch):
    approved = ipaddress.ip_address("93.184.216.34")
    seen = {}

    monkeypatch.setattr(outbound_targets, "resolve", lambda host: [approved])

    def _capture(target, address, body, headers, *, method="POST", deadline, capture_body=False):
        seen["method"] = method
        seen["target"] = target
        seen["address"] = address
        seen["body"] = body
        seen["headers"] = headers
        assert deadline > 0
        return 204, ""

    monkeypatch.setattr(delivery, "_send_to_address", _capture)
    result = delivery.post("https://receiver.example:8443/hook?q=1", b"{}", {"X-Test": "1"})

    assert result.ok is True
    assert seen["method"] == "POST"
    assert seen["address"] == approved
    assert seen["target"].hostname == "receiver.example"
    assert seen["target"].port == 8443
    assert seen["target"].request_target == "/hook?q=1"
    assert seen["target"].host_header == "receiver.example:8443"


def test_post_does_not_reresolve_after_validation(monkeypatch):
    approved = ipaddress.ip_address("93.184.216.34")
    calls = []

    def _resolve(host):
        calls.append(host)
        if len(calls) > 1:
            return [ipaddress.ip_address("127.0.0.1")]
        return [approved]

    monkeypatch.setattr(outbound_targets, "resolve", _resolve)
    monkeypatch.setattr(
        delivery,
        "_send_to_address",
        lambda target, address, body, headers, *, method="POST", deadline, capture_body=False: (200, ""),
    )

    result = delivery.post("https://receiver.example/hook", b"{}", {})
    assert result.ok is True
    assert calls == ["receiver.example"]


@pytest.mark.parametrize(
    ("status_code", "ok", "retryable"),
    [
        (200, True, False),
        (204, True, False),
        (400, False, False),
        (401, False, False),
        (404, False, False),
        (408, False, True),
        (429, False, True),
        (500, False, True),
        (503, False, True),
    ],
)
def test_post_classifies_response_codes(monkeypatch, status_code, ok, retryable):
    monkeypatch.setattr(
        outbound_targets,
        "resolve",
        lambda host: [ipaddress.ip_address("93.184.216.34")],
    )
    monkeypatch.setattr(
        delivery,
        "_send_to_address",
        lambda target, address, body, headers, *, method="POST", deadline, capture_body=False: (
            status_code,
            "body",
        ),
    )
    result = delivery.post("https://receiver.example/hook", b"{}", {})
    assert (result.ok, result.retryable) == (ok, retryable)
    assert result.status_code == status_code


def test_post_treats_transport_errors_as_retryable(monkeypatch):
    monkeypatch.setattr(
        outbound_targets,
        "resolve",
        lambda host: [ipaddress.ip_address("93.184.216.34")],
    )

    def _raise(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(delivery, "_send_to_address", _raise)
    result = delivery.post("https://receiver.example/hook", b"{}", {})
    assert result.ok is False
    assert result.retryable is True
    assert "TimeoutError" in (result.error or "")


def test_post_does_not_follow_redirects(monkeypatch):
    monkeypatch.setattr(
        outbound_targets,
        "resolve",
        lambda host: [ipaddress.ip_address("93.184.216.34")],
    )
    monkeypatch.setattr(
        delivery,
        "_send_to_address",
        lambda target, address, body, headers, *, method="POST", deadline, capture_body=False: (
            302,
            "moved",
        ),
    )
    result = delivery.post("https://receiver.example/hook", b"{}", {})
    assert result.ok is False
    assert result.status_code == 302
    assert result.retryable is False
