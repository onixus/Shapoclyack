"""Phase 10.3: the wire half of webhook delivery — signing, headers, SSRF guard.

Database-free by construction (see api/services/integrations/delivery.py), so
these run everywhere, unlike the queue tests in tests/test_webhooks.py.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

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
    """Replaying an old body under a fresh timestamp must not verify."""
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
    ["ftp://example.com/hook", "file:///etc/passwd", "://nope", ""],
)
def test_validate_url_rejects_non_http_schemes(url):
    with pytest.raises(delivery.WebhookTargetError):
        delivery.validate_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/hook",
        "http://10.0.0.5/hook",
        "http://169.254.169.254/latest/meta-data",  # cloud metadata service
        "http://[::1]/hook",
    ],
)
def test_validate_url_blocks_internal_targets_by_default(url):
    with pytest.raises(delivery.WebhookTargetError, match="non-public"):
        delivery.validate_url(url)


def test_validate_url_allows_internal_targets_when_opted_in():
    url = "http://shapoclyack-receiver.svc.cluster.local:8080/hook"
    assert delivery.validate_url(url, allow_private=True) == url


def test_validate_url_allows_public_literal():
    assert delivery.validate_url("https://93.184.216.34/hook").endswith("/hook")


def test_post_refuses_internal_target_without_retrying(monkeypatch):
    """The guard failing is the operator's to fix — retrying cannot help."""

    def _boom(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("httpx.post called for a blocked target")

    import httpx

    monkeypatch.setattr(httpx, "post", _boom)
    result = delivery.post("http://127.0.0.1/hook", b"{}", {})
    assert result.ok is False
    assert result.retryable is False
    assert "non-public" in (result.error or "")


class _Response:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


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
    import httpx

    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Response(status_code, "body"))
    result = delivery.post("https://receiver.example/hook", b"{}", {})
    assert (result.ok, result.retryable) == (ok, retryable)
    assert result.status_code == status_code


def test_post_treats_transport_errors_as_retryable(monkeypatch):
    import httpx

    def _raise(*args, **kwargs):
        raise httpx.ConnectTimeout("timed out")

    monkeypatch.setattr(httpx, "post", _raise)
    result = delivery.post("https://receiver.example/hook", b"{}", {})
    assert result.ok is False
    assert result.retryable is True
    assert "ConnectTimeout" in (result.error or "")


def test_post_does_not_follow_redirects(monkeypatch):
    """A 302 could point back inside the network the URL check just cleared."""
    seen: dict = {}

    import httpx

    def _capture(url, **kwargs):
        seen.update(kwargs)
        return _Response(302)

    monkeypatch.setattr(httpx, "post", _capture)
    result = delivery.post("https://receiver.example/hook", b"{}", {})
    assert seen["follow_redirects"] is False
    assert result.ok is False
