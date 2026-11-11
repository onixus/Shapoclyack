"""Brand-watch M2: HTTP observation, similarity, evidence, diff event.

No network. The transport is ``httpx.MockTransport``; a request that is not
one of the two allowed GETs fails the test.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from api.services.brand_watch_http import apply_http_observation, build_diff_event
from scanner.brand_watch.http_observe import (
    BODY_MAX_BYTES,
    FAVICON_MAX_BYTES,
    HttpObservationRequest,
    RefusedAddress,
    observe_http,
    observe_http_or_refuse,
    refuse_reason,
)
from scanner.brand_watch.similarity import jaccard, score_observation, word_shingles
from scanner.pipeline.parking import match_parking

FIXTURES = Path(__file__).parent / "fixtures" / "brand_watch"
NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)
# 1.1.1.1 is global. 203.0.113.0/24 is documentation space, which
# is_public_address refuses, so it cannot stand in for a DNS answer.
PUBLIC = "1.1.1.1"
NAME = "acme-login.example"


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _cert(*, cn: str = "", san: tuple[str, ...] = (), not_before: str | None = None) -> dict:
    subject = ((("commonName", cn),),) if cn else ()
    alt = tuple(("DNS", item) for item in san)
    return {"subject": subject, "subjectAltName": alt, "notBefore": not_before}


def _young_cert() -> dict:
    return _cert(cn="acme-login.example", san=("acme-login.example",), not_before="Oct 20 00:00:00 2026 GMT")


def _old_cert() -> dict:
    return _cert(cn="news.example", not_before="Jan  1 00:00:00 2020 GMT")


class _Script:
    """Answers the two allowed GETs from fixtures. Records every request."""

    def __init__(
        self,
        page: bytes | None,
        *,
        status: int = 200,
        favicon: bytes | None = None,
        location: str | None = None,
        fail: bool = False,
    ) -> None:
        self.page = page
        self.status = status
        self.favicon = favicon
        self.location = location
        self.fail = fail
        self.calls: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        if request.method != "GET":
            raise AssertionError(f"method {request.method} is not allowed")
        if request.url.path not in {"/", "/favicon.ico"}:
            raise AssertionError(f"path {request.url.path} is not allowed")
        if len(self.calls) > 2:
            raise AssertionError("more than two requests")
        if self.fail:
            raise httpx.ConnectError("no network")
        if request.url.path == "/favicon.ico":
            if self.favicon is None:
                return httpx.Response(404)
            return httpx.Response(200, content=self.favicon)
        headers = {"location": self.location} if self.location else None
        return httpx.Response(self.status, headers=headers, content=self.page or b"")


def _observe(
    script: _Script,
    *,
    address: str = PUBLIC,
    brand: str = "Acme",
    mx_present: bool = False,
    registered: bool = True,
    rdap_created: datetime | None = None,
    favicon_references: tuple[str, ...] = (),
    reference_excerpts: tuple[str, ...] = (),
    cert: dict | None = None,
    scheme: str = "http",
) -> dict:
    request = HttpObservationRequest(
        name=NAME,
        address=address,
        brand=brand,
        mx_present=mx_present,
        registered=registered,
        rdap_created=rdap_created,
        favicon_references=favicon_references,
        reference_excerpts=reference_excerpts,
        scheme=scheme,
        now=NOW,
    )
    return observe_http(
        request,
        transport=httpx.MockTransport(script),
        cert_lookup=lambda: cert,
    )


def _apply(observation: dict, previous: str | None = "registered") -> dict:
    return apply_http_observation(observation, previous_state=previous)


def test_refuse_sinkhole_and_private_before_any_request():
    script = _Script(b"<html></html>")
    for address in ("0.0.0.0", "127.0.0.1", "::", "::1", "10.1.2.3", "192.168.0.1"):
        assert refuse_reason(address) in {"sinkholed", "private_address"}
        with pytest.raises(RefusedAddress):
            _observe(script, address=address)
    assert script.calls == []
    pack = observe_http_or_refuse(
        HttpObservationRequest(name=NAME, address="127.0.0.1", brand="Acme", scheme="http", now=NOW),
        transport=httpx.MockTransport(script),
    )
    assert pack["skip_reason"] == "sinkholed"
    assert pack["state"] == "resolving"
    assert "html" not in pack


def test_public_address_is_accepted():
    assert refuse_reason(PUBLIC) is None
    assert refuse_reason("8.8.8.8") is None


def test_cross_host_redirect_is_recorded_and_not_followed():
    script = _Script(b"<html><title>gone</title><body>not the page</body></html>", status=302, location="https://evil.example/login")
    pack = _observe(script)
    assert pack["redirected_off_host"] is True
    assert pack["redirect_host"] == "evil.example"
    assert pack["requests"] == 1
    assert script.calls == [("GET", "/")]
    assert pack["title"] == ""
    assert pack["body_sha256"] is None
    assert "<html>" not in repr(pack)


def test_same_host_redirect_is_followed_on_the_pinned_origin():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/start"})
        if request.url.path == "/start":
            return httpx.Response(200, content=_load("live_unbranded.txt"))
        if request.url.path == "/favicon.ico":
            return httpx.Response(404)
        raise AssertionError(request.url.path)

    pack = observe_http(
        HttpObservationRequest(name=NAME, address=PUBLIC, brand="Acme", scheme="http", now=NOW),
        transport=httpx.MockTransport(handler),
    )
    # The same-host hop spends the second GET, so the favicon is not fetched.
    assert seen == ["/", "/start"]
    assert pack["status"] == 200
    assert pack["redirected_off_host"] is False
    assert pack["title"].startswith("Welcome")
    assert pack["requests"] == 2
    assert pack["favicon_sha256"] is None


def test_at_most_two_gets_and_byte_caps():
    page = b"<html><title>x</title><body>" + b"word " * 100 + b"</body></html>"
    favicon = b"f" * 100
    script = _Script(page, favicon=favicon)
    pack = _observe(script)
    assert script.calls == [("GET", "/"), ("GET", "/favicon.ico")]
    assert pack["requests"] == 2
    assert len(pack["excerpt"]) <= 200
    assert len(pack["title"]) <= 200
    assert pack["body_sha256"] == hashlib.sha256(page).hexdigest()
    assert pack["favicon_sha256"] == hashlib.sha256(favicon).hexdigest()
    assert BODY_MAX_BYTES == 64 * 1024
    assert FAVICON_MAX_BYTES == 32 * 1024


def test_body_is_capped_and_raw_html_is_not_returned():
    huge = b"<html><title>Big</title><body>" + (b"A" * (BODY_MAX_BYTES + 5000)) + b"</body></html>"
    script = _Script(huge, favicon=None)
    pack = _observe(script)
    assert pack["truncated"] is True
    assert pack["body_sha256"] != hashlib.sha256(huge).hexdigest()
    blob = repr(pack)
    assert b"<html>" not in blob.encode()
    assert "password" not in blob or "password_form" in blob


def test_tls_fields_without_pem():
    cert = _young_cert()
    cert["pem"] = "-----BEGIN CERTIFICATE-----\nSHOULD-NOT-LEAK\n-----END CERTIFICATE-----"
    script = _Script(_load("phish_login.txt"), favicon=_load("favicon.bin"))
    pack = _observe(script, cert=cert)
    assert pack["cert"]["subject_cn"] == "acme-login.example"
    assert pack["cert"]["san"] == ["acme-login.example"]
    assert pack["cert"]["not_before"] == "2026-10-20T00:00:00Z"
    assert "pem" not in pack["cert"]
    assert "BEGIN CERTIFICATE" not in repr(pack)


def test_parked_is_informational():
    script = _Script(_load("parked.txt"))
    pack = _observe(script, cert=_old_cert())
    assert pack["parked"] is True
    assert pack["parking_marker"] == "godaddy"
    result = _apply(pack)
    assert result["score"]["state"] == "parked"
    assert result["score"]["severity"] == "informational"
    assert result["event"]["type"] == "brand_watch.diff"
    assert result["event"]["payload"]["to_state"] == "parked"
    assert "html" not in result["event"]["payload"]


def test_live_without_brand_in_title_is_low():
    script = _Script(_load("live_unbranded.txt"))
    pack = _observe(script)
    result = _apply(pack)
    assert result["score"]["state"] == "http_live"
    assert result["score"]["severity"] == "low"
    assert result["score"]["state"] != "confirmed"


def test_news_mention_is_not_high():
    script = _Script(_load("news_mention.txt"))
    pack = _observe(script, cert=_old_cert(), reference_excerpts=(_load("reference_excerpt.txt").decode(),))
    assert pack["brand_in_title"] is False
    assert "Acme" in pack["excerpt"] or "acme" in pack["excerpt"].casefold()
    result = _apply(pack)
    assert result["score"]["severity"] not in {"high", "critical"}
    assert result["score"]["state"] != "confirmed"
    assert result["score"]["state"] == "http_live"


def test_empty_spa_is_a_skip_not_a_high_score():
    script = _Script(_load("empty_spa.txt"))
    pack = _observe(script, cert=_young_cert(), mx_present=True)
    assert pack["empty_spa"] is True
    assert pack["skip_reason"] == "empty_spa"
    result = _apply(pack)
    assert result["score"]["skipped"] is True
    assert result["score"]["severity"] not in {"high", "critical"}
    assert result["score"]["state"] == "http_live"
    assert result["score"]["state"] != "confirmed"


def test_young_domain_and_brand_in_title_is_medium_suspicious():
    page = (
        b"<html><title>Acme billing portal</title><body>"
        b"Welcome to the Acme billing portal. Review invoices and account status here today."
        b"</body></html>"
    )
    script = _Script(page)
    pack = _observe(
        script,
        rdap_created=NOW - timedelta(days=5),
        cert=_old_cert(),
    )
    assert pack["young_domain"] is True
    assert pack["brand_in_title"] is True
    result = _apply(pack)
    assert result["score"]["severity"] == "medium"
    assert result["score"]["state"] == "suspicious"


def test_password_form_young_cert_and_brand_is_high_not_confirmed():
    script = _Script(_load("phish_login.txt"))
    pack = _observe(script, cert=_young_cert(), rdap_created=NOW - timedelta(days=3))
    assert pack["password_form"] is True
    assert pack["young_cert"] is True
    result = _apply(pack, previous="http_live")
    assert result["score"]["severity"] == "high"
    assert result["score"]["state"] == "suspicious"
    payload = result["event"]["payload"]
    assert payload == {
        "name": NAME,
        "from_state": "http_live",
        "to_state": "suspicious",
        "severity": "high",
        "reasons": payload["reasons"],
    }
    assert "password_form" in payload["reasons"]
    assert "confirmed" not in payload.values()


def test_favicon_match_raises_to_critical_without_confirming():
    icon = _load("favicon.bin")
    digest = hashlib.sha256(icon).hexdigest()
    script = _Script(_load("phish_login.txt"), favicon=icon)
    pack = _observe(script, cert=_young_cert(), favicon_references=(digest,))
    assert pack["favicon_match"] is True
    result = _apply(pack)
    assert result["score"]["severity"] == "critical"
    assert result["score"]["state"] == "suspicious"
    assert result["score"]["state"] != "confirmed"


def test_parked_with_mx_is_not_informational():
    scored = score_observation({
        "parked": True,
        "registered": True,
        "live": True,
        "has_site": True,
        "mx_present": True,
    })
    assert scored["state"] == "parked"
    assert scored["severity"] == "medium"


def test_mx_without_a_site_raises_severity():
    scored = score_observation({
        "registered": True,
        "mx_present": True,
        "has_site": False,
        "live": False,
    })
    assert scored["severity"] == "medium"
    assert scored["state"] == "resolving"
    assert "mx_without_site" in scored["reasons"]


def test_mx_with_password_and_young_cert_is_high():
    scored = score_observation({
        "registered": True,
        "mx_present": True,
        "has_site": False,
        "live": False,
        "brand_in_cert": True,
        "young_cert": True,
    })
    assert scored["severity"] == "high"
    assert scored["state"] == "suspicious"


def test_shingle_overlap_matches_reference_and_not_news():
    reference = _load("reference_excerpt.txt").decode()
    phish = "Acme account sign-in Enter the password for your Acme workspace to continue to the dashboard and review your invoices today."
    news = "Analysts said Acme reported earnings in line with estimates and that the wider sector drove the move."
    assert jaccard(word_shingles(phish), word_shingles(reference)) >= 0.35
    assert jaccard(word_shingles(news), word_shingles(reference)) < 0.35


def test_parking_catalogue_does_not_match_news():
    news = _load("news_mention.txt").decode()
    assert match_parking("Daily Herald", news) is None
    assert match_parking("This domain is parked", "courtesy of GoDaddy") is not None


def test_diff_event_has_no_html_and_is_not_a_finished_scan():
    event = build_diff_event(
        name=NAME,
        from_state="registered",
        to_state="suspicious",
        severity="high",
        reasons=["password_form", "<html>nope</html>"],
    )
    assert event["type"] == "brand_watch.diff"
    assert set(event["payload"]) == {"name", "from_state", "to_state", "severity", "reasons"}
    assert "<html>" not in repr(event)
    assert event["payload"]["reasons"] == ["password_form"]


def test_unknown_severity_and_state_are_coerced():
    event = build_diff_event(
        name=NAME,
        from_state="impersonation",
        to_state="live",
        severity="info",
        reasons=["registered"],
    )
    assert event["payload"]["from_state"] == "unregistered"
    assert event["payload"]["to_state"] == "unregistered"
    assert event["payload"]["severity"] == "informational"


def test_no_answer_does_not_fetch_favicon():
    script = _Script(None, fail=True)
    pack = _observe(script)
    assert pack["error"] == "no_answer"
    assert pack["requests"] == 1
    assert script.calls == [("GET", "/")]
    assert pack["favicon_sha256"] is None
