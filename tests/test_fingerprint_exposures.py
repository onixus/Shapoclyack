"""The fingerprint stage end to end against a loopback HTTP server (DQ4).

Everything here goes through ``fingerprint_hosts_sync`` and a real socket --
redirects, headers and bodies as httpx sees them -- so what is asserted is
what lands in ``fingerprint.json``, and what the risk model then reads from it.
Responses come from ``tests/fixtures/fingerprint/web_responses.json`` or are
written inline; all are synthetic.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from api.services.risk_scoring import CDN_WAF_PROVIDERS, index_cdn_waf, resolve_compensating_control
from scanner.pipeline.config_schema import FingerprintConfig
from scanner.pipeline.fingerprint import fingerprint_hosts_sync

FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures" / "fingerprint" / "web_responses.json").read_text(encoding="utf-8")
)
#: Route: (status, [(header, value), ...], body).
Route = tuple[int, list[tuple[str, str]], str]


class _Site(ThreadingHTTPServer):
    routes: dict[str, Route]

    @property
    def port(self) -> int:
        return self.server_address[1]


@pytest.fixture()
def site():
    """A loopback web server answering ``routes[path]`` (query ignored)."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server hook
            route = self.server.routes.get(urlsplit(self.path).path)  # type: ignore[attr-defined]
            if route is None:
                self.send_error(404)
                return
            status, headers, body = route
            payload = body.encode("utf-8")
            # send_response_only, not send_response: the latter adds its own
            # "Server: BaseHTTP/..." and every banner under test would be a pair.
            self.send_response_only(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args) -> None:
            return

    server = _Site(("127.0.0.1", 0), Handler)
    server.routes = {}
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run(site: _Site, tmp_path: Path) -> dict[str, Any]:
    config = FingerprintConfig(enabled=True, http_ports=[site.port], https_ports=[])
    return fingerprint_hosts_sync([f"127.0.0.1:{site.port}/tcp"], config, tmp_path)


def _fixture(tech: str) -> Route:
    fx = next(fx for fx in FIXTURES["positives"] if fx["tech"] == tech and "url" not in fx)
    return fx["status"], [tuple(h) for h in fx["headers"]], fx["body"]


def _kinds(result: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {(e["kind"], e["technology"], e["severity"]) for e in result["exposures"]}


# ----------------------------------------------------------------- inventory


def test_stage_reports_technologies_with_version_cpe_and_exposures(site, tmp_path: Path):
    site.routes["/"] = (
        403,
        [("X-Jenkins", "2.414.3"), ("Server", "Jetty(10.0.13)")],
        "<html><head><title>Dashboard [Jenkins]</title></head></html>",
    )

    result = _run(site, tmp_path)

    (endpoint,) = result["findings"]
    techs = {t["id"]: t for t in endpoint["technologies"]}
    assert set(techs) == {"jenkins", "eclipse_jetty"}
    assert techs["jenkins"]["version"] == "2.414.3"
    assert techs["jenkins"]["cpe"] == "cpe:2.3:a:jenkins:jenkins:2.414.3:*:*:*:*:*:*:*"
    assert techs["jenkins"]["category"] == "devops"
    assert techs["jenkins"]["confidence"] == "high"
    assert "header x-jenkins: 2.414.3" in techs["jenkins"]["evidence"]
    assert techs["eclipse_jetty"]["version"] == "10.0.13"
    assert endpoint["title"] == "Dashboard [Jenkins]"
    assert endpoint["cdn_waf"] == [] and endpoint["cms_framework"] == []

    assert _kinds(result) == {
        ("exposed_admin_interface", "jenkins", "medium"),
        ("version_disclosure", "jenkins", "info"),
        ("version_disclosure", "eclipse_jetty", "info"),
    }
    admin = next(e for e in result["exposures"] if e["kind"] == "exposed_admin_interface")
    assert admin["host"] == "127.0.0.1" and admin["port"] == site.port
    assert admin["url"] == f"http://127.0.0.1:{site.port}/"
    assert admin["cpe"] == "cpe:2.3:a:jenkins:jenkins:2.414.3:*:*:*:*:*:*:*"
    disclosure = next(e for e in result["exposures"] if e["kind"] == "version_disclosure" and e["header"] == "x-jenkins")
    assert disclosure["evidence"] == ["x-jenkins: 2.414.3"]

    saved = json.loads((tmp_path / "fingerprint.json").read_text(encoding="utf-8"))
    assert saved["exposures"] == result["exposures"]
    assert saved["catalogue"]["technologies"] >= 100


def test_same_host_redirect_is_followed_and_the_portal_inventoried(site, tmp_path: Path):
    site.routes["/"] = (302, [("Location", "/owa/auth/logon.aspx?replaceCurrent=1&url=%2fowa%2f")], "")
    site.routes["/owa/auth/logon.aspx"] = (
        200,
        [("X-OWA-Version", "15.2.1258.12")],
        '<html><head><link rel="stylesheet" href="/owa/auth/15.2.1258.12/themes/resources/logon.css"></head></html>',
    )

    result = _run(site, tmp_path)

    (endpoint,) = result["findings"]
    assert endpoint["final_url"] == f"http://127.0.0.1:{site.port}/owa/auth/logon.aspx"
    assert endpoint["redirected_off_host"] is False
    assert [t["id"] for t in endpoint["technologies"]] == ["exchange_owa"]
    assert _kinds(result) == {
        ("exposed_remote_access_gateway", "exchange_owa", "info"),
        ("version_disclosure", "exchange_owa", "info"),
    }
    gateway = next(e for e in result["exposures"] if e["kind"] == "exposed_remote_access_gateway")
    # The join key for KEV: the product, without a build number NVD does not file.
    assert gateway["cpe"] == "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"
    assert gateway["version"] == "15.2.1258.12"
    assert gateway["category"] == "mail_webmail"


@pytest.mark.parametrize(
    "tech, kind",
    [
        ("fortinet_fortigate", "exposed_remote_access_gateway"),
        ("phpmyadmin", "exposed_admin_interface"),
        ("mikrotik_routeros", "exposed_admin_interface"),
        ("elasticsearch", "exposed_admin_interface"),
        ("grafana", "exposed_admin_interface"),
    ],
)
def test_category_decides_the_exposure_kind(site, tmp_path: Path, tech: str, kind: str):
    site.routes["/"] = _fixture(tech)
    result = _run(site, tmp_path)
    assert (kind, tech) in {(e["kind"], e["technology"]) for e in result["exposures"]}
    # None of these states a version in a header (Grafana, RouterOS and
    # Elasticsearch say it in the body): that is inventory, not a disclosure.
    assert not [e for e in result["exposures"] if e["kind"] == "version_disclosure"]


def test_inventory_only_categories_raise_no_exposure(site, tmp_path: Path):
    """A CMS, a framework, a load balancer: inventory, not a finding."""
    site.routes["/"] = (
        200,
        [("Server", "nginx"), ("Set-Cookie", "BIGipServerweb=1.2.3; path=/"), ("X-Powered-By", "Express")],
        "<html><body><img src='/wp-content/uploads/a.png'></body></html>",
    )
    result = _run(site, tmp_path)
    (endpoint,) = result["findings"]
    assert {t["id"] for t in endpoint["technologies"]} == {"nginx", "f5_bigip_ltm", "wordpress", "express"}
    assert result["exposures"] == []


def test_off_host_redirect_keeps_the_inventory_but_raises_no_exposure(site, tmp_path: Path):
    site.routes["/"] = (302, [("Location", f"http://localhost:{site.port}/login")], "")
    site.routes["/login"] = (200, [("X-Jenkins", "2.414.3")], "<html><title>Sign in [Jenkins]</title></html>")

    result = _run(site, tmp_path)

    (endpoint,) = result["findings"]
    assert endpoint["redirected_off_host"] is True
    assert endpoint["final_url"] == f"http://localhost:{site.port}/login"
    assert [t["id"] for t in endpoint["technologies"]] == ["jenkins"]
    assert result["exposures"] == []


@pytest.mark.parametrize("name", [fx["name"] for fx in FIXTURES["negatives"] if fx["status"] != 204])
def test_generic_pages_identify_nothing_end_to_end(site, tmp_path: Path, name: str):
    fx = next(fx for fx in FIXTURES["negatives"] if fx["name"] == name)
    site.routes["/"] = (fx["status"], [tuple(h) for h in fx["headers"]], fx["body"])
    result = _run(site, tmp_path)
    (endpoint,) = result["findings"]
    assert endpoint["technologies"] == []
    assert result["exposures"] == []


def test_a_failed_request_keeps_the_new_fields(tmp_path: Path):
    config = FingerprintConfig(enabled=True, http_ports=[9], https_ports=[], timeout_seconds=1)
    result = fingerprint_hosts_sync(["127.0.0.1:9/tcp"], config, tmp_path)
    (endpoint,) = result["findings"]
    assert endpoint["error"] == "request_failed"
    assert endpoint["technologies"] == [] and endpoint["final_url"] is None
    assert result["exposures"] == []


# ------------------------------------------- backward compatibility (#173)

# The Phase 9.1 predicates, verbatim, as the reference for what consumers saw.
def _legacy_cdn_waf(h: httpx.Headers) -> list[str]:
    blob = " ".join(h.get_list("set-cookie")).lower()
    signatures: list[tuple[str, Callable[[httpx.Headers], bool]]] = [
        ("cloudflare", lambda h: "cf-ray" in h or "cloudflare" in h.get("server", "").lower()),
        (
            "akamai",
            lambda h: any(k.lower().startswith("x-akamai") for k in h.keys())
            or "akamai" in h.get("server", "").lower(),
        ),
        ("sucuri", lambda h: "x-sucuri-id" in h or "x-sucuri-cache" in h),
        ("imperva_incapsula", lambda h: "x-iinfo" in h or any(n in blob for n in ("incap_ses", "visid_incap"))),
        ("cloudfront", lambda h: "x-amz-cf-id" in h or "cloudfront" in h.get("via", "").lower()),
        ("fastly", lambda h: "x-fastly-request-id" in h or "fastly" in h.get("x-served-by", "").lower()),
    ]
    return [name for name, matches in signatures if matches(h)]


_LEGACY_CORPUS: list[list[tuple[str, str]]] = [
    *([tuple(h) for h in fx["headers"]] for fx in FIXTURES["positives"] if fx["tech"] in CDN_WAF_PROVIDERS),
    [("Server", "cloudflare")],
    [("CF-RAY", "8a1b2c3d4e5f6a7b-AMS"), ("Server", "nginx")],
    [("Server", "AkamaiNetStorage")],
    [("X-Akamai-Request-ID", "1a2b")],
    [("X-Iinfo", "1-2-3")],
    [("Set-Cookie", "visid_incap_1=abc; path=/")],
    [("Via", "1.1 abc.cloudfront.net (CloudFront)")],
    [("X-Fastly-Request-ID", "abc")],
    [("Server", "cloudflare"), ("X-Amz-Cf-Id", "abc"), ("X-Sucuri-ID", "1")],
    [("Server", "nginx"), ("Via", "1.1 varnish")],
    [("Server", "QRATOR")],
    [("Server", "ddos-guard")],
]


@pytest.mark.parametrize("headers", _LEGACY_CORPUS, ids=lambda h: ",".join(f"{k}={v}"[:24] for k, v in h))
def test_cdn_waf_for_the_original_six_is_what_phase_9_1_reported(site, tmp_path: Path, headers):
    site.routes["/"] = (200, headers, "<html></html>")
    (endpoint,) = _run(site, tmp_path)["findings"]
    legacy = [name for name in endpoint["cdn_waf"] if name in CDN_WAF_PROVIDERS]
    assert legacy == _legacy_cdn_waf(httpx.Headers(headers))


def test_a_cookie_value_that_mentions_incapsula_earns_no_discount(site, tmp_path: Path):
    """The one place the catalogue is narrower than Phase 9.1, on purpose.

    The old predicate searched the whole Set-Cookie text, values included, so
    an application cookie whose value happened to contain ``incap_ses`` was
    "Imperva on path" and took the -6. The catalogue reads cookie names only.
    """
    site.routes["/"] = (200, [("Set-Cookie", "pref=laravel_session-and-incap_ses_like_text; path=/")], "")
    result = _run(site, tmp_path)
    (endpoint,) = result["findings"]
    assert _legacy_cdn_waf(httpx.Headers(site.routes["/"][1])) == ["imperva_incapsula"]
    assert endpoint["cdn_waf"] == []
    assert index_cdn_waf(result) == {}


@pytest.mark.parametrize(
    "tech", ["qrator", "ddos_guard", "variti", "azure_front_door", "vercel", "barracuda_waf", "f5_bigip_asm"]
)
def test_a_cdn_waf_the_catalogue_learned_later_earns_no_risk_discount(site, tmp_path: Path, tech: str):
    site.routes["/"] = _fixture(tech)
    result = _run(site, tmp_path)
    (endpoint,) = result["findings"]
    assert tech in [t["id"] for t in endpoint["technologies"]]
    assert index_cdn_waf(result) == {}
    assert resolve_compensating_control(host="127.0.0.1", port=site.port, index=index_cdn_waf(result)) == ((), "none")


def test_a_medium_confidence_cdn_waf_stays_out_of_the_cdn_waf_list(site, tmp_path: Path):
    site.routes["/"] = _fixture("barracuda_waf")
    (endpoint,) = _run(site, tmp_path)["findings"]
    assert [t["id"] for t in endpoint["technologies"]] == ["barracuda_waf"]
    assert endpoint["cdn_waf"] == []


@pytest.mark.parametrize("tech", sorted(CDN_WAF_PROVIDERS))
def test_the_original_six_still_feed_the_discount(site, tmp_path: Path, tech: str):
    site.routes["/"] = _fixture(tech)
    result = _run(site, tmp_path)
    assert index_cdn_waf(result) == {("127.0.0.1", site.port): (tech,)}


def test_cms_framework_keeps_the_phase_9_1_names_and_gains_new_ones(site, tmp_path: Path):
    site.routes["/"] = (
        200,
        [("X-Powered-By", "PHP/8.2.12"), ("Set-Cookie", "BITRIX_SM_GUEST_ID=1; path=/")],
        '<html><head><meta name="generator" content="WordPress 6.4.2"></head>'
        "<body><img src='/wp-content/a.png'><script id=\"__NEXT_DATA__\"></script></body></html>",
    )
    (endpoint,) = _run(site, tmp_path)["findings"]
    assert endpoint["cms_framework"] == ["wordpress", "bitrix", "nextjs", "generic_php"]
    lines = (tmp_path / "fingerprint_matches.txt").read_text(encoding="utf-8").splitlines()
    assert lines == [f"127.0.0.1:{site.port}:http:wordpress,bitrix,nextjs,generic_php"]
