"""The web technology catalogue behind ``scanner/pipeline/fingerprint.py`` (DQ4).

Fixtures are synthetic (``tests/fixtures/fingerprint/web_responses.json``,
see its ``note``): they hold the catalogue to its own markers and to the
negative corpus, not to the internet.
"""

from __future__ import annotations

import copy
import json
import re
import time
from collections import Counter
from pathlib import Path

import httpx
import pydantic
import pytest

from api.services.retro_match import parse_cpe
from scanner.pipeline.fingerprint_catalogue import (
    CATALOGUE_PATH,
    CATEGORIES,
    Catalogue,
    ClassificationTimeout,
    Response,
    cpe_name,
    load_catalogue,
    meta_generators,
    page_title,
    parse_page,
)

FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures" / "fingerprint" / "web_responses.json").read_text(encoding="utf-8")
)
POSITIVES = FIXTURES["positives"]
NEGATIVES = FIXTURES["negatives"]
ENDPOINT = "http://192.0.2.10"

#: What the task that introduced the catalogue asked to be covered, by
#: category. A category losing its last entry is a regression, not a cleanup.
REQUIRED_CATEGORIES = (
    "cdn_waf",
    "cms",
    "framework",
    "web_server",
    "app_server",
    "admin_panel",
    "remote_access",
    "mail_webmail",
    "devops",
    "monitoring",
    "database_ui",
    "network_appliance",
    "ecommerce",
)


def _classify(fixture: dict) -> list:
    return load_catalogue().classify(
        fixture["status"], httpx.Headers(fixture["headers"]), fixture["body"], ENDPOINT + fixture.get("url", "/")
    )


def _raw() -> dict:
    return json.loads(CATALOGUE_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- schema


def test_catalogue_loads_and_is_a_real_catalogue():
    catalogue = load_catalogue()
    ids = [tech.id for tech in catalogue.technologies]
    assert len(ids) >= 100
    assert len(ids) == len(set(ids))
    counts = Counter(tech.category for tech in catalogue.technologies)
    assert set(counts) <= set(CATEGORIES)
    missing = [category for category in REQUIRED_CATEGORIES if counts[category] == 0]
    assert not missing, f"categories without a single entry: {missing}"


def test_the_original_eleven_signatures_keep_their_names_and_order():
    ids = [tech.id for tech in load_catalogue().technologies]
    legacy_cdn = ["cloudflare", "akamai", "sucuri", "imperva_incapsula", "cloudfront", "fastly"]
    legacy_cms = ["wordpress", "drupal", "joomla", "nextjs", "generic_php"]
    assert ids[:6] == legacy_cdn
    positions = [ids.index(name) for name in legacy_cms]
    assert positions == sorted(positions)


def test_every_cpe_key_is_part_vendor_product_and_round_trips_through_the_retro_parser():
    for tech in load_catalogue().technologies:
        if tech.cpe is None:
            continue
        part, vendor, product = re.split(r"(?<!\\):", tech.cpe)
        assert part in ("a", "o", "h"), tech.id
        assert vendor and product, tech.id
        name = cpe_name(tech.cpe, "1.2.3")
        assert len(re.split(r"(?<!\\):", name)) == 13, name
        assert parse_cpe(name) == (tech.cpe, "1.2.3"), tech.id


def test_cpe_name_escapes_a_version_and_wildcards_a_missing_one():
    assert cpe_name("a:jenkins:jenkins", None) == "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"
    assert cpe_name("a:example:thing", "1.0+git~2") == "cpe:2.3:a:example:thing:1.0\\+git\\~2:*:*:*:*:*:*:*"


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda t: t.update(category="vpn"), "category"),
        (lambda t: t.update(confidence="low"), "confidence"),
        (lambda t: t.update(cpe="cpe:2.3:a:x:y"), "part:vendor:product"),
        (lambda t: t.update(id="Bad Id"), "lower-case"),
        (lambda t: t.update(unexpected=True), "Extra inputs"),
        (lambda t: t.update(match=[]), "at least 1"),
        (lambda t: t.update(match=[{"from": "cookie", "name": "sid", "contains": "x"}]), "presence only"),
        (lambda t: t.update(match=[{"from": "cookie", "name": "SID"}]), "lower-case"),
        (lambda t: t.update(match=[{"from": "header", "name": "set-cookie", "contains": "x"}]), "never sees values"),
        (lambda t: t.update(match=[{"from": "header", "prefix": "set-"}]), "never sees values"),
        (lambda t: t.update(match=[{"from": "header", "name": "x-a", "prefix": "x-"}]), "exactly one of name/prefix"),
        (lambda t: t.update(match=[{"from": "body", "contains": "wp"}]), "too short"),
        (lambda t: t.update(match=[{"from": "body", "equals": "<html>"}]), "not equals"),
        (lambda t: t.update(match=[{"from": "title"}]), "contains/equals/regex"),
        (lambda t: t.update(match=[{"from": "title", "regex": "("}]), "does not compile"),
        (lambda t: t.update(match=[{"from": "title", "contains": ""}]), "empty test"),
        (lambda t: t.update(match=[{"all": [{"from": "title", "equals": "x"}]}]), "at least two"),
        (
            lambda t: t.update(
                match=[
                    {
                        "from": "title",
                        "equals": "x",
                        "all": [{"from": "title", "equals": "a"}, {"from": "title", "equals": "b"}],
                    }
                ]
            ),
            "only sub-matchers",
        ),
        (lambda t: t.update(version=[{"from": "header", "name": "server", "regex": "\\d{1,6}"}]), "no (?P<version>"),
        (lambda t: t.update(version=[{"from": "body", "name": "server", "regex": "(?P<version>\\d)"}]), "names a header"),
        (lambda t: t.update(match=[{"from": "body", "regex": "<meta[^>]+content"}]), "without a bound"),
        (lambda t: t.update(match=[{"from": "body", "regex": "a.*b"}]), "without a bound"),
        (lambda t: t.update(match=[{"from": "title", "regex": "x{2,}"}]), "without a bound"),
        (lambda t: t.update(match=[{"from": "body", "regex": "(?:a{0,64}){0,128}"}]), "nests repeats"),
        (lambda t: t.update(version=[{"from": "json", "regex": "(?P<version>\\d+)"}]), "without a bound"),
        (lambda t: t.update(match=[{"from": "json", "equals": "{}"}]), "not equals"),
        (lambda t: t.update(match=[{"from": "attr", "contains": "x"}]), "names a tag"),
        (lambda t: t.update(match=[{"from": "attr", "tag": "div", "contains": "x"}]), "presence only"),
        (lambda t: t.update(match=[{"from": "meta", "equals": "x"}]), "names the meta"),
        (lambda t: t.update(match=[{"from": "asset", "tag": "img", "contains": "/x/"}]), "takes no tag"),
    ],
)
def test_schema_refuses_a_broken_entry(mutate, message):
    raw = _raw()
    broken = copy.deepcopy(raw)
    mutate(broken["technologies"][0])
    with pytest.raises(pydantic.ValidationError, match=re.escape(message)):
        Catalogue.model_validate(broken)


def test_schema_refuses_a_duplicate_id():
    raw = _raw()
    raw["technologies"].append(copy.deepcopy(raw["technologies"][0]))
    with pytest.raises(pydantic.ValidationError, match="appears twice"):
        Catalogue.model_validate(raw)


# ---------------------------------------------------------------- fixtures


def test_every_technology_and_every_matcher_is_exercised_by_a_fixture():
    """A matcher no fixture fires is a matcher nobody has seen work."""
    catalogue = load_catalogue()
    by_id = {tech.id: tech for tech in catalogue.technologies}
    unknown = sorted({fx["tech"] for fx in POSITIVES} - set(by_id))
    assert not unknown, f"fixtures for technologies the catalogue does not have: {unknown}"
    silent = []
    for tech in catalogue.technologies:
        mine = [fx for fx in POSITIVES if fx["tech"] == tech.id]
        assert mine, f"{tech.id} has no positive fixture"
        responses = [
            Response.build(fx["status"], httpx.Headers(fx["headers"]), fx["body"], ENDPOINT + fx.get("url", "/"))
            for fx in mine
        ]
        for index, matcher in enumerate(tech.match):
            if not any(matcher.evaluate(resp) is not None for resp in responses):
                silent.append(f"{tech.id}#{index}")
        if tech.version:
            assert any("version" in fx for fx in mine), f"{tech.id} extracts a version no fixture checks"
    assert not silent, f"matchers no fixture fires: {silent}"


@pytest.mark.parametrize("fixture", POSITIVES, ids=lambda fx: fx["tech"])
def test_positive_fixture_identifies_exactly_its_technology(fixture):
    matches = _classify(fixture)
    assert {m.technology.id for m in matches} == {fixture["tech"], *fixture.get("also", [])}
    own = next(m for m in matches if m.technology.id == fixture["tech"])
    assert own.evidence
    if "version" in fixture:
        assert own.version == fixture["version"]
    if "cpe" in fixture:
        assert own.cpe == fixture["cpe"]
    assert own.distro_hint == fixture.get("distro_hint")


@pytest.mark.parametrize("fixture", NEGATIVES, ids=lambda fx: fx["name"])
def test_negative_corpus_identifies_nothing(fixture):
    assert [(m.technology.id, m.evidence) for m in _classify(fixture)] == []


# ---------------------------------------------------------------- behaviour


def test_an_unversioned_banner_yields_no_version_and_a_wildcard_cpe():
    (jenkins,) = load_catalogue().classify(200, httpx.Headers({"X-Jenkins": "unknown"}), "")
    assert jenkins.technology.id == "jenkins"
    assert jenkins.version is None
    assert jenkins.cpe == "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"


def test_a_loose_version_rule_still_cannot_return_something_that_is_not_a_version():
    catalogue = Catalogue.model_validate(
        {
            "schema": 1,
            "updated": "2026-10-06",
            "note": "test",
            "technologies": [
                {
                    "id": "loose",
                    "name": "Loose",
                    "category": "web_server",
                    "match": [{"from": "header", "name": "server"}],
                    "version": [{"from": "header", "name": "server", "regex": "^(?P<version>\\S{1,64})"}],
                }
            ],
        }
    )
    (garbage,) = catalogue.classify(200, httpx.Headers({"Server": "build-<script>"}), "")
    assert garbage.version is None
    (good,) = catalogue.classify(200, httpx.Headers({"Server": "2.4.1"}), "")
    assert good.version == "2.4.1"


def test_version_stays_out_of_the_cpe_where_the_product_numbers_builds():
    (owa,) = load_catalogue().classify(200, httpx.Headers({"X-OWA-Version": "15.1.2507.6"}), "")
    assert owa.version == "15.1.2507.6"
    assert owa.cpe == "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"


def test_a_cookie_value_never_reaches_the_evidence():
    secret = "s3cr3t-session-value"
    headers = httpx.Headers([("Set-Cookie", f"laravel_session={secret}; path=/; httponly")])
    (laravel,) = load_catalogue().classify(200, headers, "")
    assert laravel.evidence == ("cookie laravel_session",)
    assert secret not in json.dumps(laravel.as_dict())


def test_url_evidence_keeps_the_path_and_drops_the_query():
    (owa,) = load_catalogue().classify(200, httpx.Headers(), "", "https://192.0.2.10/owa/auth/logon.aspx?token=abc")
    assert owa.evidence == ('url "/owa/auth/logon.aspx?…"',)


def test_evidence_is_bounded():
    headers = httpx.Headers({"Server": "nginx/1.25.3 " + "x" * 5000})
    (nginx,) = load_catalogue().classify(200, headers, "")
    assert all(len(item) <= 160 for item in nginx.evidence)


@pytest.mark.parametrize(
    "server, expected",
    [
        ("Apache/2.4.57 (Debian)", {"apache_httpd"}),
        ("Apache", {"apache_httpd"}),
        ("Apache-Coyote/1.1", {"apache_tomcat"}),
        ("Apache Tomcat/9.0.83", set()),
        ("nginx/1.24.0 + Phusion Passenger(R) 6.0.18", {"nginx", "phusion_passenger"}),
        ("openresty", {"openresty"}),
        ("nginxproxy", set()),
    ],
)
def test_server_banners_are_anchored(server, expected):
    """A banner names one product at its start; a longer name is another product."""
    found = {m.technology.id for m in load_catalogue().classify(200, httpx.Headers({"Server": server}), "")}
    assert found == expected


def test_confidence_is_the_best_matcher_that_fired():
    catalogue = load_catalogue()
    (weak,) = catalogue.classify(200, httpx.Headers(), "<title>Dashboard [Jenkins]</title>")
    assert weak.confidence == "medium"
    (strong,) = catalogue.classify(200, httpx.Headers({"X-Jenkins": "2.440.1"}), "<title>Dashboard [Jenkins]</title>")
    assert strong.confidence == "high"


def test_title_and_generator_parsing():
    body = (
        '<html><head><TITLE>\n  Sign in &middot;  GitLab \n</TITLE>'
        "<meta content='WordPress 6.5' name=generator><meta name=\"generator\" content=\"Elementor 3.21\">"
    )
    assert page_title(body) == "Sign in · GitLab"
    assert meta_generators(body) == ("WordPress 6.5", "Elementor 3.21")
    assert page_title("<html><title>unterminated") == ""


# ---------------------------------------------------------------- hostile bodies

MIB = 1024 * 1024


@pytest.mark.parametrize(
    "unit",
    [
        "<meta ",
        '<meta name="x" content="',
        "<title>",
        "<script>",
        "<a href='/dana-na/",
        "<x y=1>",
        '"buildinfo":{',
        "<h3>apache tomcat/",
        "a" * 63 + "=",
    ],
    ids=lambda u: u[:16],
)
@pytest.mark.parametrize("content_type", ["text/html", "application/json"])
def test_a_hostile_body_classifies_in_bounded_time(unit, content_type):
    """1 MiB written by the scanned host to cost the classifier (5fe11059: ~1 h for <meta )."""
    body = (unit * (MIB // len(unit) + 1))[:MIB]
    headers = httpx.Headers({"content-type": content_type})
    start = time.perf_counter()
    load_catalogue().classify(404, headers, body, "http://192.0.2.10/")
    assert time.perf_counter() - start < 1.0


def test_a_deadline_stops_classification():
    with pytest.raises(ClassificationTimeout):
        load_catalogue().classify(200, httpx.Headers(), "<html></html>", deadline=time.monotonic() - 1)


def test_the_page_scan_keeps_its_caps():
    assert len(parse_page("<p a=1>" * 10_000).tags) == 2048
    assert len(parse_page("<title>" + "x" * 900 + "</title>").title) == 512


def test_every_generator_is_read_and_the_first_title_wins():
    body = (
        '<html><head><title>Example blog</title><meta name="generator" content="Elementor 3.18">'
        '<meta name="generator" content="WordPress 6.4.2"></head><body><svg><title>icon</title></svg></body></html>'
    )
    (wordpress,) = load_catalogue().classify(200, httpx.Headers(), body)
    assert wordpress.technology.id == "wordpress" and wordpress.version == "6.4.2"
    assert page_title(body) == "Example blog"


def test_assets_read_as_same_origin_paths_or_foreign_hosts():
    body = (
        "<link href='/a.css'><script src='http://192.0.2.10/b.js'></script><img src='//cdn.example/c.png'>"
        "<img src='https://other.example/d;jsessionid=X/e.png?x=1'><form action='login.php'></form>"
        "<a href='/not-an-asset'>x</a>"
    )
    resp = Response.build(200, httpx.Headers(), body, "http://192.0.2.10/portal/index.html")
    assert resp.assets == ("/a.css", "/b.js", "//cdn.example/c.png", "//other.example/d/e.png?x=1", "/portal/login.php")


def test_json_markers_need_a_json_response():
    body = '{"tagline" : "You Know, for Search", "version": {"number": "8.11.1"}}'
    assert load_catalogue().classify(200, httpx.Headers({"content-type": "text/html"}), body) == []
    (es,) = load_catalogue().classify(200, httpx.Headers({"content-type": "application/json; charset=utf-8"}), body)
    assert es.technology.id == "elasticsearch" and es.version == "8.11.1"


@pytest.mark.parametrize(
    "banner, distro",
    [
        ("Apache/2.4.52 (Ubuntu)", "ubuntu"),
        ("nginx/1.22.1", None),
        ("nginx/1.14.1 (Red Hat Enterprise Linux)", "rhel"),
    ],
)
def test_a_distribution_banner_keeps_its_version_out_of_the_cpe(banner, distro):
    (match,) = [m for m in load_catalogue().classify(200, httpx.Headers({"Server": banner}), "") if m.version]
    assert match.distro_hint == distro
    assert (match.version in match.cpe) is (distro is None)
    if distro:
        assert match.as_dict()["banner"] == banner
