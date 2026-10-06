"""The subdomain-takeover catalogue: the shipped file, its schema, its matching.

The catalogue is data other people researched, so what is pinned here is what
this code relies on: that it loads, that every entry says where its status
came from and when, that no two services claim the same name, and that a
fingerprint can never be a bare status code.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from datetime import date

import httpx
import pytest

from scanner.pipeline.takeover import (
    CATALOGUE_PATH,
    CatalogueError,
    Fingerprint,
    load_catalogue,
    parse_catalogue,
)

#: What domain_monitor flagged before the catalogue existed. "s3-website" was
#: a suffix no real name could end with; the S3 entry's pattern covers it.
LEGACY_SUFFIXES = (
    "github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com",
    "azurewebsites.net", "cloudfront.net", "wpengine.com", "unbouncepages.com",
    "readme.io", "surge.sh", "fastly.net", "pantheonsite.io", "zendesk.com",
)


def _raw() -> dict:
    return json.loads(CATALOGUE_PATH.read_text(encoding="utf-8"))


def _service(**overrides: object) -> dict:
    service = {
        "id": "example_host",
        "name": "Example Host",
        "status": "vulnerable",
        "cname": ["example-host.net"],
        "nxdomain_required": False,
        "fingerprints": [{"id": "example_host.missing", "body": ["No such site"]}],
        "source": ["ciotx"],
        "checked": "2026-10-06",
        "note": "",
    }
    service.update(overrides)
    return service


def _document(*services: dict) -> dict:
    return {
        "schema_version": 1,
        "checked": "2026-10-06",
        "sources": {"ciotx": "can-i-take-over-xyz"},
        "services": list(services) or [_service()],
    }


def test_the_shipped_catalogue_loads():
    catalogue = load_catalogue()

    statuses = Counter(service.status for service in catalogue.services)
    assert set(statuses) == {"vulnerable", "edge_case", "not_vulnerable"}
    assert len(catalogue.services) >= 35
    date.fromisoformat(catalogue.checked)


def test_every_entry_names_its_sources_and_the_date_they_were_read():
    raw = _raw()
    for service in raw["services"]:
        assert service["source"], service["id"]
        assert all(source in raw["sources"] for source in service["source"]), service["id"]
        date.fromisoformat(service["checked"])


def test_every_edge_case_says_what_the_condition_is():
    """The note is what a finding's reader acts on; the finding detail quotes it."""
    for service in load_catalogue().services:
        if service.status == "edge_case":
            assert service.note.strip(), service.id


@pytest.mark.parametrize(
    "service_id",
    ["azure_cdn", "azure_other", "azure_cloud_services", "azure_front_door"],
)
def test_entries_the_sources_leave_in_doubt_are_edge_cases(service_id):
    """Each of these notes says the takeover was not verified or is not always possible."""
    service = {s.id: s for s in load_catalogue().services}[service_id]
    assert service.status == "edge_case"


def test_only_region_qualified_beanstalk_names_are_claimed():
    catalogue = load_catalogue()
    assert catalogue.match("env.us-east-1.elasticbeanstalk.com")[0].id == "aws_elastic_beanstalk"
    assert catalogue.match("legacy-env.elasticbeanstalk.com") is None


def test_every_claimable_service_can_be_confirmed_somehow():
    """A claimable service with no way to confirm it could only ever be a
    heuristic finding; that should be a decision in the file, not an accident."""
    for service in load_catalogue().services:
        if not service.claimable:
            continue
        assert service.nxdomain_required or service.fingerprints, service.id


@pytest.mark.parametrize("suffix", LEGACY_SUFFIXES)
def test_every_suffix_the_stage_used_to_flag_has_an_entry(suffix):
    matched = load_catalogue().match(f"something.{suffix}")
    assert matched is not None, suffix


def test_the_services_that_do_not_allow_a_takeover_are_kept_as_such():
    catalogue = load_catalogue()
    for name in (
        "d111.cloudfront.net",
        "x.global.ssl.fastly.net",
        "x.wpengine.com",
        "x.unbouncepages.com",
        "x.zendesk.com",
    ):
        service, _ = catalogue.match(name)
        assert service.status == "not_vulnerable", name


@pytest.mark.parametrize(
    "name",
    [
        "bucket.s3.amazonaws.com",
        "bucket.s3-website-us-east-1.amazonaws.com",
        "bucket.s3-website.eu-central-1.amazonaws.com",
        "bucket.s3.us-east-2.amazonaws.com",
        "bucket.s3-us-west-2.amazonaws.com",
        "bucket.s3.dualstack.us-east-1.amazonaws.com",
    ],
)
def test_s3_endpoints_in_every_spelling_match(name):
    service, _ = load_catalogue().match(name)
    assert service.id == "aws_s3"


@pytest.mark.parametrize(
    "name",
    [
        "pages.evilgithub.io",  # not a label boundary
        "github.io.example.com",  # the suffix in the middle
        "bucket.s3.amazonaws.com.example.net",  # the S3 pattern in the middle
        "",
    ],
)
def test_a_suffix_matches_at_the_end_and_at_a_label_boundary_only(name):
    assert load_catalogue().match(name) is None


def test_matching_ignores_case_and_a_trailing_dot():
    service, suffix = load_catalogue().match("Org.GitHub.IO.")
    assert (service.id, suffix) == ("github_pages", "github.io")


def test_load_refuses_a_file_that_is_not_json(tmp_path):
    broken = tmp_path / "catalogue.json"
    broken.write_text("{", encoding="utf-8")

    with pytest.raises(CatalogueError, match="unreadable"):
        load_catalogue.__wrapped__(broken)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(schema_version=2), "schema_version"),
        (lambda d: d.update(checked="06.10.2026"), "YYYY-MM-DD"),
        (lambda d: d["services"][0].update(status="maybe"), "status must be one of"),
        (lambda d: d["services"][0].update(cname=[".example-host.net"]), "leading dot"),
        (lambda d: d["services"][0].update(cname=["Example-Host.net"]), "lower-case"),
        (lambda d: d["services"][0].update(cname=[], cname_regex=[]), "at least one cname"),
        (lambda d: d["services"][0].update(cname_regex=["\\.example(\\.net$"]), "does not compile"),
        (lambda d: d["services"][0].update(cname_regex=["\\.example\\.net"]), "anchored"),
        (lambda d: d["services"][0].update(source=["nobody"]), "is not listed"),
        (lambda d: d["services"][0].update(source=[]), "must not be empty"),
        (lambda d: d["services"][0].pop("checked"), "missing key"),
        (lambda d: d["services"][0].update(colour="blue"), "unknown key"),
        (lambda d: d["services"][0].update(nxdomain_required="yes"), "true or false"),
        (
            lambda d: d["services"][0].update(fingerprints=[{"id": "example_host.any_404", "status": [404]}]),
            "not a status code alone",
        ),
        (
            lambda d: d["services"][0].update(fingerprints=[{"id": "other.missing", "body": ["x"]}]),
            "must start with 'example_host.'",
        ),
        (lambda d: d["services"][0].update(nxdomain_required=True), "carries no HTTP fingerprints"),
        (lambda d: d["services"][0].update(status="not_vulnerable"), "never probed"),
        (lambda d: d["services"].append(copy.deepcopy(d["services"][0])), "duplicate id"),
        (
            lambda d: d["services"].append(
                _service(id="nested_host", cname=["eu.example-host.net"], fingerprints=[])
                | {"status": "not_vulnerable"}
            ),
            "overlaps",
        ),
        # The same nesting the other way round: the wider suffix comes second.
        (
            lambda d: d["services"].insert(
                0,
                _service(id="nested_host", cname=["eu.example-host.net"], fingerprints=[])
                | {"status": "not_vulnerable"},
            ),
            "overlaps",
        ),
        (lambda d: d["services"][0].update(status="edge_case", note=""), "needs a note"),
        (lambda d: d["services"][0].update(status="edge_case", note="   "), "needs a note"),
    ],
)
def test_the_schema_refuses(mutate, message):
    document = _document()
    mutate(document)

    with pytest.raises(CatalogueError, match=message):
        parse_catalogue(document)


def test_the_minimal_document_used_above_is_itself_valid():
    """Otherwise every refusal above could be refusing for the wrong reason."""
    catalogue = parse_catalogue(_document())
    assert catalogue.match("site.example-host.net")[0].id == "example_host"


def _headers(**values: str) -> httpx.Headers:
    return httpx.Headers(values)


def test_a_fingerprint_needs_every_part_it_names():
    fingerprint = Fingerprint(
        "surge.project_not_found", body=("project not found",), header=("server: surge",), status=(404,)
    )
    body = "<h1>project not found</h1>"
    server = _headers(Server="Surge")

    assert fingerprint.matches(404, server, body)
    assert not fingerprint.matches(200, server, body)
    assert not fingerprint.matches(404, _headers(Server="nginx"), body)
    assert not fingerprint.matches(404, server, "<h1>Welcome</h1>")


def test_every_body_marker_must_be_present():
    fingerprint = Fingerprint(
        "strikingly.build_your_own",
        body=("But if you're looking to build your own website", "you've come to the right place."),
    )
    both = "But if you're looking to build your own website, you've come to the right place."

    assert fingerprint.matches(200, _headers(), both)
    assert not fingerprint.matches(200, _headers(), "But if you're looking to build your own website")


def test_body_markers_are_case_sensitive_and_header_markers_are_not():
    body_marker = Fingerprint("github_pages.no_site", body=("There isn't a GitHub Pages site here.",))
    assert not body_marker.matches(404, _headers(), "there isn't a github pages site here.")

    header_marker = Fingerprint("ghost.error_redirect", header=("error.ghost.org",), status=(302,))
    assert header_marker.matches(302, _headers(Location="https://Error.Ghost.org/x"), "")
