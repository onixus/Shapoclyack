from __future__ import annotations

import pytest

from scanner.pipeline.cert_names import (
    cert_names,
    expected_names,
    hostname_mismatch,
    matches_name,
)


class TestCertNames:
    def test_nmap_shape_dn_subject_and_typed_san(self):
        names = cert_names(
            {
                "subject": "commonName=example.com/organizationName=Example",
                "san": "DNS:example.com, DNS:www.example.com, IP Address:10.0.0.1",
            }
        )
        assert names["dns"] == ["example.com", "www.example.com"]
        assert names["ip"] == ["10.0.0.1"]
        assert names["common_name"] == ["example.com"]

    def test_pulse_shape_bare_cn_and_list_san(self):
        names = cert_names(
            {"subject_cn": "api.example.com", "san": ["api.example.com", "*.example.com"]}
        )
        assert names["dns"] == ["api.example.com", "*.example.com"]

    def test_trailing_dot_and_case_normalized(self):
        names = cert_names({"subject_cn": "API.Example.COM.", "san": "DNS:WWW.Example.com."})
        assert names["dns"] == ["api.example.com", "www.example.com"]

    def test_cn_holding_a_literal_ip_is_an_ip_identity(self):
        names = cert_names({"subject_cn": "10.0.0.7"})
        assert names["dns"] == []
        assert names["ip"] == ["10.0.0.7"]

    def test_unknown_san_types_are_ignored(self):
        names = cert_names({"subject_cn": "a.example.com", "san": "email:ops@example.com"})
        assert names["dns"] == ["a.example.com"]

    def test_no_cert_yields_empty(self):
        assert cert_names(None) == {"dns": [], "ip": [], "common_name": []}


class TestMatchesName:
    @pytest.mark.parametrize(
        "cert_name,hostname",
        [
            ("example.com", "example.com"),
            ("Example.COM", "example.com."),
            ("*.example.com", "www.example.com"),
        ],
    )
    def test_matches(self, cert_name: str, hostname: str):
        assert matches_name(cert_name, hostname)

    @pytest.mark.parametrize(
        "cert_name,hostname",
        [
            # A wildcard covers exactly one label, and not the bare domain.
            ("*.example.com", "example.com"),
            ("*.example.com", "a.b.example.com"),
            # Partial-label wildcards are refused by modern clients.
            ("www*.example.com", "www1.example.com"),
            # A wildcard must not stand in for a public-suffix-level label.
            ("*.com", "example.com"),
            ("other.example.com", "www.example.com"),
            ("", "example.com"),
            ("example.com", ""),
        ],
    )
    def test_does_not_match(self, cert_name: str, hostname: str):
        assert not matches_name(cert_name, hostname)


class TestExpectedNames:
    def test_forward_names_only_ptr_excluded(self):
        entry = {
            "forward": ["shop.example.com"],
            "reverse": ["ec2-1-2-3-4.compute.amazonaws.com"],
            "names": ["shop.example.com", "ec2-1-2-3-4.compute.amazonaws.com"],
        }
        assert expected_names(entry) == ["shop.example.com"]

    def test_ip_literals_and_blanks_dropped(self):
        assert expected_names({"forward": ["10.0.0.1", "", "a.example.com"]}) == [
            "a.example.com"
        ]

    def test_missing_entry(self):
        assert expected_names(None) == []
        assert expected_names({}) == []


class TestHostnameMismatch:
    def test_mismatch_reported(self):
        issue = hostname_mismatch(
            {"subject_cn": "other.example.net", "san": "DNS:other.example.net"},
            ["shop.example.com"],
        )
        assert issue is not None
        assert issue["kind"] == "cert_name_mismatch"
        assert issue["severity"] == "medium"
        assert issue["checked_names"] == ["shop.example.com"]
        assert issue["cert_names"] == ["other.example.net"]

    def test_wildcard_san_covers_the_expected_name(self):
        assert (
            hostname_mismatch(
                {"subject_cn": "example.com", "san": "DNS:example.com, DNS:*.example.com"},
                ["shop.example.com"],
            )
            is None
        )

    def test_one_matching_name_out_of_several_is_not_a_mismatch(self):
        assert (
            hostname_mismatch(
                {"subject_cn": "shop.example.com", "san": "DNS:shop.example.com"},
                ["shop.example.com", "legacy.example.org"],
            )
            is None
        )

    def test_no_expected_name_yields_no_finding(self):
        assert hostname_mismatch({"subject_cn": "other.example.net"}, []) is None

    def test_certificate_without_dns_identity_yields_no_finding(self):
        # A parse miss (or an IP-only certificate) must not read as a mismatch.
        assert hostname_mismatch({"subject_cn": "10.0.0.7"}, ["shop.example.com"]) is None
        assert hostname_mismatch(None, ["shop.example.com"]) is None

    def test_cn_only_certificate_is_flagged_as_such(self):
        issue = hostname_mismatch({"subject_cn": "other.example.net"}, ["shop.example.com"])
        assert issue is not None
        assert issue["cn_only"] is True

        with_san = hostname_mismatch(
            {"subject_cn": "other.example.net", "san": "DNS:alt.example.net"},
            ["shop.example.com"],
        )
        assert with_san is not None
        assert with_san["cn_only"] is False
