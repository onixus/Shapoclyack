from __future__ import annotations

from scanner.pipeline.utils import is_fqdn, is_ip_or_cidr


def test_is_ip_or_cidr_accepts_valid_values():
    assert is_ip_or_cidr("10.0.0.0/16")
    assert is_ip_or_cidr("10.0.1.10")
    assert is_ip_or_cidr("2001:db8::1")
    assert is_ip_or_cidr("2001:db8::/32")


def test_is_ip_or_cidr_rejects_invalid_values():
    assert not is_ip_or_cidr("example.com")
    assert not is_ip_or_cidr("10.0.0.256")
    assert not is_ip_or_cidr("not-an-ip")
    assert not is_ip_or_cidr("")


def test_is_fqdn_accepts_valid_domains():
    assert is_fqdn("api.example.com")
    assert is_fqdn("db01.corp.local")
    assert is_fqdn("example.com.")


def test_is_fqdn_rejects_ips_and_garbage():
    assert not is_fqdn("10.0.0.1")
    assert not is_fqdn("2001:db8::1")
    assert not is_fqdn("-bad.example.com")
    assert not is_fqdn("space domain.com")
