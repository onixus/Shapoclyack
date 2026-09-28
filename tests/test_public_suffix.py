"""Public Suffix List matcher over the bundled snapshot."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.pipeline import public_suffix
from scanner.pipeline.public_suffix import is_public_suffix, registrable_domain

# The upstream conformance vectors, tests/test_psl.txt in
# https://github.com/publicsuffix/list (CC0), as (input, registrable domain).
# They run against the real snapshot, so they also catch a snapshot that lost
# the rules they rely on.
PSL_VECTORS: list[tuple[str, str | None]] = [
    ("COM", None),
    ("example.COM", "example.com"),
    ("WwW.example.COM", "example.com"),
    (".com", None),
    (".example", None),
    (".example.com", None),
    (".example.example", None),
    ("example", None),
    ("example.example", "example.example"),
    ("b.example.example", "example.example"),
    ("a.b.example.example", "example.example"),
    ("biz", None),
    ("domain.biz", "domain.biz"),
    ("b.domain.biz", "domain.biz"),
    ("a.b.domain.biz", "domain.biz"),
    ("com", None),
    ("example.com", "example.com"),
    ("b.example.com", "example.com"),
    ("a.b.example.com", "example.com"),
    ("uk.com", None),
    ("example.uk.com", "example.uk.com"),
    ("b.example.uk.com", "example.uk.com"),
    ("a.b.example.uk.com", "example.uk.com"),
    ("test.ac", "test.ac"),
    ("mm", None),
    ("c.mm", None),
    ("b.c.mm", "b.c.mm"),
    ("a.b.c.mm", "b.c.mm"),
    ("jp", None),
    ("test.jp", "test.jp"),
    ("www.test.jp", "test.jp"),
    ("ac.jp", None),
    ("test.ac.jp", "test.ac.jp"),
    ("www.test.ac.jp", "test.ac.jp"),
    ("kyoto.jp", None),
    ("test.kyoto.jp", "test.kyoto.jp"),
    ("ide.kyoto.jp", None),
    ("b.ide.kyoto.jp", "b.ide.kyoto.jp"),
    ("a.b.ide.kyoto.jp", "b.ide.kyoto.jp"),
    ("c.kobe.jp", None),
    ("b.c.kobe.jp", "b.c.kobe.jp"),
    ("a.b.c.kobe.jp", "b.c.kobe.jp"),
    ("city.kobe.jp", "city.kobe.jp"),
    ("www.city.kobe.jp", "city.kobe.jp"),
    ("ck", None),
    ("test.ck", None),
    ("b.test.ck", "b.test.ck"),
    ("a.b.test.ck", "b.test.ck"),
    ("www.ck", "www.ck"),
    ("www.www.ck", "www.ck"),
    ("us", None),
    ("test.us", "test.us"),
    ("www.test.us", "test.us"),
    ("ak.us", None),
    ("test.ak.us", "test.ak.us"),
    ("www.test.ak.us", "test.ak.us"),
    ("k12.ak.us", None),
    ("test.k12.ak.us", "test.k12.ak.us"),
    ("www.test.k12.ak.us", "test.k12.ak.us"),
    ("食狮.com.cn", "食狮.com.cn"),
    ("食狮.公司.cn", "食狮.公司.cn"),
    ("www.食狮.公司.cn", "食狮.公司.cn"),
    ("shishi.公司.cn", "shishi.公司.cn"),
    ("公司.cn", None),
    ("食狮.中国", "食狮.中国"),
    ("www.食狮.中国", "食狮.中国"),
    ("shishi.中国", "shishi.中国"),
    ("中国", None),
    ("xn--85x722f.com.cn", "xn--85x722f.com.cn"),
    ("xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
    ("www.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
    ("shishi.xn--55qx5d.cn", "shishi.xn--55qx5d.cn"),
    ("xn--55qx5d.cn", None),
    ("xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"),
    ("www.xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"),
    ("shishi.xn--fiqs8s", "shishi.xn--fiqs8s"),
    ("xn--fiqs8s", None),
]


@pytest.mark.parametrize(("name", "expected"), PSL_VECTORS)
def test_upstream_conformance_vectors(name: str, expected: str | None):
    assert (registrable_domain(name) or None) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        # The cases that motivated the list: one ICANN, two private section.
        ("www.bbc.co.uk", "bbc.co.uk"),
        ("shop.example.com.ru", "example.com.ru"),
        ("x.github.io", "x.github.io"),
        ("a.b.example.com", "example.com"),
        # Trailing dot and case, as they arrive from dnsx and CT.
        ("WWW.Example.COM.", "example.com"),
    ],
)
def test_registrable_domain(name: str, expected: str):
    assert registrable_domain(name) == expected


@pytest.mark.parametrize("name", ["co.uk", "com.ru", "github.io", "uk", "com", "test.ck"])
def test_public_suffixes_are_recognised(name: str):
    assert is_public_suffix(name) is True
    assert registrable_domain(name) == ""


@pytest.mark.parametrize("name", ["bbc.co.uk", "x.github.io", "example.com", "www.ck"])
def test_registrable_domains_are_not_suffixes(name: str):
    assert is_public_suffix(name) is False


@pytest.mark.parametrize(
    "name",
    ["", "   ", "1.2.3.4", "2001:db8::1", "*.example.com", "a..example.com", "http://x.example.com"],
)
def test_non_host_names_have_no_registrable_domain(name: str):
    # An IP literal used to come out of "last two labels" as "3.4".
    assert registrable_domain(name) == ""
    assert is_public_suffix(name) is False


def test_snapshot_is_complete():
    snapshot = public_suffix._snapshot()
    assert snapshot.version, "the VERSION header names the snapshot in dns_hygiene.json"
    # Both sections made it: co.uk is ICANN, github.io and com.ru are private.
    assert {"co.uk", "github.io", "com.ru"} <= snapshot.rules
    assert "ck" in snapshot.wildcards
    assert "www.ck" in snapshot.exceptions
    assert len(snapshot.rules) > 5_000


def test_truncated_snapshot_is_refused(tmp_path: Path, monkeypatch):
    # Cut before the private section ends: github.io would silently become a
    # registrable domain again, so loading must fail instead.
    full = public_suffix.PSL_PATH.read_text(encoding="utf-8")
    truncated = tmp_path / "public_suffix_list.dat"
    truncated.write_text(full.split("===END PRIVATE DOMAINS===")[0], encoding="utf-8")
    monkeypatch.setattr(public_suffix, "PSL_PATH", truncated)
    public_suffix._snapshot.cache_clear()
    try:
        with pytest.raises(ValueError, match="incomplete"):
            registrable_domain("x.github.io")
    finally:
        public_suffix._snapshot.cache_clear()
