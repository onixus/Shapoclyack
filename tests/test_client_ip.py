"""Which address a request is attributed to (#157).

Pure function, no database — the trusted-proxy rules are where the limiter's
key is decided, so they are worth testing apart from the endpoint that uses
them.
"""

from __future__ import annotations

from api.core.client_ip import MAX_FORWARDED_HOPS, parse_trusted_proxies, resolve_client_ip


def test_forwarded_header_is_ignored_without_a_trusted_proxy():
    """The default configuration. A client that sends the header would
    otherwise pick its own rate-limit key, one attempt per invented value."""
    assert resolve_client_ip("203.0.113.7", "10.9.9.9", []) == "203.0.113.7"


def test_forwarded_header_is_ignored_when_the_peer_is_not_trusted():
    trusted = parse_trusted_proxies("10.0.0.0/8")
    assert resolve_client_ip("203.0.113.7", "198.51.100.4", trusted) == "203.0.113.7"


def test_rightmost_untrusted_hop_wins_behind_a_trusted_proxy():
    trusted = parse_trusted_proxies("10.0.0.0/8")
    # The client wrote "1.1.1.1"; the two rightmost entries were appended by
    # the proxies. Only the rightmost untrusted one is vouched for.
    resolved = resolve_client_ip("10.0.0.1", "1.1.1.1, 198.51.100.4, 10.0.0.2", trusted)
    assert resolved == "198.51.100.4"


def test_bare_address_is_accepted_as_a_single_host_network():
    trusted = parse_trusted_proxies("10.0.0.1")
    assert resolve_client_ip("10.0.0.1", "198.51.100.4", trusted) == "198.51.100.4"
    assert resolve_client_ip("10.0.0.2", "198.51.100.4", trusted) == "10.0.0.2"


def test_appended_source_port_is_stripped():
    trusted = parse_trusted_proxies("10.0.0.0/8")
    assert resolve_client_ip("10.0.0.1", "198.51.100.4:41234", trusted) == "198.51.100.4"
    assert resolve_client_ip("10.0.0.1", "[2001:db8::1]:443", trusted) == "2001:db8::1"


def test_unparsable_hop_ends_the_walk_at_the_proxy():
    """A garbage entry is where the vouched-for part of the chain stops;
    stepping past it would land on values the client wrote itself."""
    trusted = parse_trusted_proxies("10.0.0.0/8")
    assert resolve_client_ip("10.0.0.1", "198.51.100.4, not-an-ip", trusted) == "10.0.0.1"


def test_all_hops_trusted_falls_back_to_the_peer():
    trusted = parse_trusted_proxies("10.0.0.0/8")
    assert resolve_client_ip("10.0.0.1", "10.0.0.2, 10.0.0.3", trusted) == "10.0.0.1"


def test_long_chain_is_not_walked_past_the_cap():
    """A client can send thousands of hops; parsing is bounded."""
    trusted = parse_trusted_proxies("10.0.0.0/8")
    chain = ", ".join(["198.51.100.4"] * 5 + ["10.0.0.9"] * (MAX_FORWARDED_HOPS + 10))
    assert resolve_client_ip("10.0.0.1", chain, trusted) == "10.0.0.1"


def test_unparsable_trusted_entry_is_dropped_not_fatal():
    """A typo in OCTO_TRUSTED_PROXIES makes the limiter stricter (one fewer
    trusted hop), never looser, and must not take the API down."""
    assert parse_trusted_proxies("10.0.0.0/8, nonsense, ") == parse_trusted_proxies("10.0.0.0/8")


def test_missing_peer_is_one_key_rather_than_no_key():
    assert resolve_client_ip(None, None, []) == "unknown"
