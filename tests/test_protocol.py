from __future__ import annotations

from scanner.pipeline.protocol import (
    TOP_UDP_PORTS,
    endpoint_checkpoint_key,
    format_endpoint,
    naabu_udp_port_spec,
    parse_endpoint,
    top_udp_port_list,
)


def test_parse_endpoint_tcp_with_suffix():
    ep = parse_endpoint("10.0.0.1:80/tcp")
    assert ep is not None
    assert ep.host == "10.0.0.1"
    assert ep.port == "80"
    assert ep.protocol == "tcp"


def test_parse_endpoint_udp_with_suffix():
    ep = parse_endpoint("10.0.0.1:53/udp")
    assert ep is not None
    assert ep.protocol == "udp"


def test_parse_endpoint_defaults_to_tcp():
    ep = parse_endpoint("10.0.0.1:443")
    assert ep is not None
    assert ep.protocol == "tcp"


def test_parse_endpoint_ipv6():
    ep = parse_endpoint("[2001:db8::1]:80/udp")
    assert ep is not None
    assert ep.host == "2001:db8::1"
    assert ep.port == "80"
    assert ep.protocol == "udp"


def test_format_endpoint_ipv6():
    assert format_endpoint("2001:db8::1", "53", "udp") == "[2001:db8::1]:53/udp"


def test_endpoint_checkpoint_key():
    assert endpoint_checkpoint_key("10.0.0.1", "tcp") == "10.0.0.1/tcp"


def test_naabu_udp_port_spec():
    assert naabu_udp_port_spec(["53", "u:123"]) == "u:53,u:123"


def test_top_udp_port_list_respects_count():
    ports = top_udp_port_list(5)
    assert ports == list(TOP_UDP_PORTS[:5])
