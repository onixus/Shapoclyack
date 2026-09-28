"""The shared outbound-target boundary and its two policies (#151, #240).

``delivery.py`` and ``agent_deployer.py`` now parse and validate targets with
the same code and disagree only about policy. These tests pin that
disagreement, because the failure mode of sharing the module is that one
caller quietly inherits the other's answer: a webhook that may suddenly reach
RFC1918, or a deployment that may no longer reach the private network every
agent lives in.
"""

from __future__ import annotations

import ipaddress

import pytest

from api.services import outbound_targets
from scanner.pipeline import safe_http


def _addresses(*values: str) -> list:
    return [ipaddress.ip_address(value) for value in values]


DEPLOY = outbound_targets.ssh_deploy_policy(allowed_ports=frozenset({22}))
WEBHOOK = outbound_targets.webhook_policy(allow_private=False)


@pytest.mark.parametrize("address", ["10.0.0.5", "192.168.10.50", "172.16.4.4"])
def test_the_deployer_accepts_the_private_space_the_webhook_boundary_refuses(address):
    """The whole reason for two policies rather than one flag.

    An agent lives inside a network the platform cannot otherwise reach, so
    RFC1918 is the ordinary deployment target; for a webhook receiver it is the
    SSRF shape #151 exists to refuse.
    """
    outbound_targets.check_addresses(address, tuple(_addresses(address)), policy=DEPLOY)
    with pytest.raises(outbound_targets.OutboundTargetError, match="non-public"):
        outbound_targets.check_addresses(address, tuple(_addresses(address)), policy=WEBHOOK)


@pytest.mark.parametrize(
    "address,reason",
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("169.254.169.254", "link-local"),
        ("fe80::1", "link-local"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "unspecified"),
        # An IPv4-mapped loopback is 127.0.0.1 wearing a hat, and is judged as
        # the address it is rather than as the notation it arrived in.
        ("::ffff:127.0.0.1", "loopback"),
        # So is a NAT64 well-known address: behind the translator it is the
        # IPv4 address in its low 32 bits, and the refusal says which one.
        pytest.param("64:ff9b::7f00:1", "loopback", id="nat64-wkp-loopback"),
        pytest.param("64:ff9b::a9fe:a9fe", "link-local", id="nat64-wkp-metadata"),
        pytest.param("64:ff9b::e000:1", "multicast", id="nat64-wkp-multicast"),
    ],
)
def test_neither_policy_lets_the_platform_probe_its_own_reflection(address, reason):
    with pytest.raises(outbound_targets.OutboundTargetError, match=reason):
        outbound_targets.check_addresses(address, tuple(_addresses(address)), policy=DEPLOY)


@pytest.mark.parametrize(
    "address",
    [
        pytest.param("64:ff9b::a00:5", id="nat64-wkp-rfc1918"),
        pytest.param("64:ff9b::5db8:d822", id="nat64-wkp-public"),
        pytest.param("64:ff9b:1::a00:5", id="nat64-local-use"),
        pytest.param("::ffff:0:a00:5", id="siit-ipv4-translated"),
        pytest.param("::a00:5", id="ipv4-compatible-rfc1918"),
    ],
)
def test_the_deployer_still_refuses_translated_ipv6_it_refused_before(address):
    """Unwrapping NAT64 for a better refusal must not turn into acceptance.

    The deployer refused every one of these as reserved space before the
    well-known prefix was unwrapped; ``64:ff9b::a00:5`` reads as 10.0.0.5,
    which this policy otherwise accepts.
    """
    with pytest.raises(outbound_targets.OutboundTargetError, match="reserved"):
        outbound_targets.check_addresses(address, tuple(_addresses(address)), policy=DEPLOY)


#: IPv6 addresses that are delivered to an embedded IPv4 address. ``ipaddress``
#: calls the NAT64 well-known, SIIT and IPv4-compatible ones global, so each of
#: those passed the webhook boundary before it judged the IPv4 address behind
#: them. On an API pod whose IPv6-only egress goes through NAT64,
#: ``64:ff9b::a9fe:a9fe`` is the cloud metadata service.
EMBEDDED_IPV4_NON_PUBLIC = [
    pytest.param("64:ff9b::a00:5", id="nat64-wkp-rfc1918"),
    pytest.param("64:ff9b::7f00:1", id="nat64-wkp-loopback"),
    pytest.param("64:ff9b::a9fe:a9fe", id="nat64-wkp-metadata"),
    pytest.param("64:ff9b::6440:1", id="nat64-wkp-cgnat"),
    pytest.param("64:ff9b::e000:1", id="nat64-wkp-multicast"),
    # Local-use NAT64: the embedding depends on the operator's prefix length,
    # so even a tail that reads as 8.8.8.8 is 10.0.0.5 behind a /48.
    pytest.param("64:ff9b:1::808:808", id="nat64-local-use"),
    pytest.param("64:ff9b:1:a00:0:500:808:808", id="nat64-local-use-48"),
    pytest.param("::ffff:0:a00:5", id="siit-ipv4-translated"),
    pytest.param("2002:808:808::1", id="6to4"),
    pytest.param("::a00:5", id="ipv4-compatible-rfc1918"),
    pytest.param("::127.0.0.1", id="ipv4-compatible-loopback"),
    pytest.param("::808:808", id="ipv4-compatible-public"),
    pytest.param("::ffff:10.0.0.5", id="ipv4-mapped-rfc1918"),
]

#: Global addresses the webhook boundary must keep accepting.
PUBLIC = [
    pytest.param("93.184.216.34", id="ipv4"),
    # What DNS64 synthesizes for an IPv4-only receiver on an IPv6-only pod.
    # Refusing the prefix outright would refuse every such receiver, because
    # one failing address fails the whole name.
    pytest.param("64:ff9b::5db8:d822", id="nat64-wkp-public"),
    pytest.param("::ffff:93.184.216.34", id="ipv4-mapped-public"),
    # Only the translation prefixes are unwrapped: ordinary global IPv6 is
    # judged as itself, whatever its low 32 bits happen to spell.
    pytest.param("2606:4700:4700::1111", id="native-ipv6"),
    pytest.param("2606:4700:4700::a00:5", id="native-ipv6-low-bits-rfc1918"),
]


@pytest.mark.parametrize("address", EMBEDDED_IPV4_NON_PUBLIC)
def test_the_webhook_policy_judges_the_ipv4_address_behind_ipv6(address):
    with pytest.raises(outbound_targets.OutboundTargetError, match="non-public"):
        outbound_targets.check_addresses(address, tuple(_addresses(address)), policy=WEBHOOK)


@pytest.mark.parametrize("address", PUBLIC)
def test_the_webhook_policy_accepts_public_ipv4_behind_ipv6(address):
    outbound_targets.check_addresses(address, tuple(_addresses(address)), policy=WEBHOOK)


class _OldStdlibIPv6Address(ipaddress.IPv6Address):
    """An ``ipaddress`` whose special-purpose table calls everything global."""

    @property
    def is_global(self) -> bool:
        return True


@pytest.mark.parametrize(
    "address",
    ["64:ff9b:1::808:808", "2002:a00:5::1", "::a00:5", "::ffff:10.0.0.5", "64:ff9b::a00:5"],
)
def test_the_webhook_verdict_does_not_depend_on_the_stdlib_table(address):
    # Current CPython already refuses local-use NAT64, 6to4 and private
    # IPv4-mapped; Python 3.9 does not, and the boundary must not care.
    assert outbound_targets.is_public_address(_OldStdlibIPv6Address(address)) is False


@pytest.mark.parametrize(
    "address",
    [
        *EMBEDDED_IPV4_NON_PUBLIC,
        *PUBLIC,
        "10.0.0.5",
        "127.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::",
        "64:ff9b::",
        "::ffff:0:0",
    ],
)
def test_the_api_and_scanner_copies_of_the_public_rule_agree(address):
    """Two copies of one rule, because ``scanner/`` cannot import ``api/``.

    A change to what counts as public on one side and not the other is the
    drift this pins. The old-stdlib stand-in compares the explicit lists too:
    the current interpreter would agree with both copies on half of them even
    if one side dropped its list.
    """
    parsed = ipaddress.ip_address(address)
    candidates = [parsed]
    if parsed.version == 6:
        candidates.append(_OldStdlibIPv6Address(address))
    for candidate in candidates:
        assert outbound_targets.is_public_address(candidate) == safe_http.is_public_address(
            candidate
        ), candidate


def test_a_private_deployment_target_on_a_foreign_port_is_still_refused():
    with pytest.raises(outbound_targets.OutboundTargetError, match="5432"):
        outbound_targets.resolve_target("192.168.10.50", 5432, policy=DEPLOY)


def test_the_webhook_policy_keeps_the_open_port_range():
    """A receiver is published wherever its operator published it."""
    target = outbound_targets.parse_url("https://93.184.216.34:8443/hook", policy=WEBHOOK)
    assert (target.port, target.request_target) == (8443, "/hook")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("22,2222", frozenset({22, 2222})),
        ("22", frozenset({22})),
        (" 22 , 2222 ", frozenset({22, 2222})),
        ("*", None),
        ("", None),
    ],
)
def test_parse_ports_reads_the_configured_allowlist(value, expected):
    assert outbound_targets.parse_ports(value) == expected


@pytest.mark.parametrize("value", ["ssh", "0", "70000", "22,nope"])
def test_parse_ports_refuses_a_typo_rather_than_narrowing_silently(value):
    with pytest.raises(ValueError):
        outbound_targets.parse_ports(value)


def test_a_deployment_target_that_does_not_resolve_is_a_refusal(monkeypatch):
    """Unlike a webhook, there is nothing here to retry into."""
    monkeypatch.setattr(outbound_targets, "resolve", lambda host: [])
    with pytest.raises(outbound_targets.OutboundTargetError, match="does not resolve"):
        outbound_targets.resolve_target("agent.internal", 22, policy=DEPLOY)


def test_a_webhook_url_that_does_not_resolve_is_left_for_delivery_to_retry(monkeypatch):
    """Deliberately not a policy violation: a missing record is availability."""
    monkeypatch.setattr(outbound_targets, "resolve", lambda host: [])
    target = outbound_targets.parse_url("https://receiver.example/hook", policy=WEBHOOK)
    assert target.addresses == ()
