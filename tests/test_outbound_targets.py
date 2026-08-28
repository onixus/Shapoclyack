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
    ],
)
def test_neither_policy_lets_the_platform_probe_its_own_reflection(address, reason):
    with pytest.raises(outbound_targets.OutboundTargetError, match=reason):
        outbound_targets.check_addresses(address, tuple(_addresses(address)), policy=DEPLOY)


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
