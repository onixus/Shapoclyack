from __future__ import annotations

import pytest

from api.services import ldap
from api.settings import Settings


class Entry:
    def __init__(self, dn: str, attributes: dict):
        self.entry_dn = dn
        self.entry_attributes_as_dict = attributes


class Connection:
    def __init__(self, user: str, results: dict[str, list[Entry]]):
        self.user = user
        self.results = results
        self.entries: list[Entry] = []
        self.filters: list[str] = []
        self.closed = False

    def search(self, base, filter_text, attributes=None):
        self.filters.append(filter_text)
        if "member=" in filter_text:
            self.entries = [
                Entry("cn=vm-ops,ou=groups,dc=example,dc=com", {"cn": ["vm-ops"]}),
                Entry("cn=other,ou=groups,dc=example,dc=com", {"cn": ["other"]}),
            ]
        else:
            self.entries = self.results["users"]
        return True

    def unbind(self):
        self.closed = True


def make_settings(**overrides) -> Settings:
    settings = Settings(
        env="dev",
        ldap_url="ldaps://ldap.example.com:636",
        ldap_base_dn="dc=example,dc=com",
        ldap_bind_dn="cn=service,dc=example,dc=com",
        ldap_bind_password="service-password",
        ldap_group_search_base="ou=groups,dc=example,dc=com",
        ldap_tenant_attribute="tenant",
        oidc_role_map={"vm-ops": "operator"},
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


def directory(monkeypatch, settings):
    user_dn = "uid=alice,ou=people,dc=example,dc=com"
    user_entry = Entry(
        user_dn,
        {
            "sAMAccountName": ["alice"],
            "mail": ["alice@example.com"],
            "tenant": ["acme"],
        },
    )
    connections = []

    def connect(_server, _settings, *, user, password):
        connection = Connection(user, {"users": [user_entry]})
        connections.append(connection)
        return connection

    monkeypatch.setattr(ldap, "_connect", connect)
    return connections, user_dn


def test_bind_and_group_search_map_role_tenant_and_identity(monkeypatch):
    settings = make_settings()
    connections, user_dn = directory(monkeypatch, settings)

    identity = ldap.authenticate(settings, "alice", "correct-password")

    assert identity is not None
    assert identity.subject == user_dn
    assert identity.username == "alice"
    assert identity.role == "operator"
    assert identity.tenant_id == "acme"
    assert identity.groups == ["other", "vm-ops"]
    assert identity.issuer == "ldap:ldaps://ldap.example.com:636"
    assert all(connection.closed for connection in connections)


def test_user_and_group_filters_escape_directory_values(monkeypatch):
    settings = make_settings()
    connections, _ = directory(monkeypatch, settings)
    supplied = "alice*)(|(objectClass=*)"

    assert ldap.authenticate(settings, supplied, "correct-password") is not None

    user_filter = connections[0].filters[0]
    group_filter = connections[0].filters[-1]
    assert "\\2a" in user_filter and "\\29" in user_filter
    assert "\\2a" not in group_filter and "\\29" not in group_filter
    assert "uid=alice,ou=people" in group_filter


def test_invalid_user_bind_is_an_authentication_refusal(monkeypatch):
    settings = make_settings()
    _connections, _user_dn = directory(monkeypatch, settings)

    def bind(server, current_settings, user, password):
        if user == current_settings.ldap_bind_dn:
            return ldap._connect(server, current_settings, user=user, password=password)  # noqa: SLF001
        return None

    monkeypatch.setattr(ldap, "_bind", bind)
    assert ldap.authenticate(settings, "alice", "wrong") is None


def test_empty_password_is_never_sent_to_the_directory():
    assert ldap.authenticate(make_settings(), "alice", "") is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"ldap_url": "ldap://ldap.example.com"},
        {"ldap_url": "ldaps://ldap.example.com", "ldap_verify_tls": False},
    ],
)
def test_prod_refuses_unprotected_or_unverified_ldap(overrides):
    settings = make_settings(env="prod", **overrides)
    with pytest.raises(ldap.LdapError):
        ldap._server(settings)  # noqa: SLF001


def test_starttls_is_an_accepted_prod_transport():
    settings = make_settings(
        env="prod", ldap_url="ldap://ldap.example.com", ldap_start_tls=True
    )
    server = ldap._server(settings)  # noqa: SLF001
    assert server.port == 389
