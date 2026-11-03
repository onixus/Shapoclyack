"""LDAP/Active Directory authentication with user bind and group search (#317)."""

from __future__ import annotations

import ssl
import urllib.parse
from typing import Any

import ldap3
from ldap3.core.exceptions import LDAPException, LDAPInvalidCredentialsResult
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

from api.services.federated import FederatedIdentity, first_attribute, role_for_groups
from api.settings import ENV_PROD, Settings


class LdapError(Exception):
    pass


class LdapUnavailable(LdapError):
    pass


def is_enabled(settings: Settings) -> bool:
    return bool(settings.ldap_url and settings.ldap_base_dn)


def _server(settings: Settings) -> ldap3.Server:
    parsed = urllib.parse.urlsplit(settings.ldap_url)
    if parsed.scheme not in {"ldap", "ldaps"} or not parsed.hostname:
        raise LdapError("OCTO_LDAP_URL must be an ldap:// or ldaps:// URL")
    if settings.env == ENV_PROD and parsed.scheme != "ldaps" and not settings.ldap_start_tls:
        raise LdapError("LDAP requires ldaps:// or OCTO_LDAP_START_TLS=true in prod")
    if settings.env == ENV_PROD and not settings.ldap_verify_tls:
        raise LdapError("OCTO_LDAP_VERIFY_TLS=false is not allowed in prod")
    tls = ldap3.Tls(
        validate=ssl.CERT_REQUIRED if settings.ldap_verify_tls else ssl.CERT_NONE,
        ca_certs_file=settings.ldap_ca_file or None,
    )
    return ldap3.Server(
        parsed.hostname,
        port=parsed.port or (636 if parsed.scheme == "ldaps" else 389),
        use_ssl=parsed.scheme == "ldaps",
        connect_timeout=settings.ldap_connect_timeout_seconds,
        tls=tls,
    )


def _connect(
    server: ldap3.Server, settings: Settings, *, user: str, password: str
) -> ldap3.Connection:
    connection = ldap3.Connection(
        server,
        user=user or None,
        password=password or None,
        auto_bind=False,
        raise_exceptions=True,
        receive_timeout=settings.ldap_connect_timeout_seconds,
    )
    if settings.ldap_start_tls:
        connection.start_tls()
    connection.bind()
    return connection


def _bind(server: ldap3.Server, settings: Settings, user: str, password: str) -> Any:
    try:
        return _connect(server, settings, user=user, password=password)
    except LDAPInvalidCredentialsResult:
        return None
    except (LDAPException, OSError) as exc:
        raise LdapUnavailable("LDAP directory is unavailable") from exc


def _search(connection: Any, base: str, filter_text: str, attributes: list[str]) -> list[Any]:
    try:
        if not connection.search(base, filter_text, attributes=attributes):
            return []
        return list(connection.entries)
    except (LDAPException, OSError) as exc:
        raise LdapUnavailable("LDAP search failed") from exc


def _one(entries: list[Any], *, what: str) -> Any:
    if len(entries) != 1:
        return None
    return entries[0]


def _groups(connection: Any, settings: Settings, user_dn: str) -> list[str]:
    if not settings.ldap_group_filter or not settings.ldap_group_attribute:
        return []
    filter_text = settings.ldap_group_filter.format(user_dn=escape_filter_chars(user_dn))
    entries = _search(
        connection,
        settings.ldap_group_search_base or settings.ldap_base_dn,
        filter_text,
        [settings.ldap_group_attribute],
    )
    groups: list[str] = []
    for entry in entries:
        values = entry.entry_attributes_as_dict.get(settings.ldap_group_attribute, [])
        groups.extend(value.strip() for value in values if isinstance(value, str) and value.strip())
    return sorted(set(groups))


def authenticate(settings: Settings, username: str, password: str) -> FederatedIdentity | None:
    """Bind as the user, then map directory groups. The password is never stored."""
    username = username.strip()
    if not is_enabled(settings):
        raise LdapError("LDAP authentication is not configured")
    if not username or not password or len(username) > 128:
        return None
    server = _server(settings)
    attributes = [
        attribute
        for attribute in (
            settings.ldap_username_attribute,
            settings.ldap_email_attribute,
            settings.ldap_tenant_attribute,
        )
        if attribute
    ]
    directory = None
    entry = None
    if settings.ldap_user_dn_template:
        user_dn = settings.ldap_user_dn_template.format(username=escape_rdn(username))
    else:
        if bool(settings.ldap_bind_dn) != bool(settings.ldap_bind_password):
            raise LdapError("LDAP bind DN and password must be configured together")
        directory = _bind(
            server, settings, settings.ldap_bind_dn, settings.ldap_bind_password
        )
        if directory is None:
            raise LdapUnavailable("LDAP service bind was refused")
        filter_text = settings.ldap_user_filter.format(username=escape_filter_chars(username))
        try:
            entry = _one(
                _search(directory, settings.ldap_base_dn, filter_text, attributes),
                what="user",
            )
        except LdapUnavailable:
            directory.unbind()
            raise
        if entry is None:
            directory.unbind()
            return None
        user_dn = entry.entry_dn

    user_connection = _bind(server, settings, user_dn, password)
    if user_connection is None:
        if directory is not None:
            directory.unbind()
        return None
    try:
        if entry is None:
            filter_text = settings.ldap_user_filter.format(username=escape_filter_chars(username))
            entry = _one(
                _search(user_connection, settings.ldap_base_dn, filter_text, attributes),
                what="user",
            )
            if entry is None:
                return None
        group_connection = directory or user_connection
        groups = _groups(group_connection, settings, user_dn)
        user_attributes = entry.entry_attributes_as_dict
        directory_username = first_attribute(user_attributes, settings.ldap_username_attribute)
        email = first_attribute(user_attributes, settings.ldap_email_attribute) or None
        tenant_id = first_attribute(user_attributes, settings.ldap_tenant_attribute)
        return FederatedIdentity(
            issuer=f"ldap:{settings.ldap_url}",
            subject=user_dn,
            username=directory_username or username,
            email=email,
            email_verified=bool(email and settings.ldap_email_verified),
            role=role_for_groups(settings.oidc_role_map, groups, settings.ldap_default_role),
            tenant_id=tenant_id or settings.ldap_default_tenant,
            jit_enabled=settings.ldap_jit_provisioning,
            groups=groups,
        )
    finally:
        user_connection.unbind()
        if directory is not None:
            directory.unbind()
