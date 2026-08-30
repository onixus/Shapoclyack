"""Service-token scope algebra and token format (Track E).

The storage half is exercised in tests/test_api_service_tokens.py, which needs
Postgres. Everything here is pure and always runs, because the scope check is
the part that decides what a machine credential may reach.
"""

from __future__ import annotations

import pytest

from api.services import service_tokens


def principal(*scopes: str, role: str = "operator") -> service_tokens.ServiceTokenPrincipal:
    return service_tokens.ServiceTokenPrincipal(
        token_id="st_1", tenant_id="acme", name="ci", role=role, scopes=tuple(scopes)
    )


# --------------------------------------------------------------------------- #
# Scope parsing
# --------------------------------------------------------------------------- #


def test_scopes_are_sorted_and_deduplicated():
    assert service_tokens.normalise_scopes(["runs:read", "assets:read", "runs:read"]) == (
        "assets:read runs:read"
    )


def test_an_empty_scope_list_is_refused_rather_than_read_as_everything():
    for value in ([], None, ["   "]):
        with pytest.raises(ValueError, match="at least one scope"):
            service_tokens.normalise_scopes(value)


def test_malformed_scopes_are_refused():
    for bad in ["runs", "runs:delete", ":read", "runs:read extra", "RUNS:*:read"]:
        with pytest.raises(ValueError):
            service_tokens.normalise_scopes([bad])


def test_wildcards_are_accepted_in_either_half():
    assert service_tokens.normalise_scopes(["*"]) == "*"
    assert service_tokens.normalise_scopes(["runs:*", "*:read"]) == "*:read runs:*"


# --------------------------------------------------------------------------- #
# Request -> (resource, action)
# --------------------------------------------------------------------------- #


def test_resource_is_the_first_segment_under_api():
    assert service_tokens.resource_for_path("/api/runs/abc/hosts") == "runs"
    assert service_tokens.resource_for_path("/api/vulnerabilities") == "vulnerabilities"
    assert service_tokens.resource_for_path("/api") == ""


def test_only_the_safe_methods_count_as_reads():
    assert service_tokens.action_for_method("GET") == "read"
    assert service_tokens.action_for_method("head") == "read"
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert service_tokens.action_for_method(method) == "write"


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def test_a_read_scope_does_not_admit_a_write():
    token = principal("runs:read")
    assert token.allows(resource="runs", action="read")
    assert not token.allows(resource="runs", action="write")


def test_a_scope_admits_nothing_outside_its_resource():
    token = principal("runs:*")
    assert token.allows(resource="runs", action="write")
    assert not token.allows(resource="assets", action="read")


def test_resource_wildcard_admits_only_the_named_action():
    token = principal("*:read")
    assert token.allows(resource="assets", action="read")
    assert not token.allows(resource="assets", action="write")


def test_full_wildcard_admits_everything_the_role_allows():
    token = principal("*")
    assert token.allows(resource="jobs", action="write")


def test_identity_administration_is_closed_to_every_token():
    """Not even ``*``: a token that can mint users or further tokens is a token
    that outlives its own revocation."""
    token = principal("*", role="admin")
    for resource in sorted(service_tokens.FORBIDDEN_RESOURCES):
        assert not token.allows(resource=resource, action="read")
        assert not token.allows(resource=resource, action="write")


def test_an_unknown_resource_matches_nothing():
    assert not principal("runs:read").allows(resource="", action="read")


# --------------------------------------------------------------------------- #
# Token format
# --------------------------------------------------------------------------- #


def test_issued_tokens_carry_an_identifiable_prefix():
    plaintext, prefix = service_tokens._new_token()  # noqa: SLF001 - format is the contract
    assert plaintext.startswith(f"{service_tokens.TOKEN_SCHEME}_")
    assert plaintext.startswith(prefix + "_")
    assert service_tokens.looks_like_service_token(plaintext)


def test_a_console_jwt_is_never_mistaken_for_a_service_token():
    for candidate in [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig",
        "octo-pk-something",
        "octo_st_short_x",
        "",
    ]:
        assert not service_tokens.looks_like_service_token(candidate)


def test_two_issued_tokens_never_share_a_prefix():
    prefixes = {service_tokens._new_token()[1] for _ in range(50)}  # noqa: SLF001
    assert len(prefixes) == 50
