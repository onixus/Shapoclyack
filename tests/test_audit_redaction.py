"""Redaction of the audit trail's before/after documents (#327).

Separate from ``tests/test_api_audit.py`` because it needs no database: this is
the pure half of the rule that keeps credentials out of a table every tenant
admin can read, and it should be runnable — and reviewable — on its own.
"""

from __future__ import annotations

import pytest

from api.services import audit as audit_service


@pytest.mark.parametrize(
    "field",
    ["password", "password_hash", "token", "key", "client_secret", "webhook_secret", "api_key"],
)
def test_redact_replaces_every_credential_shaped_field(field):
    assert audit_service.redact({field: "s3cret"})[field] == audit_service.REDACTED


def test_redact_walks_nested_documents_and_keeps_everything_else():
    payload = {
        "name": "ci",
        "entries": [{"value": "10.0.0.0/8", "secret": "s3cret"}],
        "nested": {"deep": {"nvd_api_key": "s3cret"}},
    }
    cleaned = audit_service.redact(payload)
    assert cleaned["name"] == "ci"
    assert cleaned["entries"][0]["value"] == "10.0.0.0/8"
    assert cleaned["entries"][0]["secret"] == audit_service.REDACTED
    assert cleaned["nested"]["deep"]["nvd_api_key"] == audit_service.REDACTED
