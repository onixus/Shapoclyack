"""CA ownership, tenant boundaries and real TLS enforcement of exported CRLs."""

from __future__ import annotations

import http.client
import ssl
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from api import agent_crl as publisher
from api.services import agent_crl
from api.settings import Settings
from tests.mtls_pki import CA
from tests.conftest import requires_postgres
from tests.test_agent_mtls import _TLSServer


def record(issued, *, tenant="default", agent="sensor-a", source="observed", **changes):
    row = SimpleNamespace(
        tenant_id=tenant,
        agent_id=agent,
        source=source,
        fingerprint_sha256=issued.fingerprint,
        certificate_pem=issued.pem,
        not_after=issued.cert.not_valid_after_utc.replace(tzinfo=None),
        revoked_at=datetime.now(UTC).replace(tzinfo=None),
    )
    row.__dict__.update(changes)
    return row


def exporter(tmp_path, monkeypatch, ca, rows):
    cert, key = ca.write(tmp_path, "issuer")
    settings = Settings(
        agent_mtls_issuer_cert=str(cert), agent_mtls_issuer_key=str(key)
    )

    @contextmanager
    def session(_url):
        yield SimpleNamespace(
            execute=lambda _query: SimpleNamespace(scalars=lambda: rows)
        )

    monkeypatch.setattr(agent_crl, "get_session", session)
    return settings


def test_signed_crl_contains_only_owned_certificates_from_its_issuer(
    tmp_path, monkeypatch
):
    ca = CA()
    ours = ca.sensor("default", "sensor-a")
    other_tenant = ca.sensor("other", "sensor-b")
    another_ca = CA().sensor("default", "sensor-a")
    # A tenant may know anybody's public certificate, but neither a tombstone
    # nor a pin of a foreign identity must turn it into a global TLS ban.
    rows = [
        record(ours),
        record(other_tenant, tenant="other", agent="sensor-b"),
        record(another_ca),
        record(other_tenant, source="pinned"),
        record(other_tenant, source="tombstone"),
    ]
    result = agent_crl.export(exporter(tmp_path, monkeypatch, ca, rows))
    crl = x509.load_pem_x509_crl(result.pem)
    assert crl.is_signature_valid(ca.key.public_key())
    assert {entry.serial_number for entry in crl} == {
        ours.cert.serial_number,
        other_tenant.cert.serial_number,
    }
    assert (result.entries, result.api_only, result.other_issuer) == (2, 2, 1)
    assert crl.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    ).value.key_identifier
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number > 0


def test_legacy_missing_pem_is_not_guessed_and_operator_can_supply_it(
    tmp_path, monkeypatch
):
    ca = CA()
    cert = ca.sensor("default", "sensor-a")
    settings = exporter(
        tmp_path, monkeypatch, ca, [record(cert, certificate_pem="", source="csr")]
    )
    with pytest.raises(ValueError, match="issuer cannot be guessed"):
        agent_crl.export(settings)
    result = agent_crl.export(settings, certificates=[cert.cert])
    assert result.entries == 1


def test_tombstone_is_api_only_until_platform_operator_approves_exact_pem(
    tmp_path, monkeypatch
):
    ca = CA()
    cert = ca.sensor("other", "sensor-b")
    settings = exporter(
        tmp_path,
        monkeypatch,
        ca,
        [record(cert, source="tombstone", certificate_pem="")],
    )
    result = agent_crl.export(settings)
    assert (result.entries, result.api_only) == (0, 1)
    assert agent_crl.export(settings, certificates=[cert.cert]).entries == 1


def test_expired_records_are_pruned_and_duplicate_serials_keep_earliest_revocation(
    tmp_path, monkeypatch
):
    ca = CA()
    cert = ca.sensor("default", "sensor-a")
    now = datetime.now(UTC)
    expired = ca.sensor("default", "sensor-a", not_after=now - timedelta(seconds=1))
    rows = [
        record(cert),
        record(cert, revoked_at=(now - timedelta(minutes=2)).replace(tzinfo=None)),
        record(expired),
        record(expired, certificate_pem=""),
    ]
    result = agent_crl.export(exporter(tmp_path, monkeypatch, ca, rows), now=now)
    crl = x509.load_pem_x509_crl(result.pem)
    assert len(crl) == 1
    assert crl[0].revocation_date_utc == (now - timedelta(minutes=2)).replace(
        microsecond=0
    )


@pytest.mark.parametrize("lifetime", [0, 59, 86401])
def test_crl_lifetime_is_bounded(tmp_path, monkeypatch, lifetime):
    ca = CA()
    with pytest.raises(ValueError, match="lifetime"):
        agent_crl.export(
            exporter(tmp_path, monkeypatch, ca, []), lifetime_seconds=lifetime
        )


def test_wrong_private_key_and_corrupt_material_fail_export(tmp_path, monkeypatch):
    ca = CA()
    cert = ca.sensor("default", "sensor-a")
    row = record(cert, fingerprint_sha256="a" * 64)
    settings = exporter(tmp_path, monkeypatch, ca, [row])
    with pytest.raises(ValueError, match="fingerprint"):
        agent_crl.export(settings)
    _, wrong_key = CA().write(tmp_path, "wrong")
    settings.agent_mtls_issuer_key = str(wrong_key)
    with pytest.raises(ValueError, match="do not match"):
        agent_crl.export(settings)


def test_ca_without_crl_sign_is_refused(tmp_path, monkeypatch):
    ca = CA()
    usage = x509.KeyUsage(True, False, False, False, False, True, False, False, False)
    ca.cert = (
        x509.CertificateBuilder()
        .subject_name(ca.cert.subject)
        .issuer_name(ca.cert.subject)
        .public_key(ca.key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(usage, True)
        .sign(ca.key, hashes.SHA256())
    )
    with pytest.raises(ValueError, match="cRLSign"):
        agent_crl.export(exporter(tmp_path, monkeypatch, ca, []))


def test_export_is_restricted_to_platform_tool_not_a_tenant_http_route():
    from api.routes.agent_certificates import router

    assert not any("crl" in route.path for route in router.routes)


def test_atomic_writer_keeps_previous_crl_if_replace_fails(tmp_path, monkeypatch):
    path = tmp_path / "ca.crl"
    path.write_bytes(b"previous")

    def fail(*args):
        raise OSError("publication failed")

    monkeypatch.setattr(publisher.os, "replace", fail)
    with pytest.raises(OSError):
        publisher.write_atomic(path, b"replacement")
    assert path.read_bytes() == b"previous"
    assert list(tmp_path.iterdir()) == [path]


def test_kubernetes_publisher_patches_only_crl_and_does_not_read_secret(
    tmp_path, monkeypatch
):
    account = tmp_path / "serviceaccount"
    account.mkdir()
    (account / "token").write_text("test-only-token")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
    original = publisher.Path
    monkeypatch.setattr(
        publisher,
        "Path",
        lambda value: account if value.startswith("/var/run/") else original(value),
    )
    monkeypatch.setattr(
        publisher.ssl,
        "create_default_context",
        lambda **kwargs: "verified-kubernetes-tls",
    )
    seen = []

    @contextmanager
    def send(request, **kwargs):
        seen.append((request, kwargs))
        yield SimpleNamespace(status=200)

    monkeypatch.setattr(publisher, "urlopen", send)
    publisher.publish_secret("test", "sensor-crl", b"signed-crl")
    import base64
    import json

    request, options = seen[0]
    assert request.method == "PATCH"
    assert request.full_url.endswith("/namespaces/test/secrets/sensor-crl")
    assert json.loads(request.data) == {
        "data": {"ca.crl": base64.b64encode(b"signed-crl").decode()}
    }
    assert options["context"] == "verified-kubernetes-tls"
    assert options["timeout"] == 20


@pytest.mark.parametrize(
    "tls_version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]
)
def test_direct_listener_refuses_revoked_cert_before_asgi(
    tmp_path, monkeypatch, tls_version
):
    ca = CA()
    revoked = ca.sensor("default", "sensor-a")
    valid = ca.sensor("default", "sensor-b")
    result = agent_crl.export(exporter(tmp_path, monkeypatch, ca, [record(revoked)]))
    path = tmp_path / "ca.crl"
    path.write_bytes(result.pem)
    ca_path, _ = ca.write(tmp_path, "trust")
    calls = []

    async def app(scope, receive, send):
        calls.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    env = {"OCTO_AGENT_MTLS_CLIENT_CA": str(ca_path), "OCTO_AGENT_MTLS_CRL": str(path)}
    with _TLSServer(app, tmp_path, ca, monkeypatch, env=env) as server:
        assert (
            server.post("/valid", "unused", {}, cert=valid.write(tmp_path, "valid"))[0]
            == 200
        )
        # Console and initial enrolment still have no client certificate.
        assert server.post("/without-cert", "unused", {})[0] == 200
        before = len(calls)
        context = ssl.create_default_context(cafile=str(ca_path))
        context.minimum_version = context.maximum_version = tls_version
        context.load_cert_chain(*revoked.write(tmp_path, "revoked"))
        connection = http.client.HTTPSConnection(
            "127.0.0.1", server.port, context=context, timeout=3
        )
        try:
            with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
                connection.request("GET", "/revoked")
                connection.getresponse()
        finally:
            connection.close()
        assert len(calls) == before


def test_direct_listener_refuses_expired_crl_at_startup(tmp_path, monkeypatch):
    from api.__main__ import _client_ca_context

    ca = CA()
    result = agent_crl.export(
        exporter(tmp_path, monkeypatch, ca, []),
        now=datetime.now(UTC) - timedelta(hours=2),
    )
    path = tmp_path / "expired.crl"
    path.write_bytes(result.pem)
    with pytest.raises(SystemExit, match="not currently valid"):
        _client_ca_context(
            SimpleNamespace(ssl_ca_certs=str(ca.write(tmp_path, "ca")[0])),
            lambda: ssl.create_default_context(ssl.Purpose.CLIENT_AUTH),
            extra_anchor="",
            crl_path=str(path),
        )


def test_direct_listener_refuses_crl_without_ca(monkeypatch):
    from api.__main__ import client_certificate_options

    monkeypatch.delenv("OCTO_AGENT_MTLS_CLIENT_CA", raising=False)
    monkeypatch.delenv("OCTO_AGENT_MTLS_ISSUER_CERT", raising=False)
    monkeypatch.setenv("OCTO_AGENT_MTLS_CRL", "some.crl")
    with pytest.raises(SystemExit, match="requires a client CA"):
        client_certificate_options()


def test_bundle_validates_every_signature_and_every_expiry(tmp_path, monkeypatch):
    from api.core.crl import validate_bundle

    root = CA("Root")
    intermediate = CA("Issuer", parent=root)
    root_crl = agent_crl.export(exporter(tmp_path, monkeypatch, root, [])).pem
    leaf_crl = agent_crl.export(exporter(tmp_path, monkeypatch, intermediate, [])).pem
    assert (
        len(validate_bundle(root_crl + leaf_crl, [root.cert, intermediate.cert])) == 2
    )
    with pytest.raises(ValueError, match="not signed"):
        validate_bundle(root_crl + leaf_crl, [intermediate.cert])
    expired = agent_crl.export(
        exporter(tmp_path, monkeypatch, root, []),
        now=datetime.now(UTC) - timedelta(hours=2),
    ).pem
    with pytest.raises(ValueError, match="not currently valid"):
        validate_bundle(leaf_crl + expired, [root.cert, intermediate.cert])
    with pytest.raises(ValueError, match="Expected a PEM"):
        validate_bundle(b"garbage" + root_crl, [root.cert])


def test_cli_exports_and_publishes_a_validated_chain_bundle(
    tmp_path, monkeypatch, capsys
):
    import sys

    root = CA("Root")
    root_crl = agent_crl.export(exporter(tmp_path, monkeypatch, root, [])).pem
    root_path, _ = root.write(tmp_path, "root")
    parent_crl = tmp_path / "root.crl"
    parent_crl.write_bytes(root_crl)
    issuer = CA("Issuer", parent=root)
    leaf = issuer.sensor("default", "sensor-a")
    leaf_path, _ = leaf.write(tmp_path, "leaf")
    settings = exporter(
        tmp_path, monkeypatch, issuer, [record(leaf, certificate_pem="")]
    )
    monkeypatch.setenv("OCTO_POSTGRES_URL", "test-database")
    output = tmp_path / "bundle.crl"
    published = []
    monkeypatch.setattr(
        publisher, "publish_secret", lambda *args: published.append(args)
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent_crl",
            "--output",
            str(output),
            "--secret",
            "test/crl",
            "--issuer-cert",
            settings.agent_mtls_issuer_cert,
            "--issuer-key",
            settings.agent_mtls_issuer_key,
            "--certificate",
            str(leaf_path),
            "--append-crl",
            str(parent_crl),
            "--client-ca",
            str(root_path),
        ],
    )
    publisher.main()
    assert published == [("test", "crl", output.read_bytes())]
    assert output.read_bytes().count(b"-----BEGIN X509 CRL-----") == 2
    assert "entries=1" in capsys.readouterr().out
    previous = output.read_bytes()
    parent_crl.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="Expected a PEM"):
        publisher.main()
    assert output.read_bytes() == previous
    assert len(published) == 1


def test_cli_requires_operator_credentials_and_valid_secret_name(tmp_path, monkeypatch):
    import sys

    monkeypatch.delenv("OCTO_POSTGRES_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["agent_crl"])
    with pytest.raises(SystemExit) as error:
        publisher.main()
    assert error.value.code == 2
    monkeypatch.setenv("OCTO_POSTGRES_URL", "test")
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent_crl", "--issuer-cert", "ca", "--issuer-key", "key", "--secret", "bad"],
    )
    with pytest.raises(SystemExit) as error:
        publisher.main()
    assert error.value.code == 2


@requires_postgres
def test_real_api_certificate_material_and_committed_revocation_export(
    tmp_path, monkeypatch
):
    from sqlalchemy import delete, select

    from api.db import models
    from api.db.engine import get_session
    from tests.conftest import bearer, login
    from tests.test_agent_mtls import (
        _client,
        _csr,
        _issuer_settings,
        _mint_key,
        _token,
        _peer,
        _register,
        _forwarded,
        INGRESS_PEER,
    )

    ca = CA()
    settings = _issuer_settings(tmp_path, ca, agent_mtls_mode="required")
    client = _client(tmp_path, monkeypatch, settings)
    admin = login(client, "admin")
    key = _mint_key(client, admin)
    token = _token(client, key, "sensor-a")
    _, csr = _csr("sensor-a")
    response = client.post(
        "/api/agent/certificate", headers=bearer(token), json={"csr": csr}
    )
    assert response.status_code == 200, response.text
    issued = response.json()["certificate"]
    assert agent_crl.export(settings).entries == 0
    assert (
        _register(_peer(client, INGRESS_PEER), token, _forwarded(issued)).status_code
        == 200
    )
    observed = ca.sensor("default", "sensor-b")
    token_b = _token(client, key, "sensor-b")
    assert (
        _register(
            _peer(client, INGRESS_PEER), token_b, _forwarded(observed)
        ).status_code
        == 200
    )
    pinned = ca.sensor("default", "sensor-c")
    token_c = _token(client, key, "sensor-c")
    assert (
        _register(_peer(client, INGRESS_PEER), token_c, _forwarded(pinned)).status_code
        == 200
    )
    # Exercise the pin writer independently of observation.
    with get_session(settings.postgres_url) as session:
        session.execute(
            delete(models.AgentClientCert)
            .where(models.AgentClientCert.agent_id == "sensor-c")
        )
    assert (
        client.post(
            "/api/agents/sensor-c/certificates",
            headers=bearer(admin),
            json={"certificate": pinned.pem},
        ).status_code
        == 201
    )
    with get_session(settings.postgres_url) as session:
        rows = session.execute(select(models.AgentClientCert)).scalars().all()
        assert {row.source for row in rows} == {"csr", "observed", "pinned"}
        assert all(
            row.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
            for row in rows
        )
        row = next(row for row in rows if row.agent_id == "sensor-b")
        row.certificate_pem = ""  # legacy record; successful use hydrates it.
    assert (
        _register(
            _peer(client, INGRESS_PEER), token_b, _forwarded(observed)
        ).status_code
        == 200
    )
    with get_session(settings.postgres_url) as session:
        assert (
            session.execute(
                select(models.AgentClientCert.certificate_pem).where(
                    models.AgentClientCert.agent_id == "sensor-b"
                )
            ).scalar_one()
            == observed.pem
        )
    for agent in ("sensor-a", "sensor-b", "sensor-c"):
        response = client.post(
            f"/api/agents/{agent}/certificates/revoke",
            headers=bearer(admin),
            json={"all": True},
        )
        assert response.status_code == 200, response.text
    assert agent_crl.export(settings).entries == 3
