"""Client certificates for sensors and endpoint agents (#309).

The bearer token says which sensor is calling; the certificate is what makes a
copied token useless anywhere else. Two ways in, and both are tested with the
certificates a real deployment would see: an ingress that verified the
certificate and forwards it in ``ssl-client-*`` headers, and the API's own TLS
listener doing the handshake itself (the second half of this file runs a real
uvicorn over TLS).

The main risk is the headers: anyone can send them. So the first tests here
are a request that is *not* from a trusted proxy, forging a verified
certificate for exactly the sensor it holds a token for — and being treated
as one that presented nothing.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from api.settings import InsecureConfigurationError, Settings
from tests.conftest import (
    TEST_AGENT_TOKEN,
    bearer,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)
from tests.mtls_pki import CA, Issued, spiffe

INGRESS_PEER = ("10.42.0.7", 41000)
OUTSIDE_PEER = ("203.0.113.9", 41000)
TRUSTED = ["10.42.0.0/16"]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _settings(tmp_path: Path, ca: CA | None = None, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "job_execution_mode": "agent",
        "agent_token": "",
        "agent_mtls_trusted_proxies": list(TRUSTED),
    }
    if ca is not None:
        ca_path, _ = ca.write(tmp_path, "client-ca")
        values["agent_mtls_client_ca"] = str(ca_path)
    values.update(overrides)
    return make_settings(tmp_path, **values)


def _client(tmp_path: Path, monkeypatch, settings: Settings) -> TestClient:
    return configured_client(tmp_path, monkeypatch, settings=settings)


def _peer(client: TestClient, peer: tuple[str, int]) -> TestClient:
    """The same app, reached from ``peer`` — what ``request.client.host`` says."""
    return TestClient(client.app, client=peer)


def _mint_key(client: TestClient, admin: str, tenant_id: str = "default") -> str:
    created = client.post(
        f"/api/tenants/{tenant_id}/provisioning-keys", headers=bearer(admin), json={"label": ""}
    )
    assert created.status_code == 201, created.text
    return created.json()["key"]


def _token(client: TestClient, key: str, agent_id: str) -> str:
    exchanged = client.post(
        "/api/auth/agent/token", json={"provisioning_key": key, "agent_id": agent_id}
    )
    assert exchanged.status_code == 200, exchanged.text
    return exchanged.json()["access_token"]


def _forwarded(cert: Issued | str, verify: str = "SUCCESS") -> dict[str, str]:
    """The two headers ingress-nginx sets; ``cert`` as issued here or as PEM."""
    pem = cert if isinstance(cert, str) else cert.pem
    return {"ssl-client-verify": verify, "ssl-client-cert": quote(pem, safe="")}


def _register(client: TestClient, token: str, headers: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    return client.post(
        "/api/agent/register",
        headers={**bearer(token), **(headers or {})},
        json={"hostname": "edge"},
    )


def _events(client: TestClient, admin: str, action: str) -> list[dict]:
    listed = client.get("/api/audit", headers=bearer(admin), params={"action": action})
    assert listed.status_code == 200, listed.text
    return listed.json()["items"]


def _fleet(tmp_path: Path, monkeypatch, *, mode: str, ca: CA | None = None, **overrides):  # type: ignore[no-untyped-def]
    """An API, its admin, and tokens for sensors A and B of the default tenant."""
    settings = _settings(tmp_path, ca, agent_mtls_mode=mode, **overrides)
    client = _client(tmp_path, monkeypatch, settings)
    admin = login(client, "admin")
    key = _mint_key(client, admin)
    return client, admin, _token(client, key, "sensor-a"), _token(client, key, "sensor-b")


# --------------------------------------------------------------------------
# 1. Forged headers from a peer that is not the ingress count for nothing.
# --------------------------------------------------------------------------


@requires_postgres
def test_forged_headers_from_an_untrusted_peer_do_not_satisfy_required(tmp_path, monkeypatch):
    """A valid certificate *for this very sensor*, forged into the headers by a
    client the ingress list does not name, is not a certificate."""
    ca = CA()
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="required", ca=ca)
    forged = _register(_peer(client, OUTSIDE_PEER), token_a, _forwarded(ca.sensor("default", "sensor-a")))
    assert forged.status_code == 403, forged.text
    assert forged.headers["X-Client-Cert-Error"] == "missing"
    assert "OCTO_AGENT_MTLS_TRUSTED_PROXIES" in forged.json()["detail"]

    # The same headers from the ingress are what they claim to be.
    genuine = _register(_peer(client, INGRESS_PEER), token_a, _forwarded(ca.sensor("default", "sensor-a")))
    assert genuine.status_code == 200, genuine.text


@requires_postgres
def test_forged_headers_from_an_untrusted_peer_cannot_be_bound_under_optional(tmp_path, monkeypatch):
    """Ignored means ignored: under ``optional`` a forged certificate of
    *another* sensor neither refuses the request nor gets recorded as seen."""
    ca = CA()
    client, admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    forged = _register(_peer(client, OUTSIDE_PEER), token_a, _forwarded(ca.sensor("default", "sensor-b")))
    assert forged.status_code == 200, forged.text
    listed = client.get("/api/agents/sensor-a/certificates", headers=bearer(admin))
    assert listed.status_code == 200 and listed.json() == []
    assert _events(client, admin, "agent.certificate_refused") == []


@requires_postgres
def test_the_testclient_default_peer_is_not_trusted_either(tmp_path, monkeypatch):
    """An address that is not an IP at all — an ASGI transport, a Unix socket —
    is never a trusted proxy."""
    ca = CA()
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="required", ca=ca)
    forged = _register(client, token_a, _forwarded(ca.sensor("default", "sensor-a")))
    assert forged.status_code == 403
    assert forged.headers["X-Client-Cert-Error"] == "missing"


@requires_postgres
def test_a_certificate_header_the_ingress_did_not_write_is_caught_by_its_subject(tmp_path, monkeypatch):
    """Without ``auth-tls-pass-certificate-to-upstream``, nginx still writes the
    verified subject but passes the client's own ``ssl-client-cert`` through:
    sensor B's host, holding A's token, would make its handshake with B's key
    and *send* A's public certificate. The subject the ingress verified gives
    it away."""
    ca = CA()
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="required", ca=ca)
    ingress = _peer(client, INGRESS_PEER)
    cert_a, cert_b = ca.sensor("default", "sensor-a"), ca.sensor("default", "sensor-b")

    lying = _register(
        ingress,
        token_a,
        {**_forwarded(cert_a), "ssl-client-subject-dn": cert_b.cert.subject.rfc4514_string()},
    )
    assert lying.status_code == 403
    assert "does not match the subject the ingress verified" in lying.json()["detail"]

    honest = _register(
        ingress,
        token_a,
        {**_forwarded(cert_a), "ssl-client-subject-dn": cert_a.cert.subject.rfc4514_string()},
    )
    assert honest.status_code == 200, honest.text


# --------------------------------------------------------------------------
# 2. A certificate authenticates its own sensor and no other.
# --------------------------------------------------------------------------


@requires_postgres
def test_sensor_a_certificate_cannot_be_used_with_sensor_b_token(tmp_path, monkeypatch):
    ca = CA()
    client, admin, token_a, token_b = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    ingress = _peer(client, INGRESS_PEER)
    cert_a = ca.sensor("default", "sensor-a")

    # First sight: nothing on record yet, so only the URI can say whose it is.
    first = _register(ingress, token_b, _forwarded(cert_a))
    assert first.status_code == 403, first.text
    assert first.headers["X-Client-Cert-Error"] == "mismatch"

    assert _register(ingress, token_a, _forwarded(cert_a)).status_code == 200
    swapped = _register(ingress, token_b, _forwarded(cert_a))
    assert swapped.status_code == 403, swapped.text
    assert swapped.headers["X-Client-Cert-Error"] == "mismatch"

    # And every agent route, not only registration: the heartbeat of B with A's
    # certificate is the same lie.
    beat = ingress.post(
        "/api/agent/heartbeat",
        headers={**bearer(token_b), **_forwarded(cert_a)},
        json={"agent_id": "sensor-b", "status": "idle"},
    )
    assert beat.status_code == 403
    assert beat.headers["X-Client-Cert-Error"] == "mismatch"

    [refused, *_] = _events(client, admin, "agent.certificate_refused")
    assert len(_events(client, admin, "agent.certificate_refused")) == 3
    assert refused["resource_id"] == "sensor-b"
    assert refused["actor_type"] == "agent"
    assert refused["after"]["reason"] == "mismatch"
    assert refused["after"]["fingerprint_sha256"] == cert_a.fingerprint
    assert refused["after"]["presented_identities"] == [spiffe("default", "sensor-a")]


@requires_postgres
def test_a_certificate_naming_another_tenant_is_a_mismatch(tmp_path, monkeypatch):
    ca = CA()
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    other = _register(_peer(client, INGRESS_PEER), token_a, _forwarded(ca.sensor("ten_other", "sensor-a")))
    assert other.status_code == 403
    assert other.headers["X-Client-Cert-Error"] == "mismatch"


@requires_postgres
def test_a_spiffe_uri_of_another_trust_domain_names_nobody(tmp_path, monkeypatch):
    ca = CA()
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    foreign = ca.sensor("default", "sensor-a", domain="someone-else.example")
    refused = _register(_peer(client, INGRESS_PEER), token_a, _forwarded(foreign))
    assert refused.status_code == 403
    assert refused.headers["X-Client-Cert-Error"] == "unbound"


@requires_postgres
def test_a_forwarded_certificate_from_another_ca_is_not_believed(tmp_path, monkeypatch):
    """The ingress said SUCCESS, but against a CA that is not ours: an
    ``auth-tls-secret`` pointed at the wrong Secret must not widen who gets in."""
    ca, rogue = CA(), CA("Somebody Else's CA")
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="required", ca=ca)
    refused = _register(_peer(client, INGRESS_PEER), token_a, _forwarded(rogue.sensor("default", "sensor-a")))
    assert refused.status_code == 403
    assert refused.headers["X-Client-Cert-Error"] == "missing"
    assert "not issued by the configured client CA" in refused.json()["detail"]


@requires_postgres
def test_the_ingress_verdict_is_required(tmp_path, monkeypatch):
    ca = CA()
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="required", ca=ca)
    failed = _register(
        _peer(client, INGRESS_PEER),
        token_a,
        _forwarded(ca.sensor("default", "sensor-a"), verify="FAILED:certificate has expired"),
    )
    assert failed.status_code == 403
    assert failed.headers["X-Client-Cert-Error"] == "missing"


# --------------------------------------------------------------------------
# 3. Modes, and the fleet that was there before the upgrade.
# --------------------------------------------------------------------------


@requires_postgres
def test_off_is_the_default_and_reads_nothing(tmp_path, monkeypatch):
    """Post-upgrade: nothing changes until an operator says so — a forged,
    mismatched certificate from a trusted peer is not even looked at."""
    ca = CA()
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="off", ca=ca)
    assert _register(client, token_a).status_code == 200
    assert _register(_peer(client, INGRESS_PEER), token_a, _forwarded(ca.sensor("default", "sensor-b"))).status_code == 200


@requires_postgres
def test_optional_keeps_sensors_without_a_certificate_working(tmp_path, monkeypatch):
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=CA())
    assert _register(client, token_a).status_code == 200


@requires_postgres
def test_required_refuses_the_legacy_shared_token(tmp_path, monkeypatch):
    ca = CA()
    settings = _settings(tmp_path, ca, agent_mtls_mode="required", agent_token=TEST_AGENT_TOKEN)
    client = _client(tmp_path, monkeypatch, settings)
    refused = _register(_peer(client, INGRESS_PEER), TEST_AGENT_TOKEN, _forwarded(ca.sensor("default", "x")))
    assert refused.status_code == 403
    assert refused.headers["X-Client-Cert-Error"] == "no-identity"


# --------------------------------------------------------------------------
# 4. Revocation, by fingerprint and by serial, on the next request.
# --------------------------------------------------------------------------


@requires_postgres
def test_revoking_by_fingerprint_takes_effect_on_the_next_request(tmp_path, monkeypatch):
    ca = CA()
    client, admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="required", ca=ca)
    ingress = _peer(client, INGRESS_PEER)
    cert = ca.sensor("default", "sensor-a")
    assert _register(ingress, token_a, _forwarded(cert)).status_code == 200

    # First sight recorded it, so the console lists it.
    [listed] = client.get("/api/agents/sensor-a/certificates", headers=bearer(admin)).json()
    assert (listed["fingerprint_sha256"], listed["source"], listed["state"]) == (
        cert.fingerprint,
        "observed",
        "valid",
    )

    revoked = client.post(
        "/api/agents/sensor-a/certificates/revoke",
        headers=bearer(admin),
        json={"fingerprint": ":".join(cert.fingerprint[i : i + 2] for i in range(0, 64, 2)).upper(), "reason": "laptop stolen"},
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()[0]["state"] == "revoked"

    refused = _register(ingress, token_a, _forwarded(cert))
    assert refused.status_code == 403
    assert refused.headers["X-Client-Cert-Error"] == "revoked"
    assert "laptop stolen" in refused.json()["detail"]
    assert _events(client, admin, "agent.certificate_revoke")[0]["after"]["reason"] == "laptop stolen"


@requires_postgres
def test_revoking_by_serial(tmp_path, monkeypatch):
    ca = CA()
    client, admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    ingress = _peer(client, INGRESS_PEER)
    cert = ca.sensor("default", "sensor-a")
    assert _register(ingress, token_a, _forwarded(cert)).status_code == 200

    unknown = client.post(
        "/api/agents/sensor-a/certificates/revoke", headers=bearer(admin), json={"serial": "abcdef"}
    )
    assert unknown.status_code == 404
    revoked = client.post(
        "/api/agents/sensor-a/certificates/revoke",
        headers=bearer(admin),
        json={"serial": "0x" + cert.serial_hex.upper()},
    )
    assert revoked.status_code == 200, revoked.text
    refused = _register(ingress, token_a, _forwarded(cert))
    assert refused.status_code == 403
    assert refused.headers["X-Client-Cert-Error"] == "revoked"


@requires_postgres
def test_a_certificate_can_be_revoked_before_it_is_ever_used(tmp_path, monkeypatch):
    ca = CA()
    client, admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    cert = ca.sensor("default", "sensor-a")
    assert _register(client, token_a).status_code == 200
    tombstone = client.post(
        "/api/agents/sensor-a/certificates/revoke",
        headers=bearer(admin),
        json={"fingerprint": cert.fingerprint},
    )
    assert tombstone.status_code == 200, tombstone.text
    assert tombstone.json()[0]["source"] == "tombstone"
    refused = _register(_peer(client, INGRESS_PEER), token_a, _forwarded(cert))
    assert refused.status_code == 403
    assert refused.headers["X-Client-Cert-Error"] == "revoked"


@requires_postgres
def test_another_tenant_cannot_revoke_or_pin_into_this_tenant(tmp_path, monkeypatch):
    """A fingerprint is not a secret. Tenant B's admin writing one must not
    lock tenant A's sensor out — every lookup is in the token's tenant."""
    ca = CA()
    client, admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    ingress = _peer(client, INGRESS_PEER)
    cert = ca.sensor("default", "sensor-a")

    created = client.post("/api/tenants", headers=bearer(admin), json={"name": "B", "tenant_id": "ten_b"})
    assert created.status_code == 201, created.text
    assert client.put("/api/tenants/ten_b/members/operator", headers=bearer(admin), json={"role": "admin"}).status_code == 200
    other_admin = bearer(login(client, "operator"))
    key_b = _mint_key(client, login(client, "admin"), "ten_b")
    token_b = _token(client, key_b, "sensor-b-of-b")
    assert _register(client, token_b).status_code == 200

    # A's agent is not B's to touch...
    assert client.post(
        "/api/agents/sensor-a/certificates/revoke?tenant_id=ten_b",
        headers=other_admin,
        json={"fingerprint": cert.fingerprint},
    ).status_code == 404
    # ...and a tombstone or a pin of A's certificate on B's own agent changes
    # nothing for A.
    assert client.post(
        "/api/agents/sensor-b-of-b/certificates/revoke?tenant_id=ten_b",
        headers=other_admin,
        json={"fingerprint": cert.fingerprint},
    ).status_code == 200
    assert _register(ingress, token_a, _forwarded(cert)).status_code == 200


# --------------------------------------------------------------------------
# 5. A certificate that names a host, not a sensor: pinned by fingerprint.
# --------------------------------------------------------------------------


@requires_postgres
def test_a_pinned_certificate_binds_by_fingerprint_and_only_to_its_agent(tmp_path, monkeypatch):
    ca = CA()
    client, admin, token_a, token_b = _fleet(tmp_path, monkeypatch, mode="required", ca=ca)
    ingress = _peer(client, INGRESS_PEER)
    host_cert = ca.plain_client()

    unbound = _register(ingress, token_a, _forwarded(host_cert))
    assert unbound.status_code == 403
    assert unbound.headers["X-Client-Cert-Error"] == "unbound"

    # The agent row exists once the sensor registered; pin needs it.
    assert _register(_peer(client, INGRESS_PEER), token_a, _forwarded(ca.sensor("default", "sensor-a"))).status_code == 200
    pinned = client.post(
        "/api/agents/sensor-a/certificates", headers=bearer(admin), json={"certificate": host_cert.pem}
    )
    assert pinned.status_code == 201, pinned.text
    assert pinned.json()["source"] == "pinned"

    assert _register(ingress, token_a, _forwarded(host_cert)).status_code == 200
    swapped = _register(ingress, token_b, _forwarded(host_cert))
    assert swapped.status_code == 403
    assert swapped.headers["X-Client-Cert-Error"] == "mismatch"


@requires_postgres
def test_pinning_refuses_a_certificate_that_names_another_sensor(tmp_path, monkeypatch):
    ca = CA()
    client, admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    assert _register(client, token_a).status_code == 200
    refused = client.post(
        "/api/agents/sensor-a/certificates",
        headers=bearer(admin),
        json={"certificate": ca.sensor("default", "sensor-b").pem},
    )
    assert refused.status_code == 422
    assert spiffe("default", "sensor-b") in refused.json()["detail"]
    rogue = client.post(
        "/api/agents/sensor-a/certificates",
        headers=bearer(admin),
        json={"certificate": CA("Other").plain_client().pem},
    )
    assert rogue.status_code == 422
    # Viewers read, admins write.
    viewer = bearer(login(client, "viewer"))
    assert client.get("/api/agents/sensor-a/certificates", headers=viewer).status_code == 200
    assert client.post(
        "/api/agents/sensor-a/certificates/revoke", headers=viewer, json={"all": True}
    ).status_code == 403


# --------------------------------------------------------------------------
# 6. Enrolment: CSR in, certificate for the token's agent out.
# --------------------------------------------------------------------------


def _csr(common_name: str, *, uri: str | None = None) -> tuple[bytes, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    if uri:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False
        )
    csr = builder.sign(key, hashes.SHA256())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _issuer_settings(tmp_path: Path, ca: CA, **overrides: object) -> Settings:
    cert_path, key_path = ca.write(tmp_path, "issuer")
    return _settings(
        tmp_path,
        None,
        agent_mtls_issuer_cert=str(cert_path),
        agent_mtls_issuer_key=str(key_path),
        **overrides,
    )


@requires_postgres
def test_enrolment_issues_a_certificate_for_the_tokens_agent_whatever_the_csr_asks(tmp_path, monkeypatch):
    ca = CA()
    settings = _issuer_settings(tmp_path, ca, agent_mtls_mode="required")
    client = _client(tmp_path, monkeypatch, settings)
    admin = login(client, "admin")
    token_a = _token(client, _mint_key(client, admin), "sensor-a")

    # The CSR asks to be sensor-b; the certificate is sensor-a's.
    _key, csr = _csr("sensor-b", uri=spiffe("default", "sensor-b"))
    enrolled = client.post("/api/agent/certificate", headers=bearer(token_a), json={"csr": csr})
    assert enrolled.status_code == 200, enrolled.text
    body = enrolled.json()
    assert body["spiffe_id"] == spiffe("default", "sensor-a")
    from cryptography import x509

    issued = x509.load_pem_x509_certificate(body["certificate"].encode("ascii"))
    san = issued.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [spiffe("default", "sensor-a")]
    issued.verify_directly_issued_by(ca.cert)
    assert body["ca_certificate"] == ca.pem
    assert body["not_before"] < body["renew_after"] < body["not_after"]

    # It works through the ingress, as the agent it names.
    assert _register(_peer(client, INGRESS_PEER), token_a, _forwarded(body["certificate"])).status_code == 200
    [recorded] = _events(client, admin, "agent.certificate_issue")
    assert recorded["after"]["spiffe_id"] == spiffe("default", "sensor-a")


@requires_postgres
def test_renewal_needs_the_current_certificate_and_keeps_one_previous(tmp_path, monkeypatch):
    """A stolen token cannot mint itself a certificate beside the real sensor's.

    Mode ``off`` on purpose: enrolment is how a fleet gets certificates
    *before* the switch to ``required``, so its rule cannot depend on the mode.
    """
    ca = CA()
    settings = _issuer_settings(tmp_path, ca, agent_mtls_mode="off")
    client = _client(tmp_path, monkeypatch, settings)
    admin = login(client, "admin")
    token_a = _token(client, _mint_key(client, admin), "sensor-a")
    ingress = _peer(client, INGRESS_PEER)
    assert _register(client, token_a).status_code == 200

    first = client.post("/api/agent/certificate", headers=bearer(token_a), json={"csr": _csr("a")[1]})
    assert first.status_code == 200, first.text
    again = client.post("/api/agent/certificate", headers=bearer(token_a), json={"csr": _csr("a")[1]})
    assert again.status_code == 403
    assert again.headers["X-Client-Cert-Error"] == "missing"
    # Forged from outside: still nothing presented.
    forged = _peer(client, OUTSIDE_PEER).post(
        "/api/agent/certificate",
        headers={**bearer(token_a), **_forwarded(first.json()["certificate"])},
        json={"csr": _csr("a")[1]},
    )
    assert forged.status_code == 403

    current = first.json()["certificate"]
    issued = []
    for _ in range(3):
        renewed = ingress.post(
            "/api/agent/certificate",
            headers={**bearer(token_a), **_forwarded(current)},
            json={"csr": _csr("a")[1]},
        )
        assert renewed.status_code == 200, renewed.text
        current = renewed.json()["certificate"]
        issued.append(renewed.json()["fingerprint_sha256"])

    states = {
        row["fingerprint_sha256"]: row["state"]
        for row in client.get("/api/agents/sensor-a/certificates", headers=bearer(admin)).json()
    }
    # The newest and the one before it: the overlap a rotation needs. The
    # first two were superseded as the later ones were issued.
    assert sorted(fp for fp, state in states.items() if state == "valid") == sorted(issued[-2:])
    assert sum(1 for state in states.values() if state == "revoked") == 2

    # Revoking all of them is the reset: enrolment from scratch works again.
    reset = client.post(
        "/api/agents/sensor-a/certificates/revoke", headers=bearer(admin), json={"all": True}
    )
    assert reset.status_code == 200
    fresh = client.post("/api/agent/certificate", headers=bearer(token_a), json={"csr": _csr("a")[1]})
    assert fresh.status_code == 200, fresh.text


@requires_postgres
def test_enrolment_without_an_issuer_is_404_and_bad_csrs_are_422(tmp_path, monkeypatch):
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=CA())
    absent = client.post("/api/agent/certificate", headers=bearer(token_a), json={"csr": _csr("a")[1]})
    assert absent.status_code == 404

    ca = CA()
    settings = _issuer_settings(tmp_path, ca)
    client = _client(tmp_path, monkeypatch, settings)
    token = _token(client, _mint_key(client, login(client, "admin")), "sensor-a")
    garbage = client.post("/api/agent/certificate", headers=bearer(token), json={"csr": "not a csr"})
    assert garbage.status_code == 422
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a")]))
        .sign(weak, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )
    refused = client.post("/api/agent/certificate", headers=bearer(token), json={"csr": weak_csr})
    assert refused.status_code == 422
    assert "2048" in refused.json()["detail"]


# --------------------------------------------------------------------------
# 7. Fleet status: who holds one, and whose runs out.
# --------------------------------------------------------------------------


@requires_postgres
def test_fleet_summary_counts_certificates_and_warns_before_expiry(tmp_path, monkeypatch):
    ca = CA()
    client, admin, token_a, token_b = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    ingress = _peer(client, INGRESS_PEER)
    soon = datetime.now(UTC) + timedelta(days=2)
    assert _register(ingress, token_a, _forwarded(ca.sensor("default", "sensor-a"))).status_code == 200
    assert _register(ingress, token_b, _forwarded(ca.sensor("default", "sensor-b", not_after=soon))).status_code == 200

    summary = client.get("/api/agents/summary", headers=bearer(admin)).json()
    assert summary["client_cert_mode"] == "optional"
    assert summary["client_cert_agents"] == 2
    assert summary["client_certs_expiring"] == 1
    assert summary["client_certs_expired"] == 0
    [row] = client.get("/api/agents/sensor-b/certificates", headers=bearer(admin)).json()
    assert row["state"] == "expiring"


# --------------------------------------------------------------------------
# 8. Configuration that cannot work is refused at start.
# --------------------------------------------------------------------------


def test_a_misspelt_mode_is_refused(monkeypatch):
    from api.settings import _agent_mtls_settings

    monkeypatch.setenv("OCTO_AGENT_MTLS_MODE", "require")
    with pytest.raises(InsecureConfigurationError, match="OCTO_AGENT_MTLS_MODE"):
        _agent_mtls_settings()


def test_required_with_no_way_for_a_certificate_to_arrive_is_refused(monkeypatch, tmp_path):
    from api.settings import _agent_mtls_settings

    for name in ("OCTO_AGENT_MTLS_TRUSTED_PROXIES", "OCTO_API_TLS_CERT", "OCTO_AGENT_MTLS_CLIENT_CA"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OCTO_AGENT_MTLS_MODE", "required")
    with pytest.raises(InsecureConfigurationError, match="no client certificate can reach"):
        _agent_mtls_settings()
    monkeypatch.setenv("OCTO_AGENT_MTLS_TRUSTED_PROXIES", "10.42.0.0/16")
    assert _agent_mtls_settings()["agent_mtls_mode"] == "required"


def test_half_configured_issuance_is_refused(monkeypatch, tmp_path):
    from api.settings import _agent_mtls_settings

    cert, _key = CA().write(tmp_path)
    monkeypatch.setenv("OCTO_AGENT_MTLS_ISSUER_CERT", str(cert))
    monkeypatch.delenv("OCTO_AGENT_MTLS_ISSUER_KEY", raising=False)
    with pytest.raises(InsecureConfigurationError, match="OCTO_AGENT_MTLS_ISSUER_KEY"):
        _agent_mtls_settings()


def test_the_listener_asks_for_a_certificate_only_when_sensors_use_one(monkeypatch, tmp_path):
    from api.__main__ import client_certificate_options

    ca_path, _ = CA().write(tmp_path)
    monkeypatch.setenv("OCTO_AGENT_MTLS_CLIENT_CA", str(ca_path))
    monkeypatch.setenv("OCTO_AGENT_MTLS_MODE", "off")
    assert client_certificate_options() == {}
    monkeypatch.setenv("OCTO_AGENT_MTLS_MODE", "optional")
    options = client_certificate_options()
    # Optional per connection: the console shares this port and has none.
    assert options["ssl_cert_reqs"] == ssl.CERT_OPTIONAL
    assert options["ssl_ca_certs"] == str(ca_path)


# --------------------------------------------------------------------------
# 9. Direct TLS: a real handshake against uvicorn.
# --------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class _TLSServer:
    """uvicorn on 127.0.0.1 over TLS, asking for client certificates the way
    ``python -m api`` does (``api.__main__.client_certificate_options``)."""

    def __init__(self, app, tmp_path: Path, ca: CA) -> None:  # type: ignore[no-untyped-def]
        import uvicorn

        from api.core.client_cert import listener_protocol_class

        server_cert, server_key = ca.server().write(tmp_path, "server")
        ca_path, _ = ca.write(tmp_path, "listener-ca")
        self.port = _free_port()
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=self.port,
                lifespan="off",
                log_level="warning",
                ssl_certfile=str(server_cert),
                ssl_keyfile=str(server_key),
                ssl_ca_certs=str(ca_path),
                ssl_cert_reqs=ssl.CERT_OPTIONAL,
                http=listener_protocol_class(),
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.ca_path = ca_path

    def __enter__(self) -> "_TLSServer":
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            assert time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.02)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)

    def post(self, path: str, token: str, body: dict, *, cert=None) -> tuple[int, dict, dict]:  # type: ignore[no-untyped-def]
        context = ssl.create_default_context(cafile=str(self.ca_path))
        if cert is not None:
            context.load_cert_chain(*cert)
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=context, timeout=10)
        try:
            conn.request(
                "POST",
                path,
                body=json.dumps(body),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read() or b"{}")
        finally:
            conn.close()


@requires_postgres
def test_direct_tls_binds_the_handshake_certificate(tmp_path, monkeypatch):
    ca = CA()
    settings = _settings(tmp_path, ca, agent_mtls_mode="required", agent_mtls_trusted_proxies=[])
    client = _client(tmp_path, monkeypatch, settings)
    admin = login(client, "admin")
    key = _mint_key(client, admin)
    token_a, token_b = _token(client, key, "sensor-a"), _token(client, key, "sensor-b")
    cert_a = ca.sensor("default", "sensor-a").write(tmp_path, "sensor-a")
    body = {"hostname": "edge"}

    with _TLSServer(client.app, tmp_path, ca) as server:
        status, _headers, answer = server.post("/api/agent/register", token_a, body, cert=cert_a)
        assert status == 200, answer
        assert answer["agent_id"] == "sensor-a"

        status, headers, _ = server.post("/api/agent/register", token_a, body)
        assert status == 403
        assert headers["x-client-cert-error"] == "missing"

        status, headers, _ = server.post("/api/agent/register", token_b, body, cert=cert_a)
        assert status == 403
        assert headers["x-client-cert-error"] == "mismatch"

        # Headers cannot add what the handshake did not have — not even on
        # the API's own listener.
        context = ssl.create_default_context(cafile=str(server.ca_path))
        conn = http.client.HTTPSConnection("127.0.0.1", server.port, context=context, timeout=10)
        conn.request(
            "POST",
            "/api/agent/register",
            body=json.dumps(body),
            headers={
                "Authorization": f"Bearer {token_a}",
                "Content-Type": "application/json",
                **_forwarded(ca.sensor("default", "sensor-a")),
            },
        )
        assert conn.getresponse().status == 403
        conn.close()

        # A certificate from another CA does not get past the handshake.
        rogue = CA("Rogue").sensor("default", "sensor-a").write(tmp_path, "rogue")
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            status, _h, _b = server.post("/api/agent/register", token_a, body, cert=rogue)
            # TLS 1.3 reports the client-side alert on the first read.
            raise AssertionError(f"rogue certificate was answered {status}")


@requires_postgres
def test_the_sensor_enrols_over_direct_tls_and_then_presents_its_certificate(tmp_path, monkeypatch):
    """The agent's own code, end to end: no certificate on disk, enrolment over
    TLS, files written, the next call under ``required`` presents it."""
    from agent import mtls
    from agent.worker import AgentClient

    ca = CA()
    settings = _issuer_settings(tmp_path, ca, agent_mtls_mode="required", agent_mtls_trusted_proxies=[])
    client = _client(tmp_path, monkeypatch, settings)
    token = _token(client, _mint_key(client, login(client, "admin")), "sensor-a")

    with _TLSServer(client.app, tmp_path, ca) as server:
        monkeypatch.setenv("OCTO_CA_BUNDLE", str(server.ca_path))
        monkeypatch.setenv("OCTO_NO_PROXY", "127.0.0.1")
        state = tmp_path / "sensor-state"
        cert = mtls.ClientCertificate(state / "client.crt", state / "client.key", enrol=True)
        agent = AgentClient(f"https://127.0.0.1:{server.port}", token, client_cert=cert)
        assert cert.enrolment_due()
        issued = agent.enrol_client_certificate("sensor-a")
        assert issued["spiffe_id"] == spiffe("default", "sensor-a")
        assert (state / "client.key").stat().st_mode & 0o777 == 0o600
        assert not cert.enrolment_due()

        registered = agent.register(agent_id="sensor-a", hostname="edge", labels={})
        assert registered["agent_id"] == "sensor-a"

        # Renewal presents the current certificate, which the API requires.
        renewed = agent.enrol_client_certificate("sensor-a")
        assert renewed["fingerprint_sha256"] != issued["fingerprint_sha256"]
        assert agent.register(agent_id="sensor-a", hostname="edge", labels={})["agent_id"] == "sensor-a"


# --------------------------------------------------------------------------
# 10. The sensor side: configuration, renewal timing, the refusal it acts on.
# --------------------------------------------------------------------------


def test_sensor_certificate_configuration(tmp_path):
    from agent import mtls

    assert mtls.ClientCertificate.from_env({}) is None
    with pytest.raises(mtls.ClientCertConfigError, match="OCTO_AGENT_TLS_CLIENT_KEY"):
        mtls.ClientCertificate.from_env({"OCTO_AGENT_TLS_CLIENT_CERT": str(tmp_path / "c")})
    with pytest.raises(mtls.ClientCertConfigError, match="OCTO_AGENT_MTLS_ENROLL"):
        mtls.ClientCertificate.from_env({"OCTO_AGENT_MTLS_ENROLL": "true"})
    paths = {
        "OCTO_AGENT_TLS_CLIENT_CERT": str(tmp_path / "client.crt"),
        "OCTO_AGENT_TLS_CLIENT_KEY": str(tmp_path / "client.key"),
    }
    # Mounted, and not there: a cert-manager Secret that never arrived.
    with pytest.raises(mtls.ClientCertConfigError, match="do not exist"):
        mtls.ClientCertificate.from_env(paths)
    enrolled = mtls.ClientCertificate.from_env({**paths, "OCTO_AGENT_MTLS_ENROLL": "1"})
    assert enrolled is not None and enrolled.enrol and enrolled.enrolment_due()


def test_sensor_renews_at_renew_after_and_backs_off_after_a_failure(tmp_path):
    from agent import mtls

    ca = CA()
    issued = ca.sensor("default", "sensor-a")
    cert = mtls.ClientCertificate(tmp_path / "c.crt", tmp_path / "c.key", enrol=True)
    now = time.time()
    later = datetime.fromtimestamp(now + 3600, UTC).isoformat().replace("+00:00", "Z")
    cert.install(issued.key_pem, {"certificate": issued.pem, "renew_after": later})
    assert (tmp_path / "c.key").stat().st_mode & 0o777 == 0o600
    assert not cert.enrolment_due(now)
    assert cert.enrolment_due(now + 3601)

    cert.force_enrolment()
    assert cert.enrolment_due(now)
    cert.enrolment_failed(now)
    # A refusal repeated on every poll must not turn into an enrolment per poll.
    cert.force_enrolment()
    assert not cert.enrolment_due(now + 1)
    assert cert.enrolment_due(now + mtls.RETRY_SECONDS + 1)


def test_a_rotated_certificate_on_disk_is_noticed(tmp_path):
    from agent import mtls

    ca = CA()
    cert_path, key_path = ca.sensor("default", "sensor-a").write(tmp_path, "mounted")
    cert = mtls.ClientCertificate(cert_path, key_path)
    cert.ssl_context()
    assert not cert.changed_on_disk()
    time.sleep(0.01)
    ca.sensor("default", "sensor-a").write(tmp_path, "mounted")
    assert cert.changed_on_disk()
    cert.ssl_context()
    assert not cert.changed_on_disk()


@pytest.mark.parametrize("backend", ["cryptography", "openssl"])
def test_the_sensor_makes_a_key_and_csr_with_either_backend(monkeypatch, backend):
    import shutil

    from cryptography import x509

    from agent import mtls

    if backend == "openssl":
        if shutil.which("openssl") is None:
            pytest.skip("no openssl binary on this host")

        def no_cryptography(_name):  # type: ignore[no-untyped-def]
            raise ImportError("cryptography is not installed on this sensor")

        monkeypatch.setattr(mtls, "_generate_with_cryptography", no_cryptography)
    key_pem, csr_pem = mtls.generate_key_and_csr("sensor-a")
    assert b"PRIVATE KEY" in key_pem
    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    assert csr.is_signature_valid


def test_the_worker_classifies_a_certificate_refusal_by_its_header(monkeypatch):
    import email.message
    import io
    import urllib.error

    from agent import worker

    def refused(req, timeout):  # type: ignore[no-untyped-def]
        headers = email.message.Message()
        headers["X-Client-Cert-Error"] = "revoked"
        raise urllib.error.HTTPError(
            url=req.full_url, code=403, msg="Forbidden", hdrs=headers, fp=io.BytesIO(b"revoked")
        )

    client = worker.AgentClient("https://127.0.0.1:8443", "token", timeout=1.0)
    monkeypatch.setattr(client._opener, "open", refused)  # noqa: SLF001
    with pytest.raises(worker.AgentClientCertRefused) as caught:
        client.register(agent_id="sensor-a", hostname="edge", labels={})
    assert caught.value.reason == "revoked"
