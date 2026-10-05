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

    # Enrolment from scratch takes the operator's reset (not a revocation:
    # see test_a_revoked_sensor_cannot_enrol_itself_back_with_its_token).
    reset = client.post(
        "/api/agents/sensor-a/certificates/reset-enrolment", headers=bearer(admin), json={}
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
    ca_path, _ = CA().write(tmp_path)
    monkeypatch.setenv("OCTO_AGENT_MTLS_CLIENT_CA", str(ca_path))
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
    # ...and the worker waits the delay out instead of polling into the same
    # refusal (a revoked sensor's enrolment is refused until a reset).
    assert cert.retry_pending(now + 1)
    assert not cert.retry_pending(now + mtls.RETRY_SECONDS + 1)
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


# --------------------------------------------------------------------------
# 11. A revocation sticks until an operator resets the agent's enrolment.
# --------------------------------------------------------------------------


def _enrol(client: TestClient, token: str, cert: str | None = None):  # type: ignore[no-untyped-def]
    """``POST /api/agent/certificate``: token alone, or presenting ``cert`` via the ingress."""
    if cert is None:
        return client.post("/api/agent/certificate", headers=bearer(token), json={"csr": _csr("a")[1]})
    return _peer(client, INGRESS_PEER).post(
        "/api/agent/certificate",
        headers={**bearer(token), **_forwarded(cert)},
        json={"csr": _csr("a")[1]},
    )


def _revoke(client: TestClient, admin: str, agent_id: str, **body: object):  # type: ignore[no-untyped-def]
    return client.post(
        f"/api/agents/{agent_id}/certificates/revoke", headers=bearer(admin), json=body
    )


def _reset(client: TestClient, admin: str, agent_id: str, reason: str = ""):  # type: ignore[no-untyped-def]
    return client.post(
        f"/api/agents/{agent_id}/certificates/reset-enrolment",
        headers=bearer(admin),
        json={"reason": reason},
    )


@requires_postgres
def test_a_revoked_sensor_cannot_enrol_itself_back_with_its_token(tmp_path, monkeypatch):
    """The probe from the review of #509, in the order the sensor runs it.

    Before: enrol → register → revoke → old certificate 403 → enrolment by
    the token alone **200** → the stolen host back in service under
    ``required`` about five seconds after the operator revoked it.
    """
    ca = CA()
    settings = _issuer_settings(tmp_path, ca, agent_mtls_mode="required")
    client = _client(tmp_path, monkeypatch, settings)
    admin = login(client, "admin")
    token_a = _token(client, _mint_key(client, admin), "sensor-a")
    ingress = _peer(client, INGRESS_PEER)

    first = _enrol(client, token_a)
    assert first.status_code == 200, first.text
    cert = first.json()["certificate"]
    assert _register(ingress, token_a, _forwarded(cert)).status_code == 200

    revoked = _revoke(
        client, admin, "sensor-a", fingerprint=first.json()["fingerprint_sha256"], reason="laptop stolen"
    )
    assert revoked.status_code == 200, revoked.text
    old = _register(ingress, token_a, _forwarded(cert))
    assert (old.status_code, old.headers["X-Client-Cert-Error"]) == (403, "revoked")

    # What agent/worker.py does next: the same enrolment, without the
    # certificate. It is the token's last way back in, and it is shut.
    by_token = _enrol(client, token_a)
    assert by_token.status_code == 403, by_token.text
    assert by_token.headers["X-Client-Cert-Error"] == "enrolment-locked"
    assert "reset" in by_token.json()["detail"]
    renewal = _enrol(client, token_a, cert)
    assert (renewal.status_code, renewal.headers["X-Client-Cert-Error"]) == (403, "revoked")
    bare = _register(client, token_a)
    assert (bare.status_code, bare.headers["X-Client-Cert-Error"]) == (403, "enrolment-locked")
    assert all(
        row["state"] == "revoked"
        for row in client.get("/api/agents/sensor-a/certificates", headers=bearer(admin)).json()
    )

    # The operator's separate, deliberate act: re-imaged host, new enrolment.
    reset = _reset(client, admin, "sensor-a", "host re-imaged")
    assert reset.status_code == 200, reset.text
    [event] = _events(client, admin, "agent.certificate_enrolment_reset")
    assert event["after"]["reason"] == "host re-imaged"
    fresh = _enrol(client, token_a)
    assert fresh.status_code == 200, fresh.text
    assert _register(ingress, token_a, _forwarded(fresh.json()["certificate"])).status_code == 200
    # One enrolment per reset: the next one by token alone is a second
    # certificate beside a live one, refused as before.
    twice = _enrol(client, token_a)
    assert (twice.status_code, twice.headers["X-Client-Cert-Error"]) == (403, "missing")


@requires_postgres
def test_revoking_all_is_not_a_reset_any_more(tmp_path, monkeypatch):
    ca = CA()
    settings = _issuer_settings(tmp_path, ca, agent_mtls_mode="off")
    client = _client(tmp_path, monkeypatch, settings)
    admin = login(client, "admin")
    token_a = _token(client, _mint_key(client, admin), "sensor-a")
    assert _register(client, token_a).status_code == 200
    assert _enrol(client, token_a).status_code == 200

    assert _revoke(client, admin, "sensor-a", all=True).status_code == 200
    locked = _enrol(client, token_a)
    assert (locked.status_code, locked.headers["X-Client-Cert-Error"]) == (403, "enrolment-locked")
    # A reset with a live certificate still on record revokes it: "enrol from
    # scratch" means the old key stops working too.
    assert _reset(client, admin, "sensor-a").status_code == 200
    second = _enrol(client, token_a)
    assert second.status_code == 200
    assert _reset(client, admin, "sensor-a", "again").status_code == 200
    states = {
        row["fingerprint_sha256"]: row["state"]
        for row in client.get("/api/agents/sensor-a/certificates", headers=bearer(admin)).json()
    }
    assert states[second.json()["fingerprint_sha256"]] == "revoked"
    assert _enrol(client, token_a).status_code == 200


@requires_postgres
def test_under_optional_a_revoked_sensor_cannot_fall_back_to_its_token(tmp_path, monkeypatch):
    ca = CA()
    client, admin, token_a, token_b = _fleet(tmp_path, monkeypatch, mode="optional", ca=ca)
    ingress = _peer(client, INGRESS_PEER)
    cert = ca.sensor("default", "sensor-a")
    assert _register(ingress, token_a, _forwarded(cert)).status_code == 200
    assert _register(client, token_a).status_code == 200
    assert _register(client, token_b).status_code == 200

    assert _revoke(client, admin, "sensor-a", fingerprint=cert.fingerprint, reason="copied").status_code == 200
    without = _register(client, token_a)
    assert (without.status_code, without.headers["X-Client-Cert-Error"]) == (403, "enrolment-locked")
    with_revoked = _register(ingress, token_a, _forwarded(cert))
    assert (with_revoked.status_code, with_revoked.headers["X-Client-Cert-Error"]) == (403, "revoked")
    # Sensor B never had a certificate revoked; optional is unchanged for it.
    assert _register(client, token_b).status_code == 200

    assert _reset(client, admin, "sensor-a").status_code == 200
    assert _register(client, token_a).status_code == 200


@requires_postgres
def test_resetting_enrolment_is_an_admin_write_behind_step_up(tmp_path, monkeypatch):
    from tests.conftest import auth_headers
    from tests.test_api_mfa import Clock, enrol

    client, admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="optional", ca=CA())
    assert _register(client, token_a).status_code == 200
    operator = client.post(
        "/api/agents/sensor-a/certificates/reset-enrolment",
        headers=bearer(login(client, "operator")),
        json={},
    )
    assert operator.status_code == 403

    clock = Clock()
    monkeypatch.setattr("api.services.mfa._now", clock)
    headers = auth_headers(client, "admin")
    enrol(client, headers, clock)
    stale = client.post(
        "/api/agents/sensor-a/certificates/reset-enrolment", headers=headers, json={}
    )
    assert stale.status_code == 403
    assert "multi-factor" in stale.json()["detail"]


# --------------------------------------------------------------------------
# 12. Headers from the ingress are checked against our CA, always.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["optional", "required"])
def test_trusted_proxies_without_a_client_ca_are_refused_at_start(monkeypatch, tmp_path, mode):
    from api.settings import _agent_mtls_settings

    for name in ("OCTO_API_TLS_CERT", "OCTO_AGENT_MTLS_CLIENT_CA", "OCTO_AGENT_MTLS_ISSUER_CERT", "OCTO_AGENT_MTLS_ISSUER_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OCTO_AGENT_MTLS_MODE", mode)
    monkeypatch.setenv("OCTO_AGENT_MTLS_TRUSTED_PROXIES", "10.42.0.7")
    with pytest.raises(InsecureConfigurationError, match="OCTO_AGENT_MTLS_CLIENT_CA"):
        _agent_mtls_settings()
    ca_path, _ = CA().write(tmp_path)
    monkeypatch.setenv("OCTO_AGENT_MTLS_CLIENT_CA", str(ca_path))
    assert _agent_mtls_settings()["agent_mtls_mode"] == mode


def test_an_unparsable_trusted_proxy_is_refused_at_start_by_its_own_name(monkeypatch, tmp_path):
    from api.settings import _agent_mtls_settings

    ca_path, _ = CA().write(tmp_path)
    monkeypatch.setenv("OCTO_AGENT_MTLS_MODE", "required")
    monkeypatch.setenv("OCTO_AGENT_MTLS_CLIENT_CA", str(ca_path))
    monkeypatch.setenv("OCTO_AGENT_MTLS_TRUSTED_PROXIES", "10.42.0.7, ingress-nginx-controller")
    with pytest.raises(InsecureConfigurationError) as caught:
        _agent_mtls_settings()
    assert "OCTO_AGENT_MTLS_TRUSTED_PROXIES" in str(caught.value)
    assert "ingress-nginx-controller" in str(caught.value)
    assert "OCTO_TRUSTED_PROXIES " not in str(caught.value)


@requires_postgres
def test_a_forwarded_certificate_is_not_believed_without_a_ca_to_check_it(tmp_path, monkeypatch):
    """Settings built around the start-up check (as every test here does) must
    still not turn "a pod in the trusted range said SUCCESS" into a sensor."""
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="required", ca=None)
    attacker = CA("Attacker CA").sensor("default", "sensor-a")
    forged = _register(_peer(client, INGRESS_PEER), token_a, _forwarded(attacker))
    assert forged.status_code == 403
    assert "OCTO_AGENT_MTLS_CLIENT_CA" in forged.json()["detail"]


@requires_postgres
@pytest.mark.parametrize(
    "usage, not_before_days, problem",
    [
        ("server", -1, "not issued for client authentication"),
        ("client", 1, "not valid yet"),
    ],
)
def test_a_forwarded_certificate_must_be_for_clients_and_already_valid(
    tmp_path, monkeypatch, usage, not_before_days, problem
):
    from cryptography.x509.oid import ExtendedKeyUsageOID

    ca = CA()
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="required", ca=ca)
    cert = ca.sensor(
        "default",
        "sensor-a",
        usage=ExtendedKeyUsageOID.SERVER_AUTH if usage == "server" else ExtendedKeyUsageOID.CLIENT_AUTH,
        not_before=datetime.now(UTC) + timedelta(days=not_before_days),
    )
    refused = _register(_peer(client, INGRESS_PEER), token_a, _forwarded(cert))
    assert refused.status_code == 403
    assert problem in refused.json()["detail"]


# --------------------------------------------------------------------------
# 13. The subject nginx forwards is compared as a name, not as a string.
# --------------------------------------------------------------------------


def _name(*rdns: list[tuple[str, str]]):  # type: ignore[no-untyped-def]
    from cryptography import x509
    from cryptography.x509.oid import ObjectIdentifier

    return x509.Name(
        [
            x509.RelativeDistinguishedName(
                [x509.NameAttribute(ObjectIdentifier(oid), value) for oid, value in rdn]
            )
            for rdn in rdns
        ]
    )


CN, O_, OU, C, ST, L = "2.5.4.3", "2.5.4.10", "2.5.4.11", "2.5.4.6", "2.5.4.8", "2.5.4.7"
EMAIL = "1.2.840.113549.1.9.1"

#: ``$ssl_client_s_dn`` exactly as nginx 1.27 (nginx:alpine, OpenSSL 3) wrote
#: it for a certificate with that subject, captured from a live
#: ``ssl_verify_client optional`` server during the review of #509.
NGINX_SUBJECTS = {
    "cyrillic O and emailAddress": (
        [[(C, "RU")], [(O_, "ООО «Ромашка»")], [(CN, "edge-01")], [(EMAIL, "ops@example.ru")]],
        "emailAddress=ops@example.ru,CN=edge-01,"
        r"O=\D0\9E\D0\9E\D0\9E \C2\AB\D0\A0\D0\BE\D0\BC\D0\B0\D1\88\D0\BA\D0\B0\C2\BB,C=RU",
    ),
    "multi-valued RDN": (
        [[(OU, "IT"), (CN, "sensor-a")], [(O_, "Corp")]],
        "O=Corp,CN=sensor-a+OU=IT",
    ),
    "escapes, Russian OIDs, short names": (
        [
            [(CN, 'a, b+c "q" <x>;\\z ')],
            [(O_, "#hash")],
            [("0.9.2342.19200300.100.1.25", "corp")],
            [("0.9.2342.19200300.100.1.1", "u1")],
            [("1.2.643.3.131.1.1", "7700000000")],
            [("1.2.643.100.1", "1027700000000")],
            [("2.5.4.5", "SN-1")],
            [(ST, "Москва")],
            [(L, "Moscow")],
        ],
        r"L=Moscow,ST=\D0\9C\D0\BE\D1\81\D0\BA\D0\B2\D0\B0,serialNumber=SN-1,"
        r"OGRN=1027700000000,INN=7700000000,UID=u1,DC=corp,O=\#hash,"
        r'CN=a\, b\+c \"q\" \<x\>\;\\z\ ',
    ),
    "unknown OID dumped as DER": (
        [[("1.3.6.1.4.1.99999.1", "custom")], [(CN, "bmp")]],
        "CN=bmp,1.3.6.1.4.1.99999.1=#0C06637573746F6D",
    ),
}


@pytest.mark.parametrize("case", sorted(NGINX_SUBJECTS))
def test_the_subject_nginx_forwards_matches_the_certificate(case):
    from api.core import client_cert

    rdns, nginx_dn = NGINX_SUBJECTS[case]
    cert = CA().sensor("default", "sensor-a", subject=_name(*rdns)).cert
    assert client_cert.subject_matches(nginx_dn, cert.subject)
    # What uvicorn hands the app after HTTP trimmed the header's trailing
    # whitespace — the space of a trailing backslash-space escape included.
    assert client_cert.subject_matches(nginx_dn.rstrip(), cert.subject)
    # And cryptography's own spelling of it, which the older tests forward.
    assert client_cert.subject_matches(cert.subject.rfc4514_string(), cert.subject)


@pytest.mark.parametrize(
    "lying",
    [
        "emailAddress=ops@example.ru,CN=edge-02,"
        r"O=\D0\9E\D0\9E\D0\9E \C2\AB\D0\A0\D0\BE\D0\BC\D0\B0\D1\88\D0\BA\D0\B0\C2\BB,C=RU",
        # The same attributes in another order is another name.
        "CN=edge-01,emailAddress=ops@example.ru,"
        r"O=\D0\9E\D0\9E\D0\9E \C2\AB\D0\A0\D0\BE\D0\BC\D0\B0\D1\88\D0\BA\D0\B0\C2\BB,C=RU",
        # One RDN fewer.
        "CN=edge-01,"
        r"O=\D0\9E\D0\9E\D0\9E \C2\AB\D0\A0\D0\BE\D0\BC\D0\B0\D1\88\D0\BA\D0\B0\C2\BB,C=RU",
        # Two RDNs merged into one multi-valued RDN.
        "emailAddress=ops@example.ru+CN=edge-01,"
        r"O=\D0\9E\D0\9E\D0\9E \C2\AB\D0\A0\D0\BE\D0\BC\D0\B0\D1\88\D0\BA\D0\B0\C2\BB,C=RU",
        # Broken escapes and garbage are no name at all.
        r"emailAddress=ops@example.ru,CN=edge-01,O=\D0\9,C=RU",
        "not a dn",
        "",
    ],
)
def test_a_different_subject_does_not_match(lying):
    from api.core import client_cert

    rdns, _ = NGINX_SUBJECTS["cyrillic O and emailAddress"]
    cert = CA().sensor("default", "sensor-a", subject=_name(*rdns)).cert
    assert not client_cert.subject_matches(lying, cert.subject)


@requires_postgres
def test_a_corporate_subject_forwarded_by_nginx_is_accepted(tmp_path, monkeypatch):
    """Before: 403 ``missing`` — the RFC 2253 string nginx writes and the one
    cryptography writes differ for exactly the certificates a pin is for."""
    ca = CA()
    client, _admin, token_a, _ = _fleet(tmp_path, monkeypatch, mode="required", ca=ca)
    ingress = _peer(client, INGRESS_PEER)
    rdns, nginx_dn = NGINX_SUBJECTS["cyrillic O and emailAddress"]
    cert = ca.sensor("default", "sensor-a", subject=_name(*rdns))
    accepted = _register(ingress, token_a, {**_forwarded(cert), "ssl-client-subject-dn": nginx_dn})
    assert accepted.status_code == 200, accepted.text


# --------------------------------------------------------------------------
# 14. A sensor shut out by somebody else's first enrolment shows up.
# --------------------------------------------------------------------------


@requires_postgres
def test_a_sensor_locked_out_by_an_earlier_enrolment_is_audited_once_and_counted(tmp_path, monkeypatch):
    ca = CA()
    settings = _issuer_settings(tmp_path, ca, agent_mtls_mode="required")
    client = _client(tmp_path, monkeypatch, settings)
    admin = login(client, "admin")
    token_a = _token(client, _mint_key(client, admin), "sensor-a")
    ingress = _peer(client, INGRESS_PEER)

    # Whoever holds a copy of the token enrols first...
    thief = _enrol(client, token_a)
    assert thief.status_code == 200
    assert _register(ingress, token_a, _forwarded(thief.json()["certificate"])).status_code == 200
    # ...and the real sensor, polling, is refused every time.
    for _ in range(3):
        real = _enrol(client, token_a)
        assert (real.status_code, real.headers["X-Client-Cert-Error"]) == (403, "missing")
        assert _register(client, token_a).status_code == 403

    [event] = _events(client, admin, "agent.certificate_refused")
    assert event["resource_id"] == "sensor-a"
    assert event["after"]["reason"] == "missing"
    assert event["after"]["agent_holds_live_certificate"] is True
    summary = client.get("/api/agents/summary", headers=bearer(admin)).json()
    assert summary["client_cert_conflicts"] == 1

    # The operator's answer: revoke what the other host holds, reset, let
    # the real sensor enrol. The conflict is over.
    assert _revoke(client, admin, "sensor-a", all=True, reason="enrolled elsewhere").status_code == 200
    assert _reset(client, admin, "sensor-a").status_code == 200
    summary = client.get("/api/agents/summary", headers=bearer(admin)).json()
    assert summary["client_cert_conflicts"] == 0
    assert summary["client_cert_locked"] == 0


# --------------------------------------------------------------------------
# 15. What the review's surviving mutations left unpinned.
# --------------------------------------------------------------------------


@requires_postgres
def test_a_certificate_that_ran_out_while_offline_needs_no_operator(tmp_path, monkeypatch):
    """operations.md promises it: expiry is not revocation, enrolment by token
    is open again once nothing live is on record."""
    from sqlalchemy import update

    from api.db import models
    from api.db.engine import get_session

    ca = CA()
    settings = _issuer_settings(tmp_path, ca, agent_mtls_mode="required")
    client = _client(tmp_path, monkeypatch, settings)
    admin = login(client, "admin")
    token_a = _token(client, _mint_key(client, admin), "sensor-a")
    first = _enrol(client, token_a)
    assert first.status_code == 200
    assert _enrol(client, token_a).status_code == 403  # live: renewal needs it

    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.AgentClientCert)
            .where(models.AgentClientCert.agent_id == "sensor-a")
            .values(not_after=datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=1))
        )
    again = _enrol(client, token_a)
    assert again.status_code == 200, again.text


@requires_postgres
def test_an_issued_certificate_cannot_sign_others(tmp_path, monkeypatch):
    from cryptography import x509

    ca = CA()
    client = _client(tmp_path, monkeypatch, _issuer_settings(tmp_path, ca, agent_mtls_mode="off"))
    token_a = _token(client, _mint_key(client, login(client, "admin")), "sensor-a")
    enrolled = _enrol(client, token_a)
    assert enrolled.status_code == 200
    issued = x509.load_pem_x509_certificate(enrolled.json()["certificate"].encode("ascii"))
    constraints = issued.extensions.get_extension_for_class(x509.BasicConstraints)
    assert constraints.critical and constraints.value.ca is False
    usage = issued.extensions.get_extension_for_class(x509.KeyUsage).value
    assert not usage.key_cert_sign and not usage.crl_sign


@requires_postgres
def test_an_endpoint_agent_can_follow_its_contract_under_required(tmp_path, monkeypatch):
    """The order docs/operations.md gives Lariska: token, enrol (no
    certificate yet, so before register — register needs one under
    ``required``), then register and everything else with the certificate.
    The certificate names an ``/agent/``, not a ``/sensor/``."""
    ca = CA()
    settings = _issuer_settings(tmp_path, ca, agent_mtls_mode="required")
    client = _client(tmp_path, monkeypatch, settings)
    token = _token(client, _mint_key(client, login(client, "admin")), "laptop-7")

    enrolled = client.post(
        "/api/v1/agent/certificate",
        headers=bearer(token),
        json={"csr": _csr("laptop-7")[1], "agent_kind": "endpoint"},
    )
    assert enrolled.status_code == 200, enrolled.text
    assert enrolled.json()["spiffe_id"] == spiffe("default", "laptop-7", kind="agent")
    registered = _peer(client, INGRESS_PEER).post(
        "/api/v1/agent/register",
        headers={**bearer(token), **_forwarded(enrolled.json()["certificate"])},
        json={"hostname": "laptop-7", "agent_kind": "endpoint"},
    )
    assert registered.status_code == 200, registered.text
    # Once the agent is on record, its kind is the record's, not the CSR body's.
    renewed = _peer(client, INGRESS_PEER).post(
        "/api/v1/agent/certificate",
        headers={**bearer(token), **_forwarded(enrolled.json()["certificate"])},
        json={"csr": _csr("laptop-7")[1], "agent_kind": "scanner"},
    )
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["spiffe_id"] == spiffe("default", "laptop-7", kind="agent")
