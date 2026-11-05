from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
import xmlsec
from cryptography import x509
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from api.services import saml
from api.settings import Settings
from tests.conftest import POSTGRES_URL, requires_postgres

IDP_ENTITY = "https://idp.example.com/metadata"
ACS = "https://console.example.com/api/auth/saml/acs"


def _certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "saml-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


CERT, KEY = _certificate()


def metadata_xml() -> str:
    body = "".join(line for line in CERT.splitlines() if "CERTIFICATE" not in line)
    return f"""<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY}">
      <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>{body}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
      </IDPSSODescriptor>
    </EntityDescriptor>"""


def make_settings(tmp_path, **overrides) -> Settings:
    metadata = tmp_path / "idp.xml"
    metadata.write_text(metadata_xml(), encoding="utf-8")
    settings = Settings(
        env="dev",
        postgres_url=f"sqlite:///{tmp_path / 'saml.db'}",
        public_base_url="https://console.example.com",
        saml_sp_entity_id="https://console.example.com/saml",
        saml_idp_metadata_path=str(metadata),
        saml_sp_x509_cert=CERT,
        saml_sp_private_key=KEY,
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


@pytest.fixture(autouse=True)
def _clean_metadata_cache():
    saml.reset_for_tests()
    yield
    saml.reset_for_tests()


def test_metadata_import_and_security_policy(tmp_path):
    settings = make_settings(tmp_path)
    config = saml.sp_settings(settings)
    assert config["idp"]["entityId"] == IDP_ENTITY
    assert config["security"]["wantMessagesSigned"] is True
    assert config["security"]["wantAssertionsEncrypted"] is True
    assert config["security"]["authnRequestsSigned"] is True
    assert config["security"]["logoutRequestSigned"] is True
    assert config["security"]["rejectDeprecatedAlgorithm"] is True
    document = saml.metadata_xml(settings)
    assert "SPSSODescriptor" in document
    assert KEY not in document


def test_saml_is_off_without_one_metadata_source_or_decryption_key(tmp_path):
    assert not saml.is_enabled(Settings())
    settings = make_settings(tmp_path, saml_sp_private_key="")
    assert not saml.is_enabled(settings)
    settings = make_settings(
        tmp_path,
        saml_sp_private_key="",
        saml_require_encrypted_assertion=False,
        saml_sign_requests=False,
    )
    assert saml.is_enabled(settings)


def response_xml() -> str:
    now = datetime.now(UTC)
    return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="{now.isoformat().replace("+00:00", "Z")}" Destination="{ACS}" InResponseTo="request-1">
      <saml:Issuer>{IDP_ENTITY}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_assertion" IssueInstant="{now.isoformat().replace("+00:00", "Z")}" Version="2.0"><saml:Issuer>{IDP_ENTITY}</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="request-1" NotOnOrAfter="{(now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{(now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")}" NotOnOrAfter="{(now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")}"/><saml:AuthnStatement AuthnInstant="{now.isoformat().replace("+00:00", "Z")}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>
    </samlp:Response>"""


def signed_response() -> str:
    root = etree.fromstring(response_xml().encode())
    xmlsec.tree.add_ids(root, ["ID"])
    signature = xmlsec.template.create(
        root, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA256
    )
    root.insert(1, signature)
    reference = xmlsec.template.add_reference(
        signature, xmlsec.Transform.SHA256, uri="#_response"
    )
    xmlsec.template.add_transform(reference, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(reference, xmlsec.Transform.EXCL_C14N)
    context = xmlsec.SignatureContext()
    context.key = xmlsec.Key.from_memory(KEY, xmlsec.KeyFormat.PEM)
    context.sign(signature)
    return base64.b64encode(etree.tostring(root)).decode()


class FakeAuth:
    def __init__(self, attributes=None, errors=None):
        self.attributes = attributes or {}
        self.errors = errors or []
        self.request_id = None

    def process_response(self, request_id=None):
        self.request_id = request_id

    def get_errors(self):
        return self.errors

    def is_authenticated(self):
        return not self.errors

    def get_nameid(self):
        return "name-id-1"

    def get_attributes(self):
        return self.attributes


def test_response_maps_groups_role_tenant_and_checks_in_response_to(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path,
        saml_username_attribute="uid",
        saml_tenant_attribute="tenant",
        oidc_role_map={"vm-admins": "admin", "vm-ops": "operator"},
    )
    fake = FakeAuth(
        {
            "uid": ["alice"],
            "email": ["alice@example.com"],
            "groups": ["vm-ops", "vm-admins"],
            "tenant": ["acme"],
        }
    )
    monkeypatch.setattr(saml, "_auth", lambda *_args: fake)
    monkeypatch.setattr(
        saml,
        "_consume_request",
        lambda *_args, **_kwargs: saml._PendingRequest(  # noqa: SLF001
            "request-1", "/runs", saml._now() + timedelta(minutes=5)  # noqa: SLF001
        ),
    )

    completed = saml.complete_login(
        settings, saml_response="signed-response", relay_state="relay"
    )

    assert fake.request_id == "request-1"
    assert completed.next_url == "/runs"
    assert completed.identity.username == "alice"
    assert completed.identity.role == "admin"
    assert completed.identity.tenant_id == "acme"
    assert completed.identity.issuer == f"saml:{IDP_ENTITY}"


def test_a_response_with_validation_errors_is_refused(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    monkeypatch.setattr(saml, "_auth", lambda *_args: FakeAuth(errors=["invalid_signature"]))
    monkeypatch.setattr(
        saml,
        "_consume_request",
        lambda *_args, **_kwargs: saml._PendingRequest(  # noqa: SLF001
            "request-1", "", saml._now() + timedelta(minutes=5)  # noqa: SLF001
        ),
    )
    with pytest.raises(saml.SamlError, match="validation failed"):
        saml.complete_login(settings, saml_response="response", relay_state="relay")


def _pending_response(monkeypatch):
    monkeypatch.setattr(
        saml,
        "_consume_request",
        lambda *_args, **_kwargs: saml._PendingRequest(  # noqa: SLF001
            "request-1", "", saml._now() + timedelta(minutes=5)  # noqa: SLF001
        ),
    )


def test_an_unsigned_response_is_rejected_by_the_real_saml_validator(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path, saml_sign_requests=False, saml_require_encrypted_assertion=False
    )
    _pending_response(monkeypatch)
    with pytest.raises(saml.SamlError, match="validation failed"):
        saml.complete_login(
            settings,
            saml_response=base64.b64encode(response_xml().encode()).decode(),
            relay_state="relay",
        )


def test_a_signed_response_is_accepted_by_the_real_saml_validator(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path, saml_sign_requests=False, saml_require_encrypted_assertion=False
    )
    _pending_response(monkeypatch)
    completed = saml.complete_login(
        settings, saml_response=signed_response(), relay_state="relay"
    )
    assert completed.identity.subject == "alice"


def test_slo_response_is_bound_to_the_pending_logout_request(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)

    class LogoutAuth:
        request_id = None

        def process_slo(self, request_id=None):
            self.request_id = request_id

        def get_errors(self):
            return []

    fake = LogoutAuth()
    monkeypatch.setattr(saml, "_auth", lambda *_args: fake)
    _pending_response(monkeypatch)
    destination = saml.complete_logout(
        settings, get_data={"SAMLResponse": "signed", "RelayState": "relay"}
    )
    assert fake.request_id == "request-1"
    assert destination is None


@requires_postgres
def test_relay_state_is_single_use_across_the_database(tmp_path):
    settings = make_settings(
        tmp_path,
        postgres_url=POSTGRES_URL,
        saml_sign_requests=False,
        saml_require_encrypted_assertion=False,
    )
    saml.reset_for_tests(settings)
    login = saml.begin_login(settings)
    first = saml._consume_request(settings, login.relay_state, kind="login")  # noqa: SLF001
    assert first.request_id
    with pytest.raises(saml.SamlError, match="already used"):
        saml._consume_request(settings, login.relay_state, kind="login")  # noqa: SLF001
    saml.reset_for_tests(settings)
