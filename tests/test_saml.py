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
    assert config["security"]["wantMessagesSigned"] is False
    assert config["security"]["wantAssertionsSigned"] is True
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
      <saml:Assertion ID="_assertion" IssueInstant="{now.isoformat().replace("+00:00", "Z")}" Version="2.0"><saml:Issuer>{IDP_ENTITY}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">alice</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="request-1" NotOnOrAfter="{(now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{(now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")}" NotOnOrAfter="{(now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")}"><saml:AudienceRestriction><saml:Audience>https://console.example.com/saml</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{now.isoformat().replace("+00:00", "Z")}" SessionIndex="session-1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>
    </samlp:Response>"""


_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"


def signed_response(xml: str | None = None, *, signature_object: etree._Element | None = None) -> str:
    """Sign the Assertion. A Response signature alone is no longer accepted.

    ``signature_object`` is appended under ``ds:Signature`` after signing. The
    enveloped transform excludes that element, so the signature still verifies.
    """
    root = etree.fromstring((xml or response_xml()).encode())
    xmlsec.tree.add_ids(root, ["ID"])
    assertion = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    signature = xmlsec.template.create(
        assertion, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA256
    )
    issuer = assertion.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    issuer.addnext(signature)
    reference = xmlsec.template.add_reference(
        signature, xmlsec.Transform.SHA256, uri="#_assertion"
    )
    xmlsec.template.add_transform(reference, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(reference, xmlsec.Transform.EXCL_C14N)
    context = xmlsec.SignatureContext()
    context.key = xmlsec.Key.from_memory(KEY, xmlsec.KeyFormat.PEM)
    context.sign(signature)
    if signature_object is not None:
        signature.append(signature_object)
    return base64.b64encode(etree.tostring(root)).decode()


def signature_object(*children: etree._Element) -> etree._Element:
    """A ``ds:Object`` planted after the signature, which the digest does not cover."""
    obj = etree.Element(f"{{{_DS_NS}}}Object")
    for child in children:
        obj.append(child)
    return obj


def saml_element(tag: str, text: str | None = None, **attrs: str) -> etree._Element:
    node = etree.Element(f"{{{_SAML_NS}}}{tag}", attrs)
    if text is not None:
        node.text = text
    return node


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

    def get_last_response_in_response_to(self):
        return "request-1"

    def get_last_assertion_id(self):
        return "assert-1"

    def get_last_assertion_not_on_or_after(self):
        return datetime.now(UTC) + timedelta(minutes=5)

    def get_last_response_xml(self):
        return (
            '<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            "<saml:Assertion><saml:Subject>"
            f'<saml:SubjectConfirmation Method="{_BEARER}">'
            '<saml:SubjectConfirmationData InResponseTo="request-1"/>'
            "</saml:SubjectConfirmation></saml:Subject>"
            "<saml:Conditions><saml:AudienceRestriction>"
            "<saml:Audience>https://console.example.com/saml</saml:Audience>"
            "</saml:AudienceRestriction></saml:Conditions></saml:Assertion></Response>"
        )

    def get_nameid_format(self):
        return "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

    def get_session_index(self):
        return "session-1"


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
    assert completed.subject.name_id == "name-id-1"
    assert completed.subject.session_index == "session-1"


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
    assert completed.subject.session_index == "session-1"


def test_a_response_without_in_response_to_is_refused(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    fake = FakeAuth()
    # The Response attribute matches. The signed assertion does not carry it.
    fake.get_last_response_in_response_to = lambda: "request-1"
    fake.get_last_response_xml = lambda: (
        '<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" InResponseTo="request-1">'
        "<saml:Audience>https://console.example.com/saml</saml:Audience>"
        "<saml:Assertion><saml:Subject>"
        f'<saml:SubjectConfirmation Method="{_BEARER}">'
        "<saml:SubjectConfirmationData/>"
        "</saml:SubjectConfirmation></saml:Subject>"
        "<saml:Conditions><saml:AudienceRestriction>"
        "<saml:Audience>https://console.example.com/saml</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions></saml:Assertion></Response>"
    )
    monkeypatch.setattr(saml, "_auth", lambda *_args: fake)
    _pending_response(monkeypatch)
    with pytest.raises(saml.SamlError, match="not a reply"):
        saml.complete_login(settings, saml_response="response", relay_state="relay")


def test_a_response_whose_audience_is_not_the_sp_is_refused(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    fake = FakeAuth()
    fake.get_last_response_xml = lambda: (
        '<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" InResponseTo="request-1">'
        "<saml:Audience>https://console.example.com/saml</saml:Audience>"
        "<saml:Assertion><saml:Subject>"
        f'<saml:SubjectConfirmation Method="{_BEARER}">'
        '<saml:SubjectConfirmationData InResponseTo="request-1"/>'
        "</saml:SubjectConfirmation></saml:Subject>"
        "<saml:Conditions><saml:AudienceRestriction>"
        "<saml:Audience>https://other.example/saml</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions></saml:Assertion></Response>"
    )
    monkeypatch.setattr(saml, "_auth", lambda *_args: fake)
    _pending_response(monkeypatch)
    with pytest.raises(saml.SamlError, match="audience"):
        saml.complete_login(settings, saml_response="response", relay_state="relay")


@pytest.mark.parametrize(
    ("assertion_in_response_to", "message"),
    [(None, "not a reply"), ("request-1", "audience")],
)
def test_a_signed_assertion_ignores_wrapper_audience_and_in_response_to(
    tmp_path, monkeypatch, assertion_in_response_to, message
):
    """The library accepts this response. The binding values sit outside the signature."""
    settings = make_settings(
        tmp_path, saml_sign_requests=False, saml_require_encrypted_assertion=False
    )
    _pending_response(monkeypatch)
    now = datetime.now(UTC)

    def stamp(moment: datetime) -> str:
        return moment.isoformat().replace("+00:00", "Z")

    in_response_to = (
        f' InResponseTo="{assertion_in_response_to}"' if assertion_in_response_to else ""
    )
    xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="{stamp(now)}" Destination="{ACS}" InResponseTo="request-1">
      <saml:Issuer>{IDP_ENTITY}</saml:Issuer>
      <samlp:Extensions><saml:Audience>https://console.example.com/saml</saml:Audience></samlp:Extensions>
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_assertion" IssueInstant="{stamp(now)}" Version="2.0"><saml:Issuer>{IDP_ENTITY}</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData{in_response_to} NotOnOrAfter="{stamp(now + timedelta(minutes=5))}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{stamp(now - timedelta(minutes=1))}" NotOnOrAfter="{stamp(now + timedelta(minutes=5))}"/><saml:AuthnStatement AuthnInstant="{stamp(now)}" SessionIndex="session-1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>
    </samlp:Response>"""
    with pytest.raises(saml.SamlError, match=message):
        saml.complete_login(settings, saml_response=signed_response(xml), relay_state="relay")


def _binding_response(
    *,
    response_to: str | None,
    confirmation_to: str | None,
    audience: str | None,
) -> str:
    now = datetime.now(UTC)

    def stamp(moment: datetime) -> str:
        return moment.isoformat().replace("+00:00", "Z")

    response_attr = f' InResponseTo="{response_to}"' if response_to else ""
    confirmation_attr = f' InResponseTo="{confirmation_to}"' if confirmation_to else ""
    audience_xml = (
        f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>"
        if audience
        else ""
    )
    return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="{stamp(now)}" Destination="{ACS}"{response_attr}>
      <saml:Issuer>{IDP_ENTITY}</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_assertion" IssueInstant="{stamp(now)}" Version="2.0"><saml:Issuer>{IDP_ENTITY}</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID><saml:SubjectConfirmation Method="{_BEARER}"><saml:SubjectConfirmationData{confirmation_attr} NotOnOrAfter="{stamp(now + timedelta(minutes=5))}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{stamp(now - timedelta(minutes=1))}" NotOnOrAfter="{stamp(now + timedelta(minutes=5))}">{audience_xml}</saml:Conditions><saml:AuthnStatement AuthnInstant="{stamp(now)}" SessionIndex="session-1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>
    </samlp:Response>"""


def _real_login(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path, saml_sign_requests=False, saml_require_encrypted_assertion=False
    )
    _pending_response(monkeypatch)
    return settings


@pytest.mark.parametrize("confirmation_to", [None, "other-request"])
def test_in_response_to_inside_the_signature_object_is_ignored(
    tmp_path, monkeypatch, confirmation_to
):
    settings = _real_login(tmp_path, monkeypatch)
    planted = saml_element("SubjectConfirmationData", InResponseTo="request-1")
    payload = signed_response(
        _binding_response(
            response_to=None,
            confirmation_to=confirmation_to,
            audience="https://console.example.com/saml",
        ),
        signature_object=signature_object(planted),
    )
    with pytest.raises(saml.SamlError, match="not a reply"):
        saml.complete_login(settings, saml_response=payload, relay_state="relay")


def test_an_audience_inside_the_signature_object_is_ignored(tmp_path, monkeypatch):
    settings = _real_login(tmp_path, monkeypatch)
    restriction = saml_element("AudienceRestriction")
    restriction.append(saml_element("Audience", "https://console.example.com/saml"))
    payload = signed_response(
        _binding_response(response_to="request-1", confirmation_to="request-1", audience=None),
        signature_object=signature_object(restriction),
    )
    with pytest.raises(saml.SamlError, match="audience"):
        saml.complete_login(settings, saml_response=payload, relay_state="relay")


def test_an_extra_audience_inside_the_signature_object_does_not_reject(tmp_path, monkeypatch):
    settings = _real_login(tmp_path, monkeypatch)
    restriction = saml_element("AudienceRestriction")
    restriction.append(saml_element("Audience", "https://other.example/saml"))
    completed = saml.complete_login(
        settings,
        saml_response=signed_response(signature_object=signature_object(restriction)),
        relay_state="relay",
    )
    assert completed.identity.subject == "alice"


def test_a_non_bearer_confirmation_does_not_bind_the_request(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    fake = FakeAuth()
    fake.get_last_response_xml = lambda: (
        '<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        "<saml:Assertion><saml:Subject>"
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key">'
        '<saml:SubjectConfirmationData InResponseTo="request-1"/>'
        "</saml:SubjectConfirmation></saml:Subject>"
        "<saml:Conditions><saml:AudienceRestriction>"
        "<saml:Audience>https://console.example.com/saml</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions></saml:Assertion></Response>"
    )
    monkeypatch.setattr(saml, "_auth", lambda *_args: fake)
    _pending_response(monkeypatch)
    with pytest.raises(saml.SamlError, match="not a reply"):
        saml.complete_login(settings, saml_response="response", relay_state="relay")


def test_an_unsigned_logout_request_is_refused(tmp_path):
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

    settings = make_settings(
        tmp_path, saml_sign_requests=False, saml_require_encrypted_assertion=False
    )
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="_logout1" Version="2.0" IssueInstant="{now}">'
        "<saml:NameID>alice@example.com</saml:NameID></samlp:LogoutRequest>"
    )
    with pytest.raises(saml.SamlError, match="not signed"):
        saml.complete_logout(
            settings,
            get_data={"SAMLRequest": OneLogin_Saml2_Utils.deflate_and_base64_encode(xml)},
        )


def test_an_unsigned_logout_response_does_not_burn_the_pending_request(tmp_path):
    settings = make_settings(tmp_path)
    saml._store_request(settings, "request-1", "relay", kind="logout", family_id="fam-1")  # noqa: SLF001
    with pytest.raises(saml.SamlError, match="not signed"):
        saml.complete_logout(
            settings, get_data={"SAMLResponse": "signed", "RelayState": "relay"}
        )
    pending = saml._peek_request(settings, "relay", kind="logout")  # noqa: SLF001
    assert pending is not None
    assert pending.family_id == "fam-1"


def test_an_accepted_assertion_cannot_be_replayed(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    monkeypatch.setattr(saml, "_auth", lambda *_args: FakeAuth())
    _pending_response(monkeypatch)
    saml.complete_login(settings, saml_response="response", relay_state="relay")
    with pytest.raises(saml.SamlError, match="already used"):
        saml.complete_login(settings, saml_response="response", relay_state="relay")


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
    saml._store_request(  # noqa: SLF001
        settings, "request-1", "relay", kind="logout", family_id="fam-1", next_url="/done"
    )
    done = saml.complete_logout(
        settings,
        get_data={"SAMLResponse": "signed", "RelayState": "relay", "Signature": "sig"},
    )
    assert fake.request_id == "request-1"
    assert done.family_id == "fam-1"
    assert done.next_url == "/done"
    assert done.message == "response"
    with pytest.raises(saml.SamlError, match="already used"):
        saml.complete_logout(
            settings,
            get_data={"SAMLResponse": "signed", "RelayState": "relay", "Signature": "sig"},
        )


def test_a_failed_logout_response_does_not_burn_the_pending_request(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)

    class LogoutAuth:
        def process_slo(self, request_id=None):
            return None

        def get_errors(self):
            return ["invalid_logout_response_signature"]

    monkeypatch.setattr(saml, "_auth", lambda *_args: LogoutAuth())
    saml._store_request(settings, "request-1", "relay", kind="logout", family_id="fam-1")  # noqa: SLF001
    with pytest.raises(saml.SamlError, match="validation failed"):
        saml.complete_logout(
            settings,
            get_data={"SAMLResponse": "signed", "RelayState": "relay", "Signature": "sig"},
        )
    pending = saml._peek_request(settings, "relay", kind="logout")  # noqa: SLF001
    assert pending is not None
    assert pending.family_id == "fam-1"


def test_an_idp_logout_request_names_its_subject_and_ignores_relay_state(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)

    class LogoutAuth:
        def process_slo(self, request_id=None):
            assert request_id is None
            return "https://idp.example.com/slo-done"

        def get_errors(self):
            return []

        def get_last_request_xml(self):
            return (
                '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
                '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
                "alice@example.com</saml:NameID>"
                "<samlp:SessionIndex>idx-1</samlp:SessionIndex>"
                "<samlp:SessionIndex>idx-2</samlp:SessionIndex>"
                "</samlp:LogoutRequest>"
            )

    monkeypatch.setattr(saml, "_auth", lambda *_args: LogoutAuth())
    saml._store_request(settings, "request-1", "relay", kind="logout", family_id="fam-1")  # noqa: SLF001
    done = saml.complete_logout(
        settings,
        get_data={"SAMLRequest": "request", "RelayState": "relay", "Signature": "sig"},
    )
    assert done.message == "request"
    assert done.name_id == "alice@example.com"
    assert done.session_indexes == ("idx-1", "idx-2")
    # The in-flight SP logout is not the IdP's to burn.
    assert saml._peek_request(settings, "relay", kind="logout") is not None  # noqa: SLF001


def test_the_mfa_challenge_keeps_the_saml_subject_until_the_session_opens(tmp_path):
    from api.auth import create_pre_auth_token, decode_pre_auth_token
    from api.db import models
    from api.db.engine import get_session

    settings = make_settings(tmp_path)
    now = saml._now()
    with get_session(settings.postgres_url) as session:
        session.add(models.User(username="alice", created_at=now, updated_at=now))
    token = create_pre_auth_token(
        settings,
        "alice",
        ttl_minutes=5,
        saml_name_id="alice@example.com",
        saml_name_id_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        saml_session_index="idx-1",
    )
    challenge = decode_pre_auth_token(settings, token)
    assert challenge.saml_name_id == "alice@example.com"
    assert challenge.saml_name_id_format.endswith("persistent")
    assert challenge.saml_session_index == "idx-1"


def test_an_idp_logout_ends_only_families_with_that_name_id_and_index(tmp_path):
    from api.db import models
    from api.db.engine import get_session
    from api.services import sessions as sessions_service

    settings = make_settings(tmp_path)
    now = saml._now()
    with get_session(settings.postgres_url) as session:
        session.add(models.User(username="alice", created_at=now, updated_at=now))
        session.flush()
        for family_id, name_id, index in (
            ("alice-1", "alice@example.com", "idx-1"),
            ("alice-2", "alice@example.com", "idx-9"),
            ("bob", "bob@example.com", "idx-1"),
        ):
            session.add(
                models.SessionFamily(
                    family_id=family_id,
                    username="alice",
                    token_version=0,
                    created_at=now,
                    expires_at=now + timedelta(hours=1),
                    last_used_at=now,
                    saml_name_id=name_id,
                    saml_session_index=index,
                )
            )
    ended = sessions_service.end_saml_sessions(
        settings, name_id="alice@example.com", session_indexes=("idx-1",)
    )
    assert ended == ["alice-1"]
    with get_session(settings.postgres_url) as session:
        assert session.get(models.SessionFamily, "alice-1").revoked_at is not None
        assert session.get(models.SessionFamily, "alice-2").revoked_at is None
        assert session.get(models.SessionFamily, "bob").revoked_at is None


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
