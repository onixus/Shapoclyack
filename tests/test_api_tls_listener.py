"""The API's own TLS listener (``OCTO_API_TLS_CERT``/``_KEY``).

Terminating TLS in the API rather than only in an ingress is what lets an
installation without one serve HTTPS — a lab stand, a single-node deployment,
an appliance. It is also the precondition for a remotely offered agent upgrade
(#358): the build and the digest that vouches for it travel on the same
connection, so the agent refuses the whole mechanism over plain HTTP.

The behaviour worth testing is the refusal. A listener that was meant to be
encrypted and silently is not is worse than one that does not come up.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.__main__ import tls_options


def test_no_tls_configured_is_not_an_error(monkeypatch) -> None:
    monkeypatch.delenv("OCTO_API_TLS_CERT", raising=False)
    monkeypatch.delenv("OCTO_API_TLS_KEY", raising=False)
    assert tls_options() == {}


def test_both_halves_present_are_passed_through(tmp_path: Path, monkeypatch) -> None:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    monkeypatch.setenv("OCTO_API_TLS_CERT", str(cert))
    monkeypatch.setenv("OCTO_API_TLS_KEY", str(key))

    assert tls_options() == {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}


@pytest.mark.parametrize("missing", ["OCTO_API_TLS_CERT", "OCTO_API_TLS_KEY"])
def test_half_a_configuration_refuses_to_start(tmp_path: Path, monkeypatch, missing) -> None:
    """Someone who set one of the two meant to enable TLS.

    Starting in plaintext would hand them a listener they believe is
    encrypted — and every client that trusted it, an endpoint agent among
    them, would be right to have refused and would not know to.
    """
    present = tmp_path / "half.pem"
    present.write_text("x", encoding="utf-8")
    monkeypatch.setenv("OCTO_API_TLS_CERT", str(present))
    monkeypatch.setenv("OCTO_API_TLS_KEY", str(present))
    monkeypatch.delenv(missing, raising=False)

    with pytest.raises(SystemExit) as refusal:
        tls_options()
    assert missing in str(refusal.value)


def test_a_path_that_does_not_exist_refuses_to_start(tmp_path: Path, monkeypatch) -> None:
    """Caught here rather than by uvicorn, so the message names the file.

    A stand whose Secret failed to mount answers a bare stack trace otherwise,
    and the first guess is always the certificate's contents rather than its
    absence.
    """
    key = tmp_path / "tls.key"
    key.write_text("key", encoding="utf-8")
    monkeypatch.setenv("OCTO_API_TLS_CERT", str(tmp_path / "absent.crt"))
    monkeypatch.setenv("OCTO_API_TLS_KEY", str(key))

    with pytest.raises(SystemExit) as refusal:
        tls_options()
    assert "absent.crt" in str(refusal.value)
    assert "certificate" in str(refusal.value)
