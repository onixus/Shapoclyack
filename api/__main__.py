from __future__ import annotations

import logging
import os
import ssl
from typing import Any

import uvicorn

from api import __version__
from api.logging_setup import configure_logging, uvicorn_log_config


def tls_options() -> dict[str, Any]:
    """TLS for the API's own listener, from ``OCTO_API_TLS_CERT``/``_KEY``.

    Terminating here rather than only in an ingress is what lets an
    installation without one — a lab stand, a single-node deployment, an
    appliance — serve HTTPS at all. It is also what an endpoint agent needs
    before it will accept a remotely offered upgrade (#358): the build and the
    digest that vouches for it travel on the same connection, so without TLS the
    verification proves nothing and the agent refuses.

    **Fail closed on a half-configuration.** A certificate with no key (or the
    reverse) is someone who meant to enable TLS; starting in plaintext would
    hand them a listener they believe is encrypted, which is worse than not
    starting.
    """
    cert = (os.environ.get("OCTO_API_TLS_CERT") or "").strip()
    key = (os.environ.get("OCTO_API_TLS_KEY") or "").strip()
    if not cert and not key:
        return {}
    if not cert or not key:
        missing = "OCTO_API_TLS_CERT" if not cert else "OCTO_API_TLS_KEY"
        raise SystemExit(
            f"Refusing to start: TLS is half-configured -- {missing} is unset. "
            "Set both, or neither; a listener that is meant to be encrypted and "
            "is not is worse than one that does not come up."
        )
    for label, path in (("certificate", cert), ("private key", key)):
        if not os.path.exists(path):
            raise SystemExit(f"Refusing to start: TLS {label} not found at {path}")
    return {"ssl_certfile": cert, "ssl_keyfile": key, **client_certificate_options()}


def client_certificate_options() -> dict[str, Any]:
    """Ask TLS clients for a sensor certificate, when sensors use one (#309).

    Only with ``OCTO_AGENT_MTLS_MODE`` other than ``off`` and a CA to verify
    against (``OCTO_AGENT_MTLS_CLIENT_CA``, else ``OCTO_AGENT_MTLS_ISSUER_CERT``).
    ``CERT_OPTIONAL`` and never ``CERT_REQUIRED``: the console and every API
    client share this listener and have no certificate, and *which* requests
    need one is decided per route (``api.auth``), not per connection. A
    certificate that is presented is verified by OpenSSL here — one from
    another CA fails the handshake — and handed to the application through
    :func:`api.core.client_cert.listener_protocol_class`.
    """
    mode = (os.environ.get("OCTO_AGENT_MTLS_MODE") or "off").strip().lower()
    ca = (os.environ.get("OCTO_AGENT_MTLS_CLIENT_CA") or "").strip() or (
        os.environ.get("OCTO_AGENT_MTLS_ISSUER_CERT") or ""
    ).strip()
    if mode == "off" or not ca:
        return {}
    if not os.path.exists(ca):
        raise SystemExit(f"Refusing to start: client CA bundle not found at {ca}")
    from api.core.client_cert import listener_protocol_class

    return {
        "ssl_cert_reqs": ssl.CERT_OPTIONAL,
        "ssl_ca_certs": ca,
        "http": listener_protocol_class(),
    }


def main() -> None:
    host = os.environ.get("OCTO_API_HOST", "0.0.0.0")
    port = int(os.environ.get("OCTO_API_PORT", "8080"))
    tls = tls_options()
    # Before uvicorn.run(), because create_app() runs the fail-closed settings
    # checks and their refusal is the line an operator needs to see (#330).
    log_format, level = configure_logging()
    logging.getLogger("shapoclyack.api").info(
        "starting Shapoclyack API %s on %s://%s:%s (log_format=%s level=%s)",
        __version__,
        "https" if tls else "http",
        host,
        port,
        log_format,
        logging.getLevelName(level),
    )
    if "ssl_ca_certs" in tls:
        logging.getLogger("shapoclyack.api").info(
            "TLS listener asks clients for a certificate issued by %s (optional per "
            "connection; OCTO_AGENT_MTLS_MODE decides which routes need one)",
            tls["ssl_ca_certs"],
        )
    uvicorn.run(
        "api.app:app",
        host=host,
        port=port,
        reload=False,
        # One process per replica, whatever WEB_CONCURRENCY says: uvicorn reads
        # it when ``workers`` is left out, and N workers behind one port would
        # each answer a scrape with their own counters — different numbers on
        # every scrape, under one ``instance`` (#334). Scale with replicas.
        workers=1,
        # Without this uvicorn installs its own colourised formatters, so
        # `uvicorn.access` ended up in a different shape from every other line
        # and never met the redaction filter — which is what masks a `?token=`
        # in a logged request line.
        log_config=uvicorn_log_config(log_format=log_format, level=level),
        **tls,
    )


if __name__ == "__main__":
    main()
