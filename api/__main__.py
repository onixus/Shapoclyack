from __future__ import annotations

import functools
import logging
import os
import ssl
from typing import Any, Callable

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

    Whenever there is a CA to verify against (``OCTO_AGENT_MTLS_CLIENT_CA``,
    else ``OCTO_AGENT_MTLS_ISSUER_CERT``) — in every ``OCTO_AGENT_MTLS_MODE``,
    ``off`` included. Enrolment's rule does not depend on the mode: a renewal
    must present the current certificate, and the rollout enrols the fleet
    under ``off`` (docs/operations.md § Sensor client certificates). A
    listener that asked for no certificate under ``off`` turned every such
    renewal into "presented none while holding a live one": refused, and
    audited as a conflict, fleet-wide.

    ``CERT_OPTIONAL`` and never ``CERT_REQUIRED``: the console and every API
    client share this listener and have no certificate, and *which* requests
    need one is decided per route (``api.auth``), not per connection. A
    certificate that is presented is verified by OpenSSL here — one from
    another CA fails the handshake — and handed to the application through
    :func:`api.core.client_cert.listener_protocol_class`. The context itself
    is :func:`_client_ca_context`'s.
    """
    client_ca = (os.environ.get("OCTO_AGENT_MTLS_CLIENT_CA") or "").strip()
    issuer = (os.environ.get("OCTO_AGENT_MTLS_ISSUER_CERT") or "").strip()
    ca = client_ca or issuer
    crl = (os.environ.get("OCTO_AGENT_MTLS_CRL") or "").strip()
    if not ca:
        if crl:
            raise SystemExit(
                "Refusing to start: OCTO_AGENT_MTLS_CRL requires a client CA"
            )
        return {}
    for path in (client_ca, issuer):
        if path and not os.path.exists(path):
            raise SystemExit(f"Refusing to start: client CA bundle not found at {path}")
    from api.core.client_cert import listener_protocol_class

    extra = issuer if client_ca and issuer and issuer != client_ca else ""
    return {
        "ssl_cert_reqs": ssl.CERT_OPTIONAL,
        "ssl_ca_certs": ca,
        "ssl_context_factory": functools.partial(
            _client_ca_context, extra_anchor=extra, crl_path=crl
        ),
        "http": listener_protocol_class(),
    }


def _client_ca_context(
    config: uvicorn.Config,
    default_factory: Callable[[], ssl.SSLContext],
    *,
    extra_anchor: str,
    crl_path: str = "",
) -> ssl.SSLContext:
    """uvicorn's context, with the client-certificate checks it has no option for.

    ``VERIFY_X509_PARTIAL_CHAIN``: OpenSSL otherwise takes only a self-signed
    certificate as a trust anchor, so a client CA that is an intermediate —
    what docs/operations.md asks the issuer to be — failed every handshake
    that presented a certificate, on every route. Everything in the bundle is
    an anchor the operator chose, which is what the bundle means.

    ``extra_anchor`` is the issuer, when a client CA is set as well: a sensor
    enrolled before it presented its chain sends the leaf alone, and with a
    root as the client CA nothing would link the two. Start-up has checked
    that the issuer chains to the client CA (``api.settings``), so this widens
    nothing. Only its first certificate is loaded — the one the API signs
    with.
    """
    context = default_factory()
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    if extra_anchor:
        from cryptography.hazmat.primitives.serialization import Encoding

        from api.core.client_cert import load_ca_bundle

        first = load_ca_bundle(extra_anchor)[0]
        context.load_verify_locations(
            cadata=first.public_bytes(Encoding.PEM).decode("ascii")
        )
    if crl_path:
        from api.core.crl import validate_bundle
        from api.core.client_cert import load_ca_bundle

        try:
            with open(crl_path, "rb") as handle:
                data = handle.read()
            authorities = list(load_ca_bundle(config.ssl_ca_certs))
            if extra_anchor:
                authorities.extend(load_ca_bundle(extra_anchor))
            validate_bundle(data, authorities)
            context.load_verify_locations(cafile=crl_path)
            context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
            # Resumed sessions can retain the old certificate verification
            # result. Require a new client-certificate check after restart.
            context.options |= ssl.OP_NO_TICKET
            context.num_tickets = 0
        except (OSError, ValueError) as exc:
            raise SystemExit(
                f"Refusing to start: unusable client CRL at {crl_path}: {exc}"
            ) from exc
    return context


def listener_options() -> dict[str, Any]:
    """What ``main`` hands ``uvicorn.run``, from the environment.

    The peer-recording protocol is installed with or without TLS: behind an
    ingress the trusted-proxy check reads the socket's address from it
    (:func:`api.core.client_cert.socket_peer`), never the one uvicorn's
    proxy-headers middleware writes into ``scope["client"]`` from
    ``X-Forwarded-For``.
    """
    from api.core.client_cert import listener_protocol_class

    return {
        "host": os.environ.get("OCTO_API_HOST", "0.0.0.0"),
        "port": int(os.environ.get("OCTO_API_PORT", "8080")),
        "http": listener_protocol_class(),
        **tls_options(),
    }


def main() -> None:
    options = listener_options()
    # Before uvicorn.run(), because create_app() runs the fail-closed settings
    # checks and their refusal is the line an operator needs to see (#330).
    log_format, level = configure_logging()
    logging.getLogger("shapoclyack.api").info(
        "starting Shapoclyack API %s on %s://%s:%s (log_format=%s level=%s)",
        __version__,
        "https" if "ssl_certfile" in options else "http",
        options["host"],
        options["port"],
        log_format,
        logging.getLevelName(level),
    )
    if "ssl_ca_certs" in options:
        logging.getLogger("shapoclyack.api").info(
            "TLS listener asks clients for a certificate issued by %s (optional per "
            "connection; OCTO_AGENT_MTLS_MODE decides which routes need one)",
            options["ssl_ca_certs"],
        )
    uvicorn.run(
        "api.app:app",
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
        **options,
    )


if __name__ == "__main__":
    main()
