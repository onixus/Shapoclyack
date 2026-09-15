from __future__ import annotations

import logging
import os

import uvicorn

from api import __version__
from api.logging_setup import configure_logging, uvicorn_log_config


def tls_options() -> dict[str, str]:
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
    return {"ssl_certfile": cert, "ssl_keyfile": key}


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
    uvicorn.run(
        "api.app:app",
        host=host,
        port=port,
        reload=False,
        # Without this uvicorn installs its own colourised formatters, so
        # `uvicorn.access` ended up in a different shape from every other line
        # and never met the redaction filter — which is what masks a `?token=`
        # in a logged request line.
        log_config=uvicorn_log_config(log_format=log_format, level=level),
        **tls,
    )


if __name__ == "__main__":
    main()
