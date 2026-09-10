from __future__ import annotations

import logging
import os

import uvicorn

from api import __version__
from api.logging_setup import configure_logging, uvicorn_log_config


def main() -> None:
    host = os.environ.get("OCTO_API_HOST", "0.0.0.0")
    port = int(os.environ.get("OCTO_API_PORT", "8080"))
    # Before uvicorn.run(), because create_app() runs the fail-closed settings
    # checks and their refusal is the line an operator needs to see (#330).
    log_format, level = configure_logging()
    logging.getLogger("shapoclyack.api").info(
        "starting Shapoclyack API %s on %s:%s (log_format=%s level=%s)",
        __version__,
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
    )


if __name__ == "__main__":
    main()
