"""``OCTO_HTTPS_PROXY`` / ``OCTO_CA_BUNDLE`` for the pipeline's own lookups (#359).

Two stages ask a *constant, always-external* service a question of their own
rather than probing a scan target: ``asn_discovery`` asks RIPEstat, and
``cloud_discovery`` asks S3, GCS and Azure Blob whether a bucket name exists.
On a network whose only way out is a proxy those two are the stages that fail,
and they failed without naming a setting because ``httpx`` reads the ambient
``HTTPS_PROXY`` but has never heard of the ``OCTO_`` overrides or of the
internal root an inspecting appliance signs with.

This is deliberately **not** a third copy of ``api/services/egress.py``. It
covers what those two stages need and says so:

- only the ``https://`` direction, because both endpoints are HTTPS;
- ``OCTO_NO_PROXY`` is not consulted — RIPEstat and the three object stores are
  never on the inside, so there is no exemption to express, and honouring half
  the dialect would be worse than honouring none of it;
- nothing here touches scan traffic. ``fingerprint`` talks to the customer's own
  hosts, and routing those through a corporate proxy would both break the scan
  and hand the proxy a copy of it; ``safe_http`` (``ownership``) refuses a proxy
  for a stronger reason still — it pins the address it validated, and a proxy
  resolves the name again.

``docs/network-requirements.md`` carries the same list in table form.
"""

from __future__ import annotations

import os
from typing import Any


def httpx_kwargs() -> dict[str, Any]:
    """``proxy``/``verify`` for an ``httpx`` client reaching a fixed external API.

    An empty mapping when neither variable is set, which leaves ``httpx`` with
    its own defaults: the ambient ``HTTPS_PROXY`` and the system trust store.
    """
    kwargs: dict[str, Any] = {}
    proxy = os.environ.get("OCTO_HTTPS_PROXY", "").strip()
    if proxy:
        kwargs["proxy"] = proxy if "://" in proxy else f"http://{proxy}"
    bundle = os.environ.get("OCTO_CA_BUNDLE", "").strip()
    if bundle:
        # Same refusal as the API's egress module: a bundle that is not there
        # is a typo worth a stack trace, not a silent fall back to the system
        # store and a handshake failure diagnosed hours later.
        if not os.path.isfile(bundle):
            raise ValueError(f"OCTO_CA_BUNDLE={bundle} is not a readable file")
        kwargs["verify"] = bundle
    return kwargs
