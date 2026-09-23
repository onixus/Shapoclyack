#!/usr/bin/env python3
"""Record service fingerprints from the runs an installation already has.

Run once, after upgrading into retro CVE matching (docs/retro-cve-matching.md).
From the upgrade on, every succeeded run records its listeners as it is
projected; this reads the ones that finished *before*, oldest first, from the
artifact store (local volume or S3 — wherever ``OCTO_ARTIFACT_BACKEND`` points),
so a CVE published tomorrow is checked against the estate as last scanned and
not only against hosts scanned since the upgrade.

    python3 scripts/backfill-asset-services.py                  # every tenant
    python3 scripts/backfill-asset-services.py --tenant acme --limit 200

Safe to re-run and safe to run beside a live API: a listener is keyed by
``(tenant, asset, port, protocol)``, an older run never overwrites what a newer
one recorded, and a re-run of the same run changes nothing. Only runs still
inside ``run_retention_days`` can be read — the rest are counted ``missing``,
which is the reason this table exists at all. The retro worker picks the new
rows up on its next tick; nothing has to be restarted.

Exit codes: 0 done (even with ``missing`` runs), 1 some runs could not be
read (``failed``; details in the log), 2 no database configured.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.services import asset_services  # noqa: E402
from api.services import tenants as tenants_service  # noqa: E402
from api.settings import load_settings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tenant", action="append", default=[], help="Tenant id (repeatable; default: all)")
    parser.add_argument("--limit", type=int, default=None, help="At most this many runs per tenant, oldest first")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    settings = load_settings()
    if not settings.postgres_url.strip():
        print("OCTO_POSTGRES_URL is not set; fingerprints are stored in Postgres.", file=sys.stderr)
        return 2
    tenants_service.configure(settings)
    tenant_ids = args.tenant or [t["tenant_id"] for t in tenants_service.list_tenants()]

    failed = 0
    for tenant_id in tenant_ids:
        totals = asset_services.backfill_tenant(settings, tenant_id=tenant_id, limit=args.limit)
        failed += totals["failed"]
        print(
            f"{tenant_id:<24} runs {totals['runs']:>5}  missing {totals['missing']:>5}  "
            f"failed {totals['failed']:>3}  listeners {totals['seen']:>6}  "
            f"new {totals['created']:>6}  changed {totals['changed']:>5}  "
            f"no asset {totals['skipped']:>5}"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
