"""Drop the console overrides that only the removed Nmap stage understood (#548).

``config_overrides.data`` is the installation-wide set of settings the console
saved. Two of its editable paths no longer name anything: a profile's
``nmap_timing`` and ``service_probe.shadow``. The scanner now refuses a config
that carries either (it does not ignore them), so a row that kept them would
fail every scan until someone re-saved the configurator -- and the configurator
no longer lists them, so nobody would know to.

Contract step for those two keys only, and the only data this release removes:
the keys are deleted from the stored document, nothing else in it changes.
``service_probe.backend`` is *not* touched: a stored ``nmap``/``hybrid`` there
is a choice the operator has to make again (it stays editable, as ``pulse``),
and the scan failure names it. The downgrade is a no-op -- the values were
meaningless without the Nmap stage and are not recoverable.
"""

import sqlalchemy as sa
from alembic import op

revision = "0085_drop_nmap_config_overrides"
down_revision = "0084_asset_service_distro"
branch_labels = None
depends_on = None


def strip_removed_keys(data):
    """``data`` without ``profiles.*.nmap_timing`` and ``service_probe.shadow``; ``None`` if unchanged."""
    if not isinstance(data, dict):
        return None
    changed = False
    out = dict(data)
    profiles = out.get("profiles")
    if isinstance(profiles, dict):
        cleaned = {}
        for name, settings in profiles.items():
            if isinstance(settings, dict) and "nmap_timing" in settings:
                settings = {k: v for k, v in settings.items() if k != "nmap_timing"}
                changed = True
            cleaned[name] = settings
        out["profiles"] = cleaned
    probe = out.get("service_probe")
    if isinstance(probe, dict) and "shadow" in probe:
        out["service_probe"] = {k: v for k, v in probe.items() if k != "shadow"}
        changed = True
    return out if changed else None


def upgrade():
    table = sa.table("config_overrides", sa.column("scope", sa.String), sa.column("data", sa.JSON))
    bind = op.get_bind()
    for scope, data in bind.execute(sa.select(table.c.scope, table.c.data)).all():
        cleaned = strip_removed_keys(data)
        if cleaned is not None:
            bind.execute(sa.update(table).where(table.c.scope == scope).values(data=cleaned))


def downgrade():
    pass
