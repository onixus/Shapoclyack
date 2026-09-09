"""Every advisory-lock object id in the ``LOCK_CLASS_ID`` namespace is unique.

A worker's ``LeaderLock`` is session-scoped and held for the life of the
replica, so an id it shares with the migration lock turns every rolling update
into a deadlock: the new pod's init container waits for a lock the old pod
only releases when it terminates, and it terminates only once the new pod is
ready. That is exactly what happened when ``MIGRATION_LOCK_ID`` and
``REPORT_DISPATCHER_LOCK_ID`` were both ``2``.
"""

from __future__ import annotations

from api.db import migrate
from api.services import leader_lock


def test_advisory_lock_ids_are_unique() -> None:
    ids = {
        name: value
        for name, value in vars(leader_lock).items()
        if name.endswith("_LOCK_ID") and isinstance(value, int)
    }
    assert "MIGRATION_LOCK_ID" in ids, (
        "the migration lock must be registered with the worker locks"
    )
    assert migrate.MIGRATION_LOCK_ID == ids["MIGRATION_LOCK_ID"]
    duplicates = {v: [n for n, x in ids.items() if x == v] for v in ids.values()}
    clashes = {v: names for v, names in duplicates.items() if len(names) > 1}
    assert not clashes, f"advisory lock ids shared between locks: {clashes}"
