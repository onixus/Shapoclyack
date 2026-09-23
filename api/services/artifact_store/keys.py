"""Every artifact key the product uses, built in one place.

Two reasons this is a module and not a handful of f-strings at the call sites.

The first is #311: run artifacts carry their owner in the key since #427
(``runs/_tenants/{tenant}/{run_id}``, see :class:`RunRef`), while the flat
``runs/{run_id}`` of every earlier release is still read. That is one edit here
and none anywhere else -- as long as nothing else ever writes
``"runs/" + run_id``.

The second is the local backend. A key's first segment says which directory it
lived in before object storage existed, because an installation that upgrades
must find its artifacts exactly where it left them. ``runs/`` and ``reports/``
are under ``OCTO_OUTPUT_DIR``; ``job_inputs/`` is under ``OCTO_STATE_DIR``. :data:`LOCAL_ROOT_BY_FAMILY` is that mapping, and the
factory hands it to :class:`~api.services.artifact_store.local.LocalArtifactStore`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from scanner.pipeline import run_ids

from .base import normalize_key

#: Artifact families. The first segment of every key is one of these.
#:
#: Materialised wordlists are deliberately absent. They are a pod-local scratch
#: copy of a row in Postgres, read only by a subprocess the same process
#: started -- see ``_wordlist_overrides`` in ``api/services/jobs.py``. A key for
#: them would be storage nothing ever fetches.
RUNS = "runs"
REPORTS = "reports"
JOB_INPUTS = "job_inputs"

#: Which of the two historical directories a family lived in. ``output`` is
#: ``settings.output_dir``, ``state`` is ``settings.state_dir``.
LOCAL_ROOT_BY_FAMILY = {
    RUNS: "output",
    REPORTS: "output",
    JOB_INPUTS: "state",
}


#: The namespace under ``runs/`` that holds tenant-scoped runs (#427).
#:
#: A segment of its own rather than ``runs/{tenant}/{run_id}`` directly, because
#: ``runs/`` already holds every run written before this -- one directory per
#: run id -- and tenant ids and run ids share one alphabet. A legacy run called
#: ``acme`` and a tenant called ``acme`` would be the *same prefix*: the old
#: run's listing would include the tenant's runs as its files, and deleting
#: the old run would delete them. The leading underscore is what keeps the two
#: apart -- a run id has to start with an alphanumeric
#: (:data:`scanner.pipeline.run_ids.RUN_ID_RE`), so no run can be named this.
TENANT_RUNS = "_tenants"

# The same shape a tenant id is validated against at creation
# (``tenants._validate_tenant_id``), and the reserved prefix of the encoded
# form -- the scheme ``nats_bus._subject_token`` uses for the same ids.
_TENANT_SEGMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_ENCODED_TENANT_PREFIX = "h_"


def tenant_segment(tenant_id: str) -> str:
    """The path segment that names ``tenant_id`` under :data:`TENANT_RUNS`.

    A tenant id that passes today's validation is used verbatim, so an
    operator reading the bucket sees the tenant. Ids that predate that
    validation (``acme.eu``) exist, and a path must not be built from them:
    they are hashed into the reserved ``h_`` namespace, injectively -- the
    replace-the-bad-characters shortcut would put ``acme.eu`` and ``acme_eu``
    in one directory. ``tenants.create_tenant`` refuses ids starting ``h_``,
    so an encoded segment never collides with a literal one.
    """
    value = str(tenant_id or "").strip()
    if not value:
        raise ValueError("tenant_id is required for a tenant-scoped run key")
    if _TENANT_SEGMENT_RE.fullmatch(value) and not value.startswith(_ENCODED_TENANT_PREFIX):
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    return f"{_ENCODED_TENANT_PREFIX}{digest}"


def _legacy_run_segment(run_id: str) -> str:
    """A run id for the flat pre-#427 location, or raise.

    Looser than :func:`scanner.pipeline.run_ids.validate` on purpose: the flat
    layout holds whatever the CLI was given as ``--run-id`` before anything
    checked it, and a run that was readable must stay readable. What it may not
    be is more than one segment, a hidden name, or anything starting with
    ``_`` -- the last because ``runs/_tenants`` read as one "legacy run" is
    every tenant's runs at once.
    """
    value = str(run_id or "")
    if not value or "/" in value or "\\" in value or value[0] in "._":
        raise ValueError(f"not a run id: {run_id!r}")
    return value


@dataclass(frozen=True)
class RunRef:
    """Where one run lives under ``runs/``.

    ``tenant`` is the owner's :func:`tenant_segment`, or ``None`` for a run in
    the flat location of every release before #427 -- whose owner is only
    ever what its ``tenant.json`` says. Build one with :func:`run_ref`; the
    constructor does not validate.
    """

    run_id: str
    tenant: str | None = None

    @property
    def path(self) -> str:
        """The run's path relative to ``runs/`` (and to a working-copy cache)."""
        if self.tenant is None:
            return self.run_id
        return f"{TENANT_RUNS}/{self.tenant}/{self.run_id}"


def run_ref(run_id: str, tenant_id: str | None = None) -> RunRef:
    """The location of ``run_id`` for ``tenant_id``; ``None`` is the flat layout.

    Both halves are validated here, because they become a path: the tenant is
    encoded by :func:`tenant_segment`, and a tenant-scoped run id must be one
    the product could have minted or accepted
    (:func:`scanner.pipeline.run_ids.validate`).
    """
    if tenant_id is None:
        return RunRef(_legacy_run_segment(run_id))
    return RunRef(run_ids.validate(str(run_id or "")), tenant_segment(tenant_id))


def as_ref(run: RunRef | str) -> RunRef:
    """``run`` as a :class:`RunRef`; a bare string is a run in the flat layout."""
    return run if isinstance(run, RunRef) else run_ref(run)


def run_prefix(run: RunRef | str) -> str:
    """The subtree holding one run's artifacts.

    A bare string is a run in the flat pre-#427 layout. That layout's id is
    checked only as far as :func:`_legacy_run_segment` goes, which is
    intentional: a run id that is merely odd (an id from an older scanner)
    still resolves to its own subtree, which is what a store should do with a
    name it does not recognise.
    """
    return normalize_key(f"{RUNS}/{as_ref(run).path}")


def run_artifact(run: RunRef | str, relative_path: str) -> str:
    """One file inside a run, e.g. ``summary.json`` or ``screenshots/a.png``."""
    return normalize_key(f"{run_prefix(run)}/{relative_path}")


def tenant_runs_prefix(segment: str | None = None) -> str:
    """``runs/_tenants``, or one tenant's subtree of it when ``segment`` is given."""
    if segment is None:
        return normalize_key(f"{RUNS}/{TENANT_RUNS}")
    return normalize_key(f"{RUNS}/{TENANT_RUNS}/{segment}")


def report_key(tenant_id: str, filename: str) -> str:
    """One generated report. Tenant-segmented since #292 -- reports were the
    first artifact family to carry the owner in the path, and the shape the
    rest are heading for (#311)."""
    return normalize_key(f"{REPORTS}/{tenant_id}/{filename}")


def report_key_from_storage_path(storage_path: str) -> str:
    """Key for a ``generated_reports.storage_path`` row.

    The column has always held a path relative to ``output_dir`` -- typically
    ``reports/<tenant>/<id>.pdf`` -- so the stored value *is* the key and no
    migration of the table is needed. Normalised rather than trusted: the
    column is old enough to hold rows written by code that predates the
    constraint.
    """
    return normalize_key(storage_path)


def job_inputs_prefix(job_id: str) -> str:
    """Target files, ports and the scan policy handed to one job's executor."""
    return normalize_key(f"{JOB_INPUTS}/{job_id}")


def job_input(job_id: str, filename: str) -> str:
    return normalize_key(f"{job_inputs_prefix(job_id)}/{filename}")


def family_of(key: str) -> str:
    """First segment of ``key``, or ``""`` when it has none."""
    normalized = normalize_key(key)
    head, _, _ = normalized.partition("/")
    return head
