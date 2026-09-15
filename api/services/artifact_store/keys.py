"""Every artifact key the product uses, built in one place.

Two reasons this is a module and not a handful of f-strings at the call sites.

The first is #311: run artifacts are to become ``runs/{tenant}/{run_id}``, with
the existing flat directories migrated. That is one edit here and none
anywhere else -- as long as nothing else ever writes ``"runs/" + run_id``.

The second is the local backend. A key's first segment says which directory it
lived in before object storage existed, because an installation that upgrades
must find its artifacts exactly where it left them. ``runs/`` and ``reports/``
are under ``OCTO_OUTPUT_DIR``; ``job_inputs/`` is under ``OCTO_STATE_DIR``. :data:`LOCAL_ROOT_BY_FAMILY` is that mapping, and the
factory hands it to :class:`~api.services.artifact_store.local.LocalArtifactStore`.
"""

from __future__ import annotations

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


def run_prefix(run_id: str) -> str:
    """The subtree holding one run's artifacts.

    ``run_id`` is not sanitised beyond what :func:`normalize_key` does, and
    that is intentional: a run id arrives from a URL, and the store's refusal
    of ``..`` is the check that matters. A run id that is merely odd (an
    unexpected timestamp format, an id from an older scanner) still resolves
    to its own subtree, which is what a store should do with a name it does
    not recognise.
    """
    return normalize_key(f"{RUNS}/{run_id}")


def run_artifact(run_id: str, relative_path: str) -> str:
    """One file inside a run, e.g. ``summary.json`` or ``screenshots/a.png``."""
    return normalize_key(f"{run_prefix(run_id)}/{relative_path}")


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
