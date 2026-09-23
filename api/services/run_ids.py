"""Run identifier minting and validation."""

from __future__ import annotations

# One minting function for every run in the product (#427): the scanner CLI
# mints its own run ids, and before this they were the bare second the server
# had given up in #421. The scanner owns the function because the scanner image
# ships without ``api/``; the API image ships both.
from scanner.pipeline.run_ids import RUN_ID_RE, mint, validate

__all__ = ["RUN_ID_RE", "confirm", "mint", "validate"]


def confirm(expected: str | None, offered: str | None) -> str | None:
    """Resolve the run id an upload lands in.

    The server decided the run id at ``start_scan`` or at the claim, and the
    agent only echoes it back. The echo is accepted as confirmation, never as
    a choice: before this check an agent could name any directory — another
    tenant's run, or a path outside ``runs/`` — and have its archive extracted
    there and the run's ``tenant.json`` rewritten to its own tenant.
    """
    if expected and offered and offered != expected:
        raise ValueError("run_id does not match the job")
    resolved = expected or offered
    if resolved:
        validate(str(resolved))
    return resolved
