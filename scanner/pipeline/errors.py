"""Pipeline-level exceptions."""

from __future__ import annotations


class PipelineError(Exception):
    """Base class for expected pipeline failures."""


class ConfigValidationError(PipelineError):
    """Invalid configuration."""


class StageFailureError(PipelineError):
    """An external tool stage failed after retries."""

    def __init__(self, stage: str, cause: Exception) -> None:
        super().__init__(f"stage '{stage}' failed: {cause}")
        self.stage = stage
        self.cause = cause
