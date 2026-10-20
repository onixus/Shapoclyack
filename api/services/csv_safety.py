"""Spreadsheet-safe CSV cells shared by every CSV the API streams."""

from __future__ import annotations

import io
from typing import Any

# Leading characters a spreadsheet reads as the start of a formula rather than
# as text. Tab, CR and LF are here because Excel strips leading whitespace and
# control characters before deciding, so ``\t=cmd|...`` is a formula too.
FORMULA_CHARS = ("=", "+", "-", "@")
FORMULA_PREFIXES = (*FORMULA_CHARS, "\t", "\r")


def neutralize_cell(value: Any) -> Any:
    """Prefix an apostrophe when a spreadsheet would evaluate ``value``.

    The apostrophe is the convention every spreadsheet reads back as literal
    text. Non-string values pass through untouched.
    """
    if isinstance(value, str) and (
        value.startswith(("\t", "\r", "\n")) or value.lstrip().startswith(FORMULA_CHARS)
    ):
        return "'" + value
    return value


def drain(buffer: io.StringIO) -> str:
    """Return what the CSV writer buffered and reset the buffer for the next row."""
    value = buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    return value
