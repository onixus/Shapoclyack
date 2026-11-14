"""Observers the sensor calls when the scanner package is installed.

Kept out of ``agent/`` on purpose: the sensor install does not include the
scanner package, and an import of it from ``agent/`` fails the install pin
check even when it is guarded. The worker loads this module and, if it is
absent, skips the lookalike queue.
"""

from __future__ import annotations

from scanner.brand_watch.http_observe import observe_http_or_refuse, refuse_reason
from scanner.brand_watch.observe import observe_dns

__all__ = ["observe_dns", "observe_http_or_refuse", "refuse_reason"]
