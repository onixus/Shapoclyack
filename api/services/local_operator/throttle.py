"""Per-tenant budget for viewer-triggered semantic searches.

Every semantic ``GET`` costs one embedding inference on the single shared runtime,
and ``viewer`` may issue it. The budget is a sliding window held in process memory:
it bounds one API replica, which is the unit that talks to the runtime, and it is
deliberately not durable (a restart only resets the window).
"""
from __future__ import annotations

from collections import defaultdict, deque
import math
import threading
from time import monotonic

WINDOW_SECONDS = 60.0
DEFAULT_PER_WINDOW = 30
_MAX_TENANTS = 4096

_lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)


def reset():
    with _lock:
        _hits.clear()


def take(settings, tenant_id):
    """Spend one search for ``tenant_id``; return ``None`` or the seconds to wait."""
    limit = getattr(settings, "operator_semantic_queries_per_minute", DEFAULT_PER_WINDOW)
    if type(limit) is not int or limit < 1:
        limit = DEFAULT_PER_WINDOW
    now = monotonic()
    with _lock:
        if len(_hits) > _MAX_TENANTS:
            for key in [key for key, hits in _hits.items() if not hits or now - hits[-1] >= WINDOW_SECONDS]:
                del _hits[key]
        hits = _hits[tenant_id]
        while hits and now - hits[0] >= WINDOW_SECONDS:
            hits.popleft()
        if len(hits) >= limit:
            return max(1, math.ceil(WINDOW_SECONDS - (now - hits[0])))
        hits.append(now)
        return None
