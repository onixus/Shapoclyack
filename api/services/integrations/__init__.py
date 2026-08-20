"""Outbound workflow integrations (ROADMAP P2 / Phase 10.3).

Phase 10.2 put asset-level events on JetStream. This package is the first
consumer of that stream: a per-tenant webhook fan-out with signed payloads,
bounded retries, a dead-letter queue and a delivery audit trail.

Module split:
  - ``delivery.py``  — the wire: URL validation (SSRF), HMAC signing, one POST
                       and the classification of its outcome. No database.
  - ``webhooks.py``  — subscriptions, routing policy, the delivery queue, and
                       the dispatch/retention sweeps. No NATS, no HTTP.
  - ``secure_webhooks.py`` — P0 security facade for write-only header values
                       and the subscription disable kill switch.
  - ``webhook_worker.py`` — the two background threads that connect the two:
                       a JetStream consumer that enqueues, and a timer that
                       dispatches.

Ticketing bridges (Jira/ServiceNow/DefectDojo, the second half of 10.3) live
in ``tickets.py`` as further transports over the same queue.
"""

# Existing callers use ``from api.services.integrations import webhooks``.
# Export the hardened facade under that name so routes, workers and tests all
# cross the same security boundary without a parallel API surface.
from . import secure_webhooks as webhooks

__all__ = ["webhooks"]
