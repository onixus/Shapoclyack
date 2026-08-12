"""Outbound workflow integrations (ROADMAP P2 / Phase 10.3).

Phase 10.2 put asset-level events on JetStream. This package is the first
consumer of that stream: a per-tenant webhook fan-out with signed payloads,
bounded retries, a dead-letter queue and a delivery audit trail.

Module split:
  - ``delivery.py``  — the wire: URL validation (SSRF), HMAC signing, one POST
                       and the classification of its outcome. No database.
  - ``webhooks.py``  — subscriptions, routing policy, the delivery queue, and
                       the dispatch/retention sweeps. No NATS, no HTTP.
  - ``webhook_worker.py`` — the two background threads that connect the two:
                       a JetStream consumer that enqueues, and a timer that
                       dispatches.

Ticketing bridges (Jira/ServiceNow, the second half of 10.3) belong beside
``delivery.py`` as further transports over the same queue.
"""
