`idempotency_046.py` is the verbatim `api/services/idempotency.py` from the
published `shapoclyack-0.46-0922` Git tag. SHA-256:
`5ba68d7a07c28845d819edbbc1ae0e07a6fc4c205e6482a8872bd9c475b0fa04`.

`tests/test_migration_0082.py` loads this frozen service to exercise the old
reservation, completion, release and replay paths against the contracted
PostgreSQL schema alongside the current service. The hash assertion prevents
accidental modernization of the fixture. Shared ORM and engine dependencies
come from the current tree; this is a service/database compatibility test,
not a deployment of the full 0.46 image.
