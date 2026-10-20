# API changelog

## Unreleased — API v1 (#354)

- Add `/api/v1` aliases for every enabled unversioned API resource. Existing
  `/api` callers continue to work with the same authorization and middleware.
- Establish current/previous major support with a minimum twelve-month
  deprecation window. Configured legacy schedules emit Deprecation/Sunset;
  no v1 retirement date is announced.
- Add tenant-scoped asset and vulnerability CSV/NDJSON export pages, signed
  expiring keyset cursors, safe CSV cells and browser-visible continuation.
- Ship a generated Python operation client and `shapoclyack` CLI, with
  deterministic offline regeneration from OpenAPI.

See [API policy and integration instructions](api-versioning.md) for the
export columns, pagination consistency and generated transport boundaries.
