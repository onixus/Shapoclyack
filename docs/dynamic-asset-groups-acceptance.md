# Dynamic asset groups: issue #578 acceptance

This matrix maps the issue's requirements to executable checks. Commands run
from the repository root against a disposable, migrated PostgreSQL database;
tenant/RLS and concurrency checks require the real database. See
[the operational contract](dynamic-asset-groups.md) for source authority,
freshness, context ownership, batch limits and continuation semantics.

| Requirement | Evidence |
| --- | --- |
| Typed AND/OR conditions, unknown never matching, strict API validation | `tests/test_asset_group_rules.py`; OS source/freshness negatives in `tests/test_asset_groups_os.py`; rule-editor workflow tests |
| Read-only preview of entrants/exits/context/conflicts | `test_preview_does_not_write_and_replay_is_idempotent`; browser preview/save/recalculate scenario |
| Automatic discovery, exclusion, restart and replay | `test_actual_worker_tick_discovers_excludes_and_preserves_manual_override`; persisted-cursor rollback/restart tests |
| Deterministic priorities and protected manual/CMDB values | `test_priority_conflict_never_writes_and_tenant_ids_are_checked`; context ownership/release tests; `test_asset_groups_import_ownership.py` covers CMDB same-value ownership, replay, conflicts, omissions and manual-source protection |
| Versioned immutable provenance and safe disable/delete | Assignment receipt/version/release tests in both `test_asset_groups.py` and `test_asset_groups_integration.py` |
| No exposure inference | Closed assignment validator rejects `exposure_level`; OS tests use only confirmed endpoint inventory; context conditions remain explicit |
| Preserve finding identity, history, SLA, exceptions and recorded risk | `test_classification_preserves_finding_identity_sla_history_and_captured_risk` compares all persisted finding/event/risk columns and historical API output; current risk uses standard context |
| Group membership grants no scanning permission | `test_classified_group_targets_still_pass_scope_deny_and_scan_policy`: real job admission refuses denied/out-of-scope targets and unsafe profiles; no job created |
| Tenant and role isolation for data and writes | Foreign group ID operations, API viewer mutation refusals, OS snapshot tenant joins, RLS/purge suites and `test_asset_groups_privacy.py` export/erasure isolation with immutable tenant records |
| UI errors, partial/stale results, rule versions, pagination and keyboard | `web-next/src/components/asset/asset-groups.test.tsx`, API-client tests and real-browser acceptance; effective account/tenant changes reset state |
| Full discovery→assignment→exclusion→manual override→replay flow, concurrency and bounded batch | Actual worker integration flow; concurrent manual writer; 503-asset keyset fixture; measured query count independent of page size |

## Reproduction

Use separate databases for concurrent test runs. Test startup resets shared
accounts and fixtures, so running independent suites against one database can
produce misleading authentication and row-count failures.

```sh
python -m api.db.migrate
python -m pytest -q \
  tests/test_asset_group_rules.py tests/test_asset_group_worker.py \
  tests/test_asset_groups.py tests/test_asset_groups_os.py \
  tests/test_asset_groups_import_ownership.py \
  tests/test_asset_groups_privacy.py tests/test_data_subject.py \
  tests/test_asset_groups_integration.py tests/test_asset_import.py \
  tests/test_tenant_rls.py tests/test_tenant_purge.py \
  tests/test_migration_0067_tenant_rls.py tests/test_lock_ids.py \
  tests/test_settings_cli.py tests/test_api_v1_exports.py
PYTHON=python scripts/ci-sdk.sh
cd web-next
npm run typecheck
npm run lint
npm test
npm run build
```

Set `OCTO_POSTGRES_URL` to the disposable database before the migration and
backend checks. The full project pipeline additionally supplies NATS and its
other fixtures; a narrowed local run does not replace its integration gate.
Final immutable commit, CI runs and actual pass/skip counts are recorded in
PR #605 after all final checks complete. Skipped checks are not treated as
executed acceptance evidence.

## Runtime and deployment boundary

The accepted contract is bounded inventory classification and assignment over
existing identities. The synthetic benchmark documents the exercised volume;
it does not claim unmeasured production throughput or deploy to customer
infrastructure. No network scan is performed by the classifier. Actual scan
requests remain subject to existing scope, deny, maintenance and policy gates.
