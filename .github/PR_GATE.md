# Pull-request gate

`PR Gate / Python lint and unit tests` is the inexpensive check intended to run
on every pull request and merge-queue candidate.

It performs:

- the repository-wide Ruff check through `scripts/ci-lint.sh`, which also
  rejects syntax newer than Python 3.11 (`ruff.toml`), the oldest version the
  Jenkins matrix tests — the gate itself runs 3.12 only;
- `compileall` for `scanner`, `api`, `tests`, and `agent`;
- the pytest suite through `scripts/ci-pytest.sh` without PostgreSQL or NATS,
  with integration enforcement (`OCTO_REQUIRE_INTEGRATION=0`) and the coverage
  threshold (`COV_FAIL_UNDER=0`) explicitly disabled.

It does **not** replace the manually triggered full CI or Jenkins. Those runs
provide PostgreSQL/NATS integration coverage, SAST, web and manifest checks,
container builds, e2e/load tests, image scanning, and SBOM generation.

## Repository ruleset

After the workflow has produced its first successful check, edit the active
`main-lock` ruleset in repository settings:

1. target the `main` branch;
2. require changes to arrive through a pull request;
3. require the `Python lint and unit tests` status check to pass;
4. select the check from GitHub's observed-check list rather than typing a new
   context by hand;
5. keep deletion and non-fast-forward protection enabled.

The required-check rule is repository metadata and cannot be represented by a
committed workflow file. The regression test in `tests/test_pr_gate.py` protects
the part that can live in Git: it parses the workflow and compares the
triggers, the read-only permissions, the allowed job and step keys and the exact
list of commands, so `|| true`, `continue-on-error`, `if: false`, a narrowed
pytest or a widened token all fail it.
