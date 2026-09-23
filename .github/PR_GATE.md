# Pull-request gate

`PR Gate / Python lint and unit tests` is the inexpensive check intended to run
on every pull request and merge-queue candidate.

It performs:

- the repository-wide Ruff check through `scripts/ci-lint.sh`;
- `compileall` for `scanner`, `api`, `tests`, and `agent`;
- the pytest suite without PostgreSQL or NATS, with integration enforcement
  explicitly disabled.

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
the part that can live in Git: the trigger, read-only permissions, shared lint,
and infrastructure-free test command.
