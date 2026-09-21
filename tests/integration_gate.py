"""The integration gate: a session that declares infrastructure has to show for it.

Skipping is the right default on a laptop, but it makes an exit code ambiguous:
``pytest`` prints the same green whether the Postgres-backed suites ran or were
skipped wholesale, so CI proving "exit 0" proved nothing about tenant isolation
or row locks. Setting ``OCTO_REQUIRE_INTEGRATION=1`` (scripts/ci-pytest.sh does)
declares the infrastructure available, and then:

* before collection, a missing URL fails the run outright;
* at the end, a gated suite that collected nothing, skipped anything, or left
  anything unexecuted fails the run.

The hooks live here rather than in tests/conftest.py so a test can drive them
through a real pytest session (tests/test_ci_checks.py writes a throwaway suite
whose conftest imports this module). tests/conftest.py re-exports them, which is
what registers them for the repository's own runs.

"Unexecuted" is the part that has to be measured rather than inferred. The first
version of this gate computed ``ran = collected - skipped``, and ``collected``
is filled in by :func:`pytest_collection_modifyitems`, which runs *before*
``-k``/``-m`` deselection — so ``pytest -k something`` reported the whole suite
as having run and sailed through the gate with two tests executed. Execution is
now recorded per test id in :func:`pytest_runtest_logreport`, and anything
collected that neither ran nor skipped is a deselection, which under the flag is
exactly as bad as a skip.
"""

from __future__ import annotations

import os

import pytest

# Suite name -> the environment variable its skip reason names. The suites are
# recognised by that variable appearing in the skipif reason rather than by a
# marker of their own: the reasons are already written for humans, and tagging
# 307 call sites a second time would be a worse thing to keep correct than this.
# The wording is therefore API — tests/test_ci_checks.py asserts it against the
# marks themselves.
INTEGRATION_SUITES: dict[str, str] = {
    "postgres": "OCTO_POSTGRES_URL",
    "nats": "OCTO_NATS_URL",
}

# Fallback names the marks accept, so the gate recognises a suite gated on the
# bare variable too (tests/test_nats_live.py takes OCTO_NATS_URL or NATS_URL).
_SUITE_URL_VARS: dict[str, tuple[str, ...]] = {
    "postgres": ("OCTO_POSTGRES_URL", "POSTGRES_URL"),
    "nats": ("OCTO_NATS_URL", "NATS_URL"),
}

_collected: dict[str, set[str]] = {name: set() for name in INTEGRATION_SUITES}
_executed: dict[str, set[str]] = {name: set() for name in INTEGRATION_SUITES}
_skipped: dict[str, set[str]] = {name: set() for name in INTEGRATION_SUITES}


def require_integration() -> bool:
    """Whether the caller declared the integration infrastructure available."""
    return os.environ.get("OCTO_REQUIRE_INTEGRATION", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def suite_for_reason(reason: str) -> str | None:
    """The gated suite a skipif ``reason`` belongs to, if any."""
    for name, var in INTEGRATION_SUITES.items():
        if var in reason:
            return name
    return None


def integration_gate_problems(counts: dict[str, tuple[int, int, int]]) -> list[str]:
    """Describe why ``counts`` fails the gate, or return an empty list.

    ``counts`` maps a suite name to ``(collected, executed, skipped)``. Kept
    separate from the hooks so the arithmetic is readable on its own; the hooks
    themselves are covered by real sessions in tests/test_ci_checks.py.

    There is deliberately no numeric floor. An earlier version required 1000
    Postgres tests against a current count of 1232: a number nobody would keep
    right, whose only repair when it went red was to edit the number itself.
    What it was really guarding — "the mark stopped applying and the gate passed
    on an empty set" — is the ``collected == 0`` check below, which needs no
    maintenance, and the execution check catches the rest.
    """
    problems: list[str] = []
    for name, var in INTEGRATION_SUITES.items():
        collected, executed, skipped = counts.get(name, (0, 0, 0))
        if collected == 0:
            problems.append(
                f"{name}: no tests recognised as gated on {var}. Either the suite "
                "is gone or a skip reason was reworded — the gate matches on that "
                "wording (tests/integration_gate.py)"
            )
            continue
        if skipped:
            problems.append(
                f"{name}: {skipped} of {collected} tests skipped although {var} "
                "is declared available"
            )
        unexecuted = collected - executed - skipped
        if unexecuted > 0:
            problems.append(
                f"{name}: {unexecuted} of {collected} tests never ran (deselected "
                f"by -k/-m, or the session stopped early) although {var} is "
                "declared available"
            )
    return problems


def integration_counts() -> dict[str, tuple[int, int, int]]:
    return {
        name: (len(_collected[name]), len(_executed[name]), len(_skipped[name]))
        for name in INTEGRATION_SUITES
    }


def reset_for_tests() -> None:
    """Drop the recorded session state (tests/test_ci_checks.py)."""
    for state in (_collected, _executed, _skipped):
        for nodes in state.values():
            nodes.clear()


def pytest_configure(config) -> None:  # noqa: ARG001 - pytest hook signature
    """Refuse a declared-integration run that has nothing to run against.

    Fails here rather than at the end: the matrix stage takes minutes, and a
    missing URL is knowable before the first test.
    """
    if not require_integration():
        return
    missing = [
        names[0]
        for names in _SUITE_URL_VARS.values()
        if not any((os.environ.get(name) or "").strip() for name in names)
    ]
    if missing:
        raise pytest.UsageError(
            f"OCTO_REQUIRE_INTEGRATION declares the integration infrastructure "
            f"available, but {', '.join(missing)} is unset. Point it at the test "
            "database/broker, or drop the flag — a run that skips those suites "
            "must not report success."
        )


def pytest_collection_modifyitems(config, items) -> None:  # noqa: ARG001 - pytest hook signature
    for item in items:
        reasons = " ".join(
            str(mark.kwargs.get("reason", "")) for mark in item.iter_markers("skipif")
        )
        name = suite_for_reason(reasons)
        if name is not None:
            _collected[name].add(item.nodeid)


def pytest_runtest_logreport(report) -> None:
    for name, nodes in _collected.items():
        if report.nodeid not in nodes:
            continue
        if report.when == "setup" and report.skipped:
            # Where a skipif mark takes effect.
            _skipped[name].add(report.nodeid)
        elif report.when == "call" or (report.when == "setup" and report.failed):
            # A test that errored in setup still executed as far as the gate is
            # concerned: the session is red for a reason that names itself.
            _executed[name].add(report.nodeid)


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:  # noqa: ARG001
    if not require_integration():
        return
    counts = integration_counts()
    problems = integration_gate_problems(counts)
    terminalreporter.section("integration gate")
    for name, (collected, executed, skipped) in sorted(counts.items()):
        terminalreporter.write_line(
            f"{name}: {executed} ran, {skipped} skipped, "
            f"{collected - executed - skipped} never ran, {collected} collected"
        )
    for problem in problems:
        terminalreporter.write_line(f"FAILED {problem}", red=True)


def pytest_sessionfinish(session, exitstatus) -> None:  # noqa: ARG001 - pytest hook signature
    if not require_integration():
        return
    if integration_gate_problems(integration_counts()):
        # Only ever upgrades green to red: a run already failing for its own
        # reasons keeps the status that names the real cause.
        if session.exitstatus == 0:
            session.exitstatus = 1
