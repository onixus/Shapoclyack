"""Integration gate contracts, exercised through real pytest subprocesses."""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests import integration_gate
from tests.conftest import requires_postgres
from tests.integration_gate import INTEGRATION_SUITES, integration_gate_problems, suite_for_reason

REPO_ROOT = Path(__file__).resolve().parents[1]


_GATED_SUITE = """\
import os

import pytest

pytestmark = pytest.mark.skipif(
    {condition},
    reason={reason!r},
)

{tests}
"""


def _write_gated_suite(
    directory: Path,
    *,
    postgres_reason: str = "OCTO_POSTGRES_URL not set (throwaway suite)",
    nats_reason: str = "OCTO_NATS_URL not set (throwaway suite)",
    postgres_condition: str = 'not os.environ.get("OCTO_POSTGRES_URL")',
) -> None:
    """A miniature stand-in for the repository's gated suites.

    Three Postgres-gated tests and two NATS-gated ones, marked the way the real
    ones are: a module-level ``skipif`` whose reason names the variable. The
    conftest imports the gate module itself, so what runs here is the code that
    runs in CI, hooks included.
    """
    (directory / "conftest.py").write_text(
        "from tests.integration_gate import (\n"
        "    pytest_collection_modifyitems,\n"
        "    pytest_configure,\n"
        "    pytest_runtest_logreport,\n"
        "    pytest_sessionfinish,\n"
        "    pytest_terminal_summary,\n"
        ")\n",
        encoding="utf-8",
    )
    (directory / "test_gated_postgres.py").write_text(
        _GATED_SUITE.format(
            condition=postgres_condition,
            reason=postgres_reason,
            tests="\n".join(f"def test_pg_{n}():\n    pass\n" for n in range(3)),
        ),
        encoding="utf-8",
    )
    (directory / "test_gated_nats.py").write_text(
        _GATED_SUITE.format(
            condition='not os.environ.get("OCTO_NATS_URL")',
            reason=nats_reason,
            tests="\n".join(f"def test_nats_{n}():\n    pass\n" for n in range(2)),
        ),
        encoding="utf-8",
    )


def _run_gate(
    directory: Path, *args: str, env: dict[str, str | None] | None = None, **kwargs
) -> subprocess.CompletedProcess[str]:
    """Run pytest over the throwaway suite and return the finished process."""
    _write_gated_suite(directory, **kwargs)
    child_env = dict(
        os.environ,
        PYTHONPATH=str(REPO_ROOT),
        OCTO_REQUIRE_INTEGRATION="1",
        OCTO_POSTGRES_URL="postgresql://gate.invalid/none",
        OCTO_NATS_URL="nats://gate.invalid:4222",
    )
    for key, value in (env or {}).items():
        if value is None:
            child_env.pop(key, None)
        else:
            child_env[key] = value
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:randomly", "-p", "no:cacheprovider", *args],
        cwd=directory,
        env=child_env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_fully_executed_run_passes_the_gate(tmp_path: Path):
    result = _run_gate(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "postgres: 3 ran, 0 skipped, 0 never ran, 3 collected" in result.stdout
    assert "nats: 2 ran, 0 skipped, 0 never ran, 2 collected" in result.stdout


def _write_manual_runtime_case(directory: Path, *, forced_skip=False):
    body = "pytest.skip('runtime deliberately unavailable')" if forced_skip else "pass"
    (directory / "test_manual_runtime.py").write_text(
        "import os, pytest\n"
        "pytestmark = [pytest.mark.operator_runtime,\n"
        " pytest.mark.skipif(not os.environ.get('OCTO_POSTGRES_URL'), reason='OCTO_POSTGRES_URL not set'),\n"
        " pytest.mark.skipif(os.environ.get('OCTO_OPERATOR_EMBEDDING_ACCEPTANCE') != '1',\n"
        " reason='OCTO_OPERATOR_EMBEDDING_ACCEPTANCE=1 requires provisioned pinned local runtime')]\n"
        "def test_manual_hardware():\n " + body + "\n"
    )


def test_manual_runtime_skip_is_visible_separately_and_does_not_claim_postgres_execution(tmp_path):
    _write_manual_runtime_case(tmp_path)
    result = _run_gate(tmp_path, env={"OCTO_OPERATOR_EMBEDDING_ACCEPTANCE": None})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "postgres: 3 ran, 0 skipped, 0 never ran, 3 collected" in result.stdout
    assert "operator_runtime: 0 ran, 1 skipped, 0 never ran, 1 collected; manual pinned-runtime gate not provisioned" in result.stdout


@pytest.mark.parametrize("forced_skip", [False, True])
def test_explicit_runtime_opt_in_requires_its_case_to_really_execute(tmp_path, forced_skip):
    _write_manual_runtime_case(tmp_path, forced_skip=forced_skip)
    result = _run_gate(tmp_path, env={"OCTO_OPERATOR_EMBEDDING_ACCEPTANCE": "1"})
    if forced_skip:
        assert result.returncode != 0
        assert "FAILED operator_runtime: 0 ran, 1 skipped" in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "operator_runtime: 1 ran, 0 skipped, 0 never ran, 1 collected; explicit pinned-runtime opt-in" in result.stdout


def test_explicit_runtime_opt_in_cannot_pass_with_no_hardware_case_collected(tmp_path):
    result = _run_gate(tmp_path, env={"OCTO_OPERATOR_EMBEDDING_ACCEPTANCE": "1"})
    assert result.returncode != 0
    assert "0 collected although OCTO_OPERATOR_EMBEDDING_ACCEPTANCE=1" in result.stdout


def test_manual_marker_cannot_hide_an_ordinary_postgres_case_without_explicit_runtime_reason(tmp_path):
    (tmp_path / "test_bad_manual.py").write_text(
        "import pytest\n@pytest.mark.operator_runtime\n"
        "@pytest.mark.skipif(True, reason='OCTO_POSTGRES_URL not set')\n"
        "def test_wrong_scope():pass\n"
    )
    result = _run_gate(tmp_path)
    assert result.returncode != 0
    assert "operator_runtime must retain its explicit pinned-runtime opt-in skip reason" in result.stdout + result.stderr


def test_skip_inside_an_ordinary_postgres_test_call_still_fails_the_gate(tmp_path):
    (tmp_path / "test_pg_call_skip.py").write_text(
        "import pytest\n"
        "pytestmark = pytest.mark.skipif(False, reason='OCTO_POSTGRES_URL declared available')\n"
        "def test_unexecuted_database_contract():pytest.skip('not actually exercised')\n"
    )
    result = _run_gate(tmp_path)
    assert result.returncode != 0
    assert "postgres: 3 ran, 1 skipped, 0 never ran, 4 collected" in result.stdout


def test_a_selection_that_runs_two_tests_cannot_pass_as_the_whole_suite(tmp_path: Path):
    """The hole this gate had: ``-k`` deselects after the collection hook counted.

    ``scripts/ci-pytest.sh`` passes the caller's arguments through, so a stage
    added as `COV_FAIL_UNDER=0 scripts/ci-pytest.sh -k "not slow"` used to print
    "postgres: 1232 ran" and exit 0 with two tests executed.
    """
    result = _run_gate(tmp_path, "-k", "test_pg_0 or test_nats_0")
    assert result.returncode != 0, result.stdout
    assert "postgres: 1 ran, 0 skipped, 2 never ran, 3 collected" in result.stdout
    assert "2 of 3 tests never ran" in result.stdout


def test_a_suite_skipped_with_its_variable_set_fails_the_gate(tmp_path: Path):
    # The reachability case: the URL is there, the suite skips anyway. Nothing
    # in the current marks can do this, which is why it is worth a test — the
    # next gate that probes the database rather than the variable will.
    result = _run_gate(tmp_path, postgres_condition="True")
    assert result.returncode != 0, result.stdout
    assert "3 of 3 tests skipped although OCTO_POSTGRES_URL is declared available" in result.stdout


def test_a_reworded_skip_reason_fails_the_gate_instead_of_emptying_it(tmp_path: Path):
    # The gate matches suites by the variable named in the skip reason. Reword
    # the reason and the suite stops being recognised — which has to be red, not
    # an empty set passing quietly.
    result = _run_gate(tmp_path, nats_reason="live broker not configured")
    assert result.returncode != 0, result.stdout
    assert "no tests recognised as gated on OCTO_NATS_URL" in result.stdout


def test_a_missing_url_fails_before_collection(tmp_path: Path):
    result = _run_gate(tmp_path, env={"OCTO_POSTGRES_URL": None})
    assert result.returncode != 0
    assert "OCTO_POSTGRES_URL is unset" in result.stderr + result.stdout
    assert "collected" not in result.stdout, "the run must not reach collection"


def test_without_the_flag_nothing_changes(tmp_path: Path):
    # Skipping stays the right default on a laptop: no flag, no gate, not even
    # the summary section.
    result = _run_gate(tmp_path, "-k", "test_pg_0", env={"OCTO_REQUIRE_INTEGRATION": "0"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "integration gate" not in result.stdout


def test_the_repository_conftest_registers_the_gate_hooks():
    """tests/conftest.py is what makes the hooks apply to the real suite.

    The sessions above import the gate module directly, so they would stay green
    if the import in conftest were dropped or a hook redefined there.
    """
    conftest = importlib.import_module("tests.conftest")
    hooks = [
        "pytest_configure",
        "pytest_collection_modifyitems",
        "pytest_runtest_logreport",
        "pytest_terminal_summary",
        "pytest_sessionfinish",
    ]
    for hook in hooks:
        assert getattr(conftest, hook, None) is getattr(integration_gate, hook), (
            f"tests/conftest.py does not register the gate's {hook}"
        )


# --- the gate's arithmetic, read directly ----------------------------------


def _counts(
    postgres: tuple[int, int, int], nats: tuple[int, int, int]
) -> dict[str, tuple[int, int, int]]:
    """``(collected, executed, skipped)`` per suite, in the shape the gate takes."""
    return {"postgres": postgres, "nats": nats}


def test_a_single_skipped_test_fails_the_gate():
    # Not a threshold on skips: with the database declared available, one
    # skipped row-lock test is one claim the run did not make.
    problems = integration_gate_problems(_counts((1232, 1231, 1), (5, 5, 0)))
    assert any("1 of 1232" in problem for problem in problems)


def test_an_empty_collection_fails_the_gate():
    # A conftest change stops applying the mark: nothing collected, nothing
    # skipped, nothing deselected. There is no floor to catch this any more, and
    # none is needed — zero recognised tests is the condition itself.
    problems = integration_gate_problems(_counts((0, 0, 0), (0, 0, 0)))
    assert any("no tests recognised as gated on OCTO_NATS_URL" in p for p in problems)


@pytest.mark.parametrize("suite", sorted(INTEGRATION_SUITES))
def test_every_gated_suite_names_a_variable(suite: str):
    assert INTEGRATION_SUITES[suite].startswith("OCTO_")


def test_the_gate_recognises_the_postgres_suite_by_the_wording_of_its_skip_reason():
    """The collection hook matches on the skip reason, so the wording is API.

    Asserted against the mark itself, not by grepping the file: ``OCTO_POSTGRES_URL``
    also appears in an ``os.environ.get`` call and a docstring two lines away, so
    a file-wide search stays green through exactly the rewording it is meant to
    catch.
    """
    assert suite_for_reason(requires_postgres.kwargs["reason"]) == "postgres"


def test_the_gate_recognises_the_nats_suite_by_the_wording_of_its_skip_reason():
    module = importlib.import_module("tests.test_nats_live")
    assert suite_for_reason(module.pytestmark.kwargs["reason"]) == "nats"
