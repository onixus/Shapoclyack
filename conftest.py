"""Repository-root pytest hooks.

Almost all of the suite's scaffolding lives in tests/conftest.py; this file
exists for one thing that cannot. A conftest binds at most one function per
hook name, and tests/conftest.py has already given ``pytest_sessionfinish``
and ``pytest_terminal_summary`` to tests/integration_gate.py — by identity,
which tests/test_ci_checks.py asserts. The scanner-child gate needs the same
two hooks, so it is registered from a second conftest, where pytest calls it
alongside the first rather than in place of it.

See tests/scanner_gate.py for what it refuses and why.
"""

from tests.scanner_gate import (  # noqa: F401 - imported to register the hooks
    pytest_sessionfinish,
    pytest_terminal_summary,
)
