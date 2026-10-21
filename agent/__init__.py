"""Shapoclyack remote scanner agent (Phase 3)."""

# The agent ships in the same release as the API and carries the same version
# (#363). It has to be a literal: the scanner and standalone sensor carry
# ``agent`` without ``api``. The API image includes only ``agent.runtime`` and
# this lightweight package initializer; it does not carry the sensor worker.
# Neither version literal depends on the other package. ``tests/test_agent_version.py``
# is what keeps the two literals equal -- it fails on any drift, which is how
# the previous pair (``0.3.2.1`` here against ``0.42.0`` in
# ``api/services/agents.py``) was allowed to sit for whole releases and report
# every agent in every installation as outdated.
__version__ = "0.48-1021"  # keep in sync with api/__init__.py
