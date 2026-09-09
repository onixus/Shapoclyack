"""Shapoclyack remote scanner agent (Phase 3)."""

# The agent ships in the same release as the API and carries the same version
# (#363). It has to be a literal: the scanner image copies ``agent`` without
# ``api`` and the API image copies ``api`` without ``agent``, so neither
# package can import the other's ``__version__``. ``tests/test_agent_version.py``
# is what keeps the two literals equal -- it fails on any drift, which is how
# the previous pair (``0.3.2.1`` here against ``0.42.0`` in
# ``api/services/agents.py``) was allowed to sit for whole releases and report
# every agent in every installation as outdated.
__version__ = "0.44-0907"  # keep in sync with api/__init__.py
