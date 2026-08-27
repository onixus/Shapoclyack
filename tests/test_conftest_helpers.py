"""Tests for the shared test fixtures themselves (#254).

The rest of the suite trusts ``make_settings``/``configured_client`` to build
the Settings the app actually runs on. Before #254 a misspelled field name was
applied with ``setattr`` and invented an attribute nobody read, so the app kept
its default and the test still passed — which is exactly the failure mode a
test cannot detect from the outside.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import configured_client, make_settings


def test_make_settings_rejects_an_unknown_field(tmp_path: Path):
    with pytest.raises(TypeError, match="agent_stale_secondz"):
        make_settings(tmp_path, agent_stale_secondz=10)


def test_make_settings_applies_a_known_field(tmp_path: Path):
    assert make_settings(tmp_path, agent_stale_seconds=10).agent_stale_seconds == 10


def test_configured_client_refuses_a_settings_object_plus_overrides(tmp_path: Path):
    settings = make_settings(tmp_path)
    with pytest.raises(TypeError, match="agent_stale_seconds"):
        configured_client(tmp_path, None, settings=settings, agent_stale_seconds=10)
