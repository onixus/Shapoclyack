"""Start-up warning for an empty OCTO_TRUSTED_PROXIES (#323)."""
import logging

from api.app import warn_if_trusted_proxies_unset
from tests.conftest import make_settings


def test_warns_once_when_trusted_proxies_empty(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="shapoclyack.api"):
        assert warn_if_trusted_proxies_unset(make_settings(tmp_path, trusted_proxies=[])) is True
    assert caplog.text.count("OCTO_TRUSTED_PROXIES is empty") == 1


def test_silent_when_trusted_proxies_set(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="shapoclyack.api"):
        assert warn_if_trusted_proxies_unset(make_settings(tmp_path, trusted_proxies=["10.0.0.0/8"])) is False
    assert "OCTO_TRUSTED_PROXIES" not in caplog.text
