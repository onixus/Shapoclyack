"""RFC 6238 vectors, the acceptance window and single-use enforcement (#315).

Every property MFA rests on is decided in ``api/core/totp.py`` and nowhere
else, so it is tested here as a pure function: no database, no app, no clock
but the one each test hands in. The vectors are the ones printed in RFC 6238
Appendix B for HMAC-SHA-1 — an implementation that agrees with them agrees with
every authenticator app, which is the only interoperability guarantee worth
asserting.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from api.core import totp

# RFC 6238 Appendix B: the SHA-1 secret is the ASCII string "12345678901234567890".
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

# (unix time, 8-digit TOTP), SHA-1 column of the Appendix B table.
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


def _at(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, UTC)


@pytest.mark.parametrize("epoch,expected", RFC_VECTORS)
def test_rfc6238_sha1_vectors(epoch: int, expected: str) -> None:
    assert totp.code_at(RFC_SECRET, _at(epoch), digits=8) == expected


def test_generated_secret_is_unpadded_base32_of_160_bits() -> None:
    secret = totp.generate_secret()
    assert "=" not in secret
    assert secret.upper() == secret
    # 20 bytes is 32 base32 characters once the padding is stripped.
    assert len(secret) == 32
    assert totp.generate_secret() != secret


def test_secret_accepts_the_formatting_authenticators_display() -> None:
    grouped = " ".join(RFC_SECRET[i : i + 4] for i in range(0, len(RFC_SECRET), 4))
    assert totp.code_at(grouped.lower(), _at(59), digits=8) == "94287082"


def test_undecodable_secret_is_refused_not_truncated() -> None:
    with pytest.raises(totp.InvalidSecretError):
        totp.code_at("not-base32-at-all-1889", _at(59))


def test_window_accepts_one_step_either_side_and_nothing_further() -> None:
    now = _at(1_700_000_000)
    for offset in (-1, 0, 1):
        code = totp.code_at(RFC_SECRET, now + timedelta(seconds=offset * totp.STEP_SECONDS))
        assert totp.verify(RFC_SECRET, code, moment=now) is not None, offset
    for offset in (-2, 2):
        code = totp.code_at(RFC_SECRET, now + timedelta(seconds=offset * totp.STEP_SECONDS))
        assert totp.verify(RFC_SECRET, code, moment=now) is None, offset


def test_a_used_step_is_refused_the_second_time() -> None:
    now = _at(1_700_000_000)
    code = totp.code_at(RFC_SECRET, now)
    step = totp.verify(RFC_SECRET, code, moment=now)
    assert step == totp.step_at(now)
    # The same code, presented again inside its own thirty seconds, with the
    # step the first use recorded.
    assert totp.verify(RFC_SECRET, code, moment=now, last_step=step) is None
    # ...and so is the *previous* step, which the window would otherwise still
    # accept after a code from the current one has been spent.
    previous = totp.code_at(RFC_SECRET, now - timedelta(seconds=totp.STEP_SECONDS))
    assert totp.verify(RFC_SECRET, previous, moment=now, last_step=step) is None


def test_the_next_step_still_works_after_one_is_spent() -> None:
    now = _at(1_700_000_000)
    step = totp.step_at(now)
    later = now + timedelta(seconds=totp.STEP_SECONDS)
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, later), moment=later, last_step=step) == step + 1


@pytest.mark.parametrize("code", ["", "12345", "1234567", "12345a", "   ", None])
def test_malformed_codes_are_refused_without_raising(code: str | None) -> None:
    assert totp.verify(RFC_SECRET, code, moment=_at(1_700_000_000)) is None


def test_provisioning_uri_carries_the_parameters_an_app_needs() -> None:
    uri = totp.provisioning_uri(RFC_SECRET, account="admin", issuer="Shapoclyack Two")
    assert uri.startswith("otpauth://totp/Shapoclyack%20Two%3Aadmin?")
    assert f"secret={RFC_SECRET}" in uri
    assert "issuer=Shapoclyack%20Two" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri
