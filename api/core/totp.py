"""RFC 6238 time-based one-time passwords, and nothing else (#315).

No dependency, because there is no need for one: HOTP is HMAC-SHA-1 over a
counter (RFC 4226 §5.3) and TOTP is HOTP with the counter derived from the
clock (RFC 6238 §4.2). The whole of it is ``hmac``, ``struct`` and ``base64``,
and it is verified in ``tests/test_totp.py`` against the vectors printed in RFC
6238 Appendix B rather than against another implementation of the same guess.

**SHA-1, six digits, thirty seconds.** Not because SHA-1 is a good hash — it is
the one every authenticator app implements, and the alternative is a secret
that Google Authenticator, FreeOTP and 1Password all read as garbage. HMAC-SHA-1
is not affected by the collision attacks that retired SHA-1 for signatures.

**Replay is the caller's business, and it is not optional.** :func:`verify`
takes ``last_step`` and refuses a code from a step at or before it, so a code
observed on the wire (or over somebody's shoulder) cannot be used a second time
inside the thirty seconds it stays valid. The caller persists the step this
function returns — see ``users.mfa_last_step``.

Nothing here touches the database, the settings or the clock beyond the moment
it is handed: this module is a pure function of its arguments, which is what
makes the RFC vectors expressible as a test at all.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import urllib.parse
from datetime import UTC, datetime

#: The interoperable parameter set. Changing any of these silently invalidates
#: every enrolled authenticator, so they are constants rather than settings:
#: an installation that made them configurable would be one upgrade away from
#: locking its admins out with a value nobody remembers choosing.
DIGITS = 6
STEP_SECONDS = 30
#: Steps either side of the current one that are still accepted — one, i.e.
#: ±30 seconds. It is the allowance for a phone whose clock has drifted and for
#: the seconds between reading a code and pressing submit; widening it widens
#: the window an observed code stays usable in by the same amount.
WINDOW_STEPS = 1
#: 160 bits, the shared-secret size RFC 4226 §4 R6 requires as a minimum and
#: the size HMAC-SHA-1's block structure makes natural.
SECRET_BYTES = 20


class InvalidSecretError(ValueError):
    """A stored or supplied secret is not decodable base32."""


def generate_secret(*, size: int = SECRET_BYTES) -> str:
    """A fresh base32 secret, unpadded and upper-case.

    Unpadded because that is the form ``otpauth://`` URIs carry and the form
    every authenticator's manual-entry field accepts; the ``=`` padding
    confuses several of them and carries no information.
    """
    return base64.b32encode(secrets.token_bytes(size)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    """Base32 → bytes, tolerant of the shapes humans and apps produce.

    Spaces (authenticators display secrets in groups of four), lower case and
    missing padding are all accepted: they are formatting, not a different
    secret. Anything else is refused rather than silently truncated to the
    prefix that happened to decode.
    """
    cleaned = (secret or "").replace(" ", "").replace("-", "").strip().upper()
    if not cleaned:
        raise InvalidSecretError("secret is empty")
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(padded, casefold=False)
    except (binascii.Error, ValueError) as exc:
        raise InvalidSecretError("secret is not valid base32") from exc


def hotp(secret: str, counter: int, *, digits: int = DIGITS) -> str:
    """One HOTP value (RFC 4226 §5.3) for ``counter``, zero-padded to ``digits``.

    The dynamic truncation is the RFC's, byte for byte: the low nibble of the
    last byte selects the offset, four bytes are read big-endian from there,
    and the top bit is masked off so the value is positive on every platform.
    """
    digest = hmac.new(_decode_secret(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFF_FFFF
    return str(truncated % (10**digits)).zfill(digits)


def step_at(moment: datetime, *, step_seconds: int = STEP_SECONDS) -> int:
    """The RFC 6238 time step containing ``moment``.

    A naive datetime is read as UTC, because every timestamp in this schema is
    naive UTC and a value that reached here from a column must not be
    reinterpreted in the server's local zone — an hour of drift is 120 steps.
    """
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return int(moment.timestamp()) // step_seconds


def code_at(
    secret: str,
    moment: datetime,
    *,
    digits: int = DIGITS,
    step_seconds: int = STEP_SECONDS,
) -> str:
    """The TOTP value valid at ``moment``. Used by the tests and by nothing else."""
    return hotp(secret, step_at(moment, step_seconds=step_seconds), digits=digits)


def verify(
    secret: str,
    code: str,
    *,
    moment: datetime,
    last_step: int | None = None,
    window: int = WINDOW_STEPS,
    digits: int = DIGITS,
    step_seconds: int = STEP_SECONDS,
) -> int | None:
    """The step ``code`` belongs to, or ``None`` when it is not a valid code.

    Candidates are walked newest first, which is the one an honest user almost
    always presents, and every comparison goes through
    :func:`hmac.compare_digest` — a code is a short secret, and a timing signal
    that leaks how many leading digits matched turns a 10^6 space into 10×6
    guesses.

    A step at or before ``last_step`` is refused **before** the code is
    compared: replaying a code the account already spent must fail whether or
    not the digits are right, and returning early keeps the two indistinguishable
    to the caller.
    """
    cleaned = (code or "").replace(" ", "").replace("-", "").strip()
    if not cleaned.isdigit() or len(cleaned) != digits:
        return None
    current = step_at(moment, step_seconds=step_seconds)
    for candidate in range(current + window, current - window - 1, -1):
        if candidate < 0:
            continue
        if last_step is not None and candidate <= last_step:
            continue
        if hmac.compare_digest(hotp(secret, candidate, digits=digits), cleaned):
            return candidate
    return None


def provisioning_uri(secret: str, *, account: str, issuer: str) -> str:
    """The ``otpauth://`` URI an authenticator imports (Key Uri Format).

    The label carries ``issuer:account`` *and* the ``issuer`` parameter,
    because the two are read by different apps and an authenticator that gets
    neither shows the account under a blank name. Everything is percent-encoded
    with ``quote`` rather than ``quote_plus``: a space in a display name is
    ``%20`` in a URI path, and ``+`` would be imported literally.
    """
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    query = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": STEP_SECONDS,
        },
        quote_via=urllib.parse.quote,
    )
    return f"otpauth://totp/{label}?{query}"
