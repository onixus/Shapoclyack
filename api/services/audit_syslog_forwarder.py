"""Ship the audit trail to a SIEM as CEF over RFC 5424 syslog (#328).

A worker of its own, not a thread in the API::

    python -m api.services.audit_syslog_forwarder

Its own process because it is the only thing in this repository that holds a
long-lived TCP connection to a system outside the platform, and because a SIEM
that stops accepting must slow down forwarding and nothing else. Run one
replica (see ``k8s/shapoclyack/examples/audit-syslog-forwarder.example.yaml``).

Two sources, chosen with ``OCTO_AUDIT_SYSLOG_SOURCE``:

``nats`` (default)
    A JetStream durable pull consumer on ``events.audit.>``. A message is
    acked only after its bytes have been written to the socket, so a receiver
    that goes away mid-batch leaves the rest of the batch un-acked and
    JetStream redelivers it. At-least-once: a SIEM may see one event twice
    after a reconnect, and the ``cs6``/``eventId`` extension is what
    deduplicates it. ``DeliverPolicy.ALL`` on first start, unlike the webhook
    fan-out consumer (#152) — a compliance feed that silently began at "now"
    would leave a hole nobody could see, and the flood is a one-off bounded by
    the stream's 30d retention.

``db``
    Reads ``audit_events`` directly, ordered by ``(occurred_at, id)`` and
    keeping its place in ``audit_forward_cursors``. This exists because an
    installation without ``OCTO_NATS_URL`` has no event bus at all and would
    otherwise have no way to reach a SIEM. **Its boundary, stated plainly:**
    ``occurred_at`` is stamped when the change is recorded but the row becomes
    visible only at COMMIT, so a reader at the present moment would pass a row
    that is about to appear behind it. ``OCTO_AUDIT_SYSLOG_DB_LAG_SECONDS``
    (default 15) keeps the reader that far behind the present, which covers
    every transaction shorter than that; a transaction that takes longer than
    the lag between recording the change and committing it can still have its
    row skipped. The ``nats`` source has no such window, because there the
    publish happens after that commit. Choose ``db`` when there is no broker,
    not in preference to one.

Transport. ``OCTO_AUDIT_SYSLOG_URL`` is ``tls://host:6514`` or ``tcp://host:514``.
``tcp://`` is accepted and logged at WARNING on every connect: the trail says
who changed what and from where, and sending it in the clear across a network
is a decision an operator should keep being told about. UDP is not implemented
— it has no delivery signal, so there would be nothing to ack on. Verification
uses ``OCTO_AUDIT_SYSLOG_CA`` (or the system trust store), and
``OCTO_AUDIT_SYSLOG_CERT``/``_KEY`` present a client certificate when the SIEM
requires one.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import socket
import ssl
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import and_, or_, select

from api import __version__
from api.db import models
from api.db.engine import get_session
from api.services import audit_cef
from api.services.nats_bus import STREAM_EVENTS

LOG = logging.getLogger("shapoclyack.audit-syslog")

#: Durable JetStream consumer. One name, so two replicas started by mistake
#: divide the stream instead of each forwarding all of it.
CONSUMER_AUDIT_SYSLOG = "octo-audit-syslog"
SUBJECT_FILTER = "events.audit.>"

#: Name of this forwarder's row in ``audit_forward_cursors``.
CURSOR_NAME = "syslog"

SOURCE_NATS = "nats"
SOURCE_DB = "db"

# Reconnect ladder. Capped low enough that a SIEM restart costs seconds of lag
# rather than minutes, and jitter-free because there is one client.
_BACKOFF_START_SECONDS = 1.0
_BACKOFF_MAX_SECONDS = 30.0

#: Socket timeout for connect and for every write. A receiver that stops
#: reading must not park this process — in ``db`` mode the send happens inside
#: the transaction that moves the cursor, so a hang there is a held row lock.
DEFAULT_TIMEOUT_SECONDS = 10.0

#: Rows per ``db``-mode poll. Small on purpose, for the reason above.
DEFAULT_DB_BATCH = 200
DEFAULT_DB_POLL_SECONDS = 10.0
DEFAULT_DB_LAG_SECONDS = 15


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


class ForwarderConfig:
    """Everything the forwarder reads from the environment, resolved once."""

    def __init__(self, env: dict[str, str] | None = None) -> None:
        source = os.environ if env is None else env
        self.url = (source.get("OCTO_AUDIT_SYSLOG_URL") or "").strip()
        self.ca = (source.get("OCTO_AUDIT_SYSLOG_CA") or "").strip()
        self.cert = (source.get("OCTO_AUDIT_SYSLOG_CERT") or "").strip()
        self.key = (source.get("OCTO_AUDIT_SYSLOG_KEY") or "").strip()
        self.tls_hostname = (source.get("OCTO_AUDIT_SYSLOG_TLS_HOSTNAME") or "").strip()
        self.hostname = (
            source.get("OCTO_AUDIT_SYSLOG_HOSTNAME") or ""
        ).strip() or socket.gethostname()
        self.facility = _int_env(source, "OCTO_AUDIT_SYSLOG_FACILITY", audit_cef.DEFAULT_FACILITY)
        self.timeout = float(
            _int_env(source, "OCTO_AUDIT_SYSLOG_TIMEOUT_SECONDS", int(DEFAULT_TIMEOUT_SECONDS))
        )
        self.mode = (source.get("OCTO_AUDIT_SYSLOG_SOURCE") or SOURCE_NATS).strip().lower()
        self.db_batch = _int_env(source, "OCTO_AUDIT_SYSLOG_DB_BATCH", DEFAULT_DB_BATCH)
        self.db_poll_seconds = float(
            _int_env(source, "OCTO_AUDIT_SYSLOG_DB_POLL_SECONDS", int(DEFAULT_DB_POLL_SECONDS))
        )
        self.db_lag_seconds = _int_env(
            source, "OCTO_AUDIT_SYSLOG_DB_LAG_SECONDS", DEFAULT_DB_LAG_SECONDS
        )
        # Read here rather than through ``api.settings.load_settings``: that
        # function is the *API's* startup contract and under the default
        # ``OCTO_ENV=prod`` it refuses to return without a JWT secret, an
        # explicit CORS list and a public base URL. This process serves no
        # requests and issues no tokens, so demanding those would make the
        # forwarder undeployable for reasons that have nothing to do with it.
        # The two values it does need are the two it reads.
        self.nats_url = (source.get("OCTO_NATS_URL") or "").strip()
        self.postgres_url = (source.get("OCTO_POSTGRES_URL") or "").strip()

    def validate(self) -> None:
        if not self.url:
            raise ValueError("OCTO_AUDIT_SYSLOG_URL is unset; nothing to forward to")
        parts = urlsplit(self.url)
        if parts.scheme not in ("tls", "tcp"):
            raise ValueError(
                f"unsupported OCTO_AUDIT_SYSLOG_URL scheme {parts.scheme!r}: "
                "use tls://host:6514, or tcp://host:514 to send in the clear. "
                "UDP is not implemented — it carries no delivery signal, so there "
                "would be nothing to acknowledge an event against."
            )
        if not parts.hostname or not parts.port:
            raise ValueError("OCTO_AUDIT_SYSLOG_URL needs an explicit host and port")
        if self.mode not in (SOURCE_NATS, SOURCE_DB):
            raise ValueError(
                f"unknown OCTO_AUDIT_SYSLOG_SOURCE {self.mode!r}: expected "
                f"{SOURCE_NATS!r} or {SOURCE_DB!r}"
            )
        if self.mode == SOURCE_NATS and not self.nats_url:
            raise ValueError(
                "OCTO_AUDIT_SYSLOG_SOURCE=nats needs OCTO_NATS_URL. An installation "
                "with no broker forwards with OCTO_AUDIT_SYSLOG_SOURCE=db instead — "
                "see docs/operations.md § Audit events to SIEM."
            )
        if self.mode == SOURCE_DB and not self.postgres_url:
            raise ValueError(
                "OCTO_AUDIT_SYSLOG_SOURCE=db needs OCTO_POSTGRES_URL: that mode reads "
                "audit_events directly and keeps its cursor in audit_forward_cursors"
            )
        self._validate_tls_material()

    def _validate_tls_material(self) -> None:
        """Refuse a certificate path that is missing or empty, at startup.

        Not a nicety. The k8s example mounts the CA, the client certificate and
        its key from one Secret, and an installation whose SIEM wants no client
        certificate leaves those two keys as empty strings — a file that exists
        and is zero bytes. ``ssl.load_cert_chain`` then raises inside
        :meth:`SyslogClient.connect`, which treats every exception as a
        retryable network failure, and the pod reconnects forever under a log
        line that blames the network for a configuration mistake. Better to
        refuse to start and say which variable is wrong.
        """
        for name, path in (
            ("OCTO_AUDIT_SYSLOG_CA", self.ca),
            ("OCTO_AUDIT_SYSLOG_CERT", self.cert),
            ("OCTO_AUDIT_SYSLOG_KEY", self.key),
        ):
            if not path:
                continue
            if not os.path.isfile(path):
                raise ValueError(f"{name}={path!r} is not a file")
            if os.path.getsize(path) == 0:
                raise ValueError(
                    f"{name}={path!r} is empty. A SIEM that asks for no client "
                    "certificate wants the variable unset, not pointed at a blank file."
                )
        if self.key and not self.cert:
            raise ValueError(
                "OCTO_AUDIT_SYSLOG_KEY is set without OCTO_AUDIT_SYSLOG_CERT; "
                "a private key on its own presents nothing"
            )

    @property
    def use_tls(self) -> bool:
        return urlsplit(self.url).scheme == "tls"

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def port(self) -> int:
        return int(urlsplit(self.url).port or 0)


def _int_env(source: dict[str, str], name: str, default: int) -> int:
    raw = (source.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        LOG.warning("Invalid int for %s=%r; using default %s", name, raw, default)
        return default


# --------------------------------------------------------------------------
# The wire
# --------------------------------------------------------------------------


class SyslogClient:
    """One reconnecting TCP/TLS connection, with an exponential backoff.

    :meth:`send` returns True only when the bytes reached the socket. That
    boolean is the ack decision for both sources, which is why nothing here
    swallows a write error into a log line and returns success.
    """

    def __init__(self, config: ForwarderConfig, *, connector=None) -> None:
        self._config = config
        # Injected in tests: a fake connector returns an object with sendall()
        # and close(), which is the entire contract this class needs.
        self._connector = connector or self._connect_socket
        self._sock: Any = None
        self._backoff = _BACKOFF_START_SECONDS

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def _tls_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=self._config.ca or None)
        if self._config.cert:
            context.load_cert_chain(
                certfile=self._config.cert, keyfile=self._config.key or None
            )
        return context

    def _connect_socket(self) -> Any:
        raw = socket.create_connection(
            (self._config.host, self._config.port), timeout=self._config.timeout
        )
        if not self._config.use_tls:
            LOG.warning(
                "Forwarding the audit trail to %s:%s over plain TCP; it names actors "
                "and client addresses. Use tls:// unless the link is already encrypted.",
                self._config.host,
                self._config.port,
            )
            return raw
        server_hostname = self._config.tls_hostname or self._config.host
        return self._tls_context().wrap_socket(raw, server_hostname=server_hostname)

    def connect(self) -> bool:
        """Open the connection, or report the failure and grow the backoff."""
        if self._sock is not None:
            return True
        try:
            self._sock = self._connector()
        except Exception as exc:  # noqa: BLE001 - every failure here is retryable
            LOG.warning(
                "Cannot reach syslog target %s:%s (%s: %s); retrying in %.0fs",
                self._config.host,
                self._config.port,
                type(exc).__name__,
                exc,
                self._backoff,
            )
            return False
        LOG.info(
            "Connected to syslog target %s:%s (%s)",
            self._config.host,
            self._config.port,
            "tls" if self._config.use_tls else "plain tcp",
        )
        self._backoff = _BACKOFF_START_SECONDS
        return True

    def send(self, payload: bytes) -> bool:
        """Write one framed message. False means "not delivered — do not ack"."""
        if not self.connect():
            return False
        try:
            self._sock.sendall(payload)
        except Exception as exc:  # noqa: BLE001
            LOG.warning(
                "Write to syslog target failed (%s: %s); reconnecting",
                type(exc).__name__,
                exc,
            )
            self.close()
            return False
        return True

    def wait_backoff(self, stop: threading.Event) -> None:
        """Sleep the current backoff, then double it up to the ceiling."""
        stop.wait(self._backoff)
        self._backoff = min(self._backoff * 2, _BACKOFF_MAX_SECONDS)

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is None:
            return
        try:
            sock.close()
        except Exception:  # noqa: BLE001 - closing a broken socket is not news
            LOG.debug("Failed to close syslog socket cleanly", exc_info=True)


def render(envelope: dict[str, Any], config: ForwarderConfig) -> bytes:
    return audit_cef.render(
        envelope,
        product_version=__version__,
        hostname=config.hostname,
        facility=config.facility,
    )


# --------------------------------------------------------------------------
# Source: JetStream
# --------------------------------------------------------------------------


async def ensure_consumer(js: Any) -> None:
    """Create ``octo-audit-syslog`` with ``DeliverPolicy.ALL`` if it is missing.

    ALL, not NEW: see the module docstring. An existing consumer is left as it
    is — recreating it would reset the cursor and re-send everything the SIEM
    already holds.
    """
    from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy
    from nats.js.errors import NotFoundError

    try:
        await js.consumer_info(STREAM_EVENTS, CONSUMER_AUDIT_SYSLOG)
        return
    except NotFoundError:
        pass
    try:
        await js.add_consumer(
            STREAM_EVENTS,
            ConsumerConfig(
                durable_name=CONSUMER_AUDIT_SYSLOG,
                ack_policy=AckPolicy.EXPLICIT,
                filter_subject=SUBJECT_FILTER,
                deliver_policy=DeliverPolicy.ALL,
                # Unlimited, unlike the webhook fan-out's 5. A message that
                # cannot be written is almost always a receiver that is down,
                # and the reconnect backoff is what waits for it; any finite
                # ceiling here is a number of minutes of SIEM downtime after
                # which audit events are dropped silently. The stream's
                # retention is the real bound, and it is one an operator can
                # see. A message that will never render is termed in
                # :meth:`NatsSource.handle_msg`, so nothing loops on a poison
                # payload either.
                max_deliver=-1,
            ),
        )
    except Exception:  # noqa: BLE001 - a peer created it first
        LOG.debug("Audit syslog consumer already created by a peer", exc_info=True)


class NatsSource:
    """``events.audit.>`` → syslog, acking only what the socket took."""

    def __init__(self, *, config: ForwarderConfig, nats_url: str, client: SyslogClient) -> None:
        self._config = config
        self._nats_url = nats_url
        self._client = client
        self._stop = threading.Event()
        self.stats = {"messages": 0, "sent": 0, "nak": 0, "errors": 0}

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                asyncio.run(self._consume_loop())
            except Exception:  # noqa: BLE001
                self.stats["errors"] += 1
                LOG.exception("Audit syslog consume loop crashed; restarting")
                self._client.wait_backoff(self._stop)

    async def _consume_loop(self) -> None:
        import nats
        from nats.errors import TimeoutError as NatsTimeout

        nc = await nats.connect(
            self._nats_url, name="octo-audit-syslog", connect_timeout=5
        )
        try:
            js = nc.jetstream()
            await ensure_consumer(js)
            sub = await js.pull_subscribe_bind(
                durable=CONSUMER_AUDIT_SYSLOG, stream=STREAM_EVENTS
            )
            LOG.info(
                "Audit syslog forwarder subscribed stream=%s consumer=%s filter=%s",
                STREAM_EVENTS,
                CONSUMER_AUDIT_SYSLOG,
                SUBJECT_FILTER,
            )
            while not self._stop.is_set():
                try:
                    msgs = await sub.fetch(10, timeout=5.0)
                except NatsTimeout:
                    continue
                for msg in msgs:
                    await self.handle_msg(msg)
        finally:
            await _drain(nc)

    async def handle_msg(self, msg: Any) -> None:
        try:
            envelope = json.loads(msg.data.decode("utf-8"))
        except Exception:  # noqa: BLE001
            envelope = None
        if not isinstance(envelope, dict):
            # Redelivering it will not make it parse, and a SIEM has no use for
            # a message this forwarder cannot render.
            self.stats["errors"] += 1
            LOG.warning(
                "Dropping unparseable audit event on %s", getattr(msg, "subject", "?")
            )
            await _term(msg)
            return
        self.stats["messages"] += 1
        if await asyncio.to_thread(self._client.send, render(envelope, self._config)):
            self.stats["sent"] += 1
            await _ack(msg)
            return
        # Not acked: the SIEM did not take it, so JetStream must bring it back.
        self.stats["nak"] += 1
        await _nak(msg)
        await asyncio.to_thread(self._client.wait_backoff, self._stop)


# --------------------------------------------------------------------------
# Source: the table itself
# --------------------------------------------------------------------------


class DatabaseSource:
    """``audit_events`` → syslog, in ``(occurred_at, id)`` order, with a cursor row.

    The batch is claimed, sent and committed inside one transaction that holds
    ``FOR UPDATE`` on the cursor row. That is what makes a second replica wait
    rather than duplicate, and it is why :data:`DEFAULT_DB_BATCH` and the socket
    timeout are both small — the transaction is open for the length of the send.
    """

    def __init__(self, *, config: ForwarderConfig, client: SyslogClient) -> None:
        self._config = config
        self._client = client
        self._stop = threading.Event()
        self.stats = {"messages": 0, "sent": 0, "errors": 0}

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                forwarded = self.forward_once()
            except Exception:  # noqa: BLE001
                self.stats["errors"] += 1
                LOG.exception("Audit syslog database poll failed")
                self._client.wait_backoff(self._stop)
                continue
            # A full batch means there is more waiting; go straight round again
            # instead of sleeping through a backlog.
            if forwarded < self._config.db_batch:
                self._stop.wait(self._config.db_poll_seconds)

    def forward_once(self) -> int:
        """One claim-send-commit pass. Returns how many rows reached the socket.

        The cursor is ``(occurred_at, id)`` and so is the ordering, which is the
        only arrangement that does not lose rows. Keying the cursor on ``id``
        while filtering on ``occurred_at`` — the obvious first draft — skips a
        row permanently: two concurrent requests can commit in the opposite
        order to the one they took their ids in, so a pass that forwards the
        higher id first moves the cursor past the lower one, and the next pass
        reads ``id > last_id`` and never sees it again. Here a row that is not
        yet visible is simply not yet past the cursor, and the next pass picks
        it up.
        """
        from api.services import audit_events

        horizon = _naive_now() - timedelta(seconds=max(0, self._config.db_lag_seconds))
        sent = 0
        with get_session(self._config.postgres_url) as session:
            cursor = session.get(
                models.AuditForwardCursor, CURSOR_NAME, with_for_update=True
            )
            if cursor is None:
                cursor = models.AuditForwardCursor(
                    forwarder=CURSOR_NAME, last_id=0, updated_at=_naive_now()
                )
                session.add(cursor)
                session.flush()
            # A first run has no anchor, so it starts before every row there is.
            anchor = cursor.last_occurred_at or datetime.min
            rows = (
                session.execute(
                    select(models.AuditEvent)
                    .where(
                        models.AuditEvent.occurred_at <= horizon,
                        # Written out rather than as a row-value comparison:
                        # SQLite is the dev and test fallback, and its support
                        # for ``(a, b) > (c, d)`` is newer than the versions
                        # this project otherwise tolerates.
                        or_(
                            models.AuditEvent.occurred_at > anchor,
                            and_(
                                models.AuditEvent.occurred_at == anchor,
                                models.AuditEvent.id > cursor.last_id,
                            ),
                        ),
                    )
                    .order_by(models.AuditEvent.occurred_at, models.AuditEvent.id)
                    .limit(max(1, self._config.db_batch))
                )
                .scalars()
                .all()
            )
            for row in rows:
                self.stats["messages"] += 1
                payload = render(audit_events.build_envelope(row), self._config)
                if not self._client.send(payload):
                    # Stop at the first refusal rather than skipping past it:
                    # the cursor may only advance over rows the SIEM has.
                    break
                cursor.last_id = row.id
                cursor.last_occurred_at = row.occurred_at
                sent += 1
            if sent:
                cursor.updated_at = _naive_now()
                self.stats["sent"] += sent
                LOG.info(
                    "Forwarded %s audit rows (cursor now %s/%s)",
                    sent,
                    cursor.last_occurred_at,
                    cursor.last_id,
                )
        if rows and not sent:
            self._client.wait_backoff(self._stop)
        return sent


def _naive_now() -> datetime:
    """Naive UTC, matching every timestamp column in this schema."""
    return datetime.now(UTC).replace(tzinfo=None)


# --------------------------------------------------------------------------
# NATS message helpers (same fail-soft shape as webhook_worker)
# --------------------------------------------------------------------------


async def _ack(msg: Any) -> None:
    try:
        await msg.ack()
    except Exception:  # noqa: BLE001 - a failed ack is a redelivery, not an outage
        LOG.debug("ack failed", exc_info=True)


async def _nak(msg: Any) -> None:
    try:
        await msg.nak()
    except Exception:  # noqa: BLE001 - the ack wait expires and redelivers anyway
        LOG.debug("nak failed", exc_info=True)


async def _term(msg: Any) -> None:
    try:
        await msg.term()
    except Exception:  # noqa: BLE001 - max_deliver eventually drops it regardless
        LOG.debug("term failed", exc_info=True)


async def _drain(nc: Any) -> None:
    if nc is None:
        return
    try:
        if not nc.is_closed:
            await nc.drain()
    except Exception:  # noqa: BLE001 - the process is leaving anyway
        LOG.debug("NATS drain failed", exc_info=True)
    try:
        if not nc.is_closed:
            await nc.close()
    except Exception:  # noqa: BLE001
        LOG.debug("NATS close failed", exc_info=True)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def build_source(config: ForwarderConfig, client: SyslogClient):
    """The source named by ``config.mode``, over the config's own environment.

    No ``Settings`` argument, and that is the point: ``api.settings.load_settings``
    is the *API's* startup contract, and under the default ``OCTO_ENV=prod`` it
    refuses to return without a JWT secret, an explicit CORS origin list and a
    public base URL. This process serves no requests and issues no tokens, so
    demanding those would make the forwarder undeployable for reasons that have
    nothing to do with forwarding. :class:`ForwarderConfig` reads the two values
    it does need — ``OCTO_NATS_URL`` and ``OCTO_POSTGRES_URL`` — itself, and
    :meth:`ForwarderConfig.validate` is what refuses a mode whose value is
    missing, at startup rather than on the first message.
    """
    config.validate()
    if config.mode == SOURCE_DB:
        return DatabaseSource(config=config, client=client)
    return NatsSource(config=config, nats_url=config.nats_url, client=client)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m api.services.audit_syslog_forwarder",
        description="Forward audit_events to a SIEM as CEF over RFC 5424 syslog (#328).",
    )
    parser.add_argument(
        "--source",
        choices=(SOURCE_NATS, SOURCE_DB),
        default=None,
        help="Override OCTO_AUDIT_SYSLOG_SOURCE (default: nats)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    config = ForwarderConfig()
    if args.source:
        config.mode = args.source
    try:
        config.validate()
        client = SyslogClient(config)
        source = build_source(config, client)
    except Exception as exc:  # noqa: BLE001 - this is a CLI boundary
        LOG.error("%s", exc)
        return 2

    def _shutdown(_signum, _frame) -> None:
        LOG.info("Shutting down; stats=%s", source.stats)
        source.stop()

    for received in (signal.SIGTERM, signal.SIGINT):
        signal.signal(received, _shutdown)

    LOG.info(
        "Audit syslog forwarder starting (source=%s target=%s host=%s)",
        config.mode,
        config.url,
        config.hostname,
    )
    started = time.monotonic()
    try:
        source.run()
    finally:
        client.close()
        LOG.info(
            "Audit syslog forwarder stopped after %.0fs stats=%s",
            time.monotonic() - started,
            source.stats,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
