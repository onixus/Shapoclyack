"""UI-Driven Remote SSH Agent Deployer Service.

Allows operators to remotely push and install the Shapoclyack Agent onto
Linux target hosts via SSH directly from the Web UI.

Two things travel down this SSH channel: the operator's credentials for the
target host (often root) and a freshly minted tenant provisioning key. The
deployer used to accept whatever host key answered — ``AutoAddPolicy`` on the
Paramiko path, ``StrictHostKeyChecking=no`` on the OpenSSH one — so anything
that could answer for the target's address received both (#232). Now every
run resolves the target's host key *before* a credential is sent:

* a key already pinned for this tenant and target must match, or the run is
  refused — a changed key is reported, never re-added;
* an unpinned target is refused too, unless the request names the fingerprint
  the operator verified out of band, which is then pinned for next time.

The pin is per tenant (``agent_ssh_host_keys``): one tenant must not be able
to decide which key another tenant's deployment will trust. Removing a pin is
:func:`unpin_host_key` and its route (#241) rather than a SQL statement: a
machine really is rebuilt sometimes, and a legitimate operation that only the
database can perform is one that ends up performed by handing ``expected_host_key``
whatever the target offered, which switches the check off while leaving it on.

**Where a deployment may point.** Both the probe and the run open a TCP
connection to a host and port that came from a request body, so both go
through :func:`assert_target_allowed` first (#240). That check is deliberately
*not* the webhook boundary: an agent belongs inside a private network, so
RFC1918 is the ordinary answer here and refusing it would refuse the product.
What it refuses instead is the platform's own reflection — loopback,
link-local, multicast — a port outside the configured SSH list, and any host
the tenant's approved scan scope prohibits (#226). See
``api/services/outbound_targets.py`` for the two policies side by side.

Run state lives in ``agent_deployments`` rather than in this process (#223).
The previous in-memory registry meant the status poll only answered on the
replica that started the run, so a successful deployment answered 404 as soon
as there was more than one API pod.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import logging
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.schemas import AgentDeploySSHRequest, AgentDeployStatusResponse, AgentSSHHostKeyInfo
from api.services import agents as agents_service
from api.services import auth_audit
from api.services import outbound_targets
from api.services import scan_scopes
from api.services import tenants as tenants_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.agent-deployer")

_settings: Settings | None = None

# Every deployment runs on its own daemon thread, and the route answers before
# the install finishes -- that is the point of the route. Daemon threads are
# right for a process that must not be held open by an install nobody is
# waiting for, but they leave no handle to wait on, and the test suite needs
# one: a worker still writing its stage rows into a database the next test is
# about to truncate is the flake #257 was filed for. Holding the handles here
# costs one set entry per deployment and gives :func:`join_workers` something
# to join.
_workers: set[threading.Thread] = set()
_workers_lock = threading.Lock()


def join_workers(timeout: float = 10.0) -> bool:
    """Wait for the in-flight deployment threads. Returns False on timeout.

    Test-suite scaffolding rather than a production path: nothing in the API
    blocks on a deployment finishing. Threads that already finished are dropped
    from the registry either way, so a long-lived process does not accumulate
    dead handles.
    """
    with _workers_lock:
        pending = list(_workers)
    deadline = time.monotonic() + timeout
    for thread in pending:
        thread.join(max(0.0, deadline - time.monotonic()))
    with _workers_lock:
        _workers.difference_update({t for t in pending if not t.is_alive()})
        return not any(t.is_alive() for t in pending)

# Deployment rows kept per tenant. The journal is an operator surface, not an
# audit trail: it exists so a poll started ten minutes ago still resolves.
_MAX_HISTORY = 100

# How long the run waits for the freshly installed agent's first heartbeat.
# Named constants because the wait is also what makes the worker thread
# long-lived, and a test that drives a full deployment has to be able to shorten
# it without patching the time module out from under everything else.
_VERIFY_ATTEMPTS = 15
_VERIFY_INTERVAL_SECONDS = 2.0

# Log lines kept on one run. An installer that talks for an hour must not turn
# a single row into an unbounded document.
_MAX_LOG_LINES = 500

# What ssh-keyscan is asked for. Its -t vocabulary is the short family name,
# not the algorithm name that appears in known_hosts — the two lists below are
# the same thing spelled the two ways OpenSSH spells it.
_KEYSCAN_TYPES = "ed25519,ecdsa,rsa"

# known_hosts algorithm names, best first. A target offering several gets the
# strongest one pinned, which is also the one OpenSSH would negotiate.
_HOST_KEY_TYPES = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp256",
    "ssh-rsa",
)


class HostKeyUnavailable(RuntimeError):
    """The target's host key could not be read at all — nothing was sent to it."""


class HostKeyUnverified(ValueError):
    """The target has no pinned key and the request named no expected fingerprint."""


class HostKeyMismatch(ValueError):
    """The key the target offered is not the one this tenant pinned for it."""


class DeployTargetDenied(PermissionError):
    """This tenant may not open a connection to that host or port (#240).

    A ``PermissionError`` for the same reason ``scan_scopes.ScanScopeDenied``
    is one: the request is well-formed and the caller is authenticated, they
    are simply not entitled to that target, so the route answers 403 rather
    than 422.
    """


@dataclass(frozen=True)
class HostKey:
    """One SSH host key, in the two forms the rest of this module needs."""

    key_type: str
    public_key: str
    fingerprint: str


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "agent_deployer.configure() not called"
    return _settings


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if dt else None


# --------------------------------------------------------------------------
# Host keys
# --------------------------------------------------------------------------


def fingerprint_of(key_blob: bytes) -> str:
    """OpenSSH's ``SHA256:...`` fingerprint, so it can be compared by eye.

    Same string ``ssh-keyscan host | ssh-keygen -lf -`` prints, padding
    stripped, which is what an operator has in front of them.
    """
    digest = hashlib.sha256(key_blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def normalise_fingerprint(value: str) -> str:
    """Accept what an operator is likely to paste, reject what cannot be compared.

    ``SHA256:`` prefixed or bare base64 both work — the prefix is what
    ``ssh-keygen -lf`` prints and the bare form is what someone trims it to.
    An MD5 fingerprint (``16:27:ac:...``) is refused rather than silently
    never matching: it is a different hash, not a different spelling.
    """
    candidate = value.strip()
    if not candidate:
        raise HostKeyUnverified("An empty host key fingerprint verifies nothing.")
    if candidate.upper().startswith("MD5:") or ":" in candidate.removeprefix("SHA256:"):
        raise HostKeyUnverified(
            "Host key fingerprints must be the SHA256 form "
            "(SHA256:… as printed by ssh-keygen -lf); MD5 is not accepted."
        )
    if not candidate.startswith("SHA256:"):
        candidate = f"SHA256:{candidate}"
    return candidate.rstrip("=")


def _deny(actor: str, tenant_id: str, host: str, port: int, reason: str) -> DeployTargetDenied:
    """Journal one refused target and return the exception to raise.

    Best-effort like ``scan_scopes.record_denial``: the target has already been
    refused when this runs, and losing the journal write must not turn a clean
    403 into a 500 — but it is logged, because an access decision that left no
    trace is itself worth noticing.
    """
    try:
        auth_audit.record_denied(
            username=actor,
            reason=auth_audit.REASON_DEPLOY_TARGET,
            detail=f"tenant={tenant_id} target={host}:{port} {reason}"[:1000],
        )
    except Exception:  # noqa: BLE001 - see docstring
        LOG.exception(
            "Failed to record the refused deployment target %s:%s for tenant %s",
            host,
            port,
            tenant_id,
        )
    return DeployTargetDenied(reason)


def assert_target_allowed(*, tenant_id: str, host: str, port: int, actor: str) -> None:
    """Refuse a deployment target this tenant must not connect to (#240).

    Two questions, in the order that makes the cheap one first:

    1. Is this an address and port anything could legitimately be deployed on?
       ``outbound_targets.ssh_deploy_policy`` accepts private space — that is
       where agents live — and refuses the API pod's own reflection and any
       port outside the configured SSH list.
    2. Is *this tenant* allowed near this host? The approved scan scope (#226)
       already answers that for scan targets, and a host a tenant was told not
       to touch must not become reachable by another route. By default only the
       scope's prohibitions apply; ``agent_deploy_enforce_scan_scope`` also
       demands containment, which is a stricter claim than most fleets can
       make (see ``scan_scopes.rejections_for_host``).

    Raises :class:`DeployTargetDenied`; every refusal is journalled first.
    """
    settings = _require_settings()
    policy = outbound_targets.ssh_deploy_policy(
        allowed_ports=outbound_targets.parse_ports(settings.agent_deploy_ssh_ports)
    )
    try:
        target = outbound_targets.resolve_target(host, port, policy=policy)
    except outbound_targets.OutboundTargetError as exc:
        raise _deny(actor, tenant_id, host, port, str(exc)) from exc

    require_allow = settings.agent_deploy_enforce_scan_scope
    scope = scan_scopes.load_scope(settings, tenant_id)
    if require_allow:
        try:
            scope.require_approved()
        except scan_scopes.ScanScopeDenied as exc:
            raise _deny(actor, tenant_id, host, port, str(exc)) from exc
    refused = scan_scopes.rejections_for_host(
        scope,
        host=target.hostname,
        addresses=[str(address) for address in target.addresses],
        deny_only=not require_allow,
    )
    if refused:
        raise _deny(
            actor,
            tenant_id,
            host,
            port,
            f"deployment target outside the approved scan scope of tenant "
            f"{tenant_id}: {', '.join(refused)}",
        )


def _probe_with_paramiko(host: str, port: int, timeout: int) -> HostKey | None:
    """Read the host key over a transport that carries no credential.

    Returns ``None`` when Paramiko is not installed — it is not a declared
    dependency, so the OpenSSH path below is the one that actually runs in the
    shipped image.
    """
    try:
        import paramiko
    except ImportError:
        return None

    transport = paramiko.Transport((host, port))
    try:
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
    finally:
        transport.close()
    blob = key.asbytes()
    return HostKey(
        key_type=key.get_name(),
        public_key=base64.b64encode(blob).decode("ascii"),
        fingerprint=fingerprint_of(blob),
    )


def _probe_with_keyscan(host: str, port: int, timeout: int) -> HostKey:
    """Read the host key with ``ssh-keyscan``, which also sends no credential."""
    if not shutil.which("ssh-keyscan"):
        raise HostKeyUnavailable(
            "Cannot read the target's SSH host key: neither Paramiko nor ssh-keyscan "
            "is available in this API image."
        )
    proc = subprocess.run(
        [
            "ssh-keyscan",
            "-T", str(timeout),
            "-p", str(port),
            "-t", _KEYSCAN_TYPES,
            host,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout + 10,
        check=False,
    )
    offered: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        # ssh-keyscan prints "# comment" lines alongside the keys.
        if len(parts) == 3 and not line.startswith("#"):
            offered.setdefault(parts[1], parts[2])
    if not offered:
        raise HostKeyUnavailable(
            f"No SSH host key returned by {host}:{port} — the target is unreachable, "
            f"or nothing is listening on that port. ({proc.stderr.strip()[:200]})"
        )
    for key_type in _HOST_KEY_TYPES:
        if key_type in offered:
            blob = base64.b64decode(offered[key_type])
            return HostKey(
                key_type=key_type,
                public_key=offered[key_type],
                fingerprint=fingerprint_of(blob),
            )
    key_type, encoded = next(iter(offered.items()))
    return HostKey(
        key_type=key_type,
        public_key=encoded,
        fingerprint=fingerprint_of(base64.b64decode(encoded)),
    )


def probe_host_key(host: str, port: int, *, timeout: int = 10) -> HostKey:
    """Read the key ``host:port`` presents, without authenticating to it.

    Deliberately separate from the deployment: the operator gets the
    fingerprint to compare against the target's own ``ssh-keygen -lf
    /etc/ssh/ssh_host_*_key.pub`` before any credential is put on the wire.
    Nothing is pinned here — trusting the key is the operator's act, expressed
    by passing it back as ``expected_host_key``.
    """
    try:
        from_paramiko = _probe_with_paramiko(host, port, timeout)
    except Exception as exc:  # noqa: BLE001 - reported to the caller verbatim
        LOG.debug("Paramiko host key probe of %s:%s failed: %s", host, port, exc)
        from_paramiko = None
    if from_paramiko is not None:
        return from_paramiko
    try:
        return _probe_with_keyscan(host, port, timeout)
    except subprocess.TimeoutExpired as exc:
        raise HostKeyUnavailable(
            f"Timed out reading the SSH host key of {host}:{port}."
        ) from exc


def get_pinned_host_key(tenant_id: str, host: str, port: int) -> AgentSSHHostKeyInfo | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = _load_pin(session, tenant_id, host, port)
        if row is None:
            return None
        return AgentSSHHostKeyInfo(
            host=row.host,
            port=row.port,
            key_type=row.key_type,
            fingerprint=row.fingerprint,
            pinned=True,
            pinned_at=_iso(row.created_at),
        )


def describe_host_key(*, tenant_id: str, host: str, port: int, actor: str) -> AgentSSHHostKeyInfo:
    """The pinned key for this target, or the one it is currently offering.

    The policy check runs first and runs even when a pin already exists: a pin
    records that this target was once approved, not that it still is, and the
    tenant's scope may have been narrowed since (#240).
    """
    assert_target_allowed(tenant_id=tenant_id, host=host, port=port, actor=actor)
    pinned = get_pinned_host_key(tenant_id, host, port)
    if pinned is not None:
        return pinned
    key = probe_host_key(host, port)
    return AgentSSHHostKeyInfo(
        host=host,
        port=port,
        key_type=key.key_type,
        fingerprint=key.fingerprint,
        pinned=False,
    )


def unpin_host_key(*, tenant_id: str, host: str, port: int, actor: str) -> AgentSSHHostKeyInfo:
    """Drop this tenant's pin for ``host:port`` and return what was removed (#241).

    A machine is reinstalled, a box is replaced, a key is rotated — all
    ordinary, and all of them leave a pin that no longer matches. Until this
    route existed the only way through was a DELETE against the database,
    which is a privilege the person running the agent fleet does not have and
    should not need; the predictable substitute was to pass whatever
    fingerprint the target offered as ``expected_host_key``, which leaves the
    check switched on and meaning nothing.

    The removal is journalled with the fingerprint that was dropped, and the
    next deployment journals the one it pins. That *pair* is the point: one
    unpin followed by a pin of a different key is either a rebuilt machine or a
    substitution, and only the trail can tell the two apart afterwards.

    Raises LookupError when this tenant has nothing pinned for the target — the
    same answer as a target that was never deployed to, because the caller
    learning which hosts another tenant pinned is the whole of what leaks here.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = _load_pin(session, tenant_id, host, port)
        if row is None:
            raise LookupError(f"no SSH host key pinned for {host}:{port}")
        removed = AgentSSHHostKeyInfo(
            host=row.host,
            port=row.port,
            key_type=row.key_type,
            fingerprint=row.fingerprint,
            # False: this is what the pin *was*. The caller is holding a receipt
            # for a removal, not a description of current state.
            pinned=False,
            pinned_at=_iso(row.created_at),
        )
        session.delete(row)
        session.flush()

    _record_pin_change(
        actor,
        auth_audit.REASON_HOST_KEY_UNPINNED,
        tenant_id=tenant_id,
        host=host,
        port=port,
        key=removed.key_type,
        fingerprint=removed.fingerprint,
    )
    return removed


def _record_pin_change(
    actor: str,
    reason: str,
    *,
    tenant_id: str,
    host: str,
    port: int,
    key: str,
    fingerprint: str,
) -> None:
    """Journal a pin being set or removed. Best-effort, like ``_deny``."""
    try:
        auth_audit.record_trust_change(
            username=actor,
            reason=reason,
            detail=f"tenant={tenant_id} target={host}:{port} {key} {fingerprint}"[:1000],
        )
    except Exception:  # noqa: BLE001 - a lost journal write must not fail the request
        LOG.exception(
            "Failed to record SSH host key %s for %s:%s (tenant %s)",
            reason,
            host,
            port,
            tenant_id,
        )


def _load_pin(session: Any, tenant_id: str, host: str, port: int) -> Any:
    return session.execute(
        select(models.AgentSshHostKey).where(
            models.AgentSshHostKey.tenant_id == tenant_id,
            models.AgentSshHostKey.host == host,
            models.AgentSshHostKey.port == port,
        )
    ).scalars().first()


def resolve_host_key(
    *,
    tenant_id: str,
    host: str,
    port: int,
    expected_fingerprint: str | None,
    actor: str,
) -> tuple[HostKey, bool]:
    """Decide which host key this run is allowed to talk to.

    Returns the key and whether it was pinned by this call. Raises rather than
    falling back: every branch that cannot *prove* which host is answering ends
    the run before a credential exists.
    """
    settings = _require_settings()
    # Before the socket, not after: an unreachable-target message is still an
    # answer about the network behind this API, so the target has to be one
    # this tenant may point at at all (#240).
    assert_target_allowed(tenant_id=tenant_id, host=host, port=port, actor=actor)
    live = probe_host_key(host, port)

    with get_session(settings.postgres_url) as session:
        pinned = _load_pin(session, tenant_id, host, port)
        if pinned is not None:
            if pinned.fingerprint != live.fingerprint:
                raise HostKeyMismatch(
                    f"The SSH host key of {host}:{port} is not the one pinned for this "
                    f"tenant. Pinned {pinned.fingerprint}, offered {live.fingerprint}. "
                    "Either the target was rebuilt — remove the pin once you have "
                    "confirmed that with its owner — or something else is answering "
                    "for its address. No credentials were sent."
                )
            pinned.last_used_at = _now()
            session.flush()
            return live, False

        if not expected_fingerprint:
            raise HostKeyUnverified(
                f"{host}:{port} has no pinned SSH host key for this tenant. It is "
                f"currently offering {live.key_type} {live.fingerprint}. Confirm that "
                "against the target itself (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub "
                "on the host) and re-send the deployment with expected_host_key set to "
                "it. Nothing has been sent to the target."
            )

        expected = normalise_fingerprint(expected_fingerprint)
        if expected != live.fingerprint:
            raise HostKeyMismatch(
                f"The SSH host key of {host}:{port} does not match the expected "
                f"fingerprint. Expected {expected}, offered {live.fingerprint}. "
                "No credentials were sent."
            )

        session.add(
            models.AgentSshHostKey(
                tenant_id=tenant_id,
                host=host,
                port=port,
                key_type=live.key_type,
                public_key=live.public_key,
                fingerprint=live.fingerprint,
                created_at=_now(),
                last_used_at=_now(),
            )
        )
        session.flush()

    # Outside the session: the pin is the fact being journalled, so it is
    # journalled once it is committed rather than once it is staged.
    _record_pin_change(
        actor,
        auth_audit.REASON_HOST_KEY_PINNED,
        tenant_id=tenant_id,
        host=host,
        port=port,
        key=live.key_type,
        fingerprint=live.fingerprint,
    )
    return live, True


def _known_hosts_line(host: str, port: int, key: HostKey) -> str:
    target = host if port == 22 else f"[{host}]:{port}"
    return f"{target} {key.key_type} {key.public_key}\n"


@contextlib.contextmanager
def _known_hosts_file(host: str, port: int, key: HostKey):
    """A one-entry ``known_hosts`` both SSH paths verify against.

    One file rather than two mechanisms: Paramiko's ``HostKeys`` and OpenSSH
    read the same format, so the key that was verified is literally the key
    both clients are handed.
    """
    fd, path = tempfile.mkstemp(prefix="shapoclyack_known_hosts_")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(_known_hosts_line(host, port, key))
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        yield path
    finally:
        with contextlib.suppress(OSError):
            os.remove(path)


@contextlib.contextmanager
def _askpass_script():
    """An ``SSH_ASKPASS`` helper that reads the password from its environment.

    ``sshpass -p <password>`` put the operator's password for the target host
    into this container's argv, where ``/proc/*/cmdline`` makes it readable by
    every local user (#232). A process' environment is readable only by the
    same uid and root, which is the improvement being bought here.
    """
    fd, path = tempfile.mkstemp(prefix="shapoclyack_askpass_", suffix=".sh")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write('#!/bin/sh\nprintf "%s\\n" "$SHAPOCLYACK_SSH_PASSWORD"\n')
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        yield path
    finally:
        with contextlib.suppress(OSError):
            os.remove(path)


# --------------------------------------------------------------------------
# Remote execution
# --------------------------------------------------------------------------


def _execute_ssh_command(
    req: AgentDeploySSHRequest,
    command: str,
    *,
    host_key: HostKey,
    timeout: int = 120,
    stdin_data: str | None = None,
) -> tuple[int, str, str]:
    """Execute a remote shell command, against ``host_key`` and nothing else.

    ``stdin_data`` is how a secret reaches the remote command without ever
    appearing in the target's process list — the provisioning key is fed to
    the installer this way.
    """
    with _known_hosts_file(req.host, req.port, host_key) as known_hosts:
        # Attempt paramiko first
        try:
            import io

            import paramiko

            client = paramiko.SSHClient()
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

            pkey = None
            if req.private_key and req.private_key.strip():
                key_str = req.private_key.strip()
                key_file = io.StringIO(key_str)
                for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                    try:
                        key_file.seek(0)
                        pkey = key_cls.from_private_key(key_file)
                        break
                    except Exception:
                        continue

            client.connect(
                hostname=req.host,
                port=req.port,
                username=req.username,
                password=req.password,
                pkey=pkey,
                timeout=15,
                allow_agent=False,
                look_for_keys=False,
            )
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            if stdin_data is not None:
                stdin.write(stdin_data)
                stdin.flush()
                stdin.channel.shutdown_write()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            client.close()
            return exit_code, out, err
        except ImportError:
            pass
        except Exception as exc:
            return 1, "", f"Paramiko SSH failed: {exc}"

        return _execute_openssh_command(
            req,
            command,
            known_hosts=known_hosts,
            timeout=timeout,
            stdin_data=stdin_data,
        )


def _execute_openssh_command(
    req: AgentDeploySSHRequest,
    command: str,
    *,
    known_hosts: str,
    timeout: int,
    stdin_data: str | None,
) -> tuple[int, str, str]:
    key_file_path = None
    env = dict(os.environ)
    try:
        cmd = [
            "ssh",
            # StrictHostKeyChecking=yes with a known_hosts holding exactly the
            # verified key: an unknown or changed key is a refusal, and there is
            # no prompt to answer because BatchMode forbids one.
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "ConnectTimeout=15",
            "-p", str(req.port),
        ]
        if req.private_key and req.private_key.strip():
            fd, key_file_path = tempfile.mkstemp(prefix="ssh_key_")
            with os.fdopen(fd, "w") as f:
                f.write(req.private_key.strip() + "\n")
            os.chmod(key_file_path, 0o600)
            cmd.extend(["-i", key_file_path, "-o", "BatchMode=yes"])

        with contextlib.ExitStack() as stack:
            if req.password and not (req.private_key and req.private_key.strip()):
                askpass = stack.enter_context(_askpass_script())
                env["SSH_ASKPASS"] = askpass
                # 8.4+ honours "force"; DISPLAY is what older clients look at
                # before they will call an askpass helper at all.
                env["SSH_ASKPASS_REQUIRE"] = "force"
                env.setdefault("DISPLAY", ":0")
                env["SHAPOCLYACK_SSH_PASSWORD"] = req.password

            cmd.append(f"{req.username}@{req.host}")
            cmd.append(command)

            res = subprocess.run(
                cmd,
                input=stdin_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
                env=env,
                # Detached from this process' controlling terminal, or ssh reads
                # the password from the tty instead of calling SSH_ASKPASS.
                start_new_session=True,
            )
        return res.returncode, res.stdout, res.stderr
    finally:
        if key_file_path and os.path.exists(key_file_path):
            with contextlib.suppress(OSError):
                os.remove(key_file_path)


# --------------------------------------------------------------------------
# Deployment journal
# --------------------------------------------------------------------------


def _to_status(row: models.AgentDeployment) -> AgentDeployStatusResponse:
    return AgentDeployStatusResponse(
        deploy_id=row.deploy_id,
        status=row.status,
        stage=row.stage,
        progress_percent=row.progress_percent,
        logs=list(row.logs or []),
        agent_id=row.agent_id,
        error=row.error,
        started_at=_iso(row.started_at),
        completed_at=_iso(row.completed_at),
    )


def get_deployment_status(deploy_id: str, *, tenant_id: str | None) -> AgentDeployStatusResponse | None:
    """One run, scoped to ``tenant_id``.

    A run belonging to another tenant is reported exactly like one that does
    not exist: the caller learning that ``dep_…`` is a real id somewhere else
    is the whole of what an id oracle leaks.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.AgentDeployment, deploy_id)
        if row is None:
            return None
        if tenant_id and row.tenant_id != tenant_id:
            return None
        return _to_status(row)


def _append_log(deploy_id: str, message: str) -> None:
    timestamp = datetime.now(UTC).strftime("%H:%M:%S")
    formatted = f"[{timestamp}] {message}"
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.AgentDeployment, deploy_id)
        if row is None:
            return
        # Reassigned rather than appended to: a JSON column mutated in place is
        # not seen as dirty, so the append would never be written back.
        row.logs = [*(row.logs or []), formatted][-_MAX_LOG_LINES:]
        session.flush()


def _update_stage(
    deploy_id: str,
    *,
    status: str | None = None,
    stage: str | None = None,
    progress_percent: int | None = None,
    error: str | None = None,
    agent_id: str | None = None,
) -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.AgentDeployment, deploy_id)
        if row is None:
            return
        if status:
            row.status = status
        if stage:
            row.stage = stage
        if progress_percent is not None:
            row.progress_percent = progress_percent
        if error:
            row.error = error
        if agent_id:
            row.agent_id = agent_id
        if status in ("completed", "failed"):
            row.completed_at = _now()
        session.flush()


def _prune_history(session: Any, tenant_id: str) -> None:
    stale = session.execute(
        select(models.AgentDeployment.deploy_id)
        .where(models.AgentDeployment.tenant_id == tenant_id)
        .order_by(models.AgentDeployment.started_at.desc())
        .offset(_MAX_HISTORY)
    ).scalars().all()
    for deploy_id in stale:
        row = session.get(models.AgentDeployment, deploy_id)
        if row is not None:
            session.delete(row)


# --------------------------------------------------------------------------
# The run itself
# --------------------------------------------------------------------------


def _install_command(
    req: AgentDeploySSHRequest,
    *,
    server_url: str,
    install_url: str,
    agent_id: str,
) -> str:
    """The remote command line — with no secret anywhere in it.

    The provisioning key is read by the installer from stdin (``--key-stdin``),
    because the whole command string becomes the argv of the remote shell and
    is therefore readable by every local user on the target. ``sudo -n`` for
    the same reason: a sudo that decides to prompt would consume the
    provisioning key as its password guess.
    """
    sudo_prefix = "" if req.username == "root" else "sudo -n "
    args = [
        "--key-stdin",
        "--server", server_url,
        "--tenant", req.tenant_id,
        "--agent-id", agent_id,
    ]
    if req.use_docker:
        args.append("--docker")
    quoted = " ".join(shlex.quote(part) for part in args)
    # Downloaded to a file rather than piped into bash, because the installer
    # reads the key from its own stdin and a pipe would already own it. The
    # trap, not `set -e`, is what removes the file: with `set -e` a failing
    # installer exits the shell before any cleanup line is reached.
    return (
        "INSTALLER=$(mktemp); "
        "trap 'rm -f \"$INSTALLER\"' EXIT; "
        f"curl -sSL --fail {shlex.quote(install_url)} -o \"$INSTALLER\" || exit 1; "
        f"{sudo_prefix}bash \"$INSTALLER\" {quoted}"
    )


def _deploy_worker(
    deploy_id: str,
    req: AgentDeploySSHRequest,
    server_url: str,
    host_key: HostKey,
) -> None:
    try:
        _update_stage(deploy_id, status="connecting", stage="Connecting to remote host", progress_percent=15)
        _append_log(
            deploy_id,
            f"Host key verified for {req.host}:{req.port} "
            f"({host_key.key_type} {host_key.fingerprint}).",
        )
        _append_log(deploy_id, f"Initiating SSH connection to {req.username}@{req.host}:{req.port}...")

        # Test remote connectivity
        code, out, err = _execute_ssh_command(
            req, "uname -s -m && id -u", host_key=host_key, timeout=20
        )
        if code != 0:
            err_msg = f"SSH connection failed (exit code {code}): {err.strip() or out.strip()}"
            _append_log(deploy_id, f"[ERROR] {err_msg}")
            _update_stage(deploy_id, status="failed", stage="Connection failed", error=err_msg)
            return

        remote_info = out.strip().replace("\n", " ")
        _append_log(deploy_id, f"Connected to host successfully: {remote_info}")

        # Provisioning Key
        _update_stage(deploy_id, status="installing", stage="Minting provisioning credentials", progress_percent=30)
        _append_log(deploy_id, f"Generating provisioning key for tenant '{req.tenant_id}'...")
        key_res = tenants_service.create_provisioning_key(
            tenant_id=req.tenant_id,
            label=f"SSH Remote Deploy on {req.host}",
        )
        provisioning_key = key_res["key"]
        agent_id = req.agent_id or f"agent-{req.host.replace('.', '-').replace(':', '-')}-{uuid.uuid4().hex[:6]}"
        _append_log(deploy_id, f"Provisioned agent_id: {agent_id}")

        # Run remote installer
        _update_stage(deploy_id, status="installing", stage="Running remote agent installation", progress_percent=55)
        clean_server = server_url.rstrip("/")
        install_url = f"{clean_server}/api/agent/install.sh"
        _append_log(deploy_id, f"Fetching installer script from {install_url}...")

        install_cmd = _install_command(
            req, server_url=clean_server, install_url=install_url, agent_id=agent_id
        )

        _append_log(deploy_id, "Executing installation payload on remote host...")
        code, out, err = _execute_ssh_command(
            req,
            install_cmd,
            host_key=host_key,
            timeout=300,
            # Never in the command line: the target's process list is world
            # readable, and the key registers agents into this tenant.
            stdin_data=f"{provisioning_key}\n",
        )

        # Log lines from remote output
        for line in out.splitlines():
            if line.strip():
                _append_log(deploy_id, f"[REMOTE] {line.strip()}")
        for line in err.splitlines():
            if line.strip():
                _append_log(deploy_id, f"[REMOTE ERR] {line.strip()}")

        if code != 0:
            err_msg = f"Remote installer exited with code {code}"
            _append_log(deploy_id, f"[ERROR] {err_msg}")
            _update_stage(deploy_id, status="failed", stage="Installation failed", error=err_msg)
            return

        # Verification step
        _update_stage(deploy_id, status="verifying", stage="Verifying agent heartbeat registration", progress_percent=85)
        _append_log(deploy_id, f"Waiting for agent {agent_id} to send initial heartbeat...")

        registered = False
        for _ in range(_VERIFY_ATTEMPTS):
            time.sleep(_VERIFY_INTERVAL_SECONDS)
            info = agents_service.get_agent(agent_id, tenant_id=req.tenant_id)
            if info and info.online:
                registered = True
                _append_log(deploy_id, f"Agent {agent_id} is ONLINE! Version: {info.version}, Hostname: {info.hostname}")
                break

        if not registered:
            _append_log(deploy_id, "[WARN] Agent service started, but heartbeat verification timed out (agent may take a moment).")

        _update_stage(
            deploy_id,
            status="completed",
            stage="Deployment successfully completed",
            progress_percent=100,
            agent_id=agent_id,
        )
        _append_log(deploy_id, f"Deployment completed successfully for agent {agent_id}.")

    except Exception as exc:
        LOG.exception("Unexpected error in agent SSH deployer")
        err_msg = f"Unexpected deployment error: {exc}"
        _append_log(deploy_id, f"[FATAL] {err_msg}")
        _update_stage(deploy_id, status="failed", stage="Fatal error", error=err_msg)


def start_ssh_deployment(req: AgentDeploySSHRequest, server_url: str, *, actor: str) -> str:
    """Verify the target's host key, then queue the push deployment.

    The host key is resolved **before** the run row exists, and synchronously,
    so an unverifiable target is a refusal the caller reads directly rather
    than a deployment that fails somewhere in a log. Nothing has been sent to
    the target at that point — the probe authenticates to nothing.
    """
    settings = _require_settings()
    host_key, newly_pinned = resolve_host_key(
        tenant_id=req.tenant_id,
        host=req.host,
        port=req.port,
        expected_fingerprint=req.expected_host_key,
        actor=actor,
    )

    deploy_id = f"dep_{uuid.uuid4().hex[:12]}"
    started = _now()
    opening = (
        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] "
        f"Deployment initialized for target {req.host}"
    )
    pin_note = (
        f"[{datetime.now(UTC).strftime('%H:%M:%S')}] "
        f"Pinned SSH host key {host_key.key_type} {host_key.fingerprint} for "
        f"{req.host}:{req.port}"
    )

    with get_session(settings.postgres_url) as session:
        session.add(
            models.AgentDeployment(
                deploy_id=deploy_id,
                tenant_id=req.tenant_id,
                host=req.host,
                port=req.port,
                username=req.username,
                status="queued",
                stage="Queued for deployment",
                progress_percent=5,
                agent_id=req.agent_id,
                logs=[opening, *([pin_note] if newly_pinned else [])],
                started_at=started,
            )
        )
        session.flush()
        _prune_history(session, req.tenant_id)

    thread = threading.Thread(
        target=_deploy_worker,
        args=(deploy_id, req, server_url, host_key),
        daemon=True,
        name=f"agent-deploy-{deploy_id}",
    )
    with _workers_lock:
        _workers.add(thread)
    thread.start()
    return deploy_id
