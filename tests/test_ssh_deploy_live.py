"""The SSH push deployment's transport, against a real ``sshd``.

Everything else about ``api/services/agent_deployer.py`` is unit-tested with
``ssh`` replaced by a recording stub. That leaves exactly the claim a stub can
never make: that the argv the deployer builds is one OpenSSH accepts, that the
``SSH_ASKPASS`` helper is what the client actually calls for the password, that
the one-entry ``known_hosts`` is honoured and a wrong pin is a refusal rather
than a prompt, and that stdin reaches the remote command. #272 — an argv the
client parsed as options — lived on ``main`` for two days precisely because no
test ever handed the argv to ``ssh``.

The environment names the target; ``tests/e2e/ssh-deploy.sh`` (locally) and the
Jenkins stage of the same name start the server and set these:

- ``OCTO_SSHD_TEST_HOST`` / ``OCTO_SSHD_TEST_PORT`` — where ``sshd`` listens;
- ``OCTO_SSHD_TEST_USER`` / ``OCTO_SSHD_TEST_PASSWORD`` — a password login;
- ``OCTO_SSHD_TEST_FINGERPRINT`` — ``SHA256:…`` of the server's ed25519 key,
  read *from the server's own files*, which is what the probe is checked against;
- ``OCTO_SSHD_TEST_KEY_FILE`` — optional: a private key the server also accepts.

Unset, the module is skipped: this is a live test, not a unit test.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from api.schemas import AgentDeploySSHRequest
from api.services import agent_deployer as deployer
from api.services.agent_deployer import HostKey, fingerprint_of

_HOST = os.environ.get("OCTO_SSHD_TEST_HOST", "")

pytestmark = pytest.mark.skipif(
    not _HOST,
    reason="OCTO_SSHD_TEST_HOST not set (live sshd) — see tests/e2e/ssh-deploy.sh",
)


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        pytest.fail(f"{name} is required alongside OCTO_SSHD_TEST_HOST")
    return value


@pytest.fixture(scope="module")
def target() -> dict[str, object]:
    if not shutil.which("ssh") or not shutil.which("ssh-keyscan"):
        pytest.fail("openssh-client is not installed where this test runs")
    return {
        "host": _HOST,
        "port": int(os.environ.get("OCTO_SSHD_TEST_PORT", "22")),
        "username": _env("OCTO_SSHD_TEST_USER"),
        "password": _env("OCTO_SSHD_TEST_PASSWORD"),
        "fingerprint": _env("OCTO_SSHD_TEST_FINGERPRINT"),
    }


@pytest.fixture(scope="module")
def host_key(target: dict[str, object]) -> HostKey:
    """The key as the deployer reads it off the wire, before any credential."""
    return deployer.probe_host_key(str(target["host"]), int(target["port"]), timeout=10)


def _request(target: dict[str, object], **overrides: object) -> AgentDeploySSHRequest:
    fields: dict[str, object] = {
        "host": target["host"],
        "port": target["port"],
        "username": target["username"],
        "password": target["password"],
    }
    fields.update(overrides)
    return AgentDeploySSHRequest(**fields)  # type: ignore[arg-type]


def test_the_probe_reads_the_key_the_server_actually_holds(target, host_key):
    """``ssh-keyscan``'s answer must equal ``ssh-keygen -lf`` on the server's
    own key file — the fingerprint the operator is told to compare against."""
    assert host_key.key_type == "ssh-ed25519"
    assert host_key.fingerprint == target["fingerprint"]
    # The fingerprint the API stores is derived from the blob it pins, so the
    # two cannot drift apart between the probe and the pin.
    import base64

    assert fingerprint_of(base64.b64decode(host_key.public_key)) == host_key.fingerprint


def test_a_password_reaches_the_client_through_askpass(target, host_key):
    """The connectivity check the worker runs first, over a password login.

    The password travels via ``SSH_ASKPASS``; if the client ignored the helper
    it would wait on a tty that ``start_new_session`` denies it, and the
    command would time out or fail rather than answer.
    """
    code, out, err = deployer._execute_ssh_command(
        _request(target), "uname -s -m && id -u", host_key=host_key, timeout=30
    )
    assert code == 0, err
    lines = out.split()
    assert lines[0] == "Linux"
    assert lines[-1].isdigit()


def test_stdin_reaches_the_remote_command(target, host_key):
    """The provisioning key is fed to the installer on stdin, never in argv
    (#232). ``cat`` echoing it back proves the channel is wired through."""
    secret = "prov-key-for-stdin-only\n"
    code, out, err = deployer._execute_ssh_command(
        _request(target), "cat", host_key=host_key, timeout=30, stdin_data=secret
    )
    assert code == 0, err
    assert out == secret


def test_a_wrong_pin_is_refused_by_the_client_and_not_prompted(target, host_key, tmp_path: Path):
    """A pin that does not match the server is a refusal from OpenSSH itself,
    with no prompt to accept the new key — ``BatchMode``/``StrictHostKeyChecking``
    are only worth anything if the client honours them, which is not a thing a
    stubbed ``ssh`` can show."""
    other = tmp_path / "other_host_key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key_type, blob_b64 = other.with_suffix(".pub").read_text().split()[:2]
    import base64

    wrong = HostKey(
        key_type=key_type,
        public_key=blob_b64,
        fingerprint=fingerprint_of(base64.b64decode(blob_b64)),
    )
    assert wrong.fingerprint != host_key.fingerprint

    code, out, err = deployer._execute_ssh_command(
        _request(target), "id -u", host_key=wrong, timeout=30
    )
    assert code != 0
    assert out == ""
    assert "Host key verification failed" in err or "REMOTE HOST IDENTIFICATION" in err


def test_a_wrong_password_is_a_failure_and_not_a_hang(target, host_key):
    code, out, err = deployer._execute_ssh_command(
        _request(target, password="not-the-password"), "id -u", host_key=host_key, timeout=30
    )
    assert code != 0
    assert out == ""
    assert "Permission denied" in err


def test_a_private_key_login_uses_batch_mode(target, host_key):
    key_file = os.environ.get("OCTO_SSHD_TEST_KEY_FILE", "")
    if not key_file:
        pytest.skip("OCTO_SSHD_TEST_KEY_FILE not set")
    private_key = Path(key_file).read_text()
    code, out, err = deployer._execute_ssh_command(
        _request(target, password=None, private_key=private_key),
        "id -u",
        host_key=host_key,
        timeout=30,
    )
    assert code == 0, err
    assert out.strip().isdigit()
