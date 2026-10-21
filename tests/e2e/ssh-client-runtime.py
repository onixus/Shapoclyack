"""Exercise the shipped SSH client as the image's unprivileged runtime user."""
from __future__ import annotations

import base64
import os
import re
import socket
import subprocess
import time
from pathlib import Path

from api.schemas import AgentDeploySSHRequest
from api.services import agent_deployer as deployer
from api.services.agent_deployer import HostKey, fingerprint_of


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, timeout=90, **kwargs)


def main():
    assert os.getuid() != 0, "test must exercise the shipped non-root user"
    version = run(["ssh", "-V"]).stderr.decode()
    assert version.startswith("OpenSSH_10.6p1,"), version
    packages = subprocess.run(
        ["dpkg-query", "-W", "-f=${db:Status-Status}", "openssh-client"],
        capture_output=True, check=False,
    )
    assert packages.stdout != b"installed", "vulnerable distro package remains"
    host, port = "sshd", 2222
    for attempt in range(60):
        try:
            with socket.create_connection((host, port), timeout=1):
                break
        except OSError:
            if attempt == 59:
                raise
            time.sleep(1)
    key = deployer.probe_host_key(host, port, timeout=10)
    assert key.fingerprint == os.environ["OCTO_SSHD_TEST_FINGERPRINT"]
    req = dict(host=host, port=port, username="deploy", password="deploy-ci-secret")
    private = Path("/ssh-test/client_key").read_text()
    payload = "shapoclyack-stdin-control\n"
    for auth in ({}, {"password": None, "private_key": private}):
        request = AgentDeploySSHRequest(**(req | auth))
        code, out, err = deployer._execute_ssh_command(
            request, "cat", host_key=key, stdin_data=payload, timeout=30,
        )
        assert code == 0 and out == payload, (code, out, err)
    badkey = Path("/ssh-test/wrong_host")
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(badkey)])
    kind, blob = badkey.with_suffix(".pub").read_text().split()[:2]
    wrong = HostKey(key_type=kind, public_key=blob,
                    fingerprint=fingerprint_of(base64.b64decode(blob)))
    for invalid, pin in (({}, wrong), ({"password": "wrong-password"}, key)):
        code, out, err = deployer._execute_ssh_command(
            AgentDeploySSHRequest(**(req | invalid)), "id -u", host_key=pin, timeout=30,
        )
        assert code != 0 and out == "", (code, out, err)
        assert ("Host key verification failed" in err or
                "REMOTE HOST IDENTIFICATION" in err or "Permission denied" in err), err
    known = Path("/ssh-test/known_hosts")
    known.write_text(f"[{host}]:{port} {key.key_type} {key.public_key}\n")
    opts = ["-i", "/ssh-test/client_key", "-o", "BatchMode=yes", "-o",
            "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}"]
    bulk = b"0123456789abcdef" * 131072
    rekey = run(["ssh", "-vv", *opts, "-p", str(port), "-o", "RekeyLimit=16K",
                 "deploy@sshd", "cat"], input=bulk)
    assert rekey.stdout == bulk
    newkeys = len(re.findall(rb"SSH2_MSG_NEWKEYS sent", rekey.stderr))
    assert newkeys > 1, rekey.stderr.decode(errors="replace")
    source = Path("/ssh-test/upload")
    source.write_bytes(bulk)
    remote = f"/tmp/shapo-client-{os.getpid()}"
    try:
        run(["scp", *opts, "-P", str(port), str(source), f"deploy@sshd:{remote}"])
        run(["scp", *opts, "-P", str(port), f"deploy@sshd:{remote}", "/ssh-test/download"])
        assert Path("/ssh-test/download").read_bytes() == bulk
        run(["sftp", *opts, "-P", str(port), "-b", "-", "deploy@sshd"],
            input=f"get {remote} /ssh-test/sftp-download\n".encode())
        assert Path("/ssh-test/sftp-download").read_bytes() == bulk
        # Legacy SCP also calls the compiled SSH path and must find the fixed client.
        run(["scp", "-O", *opts, "-P", str(port), f"deploy@sshd:{remote}", "/ssh-test/legacy-download"])
        assert Path("/ssh-test/legacy-download").read_bytes() == bulk
    finally:
        run(["ssh", *opts, "-p", str(port), "deploy@sshd", f"rm -f {remote}"])
    print(f"{version.strip()}: non-root password/key/stdin, wrong-pin/password refusal, "
          f"{newkeys} NEWKEYS, SCP/SFTP/legacy-SCP roundtrips passed")


if __name__ == "__main__":
    main()
