"""The shipped Rhai plugins as files (#544): contract, limits, attribution, behaviour.

Three layers. The first needs nothing but the files: every plugin defines what
Pulse's loader reads, is named like its file, stays inside the sandbox's limits
(GenDec v1.3.0 ``sandbox.rs``) and carries the licence header its origin
requires. The second needs a Pulse binary (``OCTO_PULSE_BIN`` or ``pulse`` on
PATH, otherwise skipped): ``pulse plugin check`` accepts every file. The third
runs the plugins with ``pulse plugin run`` against stub servers that speak just
enough of each protocol, which is the only way to know the sanitised-reply
parsing in ``shapo_ssh_algorithms`` works: its input is whatever Pulse's
sandbox leaves of a binary packet.
"""

from __future__ import annotations

import os
import random
import re
import shutil
import socket
import struct
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from scanner.pipeline import pulse_plugins

ROOT = Path(__file__).resolve().parents[1]
PLUGINS = sorted(pulse_plugins.PLUGINS_DIR.glob("*.rhai"))
PULSE = os.environ.get("OCTO_PULSE_BIN") or shutil.which("pulse")
needs_pulse = pytest.mark.skipif(not PULSE, reason="no pulse binary (OCTO_PULSE_BIN / PATH)")

#: Plugins adapted from GenDec scripts (MIT): they must say so, and NOTICE must too.
DERIVED = {
    "shapo_ssh_banner": "ssh_audit.rhai",
    "shapo_smb_exposure": "smb_netbios_exposure_audit.rhai",
    "shapo_remote_admin_exposure": "rdp_vnc_exposure_audit.rhai",
}


def _id(path: Path) -> str:
    return path.stem


# --------------------------------------------------------------------------
# Files only
# --------------------------------------------------------------------------


def test_the_directory_is_not_empty():
    assert len(PLUGINS) >= 6


@pytest.mark.parametrize("path", PLUGINS, ids=_id)
def test_plugin_defines_the_loader_contract_and_is_named_like_its_file(path):
    text = path.read_text(encoding="utf-8")
    for function in ("name", "description", "ports", "run"):
        assert re.search(rf"^fn {function}\(\)", text, re.M), f"{path.name} has no fn {function}()"
    declared = re.search(r'fn name\(\)\s*\{\s*"([^"]+)"\s*\}', text)
    assert declared and declared.group(1) == path.stem, (
        "name() is the cve_id suffix and the detector ref; it must be the file name"
    )
    assert path.stem.startswith("shapo_"), "a prefix keeps our finding ids apart from GenDec's bundled scripts"


@pytest.mark.parametrize("path", PLUGINS, ids=_id)
def test_plugin_stays_inside_the_sandbox_limits(path):
    text = path.read_text(encoding="utf-8")
    assert "http_get(" not in text, "http_get has a fixed 2 s timeout the time budget does not count"
    calls = re.findall(r"probe_(?:send|recv)\(([^;]*)\)\s*;", text)
    for arguments in calls:
        timeout = int(arguments.rsplit(",", 1)[1])
        assert timeout <= pulse_plugins.PLUGIN_CALL_TIMEOUT_MS, f"{path.name}: {arguments}"
    # Call sites, not calls: nothing here proves how many run on one path. The adapter's
    # time allowance rests on the reads in the sandbox, not on this count.
    assert len(calls) <= 4
    # The sandbox sends a Rhai string as UTF-8: a byte above 0x7F cannot be written
    # with it, so an escape that looks like one would silently send two others.
    assert not re.search(r"\\x[89a-fA-F][0-9a-fA-F]|\\u[0-9a-fA-F]{2}[89a-fA-F][0-9a-fA-F]|\\u00[89a-fA-F]", text)
    assert all(ord(ch) < 128 for ch in text), "non-ASCII source: say it in ASCII"


@pytest.mark.parametrize("path", PLUGINS, ids=_id)
def test_a_failed_probe_is_raised_not_swallowed(path):
    """A plugin that probes must throw when the probe fails.

    An empty result reads as "looked, clean" to a verification re-scan; the
    error lines are the only trace that it did not look.
    """
    text = path.read_text(encoding="utf-8")
    if "probe_send(" in text or "probe_recv(" in text:
        assert "throw " in text or re.search(r"\bexpect\(", text), path.name


@pytest.mark.parametrize("path", PLUGINS, ids=_id)
def test_plugin_carries_its_licence_header(path):
    head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:12])
    assert "SPDX-License-Identifier:" in head
    if path.stem in DERIVED:
        assert "SPDX-License-Identifier: MIT" in head
        assert f"GenDec scripts/{DERIVED[path.stem]}" in head
        assert "Changes for Shapoclyack" in head
    else:
        assert "SPDX-License-Identifier: Apache-2.0" in head


def test_notice_and_third_party_name_every_derived_plugin():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    third_party = (ROOT / "docs" / "third-party.md").read_text(encoding="utf-8")
    for plugin, origin in DERIVED.items():
        assert (pulse_plugins.PLUGINS_DIR / f"{plugin}.rhai").is_file()
        assert plugin in notice and origin in notice, plugin
        assert plugin in third_party, plugin
    assert "MIT" in notice


def test_plugin_budget_is_an_allowance_with_a_ceiling_not_a_promise():
    """The sandbox's timeout applies to every read, so no per-call bound exists (GenDec#38)."""
    assert pulse_plugins.plugin_budget_seconds(3) == 3 * pulse_plugins.PLUGIN_SECONDS_PER_ENDPOINT
    assert pulse_plugins.plugin_budget_seconds(0) == 0
    assert pulse_plugins.plugin_budget_seconds(10**6) == pulse_plugins.PLUGIN_BUDGET_CAP_SECONDS
    assert "worst case" not in (pulse_plugins.__doc__ or "").lower().replace("not a worst case", "")


@pytest.mark.parametrize("path", PLUGINS, ids=_id)
def test_ports_is_empty_so_the_applicability_table_need_not_model_it(path):
    text = path.read_text(encoding="utf-8")
    assert re.search(r"fn ports\(\)\s*\{\s*\[\s*\]\s*\}", text), (
        f"{path.name}: ports() filters before run(); pulse_plugins.APPLICABILITY does not model it"
    )


def _gate_text(text: str) -> str:
    """What decides whether a plugin acts: run() up to its first bare ``return;``, plus ``kind_of``.

    Every shipped plugin opens run() with its gate and leaves by ``return;``
    (the smb and rdp ones after an if/else chain that names the service); the
    cleartext plugin keeps its classification in ``kind_of``. Comments are
    dropped so that prose cannot pose as a gate.
    """
    code = "\n".join(line for line in text.splitlines() if not line.strip().startswith("//"))
    start = code.index("fn run()")
    gate = code[start : code.index("return;", start)]
    if "fn kind_of" in code:
        kind = code.index("fn kind_of")
        gate += code[kind : code.index("\nfn ", kind + 1)]
    return gate


def _literals(pattern: str, text: str) -> set[str]:
    return {m.lower() for m in re.findall(pattern, text)}


@pytest.mark.parametrize("path", PLUGINS, ids=_id)
def test_applicability_table_matches_the_gate_in_the_plugin(path):
    gate = pulse_plugins.APPLICABILITY[path.stem]
    text = _gate_text(path.read_text(encoding="utf-8"))
    services = _literals(r'(?:service|svc) == "([a-z0-9-]+)"', text) - {"unknown"}
    prefixes = _literals(r'starts_with\("([^"]+)"\)', text)
    needles = _literals(r'\.contains\("([^"]+)"\)', text)
    ports = {int(n) for n in re.findall(r"(?:port|number) == (\d+)", text)}
    assert services == gate["services"], path.name
    assert prefixes == {p for p, _ in gate["banner"]}, path.name
    assert needles == {n for _, n in gate["banner"] if n}, path.name
    assert ports == gate["ports"], path.name


@pytest.mark.parametrize("path", PLUGINS, ids=_id)
def test_a_port_number_only_counts_when_the_service_is_unnamed(path):
    """A different service on 445 or 3389 is not SMB or RDP: the table says so, so must the gate."""
    text = _gate_text(path.read_text(encoding="utf-8"))
    for match in re.finditer(r"(?:port|number) == \d+", text):
        before = text[max(0, match.start() - 60) : match.start()]
        assert re.search(r"unnamed && \(?$|\(svc == \"\" \|\| svc == \"unknown\"\) && $", before), (
            f"{path.name}: {match.group(0)} is not guarded by an unnamed-service condition"
        )


def test_every_shipped_plugin_has_an_applicability_entry():
    assert {p.stem for p in PLUGINS} == set(pulse_plugins.APPLICABILITY)


# --------------------------------------------------------------------------
# A Pulse binary
# --------------------------------------------------------------------------


@needs_pulse
@pytest.mark.parametrize("path", PLUGINS, ids=_id)
def test_pulse_plugin_check_accepts_the_plugin(path, tmp_path):
    reason = pulse_plugins.check_plugin(PULSE, path, env={"HOME": str(tmp_path)}, cwd=tmp_path)
    assert reason is None, reason


@needs_pulse
def test_pulse_plugin_check_rejects_a_broken_script(tmp_path):
    broken = tmp_path / "broken.rhai"
    broken.write_text("fn name() { \"broken\" } fn run( {", encoding="utf-8")
    reason = pulse_plugins.check_plugin(PULSE, broken, env={"HOME": str(tmp_path)}, cwd=tmp_path)
    assert reason and "Compilation error" in reason


# --------------------------------------------------------------------------
# Stub servers
# --------------------------------------------------------------------------


def _name_list(items) -> bytes:
    data = ",".join(items).encode()
    return struct.pack(">I", len(data)) + data


def kexinit(kex, hostkeys, ciphers, macs, *, pad_names=0, rng=random) -> bytes:
    """An SSH_MSG_KEXINIT binary packet, random cookie and padding like a real server's."""
    pad = (lambda: [f"x{i}@pad.example" for i in range(rng.randint(0, pad_names))]) if pad_names else (lambda: [])
    body = bytes([20]) + bytes(rng.getrandbits(8) for _ in range(16))
    for names in (kex, hostkeys, ciphers, ciphers, macs, macs, ["none"], ["none"], [], []):
        body += _name_list(list(names) + pad() if names else [])
    body += b"\x00" + b"\x00" * 4
    padding = 8 - ((len(body) + 5) % 8)
    padding = padding + 8 if padding < 4 else padding
    packet = bytes([padding]) + body + bytes(rng.getrandbits(8) for _ in range(padding))
    return struct.pack(">I", len(packet)) + packet


class Stub:
    """Sends a greeting on connect, then ``reply(received)`` if the client wrote.

    ``greeting`` may be a list: connection N gets item N (the last one repeats).
    ``pulse plugin run`` first connects bare to learn the banner, so a second
    entry is how a test makes the plugin's own connection see something else.
    """

    def __init__(self, greeting: bytes | list[bytes], reply: Callable[[bytes], bytes] | None):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.received: list[bytes] = []
        self._greetings = [greeting] if isinstance(greeting, bytes) else list(greeting)
        self._connections = 0
        self._reply = reply
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.sendall(self._greetings[min(self._connections, len(self._greetings) - 1)])
            self._connections += 1
            conn.settimeout(1)
            try:
                got = conn.recv(4096)
            except OSError:
                got = b""
            if got:
                self.received.append(got)
                if self._reply:
                    conn.sendall(self._reply(got))
        finally:
            conn.close()

    def close(self):
        self.sock.close()


@pytest.fixture
def stub():
    made: list[Stub] = []

    def make(greeting: bytes | list[bytes], reply=None) -> Stub:
        made.append(Stub(greeting, reply))
        return made[-1]

    yield make
    for item in made:
        item.close()


def run_plugin(name: str, port: int) -> tuple[list[str], str]:
    """``(finding lines, stderr)`` of ``pulse plugin run`` for one plugin and stub."""
    done = subprocess.run(  # noqa: S603
        [PULSE, "plugin", "run", str(pulse_plugins.PLUGINS_DIR / f"{name}.rhai"), f"127.0.0.1:{port}"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    clean = re.sub(r"\x1b\[[0-9;]*m", "", done.stdout)
    return [line.strip() for line in clean.splitlines() if line.strip()], re.sub(r"\x1b\[[0-9;]*m", "", done.stderr)


def finding(lines: list[str]) -> tuple[str, str, str] | None:
    """``(severity, title, evidence)`` or ``None``."""
    head = next((line for line in lines if line.startswith("FINDING")), None)
    if head is None:
        return None
    match = re.match(r"FINDING\s+\[(\w+)\]\s+(.*)", head)
    evidence = next((line[len("Evidence:") :].strip() for line in lines if line.startswith("Evidence:")), "")
    return match.group(1), match.group(2), evidence


STRONG = (["curve25519-sha256", "diffie-hellman-group14-sha256"], ["rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519"],
          ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
          ["hmac-sha2-256-etm@openssh.com", "umac-64-etm@openssh.com", "hmac-sha1-etm@openssh.com"])


@needs_pulse
def test_ssh_algorithms_reports_broken_ones_by_name(stub):
    weak = kexinit(["curve25519-sha256", "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"],
                   ["ssh-rsa", "ssh-dss"], ["aes128-ctr", "3des-cbc", "aes256-cbc"], ["hmac-sha2-256", "hmac-md5"])
    server = stub(b"SSH-2.0-OpenSSH_7.4\r\n", lambda _: weak)
    severity, title, evidence = finding(run_plugin("shapo_ssh_algorithms", server.port)[0])
    assert (severity, title) == ("MEDIUM", "SSH server offers weak algorithms")
    for name in ("diffie-hellman-group1-sha1", "ssh-dss", "3des-cbc", "hmac-md5", "aes256-cbc"):
        assert name in evidence
    assert server.received and server.received[0].startswith(b"SSH-2.0-shapoclyack_audit\r\n")


@needs_pulse
def test_ssh_algorithms_deprecated_only_is_low(stub):
    packet = kexinit(["curve25519-sha256", "diffie-hellman-group14-sha1"], ["rsa-sha2-256", "ssh-rsa"],
                     ["aes128-ctr", "aes128-cbc"], ["hmac-sha2-256"])
    server = stub(b"SSH-2.0-OpenSSH_7.4\r\n", lambda _: packet)
    severity, _, evidence = finding(run_plugin("shapo_ssh_algorithms", server.port)[0])
    assert severity == "LOW" and "aes128-cbc" in evidence and "group14-sha1" in evidence
    assert "ssh-rsa" not in evidence  # rsa-sha2-* is offered beside it


@needs_pulse
def test_ssh_algorithms_ssh_rsa_alone_is_deprecated(stub):
    packet = kexinit(["curve25519-sha256"], ["ssh-rsa"], ["aes128-ctr"], ["hmac-sha2-256"])
    server = stub(b"SSH-2.0-OpenSSH_7.4\r\n", lambda _: packet)
    assert "ssh-rsa" in finding(run_plugin("shapo_ssh_algorithms", server.port)[0])[2]


@needs_pulse
def test_ssh_algorithms_modern_server_is_clean(stub):
    packet = kexinit(*STRONG)
    server = stub(b"SSH-2.0-OpenSSH_9.9\r\n", lambda _: packet)
    lines, stderr = run_plugin("shapo_ssh_algorithms", server.port)
    assert finding(lines) is None and "error" not in stderr


@needs_pulse
def test_ssh_algorithms_survives_the_sanitiser_whatever_the_list_lengths_and_cookie(stub):
    """A weak name first in its list is what a 3-byte length prefix mangles.

    Each connection gets a different cookie and different list lengths, so the
    byte that lands in front of the first name (a printable letter, a dot, or a
    replacement character) varies too.
    """
    rng = random.Random(544)
    server = stub(
        b"SSH-2.0-OpenSSH_7.4\r\n",
        lambda _: kexinit(["diffie-hellman-group1-sha1"], ["ssh-dss"], ["3des-cbc"], ["hmac-md5"], pad_names=9, rng=rng),
    )
    for _ in range(25):
        evidence = finding(run_plugin("shapo_ssh_algorithms", server.port)[0])[2]
        assert evidence.startswith("broken: diffie-hellman-group1-sha1, ssh-dss, 3des-cbc, hmac-md5"), evidence


@needs_pulse
def test_ssh_algorithms_never_flags_a_modern_server_whatever_the_lengths(stub):
    rng = random.Random(545)
    server = stub(
        b"SSH-2.0-OpenSSH_9.9\r\n",
        lambda _: kexinit(["curve25519-sha256"], ["ssh-ed25519"], ["aes256-gcm@openssh.com"],
                          ["hmac-sha1-etm@openssh.com", "umac-64-etm@openssh.com"], pad_names=9, rng=rng),
    )
    for _ in range(25):
        assert finding(run_plugin("shapo_ssh_algorithms", server.port)[0]) is None


@needs_pulse
def test_ssh_algorithms_raises_when_the_server_hangs_up_before_its_lists(stub):
    server = stub(b"SSH-2.0-OpenSSH_9.9\r\n", None)
    lines, stderr = run_plugin("shapo_ssh_algorithms", server.port)
    assert finding(lines) is None
    assert "closed before sending its algorithm lists" in stderr


@needs_pulse
@pytest.mark.parametrize(
    ("banner", "expected"),
    [(b"SSH-1.5-old\r\n", ("HIGH", "SSH protocol 1 only")),
     (b"SSH-1.99-OpenSSH_3.9\r\n", ("MEDIUM", "SSH protocol 1 compatibility advertised")),
     (b"SSH-2.0-OpenSSH_6.6.1\r\n", ("LOW", "Old OpenSSH release")),
     (b"SSH-2.0-OpenSSH_7.4\r\n", None),
     (b"SSH-2.0-OpenSSH_9.9\r\n", None),
     (b"SSH-2.0-dropbear_2020.81\r\n", None)],
)
def test_ssh_banner(stub, banner, expected):
    server = stub(banner)
    got = finding(run_plugin("shapo_ssh_banner", server.port)[0])
    assert (got[:2] if got else None) == expected


FTP_ANON = b"331 Please specify the password.\r\n230 Login successful.\r\n221 Goodbye.\r\n"
FTP_DENIED = b"331 Please specify the password.\r\n530 Login incorrect.\r\n221 Goodbye.\r\n"


@needs_pulse
def test_ftp_anonymous_login_is_a_finding_and_only_one_connection_is_made(stub):
    server = stub(b"220 (vsFTPd 3.0.3)\r\n", lambda _: FTP_ANON)
    severity, title, evidence = finding(run_plugin("shapo_ftp_anonymous", server.port)[0])
    assert (severity, title, evidence) == ("MEDIUM", "Anonymous FTP login allowed", "230 Login successful.")
    # USER, PASS and QUIT in one write: the server closes after QUIT.
    assert server.received[-1] == b"USER anonymous\r\nPASS anonymous@example.invalid\r\nQUIT\r\n"


@needs_pulse
def test_ftp_anonymous_refused_is_clean(stub):
    server = stub(b"220 (vsFTPd 3.0.3)\r\n", lambda _: FTP_DENIED)
    assert finding(run_plugin("shapo_ftp_anonymous", server.port)[0]) is None


@needs_pulse
def test_ftp_anonymous_ignores_services_that_are_not_ftp(stub):
    server = stub(b"HTTP/1.1 200 OK\r\n", lambda _: FTP_ANON)
    lines, stderr = run_plugin("shapo_ftp_anonymous", server.port)
    assert finding(lines) is None and not server.received and "error" not in stderr


@needs_pulse
def test_ftp_anonymous_raises_when_the_greeting_is_not_ftp(stub):
    # Greets like FTP for the banner grab, then refuses the plugin's own connection.
    server = stub([b"220 FTP ready\r\n", b"421 Too many connections\r\n"], lambda _: b"")
    lines, stderr = run_plugin("shapo_ftp_anonymous", server.port)
    assert finding(lines) is None
    assert "no complete FTP reply" in stderr


CLEARTEXT = [
    ("ftp", b"220 (vsFTPd 3.0.3)\r\n", b"211-Features:\r\n EPSV\r\n211 End\r\n221 Bye\r\n",
     b"211-Features:\r\n AUTH TLS\r\n211 End\r\n221 Bye\r\n", "FTP without TLS"),
    ("pop3", b"+OK POP3 ready\r\n", b"+OK\r\nUSER\r\n.\r\n+OK bye\r\n", b"+OK\r\nUSER\r\nSTLS\r\n.\r\n+OK bye\r\n",
     "POP3 without STLS"),
    ("imap", b"* OK IMAP4rev1 ready\r\n", b"* CAPABILITY IMAP4rev1\r\na1 OK done\r\n* BYE\r\n",
     b"* CAPABILITY IMAP4rev1 STARTTLS\r\na1 OK done\r\n* BYE\r\n", "IMAP without STARTTLS"),
    ("smtp", b"220 mail.example ESMTP\r\n", b"250-mail.example\r\n250 SIZE 100\r\n221 Bye\r\n",
     b"250-mail.example\r\n250-STARTTLS\r\n250 SIZE 100\r\n221 Bye\r\n",
     "SMTP without STARTTLS"),
]


@needs_pulse
@pytest.mark.parametrize(("kind", "greeting", "plain", "tls", "title"), CLEARTEXT, ids=[c[0] for c in CLEARTEXT])
def test_cleartext_service_without_tls_is_reported_and_with_tls_is_not(stub, kind, greeting, plain, tls, title):
    cleartext = stub(greeting, lambda _: plain)
    assert finding(run_plugin("shapo_cleartext_services", cleartext.port)[0])[1] == title
    offers_tls = stub(greeting, lambda _: tls)
    assert finding(run_plugin("shapo_cleartext_services", offers_tls.port)[0]) is None


@needs_pulse
def test_smtp_authentication_without_starttls_is_medium(stub):
    reply = b"250-m\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE\r\n221 Bye\r\n"
    server = stub(b"220 m ESMTP\r\n", lambda _: reply)
    severity, title, _ = finding(run_plugin("shapo_cleartext_services", server.port)[0])
    assert (severity, title) == ("MEDIUM", "SMTP authentication without STARTTLS")


@needs_pulse
def test_cleartext_check_closes_the_session_in_the_same_write(stub):
    server = stub(b"+OK POP3 ready\r\n", lambda _: b"+OK\r\nUSER\r\n.\r\n")
    run_plugin("shapo_cleartext_services", server.port)
    assert server.received[-1] == b"CAPA\r\nQUIT\r\n"


@needs_pulse
def test_cleartext_check_raises_when_the_server_does_not_greet_the_plugin(stub):
    server = stub([b"+OK POP3 ready\r\n", b"-ERR too busy\r\n"], lambda _: b"")
    lines, stderr = run_plugin("shapo_cleartext_services", server.port)
    assert finding(lines) is None and "no POP3 greeting in the reply" in stderr


@pytest.mark.parametrize(
    ("plugin", "unchecked"),
    [("shapo_smb_exposure", "message signing, SMBv1"), ("shapo_remote_admin_exposure", "network-level authentication")],
)
def test_exposure_plugins_claim_reachability_only(plugin, unchecked):
    text = (pulse_plugins.PLUGINS_DIR / f"{plugin}.rhai").read_text(encoding="utf-8")
    run = text.split("fn run()")[1]
    assert "Exposure only" in run and unchecked.lower() in run.lower()
    assert 'severity: "LOW"' in run and "HIGH" not in run and "MEDIUM" not in run


@needs_pulse
def test_rdp_is_recognised_by_its_port():
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 3389))
    except OSError:
        sock.close()
        pytest.skip("port 3389 is taken on this host")
    sock.listen(4)
    try:
        severity, title, _ = finding(run_plugin("shapo_remote_admin_exposure", 3389)[0])
    finally:
        sock.close()
    assert severity == "LOW" and title.endswith("(RDP)")


@needs_pulse
def test_vnc_greeting_is_recognised_on_any_port(stub):
    server = stub(b"RFB 003.008\n")
    severity, title, _ = finding(run_plugin("shapo_remote_admin_exposure", server.port)[0])
    assert severity == "LOW" and title.endswith("(VNC)")


# --- a refused capability command says nothing about TLS ------------------

REFUSED = [
    ("ftp", b"220 (vsFTPd 3.0.3)\r\n", b"530 Please login with USER and PASS.\r\n221 Bye\r\n", "FTP FEAT"),
    ("smtp", b"220 mail.example ESMTP Postfix\r\n", b"554 5.5.0 Error: SMTP protocol synchronization\r\n221 Bye\r\n", "SMTP EHLO"),
    ("pop3", b"+OK POP3 ready\r\n", b"-ERR unknown command\r\n+OK bye\r\n", "POP3 CAPA"),
    ("imap", b"* OK IMAP4rev1 ready\r\n", b"a1 BAD command refused\r\n* BYE\r\n", "IMAP CAPABILITY"),
]


@needs_pulse
@pytest.mark.parametrize(("kind", "greeting", "refusal", "what"), REFUSED, ids=[r[0] for r in REFUSED])
def test_a_refused_capability_command_is_an_error_not_a_cleartext_finding(stub, kind, greeting, refusal, what):
    server = stub(greeting, lambda _: refusal)
    lines, stderr = run_plugin("shapo_cleartext_services", server.port)
    assert finding(lines) is None
    assert f"{what} did not accept the capability command" in stderr


@needs_pulse
def test_smtp_ehlo_accepted_after_a_multiline_reply_is_judged(stub):
    server = stub(b"220-mail.example ESMTP\r\n220 ready\r\n", lambda _: b"250-m\r\n250-PIPELINING\r\n250 8BITMIME\r\n221 Bye\r\n")
    assert finding(run_plugin("shapo_cleartext_services", server.port)[0])[1] == "SMTP without STARTTLS"


@needs_pulse
def test_a_greeting_with_continuation_lines_of_the_same_code_does_not_shift_the_replies(stub):
    greeting = b"220-first\r\n220-second\r\n220 FTP ready\r\n"
    server = stub(greeting, lambda _: b"331 Password required\r\n230 Login successful.\r\n221 Bye\r\n")
    assert finding(run_plugin("shapo_ftp_anonymous", server.port)[0])[1] == "Anonymous FTP login allowed"


# --- anonymous FTP is the answer to PASS, not a 230 anywhere ----------------


@needs_pulse
def test_a_230_inside_a_multiline_greeting_is_not_a_login(stub):
    greeting = b"220-Welcome. Notice:\r\n230 is the code for logged-in users only\r\n220 ready (FTP)\r\n"
    server = stub(greeting, lambda _: b"331 Password required\r\n530 Login incorrect.\r\n221 Bye\r\n")
    lines, stderr = run_plugin("shapo_ftp_anonymous", server.port)
    assert finding(lines) is None and "error" not in stderr


@needs_pulse
def test_a_server_that_logs_in_on_user_alone_is_anonymous(stub):
    server = stub(b"220 FTP ready\r\n", lambda _: b"230 Anonymous access granted.\r\n503 Already logged in.\r\n221 Bye\r\n")
    assert finding(run_plugin("shapo_ftp_anonymous", server.port)[0])[1] == "Anonymous FTP login allowed"


@needs_pulse
def test_a_server_that_closes_before_answering_pass_is_an_error(stub):
    server = stub(b"220 FTP ready\r\n", lambda _: b"331 Password required\r\n")
    lines, stderr = run_plugin("shapo_ftp_anonymous", server.port)
    assert finding(lines) is None and "no complete FTP reply" in stderr
