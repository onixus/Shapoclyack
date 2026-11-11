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
    assert len(PLUGINS) >= 7


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
    calls = re.findall(r"probe_(?:send_hex|udp_hex|send|recv|smb|ms17_010|rdp_ntlm|vnc_security)\(([^)]*)\)", text)
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
    if any(call in text for call in ("probe_send(", "probe_recv(", "probe_send_hex(", "probe_udp_hex(")):
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
    assert "fn run()" in code, "no run(): there is no gate to compare"
    start = code.index("fn run()")
    cut = code.find("return;", start)
    assert cut > start, "run() has no bare `return;`: the gate cannot be told from the body"
    gate = code[start:cut]
    if "fn kind_of" in code:
        kind = code.index("fn kind_of")
        end = code.find("\nfn ", kind + 1)
        assert end > kind, "kind_of is the last function: its end is unknown"
        gate += code[kind:end]
    assert re.search(r"\b(?:service|svc)\b", gate), "gate region names no service: it was cut in the wrong place"
    return gate


def _banner_pairs(text: str) -> set[tuple[str, str]]:
    """(prefix, needle) pairs: `x.starts_with("p")` optionally followed by `&& x.contains("n")` on
    the same variable. Sets of literals would not notice a needle moving to another prefix."""
    return {
        (m.group(2).lower(), (m.group(3) or "").lower())
        for m in re.finditer(r'(\w+)(?:\.to_lower\(\))?\.starts_with\("([^"]+)"\)(?:\s*&&\s*\1\.contains\("([^"]+)"\))?', text)
    }


def _literals(pattern: str, text: str) -> set[str]:
    return {m.lower() for m in re.findall(pattern, text)}


@pytest.mark.parametrize("path", PLUGINS, ids=_id)
def test_applicability_table_matches_the_gate_in_the_plugin(path):
    gate = pulse_plugins.APPLICABILITY[path.stem]
    text = _gate_text(path.read_text(encoding="utf-8"))
    services = _literals(r'(?:service|svc) == "([a-z0-9-]+)"', text) - {"unknown"}
    pairs = _banner_pairs(text)
    ports = {int(n) for n in re.findall(r"(?:port|number) == (\d+)", text)}
    assert services == gate["services"], path.name
    assert pairs == set(gate["banner"]), path.name
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
        self.sock.settimeout(0.1)
        self._stopped = threading.Event()
        self._workers: list[threading.Thread] = []
        self.port = self.sock.getsockname()[1]
        self.received: list[bytes] = []
        self._greetings = [greeting] if isinstance(greeting, bytes) else list(greeting)
        self._connections = 0
        self._reply = reply
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()

    def _accept(self):
        while not self._stopped.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self._workers.append(worker)
            worker.start()

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
        self._stopped.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # No connected listener peer, or already closed.
        self.sock.close()
        self._accept_thread.join(timeout=2)
        assert not self._accept_thread.is_alive(), "stub listener did not stop"
        for worker in self._workers:
            worker.join(timeout=2)
            assert not worker.is_alive(), "stub connection did not stop"


def test_stub_close_joins_listener_and_idle_connection_repeatedly():
    for _ in range(5):
        server = Stub(b"hello", None)
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as client:
            assert client.recv(5) == b"hello"
            server.close()
            assert not server._accept_thread.is_alive()
            assert server._workers
            assert all(not worker.is_alive() for worker in server._workers)
        server.close()  # Teardown is idempotent.


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


def test_the_gate_extractor_refuses_a_plugin_it_cannot_read():
    with pytest.raises(AssertionError, match="bare `return;`"):
        _gate_text('fn run() {\n    if service == "ssh" { return #{ title: "x" }; }\n}\n')
    with pytest.raises(AssertionError, match="no run"):
        _gate_text('fn name() { "x" }')


def test_a_needle_moved_to_another_prefix_is_a_different_gate():
    """("220", "smtp") is not ("220", "ftp"), though both literals are present."""
    moved = _gate_text('fn run() {\n    if service == "x" || (g.starts_with("220") && g.contains("smtp")) { return; }\n}')
    assert _banner_pairs(moved) == {("220", "smtp")}
    assert _banner_pairs(moved) != {("220", "ftp")}
    assert _banner_pairs('b.starts_with("220") || c.contains("ftp")') == {("220", "")}  # different variables: no pair


@needs_pulse
def test_anonymous_ftp_evidence_is_the_reply_to_pass_not_the_first_230_line(stub):
    greeting = b"220-Banner mentions\r\n230 as text\r\n220 FTP ready\r\n"
    server = stub(greeting, lambda _: b"331 Password required\r\n230-Welcome\r\n230 Login successful, guest.\r\n221 Bye\r\n")
    assert finding(run_plugin("shapo_ftp_anonymous", server.port)[0])[2] == "230 Login successful, guest."


# --------------------------------------------------------------------------
# shapo_http_trace (#547)
# --------------------------------------------------------------------------

#: What `pulse plugin run` learns the banner from: the first, bare connection.
HTTP_BANNER = b"HTTP/1.1 400 Bad Request\r\nServer: stub\r\n\r\n"


def _trace_echo(request: bytes) -> bytes:
    body = request
    return b"HTTP/1.1 200 OK\r\nContent-Type: message/http\r\nContent-Length: %d\r\n\r\n" % len(body) + body


@needs_pulse
def test_http_trace_that_echoes_the_request_is_a_finding_and_one_connection_is_made(stub):
    server = stub([HTTP_BANNER, b""], _trace_echo)
    severity, title, evidence = finding(run_plugin("shapo_http_trace", server.port)[0])
    assert (severity, title) == ("LOW", "HTTP TRACE method enabled")
    assert evidence == "HTTP/1.1 200 OK (request echoed)"
    assert server.received[-1].startswith(b"TRACE / HTTP/1.1\r\n")
    assert b"X-Shapo-Trace: shapo-trace-547" in server.received[-1]


@needs_pulse
def test_http_trace_refused_is_clean(stub):
    server = stub([HTTP_BANNER, b""], lambda _: b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
    assert finding(run_plugin("shapo_http_trace", server.port)[0]) is None


@needs_pulse
def test_http_trace_200_without_the_echo_is_not_a_finding(stub):
    """A catch-all (the corpus's IIS stub) answers 200 to any method and echoes nothing."""
    server = stub([HTTP_BANNER, b""], lambda _: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n<html>")
    assert finding(run_plugin("shapo_http_trace", server.port)[0]) is None


@needs_pulse
def test_http_trace_header_echo_outside_the_body_is_not_a_finding(stub):
    """The marker must come back in the body, not merely appear in a header the server set."""
    reply = b"HTTP/1.1 200 OK\r\nX-Shapo-Trace: shapo-trace-547\r\nContent-Length: 0\r\n\r\n"
    server = stub([HTTP_BANNER, b""], lambda _: reply)
    assert finding(run_plugin("shapo_http_trace", server.port)[0]) is None


@needs_pulse
def test_http_trace_ignores_services_that_are_not_http(stub):
    server = stub(b"220 (vsFTPd 3.0.3)\r\n", _trace_echo)
    lines, stderr = run_plugin("shapo_http_trace", server.port)
    assert finding(lines) is None and not server.received and "error" not in stderr


@needs_pulse
def test_http_trace_raises_when_the_reply_is_not_http(stub):
    server = stub([HTTP_BANNER, b""], lambda _: b"garbage\r\n")
    lines, stderr = run_plugin("shapo_http_trace", server.port)
    assert finding(lines) is None
    assert "no HTTP status line" in stderr


@needs_pulse
def test_http_trace_needs_a_200_even_when_an_error_page_quotes_the_request(stub):
    def quoting_404(request: bytes) -> bytes:
        return b"HTTP/1.1 404 Not Found\r\n\r\nNo handler for:\r\n" + request

    server = stub([HTTP_BANNER, b""], quoting_404)
    assert finding(run_plugin("shapo_http_trace", server.port)[0]) is None


@needs_pulse
def test_http_trace_a_server_that_hangs_up_on_trace_refused_it_and_is_clean(stub):
    server = stub([HTTP_BANNER, b""], lambda _: b"")
    lines, stderr = run_plugin("shapo_http_trace", server.port)
    assert finding(lines) is None
    assert "error" not in stderr.lower()

def _assert_unknown_assessment(result: subprocess.CompletedProcess, plugin: str):
    """The canonical CLI contract: a scoped plugin error cannot be a clean exit."""
    stderr = re.sub(r"\x1b\[[0-9;]*m", "", result.stderr)
    assert result.returncode != 0, (result.stdout, stderr)
    assert re.search(rf"(?m)^\s*plugin error — {re.escape(plugin)}: .+", stderr), stderr
    assert "Error: assessment incomplete; no clean verdict" in stderr, stderr
    assert "No findings reported by script" not in result.stdout
    assert "Function not found" not in stderr, stderr


# Binary protocol fixtures force the already-tested applicability input; the
# loopback listener uses an ephemeral port, never a real SMB/RDP endpoint.
def _run_binary_plugin(name, service_name, server, tmp_path, *, unnamed_stub=False):
    source = (pulse_plugins.PLUGINS_DIR / f"{name}.rhai").read_text()
    if unnamed_stub:
        # Keep probe_send on Pulse's port global (the stub). Only the gate
        # additionally accepts that ephemeral port, as if it were 7687.
        opened = source.replace(
            "unnamed && port == 7687",
            f"unnamed && (port == 7687 || port == {server.port})",
            1,
        )
        assert opened != source, "unnamed 7687 gate was not in the plugin"
        source = opened
        service_name = ""
    source = source.replace("fn run() {", f'fn run() {{ let service = "{service_name}";', 1)
    script = tmp_path / f"{name}.rhai"
    script.write_text(source)
    result = subprocess.run([PULSE, "plugin", "run", str(script), f"127.0.0.1:{server.port}"], capture_output=True, text=True, timeout=30)
    if result.stderr.strip():
        _assert_unknown_assessment(result, name)
    clean = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    return [line.strip() for line in clean.splitlines() if line.strip()], result.stderr


def _smb2_response(mode):
    packet = bytearray(128)
    packet[:4] = b"\xfeSMB"
    struct.pack_into("<H", packet, 4, 64)
    struct.pack_into("<I", packet, 16, 1)
    struct.pack_into("<HHH", packet, 64, 65, mode, 0x0210)
    return len(packet).to_bytes(4, "big") + packet


@needs_pulse
@pytest.mark.parametrize("mode, expected", [(1, True), (3, False)])
def test_smb2_signing_is_observed_from_binary_negotiation(mode, expected, stub, tmp_path):
    server = stub(b"", lambda _: _smb2_response(mode))
    lines, errors = _run_binary_plugin("shapo_smb_signing", "smb", server, tmp_path)
    assert (finding(lines) is not None) is expected, errors
    assert not errors.strip(), errors
    assert any(request[4:8] == b"\xfeSMB" for request in server.received)
    assert all(len(request) == 108 for request in server.received)


@needs_pulse
@pytest.mark.parametrize("reply", [b"", b"\x00\x00\x00\xff", _smb2_response(1)[:40], _smb2_response(0), _smb2_response(2), _smb2_response(8), _smb2_response(1) + b"junk"])
def test_smb_malformed_reply_is_an_error_not_a_clean_result(reply, stub, tmp_path):
    server = stub(b"", lambda _: reply)
    lines, errors = _run_binary_plugin("shapo_smb_signing", "smb", server, tmp_path)
    assert finding(lines) is None and errors.strip()
    assert "Function not found" not in errors


@needs_pulse
@pytest.mark.parametrize("kind, value, expected", [(2, 0, True), (3, 1, False), (3, 5, False), (3, 6, False)])
def test_rdp_negotiation_distinguishes_standard_security_from_refusal(kind, value, expected, stub, tmp_path):
    reply = bytes.fromhex("030000130ed00000000000") + bytes([kind, 0]) + struct.pack("<HI", 8, value)
    server = stub(b"", lambda _: reply)
    lines, errors = _run_binary_plugin("shapo_rdp_negotiation", "rdp", server, tmp_path)
    assert (finding(lines) is not None) is expected, errors
    assert not errors.strip(), errors
    assert bytes.fromhex("030000130ee000000000000100080000000000") in server.received


@needs_pulse
@pytest.mark.parametrize("reply", [b"", b"\x03\x00", bytes.fromhex("030000130ed000000000000200080002000000"), bytes.fromhex("030000130ed000000000000300080002000000")])
def test_rdp_malformed_or_unrequested_protocol_does_not_assert_policy(reply, stub, tmp_path):
    server = stub(b"", lambda _: reply)
    lines, errors = _run_binary_plugin("shapo_rdp_negotiation", "rdp", server, tmp_path)
    assert finding(lines) is None and errors.strip()
    assert "Function not found" not in errors


@needs_pulse
@pytest.mark.parametrize("accepted", [True, False])
def test_smb1_only_reports_an_explicit_selected_dialect(accepted, stub, tmp_path):
    packet = bytearray(69 if accepted else 37)
    packet[:5] = b"\xffSMB\x72"
    packet[9] = 0x80
    packet[32] = 17 if accepted else 1
    packet[33:35] = b"\0\0" if accepted else b"\xff\xff"
    reply = len(packet).to_bytes(4, "big") + packet
    server = stub(b"", lambda _: reply)
    lines, errors = _run_binary_plugin("shapo_smb1", "smb", server, tmp_path)
    assert (finding(lines) is not None) is accepted, errors
    assert not errors.strip(), errors
    assert any(request[4:9] == b"\xffSMB\x72" for request in server.received)


def _ber(tag, payload):
    length = bytes([len(payload)]) if len(payload) < 128 else b"\x82" + len(payload).to_bytes(2, "big")
    return bytes([tag]) + length + payload


def _snmp_reply(request_id=b"SHAP", extra=b"", exception=False):
    values = []
    for oid, value in [(bytes.fromhex("2b060102010100"), b"test OS"), (bytes.fromhex("2b060102010500"), b"test-host")]:
        values.append(_ber(48, _ber(6, oid) + _ber(129 if exception else 4, value)))
    pdu = _ber(162, _ber(2, request_id) + _ber(2, b"\0") + _ber(2, b"\0") + _ber(48, b"".join(values)))
    return _ber(48, _ber(2, b"\1") + _ber(4, b"public") + pdu) + extra


@needs_pulse
@pytest.mark.parametrize("case", ["ok", "wrong-id", "truncated", "trailing", "exception", "oversized-value"])
def test_snmp_read_only_information_uses_scoped_udp_and_bounded_ber(case, tmp_path):
    response = _snmp_reply()
    if case == "wrong-id":
        response = _snmp_reply(request_id=b"NOPE")
    elif case == "truncated":
        response = response[:-1]
    elif case == "trailing":
        response = _snmp_reply(extra=b"junk")
    elif case == "exception":
        response = _snmp_reply(exception=True)
    elif case == "oversized-value":
        response = b"\x30\x82\xff\xff"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)
    seen = []
    def peer():
        try:
            data, addr = sock.recvfrom(4096)
            seen.append(data)
            sock.sendto(response, addr)
        except OSError:
            pass
    worker = threading.Thread(target=peer, daemon=True)
    worker.start()
    source = (pulse_plugins.PLUGINS_DIR / "shapo_snmp_info.rhai").read_text().replace('fn run() {', 'fn run() { let service = "snmp";', 1)
    script = tmp_path / "snmp.rhai"
    script.write_text(source)
    try:
        result = subprocess.run([PULSE, "plugin", "run", str(script), f"127.0.0.1:{sock.getsockname()[1]}", "--protocol", "udp"], capture_output=True, text=True, timeout=10)
        clean = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
        observed = finding([line.strip() for line in clean.splitlines()])
        if case == "ok":
            assert observed and observed[0] == "INFO", result.stderr
            assert "74657374204f53" in observed[2] and "746573742d686f7374" in observed[2]
            assert not result.stderr.strip()
        else:
            assert observed is None
            _assert_unknown_assessment(result, "shapo_snmp_info")
        worker.join(2)
        assert seen == [bytes.fromhex("303502010104067075626c6963a028020453484150020100020100301a300b06072b0601020101000500300b06072b0601020105000500")]
    finally:
        sock.close()


@needs_pulse
@pytest.mark.parametrize("case", ["ok", "bad-signature", "zero-curve", "oversized-packet", "unsupported-kex"])
def test_ssh_hostkey_verifies_real_exchange_signature_and_rejects_bad_peers(case, tmp_path):
    import base64
    import hashlib
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives import serialization
    key = ed25519.Ed25519PrivateKey.generate()
    def string(value):
        return struct.pack(">I", len(value)) + value
    hostkey = string(b"ssh-ed25519") + string(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(hostkey).digest()).decode().rstrip("=")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    listener.settimeout(5)
    server_errors = []
    def exact(conn, n):
        result = b""
        while len(result) < n:
            data = conn.recv(n - len(result))
            if not data:
                raise EOFError
            result += data
        return result
    def packet(payload):
        pad = 8 - (len(payload) + 5) % 8
        if pad < 4:
            pad += 8
        return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + bytes(pad)
    def read_packet(conn):
        n = struct.unpack(">I", exact(conn, 4))[0]
        payload = exact(conn, n)
        return payload[1:-payload[0]]
    def field(data, pos):
        n = struct.unpack(">I", data[pos:pos + 4])[0]
        return data[pos + 4:pos + 4 + n], pos + 4 + n
    def server():
        try:
            # Standalone banner observation opens one connection before the native helper.
            for _ in range(2):
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(3)
                    ident = b"SSH-2.0-independent-fixture"
                    conn.sendall(ident + b"\r\n")
                    line = b""
                    try:
                        while not line.endswith(b"\n"):
                            line += exact(conn, 1)
                    except (EOFError, TimeoutError):
                        continue
                    vc = line.rstrip(b"\r\n")
                    ic = read_packet(conn)
                    names = [b"curve25519-sha256", b"ssh-ed25519", b"aes128-ctr", b"aes128-ctr", b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none", b"", b""]
                    if case == "unsupported-kex":
                        names[0] = b"diffie-hellman-group14-sha256"
                    server_init = bytes([20]) + bytes(16) + b"".join(string(n) for n in names) + bytes(5)
                    if case == "oversized-packet":
                        conn.sendall(struct.pack(">I", 0xffffffff))
                        return
                    conn.sendall(packet(server_init))
                    if case == "unsupported-kex":
                        return
                    qc, _ = field(read_packet(conn), 1)
                    private = x25519.X25519PrivateKey.generate()
                    qs = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(qc))
                    k = shared.lstrip(b"\0")
                    if k and k[0] & 128:
                        k = b"\0" + k
                    digest = hashlib.sha256(b"".join(string(v) for v in [vc, ident, ic, server_init, hostkey, qc, qs, k])).digest()
                    sig = key.sign(digest)
                    if case == "bad-signature":
                        sig = bytes([sig[0] ^ 1]) + sig[1:]
                    if case == "zero-curve":
                        qs = bytes(32)
                    conn.sendall(packet(bytes([31]) + string(hostkey) + string(qs) + string(string(b"ssh-ed25519") + string(sig))))
                    return
        except Exception as exc:
            server_errors.append(repr(exc))
    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    source = (pulse_plugins.PLUGINS_DIR / "shapo_ssh_hostkey.rhai").read_text().replace('fn run() {', 'fn run() { let service = "ssh";', 1)
    script = tmp_path / "hostkey.rhai"
    script.write_text(source)
    try:
        result = subprocess.run([PULSE, "plugin", "run", str(script), f"127.0.0.1:{port}"], capture_output=True, text=True, timeout=10)
        clean = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
        observed = finding([line.strip() for line in clean.splitlines()])
        if case == "ok":
            assert observed and observed[0] == "INFO" and expected in observed[2], result.stderr
            assert not result.stderr.strip()
        else:
            assert observed is None
            _assert_unknown_assessment(result, "shapo_ssh_hostkey")
        worker.join(3)
        assert not server_errors, server_errors
    finally:
        listener.close()


@needs_pulse
@pytest.mark.parametrize("case", ["async", "compound", "tree-id", "session-id", "buffer-header-overlap", "buffer-overrun"])
def test_direct_smb_signing_rejects_uncorrelated_headers_and_bad_security_buffers(case, stub, tmp_path):
    reply = bytearray(_smb2_response(3))
    if case == "async":
        struct.pack_into("<I", reply, 20, 3)
    elif case == "compound":
        struct.pack_into("<I", reply, 24, 64)
    elif case == "tree-id":
        struct.pack_into("<I", reply, 40, 1)
    elif case == "session-id":
        struct.pack_into("<Q", reply, 44, 1)
    elif case == "buffer-header-overlap":
        struct.pack_into("<HH", reply, 124, 120, 1)
    elif case == "buffer-overrun":
        struct.pack_into("<HH", reply, 124, 128, 1)
    server = stub(b"", lambda _: bytes(reply))
    lines, errors = _run_binary_plugin("shapo_smb_signing", "smb", server, tmp_path)
    assert finding(lines) is None and "plugin error — shapo_smb_signing:" in errors
    assert "Function not found" not in errors


@needs_pulse
@pytest.mark.parametrize("size", [0, 3, 4, 63, 64, 67, 127, 131])
def test_direct_smb_signing_short_headers_are_unknown_before_field_access(size, stub, tmp_path):
    server = stub(b"", lambda _: _smb2_response(3)[:size])
    lines, errors = _run_binary_plugin("shapo_smb_signing", "smb", server, tmp_path)
    assert finding(lines) is None and "plugin error — shapo_smb_signing:" in errors
    assert "Function not found" not in errors and "index out of bounds" not in errors.lower()


# --------------------------------------------------------------------------
# Phases 1-4 (docs/pulse-plugin-phases.ru.md): one request, one parsed reply.
# Service injection via _run_binary_plugin passes the gate on the stub's
# ephemeral port; every plugin here makes exactly one exchange, so the stub
# sees exactly one request (the bare banner grab writes nothing).
# --------------------------------------------------------------------------


def _http_reply(status: str, *headers: bytes, body: bytes = b"") -> bytes:
    """A complete minimal HTTP response; Content-Length always matches the body."""
    head = f"HTTP/1.1 {status}\r\n".encode()
    for header in headers:
        head += header + b"\r\n"
    return head + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def _chunked_http_reply(
    status: str, *headers: bytes, body: bytes = b"", content_length: int | None = None
) -> bytes:
    """One complete chunked HTTP response.

    Content-Length is omitted unless the caller passes one. A length that does
    not match the raw chunk bytes shows that chunked framing wins.
    """
    chunk = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    head = f"HTTP/1.1 {status}\r\n".encode()
    for header in headers:
        head += header + b"\r\n"
    head += b"Transfer-Encoding: chunked\r\n"
    if content_length is not None:
        head += b"Content-Length: " + str(content_length).encode() + b"\r\n"
    return head + b"\r\n" + chunk


#: (id, plugin, service, request target, stub reply, expected outcome).
#: Docs criteria: clickhouse wants X-ClickHouse with an Ok. body; prometheus and
#: grafana treat a wrong 200 body as a parse error, not a finding; jenkins must
#: stay silent on a 403 even with X-Jenkins; vault answers 503 without Vault
#: JSON fields only as an error; kube and ollama treat a wrong 200 JSON as an
#: error, never as clean.
HTTP_PHASE_CASES = [
    ("clickhouse-ok", "shapo_clickhouse_ping", "clickhouse", "/ping",
     _http_reply("200 OK", b"X-ClickHouse-Summary: {}", body=b"Ok.\n"), "finding"),
    ("clickhouse-chunked", "shapo_clickhouse_ping", "clickhouse", "/ping",
     _chunked_http_reply("200 OK", b"X-ClickHouse-Summary: {}", body=b"Ok.\n", content_length=2),
     "finding"),
    ("clickhouse-crlf", "shapo_clickhouse_ping", "clickhouse", "/ping",
     _http_reply("200 OK", b"X-ClickHouse-Summary: {}", body=b"Ok.\r\n"), "finding"),
    ("clickhouse-trailing-junk", "shapo_clickhouse_ping", "clickhouse", "/ping",
     _http_reply("200 OK", b"X-ClickHouse-Summary: {}", body=b"Ok.junk"), "error"),
    ("clickhouse-refused", "shapo_clickhouse_ping", "clickhouse", "/ping",
     _http_reply("401 Unauthorized"), "clean"),
    ("clickhouse-garbage", "shapo_clickhouse_ping", "clickhouse", "/ping",
     b"NO CARRIER, this is not HTTP\r\n", "error"),
    ("etcd-ok", "shapo_etcd_version", "etcd", "/version",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"etcdserver":"3.5.9","etcdcluster":"3.5.9"}'), "finding"),
    ("etcd-refused", "shapo_etcd_version", "etcd", "/version",
     _http_reply("401 Unauthorized"), "clean"),
    ("etcd-truncated", "shapo_etcd_version", "etcd", "/version",
     b'HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{"etcdserver": "3.5.9"', "error"),
    ("docker-ok", "shapo_docker_version", "docker", "/version",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"Version":"25.0.1","ApiVersion":"1.44","Engine":{"Version":"25.0.1","ApiType":"ce"}}'),
     "finding"),
    ("docker-refused", "shapo_docker_version", "docker", "/version",
     _http_reply("401 Unauthorized"), "clean"),
    ("docker-truncated", "shapo_docker_version", "docker", "/version",
     b'HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\n{"ApiVersi', "error"),
    ("prometheus-ok", "shapo_prometheus_ready", "prometheus", "/api/v1/status/buildinfo",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"status":"success","data":{"version":"2.47.0","revision":"abc1234"}}'), "finding"),
    ("prometheus-spaced-success", "shapo_prometheus_ready", "prometheus", "/api/v1/status/buildinfo",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status": "success", "data": {}}'),
     "finding"),
    ("prometheus-chunked", "shapo_prometheus_ready", "prometheus", "/api/v1/status/buildinfo",
     _chunked_http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"success","data":{}}'),
     "finding"),
    ("prometheus-refused", "shapo_prometheus_ready", "prometheus", "/api/v1/status/buildinfo",
     _http_reply("401 Unauthorized"), "clean"),
    ("prometheus-healthy-word", "shapo_prometheus_ready", "prometheus", "/api/v1/status/buildinfo",
     _http_reply("200 OK", b"Content-Type: text/plain", body=b"Healthy"), "error"),
    ("prometheus-successful", "shapo_prometheus_ready", "prometheus", "/api/v1/status/buildinfo",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"successful"}'), "error"),
    ("prometheus-success-extra", "shapo_prometheus_ready", "prometheus", "/api/v1/status/buildinfo",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"success extra"}'), "error"),
    ("prometheus-truncated-chunk", "shapo_prometheus_ready", "prometheus", "/api/v1/status/buildinfo",
     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n{\"sta", "error"),
    ("grafana-ok", "shapo_grafana_health", "grafana", "/api/health",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"database":"ok","commit":"f2a5a52fee","version":"10.1.5"}'), "finding"),
    ("grafana-refused", "shapo_grafana_health", "grafana", "/api/health",
     _http_reply("401 Unauthorized"), "clean"),
    ("grafana-plain-ok", "shapo_grafana_health", "grafana", "/api/health",
     _http_reply("200 OK", body=b"ok"), "error"),
    ("jenkins-ok", "shapo_jenkins_anonymous", "jenkins", "/whoAmI/api/json",
     _http_reply("200 OK", b"X-Jenkins: 2.440",
                 body=b'{"_class":"hudson.model.Hudson","authenticated":false,"authorities":["anonymous"]}'),
     "finding"),
    ("jenkins-forbidden-with-x-jenkins", "shapo_jenkins_anonymous", "jenkins", "/whoAmI/api/json",
     _http_reply("403 Forbidden", b"X-Jenkins: 2.440"), "clean"),
    ("jenkins-chunked-forbidden", "shapo_jenkins_anonymous", "jenkins", "/whoAmI/api/json",
     _chunked_http_reply("403 Forbidden", b"X-Jenkins: 2.440", body=b"no"), "clean"),
    ("jenkins-garbage", "shapo_jenkins_anonymous", "jenkins", "/whoAmI/api/json",
     b"\x16\x03\x01 not http at all\r\n", "error"),
    ("consul-ok", "shapo_consul_status", "consul", "/v1/status/leader",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'"127.0.0.1:8300"'), "finding"),
    ("consul-refused", "shapo_consul_status", "consul", "/v1/status/leader",
     _http_reply("403 Forbidden"), "clean"),
    ("consul-html", "shapo_consul_status", "consul", "/v1/status/leader",
     _http_reply("200 OK", b"Content-Type: text/html", body=b"<html><body>leader</body></html>"), "error"),
    ("vault-ok", "shapo_vault_health", "vault", "/v1/sys/health",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"initialized":true,"sealed":false}'),
     "finding"),
    ("vault-refused", "shapo_vault_health", "vault", "/v1/sys/health",
     _http_reply("403 Forbidden"), "clean"),
    ("vault-503-not-json", "shapo_vault_health", "vault", "/v1/sys/health",
     _http_reply("503 Service Unavailable", body=b"upstream connect error or disconnect"), "error"),
    ("kube-ok", "shapo_kube_version", "k8s-api", "/version",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"major":"1","minor":"28","gitVersion":"v1.28.2","platform":"linux/amd64"}'), "finding"),
    ("kube-refused", "shapo_kube_version", "k8s-api", "/version",
     _http_reply("401 Unauthorized"), "clean"),
    ("kube-empty-object", "shapo_kube_version", "k8s-api", "/version",
     _http_reply("200 OK", b"Content-Type: application/json", body=b"{}"), "error"),
    ("ollama-ok", "shapo_ollama_tags", "ollama", "/api/tags",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"models":[]}'), "finding"),
    ("ollama-refused", "shapo_ollama_tags", "ollama", "/api/tags",
     _http_reply("401 Unauthorized"), "clean"),
    ("ollama-wrong-json", "shapo_ollama_tags", "ollama", "/api/tags",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"error":"models disabled"}'), "error"),
]


@needs_pulse
@pytest.mark.parametrize(("plugin", "service", "target", "reply", "expect"),
                         [case[1:] for case in HTTP_PHASE_CASES], ids=[case[0] for case in HTTP_PHASE_CASES])
def test_http_status_plugins_of_phases_1_2_and_4(plugin, service, target, reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin(plugin, service, server, tmp_path)
    seen = finding(lines)
    request = server.received[-1]
    assert request.startswith(f"GET {target} HTTP/1.1\r\n".encode()), request
    assert b"Host: shapoclyack.invalid\r\n" in request
    assert b"Connection: close\r\n" in request
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# Phase 8. A 200 that is not the parsed condition is clean for the two plain-HTTP
# checks, and an error for the service-gated documents. Evidence stays static.
PHASE8_CASES = [
    ("es-ok", "shapo_elasticsearch_root", "elasticsearch", "/",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"tagline":"You Know, for Search","version":{"number":"8.11.0"}}'),
     "finding", ()),
    ("es-spaced", "shapo_elasticsearch_root", "elasticsearch", "/",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"tagline" : "You Know, for Search", "version" : {"number":"8.11.0"}}'),
     "finding", ()),
    ("es-chunked", "shapo_elasticsearch_root", "elasticsearch", "/",
     _chunked_http_reply("200 OK", b"Content-Type: application/json",
                         body=b'{"tagline":"You Know, for Search","version":{"number":"8.11.0"}}'),
     "finding", ("8.11.0",)),
    ("es-refused", "shapo_elasticsearch_root", "elasticsearch", "/",
     _http_reply("401 Unauthorized"), "clean", ()),
    ("es-redirect", "shapo_elasticsearch_root", "elasticsearch", "/",
     _http_reply("302 Found", b"Location: https://example.invalid/"), "clean", ()),
    ("es-longer-tagline", "shapo_elasticsearch_root", "elasticsearch", "/",
     _http_reply("200 OK", body=b'{"tagline":"You Know, for Searching","version":{}}'), "error", ()),
    ("es-no-version", "shapo_elasticsearch_root", "elasticsearch", "/",
     _http_reply("200 OK", body=b'{"tagline":"You Know, for Search"}'), "error", ()),
    ("es-garbage", "shapo_elasticsearch_root", "elasticsearch", "/",
     b"NO CARRIER\r\n", "error", ()),
    ("os-ok", "shapo_opensearch_root", "opensearch", "/",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"distribution":"opensearch","version":{"number":"2.11.0"}}'),
     "finding", ("2.11.0",)),
    ("os-refused", "shapo_opensearch_root", "opensearch", "/",
     _http_reply("403 Forbidden"), "clean", ()),
    ("os-elastic-body", "shapo_opensearch_root", "opensearch", "/",
     _http_reply("200 OK", body=b'{"tagline":"You Know, for Search","version":{}}'), "error", ()),
    ("minio-ok", "shapo_minio_health", "minio", "/minio/health/live",
     _http_reply("200 OK", b"Server: MinIO"), "finding", ()),
    ("minio-release", "shapo_minio_health", "minio", "/minio/health/live",
     _http_reply("200 OK", b"Server: MinIO/2024.01.01.01"), "finding", ("2024.01.01.01",)),
    ("minio-refused", "shapo_minio_health", "minio", "/minio/health/live",
     _http_reply("401 Unauthorized"), "clean", ()),
    ("minio-other-server", "shapo_minio_health", "minio", "/minio/health/live",
     _http_reply("200 OK", b"Server: nginx/1.24.0"), "error", ()),
    ("minio-garbage", "shapo_minio_health", "minio", "/minio/health/live",
     b"NO CARRIER\r\n", "error", ()),
    ("neo4j-ok", "shapo_neo4j_http", "neo4j", "/",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"neo4j_version":"5.15.0","neo4j_edition":"community"}'),
     "finding", ("5.15.0", "community")),
    ("neo4j-refused", "shapo_neo4j_http", "neo4j", "/",
     _http_reply("401 Unauthorized"), "clean", ()),
    ("neo4j-no-version", "shapo_neo4j_http", "neo4j", "/",
     _http_reply("200 OK", body=b'{"bolt_direct":"bolt://localhost:7687"}'), "error", ()),
    ("git-ok", "shapo_http_git", "http", "/.git/HEAD",
     _http_reply("200 OK", body=b"ref: refs/heads/main\n"), "finding", ("heads/main", "main")),
    ("git-404", "shapo_http_git", "http", "/.git/HEAD",
     _http_reply("404 Not Found"), "clean", ()),
    ("git-html", "shapo_http_git", "http", "/.git/HEAD",
     _http_reply("200 OK", body=b"<html>ref: refs/heads/main</html>"), "clean", ()),
    ("git-garbage", "shapo_http_git", "http", "/.git/HEAD",
     b"NO CARRIER\r\n", "error", ()),
    ("status-ok", "shapo_http_server_status", "http", "/server-status",
     _http_reply("200 OK", body=b"<html><head><title>Apache Server Status for example.invalid</title></head></html>"),
     "finding", ("example.invalid",)),
    ("status-h1", "shapo_http_server_status", "http", "/server-status",
     _http_reply("200 OK", body=b"<h1>Apache Server Status for example.invalid</h1>"),
     "finding", ("example.invalid",)),
    ("status-homepage", "shapo_http_server_status", "http", "/server-status",
     _http_reply("200 OK", body=b"<html><title>Welcome</title></html>"), "clean", ()),
    ("status-401", "shapo_http_server_status", "http", "/server-status",
     _http_reply("401 Unauthorized"), "clean", ()),
    ("status-garbage", "shapo_http_server_status", "http", "/server-status",
     b"NO CARRIER\r\n", "error", ()),
]


@needs_pulse
@pytest.mark.parametrize(("plugin", "service", "target", "reply", "expect", "hidden"),
                         [case[1:] for case in PHASE8_CASES], ids=[case[0] for case in PHASE8_CASES])
def test_phase8_plugins_parse_one_reply(plugin, service, target, reply, expect, hidden, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin(plugin, service, server, tmp_path)
    seen = finding(lines)
    request = server.received[-1]
    assert request.startswith(f"GET {target} HTTP/1.1\r\n".encode()), request
    assert b"Host: shapoclyack.invalid\r\n" in request
    assert b"Connection: close\r\n" in request
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
        evidence = seen[2]
        for secret in hidden:
            assert secret not in evidence
            assert secret not in seen[1]
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_http_webdav: one Depth 0 PROPFIND; only 207 Multi-Status reports ---


@needs_pulse
@pytest.mark.parametrize(("reply", "expect"), [
    (_http_reply("207 Multi-Status", b"Content-Type: application/xml; charset=utf-8",
                 body=b'<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">'
                      b'<D:response><D:href>/protected/file.txt</D:href></D:response></D:multistatus>'),
     "finding"),
    (_http_reply("404 Not Found"), "clean"),
    (_http_reply("200 OK", b"Content-Type: text/html", body=b"<html><body>Welcome</body></html>"), "clean"),
    (b"NO CARRIER\r\n", "error"),
], ids=["webdav-207", "webdav-404", "webdav-html-200", "webdav-not-http"])
def test_http_webdav_depth0_propfind_reports_only_207_multistatus(reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_http_webdav", "http", server, tmp_path)
    seen = finding(lines)
    request = server.received[-1]
    assert request.startswith(b"PROPFIND / HTTP/1.1\r\n"), request
    assert b"Host: shapoclyack.invalid\r\n" in request
    assert b"Depth: 0\r\n" in request
    assert b"Content-Length: 0\r\n" in request
    assert b"Connection: close\r\n" in request
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
        assert "/protected/file.txt" not in seen[2]
        assert "href" not in seen[2].lower()
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_winrm_http: the 401 needs both the challenge and the product mark ---


@needs_pulse
@pytest.mark.parametrize(("reply", "expect"), [
    (_http_reply("401 Unauthorized", b"Server: Microsoft-HTTPAPI/2.0", b"WWW-Authenticate: Negotiate"), "finding"),
    (_http_reply("401 Unauthorized", b"Server: nginx/1.24.0"), "clean"),
    (b"\x16\x03\x01\x00garbage-not-http", "error"),
], ids=["401-with-challenge-and-httpapi", "401-without-signatures", "not-http"])
def test_winrm_http_challenge_needs_both_signatures_and_shapes_the_post(reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_winrm_http", "winrm", server, tmp_path)
    seen = finding(lines)
    request = server.received[-1]
    assert request.startswith(b"POST /wsman HTTP/1.1\r\n"), request
    assert b"Host: shapoclyack.invalid\r\n" in request
    assert b"Connection: close\r\n" in request
    assert b"Content-Length: 0\r\n" in request
    assert b"Content-Type: application/soap+xml\r\n" in request
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_http_headers: one HEAD, two missing hardening header groups -------


@needs_pulse
@pytest.mark.parametrize(("reply", "expect"), [
    (_http_reply("200 OK", b"Server: stub/1.0"), "finding"),
    (_http_reply("200 OK", b"X-Content-Type-Options: nosniff", b"Content-Security-Policy: default-src 'self'"),
     "clean"),
    (_http_reply("500 Internal Server Error"), "clean"),
    (b"this is not http\r\n", "error"),
    (b"HTTP/1.1 200 OK\r\nServer: stub", "error"),
], ids=["200-missing-both-groups", "200-with-both-groups", "500-outside-the-status-list", "not-http",
        "truncated-headers"])
def test_http_headers_reports_missing_hardening_headers_on_head(reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_http_headers", "http", server, tmp_path)
    seen = finding(lines)
    request = server.received[-1]
    assert request.startswith(b"HEAD / HTTP/1.1\r\n"), request
    assert b"Host: shapoclyack.invalid\r\n" in request
    assert b"Connection: close\r\n" in request
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --------------------------------------------------------------------------
# Phase 1: shapo_mongodb_hello -- one legacy OP_QUERY isMaster, BSON answer.
# --------------------------------------------------------------------------


def _bson_doc(elements) -> bytes:
    body = b""
    for kind, name, value in elements:
        body += bytes([kind]) + name.encode() + b"\x00"
        if kind == 0x01:  # double
            body += struct.pack("<d", value)
        elif kind == 0x02:  # string
            raw = value.encode()
            body += struct.pack("<i", len(raw) + 1) + raw + b"\x00"
        elif kind == 0x08:  # bool
            body += b"\x01" if value else b"\x00"
        elif kind == 0x10:  # int32
            body += struct.pack("<i", value)
        elif kind == 0x0B:  # regex: pattern and options, each a C string
            pattern, options = value
            body += pattern.encode() + b"\x00" + options.encode() + b"\x00"
        elif kind == 0x11:  # timestamp, eight raw bytes
            if len(value) != 8:
                raise ValueError("BSON timestamp must be 8 bytes")
            body += value
        else:
            raise ValueError(f"unsupported BSON element kind {kind:#x}")
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def _mongo_wire_reply(request: bytes, doc: bytes) -> bytes:
    """One legacy OP_REPLY (the plugin sends OP_QUERY), echoing the request id."""
    assert struct.unpack_from("<i", request, 12)[0] == 2004, "the plugin sends a legacy OP_QUERY hello"
    request_id = struct.unpack_from("<i", request, 4)[0]
    body = struct.pack("<iqii", 0, 0, 0, 1) + doc
    return struct.pack("<iiii", 16 + len(body), 0, request_id, 1) + body


@needs_pulse
@pytest.mark.parametrize("case", ["hello-ok", "auth-error", "truncated"])
def test_mongodb_hello_parses_the_bson_answer_or_raises(stub, tmp_path, case):
    def reply(request: bytes) -> bytes:
        if case == "hello-ok":
            # ok is the double 1.0, which is not eight zero bytes. operationTime
            # is a top-level timestamp. note is a regex of two C strings.
            doc = _bson_doc([
                (0x08, "ismaster", True),
                (0x01, "ok", 1.0),
                (0x11, "operationTime", b"\x01\x00\x00\x00\x02\x00\x00\x00"),
                (0x0B, "note", ("a", "i")),
                (0x10, "maxBsonObjectSize", 16777216),
            ])
        elif case == "auth-error":
            doc = _bson_doc([(0x01, "ok", 0.0), (0x02, "errmsg", "not authorized on admin to execute command"),
                             (0x10, "code", 13)])
        else:
            return _mongo_wire_reply(request, _bson_doc([(0x08, "ismaster", True)]))[:-3]
        return _mongo_wire_reply(request, doc)

    server = stub(b"", reply)
    lines, errors = _run_binary_plugin("shapo_mongodb_hello", "mongodb", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == (
        "3a0000005348415000000000d40700000000000061646d696e2e24636d6400"
        "0000000001000000130000001069734d6173746572000100000000"
    ), "one legacy OP_QUERY isMaster on admin.$cmd with request id SHAP"
    if case == "hello-ok":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif case == "auth-error":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --------------------------------------------------------------------------
# Phase 3: brokers and catalogs -- exact binary frames.
# --------------------------------------------------------------------------


def _kafka_apiversions_reply(request: bytes, error_code: int, cut: int | None = None) -> bytes:
    """ApiVersions v0: frame length, correlation id, error code, one api (0, 0..8)."""
    body = request[8:12] + struct.pack(">h", error_code) + struct.pack(">i", 1) + struct.pack(">hhh", 0, 0, 8)
    frame = struct.pack(">I", len(body)) + body
    return frame if cut is None else frame[:cut]


@needs_pulse
@pytest.mark.parametrize("case", ["error-code-zero", "nonzero-code-unverified", "shorter-than-header"])
def test_kafka_apiversions_accepts_only_a_verified_zero_error_code(stub, tmp_path, case):
    error_code = 1 if case == "nonzero-code-unverified" else 0
    cut = 3 if case == "shorter-than-header" else None

    def reply(request: bytes) -> bytes:
        return _kafka_apiversions_reply(request, error_code, cut)

    server = stub(b"", reply)
    lines, errors = _run_binary_plugin("shapo_kafka_apiversions", "kafka", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == "0000000f00120000534841500005736861706f", (
        "frame length 15, ApiVersions v0, correlation id SHAP, client id shapo"
    )
    if case == "error-code-zero":
        assert seen and seen[0] == "LOW" and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


@needs_pulse
@pytest.mark.parametrize(("reply", "expect"), [
    (b"\x20\x02\x00\x00", "finding"),
    (b"\x20\x02\x00\x05", "clean"),
    (b"\x20\x02\x00", "error"),
], ids=["connack-accepted", "connack-not-authorized", "truncated-connack"])
def test_mqtt_anonymous_connect_is_level_4_clean_session_without_credentials(reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_mqtt_anonymous", "mqtt", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == "101100044d5154540402003c0005736861706f", (
        "CONNECT at level 4, clean session, keepalive 60, client id shapo, no credentials"
    )
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


_AMQP_START_PAYLOAD = (b"\x00\x0a\x00\x0a"  # class 10 (connection), method 10 (start)
                       + b"\x00\x09"  # AMQP 0-9-1
                       + b"\x00\x00\x00\x00"  # empty server-properties table
                       + b"\x00\x00\x00\x0ePLAIN AMQPLAIN"
                       + b"\x00\x00\x00\x05en_US")
_AMQP_START = b"\x01\x00\x00" + struct.pack(">I", len(_AMQP_START_PAYLOAD)) + _AMQP_START_PAYLOAD + b"\xce"


@needs_pulse
@pytest.mark.parametrize(("reply", "expect"), [
    (_AMQP_START, "finding"),
    (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "error"),
    (_AMQP_START[:12], "error"),
], ids=["connection-start", "http-instead-of-amqp", "truncated-frame"])
def test_amqp_start_confirms_the_protocol_without_logging_in(reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_amqp_start", "amqp", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1] == b"AMQP\x00\x00\x09\x01", "the whole exchange is the protocol header"
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


#: The documented access-refusal result codes: insufficientAccessRights (50) or
#: invalidCredentials (49). The plugin records 49 and 50; keep one fixture code.
_LDAP_REFUSAL_CODE = 50


def _ldap_message_id(request: bytes) -> bytes:
    pos = 2 + (request[1] & 0x7F if request[1] & 0x80 else 0)
    assert request[pos] == 0x02, "LDAPMessage must open with the messageID INTEGER"
    size = request[pos + 1]
    return request[pos + 2: pos + 2 + size]


def _ldap_rootdse_response(request: bytes, result_code: int, entry: bool) -> bytes:
    """Separate LDAPMessage sequences for the optional entry and SearchResultDone."""
    mid = _ber(2, _ldap_message_id(request))
    messages = []
    if entry:
        attribute = _ber(0x30, _ber(4, b"supportedLDAPVersion") + _ber(0x31, _ber(4, b"3")))
        result = _ber(0x64, _ber(4, b"") + _ber(0x30, attribute))
        messages.append(_ber(0x30, mid + result))
    done = _ber(0x65, _ber(0x0A, bytes([result_code])) + _ber(4, b"") + _ber(4, b""))
    messages.append(_ber(0x30, mid + done))
    return b"".join(messages)


@needs_pulse
@pytest.mark.parametrize("case", ["entry-ok", "insufficient-access-rights", "truncated-ber"])
def test_ldap_rootdse_base_search_parses_ber_or_raises(stub, tmp_path, case):
    def reply(request: bytes) -> bytes:
        if case == "entry-ok":
            return _ldap_rootdse_response(request, 0, entry=True)
        if case == "insufficient-access-rights":
            return _ldap_rootdse_response(request, _LDAP_REFUSAL_CODE, entry=False)
        return _ldap_rootdse_response(request, 0, entry=True)[:-3]

    server = stub(b"", reply)
    lines, errors = _run_binary_plugin("shapo_ldap_rootdse", "ldap", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == (
        "304b020101634604000a01000a0100020100020100010100870b6f626a656374436c617373"
        "30260414737570706f727465644c44415056657273696f6e040e6e616d696e67436f6e7465787473"
    ), "one base SearchRequest: present filter objectClass, two naming attributes"
    if case == "entry-ok":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif case == "insufficient-access-rights":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --------------------------------------------------------------------------
# Phase 4: shapo_x11_noauth -- the first reply byte decides, MEDIUM on success.
# --------------------------------------------------------------------------


def _x11_success() -> bytes:
    return b"\x01" + b"\x00" * 5 + b"\x00\x00"  # accepted, no additional data


def _x11_refusal() -> bytes:
    # Refused: status 0, reason length 8, two additional 8-byte blocks total 16 bytes.
    return b"\x00\x08" + b"\x00" * 4 + b"\x02\x00" + b"no auth!"


@needs_pulse
@pytest.mark.parametrize(("reply", "expect"), [
    (_x11_success(), "finding"),
    (_x11_refusal(), "clean"),
    (b"", "error"),
], ids=["success", "refusal", "empty"])
def test_x11_noauth_first_reply_byte_decides_and_setup_is_empty(stub, tmp_path, reply, expect):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_x11_noauth", "x11", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == "6c000b000000000000000000", (
        "little-endian 11.0 setup with zero-length authorisation name and data"
    )
    if expect == "finding":
        assert seen and seen[0] == "MEDIUM" and not errors.strip()
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --------------------------------------------------------------------------
# Phase 7 (docs/pulse-plugin-phases.ru.md): twelve single-request status checks.
# Every HTTP plugin sends one raw GET (Host: shapoclyack.invalid,
# Connection: close); 401/403 and redirects are silent, any other parsed
# status without the finding condition is a plugin error. Evidence is a static
# phrase about the parse and must not carry reply values.
# --------------------------------------------------------------------------

#: (id, plugin, service, request target, stub reply, expected outcome).
#: Docs criteria: couchdb wants the exact "Welcome" value plus a version key;
#: nomad accepts any single JSON string (or the empty string) but no HTML;
#: influx answers 204 only with X-Influxdb-Version in the headers, or 200 with
#: the header and a JSON version key; rabbitmq wants both whoami keys;
#: gitlab and rancher want an exact body; harbor accepts healthy and unhealthy
#: alike; portainer's keys are case-sensitive; sonarqube's status enum rejects
#: UPSTREAM; keycloak wants a JSON array, an empty one included.
HTTP_PHASE_7_CASES = [
    ("p7-couchdb-welcome", "shapo_couchdb_root", "couchdb", "/",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"couchdb":"Welcome","version":"3.3.3","uuid":"d3adbeef-cafe","git_sha":"abc123"}'),
     "finding"),
    ("p7-couchdb-chunked", "shapo_couchdb_root", "couchdb", "/",
     _chunked_http_reply("200 OK", b"Content-Type: application/json",
                         body=b'{"couchdb":"Welcome","version":"0"}', content_length=2),
     "finding"),
    ("p7-couchdb-refused", "shapo_couchdb_root", "couchdb", "/",
     _http_reply("401 Unauthorized"), "clean"),
    ("p7-couchdb-ok-only", "shapo_couchdb_root", "couchdb", "/",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"ok":true}'), "error"),
    ("p7-couchdb-long-welcome", "shapo_couchdb_root", "couchdb", "/",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"couchdb":"WelcomeBack","version":"0"}'), "error"),
    ("p7-nomad-leader", "shapo_nomad_status", "nomad", "/v1/status/leader",
     _http_reply("200 OK", body=b'"127.0.0.1:4647"'), "finding"),
    ("p7-nomad-leader-crlf", "shapo_nomad_status", "nomad", "/v1/status/leader",
     _http_reply("200 OK", body=b'"10.20.30.40:4647"\r\n'), "finding"),
    ("p7-nomad-empty-string", "shapo_nomad_status", "nomad", "/v1/status/leader",
     _http_reply("200 OK", body=b'""'), "finding"),
    ("p7-nomad-refused", "shapo_nomad_status", "nomad", "/v1/status/leader",
     _http_reply("403 Forbidden"), "clean"),
    ("p7-nomad-html", "shapo_nomad_status", "nomad", "/v1/status/leader",
     _http_reply("200 OK", b"Content-Type: text/html", body=b"<html>leader</html>"), "error"),
    ("p7-nomad-object", "shapo_nomad_status", "nomad", "/v1/status/leader",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"leader":"x"}'), "error"),
    ("p7-influx-204-header", "shapo_influx_health", "influxdb", "/ping",
     _http_reply("204 No Content", b"X-Influxdb-Version: 2.7.5"), "finding"),
    ("p7-influx-204-lower-header", "shapo_influx_health", "influxdb", "/ping",
     _http_reply("204 No Content", b"x-influxdb-version: 2.7.5"), "finding"),
    ("p7-influx-200-json", "shapo_influx_health", "influxdb", "/ping",
     _http_reply("200 OK", b"X-Influxdb-Version: 2.7.5", body=b'{"version":"2.7.5"}'), "finding"),
    ("p7-influx-refused", "shapo_influx_health", "influxdb", "/ping",
     _http_reply("401 Unauthorized"), "clean"),
    ("p7-influx-204-no-header", "shapo_influx_health", "influxdb", "/ping",
     _http_reply("204 No Content"), "error"),
    ("p7-influx-200-no-version", "shapo_influx_health", "influxdb", "/ping",
     _http_reply("200 OK", b"X-Influxdb-Version: 2.7.5", body=b"{}"), "error"),
    ("p7-influx-200-version-in-html", "shapo_influx_health", "influxdb", "/ping",
     _http_reply("200 OK", b"X-Influxdb-Version: 2.7.5", body=b'<p>"version":"2.7.5"</p>'), "error"),
    ("p7-rabbitmq-whoami", "shapo_rabbitmq_mgmt", "rabbitmq-mgmt", "/api/whoami",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"name":"svc-mq-user-7","tags":"administrator"}'), "finding"),
    ("p7-rabbitmq-refused", "shapo_rabbitmq_mgmt", "rabbitmq-mgmt", "/api/whoami",
     _http_reply("401 Unauthorized"), "clean"),
    ("p7-rabbitmq-html", "shapo_rabbitmq_mgmt", "rabbitmq-mgmt", "/api/whoami",
     _http_reply("200 OK", b"Content-Type: text/html", body=b"<html>login</html>"), "error"),
    ("p7-rabbitmq-name-only", "shapo_rabbitmq_mgmt", "rabbitmq-mgmt", "/api/whoami",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"name":"svc-mq-user-7"}'),
     "error"),
    ("p7-gitlab-ok", "shapo_gitlab_health", "gitlab", "/-/health",
     _http_reply("200 OK", body=b"GitLab OK"), "finding"),
    ("p7-gitlab-ok-lf", "shapo_gitlab_health", "gitlab", "/-/health",
     _http_reply("200 OK", body=b"GitLab OK\n"), "finding"),
    ("p7-gitlab-ok-crlf", "shapo_gitlab_health", "gitlab", "/-/health",
     _http_reply("200 OK", body=b"GitLab OK\r\n"), "finding"),
    ("p7-gitlab-redirect", "shapo_gitlab_health", "gitlab", "/-/health",
     _http_reply("302 Found", b"Location: https://gitlab.example/users/sign_in"), "clean"),
    ("p7-gitlab-bare-ok", "shapo_gitlab_health", "gitlab", "/-/health",
     _http_reply("200 OK", body=b"OK"), "error"),
    ("p7-harbor-healthy", "shapo_harbor_health", "harbor", "/api/v2.0/health",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"healthy"}'),
     "finding"),
    ("p7-harbor-unhealthy", "shapo_harbor_health", "harbor", "/api/v2.0/health",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"unhealthy"}'),
     "finding"),
    ("p7-harbor-refused", "shapo_harbor_health", "harbor", "/api/v2.0/health",
     _http_reply("401 Unauthorized"), "clean"),
    ("p7-harbor-healthyish", "shapo_harbor_health", "harbor", "/api/v2.0/health",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"healthyish"}'),
     "error"),
    ("p7-harbor-space-in-status", "shapo_harbor_health", "harbor", "/api/v2.0/health",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"heal thy"}'),
     "error"),
    ("p7-portainer-status", "shapo_portainer_status", "portainer", "/api/system/status",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"Version":"0.3.1","InstanceID":"9f2c-demo-id"}'), "finding"),
    ("p7-portainer-refused", "shapo_portainer_status", "portainer", "/api/system/status",
     _http_reply("401 Unauthorized"), "clean"),
    ("p7-portainer-lowercase", "shapo_portainer_status", "portainer", "/api/system/status",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"version":"0"}'), "error"),
    ("p7-sonarqube-up", "shapo_sonarqube_status", "sonarqube", "/api/system/status",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"UP"}'), "finding"),
    ("p7-sonarqube-migration", "shapo_sonarqube_status", "sonarqube", "/api/system/status",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"DB_MIGRATION_RUNNING"}'),
     "finding"),
    ("p7-sonarqube-refused", "shapo_sonarqube_status", "sonarqube", "/api/system/status",
     _http_reply("401 Unauthorized"), "clean"),
    ("p7-sonarqube-upstream", "shapo_sonarqube_status", "sonarqube", "/api/system/status",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"status":"UPSTREAM"}'),
     "error"),
    ("p7-keycloak-empty", "shapo_keycloak_realm", "keycloak", "/admin/realms",
     _http_reply("200 OK", b"Content-Type: application/json", body=b"[]"), "finding"),
    ("p7-keycloak-list", "shapo_keycloak_realm", "keycloak", "/admin/realms",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'[{"realm":"internal-corp","id":"internal-corp"}]'), "finding"),
    ("p7-keycloak-refused", "shapo_keycloak_realm", "keycloak", "/admin/realms",
     _http_reply("401 Unauthorized"), "clean"),
    ("p7-keycloak-object", "shapo_keycloak_realm", "keycloak", "/admin/realms",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'{"realm":"master"}'), "error"),
    ("p7-rancher-pong", "shapo_rancher_status", "rancher", "/ping",
     _http_reply("200 OK", body=b"pong"), "finding"),
    ("p7-rancher-pong-lf", "shapo_rancher_status", "rancher", "/ping",
     _http_reply("200 OK", body=b"pong\n"), "finding"),
    ("p7-rancher-pong-crlf", "shapo_rancher_status", "rancher", "/ping",
     _http_reply("200 OK", body=b"pong\r\n"), "finding"),
    ("p7-rancher-redirect", "shapo_rancher_status", "rancher", "/ping",
     _http_reply("302 Found", b"Location: https://rancher.example/ping"), "clean"),
    ("p7-rancher-pong-extra", "shapo_rancher_status", "rancher", "/ping",
     _http_reply("200 OK", body=b"pong-extra"), "error"),
]


@needs_pulse
@pytest.mark.parametrize(("plugin", "service", "target", "reply", "expect"),
                         [case[1:] for case in HTTP_PHASE_7_CASES],
                         ids=[case[0] for case in HTTP_PHASE_7_CASES])
def test_http_status_plugins_of_phase_7(plugin, service, target, reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin(plugin, service, server, tmp_path)
    seen = finding(lines)
    request = server.received[-1]
    assert request.startswith(f"GET {target} HTTP/1.1\r\n".encode()), request
    assert b"Host: shapoclyack.invalid\r\n" in request
    assert b"Connection: close\r\n" in request
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


#: (id, plugin, service, request target, stub reply, reply values the evidence must not leak).
#: Every plugin in this table has a static evidence phrase by contract; the
#: banned strings are values only present in the stub reply.
EVIDENCE_PHASE_7_CASES = [
    ("p7-ev-couchdb", "shapo_couchdb_root", "couchdb", "/",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"couchdb":"Welcome","version":"3.3.3","uuid":"d3adbeef-cafe","git_sha":"abc123"}'),
     ("3.3.3", "d3adbeef", "abc123")),
    ("p7-ev-nomad", "shapo_nomad_status", "nomad", "/v1/status/leader",
     _http_reply("200 OK", body=b'"10.20.30.40:4647"'), ("10.20.30.40", "4647")),
    ("p7-ev-influx-204", "shapo_influx_health", "influxdb", "/ping",
     _http_reply("204 No Content", b"X-Influxdb-Version: 2.7.5"), ("2.7.5",)),
    ("p7-ev-influx-200", "shapo_influx_health", "influxdb", "/ping",
     _http_reply("200 OK", b"X-Influxdb-Version: 2.7.5", body=b'{"version":"2.7.5"}'), ("2.7.5",)),
    ("p7-ev-rabbitmq", "shapo_rabbitmq_mgmt", "rabbitmq-mgmt", "/api/whoami",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"name":"svc-mq-user-7","tags":"administrator"}'),
     ("svc-mq-user-7", "administrator")),
    ("p7-ev-portainer", "shapo_portainer_status", "portainer", "/api/system/status",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"Version":"0.3.1","InstanceID":"9f2c-demo-id"}'), ("0.3.1", "9f2c-demo-id")),
    ("p7-ev-sonarqube", "shapo_sonarqube_status", "sonarqube", "/api/system/status",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"status":"UP","id":"123abc","version":"10.5.1"}'), ("123abc", "10.5.1")),
    ("p7-ev-harbor", "shapo_harbor_health", "harbor", "/api/v2.0/health",
     _http_reply("200 OK", b"Content-Type: application/json",
                 body=b'{"status":"healthy","components":[{"name":"comp-trivy-7","error":"boom-detail-9"}]}'),
     ("comp-trivy-7", "boom-detail-9")),
    ("p7-ev-keycloak", "shapo_keycloak_realm", "keycloak", "/admin/realms",
     _http_reply("200 OK", b"Content-Type: application/json", body=b'[{"realm":"internal-corp"}]'),
     ("internal-corp",)),
]


@needs_pulse
@pytest.mark.parametrize(("plugin", "service", "target", "reply", "banned"),
                         [case[1:] for case in EVIDENCE_PHASE_7_CASES],
                         ids=[case[0] for case in EVIDENCE_PHASE_7_CASES])
def test_phase_7_evidence_is_a_static_phrase_without_reply_values(plugin, service, target, reply,
                                                                  banned, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin(plugin, service, server, tmp_path)
    seen = finding(lines)
    assert seen and seen[0] == "LOW" and not errors.strip(), errors
    for value in banned:
        assert value not in seen[2], f"evidence leaks {value!r}: {seen[2]}"


# --- shapo_nats_info: CONNECT without credentials, PING, one PONG line ------


#: The documented exchange: CONNECT carries no user/pass/token keys, then PING.
_NATS_CONNECT = b'CONNECT {"verbose":false,"pedantic":false,"lang":"shapo","version":"1","protocol":1}\r\nPING\r\n'


@needs_pulse
@pytest.mark.parametrize(("reply", "expect", "banned"), [
    (b"PONG\r\n", "finding", ()),
    (b'INFO {"server_id":"SRV7X","version":"2.10.4","host":"10.0.0.9","port":4222,"client_id":99}\r\nPONG\r\n',
     "finding", ("SRV7X", "10.0.0.9", "2.10.4")),
    (b"-ERR 'Authorization Violation'\r\n", "clean", ()),
    (b'-ERR "Authentication Timeout"\r\n', "clean", ()),
    (b'INFO {"server_id":"SRV7X"}\r\n', "error", ()),
    (b'-ERR "Unknown Protocol Operation"\r\n', "error", ()),
    (b'PONG\r\n-ERR "Unknown Protocol Operation"\r\n', "error", ()),
    (b"", "error", ()),
], ids=["pong", "info-then-pong", "authorization-violation", "authentication-timeout",
        "info-without-pong", "other-err", "pong-with-other-err", "empty"])
def test_nats_info_pongs_after_an_unauthenticated_connect_and_ping(reply, expect, banned, stub,
                                                                   tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_nats_info", "nats", server, tmp_path)
    seen = finding(lines)
    assert server.received == [_NATS_CONNECT], server.received
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
        for value in banned:
            assert value not in seen[2], f"evidence leaks {value!r}: {seen[2]}"
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_neo4j_discovery: one Bolt version offer, the first 4 bytes decide --

#: magic 6060b017, then Bolt 5.4, 5.0, 4.4, 4.0 as big-endian version ints.
_NEO4J_BOLT_OFFER = "6060b01700000405000000050000040400000004"


@needs_pulse
@pytest.mark.parametrize(("reply", "expect"), [
    (bytes.fromhex("00000404"), "finding"),
    (bytes.fromhex("000001ff"), "finding"),  # the manifest marker is also a server choice
    (bytes.fromhex("00000000"), "clean"),
    (bytes.fromhex("000004"), "error"),
    (b"", "error"),
], ids=["bolt-4.4-chosen", "manifest-marker", "zero-version", "three-bytes", "empty"])
def test_neo4j_discovery_offers_four_bolt_versions_in_one_hex_write(reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin(
        "shapo_neo4j_discovery", "", server, tmp_path, unnamed_stub=True,
    )
    seen = finding(lines)
    assert server.received[-1].hex() == _NEO4J_BOLT_OFFER, (
        "one probe_send_hex: magic, then versions 5.4, 5.0, 4.4, 4.0 big-endian"
    )
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


@needs_pulse
def test_neo4j_http_service_does_not_offer_bolt(stub, tmp_path):
    # probes.json names this service from an HTTP "neo4j_version" document.
    server = stub(b"", lambda _request: b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    lines, errors = _run_binary_plugin("shapo_neo4j_discovery", "neo4j", server, tmp_path)
    assert finding(lines) is None and not errors.strip(), errors
    assert all(request.hex() != _NEO4J_BOLT_OFFER for request in server.received)


# --------------------------------------------------------------------------
# Phase 8: shapo_pop3_ntlm -- two-step AUTH NTLM observation. The sandbox
# opens one connection per probe call, so the stub answers the plugin's second
# record the way a socket-reusing server would: the type2 challenge arrives
# without a repeated greeting. A fresh "+OK" there is the documented blocked
# outcome; the plugin raises it instead of calling the port clean.
# --------------------------------------------------------------------------

POP3_TYPE1_HEX = "4e544c4d53535000010000000782080000000000000000000000000000000000"
POP3_TYPE2_HEX = (
    "4e544c4d53535000020000000000000000000000000000001234567890abcdef"
    "000000000000000000000000000000000000000000000000"
)
POP3_GREETING = b"+OK POP3 stub ready\r\n"


def _pop3_ntlm_stub(stub, second_reply):
    # conn 1 is pulse's bare banner grab; conn 2 is AUTH NTLM, answered with a
    # continuation; conn 3 is the type1 and gets the challenge a kept session
    # would send (no greeting repeated).
    return stub([POP3_GREETING, POP3_GREETING, b""],
                lambda got: second_reply if got.startswith(b"NTLMSSP") else b"+ \r\n")


@needs_pulse
def test_pop3_ntlm_type2_challenge_is_a_low_finding_without_leaking_names(stub, tmp_path):
    server = _pop3_ntlm_stub(stub, bytes.fromhex(POP3_TYPE2_HEX))
    lines, errors = _run_binary_plugin("shapo_pop3_ntlm", "pop3", server, tmp_path)
    seen = finding(lines)
    assert seen and seen[0] == "LOW" and not errors.strip(), errors
    # The hex call is the only way to put the 0x82 flag byte on the wire as
    # one byte: both records, exactly as specified.
    assert server.received == [b"AUTH NTLM\r\n", bytes.fromhex(POP3_TYPE1_HEX)], server.received
    # The evidence names the parse, not the reply values: the challenge bytes
    # of the stub's type2 must not be copied.
    assert "type2" in seen[2]
    assert "001234567890abcdef" not in seen[2]


@needs_pulse
def test_pop3_ntlm_refusal_is_clean_and_stops_before_the_type1(stub, tmp_path):
    server = stub(POP3_GREETING, lambda _got: b"-ERR Authentication required.\r\n")
    lines, errors = _run_binary_plugin("shapo_pop3_ntlm", "pop3", server, tmp_path)
    assert finding(lines) is None and not errors.strip(), errors
    assert server.received == [b"AUTH NTLM\r\n"], server.received


@needs_pulse
def test_pop3_ntlm_truncated_type2_is_an_error_not_a_verdict(stub, tmp_path):
    server = _pop3_ntlm_stub(stub, bytes.fromhex(POP3_TYPE2_HEX)[:40])
    lines, errors = _run_binary_plugin("shapo_pop3_ntlm", "pop3", server, tmp_path)
    assert finding(lines) is None
    assert "truncated" in errors and "Function not found" not in errors, errors


# --------------------------------------------------------------------------
# Phase 8: shapo_socks_noauth -- one SOCKS5 greeting, the two-byte method
# selection decides. 05 00 selects no authentication (LOW); 05 ff or any
# other method is clean; anything that is not exactly a version-5 two-byte
# reply is an error. No CONNECT is ever sent.
# --------------------------------------------------------------------------


@needs_pulse
@pytest.mark.parametrize(("reply", "expect"), [
    (b"\x05\x00", "finding"),
    (b"\x05\xff", "clean"),
    (b"\x05", "error"),
], ids=["noauth-selected", "no-acceptable-method", "one-byte"])
def test_socks_noauth_greeting_selects_the_method_without_a_tunnel(reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_socks_noauth", "socks", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == "050100", (
        "one SOCKS5 greeting: version 5, one method, method 0 (no authentication)"
    )
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --------------------------------------------------------------------------
# Phase 8: shapo_s7_identity -- a COTP Connection Request, then one ReadSZL
# module-identification request. Each probe_send_hex call is its own
# connection in the sandbox, so the stub answers by request bytes: the
# Connection Confirm to the CR, the SZL block to the ReadSZL job. Order
# number, serial number and station name stay inside the stub reply.
# --------------------------------------------------------------------------

_COTP_CR = bytes.fromhex("0300001611e00000000100c00109c1020100c2020101")
_COTP_CC = bytes.fromhex("0300000b06d00001000000")
_COTP_DR = bytes.fromhex("0300000b06800001000000")
_SZL_REQUEST = bytes.fromhex("0300002002f080320100000000000e00000401120a10020001000100000300c0")

#: Values that exist only inside the stub reply; none may reach a finding row.
_S7_SECRETS = ("6ES7 315-2AG10-0AB0", "S C-X8F5 0420", "LINE-42-CONTROL")


def _szl_ident_reply(szl: bytes) -> bytes:
    """A ReadSZL Ack_Data: S7 error 0, return code 0xff, one consistent block."""
    data = b"\xff\x09" + len(szl).to_bytes(2, "big") + szl
    param = bytes.fromhex("0401120a10020000")
    s7 = (b"\x32\x03\x00\x00\x00\x00" + len(param).to_bytes(2, "big")
          + len(data).to_bytes(2, "big") + b"\x00\x00" + param + data)
    return b"\x03\x00" + (7 + len(s7)).to_bytes(2, "big") + b"\x02\xf0\x80" + s7


def _s7_stub(stub, szl_reply):
    def reply(request: bytes) -> bytes:
        if request == _COTP_CR:
            return _COTP_CC if szl_reply is not None else _COTP_DR
        if request == _SZL_REQUEST:
            return szl_reply or b""
        return b""

    return stub(b"", reply)


@needs_pulse
def test_s7_identity_answers_szl_and_keeps_module_identifiers_out_of_evidence(stub, tmp_path):
    szl = (b"001c0001"
           + b"6ES7 315-2AG10-0AB0".ljust(20, b" ")
           + b"S C-X8F5 0420".ljust(24, b" ")
           + b"LINE-42-CONTROL".ljust(24, b" "))
    server = _s7_stub(stub, _szl_ident_reply(szl))
    lines, errors = _run_binary_plugin("shapo_s7_identity", "s7", server, tmp_path)
    seen = finding(lines)
    assert seen and seen[0] == "LOW" and not errors.strip(), errors
    assert server.received == [_COTP_CR, _SZL_REQUEST], server.received
    for secret in _S7_SECRETS:
        assert secret not in seen[1] and secret not in seen[2]


@needs_pulse
def test_s7_identity_cotp_refusal_is_clean_and_stops_before_the_szl_request(stub, tmp_path):
    server = _s7_stub(stub, None)
    lines, errors = _run_binary_plugin("shapo_s7_identity", "s7", server, tmp_path)
    assert finding(lines) is None and not errors.strip(), errors
    assert server.received == [_COTP_CR], server.received


@needs_pulse
def test_s7_identity_truncated_tpkt_is_an_error_not_a_clean_result(stub, tmp_path):
    server = stub(b"", lambda _request: bytes.fromhex("0300001611d0"))
    lines, errors = _run_binary_plugin("shapo_s7_identity", "s7", server, tmp_path)
    assert finding(lines) is None and errors.strip()
    assert "Function not found" not in errors


# --------------------------------------------------------------------------
# Phase 8: shapo_enip_identity -- one List Identity (command 0x0063) with no
# registered session. A zero-status reply whose encapsulation length and the
# single identity item length both close is the finding; a non-zero command
# status is clean; a frame that does not close is an error. Product name,
# serial number and socket address stay inside the stub reply.
# --------------------------------------------------------------------------

_ENIP_LIST_IDENTITY = bytes.fromhex("6300000000000000000000000000000000000000")


def _enip_identity_item(product_name=b"WidgetPLC 9000", serial=0x1234ABCD):
    """A CPF identity item body: fixed CIP fields, then name, state, an IP."""
    socket_addr = struct.pack(">HH", 2, 44818) + bytes([10, 9, 8, 7]) + b"\x00" * 8
    return (
        struct.pack("<H", 1)               # encapsulation protocol version
        + socket_addr                      # 16-byte socket address (IP inside)
        + struct.pack("<HHH", 42, 12, 34)  # vendor id, device type, product code
        + bytes([2, 1])                    # revision (major, minor)
        + struct.pack("<H", 0x0030)        # device status
        + struct.pack("<I", serial)        # serial number
        + bytes([len(product_name)]) + product_name
        + b"\xff"                          # state
    )


def _enip_list_identity_reply(item=None, status=0, cut=None):
    """An encapsulation header (command 0x0063) plus one 0x0c identity item."""
    data = b"" if item is None else struct.pack("<HHH", 1, 0x0C, len(item)) + item
    reply = (
        struct.pack("<HHI", 0x0063, len(data), 0)
        + struct.pack("<I", status)
        + b"\x00" * 8  # sender context
        + b"\x00" * 4  # options
        + data
    )
    return reply if cut is None else reply[:cut]


@needs_pulse
def test_enip_identity_one_complete_item_is_a_finding_without_identity_fields(stub, tmp_path):
    server = stub(b"", lambda _request: _enip_list_identity_reply(_enip_identity_item()))
    lines, errors = _run_binary_plugin("shapo_enip_identity", "enip", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1] == _ENIP_LIST_IDENTITY, (
        "one List Identity: command 0x0063, session handle 0, empty context"
    )
    assert seen and seen[0] == "LOW" and not errors.strip(), errors
    for secret in ("WidgetPLC 9000", "cdab3412", "10.9.8.7"):
        assert secret.lower() not in seen[1].lower(), f"title leaks {secret!r}"
        assert secret.lower() not in seen[2].lower(), f"evidence leaks {secret!r}"


@needs_pulse
def test_enip_identity_nonzero_command_status_is_clean(stub, tmp_path):
    server = stub(b"", lambda _request: _enip_list_identity_reply(status=0x0001))
    lines, errors = _run_binary_plugin("shapo_enip_identity", "enip", server, tmp_path)
    assert finding(lines) is None and not errors.strip(), errors


@needs_pulse
def test_enip_identity_truncated_encapsulation_header_is_an_error(stub, tmp_path):
    server = stub(b"", lambda _request: _enip_list_identity_reply(_enip_identity_item(), cut=20))
    lines, errors = _run_binary_plugin("shapo_enip_identity", "enip", server, tmp_path)
    assert finding(lines) is None and errors.strip()
    assert "Function not found" not in errors


# --------------------------------------------------------------------------
# Phase 8: shapo_imap_ntlm -- AUTHENTICATE NTLM, then a minimal NTLM type1
# token on the continuation. A parsed type2 challenge is the finding; a NO/BAD
# answer is clean and sends no type1; a truncated type2 is an error. The stub
# answers by request bytes because the sandbox opens one connection per
# probe_send call; a fresh IMAP greeting on the second call stops the check as
# blocked with the reason, so the stub serves the type2 connection no greeting.
# --------------------------------------------------------------------------

#: The minimal NTLM type1 from the phase doc: 32 bytes, no workstation name,
#: no type3.
_IMAP_TYPE1_HEX = "4e544c4d53535000010000000782080000000000000000000000000000000000"
#: The doc's short correct type2: signature, message type 2, zero-length target
#: name and target info blocks, challenge 1234567890abcdef.
_IMAP_TYPE2_HEX = (
    "4e544c4d53535000020000000000000000000000000000001234567890abcdef"
    "000000000000000000000000000000000000000000000000"
)
_IMAP_AUTHENTICATE = b"a001 AUTHENTICATE NTLM\r\n"
_IMAP_GREETING = b"* OK IMAP4rev1 ready\r\n"


@needs_pulse
def test_imap_ntlm_type2_challenge_is_a_low_finding_without_names(stub, tmp_path):
    import base64

    def reply(request: bytes) -> bytes:
        if request.startswith(b"a001 AUTHENTICATE"):
            return b"+ \r\n"
        return b"+ " + base64.b64encode(bytes.fromhex(_IMAP_TYPE2_HEX)) + b"\r\n"

    server = stub([_IMAP_GREETING, _IMAP_GREETING, b""], reply)
    lines, errors = _run_binary_plugin("shapo_imap_ntlm", "imap", server, tmp_path)
    seen = finding(lines)
    assert server.received == [_IMAP_AUTHENTICATE, bytes.fromhex(_IMAP_TYPE1_HEX)], server.received
    assert seen and seen[0] == "LOW" and not errors.strip(), errors
    for secret in ("1234567890abcdef",):
        assert secret not in seen[1], f"title leaks {secret!r}"
        assert secret not in seen[2], f"evidence leaks {secret!r}"


@needs_pulse
def test_imap_ntlm_refusal_is_clean_and_sends_no_type1(stub, tmp_path):
    server = stub([_IMAP_GREETING, _IMAP_GREETING], lambda _request: b"a001 NO AUTHENTICATE failed\r\n")
    lines, errors = _run_binary_plugin("shapo_imap_ntlm", "imap", server, tmp_path)
    assert finding(lines) is None and not errors.strip(), errors
    assert server.received == [_IMAP_AUTHENTICATE], server.received


@needs_pulse
def test_imap_ntlm_truncated_type2_is_an_error(stub, tmp_path):
    import base64

    def reply(request: bytes) -> bytes:
        if request.startswith(b"a001 AUTHENTICATE"):
            return b"+ \r\n"
        return b"+ " + base64.b64encode(bytes.fromhex(_IMAP_TYPE2_HEX)[:20]) + b"\r\n"

    server = stub([_IMAP_GREETING, _IMAP_GREETING, b""], reply)
    lines, errors = _run_binary_plugin("shapo_imap_ntlm", "imap", server, tmp_path)
    assert finding(lines) is None and errors.strip()
    assert "Function not found" not in errors


# --------------------------------------------------------------------------
# Phase 8: shapo_smtp_ntlm -- EHLO, then AUTH NTLM on the 250 answer, then the
# same minimal NTLM type1 on the 334 continuation. The sandbox opens one
# connection per probe_send call, so the stub answers by request bytes and
# serves the AUTH NTLM and type1 connections no greeting, the way a
# socket-keeping server would; a fresh "220" there is the documented blocked
# outcome. No MAIL FROM/RCPT TO/VRFY/EXPN and no type3 are ever sent.
# --------------------------------------------------------------------------

#: The doc's type1 (same 32-byte blob as the IMAP and POP3 checks), base64 in
#: one SMTP text line.
_SMTP_TYPE1_B64 = b"TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
_SMTP_EHLO = b"EHLO shapoclyack.invalid\r\n"
_SMTP_GREETING = b"220 mail.example ESMTP\r\n"


def _smtp_type2_b64(target_name: bytes = b"") -> bytes:
    """The doc's type2 shape: signature, message type 2, challenge, blocks that
    close inside the frame. With a target name only to prove it stays secret."""
    import base64

    frame = bytearray(56)
    frame[0:8] = b"NTLMSSP\x00"
    struct.pack_into("<I", frame, 8, 2)
    struct.pack_into("<HHI", frame, 12, len(target_name), len(target_name), 56)
    struct.pack_into("<I", frame, 20, 0x00088205)
    frame[24:32] = bytes.fromhex("0123456789abcdef")
    struct.pack_into("<HHI", frame, 40, 0, 0, 0)
    return base64.b64encode(bytes(frame) + target_name)


def _smtp_ntlm_stub(stub, ehlo_block, *step_replies):
    # conn 1 is pulse's bare banner grab; conn 2 is EHLO and is greeted again
    # like any fresh SMTP session; conn 3 (AUTH NTLM) and conn 4 (the type1)
    # get no greeting repeated, as a kept socket would behave.
    remaining = list(step_replies)

    def reply(request: bytes) -> bytes:
        if request.startswith(b"EHLO"):
            return ehlo_block
        return remaining.pop(0)

    return stub([_SMTP_GREETING, _SMTP_GREETING, b"", b""], reply)


@needs_pulse
def test_smtp_ntlm_type2_challenge_is_a_low_finding_without_names(stub, tmp_path):
    challenge = _smtp_type2_b64("SRV-DC-01".encode("utf-16-le"))
    server = _smtp_ntlm_stub(stub, b"250-mail.example\r\n250-AUTH NTLM\r\n250 HELP\r\n",
                             b"334 \r\n", b"334 " + challenge + b"\r\n")
    lines, errors = _run_binary_plugin("shapo_smtp_ntlm", "smtp", server, tmp_path)
    seen = finding(lines)
    assert server.received == [_SMTP_EHLO, b"AUTH NTLM\r\n", _SMTP_TYPE1_B64 + b"\r\n"], server.received
    assert seen and seen[0] == "LOW" and not errors.strip(), errors
    for secret in ("SRV-DC-01", "1234567890abcdef", _smtp_type2_b64().decode()):
        assert secret not in seen[1], f"title leaks {secret!r}"
        assert secret not in seen[2], f"evidence leaks {secret!r}"


@needs_pulse
def test_smtp_ntlm_auth_refusal_is_clean_and_sends_no_type1(stub, tmp_path):
    server = _smtp_ntlm_stub(stub, b"250-mail.example\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n",
                             b"504 5.7.4 Unrecognized authentication type\r\n")
    lines, errors = _run_binary_plugin("shapo_smtp_ntlm", "smtp", server, tmp_path)
    assert finding(lines) is None and not errors.strip(), errors
    assert server.received == [_SMTP_EHLO, b"AUTH NTLM\r\n"], server.received


@needs_pulse
def test_smtp_ntlm_truncated_type2_is_an_error_not_a_verdict(stub, tmp_path):
    server = _smtp_ntlm_stub(stub, b"250-mail.example\r\n250-AUTH NTLM\r\n250 HELP\r\n",
                             b"334 \r\n", b"334 " + _smtp_type2_b64()[:40] + b"\r\n")
    lines, errors = _run_binary_plugin("shapo_smtp_ntlm", "smtp", server, tmp_path)
    assert finding(lines) is None and errors.strip()
    assert "truncated" in errors and "Function not found" not in errors, errors


# --------------------------------------------------------------------------
# Phase 9 (docs/pulse-plugin-phases.ru.md): five HTTP checks and eleven
# protocol handshakes. HTTP plugins gate on `service == "http"`; protocol
# plugins gate on the probe service name or an unnamed port.
# --------------------------------------------------------------------------

_NTLM_TYPE2_B64 = "TlRMTVNTUAACAAAAAAAAADgAAAA="

#: (id, plugin, service, method, target, stub reply, expected outcome).
HTTP_PHASE_9_CASES = [
    ("p9-methods-put", "shapo_http_methods", "http", "OPTIONS", "/",
     _http_reply("200 OK", b"Allow: GET, HEAD, PUT, OPTIONS"), "finding"),
    ("p9-methods-connect", "shapo_http_methods", "http", "OPTIONS", "/",
     _http_reply("200 OK", b"Allow: GET, CONNECT"), "finding"),
    ("p9-methods-safe", "shapo_http_methods", "http", "OPTIONS", "/",
     _http_reply("200 OK", b"Allow: GET, HEAD, OPTIONS"), "clean"),
    ("p9-methods-redirect", "shapo_http_methods", "http", "OPTIONS", "/",
     _http_reply("302 Found", b"Location: /elsewhere"), "clean"),
    ("p9-methods-garbage", "shapo_http_methods", "http", "OPTIONS", "/",
     b"NO CARRIER\r\n", "error"),
    ("p9-methods-broken-chunk", "shapo_http_methods", "http", "OPTIONS", "/",
     b"HTTP/1.1 200 OK\r\nAllow: PUT\r\nTransfer-Encoding: chunked\r\n\r\nnot-a-chunk", "finding"),
    ("p9-cookie-missing-httponly", "shapo_http_cookie_flags", "http", "HEAD", "/",
     _http_reply("200 OK", b"Set-Cookie: session=abc123; Path=/"), "finding"),
    ("p9-cookie-has-httponly", "shapo_http_cookie_flags", "http", "HEAD", "/",
     _http_reply("200 OK", b"Set-Cookie: session=abc123; HttpOnly; Path=/"), "clean"),
    ("p9-cookie-no-set-cookie", "shapo_http_cookie_flags", "http", "HEAD", "/",
     _http_reply("200 OK"), "clean"),
    ("p9-cookie-garbage", "shapo_http_cookie_flags", "http", "HEAD", "/",
     b"not http\r\n", "error"),
    ("p9-cors-wildcard-with-creds", "shapo_http_cors", "http", "GET", "/",
     _http_reply("200 OK",
                 b"Access-Control-Allow-Origin: *",
                 b"Access-Control-Allow-Credentials: true"), "finding"),
    ("p9-cors-wildcard-no-creds", "shapo_http_cors", "http", "GET", "/",
     _http_reply("200 OK", b"Access-Control-Allow-Origin: *"), "clean"),
    ("p9-cors-origin-with-creds", "shapo_http_cors", "http", "GET", "/",
     _http_reply("200 OK",
                 b"Access-Control-Allow-Origin: http://shapoclyack.invalid",
                 b"Access-Control-Allow-Credentials: true"), "clean"),
    ("p9-cors-garbage", "shapo_http_cors", "http", "GET", "/",
     b"NO CARRIER\r\n", "error"),
    ("p9-ntlm-type2", "shapo_http_ntlm_info", "http", "GET", "/",
     _http_reply("401 Unauthorized", b"WWW-Authenticate: NTLM " + _NTLM_TYPE2_B64.encode()), "finding"),
    ("p9-ntlm-no-challenge", "shapo_http_ntlm_info", "http", "GET", "/",
     _http_reply("401 Unauthorized"), "clean"),
    ("p9-ntlm-200", "shapo_http_ntlm_info", "http", "GET", "/",
     _http_reply("200 OK"), "clean"),
    ("p9-ntlm-garbage", "shapo_http_ntlm_info", "http", "GET", "/",
     b"NO CARRIER\r\n", "error"),
    ("p9-svn-wc-db", "shapo_http_svn", "http", "GET", "/.svn/wc.db",
     _http_reply("200 OK", b"Content-Type: application/octet-stream",
                 body=b"SQLite format 3\x00"), "finding"),
    ("p9-svn-404", "shapo_http_svn", "http", "GET", "/.svn/wc.db",
     _http_reply("404 Not Found"), "clean"),
    ("p9-svn-other-body", "shapo_http_svn", "http", "GET", "/.svn/wc.db",
     _http_reply("200 OK", body=b"not a database"), "clean"),
    ("p9-svn-garbage", "shapo_http_svn", "http", "GET", "/.svn/wc.db",
     b"NO CARRIER\r\n", "error"),
    ("p9-svn-chunked", "shapo_http_svn", "http", "GET", "/.svn/wc.db",
     _chunked_http_reply("200 OK", body=b"SQLite format 3\x00"), "finding"),
    ("p9-svn-lf-only", "shapo_http_svn", "http", "GET", "/.svn/wc.db",
     b"HTTP/1.1 200 OK\nContent-Length: 16\n\nSQLite format 3\x00", "finding"),
]


@needs_pulse
@pytest.mark.parametrize(("plugin", "service", "method", "target", "reply", "expect"),
                         [case[1:] for case in HTTP_PHASE_9_CASES],
                         ids=[case[0] for case in HTTP_PHASE_9_CASES])
def test_http_plugins_of_phase_9(plugin, service, method, target, reply, expect, stub, tmp_path):
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin(plugin, service, server, tmp_path)
    seen = finding(lines)
    request = server.received[-1]
    assert request.startswith(f"{method} {target} HTTP/1.1\r\n".encode()), request
    assert b"Host: shapoclyack.invalid\r\n" in request
    assert b"Connection: close\r\n" in request
    if expect == "finding":
        assert seen and seen[0] == "LOW" and not errors.strip()
        if plugin == "shapo_http_cookie_flags":
            # The finding names the header. It must not copy the header line or value.
            assert "abc123" not in seen[1] and "abc123" not in seen[2]
            assert "Set-Cookie:" not in seen[2]
            assert "session=" not in seen[2]
    elif expect == "clean":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_smb_os: SMB1 NEGOTIATE returns a Native OS string ----------------


_SMB1_NEGOTIATE = (
    "0000008eff534d4272000000001801000000000000000000000000000000000000000000006b00"
    "025043204e4554574f524b2050524f4752414d20312e3000024d4943524f534f4654204e455457"
    "4f524b5320312e303300024d4943524f534f4654204e4554574f524b5320332e3000024c414e4d"
    "414e312e3000024c4d312e325830303200024e54204c4d20302e313200"
)


def _smb1_negotiate_response(
    os: bytes | None = b"Windows Server",
    *,
    capabilities: bytes = b"\x00\x00\x00\x00",
    challenge_len: int = 8,
) -> bytes:
    """SMB1 NEGOTIATE response. Word count 17, little-endian fields.

    ``os is None`` sends only the challenge, so ByteCount is too small for a
    Native OS string. Capabilities are the four bytes at packet offset 56.
    """
    word_params = bytes([
        0x11,  # word count
        0x00, 0x00,  # dialect index
        0x00,  # security mode
        0x00, 0x00,  # max mpx
        0x00, 0x00,  # max vc
        0x00, 0x00, 0x00, 0x00,  # max buffer
        0x00, 0x00, 0x00, 0x00,  # max raw
        0x00, 0x00, 0x00, 0x00,  # session key
    ]) + capabilities + bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # system time
        0x00, 0x00,  # timezone
        challenge_len,
    ])
    challenge = b"\x00" * challenge_len
    if os is None:
        data = challenge
        byte_count = len(challenge)
    else:
        data = challenge + os + b"\x00" + b"\x00"
        byte_count = len(data)
    body = word_params + byte_count.to_bytes(2, "little") + data
    smb_header = b"\xffSMB\x72" + b"\x00" * 27  # 32 bytes total
    msg = smb_header + body
    return len(msg).to_bytes(4, "big") + msg


@needs_pulse
@pytest.mark.parametrize("case", ["native-os", "extended-security", "no-os", "empty", "truncated"])
def test_smb_os_reports_native_os_or_raises(case, stub, tmp_path):
    if case == "native-os":
        reply = _smb1_negotiate_response()
    elif case == "extended-security":
        reply = _smb1_negotiate_response(capabilities=b"\x00\x00\x00\x80")
    elif case == "no-os":
        reply = _smb1_negotiate_response(os=None)
    elif case == "empty":
        reply = b""
    else:
        reply = _smb1_negotiate_response()[:40]
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_smb_os", "smb", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == _SMB1_NEGOTIATE
    if case == "native-os":
        assert seen and seen[0] == "LOW" and not errors.strip()
        assert "Windows" not in seen[1] and "Windows" not in seen[2]
    elif case in {"extended-security", "no-os"}:
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_cassandra_ready: CQL STARTUP -> READY is a finding ---------------


def _cql_frame(opcode: int, body: bytes = b"") -> bytes:
    # v3 header: version, flags, 2-byte stream, opcode, 4-byte body length.
    return bytes([0x83, 0x00, 0x00, 0x00, opcode]) + len(body).to_bytes(4, "big") + body


@needs_pulse
@pytest.mark.parametrize("case", ["ready", "authenticate", "truncated"])
def test_cassandra_ready_parses_cql_startup_reply(case, stub, tmp_path):
    if case == "ready":
        reply = _cql_frame(0x02)
    elif case == "authenticate":
        reply = _cql_frame(0x03)
    else:
        reply = _cql_frame(0x02)[:6]
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_cassandra_ready", "cassandra", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == (
        "0300000001000000160001000b43514c5f56455253494f4e0005332e302e30"
    )
    if case == "ready":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif case == "authenticate":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_jdwp_handshake: echoed handshake is a finding --------------------


@needs_pulse
@pytest.mark.parametrize("case", ["echo", "other", "empty"])
def test_jdwp_handshake_reports_echo_or_raises(case, stub, tmp_path):
    if case == "echo":
        reply = b"JDWP-Handshake"
    elif case == "other":
        reply = b"HTTP/1.1 400\r\n"
    else:
        reply = b""
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_jdwp_handshake", "jdwp", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1] == b"JDWP-Handshake"
    if case == "echo":
        assert seen and seen[0] == "LOW" and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_mssql_prelogin: parsed TDS PRELOGIN response is a finding --------


@needs_pulse
@pytest.mark.parametrize("case", ["prelogin", "empty", "short"])
def test_mssql_prelogin_parses_tds_reply(case, stub, tmp_path):
    if case == "prelogin":
        body = bytes.fromhex("00001e000000000600060001020007000103000804000c0001ff0a00000400000200")
        reply = bytes([0x04, 0x01]) + (len(body) + 4).to_bytes(2, "big") + body
    elif case == "empty":
        reply = b""
    else:
        reply = b"\x04\x01\x00\x08\x00\x00"
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_mssql_prelogin", "mssql", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == (
        "1201002f0000010000001a00060100200001020021000103002200040400260001ff00000000000002000000000000"
    )
    if case == "prelogin":
        assert seen and seen[0] == "LOW" and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_oracle_tns_version: Accept containing VERSION is a finding -------


@needs_pulse
@pytest.mark.parametrize("case", ["version", "refuse", "accept-only", "truncated"])
def test_oracle_tns_version_looks_for_version_in_accept(case, stub, tmp_path):
    if case == "version":
        body = b"(DESCRIPTION=(ERR=0)(VSNNUM=0)(VERSION=0))"
        reply = (len(body) + 8).to_bytes(2, "big") + b"\x00\x00\x02\x00\x00\x00" + body
    elif case == "refuse":
        body = b"(DESCRIPTION=(ERR=12504)(VSNNUM=186646784))"
        reply = (len(body) + 8).to_bytes(2, "big") + b"\x00\x00\x04\x00\x00\x00" + body
    elif case == "accept-only":
        body = b"(DESCRIPTION=(ERR=0))"
        reply = (len(body) + 8).to_bytes(2, "big") + b"\x00\x00\x02\x00\x00\x00" + body
    else:
        reply = b"\x00\x08\x00\x00\x02\x00"
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_oracle_tns_version", "oracle", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == (
        "005a0000010000000136012c000008007fff7f08000000010020003a000000000000000000000000"
        "0000000034e600000001000000000000000028434f4e4e4543545f444154413d28434f4d4d414e443d"
        "76657273696f6e2929"
    )
    if case in {"version", "refuse"}:
        assert seen and seen[0] == "LOW" and not errors.strip()
        assert "186646784" not in seen[1] and "186646784" not in seen[2]
        assert "VSNNUM" not in seen[2]
    elif case == "accept-only":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_modbus_identity: function 43 read-device-identification ---------


@needs_pulse
@pytest.mark.parametrize("case", ["identity", "exception", "truncated"])
def test_modbus_identity_parses_function_43_or_exception(case, stub, tmp_path):
    if case == "identity":
        reply = bytes.fromhex("000100000005002b0e0101")
    elif case == "exception":
        reply = bytes.fromhex("00010000000300ab01")
    else:
        reply = bytes.fromhex("000100000004002b0e")
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_modbus_identity", "modbus", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == "000100000005002b0e0100"
    if case == "identity":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif case == "exception":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_rmi_registry: JRMP protocol-ok marker is a finding ---------------


@needs_pulse
@pytest.mark.parametrize("case", ["ack", "nack", "other"])
def test_rmi_registry_reports_protocol_ok(case, stub, tmp_path):
    if case == "ack":
        reply = b"\x4e"
    elif case == "nack":
        reply = b"\x4f"
    else:
        reply = b"\x00"
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_rmi_registry", "rmi", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == "4a524d4900024b"
    if case == "ack":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif case == "nack":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_epmd_names: names reply containing a node entry is a finding -----


@needs_pulse
@pytest.mark.parametrize("case", ["node", "empty", "truncated"])
def test_epmd_names_parses_node_list(case, stub, tmp_path):
    if case == "node":
        reply = b"\x00\x00\x11\x11" + b"name secretnode at port 9999\n"
    elif case == "empty":
        reply = b"\x00\x00\x00\x00"
    else:
        reply = b"\x00\x00"
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_epmd_names", "epmd", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == "00016e"
    if case == "node":
        assert seen and seen[0] == "LOW" and not errors.strip()
        assert "secretnode" not in seen[1] and "secretnode" not in seen[2]
    elif case == "empty":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_iscsi_text: Login Response to an unauthenticated login ----------


def _iscsi_pdu(opcode: int, status_class: int = 0) -> bytes:
    packet = bytearray(48)
    packet[0] = opcode
    packet[36] = status_class
    return bytes(packet)


@needs_pulse
@pytest.mark.parametrize("case", ["login-response", "reject", "status-class", "truncated"])
def test_iscsi_text_parses_login_response(case, stub, tmp_path):
    if case == "login-response":
        reply = _iscsi_pdu(0x23)
    elif case == "reject":
        reply = _iscsi_pdu(0x3f)
    elif case == "status-class":
        reply = _iscsi_pdu(0x23, 0x02)
    else:
        reply = bytes.fromhex("23" + "00" * 30)
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_iscsi_text", "iscsi", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == (
        "430000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    if case == "login-response":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif case in {"reject", "status-class"}:
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_nbd_hello: INIT_PASSWD magic after new-style handshake ----------


@needs_pulse
@pytest.mark.parametrize("case", ["init-passwd", "other", "truncated"])
def test_nbd_hello_reports_init_passwd_magic(case, stub, tmp_path):
    if case == "init-passwd":
        reply = b"NBDMAGIC" + b"\x00" * 8 + bytes.fromhex("00000000")
    elif case == "other":
        reply = b"HTTP/1.1"
    else:
        reply = b"NBDMAG"
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_nbd_hello", "nbd", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == "4e42444d4147494349484156454f505400000001"
    if case == "init-passwd":
        assert seen and seen[0] == "LOW" and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_drda_exchange: EXCSATRD is a finding -----------------------------


@needs_pulse
@pytest.mark.parametrize("case", ["excsatrd", "other", "truncated"])
def test_drda_exchange_parses_excsatrd(case, stub, tmp_path):
    if case == "excsatrd":
        reply = bytes.fromhex("0012d0020001000c14430008116d44423258")
    elif case == "other":
        reply = bytes.fromhex("0012d0020001000c10410008116d44423258")
    else:
        reply = bytes.fromhex("0010d00100011440")
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_drda_exchange", "drda", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == (
        "0032d0010001002c10410004115e0004116d0004115a001814041403000724070008240f0008144000081474000800041147"
    )
    if case == "excsatrd":
        assert seen and seen[0] == "LOW" and not errors.strip()
        assert "DB2X" not in seen[1] and "DB2X" not in seen[2]
    elif case == "other":
        assert seen is None and not errors.strip()
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors


# --- shapo_giop_locate: LocateReply is a finding ----------------------------


@needs_pulse
@pytest.mark.parametrize("case", ["locate", "not-locate", "truncated"])
def test_giop_locate_parses_locate_reply(case, stub, tmp_path):
    if case == "locate":
        reply = bytes.fromhex("47494f5001000004000000080000000100000000")
    elif case == "not-locate":
        reply = bytes.fromhex("47494f5001000003000000080000000100000000")
    else:
        reply = bytes.fromhex("47494f5001000004")
    server = stub(b"", lambda _request: reply)
    lines, errors = _run_binary_plugin("shapo_giop_locate", "giop", server, tmp_path)
    seen = finding(lines)
    assert server.received[-1].hex() == "47494f5001000003000000080000000100000000"
    if case == "locate":
        assert seen and seen[0] == "LOW" and not errors.strip()
    elif case == "not-locate":
        assert seen is None and errors.strip() and "Function not found" not in errors
    else:
        assert seen is None and errors.strip() and "Function not found" not in errors
