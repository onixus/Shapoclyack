"""Native read-only protocol dialogues, with synthetic loopback peers only."""
from __future__ import annotations

import contextlib
import os
import re
import shutil
import socket
import struct
import subprocess
import threading

import pytest
from scanner.pipeline import pulse_plugins

PULSE = os.environ.get("OCTO_PULSE_BIN") or shutil.which("pulse")
needs_pulse = pytest.mark.skipif(not PULSE, reason="Pulse candidate required")


def receive(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError
        data += part
    return data


def smb_frame(sock):
    header = receive(sock, 4)
    assert header[0] == 0
    size = int.from_bytes(header[1:], "big")
    assert 32 <= size <= 4096
    return receive(sock, size)


def send_smb(sock, body):
    sock.sendall(len(body).to_bytes(4, "big") + body)


def smb1_reply(request, status=0, words=b"", uid=0, tid=0):
    response = bytearray(request[:32])
    response[9] |= 0x80
    struct.pack_into("<I", response, 5, status)
    struct.pack_into("<HHH", response, 24, tid, 0x4C50, uid)
    return response + bytes([len(words) // 2]) + words + b"\0\0"


@contextlib.contextmanager
def peer(handler):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.1)
    port = listener.getsockname()[1]
    stop = threading.Event()
    failures = []

    def worker():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(3)
                try:
                    handler(connection)
                except (EOFError, ConnectionResetError, BrokenPipeError):
                    pass  # standalone banner-only connection, or bounded close
                except Exception as exc:
                    failures.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        listener.close()
        thread.join(4)
        assert not failures, failures
        assert not thread.is_alive()


def run_plugin(name, service, port, tmp_path):
    source = (pulse_plugins.PLUGINS_DIR / f"{name}.rhai").read_text()
    source = source.replace("fn run() {", f'fn run() {{ let service = "{service}";', 1)
    path = tmp_path / f"{name}.rhai"
    path.write_text(source)
    result = subprocess.run([PULSE, "plugin", "run", str(path), f"127.0.0.1:{port}"], capture_output=True, text=True, timeout=35)
    assert result.returncode == 0 or (result.returncode == 1 and "plugin error" in result.stderr), result.stderr
    return re.sub(r"\x1b\[[0-9;]*m", "", result.stdout), result.stderr


@needs_pulse
@pytest.mark.parametrize("status, indicator", [(0xC0000205, True), (0xC0000022, False), (0xC0000008, False), (0, False)])
def test_ms17_010_status_is_separate_and_non_indicators_are_unknown(status, indicator, tmp_path):
    commands = []

    def handler(sock):
        request = smb_frame(sock)
        commands.append(request[4])
        assert request[4] == 0x72
        words = bytearray(34)
        words[2] = 3
        send_smb(sock, smb1_reply(request, words=words))
        request = smb_frame(sock)
        commands.append(request[4])
        assert request[4] == 0x73 and request[32] == 13
        send_smb(sock, smb1_reply(request, words=b"\xff\0\0\0\1\0", uid=42))
        request = smb_frame(sock)
        commands.append(request[4])
        assert request[4] == 0x75 and b"IPC$\0" in request
        send_smb(sock, smb1_reply(request, words=b"\xff\0\0\0\0\0", uid=42, tid=77))
        request = smb_frame(sock)
        commands.append(request[4])
        assert request[4] == 0x25
        assert struct.unpack_from("<H", request, 24)[0] == 77
        assert struct.unpack_from("<H", request, 28)[0] == 42
        assert request[61:65] == b"\x23\0\0\0"  # FID0 PeekNamedPipe
        send_smb(sock, smb1_reply(request, status=status, uid=42, tid=77))

    with peer(handler) as port:
        stdout, stderr = run_plugin("shapo_ms17_010", "smb", port, tmp_path)
    assert commands == [0x72, 0x73, 0x75, 0x25]
    assert ("SMB MS17-010 status indication observed" in stdout) is indicator
    if indicator:
        assert not stderr.strip()
    else:
        assert "assessment unknown" in stderr
        assert "non_indicator_status_observed" in stderr or "unknown_status" in stderr


@needs_pulse
def test_ms17_session_denial_never_becomes_a_clean_receipt(tmp_path):
    def handler(sock):
        request = smb_frame(sock)
        words = bytearray(34)
        words[2] = 3
        send_smb(sock, smb1_reply(request, words=words))
        request = smb_frame(sock)
        assert request[4] == 0x73
        send_smb(sock, smb1_reply(request, status=0xC0000022))

    with peer(handler) as port:
        stdout, stderr = run_plugin("shapo_ms17_010", "smb", port, tmp_path)
    assert "SMB MS17-010 status indication observed" not in stdout
    assert "assessment unknown" in stderr and "anonymous session refused" in stderr


@needs_pulse
@pytest.mark.parametrize("malformed_311", [False, True])
def test_smb_dialects_include_3x_and_incomplete_context_is_retained_as_error(malformed_311, tmp_path):
    observed = []

    def handler(sock):
        request = smb_frame(sock)
        if request.startswith(b"\xffSMB"):
            send_smb(sock, smb1_reply(request, words=b"\xff\xff"))
            return
        assert request.startswith(b"\xfeSMB")
        dialect = struct.unpack_from("<H", request, 100)[0]
        observed.append(dialect)
        response = bytearray(128)
        response[:4] = b"\xfeSMB"
        struct.pack_into("<H", response, 4, 64)
        struct.pack_into("<I", response, 16, 1)
        struct.pack_into("<HHH", response, 64, 65, 3, dialect)
        if dialect == 0x0311:
            assert struct.unpack_from("<I", request, 92)[0] == 104
            assert request[104:108] == b"\1\0\x26\0"
            if not malformed_311:
                struct.pack_into("<H", response, 70, 1)
                struct.pack_into("<I", response, 124, 128)
                response.extend(b"\1\0\6\0\0\0\0\0\1\0\0\0\1\0")
        send_smb(sock, response)

    with peer(handler) as port:
        stdout, stderr = run_plugin("shapo_smb_protocols", "smb", port, tmp_path)
    assert observed == [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    assert "3.0.2" in stdout and "3.0" in stdout
    if malformed_311:
        assert "3.1.1" in stderr and "negotiate contexts" in stderr
    else:
        assert "3.1.1" in stdout and not stderr.strip()


@needs_pulse
@pytest.mark.parametrize("security_types, finding", [(bytes([1, 2, 19]), True), (bytes([2, 19]), False)])
def test_vnc_security_advertisement_does_not_start_a_desktop(security_types, finding, tmp_path):
    extra = []

    def handler(sock):
        sock.sendall(b"RFB 003.008\n")
        version = receive(sock, 12)
        assert version == b"RFB 003.008\n"
        sock.sendall(bytes([len(security_types)]) + security_types)
        extra.append(sock.recv(1))

    with peer(handler) as port:
        stdout, stderr = run_plugin("shapo_vnc_security", "vnc", port, tmp_path)
    assert ("VNC advertises security type None" in stdout) is finding
    assert extra == [b""] and not stderr.strip()


@needs_pulse
def test_actual_ms17_unknown_stderr_invalidates_verification_after_positive_same_hash(tmp_path):
    import hashlib
    import json
    from datetime import UTC, datetime
    from api.services import verification_coverage as vc
    from api.services import vulnerabilities as vulns
    from scanner.pipeline import pulse_progress

    statuses = [0xC0000205, 0xC0000022]

    def handler(sock):
        request = smb_frame(sock)
        words = bytearray(34)
        words[2] = 3
        send_smb(sock, smb1_reply(request, words=words))
        request = smb_frame(sock)
        send_smb(sock, smb1_reply(request, words=b"\xff\0\0\0\1\0", uid=42))
        request = smb_frame(sock)
        send_smb(sock, smb1_reply(request, words=b"\xff\0\0\0\0\0", uid=42, tid=77))
        request = smb_frame(sock)
        send_smb(sock, smb1_reply(request, status=statuses.pop(0), uid=42, tid=77))

    with peer(handler) as port:
        positive, errors = run_plugin("shapo_ms17_010", "smb", port, tmp_path)
        assert "SMB MS17-010 status indication observed" in positive and not errors.strip()
        sha = "sha256:" + hashlib.sha256((tmp_path / "shapo_ms17_010.rhai").read_bytes()).hexdigest()
        (detector,) = vulns._observed_detectors(
            {"host": "127.0.0.1", "source": "pulse-plugin", "script_id": "pulse-plugin:shapo_ms17_010", "protocol": "tcp", "ruleset_version": sha},
            port=str(port), run_id="positive", now=datetime.now(UTC),
        )
        private = tmp_path / "sandbox"
        private.mkdir()
        service_db = private / "services.tsv"
        service_db.write_text(f"smb {port}/tcp\n")
        scan = subprocess.run(
            [PULSE, "127.0.0.1", "-p", str(port), "-f", "json", "-q", "--no-nmap-data", "--services-db", str(service_db), "--script-dir", str(tmp_path)],
            cwd=private, env={**os.environ, "HOME": str(private)},
            capture_output=True, text=True, timeout=35,
        )
        assert scan.returncode == 0, scan.stderr
        scanned = json.loads(scan.stdout)
        assert pulse_progress.completed_hosts({"127.0.0.1": [port]}, scanned, scan.returncode) == {"127.0.0.1"}
        assert not any("MS17-010 status indication" in finding.get("title", "") for finding in scanned.get("cves", []))
        parsed = pulse_plugins.parse_plugin_errors(scan.stderr)
        assert parsed and parsed[0]["plugin"] == "shapo_ms17_010"
        assert "assessment unknown" in parsed[0]["message"]
        assert sha == "sha256:" + hashlib.sha256((tmp_path / "shapo_ms17_010.rhai").read_bytes()).hexdigest()
    raw = {
        "open": [{"ip": "127.0.0.1", "port": port, "service": "smb", "protocol": "tcp"}],
        "completion": pulse_progress.completion_manifest({"127.0.0.1": [port]}),
        "adapter": {"plugins": {
            "loaded": [{"name": "shapo_ms17_010", "sha256": sha.removeprefix("sha256:")}],
            "errors": [{**error, "hosts": ["127.0.0.1"], "ports": [port]} for error in parsed],
        }},
    }
    (tmp_path / "pulse").mkdir()
    (tmp_path / "pulse" / "raw.json").write_text(json.dumps(raw))
    coverage = vc.RunCoverage(tmp_path)
    gaps = coverage.gaps([detector], port=str(port), asset_hosts={"127.0.0.1"})
    assert [gap["reason"] for gap in gaps] == ["plugin_error"]
    assert statuses == []  # same completed endpoint, detector/hash, and service

@needs_pulse
@pytest.mark.parametrize("kind", ["error_truncated", "error_count", "mode0", "mode2", "async", "compound"])
def test_smb_malformed_negotiation_never_credits_dialect_refusal_or_signing(kind, tmp_path):
    def handler(sock):
        request = smb_frame(sock)
        if request.startswith(b"\xffSMB"):
            send_smb(sock, smb1_reply(request, words=b"\xff\xff"))
            return
        response = bytearray(128)
        response[:4] = b"\xfeSMB"
        struct.pack_into("<H", response, 4, 64)
        struct.pack_into("<I", response, 16, 3 if kind == "async" else 1)
        struct.pack_into("<I", response, 20, 64 if kind == "compound" else 0)
        dialect = struct.unpack_from("<H", request, 100)[0]
        struct.pack_into("<HHH", response, 64, 65, 0 if kind == "mode0" else 2 if kind == "mode2" else 3, dialect)
        if kind.startswith("error"):
            response = response[:64 if kind == "error_truncated" else 72]
            struct.pack_into("<I", response, 8, 0xC00000BB)
            if len(response) == 72:
                struct.pack_into("<H", response, 64, 9)
                struct.pack_into("<I", response, 68, 7)
        send_smb(sock, response)
    with peer(handler) as port:
        stdout, stderr = run_plugin("shapo_smb_protocols", "smb", port, tmp_path)
    assert "plugin error" in stderr and "No findings" not in stdout
