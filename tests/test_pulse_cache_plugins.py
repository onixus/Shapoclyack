"""Exercise cache probes through Pulse against controlled TCP endpoints."""
import os
import re
import shutil
import socket
import subprocess
import threading

import pytest

from scanner.pipeline import pulse_plugins

PULSE = os.environ.get("OCTO_PULSE_BIN") or shutil.which("pulse")


@pytest.mark.parametrize(
    ("plugin", "service", "port", "expected"),
    [("shapo_redis_info", "redis", 16379, True),
     ("shapo_redis_info", "unknown", 6379, True),
     ("shapo_redis_info", "http", 6379, False),
     ("shapo_memcached_stats", "memcached", 12345, True),
     ("shapo_memcached_stats", "unknown", 11211, True),
     ("shapo_memcached_stats", "http", 11211, False)],
)
def test_cache_plugin_applicability(plugin, service, port, expected):
    assert pulse_plugins.applies(plugin, service=service, port=port, banner="") is expected


@pytest.mark.skipif(not PULSE, reason="Pulse binary unavailable")
@pytest.mark.parametrize(
    ("name", "port", "response", "verdict"),
    [
        ("redis_info", 6379, b"$31\r\n# Server\r\nredis_version:7.2.0\r\n\r\n", "finding"),
        ("redis_info", 6379, b"-NOAUTH Authentication required.\r\n", "clean"),
        ("redis_info", 6379, b"-NOPERM this user has no permissions\r\n", "clean"),
        ("redis_info", 6379, b"$99\r\n# Server\r\nredis_version:7.2.0\r\n", "error"),
        ("redis_info", 6379, b"-NOAUTH truncated", "error"),
        ("redis_info", 6379, b"+PONG\r\n", "error"),
        ("memcached_stats", 11211, b"STAT pid 12\r\nSTAT version 1.6.1\r\nEND\r\n", "finding"),
        ("memcached_stats", 11211, b"STAT version 1.6.1\r\n", "error"),
        ("memcached_stats", 11211, b"ERROR\r\n", "error"),
        ("memcached_stats", 11211, b"STAT untrusted value\r\nEND\r\n", "error"),
    ],
)
def test_cache_probes(name, port, response, verdict):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", port))
    except OSError:
        listener.close()
        pytest.skip(f"test port {port} unavailable")
    listener.listen(4)
    listener.settimeout(0.2)
    stop = threading.Event()
    received = []

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2)
                try:
                    data = conn.recv(4096)
                    if data:
                        received.append(data)
                        conn.sendall(response)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [PULSE, "plugin", "run", str(pulse_plugins.PLUGINS_DIR / f"shapo_{name}.rhai"), f"127.0.0.1:{port}"],
            capture_output=True, text=True, timeout=15, check=False,
        )
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=3)
    assert not thread.is_alive()
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    assert len(received) == 1
    assert received[0] == (b"*2\r\n$4\r\nINFO\r\n$6\r\nSERVER\r\n" if name == "redis_info" else b"stats\r\nquit\r\n")
    if verdict == "finding":
        assert result.returncode == 0 and "FINDING" in output, output
    elif verdict == "clean":
        assert result.returncode == 0 and "FINDING" not in output and "plugin error" not in output, output
    else:
        assert "FINDING" not in output and "plugin error" in output, output
