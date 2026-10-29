"""Protocol boundaries for reimplemented Nuclei template checks."""
import pytest

from scanner.pipeline import pulse_plugins
from tests.test_pulse_plugins_files import Stub, _run_binary_plugin, finding, needs_pulse


@pytest.fixture
def server_stub():
    servers = []

    def make(greeting, reply):
        server = Stub(greeting, reply)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


@pytest.mark.parametrize("plugin,service,port,expected", [
    ("shapo_rsync_modules", "rsync", 18730, True),
    ("shapo_rsync_modules", "unknown", 873, True),
    ("shapo_rsync_modules", "http", 873, False),
    ("shapo_zookeeper_envi", "zookeeper", 12181, True),
    ("shapo_zookeeper_envi", "unknown", 2181, True),
    ("shapo_zookeeper_envi", "http", 2181, False),
])
def test_applicability(plugin, service, port, expected):
    assert pulse_plugins.applies(plugin, service=service, port=port, banner="") is expected


@needs_pulse
@pytest.mark.parametrize("response,verdict", [
    (b"@RSYNCD: 29\npublic\tpublic files\n@RSYNCD: EXIT\n", "finding"),
    (b"@RSYNCD: 29\n@RSYNCD: EXIT\n", "clean"),
    (b"@RSYNCD: 29\npublic\n", "error"),
    (b"@RSYNCD: 29\n@ERROR: denied\n@RSYNCD: EXIT\n", "error"),
    (b"HTTP/1.1 200 OK\r\n\r\n", "error"),
])
def test_rsync(response, verdict, server_stub, tmp_path):
    server = server_stub(b"", lambda _: response)
    lines, errors = _run_binary_plugin("shapo_rsync_modules", "rsync", server, tmp_path)
    assert (finding(lines) is not None) == (verdict == "finding")
    assert bool(errors.strip()) == (verdict == "error")
    assert server.received == [b"@RSYNCD: 29.0\n#list\n"]


@needs_pulse
@pytest.mark.parametrize("response,verdict", [
    (b"Environment:\nzookeeper.version=3.9.3\njava.version=17\n", "finding"),
    (b"envi is not executed because it is not in the whitelist.\n", "error"),
    (b"Environment:\nzookeeper.version=3.9.3", "error"),
    (b"Environment:\nother=zookeeper.version=3.9.3\n", "error"),
])
def test_zookeeper(response, verdict, server_stub, tmp_path):
    server = server_stub(b"", lambda _: response)
    lines, errors = _run_binary_plugin("shapo_zookeeper_envi", "zookeeper", server, tmp_path)
    assert (finding(lines) is not None) == (verdict == "finding")
    assert bool(errors.strip()) == (verdict == "error")
    assert server.received == [b"envi"]
