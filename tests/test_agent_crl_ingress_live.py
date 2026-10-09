"""Opt-in acceptance against a real ingress-nginx in a disposable cluster.

OCTO_CRL_TEST_KUBECONFIG and OCTO_CRL_TEST_INGRESS_PORT must be explicit.
Creates/deletes only its own random namespace; the controller is preinstalled.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import ssl
import socket
import subprocess
import time
import uuid

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from api.services import agent_crl
from tests.mtls_pki import CA
from tests.test_agent_crl import exporter, record

KUBECONFIG = os.environ.get("OCTO_CRL_TEST_KUBECONFIG", "")
PORT = os.environ.get("OCTO_CRL_TEST_INGRESS_PORT", "")
pytestmark = pytest.mark.skipif(
    not KUBECONFIG or not PORT,
    reason="Explicit disposable ingress test cluster not set",
)


def test_ingress_reloads_crl_and_rejects_revoked_certificate_before_upstream(
    tmp_path, monkeypatch
):
    namespace = "crl-" + uuid.uuid4().hex[:10]
    hostname = namespace + ".localhost"

    def kube(*args, body=None):
        result = subprocess.run(
            ["kubectl", "--kubeconfig", KUBECONFIG, *args],
            input=json.dumps(body) if body is not None else None,
            text=True,
            capture_output=True,
            timeout=80,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    ca = CA()
    stolen = ca.sensor("default", "sensor-a")
    healthy = ca.sensor("default", "sensor-b")
    server = ca._issue(
        hostname, [x509.DNSName(hostname)], ExtendedKeyUsageOID.SERVER_AUTH
    )  # noqa: SLF001
    ca_path, _ = ca.write(tmp_path)
    rows = []
    settings = exporter(tmp_path, monkeypatch, ca, rows)
    initial = agent_crl.export(settings)

    def encode(data):
        return base64.b64encode(data).decode()

    backend = """from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print('BACKEND ' + self.path, flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'upstream')
HTTPServer(('0.0.0.0',8080), Handler).serve_forever()
"""
    resources = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}},
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "client-ca", "namespace": namespace},
            "data": {"ca.crt": encode(ca.pem.encode()), "ca.crl": encode(initial.pem)},
        },
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "type": "kubernetes.io/tls",
            "metadata": {"name": "server", "namespace": namespace},
            "data": {
                "tls.crt": encode(server.pem.encode()),
                "tls.key": encode(server.key_pem),
            },
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "backend", "namespace": namespace},
            "spec": {
                "selector": {"matchLabels": {"app": "crl-backend"}},
                "template": {
                    "metadata": {"labels": {"app": "crl-backend"}},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "containers": [
                            {
                                "name": "backend",
                                "image": "python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016",
                                "command": ["python", "-u", "-c", backend],
                                "ports": [{"containerPort": 8080}],
                            }
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "backend", "namespace": namespace},
            "spec": {
                "selector": {"app": "crl-backend"},
                "ports": [{"port": 8080, "targetPort": 8080}],
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "name": "api",
                "namespace": namespace,
                "annotations": {
                    "nginx.ingress.kubernetes.io/auth-tls-secret": namespace
                    + "/client-ca",
                    "nginx.ingress.kubernetes.io/auth-tls-verify-client": "optional",
                    "nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream": "true",
                },
            },
            "spec": {
                "ingressClassName": "nginx",
                "tls": [{"hosts": [hostname], "secretName": "server"}],
                "rules": [
                    {
                        "host": hostname,
                        "http": {
                            "paths": [
                                {
                                    "path": "/",
                                    "pathType": "Prefix",
                                    "backend": {
                                        "service": {
                                            "name": "backend",
                                            "port": {"number": 8080},
                                        }
                                    },
                                }
                            ]
                        },
                    }
                ],
            },
        },
    ]
    stolen_pair = stolen.write(tmp_path, "stolen")
    healthy_pair = healthy.write(tmp_path, "healthy")

    def request(path, pair=None, version=None):
        context = ssl.create_default_context(cafile=str(ca_path))
        if pair:
            context.load_cert_chain(*pair)
        if version:
            context.minimum_version = context.maximum_version = version
        connection = http.client.HTTPSConnection(
            hostname, int(PORT), context=context, timeout=5
        )
        connection._create_connection = lambda address, timeout, *args: (
            socket.create_connection(("127.0.0.1", int(PORT)), timeout)
        )
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def eventually(pair, expected):
        deadline = time.monotonic() + 60
        answer = None
        while time.monotonic() < deadline:
            try:
                answer = request("/reload-probe", pair)
                if answer[0] == expected:
                    return
            except (ssl.SSLError, OSError):
                pass
            time.sleep(0.5)
        raise AssertionError(f"Ingress did not reach HTTP {expected}: {answer}")

    # Save a TLS 1.2 session while the certificate is valid. Reusing it must
    # not preserve its old verification verdict after a CRL reload.
    session_context = ssl.create_default_context(cafile=str(ca_path))
    session_context.minimum_version = session_context.maximum_version = (
        ssl.TLSVersion.TLSv1_2
    )
    session_context.load_cert_chain(*stolen_pair)

    def session_request(path, session=None):
        with socket.create_connection(("127.0.0.1", int(PORT)), timeout=5) as raw:
            with session_context.wrap_socket(
                raw, server_hostname=hostname, session=session
            ) as tls:
                tls.sendall(
                    f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode()
                )
                data = b""
                while block := tls.recv(4096):
                    data += block
                return int(data.split(b" ", 2)[1]), tls.session, tls.session_reused

    try:
        kube(
            "apply",
            "-f",
            "-",
            body={"apiVersion": "v1", "kind": "List", "items": resources},
        )
        kube(
            "-n", namespace, "rollout", "status", "deployment/backend", "--timeout=60s"
        )
        eventually(stolen_pair, 200)
        assert request("/healthy-before", healthy_pair)[0] == 200
        status, old_session, _ = session_request("/session-before")
        assert status == 200
        rows.append(record(stolen))
        revoked = agent_crl.export(settings)
        kube(
            "-n",
            namespace,
            "patch",
            "secret",
            "client-ca",
            "--type=merge",
            "--patch-file=/dev/stdin",
            body={"data": {"ca.crl": encode(revoked.pem)}},
        )
        eventually(stolen_pair, 400)
        status, _, reused = session_request("/revoked-after-resumption", old_session)
        assert status == 400 and not reused
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            status, body = request(
                "/revoked-after-" + version.name, stolen_pair, version
            )
            assert status == 400 and "SSL certificate error" in body
            assert (
                request("/healthy-after-" + version.name, healthy_pair, version)[0]
                == 200
            )
        assert request("/console-no-certificate")[0] == 200
        logs = kube("-n", namespace, "logs", "deployment/backend")
        assert "BACKEND /healthy-after-" in logs
        assert "BACKEND /revoked-after-" not in logs
        controller_logs = kube(
            "-n", "ingress-nginx", "logs", "deployment/ingress-nginx-controller"
        )
        assert "certificate revoked" in controller_logs
        print(
            "Ingress CRL acceptance: revoked=400 before upstream, healthy=200, console=200; TLS1.2+1.3"
        )
    finally:
        kube("delete", "namespace", namespace, "--ignore-not-found", "--wait=false")
