"""Platform-only CRL publisher: ``python -m api.agent_crl --help``."""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import tempfile
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

from api.core.client_cert import load_ca_bundle, load_pem_certificate
from api.core.crl import validate_bundle
from api.services.agent_crl import export
from api.settings import Settings


def write_atomic(path: Path, data: bytes) -> None:
    """Do not truncate a working CRL when generation or publication fails."""
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def publish_secret(namespace: str, secret: str, pem: bytes) -> None:
    """Patch only ca.crl in an existing Secret using narrowly scoped pod RBAC.

    Keep ca.crt and all metadata; never read/print a Secret or private key. This
    publisher runs in cluster; the Kubernetes service account trust is mandatory.
    """
    service_account = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    if ":" in host:
        host = f"[{host}]"
    endpoint = f"https://{host}:{port}/api/v1/namespaces/{quote(namespace, safe='')}/secrets/{quote(secret, safe='')}"
    body = json.dumps(
        {"data": {"ca.crl": base64.b64encode(pem).decode("ascii")}}
    ).encode()
    request = Request(
        endpoint,
        data=body,
        method="PATCH",
        headers={
            "Authorization": "Bearer "
            + (service_account / "token").read_text().strip(),
            "Content-Type": "application/merge-patch+json",
        },
    )
    context = ssl.create_default_context(cafile=str(service_account / "ca.crt"))
    with urlopen(request, context=context, timeout=20) as response:  # noqa: S310 - fixed Kubernetes HTTPS endpoint
        if response.status != 200:
            raise RuntimeError(f"Kubernetes CRL patch returned HTTP {response.status}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--secret",
        help="Existing Kubernetes Secret as namespace/name; patch ca.crl only",
    )
    parser.add_argument(
        "--issuer-cert", default=os.environ.get("OCTO_AGENT_MTLS_ISSUER_CERT", "")
    )
    parser.add_argument(
        "--issuer-key", default=os.environ.get("OCTO_AGENT_MTLS_ISSUER_KEY", "")
    )
    parser.add_argument(
        "--certificate",
        type=Path,
        action="append",
        default=[],
        help="Explicitly approve this certificate for TLS revocation; also supplies legacy PEM",
    )
    parser.add_argument("--lifetime-seconds", type=int, default=3600)
    parser.add_argument(
        "--append-crl",
        type=Path,
        action="append",
        default=[],
        help="Parent/other CA CRL to include for ingress full-chain checking",
    )
    parser.add_argument(
        "--client-ca",
        default=os.environ.get("OCTO_AGENT_MTLS_CLIENT_CA", ""),
        help="CA bundle authenticating appended CRLs; defaults to the issuer certificate",
    )
    args = parser.parse_args()
    database = os.environ.get("OCTO_POSTGRES_URL", "")
    if (
        not database
        or not args.issuer_cert
        or not args.issuer_key
        or not (args.output or args.secret)
    ):
        parser.error(
            "OCTO_POSTGRES_URL, issuer certificate/key, and --output or --secret are required"
        )
    if args.secret and (
        len(args.secret.split("/")) != 2 or not all(args.secret.split("/"))
    ):
        parser.error("--secret must be namespace/name")
    settings = Settings(
        postgres_url=database,
        agent_mtls_issuer_cert=args.issuer_cert,
        agent_mtls_issuer_key=args.issuer_key,
        agent_mtls_trust_domain=os.environ.get(
            "OCTO_AGENT_MTLS_TRUST_DOMAIN", "shapoclyack"
        ),
    )
    result = export(
        settings,
        certificates=[
            load_pem_certificate(path.read_bytes()) for path in args.certificate
        ],
        lifetime_seconds=args.lifetime_seconds,
    )
    pem = result.pem + b"".join(
        path.read_bytes().strip() + b"\n" for path in args.append_crl
    )
    crls = validate_bundle(
        pem,
        (
            *load_ca_bundle(args.issuer_cert),
            *load_ca_bundle(args.client_ca or args.issuer_cert),
        ),
    )
    if args.output:
        write_atomic(args.output, pem)
    if args.secret:
        publish_secret(*args.secret.split("/"), pem)
    print(
        f"CRL: entries={result.entries}, API-only={result.api_only}, other-issuer={result.other_issuer}, "
        f"nextUpdate={min(crl.next_update_utc for crl in crls).isoformat()}"
    )


if __name__ == "__main__":
    main()
