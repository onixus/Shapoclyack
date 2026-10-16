"""OpenAPI-generated operation CLI; credentials come only from the environment."""

import argparse
import json
import os
import shutil
import sys
import urllib.error

from .client import Client
from .operations import OPERATIONS

_ERROR_BODY_LIMIT = 4096


def main():
    parser = argparse.ArgumentParser(prog="shapoclyack")
    parser.add_argument("operation", choices=sorted(OPERATIONS))
    parser.add_argument(
        "--url", default=os.environ.get("SHAPOCLYACK_URL", "http://localhost:8000")
    )
    parser.add_argument("--tenant", default=os.environ.get("SHAPOCLYACK_TENANT"))
    parser.add_argument("--path", default="{}", help="JSON path parameter object")
    parser.add_argument("--query", default="{}", help="JSON query parameter object")
    parser.add_argument("--body", help="JSON body file, or - for stdin")
    parser.add_argument("--data", help="Encoded binary/form/multipart body file")
    parser.add_argument(
        "--content-type", help="Declared content type, including multipart boundary"
    )
    args = parser.parse_args()
    if args.body and args.data:
        parser.error("Pass either --body or --data")
    token = os.environ.get("SHAPOCLYACK_TOKEN")
    if not token:
        parser.error("SHAPOCLYACK_TOKEN is required")
    body = None
    if args.body:
        if args.body == "-":
            body = json.load(sys.stdin)
        else:
            with open(args.body) as source:
                body = json.load(source)
    data = None
    if args.data:
        with open(args.data, "rb") as source:
            data = source.read()
    client = Client(args.url, token, tenant_id=args.tenant)
    try:
        with client.request(
            args.operation,
            path=json.loads(args.path),
            query=json.loads(args.query),
            body=body,
            data=data,
            content_type=args.content_type,
            raw=True,
        ) as response:
            shutil.copyfileobj(response, sys.stdout.buffer)
            cursor = response.headers.get("X-Next-Cursor")
            if cursor:
                print("X-Next-Cursor: " + cursor, file=sys.stderr)
    except Exception as exc:
        # urllib errors do not print headers or the bearer credential.
        message = str(exc)
        if isinstance(exc, urllib.error.HTTPError):
            # The server's explanation (validation detail, 403 reason) lives in
            # the body; bound it so a hostile or broken server cannot flood us.
            try:
                body = exc.read(_ERROR_BODY_LIMIT).decode("utf-8", "replace").strip()
            except Exception:  # the status line alone is still a useful error
                body = ""
            if body:
                message += "\n" + body
        parser.exit(1, message + "\n")


if __name__ == "__main__":
    main()
