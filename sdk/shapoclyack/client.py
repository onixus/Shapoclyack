"""Dependency-free transport for every generated OpenAPI operation."""

from __future__ import annotations

import json
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .operations import OPERATIONS


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward a bearer credential to a redirect target.


class Client:
    def __init__(self, base_url, token, *, tenant_id=None, timeout=30):
        url = urlsplit(base_url)
        if (
            url.scheme not in {"https", "http"}
            or not url.netloc
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError("base_url must be an HTTP(S) origin without credentials")
        if url.path not in {"", "/"}:
            raise ValueError("base_url must be an origin, without a path")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.tenant_id = tenant_id
        self.timeout = timeout
        self._opener = build_opener(_NoRedirect())

    def request(
        self,
        operation,
        *,
        path=None,
        query=None,
        body=None,
        data=None,
        content_type=None,
        headers=None,
        raw=False,
    ):
        spec = OPERATIONS[operation]
        target = spec["path"]
        for key, value in (path or {}).items():
            target = target.replace("{" + key + "}", quote(str(value), safe=""))
        if "{" in target:
            raise ValueError("Missing path parameters")
        params = dict(query or {})
        if self.tenant_id is not None:
            if "tenant_id" in params and params["tenant_id"] != self.tenant_id:
                raise ValueError("query tenant differs from the client's tenant")
            params["tenant_id"] = self.tenant_id
        request_headers = dict(headers or {})
        request_headers["Authorization"] = "Bearer " + self.token
        media = (spec.get("requestBody") or {}).get("content", {})
        if body is not None and data is not None:
            raise ValueError("Pass either JSON body or encoded data")
        if data is not None:
            if (
                not isinstance(data, bytes)
                or not content_type
                or content_type.split(";", 1)[0] not in media
            ):
                raise ValueError(
                    "Encoded data requires bytes and a declared request content type"
                )
            request_headers["Content-Type"] = content_type
        if body is not None:
            if "application/json" not in media:
                raise ValueError(
                    "Operation requires encoded data instead of a JSON body"
                )
            data = json.dumps(body).encode()
            request_headers["Content-Type"] = "application/json"
        request = Request(
            self.base_url
            + target
            + ("?" + urlencode(params, doseq=True) if params else ""),
            data=data,
            headers=request_headers,
            method=spec["method"],
        )
        response = self._opener.open(request, timeout=self.timeout)
        if raw:
            return response  # Context-managed streaming response; caller closes it.
        with response:
            content = response.read()
            media = (response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if media != "application/json" and not media.endswith("+json"):
                # NDJSON/CSV exports, files and other bodies are returned as
                # bytes; use raw=True to stream them and read X-Next-Cursor.
                return content
            return json.loads(content) if content else None


def _method(name, spec):
    def operation(self, **kwargs):
        return self.request(name, **kwargs)

    operation.__name__ = name
    operation.__doc__ = (
        spec["method"]
        + " "
        + spec["path"]
        + "; path/query/body/data/content_type/headers/raw keyword arguments."
    )
    return operation


for _name, _spec in OPERATIONS.items():
    setattr(Client, _name, _method(_name, _spec))
