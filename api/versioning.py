"""Version aliases enter all existing security middleware through the legacy path."""

from datetime import UTC, datetime
from email.utils import format_datetime
from urllib.parse import quote, urlsplit, urlunsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse


def canonical_path(path: str) -> str:
    return "/api/" + path[len("/api/v1/") :] if path.startswith("/api/v1/") else path


def versioned_location(location: str, host: str | None = None) -> str:
    """Put ``/v1`` back into a same-site redirect target the router built from
    the canonical path (e.g. the ``redirect_slashes`` 307). A target on another
    host (``host`` is the request's ``Host``) is left untouched."""
    parts = urlsplit(location)
    if parts.netloc and parts.netloc != host:
        return location
    if parts.path.startswith("/api/") and not parts.path.startswith("/api/v1/"):
        parts = parts._replace(path="/api/v1/" + parts.path[len("/api/") :])
    return urlunsplit(parts)


def _parse_instant(name: str, value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(
            f"{name} must be an ISO 8601 timestamp with a timezone, "
            f"e.g. 2026-10-15T00:00:00Z (got {value!r})"
        ) from None
    if parsed.tzinfo is None:
        raise ValueError(
            f"{name} must include a timezone, e.g. 2026-10-15T00:00:00Z (got {value!r})"
        )
    return parsed


def deprecation_headers(deprecated_at: str = "", sunset_at: str = "") -> dict[str, str]:
    """Validate the deprecation schedule and return its response headers.

    Raises ``ValueError`` naming the variable; ``api.settings.load_settings``
    calls this so a bad schedule stops the process at startup instead of
    failing on the first request (Starlette builds middleware lazily).
    """
    deprecated_at = (deprecated_at or "").strip()
    sunset_at = (sunset_at or "").strip()
    if bool(deprecated_at) != bool(sunset_at):
        raise ValueError(
            "OCTO_API_DEPRECATED_AT and OCTO_API_SUNSET_AT must be configured together"
        )
    if not deprecated_at:
        return {}
    start = _parse_instant("OCTO_API_DEPRECATED_AT", deprecated_at)
    end = _parse_instant("OCTO_API_SUNSET_AT", sunset_at)
    # At least twelve calendar months, including leap-day announcements.
    anniversary = (
        start.replace(year=start.year + 1, day=min(start.day, 28))
        if start.month == 2 and start.day == 29
        else start.replace(year=start.year + 1)
    )
    if end < anniversary:
        raise ValueError(
            "OCTO_API_SUNSET_AT must be at least twelve months after OCTO_API_DEPRECATED_AT"
        )
    return {
        "Deprecation": f"@{int(start.timestamp())}",
        "Sunset": format_datetime(end.astimezone(UTC), usegmt=True),
    }


def versioned_path(path: str) -> str:
    """The ``/api/v1`` equivalent of a legacy ``/api`` path."""
    return "/api/v1/" + path[len("/api/") :] if path.startswith("/api/") else path


def _strip_version(raw_path: bytes, root_path: str) -> bytes | None:
    """Drop the ``/v1`` segment from the client's original (still encoded) path."""
    marker = root_path.encode("utf-8") + b"/api/v1/"
    if raw_path.startswith(marker):
        return raw_path[: len(marker) - len(b"v1/")] + raw_path[len(marker) :]
    return None


class ApiVersionMiddleware:
    def __init__(self, app, *, headers=None):
        self.app = app
        self.headers = dict(headers or {})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        canonical = canonical_path(path)
        # A second version segment must never reach a versioned router with
        # guard code still seeing "v1" as the resource.
        if canonical.startswith("/api/v1/"):
            return await JSONResponse({"detail": "Not Found"}, status_code=404)(
                scope, receive, send
            )
        versioned = path != canonical
        successor = versioned_path(path)
        if versioned:
            raw_path = scope.get("raw_path")
            stripped = (
                _strip_version(raw_path, scope.get("root_path", "")) if raw_path else None
            )
            scope = dict(
                scope,
                path=canonical,
                raw_path=stripped
                if stripped is not None
                else (scope.get("root_path", "") + canonical).encode("utf-8"),
            )

        async def send_version(message):
            if message["type"] == "http.response.start" and (
                versioned or path.startswith("/api/")
            ):
                headers = MutableHeaders(scope=message)
                headers["API-Version"] = "1"
                if versioned and 300 <= message["status"] < 400:
                    location = headers.get("location")
                    if location:
                        host = Headers(scope=scope).get("host")
                        headers["location"] = versioned_location(location, host)
                if not versioned:
                    headers.update(self.headers)
                    headers.append(
                        "Link",
                        f'<{quote(scope.get("root_path", "") + successor)}>; rel="successor-version"',
                    )
            await send(message)

        await self.app(scope, receive, send_version)
