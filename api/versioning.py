"""Version aliases enter all existing security middleware through the legacy path."""

from datetime import UTC, datetime
from email.utils import format_datetime

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse


def canonical_path(path: str) -> str:
    return "/api/" + path[len("/api/v1/") :] if path.startswith("/api/v1/") else path


class ApiVersionMiddleware:
    def __init__(self, app, *, deprecated_at="", sunset_at=""):
        self.app = app
        self.headers = {}
        if bool(deprecated_at) != bool(sunset_at):
            raise ValueError("API deprecation and sunset must be configured together")
        if deprecated_at:
            start = datetime.fromisoformat(deprecated_at.replace("Z", "+00:00"))
            end = datetime.fromisoformat(sunset_at.replace("Z", "+00:00"))
            if start.tzinfo is None or end.tzinfo is None:
                raise ValueError("API deprecation dates must include a timezone")
            # At least twelve calendar months, including leap-day announcements.
            anniversary = (
                start.replace(year=start.year + 1, day=min(start.day, 28))
                if start.month == 2 and start.day == 29
                else start.replace(year=start.year + 1)
            )
            if end < anniversary:
                raise ValueError("API sunset must allow at least twelve months")
            self.headers = {
                "Deprecation": f"@{int(start.timestamp())}",
                "Sunset": format_datetime(end.astimezone(UTC), usegmt=True),
            }

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
        if versioned:
            scope = dict(scope, path=canonical, raw_path=canonical.encode("utf-8"))

        async def send_version(message):
            if message["type"] == "http.response.start" and (
                versioned or path.startswith("/api/")
            ):
                headers = MutableHeaders(scope=message)
                headers["API-Version"] = "1"
                if not versioned:
                    headers.update(self.headers)
                    headers.append("Link", '</api/v1/>; rel="successor-version"')
            await send(message)

        await self.app(scope, receive, send_version)
