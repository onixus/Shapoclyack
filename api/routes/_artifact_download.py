"""One way to answer "give me that artifact", for every route that does.

Three routes hand a stored object to a browser -- a generated report, a run
artifact, a screenshot -- and each of them used to be a ``FileResponse`` over a
path on the shared volume. With artifacts in object storage (#336) there is no
such path, and there are two ways to answer instead:

* **Redirect** to a presigned URL, when the backend offers one. The bytes never
  enter the API process: a 400 MB PDF is downloaded from object storage
  directly, at object storage's bandwidth, while the API goes on serving
  requests. This is the default wherever it is possible.
* **Stream** the object through the API, in chunks. Always available, and the
  only answer the filesystem backend can give.

Both are behind one function so the *authorisation* stays where it was. Every
caller has already resolved the artifact under its principal's tenant before it
gets here; this module decides only how the bytes travel.

A presigned URL is a bearer token for one object, valid without a session for
as long as it lasts (``OCTO_ARTIFACT_PRESIGN_EXPIRES_SECONDS``, 15 minutes by
default, clamped to a day). An installation that would rather not hand those
out -- or whose object storage is not reachable from the operator's browser at
all, which is the common case for an in-cluster MinIO -- sets
``OCTO_ARTIFACT_PRESIGN_ENABLED=false`` and gets streaming everywhere.
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from fastapi import HTTPException, status
from fastapi.responses import RedirectResponse, StreamingResponse

from api.services import artifact_store
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.artifacts")


def content_disposition(filename: str) -> str:
    """An ``attachment`` disposition that survives a non-ASCII filename.

    Both forms: the quoted one for old clients, RFC 5987's ``filename*`` for
    everything since. Built rather than interpolated because the name comes
    from a report title or a run's own artifact list, and a quote or a newline
    in a header value is a response-splitting bug rather than a cosmetic one.
    """
    safe = "".join(ch for ch in filename if ch.isprintable() and ch not in ('"', "\\", ";"))
    ascii_name = safe.encode("ascii", "replace").decode("ascii") or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(safe or 'download')}"


def respond(
    settings: Settings,
    key: str,
    *,
    media_type: str,
    filename: str,
) -> StreamingResponse | RedirectResponse:
    """Hand ``key`` to the client, redirecting or streaming as the backend allows.

    Raises 404 when the object is gone. That is not defensive coding: every
    caller checked existence a moment ago, and the gap between the check and
    this call is exactly where a retention sweep runs.
    """
    store = artifact_store.get_store(settings)
    if settings.artifact_presign_enabled:
        url = store.presigned_url(
            key,
            expires_seconds=settings.artifact_presign_expires_seconds,
            filename=filename,
            content_type=media_type,
        )
        if url:
            # 307, not 302: a redirect that a client may rewrite to GET is
            # harmless here, but keeping the method explicit means a future
            # HEAD of an artifact behaves the same way.
            return RedirectResponse(url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    try:
        chunks = store.stream(key)
    except artifact_store.ArtifactNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found"
        ) from None
    except artifact_store.ArtifactStoreError as exc:
        # A reachable store that cannot serve the object is the operator's
        # problem, not the caller's: 502 says "the thing behind me failed",
        # where a 404 would have them looking for a report that exists.
        LOG.error("Artifact store failed serving %s: %s", key, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Artifact storage is unavailable",
        ) from exc

    headers = {"Content-Disposition": content_disposition(filename)}
    size = store.size(key)
    if size is not None:
        # So the browser can draw a progress bar. Omitted rather than guessed
        # when the backend will not say.
        headers["Content-Length"] = str(size)
    return StreamingResponse(chunks, media_type=media_type, headers=headers)
