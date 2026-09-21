"""An in-memory stand-in for the boto3 S3 client, for the artifact store tests.

Not a general S3 emulator and not trying to be: it implements exactly the eight
calls :class:`api.services.artifact_store.s3.S3ArtifactStore` makes, with the
two behaviours that actually catch bugs in that class -- keys are flat strings
(so a prefix that forgets its slash matches a sibling), and a listing with a
``Delimiter`` reports folders as ``CommonPrefixes`` rather than as objects.

Preferred over ``moto`` because it is thirty lines of dictionary rather than a
dependency the size of botocore itself, and because a test that wants to see
what happens when the gateway refuses a delete can simply say so here.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from typing import Any


class FakeClientError(Exception):
    """Shaped like ``botocore.exceptions.ClientError`` where the store looks."""

    def __init__(self, code: str, status: int = 404) -> None:
        super().__init__(code)
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class _Paginator:
    def __init__(self, objects: dict[str, tuple[bytes, datetime]]) -> None:
        self._objects = objects

    def paginate(
        self, *, Bucket: str, Prefix: str = "", Delimiter: str | None = None, **_: Any
    ):
        contents = []
        common: set[str] = set()
        for key in sorted(self._objects):
            if not key.startswith(Prefix):
                continue
            rest = key[len(Prefix) :]
            if Delimiter and Delimiter in rest:
                common.add(Prefix + rest.split(Delimiter, 1)[0] + Delimiter)
                continue
            body, modified = self._objects[key]
            contents.append({"Key": key, "Size": len(body), "LastModified": modified})
        # One page. Paging is botocore's concern, and the store consumes the
        # paginator rather than the raw call precisely so it never becomes ours.
        yield {
            "Contents": contents,
            "CommonPrefixes": [{"Prefix": prefix} for prefix in sorted(common)],
        }


class FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[str, tuple[bytes, datetime]] = {}
        self.content_types: dict[str, str] = {}
        self.presign_calls: list[dict[str, Any]] = []
        self.deleted_batches: list[list[str]] = []
        self.buckets_headed: list[str] = []
        #: Set to raise from the next mutating call, to test error handling.
        self.fail_with: Exception | None = None
        #: Set to raise from deletes only. A store outage refuses the cleanup
        #: of a half-finished upload exactly as it refused the upload, and a
        #: fake that puts badly but always deletes proves the rollback against
        #: a kindness the real thing does not offer.
        self.fail_deletes_with: Exception | None = None
        #: Keys this client refuses to accept, to stop a tree halfway without
        #: having to monkeypatch the store the code under test is holding.
        self.refuse_keys: set[str] = set()

    # -- objects ----------------------------------------------------------

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, ContentType: str = "") -> dict:
        if self.fail_with is not None:
            raise self.fail_with
        if Key in self.refuse_keys:
            raise FakeClientError("AccessDenied", status=403)
        self.objects[Key] = (bytes(Body), datetime.now(UTC))
        self.content_types[Key] = ContentType
        return {}

    def get_object(self, *, Bucket: str, Key: str) -> dict:
        if Key not in self.objects:
            raise FakeClientError("NoSuchKey")
        body, _ = self.objects[Key]
        return {"Body": io.BytesIO(body)}

    def head_object(self, *, Bucket: str, Key: str) -> dict:
        if Key not in self.objects:
            raise FakeClientError("404")
        body, modified = self.objects[Key]
        return {"ContentLength": len(body), "LastModified": modified}

    def delete_object(self, *, Bucket: str, Key: str) -> dict:
        if self.fail_with is not None:
            raise self.fail_with
        if self.fail_deletes_with is not None:
            raise self.fail_deletes_with
        self.objects.pop(Key, None)
        return {}

    def delete_objects(self, *, Bucket: str, Delete: dict) -> dict:
        if self.fail_with is not None:
            raise self.fail_with
        if self.fail_deletes_with is not None:
            raise self.fail_deletes_with
        keys = [item["Key"] for item in Delete["Objects"]]
        self.deleted_batches.append(keys)
        for key in keys:
            self.objects.pop(key, None)
        return {}

    # -- other ------------------------------------------------------------

    def get_paginator(self, name: str) -> _Paginator:
        assert name == "list_objects_v2"
        return _Paginator(self.objects)

    def generate_presigned_url(self, operation: str, *, Params: dict, ExpiresIn: int) -> str:
        self.presign_calls.append({"op": operation, "params": Params, "expires": ExpiresIn})
        return f"https://objects.example.com/{Params['Key']}?X-Amz-Expires={ExpiresIn}"

    def head_bucket(self, *, Bucket: str) -> dict:
        self.buckets_headed.append(Bucket)
        if self.fail_with is not None:
            raise self.fail_with
        return {}
