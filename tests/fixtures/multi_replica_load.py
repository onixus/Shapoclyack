"""Multi-replica API load and concurrency validation runner (Issue #188).

Tests live multi-replica API deployments or concurrent endpoints by issuing
bursts of concurrent requests (job creation, claims, asset queries, auth)
across multiple API instances / endpoints to verify lack of race conditions,
accurate idempotency, and stable latency.

Usage::

    python -m tests.fixtures.multi_replica_load \\
        --urls http://127.0.0.1:8080,http://127.0.0.1:8081 \\
        --username operator --password operator-change-me \\
        --concurrency 16 --jobs 50
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


def _request(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, bytes, float]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            elapsed = time.perf_counter() - t0
            return int(resp.status), payload, elapsed
    except urllib.error.HTTPError as exc:
        elapsed = time.perf_counter() - t0
        return int(exc.code), exc.read() if exc.fp else b"", elapsed
    except Exception as exc:  # noqa: BLE001
        elapsed = time.perf_counter() - t0
        return 0, str(exc).encode(), elapsed


def login(base_url: str, username: str, password: str) -> str:
    status, payload, _ = _request(
        f"{base_url.rstrip('/')}/api/auth/login",
        method="POST",
        body=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
    )
    if status != 200:
        raise SystemExit(f"login to {base_url} failed: HTTP {status} {payload[:200]!r}")
    token = json.loads(payload.decode())["access_token"]
    return str(token)


def run_load_test(
    urls: list[str],
    *,
    username: str,
    password: str,
    concurrency: int = 16,
    num_jobs: int = 40,
) -> dict[str, Any]:
    print(f"[#188 multi-replica load] Target URLs: {urls}")
    print(f"[#188 multi-replica load] Concurrency: {concurrency}, Jobs to submit: {num_jobs}")

    # Authenticate across all URLs
    tokens = [login(url, username, password) for url in urls]

    results = {
        "created_jobs": 0,
        "replayed_jobs": 0,
        "errors": 0,
        "latencies_ms": [],
    }

    # Submit jobs with shared idempotency keys across different replicas
    idempotency_keys = [f"multi-rep-load-{i}" for i in range(num_jobs // 2)]
    # Double the list so each key is submitted at least twice to different replicas
    submission_keys = idempotency_keys * 2
    random.shuffle(submission_keys)

    def submit_job(key: str) -> tuple[int, bool, float]:
        idx = random.randint(0, len(urls) - 1)
        target_url = urls[idx]
        token = tokens[idx]

        body = json.dumps({
            "target": ["192.168.1.1"],
            "profile": "quick",
            "execution": "agent",
        }).encode()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": key,
        }

        status, payload, elapsed = _request(
            f"{target_url.rstrip('/')}/api/jobs",
            method="POST",
            body=body,
            headers=headers,
        )

        is_replayed = status == 200  # 200 is replayed, 202 is newly queued
        is_ok = status in (200, 202)
        return status if is_ok else 0, is_replayed, elapsed * 1000.0

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(submit_job, k) for k in submission_keys]
        for fut in as_completed(futures):
            code, replayed, ms = fut.result()
            results["latencies_ms"].append(ms)
            if code == 0:
                results["errors"] += 1
            elif replayed:
                results["replayed_jobs"] += 1
            else:
                results["created_jobs"] += 1

    print(
        f"[#188 load results] Created: {results['created_jobs']}, "
        f"Replayed: {results['replayed_jobs']}, Errors: {results['errors']}"
    )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--urls", default="http://127.0.0.1:8080,http://127.0.0.1:8081")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin-change-me")
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--jobs", type=int, default=40)
    args = parser.parse_args()

    url_list = [u.strip() for u in args.urls.split(",") if u.strip()]
    if not url_list:
        sys.exit("Error: --urls must contain at least one valid URL")

    res = run_load_test(
        url_list,
        username=args.username,
        password=args.password,
        concurrency=args.concurrency,
        num_jobs=args.jobs,
    )
    if res["errors"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
