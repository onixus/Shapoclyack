"""End-to-end API latency probe (issue #185).

Hits the list/status routes named in ``docs/slo.md`` through the real HTTP
stack (FastAPI, auth, serialization) under several concurrency levels, and
compares client percentiles with ``octo_http_request_duration_seconds``.

This is the missing layer between ``scale_profile.py`` (in-process query
paths) and ``tests/load/run.sh`` (scanner against live target containers).

Usage::

    python -m tests.fixtures.api_latency \\
        --base-url http://127.0.0.1:8080 \\
        --username operator --password operator-change-me \\
        --concurrency 1,8,32 --requests 50 --markdown

Do not point this at a production installation: it issues a burst of GETs.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Any


DEFAULT_PATHS = (
    "/api/assets?limit=100",
    "/api/runs?limit=100",
    "/api/jobs?limit=100",
    "/api/agents?limit=100",
    "/api/schedules?limit=100",
    "/api/system",
    "/api/vulnerabilities?limit=100",
)


@dataclass(frozen=True)
class ProbeResult:
    path: str
    concurrency: int
    n: int
    ok: int
    errors: int
    statuses: dict[str, int]
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float


def percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = k - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


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


def login(base_url: str, username: str, password: str) -> str:
    status, payload, _ = _request(
        f"{base_url.rstrip('/')}/api/auth/login",
        method="POST",
        body=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
    )
    if status != 200:
        raise SystemExit(f"login failed: HTTP {status} {payload[:200]!r}")
    token = json.loads(payload.decode())["access_token"]
    return str(token)


def probe_path(
    base_url: str,
    path: str,
    *,
    token: str,
    tenant_id: str | None,
    concurrency: int,
    requests: int,
    timeout: float,
) -> ProbeResult:
    url = f"{base_url.rstrip('/')}{path}"
    if tenant_id:
        joiner = "&" if "?" in path else "?"
        url = f"{url}{joiner}tenant_id={tenant_id}"
    headers = {"Authorization": f"Bearer {token}"}
    samples: list[float] = []
    statuses: dict[str, int] = {}
    errors = 0

    def timed() -> tuple[int, float]:
        status, _, elapsed = _request(url, headers=headers, timeout=timeout)
        return status, elapsed

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futs = [pool.submit(timed) for _ in range(requests)]
        for fut in as_completed(futs):
            try:
                status, elapsed = fut.result()
            except Exception:  # noqa: BLE001
                errors += 1
                continue
            samples.append(elapsed * 1000.0)
            key = str(status)
            statuses[key] = statuses.get(key, 0) + 1
            if status >= 400:
                errors += 1

    samples.sort()
    ok = sum(n for code, n in statuses.items() if int(code) < 400)
    return ProbeResult(
        path=path,
        concurrency=concurrency,
        n=len(samples),
        ok=ok,
        errors=errors,
        statuses=statuses,
        p50_ms=round(percentile(samples, 0.50), 1),
        p95_ms=round(percentile(samples, 0.95), 1),
        p99_ms=round(percentile(samples, 0.99), 1),
        max_ms=round(samples[-1], 1) if samples else 0.0,
    )


def parse_histogram_p95(metrics_text: str, *, method: str = "GET") -> float | None:
    """p95 from ``octo_http_request_duration_seconds`` for ``method``, seconds."""
    buckets: dict[str, float] = {}
    prefix = "octo_http_request_duration_seconds_bucket{"
    for line in metrics_text.splitlines():
        if not line.startswith(prefix) or line.startswith("#"):
            continue
        if f'method="{method}"' not in line:
            continue
        # metric{labels} value
        labels, _, value = line.partition("} ")
        if 'le="' not in labels:
            continue
        le = labels.split('le="', 1)[1].split('"', 1)[0]
        buckets[le] = buckets.get(le, 0.0) + float(value.strip())
    if not buckets:
        return None
    # Cumulative histogram: convert to a coarse quantile.
    items = []
    for le, count in buckets.items():
        bound = float("inf") if le == "+Inf" else float(le)
        items.append((bound, count))
    items.sort()
    if not items or items[-1][1] <= 0:
        return None
    target = items[-1][1] * 0.95
    prev = 0.0
    prev_count = 0.0
    for bound, count in items:
        if count >= target:
            if bound == float("inf"):
                return prev
            if count == prev_count:
                return bound
            frac = (target - prev_count) / (count - prev_count)
            return prev + (bound - prev) * frac
        prev, prev_count = bound, count
    return prev


def as_markdown(rows: list[ProbeResult], *, extra: str = "") -> str:
    lines = [
        "| path | conc | n | ok | err | p50 ms | p95 ms | p99 ms | max ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| `{row.path}` | {row.concurrency} | {row.n} | {row.ok} | {row.errors} "
            f"| {row.p50_ms} | {row.p95_ms} | {row.p99_ms} | {row.max_ms} |"
        )
    if extra:
        lines.extend(["", extra])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--username", default="operator")
    parser.add_argument("--password", default="operator-change-me")
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--concurrency", default="1,8,32", help="comma-separated worker counts")
    parser.add_argument("--requests", type=int, default=40, help="GETs per path per concurrency")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--json-out", default=None)
    args = parser.parse_args(argv)

    concs = [int(part) for part in args.concurrency.split(",") if part.strip()]
    token = login(args.base_url, args.username, args.password)
    rows: list[ProbeResult] = []
    for conc in concs:
        for path in DEFAULT_PATHS:
            rows.append(
                probe_path(
                    args.base_url,
                    path,
                    token=token,
                    tenant_id=args.tenant_id,
                    concurrency=conc,
                    requests=args.requests,
                    timeout=args.timeout,
                )
            )

    metrics_p95 = None
    try:
        status, payload, _ = _request(f"{args.base_url.rstrip('/')}/metrics", timeout=args.timeout)
        if status == 200:
            metrics_p95 = parse_histogram_p95(payload.decode())
    except Exception:  # noqa: BLE001
        metrics_p95 = None

    payload_out: dict[str, Any] = {
        "base_url": args.base_url,
        "tenant_id": args.tenant_id,
        "requests_per_cell": args.requests,
        "results": [asdict(row) for row in rows],
        "server_get_p95_seconds": metrics_p95,
    }
    extra = ""
    if metrics_p95 is not None:
        extra = f"Server `octo_http_request_duration_seconds` GET p95 ≈ **{metrics_p95 * 1000:.1f} ms** (all GET routes, cumulative since process start)."
        payload_out["note"] = extra

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload_out, fh, indent=2)
            fh.write("\n")
    if args.markdown:
        sys.stdout.write(as_markdown(rows, extra=extra))
    else:
        json.dump(payload_out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
