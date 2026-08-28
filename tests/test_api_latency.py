"""Unit tests for the #185 latency probe helpers (no live server)."""

from tests.fixtures.api_latency import parse_histogram_p95, percentile


def test_percentile_interpolates():
    assert percentile([], 0.95) == 0.0
    assert percentile([10.0], 0.95) == 10.0
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.5


def test_histogram_p95_from_prom_text():
    text = """
# HELP octo_http_request_duration_seconds HTTP request duration in seconds.
octo_http_request_duration_seconds_bucket{method="GET",path="/api/assets",le="0.1"} 10
octo_http_request_duration_seconds_bucket{method="GET",path="/api/assets",le="0.5"} 90
octo_http_request_duration_seconds_bucket{method="GET",path="/api/assets",le="1.0"} 100
octo_http_request_duration_seconds_bucket{method="GET",path="/api/assets",le="+Inf"} 100
octo_http_request_duration_seconds_bucket{method="POST",path="/api/jobs",le="0.1"} 0
octo_http_request_duration_seconds_bucket{method="POST",path="/api/jobs",le="+Inf"} 5
"""
    p95 = parse_histogram_p95(text)
    assert p95 is not None
    # 90 of 100 are ≤ 0.5, so p95 sits in (0.5, 1.0].
    assert 0.5 < p95 <= 1.0
