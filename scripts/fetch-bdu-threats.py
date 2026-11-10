#!/usr/bin/env python3
"""Refresh the local FSTEC Threat Bank (БДУ УБИ) overlay from thrlist.xlsx (#356).

Upstream is the official FSTEC BDU threat list: https://bdu.fstec.ru/files/documents/thrlist.xlsx
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.services import bdu_threats  # noqa: E402
import feed_fetch  # noqa: E402

LOG = logging.getLogger("fetch-bdu-threats")
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024


def _write(payload: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    tmp.replace(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", type=Path, default=bdu_threats.DEFAULT_DATABASE)
    parser.add_argument(
        "--source",
        type=Path,
        default=None,
        help="parse a local official thrlist.xlsx instead of downloading it",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    try:
        if args.source is not None:
            payload = bdu_threats.build_overlay(args.source)
        else:
            url = feed_fetch.feed_url(bdu_threats.SOURCE_URL_ENV, bdu_threats.SOURCE_URL)
            with tempfile.TemporaryDirectory(prefix="shapoclyack-bdu-threats-") as temp:
                source = Path(temp) / "thrlist.xlsx"
                feed_fetch.download(url, source, max_bytes=MAX_DOWNLOAD_BYTES)
                payload = bdu_threats.build_overlay(
                    source, origin_url=feed_fetch.redact_url(url)
                )
        _write(payload, args.output)
    except (
        OSError,
        ValueError,
        feed_fetch.FeedError,
        feed_fetch.egress.EgressConfigError,
    ) as exc:
        LOG.error("BDU threats refresh failed; existing overlay was not replaced: %s", exc)
        return 1

    LOG.info(
        "Wrote %d FSTEC threat records (БДУ УБИ) to %s",
        len(payload["threats"]),
        args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
