"""Safe iteration helpers for scanner result aggregation.

WHY: scanner output shapes differ across versions and providers, and
historically a single malformed finding (e.g., a Trivy CVSS field that
came back as a string instead of a dict) would raise an exception that
bubbled all the way to `process_scan_results`'s outer handler and
*lost the entire scan's data*.

These helpers wrap each per-scanner loop so:
  - non-dict entries are logged and skipped,
  - exceptions raised while processing one finding are logged and
    skipped, but the rest of the scan's findings still persist.

This is a tactical fix sitting inside server.py for now. Phase 1 of
the migration extracts a full `ResultAggregator` service with one
method per scanner — at which point this helper is folded into the
service.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import Any

logger = logging.getLogger(__name__)


def safe_findings(findings: Iterable[Any], scanner_name: str) -> Iterable[dict]:
    """Yield only dict-shaped findings from a scanner output list.

    Non-dict entries (strings, None, lists) are logged once and
    skipped. Returning an iterator (not a list) keeps memory profile
    identical to the original loop.
    """
    if findings is None:
        return
    for finding in findings:
        if isinstance(finding, dict):
            yield finding
        else:
            logger.warning(
                "Skipping non-dict %s finding: %s",
                scanner_name,
                type(finding).__name__,
            )


def process_findings(
    findings: Iterable[Any],
    scanner_name: str,
    handler: Callable[[dict], None | None],
) -> int:
    """Apply `handler` to each dict-shaped finding from `findings`.

    Returns the count of successfully processed findings. Logs and
    skips both non-dict entries and per-finding exceptions.

    Use when the per-finding logic is more than a couple of lines —
    extract a function and call this helper. For tight loops it is
    fine to use ``for finding in safe_findings(...)`` directly with an
    explicit ``try/except`` body.
    """
    processed = 0
    for finding in safe_findings(findings, scanner_name):
        try:
            handler(finding)
            processed += 1
        except Exception as exc:  # noqa: BLE001 - intentional broad catch
            logger.warning(
                "Failed to process %s finding, skipping: %s",
                scanner_name,
                exc,
            )
    return processed
