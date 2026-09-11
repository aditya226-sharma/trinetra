"""Retention policy — prune expired UES events + aligned raw records.

``events.retention_days`` accepts 1 / 7 / 30 / 90 / 365 or 0 (0 = keep
forever). A daemon thread started with the FastAPI lifespan runs on an
interval and deletes events older than the cutoff from the event store, then
rewrites the raw store to keep the two aligned.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from config.settings import Settings
from pipeline.event_store import EventStore
from pipeline.raw_store import RawStore

log = logging.getLogger("trinetra.retention")

_VALID_VALUES = (1, 7, 30, 90, 365, 0)
_DEFAULT_DAYS = 30
_DEFAULT_INTERVAL_SECONDS = 600


def _cutoff(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_days(settings: Settings, days: Optional[int]) -> int:
    if days is None:
        days = settings.get("events.retention_days", _DEFAULT_DAYS)
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = _DEFAULT_DAYS
    if days not in _VALID_VALUES:
        days = _DEFAULT_DAYS
    return days


def prune(settings: Settings, days: Optional[int] = None) -> Dict[str, int]:
    """Delete events (and aligned raw records) older than ``days``.

    Returns ``{"events": n, "raw_records": n}``. Retention is skipped when
    the configured value is 0 (keep forever).
    """
    retention = _resolve_days(settings, days)
    if retention <= 0:
        return {"events": 0, "raw_records": 0}
    cutoff = _cutoff(retention)
    store = EventStore(settings.path("event_store"))
    try:
        events_removed = store.prune_before(cutoff)
    finally:
        store.close()
    raw_removed = RawStore(settings.path("raw_store")).prune_before(cutoff)
    return {"events": events_removed, "raw_records": raw_removed}


def start_retention_loop(settings: Settings, interval_seconds: int = _DEFAULT_INTERVAL_SECONDS) -> threading.Thread:
    """Start the background prune loop (daemon)."""

    def _loop() -> None:
        while True:
            try:
                result = prune(settings)
                if result["events"] or result["raw_records"]:
                    log.info("retention prune: %s", result)
            except Exception as exc:  # noqa: BLE001 — never kill the loop
                log.warning("retention prune failed: %s", exc)
            time.sleep(interval_seconds)

    thread = threading.Thread(target=_loop, name="trinetra-retention", daemon=True)
    thread.start()
    return thread
