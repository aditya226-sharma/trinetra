"""Retention policy — prune expired UES events + aligned raw records.

``events.retention_days`` accepts 1 / 7 / 30 / 90 / 365 or 0 (0 = keep
forever). A daemon thread started with the FastAPI lifespan runs on an
interval and deletes events older than the cutoff from the event store, then
rewrites the raw store to keep the two aligned.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

from config.settings import Settings
from pipeline.event_store import EventStore
from pipeline.raw_store import RawStore

log = logging.getLogger("trinetra.retention")

_VALID_VALUES = (1, 7, 30, 90, 365, 0)
_DEFAULT_DAYS = 30
_DEFAULT_INTERVAL_SECONDS = 600

# Persisted override written by the admin UI, so a retention change survives
# restarts and the background loop picks it up without config-file edits.
_OVERRIDE_FILE = "retention_override.json"


def _override_path(settings: Settings):
    return Path(settings.path("event_store")).parent / _OVERRIDE_FILE


def _read_override(settings: Settings) -> Optional[int]:
    try:
        path = _override_path(settings)
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return _resolve(data.get("days"))
    except Exception:  # noqa: BLE001 — a corrupt override must never block
        log.warning("retention override unreadable; ignoring")
    return None


def _resolve(days) -> Optional[int]:
    try:
        days = int(days)
    except (TypeError, ValueError):
        return None
    if days not in _VALID_VALUES:
        return None
    return days


def effective_days(settings: Settings) -> int:
    """Configured retention (1/7/30/90/365/0), preferring a persisted override."""
    override = _read_override(settings)
    if override is not None:
        return override
    fallback = _resolve(settings.get("events.retention_days", _DEFAULT_DAYS))
    return _DEFAULT_DAYS if fallback is None else fallback


def set_retention(settings: Settings, days: int) -> int:
    """Persist a new retention policy; raises ValueError when invalid."""
    days = _resolve(days)
    if days is None:
        raise ValueError(f"retention must be one of {_VALID_VALUES}")
    path = _override_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"days": days}), encoding="utf-8")
    return days


def _cutoff(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_days(settings: Settings, days: Optional[int]) -> int:
    if days is None:
        days = effective_days(settings)
    days = _resolve(days)
    return _DEFAULT_DAYS if days is None else days


def prune(settings: Settings, days: Optional[int] = None) -> Dict[str, int]:
    """Delete events (and aligned raw records) older than ``days``.

    Returns ``{"events": n, "raw_records": n, "retention_days": d, "cutoff": c}``.
    Retention is skipped when the effective value is 0 (keep forever).
    """
    retention = _resolve_days(settings, days)
    if retention <= 0:
        return {"events": 0, "raw_records": 0, "retention_days": 0, "cutoff": ""}
    cutoff = _cutoff(retention)
    store = EventStore(settings.path("event_store"))
    try:
        events_removed = store.prune_before(cutoff)
    finally:
        store.close()
    raw_removed = RawStore(settings.path("raw_store")).prune_before(cutoff)
    return {"events": events_removed, "raw_records": raw_removed,
            "retention_days": retention, "cutoff": cutoff}


def _dir_bytes(path) -> int:
    path = Path(path)
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                total += p.stat().st_size
    except OSError:
        pass
    return total


def storage_snapshot(settings: Settings) -> Dict[str, object]:
    """Store state + sizes for the admin storage panel."""
    store = EventStore(settings.path("event_store"))
    try:
        events = store.count()
    finally:
        store.close()
    raw = RawStore(settings.path("raw_store"))
    try:
        raw_records = len(raw)
    finally:
        pass
    days = effective_days(settings)
    return {
        "retention_days": days,
        "valid_values": list(_VALID_VALUES),
        "events": events,
        "raw_records": raw_records,
        "event_db_bytes": _dir_bytes(settings.path("event_store")),
        "raw_store_bytes": _dir_bytes(settings.path("raw_store")),
        "event_db_path": str(settings.path("event_store")),
        "cutoff": _cutoff(days) if days else None,
    }


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
