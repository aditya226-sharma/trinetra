"""Batcher — fingerprint-based deduplication + time-window batching.

This is PS26156-g ("efficient SIEM/Data Lake integration"): identical
fingerprints in a batch collapse into one representative event with a
count, and events are emitted in fixed-size / fixed-time batches so the
downstream AI layers see a bounded, denoised stream.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import List, Optional

from schema import Event


def event_fingerprint(event: Event) -> str:
    """Stable fingerprint over source/client/category/message/fields.

    Timestamps and event_ids are excluded so *repetitive* lines (the classic
    syslog duplicate) collapse into one representative event with a count.
    """
    payload = {
        "source": event.source_type,
        "client": event.client_id,
        "category": event.category,
        "severity": event.severity,
        "message": event.message.strip()[:500],
        "fields": json.dumps(event.fields, sort_keys=True, default=str)[:1000],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:20]


class Batcher:
    def __init__(self, window_seconds: float = 2.0, max_events: int = 500) -> None:
        self.window_seconds = window_seconds
        self.max_events = max_events
        self._window_start = time.monotonic()
        self._events: List[Event] = []
        self._counts: dict = {}

    def add(self, event: Event) -> Optional[List[Event]]:
        """Add one event; return a ready batch (or None if not yet)."""
        fp = event_fingerprint(event)
        if fp in self._counts:
            self._counts[fp] += 1
            return None
        self._counts[fp] = 1
        self._events.append(event)

        now = time.monotonic()
        if len(self._events) >= self.max_events or (now - self._window_start) >= self.window_seconds:
            return self.flush()
        return None

    def flush(self) -> Optional[List[Event]]:
        if not self._events:
            return None
        batch = self._events
        counts = dict(self._counts)
        # Attach the count to each representative event as a field.
        for event in batch:
            fp = event_fingerprint(event)
            if counts.get(fp, 1) > 1:
                event.fields["_dedup_count"] = counts[fp]
                event.severity = event.severity  # keep severity as parsed
        self._events = []
        self._counts = {}
        self._window_start = time.monotonic()
        return batch


class DedupCounter:
    """Lightweight fingerprint->count tracker for reporting dedup stats."""

    def __init__(self) -> None:
        self.seen_fingerprints: set = set()
        self.raw_in = 0
        self.raw_duplicates = 0

    def track(self, event: Event) -> bool:
        """Return True if this event is a *new* unique event."""
        self.raw_in += 1
        fp = event_fingerprint(event)
        if fp in self.seen_fingerprints:
            self.raw_duplicates += 1
            return False
        self.seen_fingerprints.add(fp)
        return True

    @property
    def duplicate_rate(self) -> float:
        if self.raw_in == 0:
            return 0.0
        return self.raw_duplicates / self.raw_in