"""Server-Sent Events live stream (in-app pub/sub).

The dashboard's Events page subscribes to ``GET /api/events/stream`` and
receives every UES event as it lands in the store. The hub is a lock-guarded
set of per-connection ``asyncio.Queue``s; ``publish`` is safe to call from
the worker threadpool the sync ingest endpoint runs in.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, Dict, List, Set

_EVENT_LIMIT = 256  # newest N events a new subscriber sees per publish (n/a here)


class EventStreamHub:
    def __init__(self) -> None:
        self._queues: Set[asyncio.Queue] = set()
        self._lock = threading.Lock()

    def publish(self, event: Dict[str, Any]) -> None:
        line = "data: " + json.dumps(event, default=str) + "\n\n"
        with self._lock:
            queues: List[asyncio.Queue] = list(self._queues)
        for queue in queues:
            try:
                queue.put_nowait(line)
            except asyncio.QueueFull:
                pass

    def subscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._queues.add(queue)

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._queues.discard(queue)


hub = EventStreamHub()
