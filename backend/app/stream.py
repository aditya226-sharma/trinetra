"""Server-Sent Events live stream (in-app pub/sub).

The dashboard's Events page subscribes to ``GET /api/events/stream`` and
receives every UES event as it lands in the store. The hub guards per-
connection ``asyncio.Queue``s.

Thread-safety: ``publish`` may be called from the sync ingest endpoints'
threadpool, so the ``put`` is always re-scheduled onto the subscriber's event
loop with ``loop.call_soon_threadsafe`` — a bare cross-thread ``put_nowait``
sets the result on a Future the loop may never poll, which stalls readers
unpredictably (curl would see events, a browser EventSource would not).
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, Dict, Tuple

# event -> framed SSE line length cap (safety valve)
_EVENT_LIMIT = 1_000_000


class EventStreamHub:
    def __init__(self) -> None:
        self._subs: Dict[asyncio.Queue, asyncio.AbstractEventLoop] = {}
        self._lock = threading.Lock()

    def publish(self, event: Dict[str, Any]) -> None:
        try:
            line = "data: " + json.dumps(event, default=str) + "\n\n"
        except (TypeError, ValueError):
            return
        if len(line) > _EVENT_LIMIT:
            line = line[:_EVENT_LIMIT] + "\n\n"
        with self._lock:
            subs = list(self._subs.items())

        def _offer(queue: asyncio.Queue, line: str) -> None:
            # A slow subscriber's full queue must not crash the loop: drop the
            # event for that connection and keep the others flowing.
            try:
                queue.put_nowait(line)
            except asyncio.QueueFull:
                pass

        for queue, loop in subs:
            if loop.is_closed():
                continue
            loop.call_soon_threadsafe(_offer, queue, line)

    def subscribe(self, queue: asyncio.Queue,
                  loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._subs[queue] = loop

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subs.pop(queue, None)


hub = EventStreamHub()