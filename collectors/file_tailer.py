"""File tailer — follows one or more files like ``tail -f``.

Yields ``(raw_line, source, client_id, host_hint)`` tuples. Re-tails from the
start when a file grows past a hard cap (log rotation safety). Used primarily
for app logs, web-server logs and any flat-file source.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

Line = Tuple[str, str, str, str]


class FileTailer:
    def __init__(self, paths: List[str], source: Optional[str] = None,
                 client_id: str = "trinetra-core", poll_seconds: float = 0.2,
                 max_bytes_per_read: int = 1_000_000) -> None:
        self.paths = [Path(p) for p in paths]
        self.source = source
        self.client_id = client_id
        self.poll_seconds = poll_seconds
        self.max_bytes_per_read = max_bytes_per_read
        self._offsets: dict = {}

    def _ensure_offset(self, path: Path) -> None:
        if path not in self._offsets:
            self._offsets[path] = 0
            if path.exists():
                size = path.stat().st_size
                # Only track new content on the first pass for safety.
                self._offsets[path] = max(size - self.max_bytes_per_read, 0)

    def iterate(self) -> Iterator[Line]:
        while True:
            emitted = False
            for path in self.paths:
                self._ensure_offset(path)
                if not path.exists():
                    continue
                try:
                    size = path.stat().st_size
                    offset = self._offsets.get(path, 0)
                    if offset < 0:
                        offset = 0
                    if size < offset:  # file rotated / truncated
                        offset = 0
                    if size == offset:
                        continue
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(offset)
                        for line in fh:
                            if line.strip():
                                emitted = True
                                yield (line.rstrip("\n"),
                                       self.source or _guess_source(path),
                                       self.client_id,
                                       path.name)
                    self._offsets[path] = fh.tell()
                except (PermissionError, OSError):
                    continue
            if emitted:
                time.sleep(self.poll_seconds)
            else:
                time.sleep(max(self.poll_seconds, 0.5))


def _guess_source(path: Path) -> str:
    name = path.name.lower()
    if "netflow" in name or "flow" in name:
        return "netflow"
    if "cef" in name:
        return "cef"
    if "json" in name:
        return "json"
    if "csv" in name:
        return "csv"
    if name.endswith(".evtx") or "windows" in name:
        return "windows"
    if name.endswith(".log") or name.endswith(".txt"):
        return "syslog"
    return "generic"