"""Raw event store — append-only, keyed by ``trace_id`` (PS26156-a, PS26156-d).

Every raw line is persisted byte-for-byte *before* normalization touches it,
so any downstream derived event can always be traced back to the exact
original input. Stored as append-only JSONL; reading is done lazily.

Production upgrade path (documented, not built): swap this file for S3 +
Parquet or a Kafka-fed object store — nothing upstream or downstream cares.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Dict, Iterator, Optional


class RawStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._index: Dict[str, str] = {}  # trace_id -> raw

    def append(self, trace_id: str, client_id: str, source_type: str, raw: str) -> None:
        record = {
            "trace_id": trace_id,
            "stored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client_id": client_id,
            "source_type": source_type,
            "raw": raw,
        }
        with self._lock:
            if trace_id in self._index:
                return  # idempotent — duplicates collapse here
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=True) + "\n")
            self._index[trace_id] = raw

    def get(self, trace_id: str) -> Optional[str]:
        raw = self._index.get(trace_id)
        if raw is not None:
            return raw
        # Fall back to a scan (covers stores written by a different process).
        for record in self.iter_records():
            if record.get("trace_id") == trace_id:
                self._index[trace_id] = record.get("raw", "")
                return record.get("raw")
        return None

    def iter_records(self) -> Iterator[Dict[str, str]]:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def __len__(self) -> int:
        if self._index:
            return len(self._index)
        return sum(1 for _ in self.iter_records())

    def __iter__(self) -> Iterator[Dict[str, str]]:
        return self.iter_records()