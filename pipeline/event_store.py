"""Event store — SQLite persistence for normalized UES events + rich search.

The raw store keeps byte-for-byte originals; this store keeps the derived UES
records so the dashboard / API can search, paginate and drill down without
touching raw data. Storage layout is deliberately simple:

    events(event_id PK, timestamp, source_type, client_id, client_ip,
           category, severity, message, trace_id, fields_json)

Production swap-out is a shim change (documented, not built) — nothing else
in the system dereferences this file directly.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from schema import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    timestamp  TEXT NOT NULL,
    source_type TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    client_ip  TEXT,
    category   TEXT NOT NULL,
    severity   TEXT NOT NULL,
    message    TEXT,
    trace_id   TEXT,
    fields_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_sev     ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source  ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_events_client  ON events(client_id);
"""


def _row_to_event(row: Optional[sqlite3.Row]) -> Optional[Event]:
    if row is None:
        return None
    return Event(
        event_id=row["event_id"],
        timestamp=row["timestamp"],
        source_type=row["source_type"],
        client_id=row["client_id"],
        client_ip=row["client_ip"],
        category=row["category"],
        severity=row["severity"],
        message=row["message"] or "",
        trace_id=row["trace_id"] or "",
        fields=json.loads(row["fields_json"]) if row["fields_json"] else {},
    )


class EventStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------- writes
    def save(self, event: Event) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO events
                   (event_id, timestamp, source_type, client_id, client_ip,
                    category, severity, message, trace_id, fields_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event.event_id, event.timestamp, event.source_type,
                 event.client_id, event.client_ip, event.category,
                 event.severity, event.message, event.trace_id,
                 json.dumps(event.fields, default=str)),
            )
            self._conn.commit()

    def save_many(self, events: List[Event]) -> None:
        with self._lock:
            self._conn.executemany(
                """INSERT OR REPLACE INTO events
                   (event_id, timestamp, source_type, client_id, client_ip,
                    category, severity, message, trace_id, fields_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(e.event_id, e.timestamp, e.source_type, e.client_id,
                  e.client_ip, e.category, e.severity, e.message, e.trace_id,
                  json.dumps(e.fields, default=str)) for e in events],
            )
            self._conn.commit()

    # ------------------------------------------------------------- reads
    def get(self, event_id: str) -> Optional[Event]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return _row_to_event(row)

    def search(self, query: str = "", source_type: str = "", severity: str = "",
               category: str = "", client_id: str = "", limit: int = 100,
               offset: int = 0) -> List[Event]:
        clauses, params = [], []
        if query:
            clauses.append("(message LIKE ? OR trace_id LIKE ? OR client_ip LIKE ?)")
            params += [f"%{query}%"] * 3
        for column, value in (("source_type", source_type), ("severity", severity),
                              ("category", category), ("client_id", client_id)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (f"SELECT * FROM events {where} ORDER BY timestamp DESC, event_id "
               f"LIMIT ? OFFSET ?")
        params += [limit, offset]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [e for e in (_row_to_event(r) for r in rows) if e is not None]

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
        return int(row["c"])

    def count_by(self, column: str) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {column} AS k, COUNT(*) AS c FROM events GROUP BY {column}"
            ).fetchall()
        return {str(r["k"]): int(r["c"]) for r in rows}

    def clients(self) -> List[Dict[str, Any]]:
        """Per-client summary: total events plus dominant source type."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT client_id, source_type, COUNT(*) AS c FROM events "
                "GROUP BY client_id, source_type ORDER BY client_id, c DESC"
            ).fetchall()
        merged: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            cid = str(r["client_id"])
            # First row per client is its dominant source (c DESC ordering).
            entry = merged.setdefault(
                cid, {"client_id": cid, "events": 0,
                      "source_type": str(r["source_type"])})
            entry["events"] += int(r["c"])
        return list(merged.values())

    def range_result(self, **kwargs: Any) -> Dict[str, Any]:
        limit = min(int(kwargs.pop("limit", 100)), 1000)
        offset = int(kwargs.pop("offset", 0))
        events = self.search(limit=limit, offset=offset, **kwargs)
        return {
            "total": self.count(),
            "limit": limit,
            "offset": offset,
            "events": [e.to_dict() for e in events],
        }

    def by_trace(self, trace_id: str) -> List[Event]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE trace_id = ?", (trace_id,)).fetchall()
        return [e for e in (_row_to_event(r) for r in rows) if e is not None]

    def close(self) -> None:
        with self._lock:
            self._conn.close()