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
    fields_json TEXT,
    module_findings_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_sev     ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source  ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_events_client  ON events(client_id);
CREATE INDEX IF NOT EXISTS idx_events_client_ts ON events(client_id, timestamp);
"""


def _row_to_event(row: Optional[sqlite3.Row]) -> Optional[Event]:
    if row is None:
        return None
    try:
        findings = json.loads(row["module_findings_json"]) if row["module_findings_json"] else {}
    except (TypeError, ValueError):
        findings = {}
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
        module_findings=findings if isinstance(findings, dict) else {},
    )


class EventStore:
    _STALE_MSGS = ("readonly database", "unable to open database file",
                   "disk i/o error")

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._connect()

    # ------------------------------------------------------------- connection
    def _connect(self) -> None:
        """Open the sqlite connection (assumes the caller holds ``_lock``)."""
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL").fetchone()
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        # Migrate databases created before module findings were persisted.
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(events)").fetchall()}
        if "module_findings_json" not in cols:
            self._conn.execute(
                "ALTER TABLE events ADD COLUMN module_findings_json TEXT")
        self._conn.commit()

    def _reconnect(self) -> None:
        """Re-open the store after the underlying file was replaced under us.

        Triggers like ``demo_run(reset=True)`` or a second process unlinking
        ``data/trinetra.db`` while this store is open leave our connection
        pointing at a stale inode: reads then return old data and writes fail
        with "attempt to write a readonly database" or "disk I/O error".
        Reconnecting re-binds to the current file.  The caller must hold
        ``_lock``.
        """
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
        self._connect()

    def _staleness_retry(self, op: Any) -> Any:
        """Run ``op`` (with ``_lock`` already held), retry once after a
        reconnect if the database file was replaced outside this process."""
        try:
            return op()
        except sqlite3.Error as exc:
            if not any(msg in str(exc).lower() for msg in self._STALE_MSGS):
                raise
            self._reconnect()
            return op()

    # ------------------------------------------------------------- writes
    def save(self, event: Event) -> None:
        with self._lock:
            def _do() -> None:
                self._conn.execute(
                    """INSERT OR REPLACE INTO events
                       (event_id, timestamp, source_type, client_id, client_ip,
                        category, severity, message, trace_id, fields_json,
                        module_findings_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (event.event_id, event.timestamp, event.source_type,
                     event.client_id, event.client_ip, event.category,
                     event.severity, event.message, event.trace_id,
                     json.dumps(event.fields, default=str),
                     json.dumps(event.module_findings, default=str)
                     if event.module_findings else None),
                )
                self._conn.commit()
            self._staleness_retry(_do)

    def save_many(self, events: List[Event]) -> None:
        with self._lock:
            def _do() -> None:
                self._conn.executemany(
                    """INSERT OR REPLACE INTO events
                       (event_id, timestamp, source_type, client_id, client_ip,
                        category, severity, message, trace_id, fields_json,
                        module_findings_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [(e.event_id, e.timestamp, e.source_type, e.client_id,
                      e.client_ip, e.category, e.severity, e.message, e.trace_id,
                      json.dumps(e.fields, default=str),
                      json.dumps(e.module_findings, default=str)
                      if e.module_findings else None) for e in events],
                )
                self._conn.commit()
            self._staleness_retry(_do)

    # ------------------------------------------------------------- reads
    def get(self, event_id: str) -> Optional[Event]:
        with self._lock:
            def _do() -> Optional[sqlite3.Row]:
                return self._conn.execute(
                    "SELECT * FROM events WHERE event_id = ?",
                    (event_id,)).fetchone()
            row = self._staleness_retry(_do)
        return _row_to_event(row)

    # ------------------------------------------------------------- findings
    def attach_findings(self, event_ids: List[str], module: str,
                        finding: Dict[str, Any]) -> int:
        """Attach a module finding back onto the source flow event(s) so the
        ``threat_class`` search filter finds real correlated events.

        Returns the number of events updated (events that no longer exist,
        e.g. after a reset, are skipped).
        """
        updated = 0
        for event_id in event_ids or []:
            event = self.get(event_id)
            if event is None:
                continue
            existing = event.module_findings.get(module)
            if isinstance(existing, list):
                existing.append(finding)
            else:
                event.module_findings[module] = [finding]
            self.save(event)
            updated += 1
        return updated

    def _where(self, query: str = "", source_type: str = "", severity: str = "",
               category: str = "", client_id: str = "", threat_class: str = "",
               ts_from: str = "", ts_to: str = "") -> tuple[str, list]:
        clauses, params = [], []
        if query:
            # Treat % _ \ literally so user input can't degenerate into SQL
            # LIKE wildcards (q="%" previously matched the whole corpus).
            esc = (query.replace("\\", "\\\\")
                   .replace("%", "\\%").replace("_", "\\_"))
            clauses.append("(message LIKE ? ESCAPE '\\' OR trace_id LIKE ?"
                           " ESCAPE '\\' OR client_ip LIKE ? ESCAPE '\\'"
                           " OR fields_json LIKE ? ESCAPE '\\')")
            params += [f"%{esc}%"] * 4
        for column, value in (("source_type", source_type), ("severity", severity),
                              ("category", category), ("client_id", client_id)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        if threat_class:
            # threat_class lives in the serialized fields blob and/or the
            # persisted module findings. Match the exact JSON key/value so the
            # filter is stable regardless of surrounding field order.
            # (json.dumps default separators put a space after the colon.)
            esc = (threat_class.replace("\\", "\\\\")
                   .replace("%", "\\%").replace("_", "\\_"))
            clauses.append("(fields_json LIKE ? ESCAPE '\\'"
                           " OR module_findings_json LIKE ? ESCAPE '\\')")
            params += [f'%"threat_class": "{esc}"%'] * 2
        if ts_from:
            clauses.append("timestamp >= ?")
            params.append(ts_from)
        if ts_to:
            clauses.append("timestamp <= ?")
            params.append(ts_to)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def search(self, query: str = "", source_type: str = "", severity: str = "",
               category: str = "", client_id: str = "", threat_class: str = "",
               ts_from: str = "", ts_to: str = "", limit: int = 100,
               offset: int = 0) -> List[Event]:
        where, params = self._where(query, source_type, severity, category,
                                    client_id, threat_class, ts_from, ts_to)
        sql = (f"SELECT * FROM events {where} ORDER BY timestamp DESC, event_id "
               f"LIMIT ? OFFSET ?")
        params += [limit, offset]
        with self._lock:
            def _do() -> List[sqlite3.Row]:
                return self._conn.execute(sql, params).fetchall()
            rows = self._staleness_retry(_do)
        return [e for e in (_row_to_event(r) for r in rows) if e is not None]

    def count_filtered(self, query: str = "", source_type: str = "",
                       severity: str = "", category: str = "",
                       client_id: str = "", threat_class: str = "",
                       ts_from: str = "", ts_to: str = "") -> int:
        where, params = self._where(query, source_type, severity, category,
                                    client_id, threat_class, ts_from, ts_to)
        with self._lock:
            def _do() -> sqlite3.Row:
                return self._conn.execute(
                    f"SELECT COUNT(*) AS c FROM events {where}", params).fetchone()
            row = self._staleness_retry(_do)
        return int(row["c"])

    def count(self) -> int:
        with self._lock:
            def _do() -> sqlite3.Row:
                return self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
            row = self._staleness_retry(_do)
        return int(row["c"])

    def iter_all(self, page: int = 500) -> Iterable[Event]:
        """Yield every stored event, oldest first, in bounded pages.

        Used to rebuild in-memory derived state (graph / threats) after a
        restart so persisted events keep the dashboard populated.
        """
        offset = 0
        while True:
            with self._lock:
                def _do() -> List[sqlite3.Row]:
                    return self._conn.execute(
                        "SELECT * FROM events ORDER BY timestamp ASC, event_id "
                        "LIMIT ? OFFSET ?", (page, offset)).fetchall()
                rows = self._staleness_retry(_do)
            if not rows:
                return
            for r in rows:
                event = _row_to_event(r)
                if event is not None:
                    yield event
            offset += page
            if len(rows) < page:
                return

    def count_by(self, column: str) -> Dict[str, int]:
        with self._lock:
            def _do() -> List[sqlite3.Row]:
                return self._conn.execute(
                    f"SELECT {column} AS k, COUNT(*) AS c FROM events GROUP BY {column}"
                ).fetchall()
            rows = self._staleness_retry(_do)
        return {str(r["k"]): int(r["c"]) for r in rows}

    def client_counts_since(self, cutoff: str) -> Dict[str, int]:
        """Events per client with ``timestamp >= cutoff`` (ISO UTC)."""
        with self._lock:
            def _do() -> List[sqlite3.Row]:
                return self._conn.execute(
                    "SELECT client_id AS cid, COUNT(*) AS c FROM events "
                    "WHERE timestamp >= ? GROUP BY client_id",
                    (cutoff,)).fetchall()
            rows = self._staleness_retry(_do)
        return {str(r["cid"]): int(r["c"]) for r in rows}

    def clients(self) -> List[Dict[str, Any]]:
        """Per-client summary: total events, dominant source type, last seen."""
        with self._lock:
            def _do() -> List[sqlite3.Row]:
                return self._conn.execute(
                    "SELECT client_id, source_type, COUNT(*) AS c, "
                    "MAX(timestamp) AS last_seen FROM events "
                    "GROUP BY client_id, source_type ORDER BY client_id, c DESC"
                ).fetchall()
            rows = self._staleness_retry(_do)
        merged: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            cid = str(r["client_id"])
            # First row per client is its dominant source (c DESC ordering).
            entry = merged.setdefault(
                cid, {"client_id": cid, "events": 0,
                      "source_type": str(r["source_type"]),
                      "last_seen": str(r["last_seen"] or "")})
            entry["events"] += int(r["c"])
            if str(r["last_seen"] or "") > str(entry["last_seen"] or ""):
                entry["last_seen"] = str(r["last_seen"])
        return list(merged.values())

    def prune_before(self, cutoff: str) -> int:
        """Delete events with ``timestamp < cutoff`` (ISO UTC). Returns count."""
        with self._lock:
            def _do() -> int:
                cur = self._conn.execute(
                    "DELETE FROM events WHERE timestamp < ?", (cutoff,))
                self._conn.commit()
                return cur.rowcount
            return self._staleness_retry(_do)

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
            def _do() -> List[sqlite3.Row]:
                return self._conn.execute(
                    "SELECT * FROM events WHERE trace_id = ?", (trace_id,)).fetchall()
            rows = self._staleness_retry(_do)
        return [e for e in (_row_to_event(r) for r in rows) if e is not None]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
