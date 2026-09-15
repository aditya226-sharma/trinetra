"""Audit trail — append-only, SQLite-backed record of privileged actions.

Kept intentionally simple: privileged endpoints call :func:`audit_log` with an
actor (username or ``system``) and a terse, human-readable action. Reads go
through :func:`audit_recent` (newest-first, capped). The store trims itself to
a bounded number of rows so it can't grow without bound on a long-lived edge
deployment.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from config.settings import Settings

log = logging.getLogger("trinetra.audit")

_MAX_ROWS = 5000


def _db_path(settings: Settings) -> Path:
    return Path(settings.path("event_store")).parent / "audit.db"


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_conns: Dict[str, sqlite3.Connection] = {}
_lock = threading.Lock()


def _connect(settings: Settings) -> sqlite3.Connection:
    path = str(_db_path(settings))
    with _lock:
        conn = _conns.get(path)
        if conn is None:
            path_obj = Path(path)
            path_obj.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute(
                "CREATE TABLE IF NOT EXISTS audit ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " ts TEXT NOT NULL, actor TEXT NOT NULL,"
                " action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC)")
            conn.commit()
            _conns[path] = conn
        return conn


def audit_log(settings: Settings, actor: str, action: str,
              detail: str = "") -> None:
    """Append one audit row. Never raises — audited paths must not burst."""
    try:
        conn = _connect(settings)
        with _lock:
            conn.execute(
                "INSERT INTO audit (ts, actor, action, detail) VALUES (?,?,?,?)",
                (_iso_now(), str(actor)[:64], str(action)[:64],
                 str(detail)[:1000]))
            conn.execute(
                "DELETE FROM audit WHERE id NOT IN "
                "(SELECT id FROM audit ORDER BY id DESC LIMIT ?)",
                (_MAX_ROWS,))
            conn.commit()
    except Exception as exc:  # noqa: BLE001 — audit is best-effort
        log.warning("audit write failed: %s", exc)


def audit_recent(settings: Settings, limit: int = 100) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    try:
        conn = _connect(settings)
        rows = conn.execute(
            "SELECT ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        log.warning("audit read failed: %s", exc)
        return []