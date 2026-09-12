"""Client registry — per-machine metadata + agent tokens (SQLite).

Rides in the same database file as the event store (the ``event_store``
path) so fleet state, events and retention stay in one bucket:

    client_meta   client_id PK, hostname, platform, agent_version, ip,
                  source_types (JSON list), token_id, first_seen, last_seen,
                  last_heartbeat

    agent_tokens  token_id PK, token_hash, client_id (nullable until the
                  token's first use binds it), label, created_at, last_used,
                  enabled

Only the sha256 of an agent token is ever persisted; the raw value is shown
exactly once at mint time. Writes are serialized with a lock and reconnect
after the database file is replaced under us, mirroring :class:`EventStore`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("trinetra.client_store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS client_meta (
    client_id      TEXT PRIMARY KEY,
    hostname       TEXT,
    platform       TEXT,
    agent_version  TEXT,
    ip             TEXT,
    source_types   TEXT,
    token_id       TEXT,
    first_seen     TEXT,
    last_seen      TEXT,
    last_heartbeat TEXT
);
CREATE TABLE IF NOT EXISTS agent_tokens (
    token_id   TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    client_id  TEXT,
    label      TEXT,
    created_at TEXT NOT NULL,
    last_used  TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1
);
"""


def _djb2_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ClientStore:
    _STALE_MSGS = ("readonly database", "unable to open database file",
                   "disk i/o error")

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._connect()

    # ------------------------------------------------------------- connection
    def _connect(self) -> None:
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL").fetchone()
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _reconnect(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
        self._connect()

    def _staleness_retry(self, op: Any) -> Any:
        try:
            return op()
        except sqlite3.Error as exc:
            if not any(msg in str(exc).lower() for msg in self._STALE_MSGS):
                raise
            self._reconnect()
            return op()

    # ------------------------------------------------------------- client meta
    @staticmethod
    def _merge_source_types(existing: Optional[str], new_type: str) -> str:
        types = json.loads(existing) if existing else []
        if new_type and new_type not in types:
            types.append(new_type)
        return json.dumps(sorted(types))

    def touch(self, client_id: str, timestamp: str, source_type: str = "",
              hostname: str = "", platform: str = "", agent_version: str = "",
              ip: str = "") -> None:
        """Bump a client's presence from an ingested event (never called
        before the event itself is persisted)."""
        with self._lock:
            def _do() -> None:
                row = self._conn.execute(
                    "SELECT * FROM client_meta WHERE client_id = ?",
                    (client_id,)).fetchone()
                if row is None:
                    self._conn.execute(
                        """INSERT INTO client_meta
                           (client_id, hostname, platform, agent_version, ip,
                            source_types, first_seen, last_seen, last_heartbeat)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                        (client_id, hostname or client_id,
                         platform, agent_version, ip,
                         self._merge_source_types(None, source_type),
                         timestamp, timestamp))
                else:
                    source_types = self._merge_source_types(
                        row["source_types"], source_type)
                    self._conn.execute(
                        """UPDATE client_meta SET
                           hostname = COALESCE(NULLIF(?, ''), hostname),
                           platform = COALESCE(NULLIF(?, ''), platform),
                           agent_version = COALESCE(NULLIF(?, ''), agent_version),
                           ip = COALESCE(NULLIF(?, ''), ip),
                           source_types = ?, last_seen = MAX(last_seen, ?)
                           WHERE client_id = ?""",
                        (hostname, platform, agent_version, ip,
                         source_types, timestamp, client_id))
                self._conn.commit()
            self._staleness_retry(_do)

    def heartbeat(self, client_id: str, hostname: str = "",
                  platform: str = "", agent_version: str = "",
                  ip: str = "") -> None:
        """Record an agent liveness ping (presence model: online while the
        heartbeat stays fresher than the configured grace window)."""
        stamp = self._iso_utc()
        with self._lock:
            def _do() -> None:
                self._conn.execute(
                    """INSERT INTO client_meta
                       (client_id, hostname, platform, agent_version, ip,
                        first_seen, last_seen, last_heartbeat)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(client_id) DO UPDATE SET
                       hostname = COALESCE(NULLIF(excluded.hostname, ''), hostname),
                       platform = COALESCE(NULLIF(excluded.platform, ''), platform),
                       agent_version = COALESCE(NULLIF(excluded.agent_version, ''), agent_version),
                       ip = COALESCE(NULLIF(excluded.ip, ''), ip),
                       last_seen = ?, last_heartbeat = ?""",
                    (client_id, hostname, platform, agent_version,
                     ip, stamp, stamp, stamp, stamp, stamp))
                self._conn.commit()
            self._staleness_retry(_do)

    def list_clients(self) -> List[Dict[str, Any]]:
        with self._lock:
            def _do() -> List[sqlite3.Row]:
                return self._conn.execute(
                    "SELECT * FROM client_meta ORDER BY last_seen DESC").fetchall()
            rows = self._staleness_retry(_do)
        out = []
        for r in rows:
            item = {key: r[key] for key in r.keys()}
            item["source_types"] = (json.loads(item.get("source_types"))
                                    if item.get("source_types") else [])
            item["enabled"] = True
            out.append(item)
        return out

    def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            def _do() -> Optional[sqlite3.Row]:
                return self._conn.execute(
                    "SELECT * FROM client_meta WHERE client_id = ?",
                    (client_id,)).fetchone()
            row = self._staleness_retry(_do)
        if row is None:
            return None
        item = {key: row[key] for key in row.keys()}
        item["source_types"] = (json.loads(item.get("source_types"))
                                if item.get("source_types") else [])
        return item

    def bind_token(self, client_id: str, token_id: Optional[str]) -> None:
        """Bind a per-machine token to its client. The authoritative link
        lives on ``agent_tokens.client_id`` (used to pin ingestion); the
        ``client_meta.token_id`` column mirrors it for fleet display."""
        if not token_id:
            return
        with self._lock:
            def _do() -> None:
                self._conn.execute(
                    "UPDATE agent_tokens SET client_id = ? WHERE token_id = ?",
                    (client_id, token_id))
                self._conn.execute(
                    "UPDATE client_meta SET token_id = ? WHERE client_id = ?",
                    (token_id, client_id))
                self._conn.commit()
            self._staleness_retry(_do)

    # ------------------------------------------------------------- tokens
    def mint_token(self, label: str = "", client_id: str = "") -> tuple[str, str]:
        token_id = "agt_" + secrets.token_urlsafe(6)
        token = "trn_" + secrets.token_urlsafe(32)
        with self._lock:
            def _do() -> None:
                self._conn.execute(
                    """INSERT INTO agent_tokens
                       (token_id, token_hash, client_id, label, created_at)
                       VALUES (?, ?, NULLIF(?, ''), ?, ?)""",
                    (token_id, _djb2_hash(token), client_id, label,
                     self._iso_utc()))
                self._conn.commit()
            self._staleness_retry(_do)
        if client_id:
            self.bind_token(client_id, token_id)
        return token_id, token

    def token_by_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            def _do() -> Optional[sqlite3.Row]:
                return self._conn.execute(
                    "SELECT * FROM agent_tokens WHERE token_hash = ?",
                    (token_hash,)).fetchone()
            row = self._staleness_retry(_do)
        return {key: row[key] for key in row.keys()} if row else None

    def note_token_used(self, token_id: str) -> None:
        with self._lock:
            def _do() -> None:
                self._conn.execute(
                    "UPDATE agent_tokens SET last_used = ? WHERE token_id = ?",
                    (self._iso_utc(), token_id))
                self._conn.commit()
            self._staleness_retry(_do)

    def revoke_token(self, token_id: str) -> bool:
        with self._lock:
            def _do() -> bool:
                cur = self._conn.execute(
                    "UPDATE agent_tokens SET enabled = 0 WHERE token_id = ?",
                    (token_id,))
                self._conn.commit()
                return cur.rowcount > 0
            return self._staleness_retry(_do)

    def list_tokens(self) -> List[Dict[str, Any]]:
        with self._lock:
            def _do() -> List[sqlite3.Row]:
                return self._conn.execute(
                    "SELECT token_id, client_id, label, created_at, last_used, "
                    "enabled FROM agent_tokens ORDER BY created_at DESC").fetchall()
            rows = self._staleness_retry(_do)
        return [{key: r[key] for key in r.keys()} for r in rows]

    # ------------------------------------------------------------- misc
    @staticmethod
    def _iso_utc() -> str:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass