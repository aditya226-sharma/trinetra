"""Collector runtime — daemon threads that feed the pipeline.

Manages three live sources, toggled via the admin UI and persisted to a
runtime override (``data/collectors_override.json``):

  * **syslog** — UDP receiver (RFC 3164/5424 datagrams) on a configurable port
  * **tailers** — ``tail -f`` style file followers for flat-file sources
  * **demo** — replay of the bundled demo story onto the live pipeline

Threads are restarted (stop-all → start-all) whenever a toggle or a setting
changes, so edits apply without an app restart or loss of already-collected
store data.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.settings import Settings

log = logging.getLogger("trinetra.collectors")

_OVERRIDE_FILE = "collectors_override.json"


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CollectorsManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._threads: Dict[str, threading.Thread] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        self._orch: Any = None

    # ------------------------------------------------------------- config
    def _override_path(self) -> Path:
        return Path(self.settings.path("event_store")).parent / _OVERRIDE_FILE

    def read_override(self) -> Dict[str, Any]:
        try:
            path = self._override_path()
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:  # noqa: BLE001 — corrupt override must not block
            log.warning("collectors override unreadable; ignoring")
        return {}

    def write_override(self, cfg: Dict[str, Any]) -> None:
        path = self._override_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    def _config_defaults(self) -> Dict[str, Any]:
        s = self.settings
        return {
            "syslog": {
                "enabled": bool(int(s.get("events.syslog_port", 0) or 0)),
                "host": "0.0.0.0",
                "port": int(s.get("events.syslog_port", 0) or 1514),
                "client_id": s.get("agent.client_id", "trinetra-core"),
            },
            "tailers": [
                {"path": p, "source": "file_log",
                 "client_id": s.get("agent.client_id", "trinetra-core")}
                for p in (s.get("events.file_sources") or [])
            ],
            "demo": {"enabled": False, "replay_delay_s": 300,
                     "client_id": s.get("agent.client_id", "trinetra-core")},
        }

    def effective(self) -> Dict[str, Any]:
        base = self._config_defaults()
        override = self.read_override()
        for section in ("syslog", "tailers", "demo"):
            if isinstance(override.get(section), dict):
                base[section].update({k: v for k, v in override[section].items()
                                      if k in base[section]})
            elif section == "tailers" and isinstance(override.get("tailers"), list):
                base["tailers"] = override["tailers"]
        return base

    def apply(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """Fold a UI patch into the persisted override and restart collectors."""
        override = self.read_override()
        for section in ("syslog", "demo"):
            if isinstance(patch.get(section), dict):
                override[section] = override.get(section, {})
                override[section].update(patch[section])
        if "tailers" in patch:
            override["tailers"] = patch["tailers"]
        self.write_override(override)
        self.restart()
        return {"config": self.effective(), "running": self.status()}

    def status(self) -> Dict[str, Any]:
        running = {k: not ev.is_set() for k, ev in self._stop_events.items()}
        cfg = self.effective()
        return {
            "syslog_active": running.get("syslog", False),
            "tailer_active": running.get("tailer", False),
            "demo_active": running.get("demo", False),
            "syslog_port": cfg["syslog"]["port"],
            "tailers": [t.get("path") for t in cfg["tailers"]],
            "demo_enabled": cfg["demo"]["enabled"],
            "started_at": getattr(self, "_started_at", None),
        }

    # ------------------------------------------------------------ threads
    def start_all(self, orch: Any) -> None:
        self._orch = orch
        cfg = self.effective()
        self._started_at = _iso_now()
        if cfg["syslog"]["enabled"] and cfg["syslog"]["port"]:
            self._start("syslog", self._syslog_loop, cfg["syslog"])
        if cfg["tailers"]:
            self._start("tailer", self._tailer_loop, {"tailers": cfg["tailers"]})
        if cfg["demo"]["enabled"]:
            self._start("demo", self._demo_loop, cfg["demo"])

    def stop_all(self) -> None:
        for ev in list(self._stop_events.values()):
            ev.set()
        for t in list(self._threads.values()):
            t.join(timeout=2)
        self._threads.clear()
        self._stop_events.clear()

    def restart(self) -> None:
        self.stop_all()
        self.start_all(self._orch)

    def _start(self, key: str, target, cfg) -> None:
        ev = threading.Event()
        t = threading.Thread(target=target, args=(cfg, ev),
                             name=f"collector-{key}", daemon=True)
        self._stop_events[key] = ev
        self._threads[key] = t
        t.start()
        log.info("collector %s started", key)

    # ------------------------------------------------------------- loops
    def _syslog_loop(self, cfg: Dict[str, Any], stop: threading.Event) -> None:
        port = int(cfg.get("port") or 1514)
        host = str(cfg.get("host") or "0.0.0.0")
        client_id = str(cfg.get("client_id") or "trinetra-core")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        try:
            sock.bind((host, port))
        except OSError as exc:
            log.error("syslog bind :%s failed: %s", port, exc)
            sock.close()
            return
        log.info("syslog UDP listening on %s:%s", host, port)
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode("utf-8", errors="replace").rstrip("\n")
            if text.strip() and self._orch is not None:
                try:
                    self._orch.ingest(text, "syslog", client_id, addr[0])
                except Exception as exc:  # noqa: BLE001
                    log.warning("syslog ingest failed: %s", exc)
        sock.close()

    def _tailer_loop(self, cfg: Dict[str, Any], stop: threading.Event) -> None:
        from collectors.file_tailer import FileTailer

        entries = [t for t in cfg.get("tailers", []) if t.get("path")]
        if not entries:
            return
        tailer = FileTailer(
            paths=[t["path"] for t in entries],
            source=entries[0].get("source") or "file_log",
            client_id=entries[0].get("client_id") or "trinetra-core",
        )
        for raw, source, client_id, host in tailer.iterate():
            if stop.is_set():
                return
            if raw.strip() and self._orch is not None:
                try:
                    self._orch.ingest(raw, source, client_id, host)
                except Exception as exc:  # noqa: BLE001
                    log.warning("tailer ingest failed: %s", exc)

    def _demo_loop(self, cfg: Dict[str, Any], stop: threading.Event) -> None:
        from collectors.demo_feed import DemoFeed

        delay = max(5, float(cfg.get("replay_delay_s") or 300))
        while not stop.is_set():
            try:
                for raw, source, client_id, host in DemoFeed().iterate():
                    if stop.is_set():
                        return
                    if raw.strip() and self._orch is not None:
                        try:
                            self._orch.ingest(raw, source, client_id, host)
                        except Exception as exc:  # noqa: BLE001
                            log.warning("demo ingest failed: %s", exc)
                if self._orch is not None:
                    self._orch.flush_batch()
            except Exception as exc:  # noqa: BLE001
                log.warning("demo loop failed: %s", exc)
            stop.wait(delay)