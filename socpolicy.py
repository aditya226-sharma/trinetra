"""SOC policy engine — watchlist, blocklist, custom rules, alert-case lifecycle
and external delivery (email / webhook) with a scheduled daily digest.

Phase 3. Persisted next to the event store (same parent as ``trinetra.db``)
so policies survive restarts and the container is wiped-dir-safe:

    socpolicy.json   watchlist / blocklist / rules / notifications / digest state
    soc_cases.db     durable alert-case ledger (triage + lifecycle)

Every policy decision is wrapped so it can never break the event pipeline:
``evaluate_event`` runs before the UES event is persisted and only mutates
``event.fields["blocked"]`` on a blocklist hit. Cases created by rules /
watch / block / module findings all share one triage lifecycle (open →
acknowledged → resolved, assign, notes) and fan out to the enabled notifiers
whose severity threshold is satisfied.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from alerting.notifier import ConsoleNotifier, EmailNotifier, Notifier
from backend.app.services.audit import audit_log
from config.settings import Settings
from schema import SEVERITY_LEVELS, new_uuid

log = logging.getLogger("trinetra.socpolicy")

_POLICY_FILE = "socpolicy.json"
_CASES_DB = "soc_cases.db"

_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_LEVELS)}  # info < warning < error < critical

_STATUSES = ("open", "investigation", "closed")
_ACTIONS = ("investigate", "uninvestigate", "close", "reopen", "assign", "note")
_LEGACY_ACTIONS = {"ack": "investigate", "unack": "uninvestigate", "resolve": "close"}

_TASK_STATUSES = ("todo", "in_progress", "done")
_TASK_PRIORITIES = ("P1", "P2", "P3", "P4")

_ENTITY_KINDS = ("ip", "client", "user", "domain", "asset")
_MATCH_OPS = ("eq", "neq", "contains", "regex")
_DEFAULT_THROTTLE_S = 300        # close-together duplicate matches collapse into hits
_FLOW_THROTTLE_S = 3600          # repeated module findings on identical flows collapse


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _night_before(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Parse a confidence/score into a float, tolerating strings and junk."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class SocPolicyError(ValueError):
    """Raised by validators on malformed user input (mapped to 400/404)."""


class SocPolicy:
    """One per API process; owns persisted policy + the case ledger."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        base = Path(settings.path("event_store")).parent
        self._policy_path = base / _POLICY_FILE
        self._db_path = base / _CASES_DB
        self._lock = threading.RLock()
        self._data = {
            "watchlist": [],
            "blocklist": [],
            "rules": [],
            "notifications": self._default_notifications(),
            "state": {"last_digest": ""},
        }
        self._window: Dict[tuple, float] = {}
        self._load()
        self._bootstrap_db()
        self._notify_lock = threading.Lock()

    # ------------------------------------------------------------------ init

    def _default_notifications(self) -> Dict[str, Any]:
        return {
            "enabled": True,
            "severity_min": "warning",
            "email": {
                "host": os.environ.get("TRINETRA_SMTP_HOST", ""),
                "port": int(os.environ.get("TRINETRA_SMTP_PORT", "587")),
                "sender": os.environ.get("TRINETRA_SMTP_FROM", ""),
                "recipient": os.environ.get("TRINETRA_SMTP_TO", ""),
                "username": os.environ.get("TRINETRA_SMTP_USER", ""),
                "password": os.environ.get("TRINETRA_SMTP_PASS", ""),
            },
            "webhook": {"url": "", "secret": ""},
            "digest": {"enabled": False, "hour_utc": 8},
        }

    def _load(self) -> None:
        try:
            if self._policy_path.exists():
                raw = json.loads(self._policy_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._data = self._merge_defaults(raw)
        except Exception as exc:  # noqa: BLE001
            log.warning("socpolicy unreadable (%s); using defaults", exc)

    def _merge_defaults(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        defaults = {k: v for k, v in self._data.items()}
        for key in ("watchlist", "blocklist", "rules"):
            if isinstance(raw.get(key), list):
                defaults[key] = [e for e in raw[key] if isinstance(e, dict)]
        if isinstance(raw.get("notifications"), dict):
            notif = dict(defaults["notifications"])
            notif.update({k: v for k, v in raw["notifications"].items() if isinstance(v, (dict, bool, int, str))})
            defaults["notifications"] = notif
        if isinstance(raw.get("state"), dict):
            defaults["state"]["last_digest"] = str(raw["state"].get("last_digest") or "")
        return defaults

    def _save(self) -> None:
        with self._lock:
            self._policy_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._policy_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            tmp.replace(self._policy_path)

    # ------------------------------------------------------------- case db

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cases ("
            " id TEXT PRIMARY KEY,"
            " threat_class TEXT NOT NULL, severity TEXT NOT NULL,"
            " source_kind TEXT NOT NULL, source_value TEXT NOT NULL DEFAULT '',"
            " rule_id TEXT NOT NULL DEFAULT '',"
            " message TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '{}',"
            " verdict TEXT NOT NULL DEFAULT 'n/a', store_decision TEXT NOT NULL DEFAULT 'keep',"
            " confidence REAL NOT NULL DEFAULT 0, flows TEXT NOT NULL DEFAULT '',"
            " timestamp TEXT NOT NULL, last_seen TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 1,"
            " status TEXT NOT NULL DEFAULT 'open', assignee TEXT NOT NULL DEFAULT '',"
            " notes TEXT NOT NULL DEFAULT '[]', timeline TEXT NOT NULL DEFAULT '[]',"
            " client_id TEXT NOT NULL DEFAULT '', involved TEXT NOT NULL DEFAULT '[]',"
            " delivery TEXT NOT NULL DEFAULT 'null')")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_ts ON cases(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(cases)").fetchall()}
        if "client_id" not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN client_id TEXT NOT NULL DEFAULT ''")
        if "involved" not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN involved TEXT NOT NULL DEFAULT '[]'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_client ON cases(client_id)")
        # Migrate legacy statuses -> open/investigation/closed.
        conn.execute("UPDATE cases SET status = 'investigation' WHERE status = 'acknowledged'")
        conn.execute("UPDATE cases SET status = 'closed' WHERE status = 'resolved'")
        # Task ledger — admin-assigned work items surfaced on each client's
        # individual dashboard (assign a task -> appears on the client view).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tasks ("
            " id TEXT PRIMARY KEY,"
            " title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',"
            " priority TEXT NOT NULL DEFAULT 'P3',"
            " status TEXT NOT NULL DEFAULT 'todo',"
            " due_at TEXT NOT NULL DEFAULT '',"
            " client_id TEXT NOT NULL DEFAULT '',"
            " created_by TEXT NOT NULL DEFAULT 'system',"
            " linked_case_id TEXT NOT NULL DEFAULT '',"
            " notes TEXT NOT NULL DEFAULT '[]',"
            " timeline TEXT NOT NULL DEFAULT '[]',"
            " timer TEXT NOT NULL DEFAULT 'null',"
            " created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_client ON tasks(client_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        conn.commit()
        return conn

    def _bootstrap_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute("ANALYZE")
        finally:
            conn.close()

    def _case_row(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        case = dict(row)
        for key in ("evidence", "notes", "timeline"):
            try:
                case[key] = json.loads(case[key]) if case[key] else ([] if key != "evidence" else {})
            except (TypeError, ValueError):
                case[key] = [] if key != "evidence" else {}
        try:
            case["involved"] = json.loads(case["involved"]) if case["involved"] else []
        except (TypeError, ValueError):
            case["involved"] = []
        try:
            case["delivery"] = json.loads(case["delivery"]) if case["delivery"] else None
        except (TypeError, ValueError):
            case["delivery"] = None
        return case

    # ------------------------------------------------------------ policy CRUD

    def list_entries(self, list_name: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._data.get(list_name, [])]

    def add_entry(self, list_name: str, kind: str, value: str,
                  reason: str = "", actor: str = "system") -> Dict[str, Any]:
        if list_name not in ("watchlist", "blocklist"):
            raise SocPolicyError("list must be 'watchlist' or 'blocklist'")
        if kind not in _ENTITY_KINDS:
            raise SocPolicyError(f"kind must be one of {_ENTITY_KINDS}")
        value = str(value or "").strip()
        if not value or len(value) > 256:
            raise SocPolicyError("value is required (max 256 chars)")
        with self._lock:
            for e in self._data[list_name]:
                if e.get("kind") == kind and e.get("value", "").lower() == value.lower():
                    raise SocPolicyError(f"{kind} '{value}' already on the {list_name}")
            entry = {
                "kind": kind,
                "value": value,
                "reason": str(reason or "").strip()[:512],
                "created_by": str(actor)[:64],
                "created_at": _iso_now(),
                "active": True,
            }
            entries = self._data[list_name]
            entries.append(entry)
            self._save()
        audit_log(self.settings, actor, f"soc.{list_name}.add",
                  f"{kind}={value} reason={reason}")
        return dict(entry)

    def remove_entry(self, list_name: str, kind: str, value: str,
                     actor: str = "system") -> bool:
        entries = self._data.get(list_name)
        if entries is None:
            return False
        with self._lock:
            kept = [e for e in entries
                    if not (e.get("kind") == kind and e.get("value", "").lower() == value.lower())]
            if len(kept) == len(entries):
                return False
            self._data[list_name] = kept
            self._save()
        audit_log(self.settings, actor, f"soc.{list_name}.remove", f"{kind}={value}")
        return True

    def set_entry_active(self, list_name: str, kind: str, value: str,
                         active: bool, actor: str = "system") -> bool:
        entries = self._data.get(list_name)
        if entries is None:
            return False
        with self._lock:
            for e in entries:
                if e.get("kind") == kind and e.get("value", "").lower() == value.lower():
                    e["active"] = bool(active)
                    self._save()
                    audit_log(self.settings, actor, f"soc.{list_name}.toggle",
                              f"{kind}={value} active={active}")
                    return True
        return False

    # -------------------------------------------------------------- rules CRUD

    def list_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._data["rules"]]

    def _slug_id(self, name: str) -> str:
        import uuid

        slug = re.sub(r"[^a-z0-9_]+", "_", name.lower()).strip("_") or "rule"
        return f"{slug[:40]}_{uuid.uuid4().hex[:6]}"

    def _validate_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        name = str(rule.get("name") or "").strip()
        if not name or len(name) > 120:
            raise SocPolicyError("rule name is required (max 120 chars)")
        source_types = [str(x).strip() for x in rule.get("source_types", []) if str(x).strip()]
        categories = [str(x).strip().lower() for x in rule.get("categories", []) if str(x).strip()]
        min_severity = str(rule.get("min_severity") or "warning").lower()
        if min_severity not in SEVERITY_LEVELS:
            raise SocPolicyError("min_severity must be one of info/warning/error/critical")
        action = str(rule.get("action") or "alert").lower()
        if action not in ("alert", "notify"):
            raise SocPolicyError("action must be 'alert' or 'notify'")
        match = rule.get("match") or []
        if not match or not isinstance(match, list):
            raise SocPolicyError("a rule needs at least one match condition")
        clean_match: List[Dict[str, Any]] = []
        for cond in match:
            if not isinstance(cond, dict):
                raise SocPolicyError("each condition must be an object")
            field = str(cond.get("field") or "").strip()
            if not field:
                raise SocPolicyError("condition field is required")
            op = str(cond.get("op") or "eq").lower()
            if op not in _MATCH_OPS:
                raise SocPolicyError(f"condition op must be one of {_MATCH_OPS}")
            value = cond.get("value")
            if value is None or (isinstance(value, str) and not value.strip()):
                raise SocPolicyError("condition value is required")
            if op == "regex":
                try:
                    re.compile(str(value))
                except re.error as exc:
                    raise SocPolicyError(f"bad regex for {field}: {exc}") from exc
            clean_match.append({"field": field, "op": op, "value": value})
        return {
            "id": str(rule.get("id") or self._slug_id(name))[:64],
            "name": name,
            "description": str(rule.get("description") or "").strip()[:512],
            "source_types": source_types,
            "categories": categories,
            "min_severity": min_severity,
            "action": action,
            "match": clean_match,
            "enabled": bool(rule.get("enabled", True)),
            "updated_at": _iso_now(),
        }

    def upsert_rule(self, rule: Dict[str, Any], actor: str = "system",
                    rule_id: Optional[str] = None) -> Dict[str, Any]:
        clean = self._validate_rule(rule)
        if rule_id:
            clean["id"] = rule_id
        with self._lock:
            rules = self._data["rules"]
            replaced = [r for r in rules if r.get("id") != clean["id"]]
            existed = len(replaced) != len(rules)
            replaced.append(clean)
            self._data["rules"] = replaced
            self._save()
        audit_log(self.settings, actor, "soc.rule.save",
                  f"{clean['id']} ({clean['name']})")
        return dict(clean)

    def delete_rule(self, rule_id: str, actor: str = "system") -> bool:
        with self._lock:
            kept = [r for r in self._data["rules"] if r.get("id") != rule_id]
            if len(kept) == len(self._data["rules"]):
                return False
            self._data["rules"] = kept
            self._save()
        audit_log(self.settings, actor, "soc.rule.delete", rule_id)
        return True

    def toggle_rule(self, rule_id: str, enabled: bool, actor: str = "system") -> bool:
        with self._lock:
            for r in self._data["rules"]:
                if r.get("id") == rule_id:
                    r["enabled"] = bool(enabled)
                    r["updated_at"] = _iso_now()
                    self._save()
                    audit_log(self.settings, actor, "soc.rule.toggle",
                              f"{rule_id} enabled={enabled}")
                    return True
        return False

    # --------------------------------------------------------- notification cfg

    def notifications(self) -> Dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._data["notifications"]))

    def save_notifications(self, patch: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
        with self._lock:
            notif = self._data["notifications"]
            for key in ("enabled", "severity_min", "digest"):
                if key in patch:
                    if key == "severity_min" and patch[key] not in SEVERITY_LEVELS:
                        raise SocPolicyError("severity_min must be info/warning/error/critical")
                    notif[key] = patch[key]
            if isinstance(patch.get("email"), dict):
                email = notif["email"]
                for k in ("host", "port", "sender", "recipient", "username"):
                    if k in patch["email"]:
                        email[k] = str(patch["email"][k] or "")[:512]
                if patch["email"].get("password"):
                    email["password"] = str(patch["email"]["password"])[:512]
            if isinstance(patch.get("webhook"), dict):
                webhook = notif["webhook"]
                if "url" in patch["webhook"]:
                    webhook["url"] = str(patch["webhook"]["url"] or "")[:512]
                if patch["webhook"].get("secret"):
                    webhook["secret"] = str(patch["webhook"]["secret"])[:512]
            if isinstance(patch.get("digest"), dict):
                digest = notif["digest"]
                if "enabled" in patch["digest"]:
                    digest["enabled"] = bool(patch["digest"]["enabled"])
                if "hour_utc" in patch["digest"]:
                    hour = int(patch["digest"]["hour_utc"])
                    if not 0 <= hour <= 23:
                        raise SocPolicyError("digest.hour_utc must be 0..23")
                    digest["hour_utc"] = hour
            self._save()
        audit_log(self.settings, actor, "soc.notify.save",
                  "delivery config updated")
        return self.notifications()

    def _transports(self) -> List[Any]:
        notif = self._data["notifications"]
        transports: List[Any] = [ConsoleNotifier()]
        email = notif.get("email") or {}
        if email.get("host") and email.get("sender") and email.get("recipient"):
            transports.append(EmailNotifier(
                host=str(email["host"]), port=int(email.get("port") or 587),
                sender=str(email["sender"]), recipient=str(email["recipient"]),
                username=str(email.get("username") or ""),
                password=str(email.get("password") or "")))
        webhook = notif.get("webhook") or {}
        if webhook.get("url"):
            transports.append(_WebhookNotifier(str(webhook["url"]),
                                               str(webhook.get("secret") or "")))
        return transports

    def _rank(self, severity: str) -> int:
        return _SEV_RANK.get(str(severity).lower(), _SEV_RANK["info"])

    def notify_case(self, case: Dict[str, Any]) -> List[Dict[str, Any]]:
        notif = self._data["notifications"]
        if not notif.get("enabled"):
            return [{"transport": "policy", "status": "skipped", "reason": "notifications disabled"}]
        if self._rank(case.get("severity", "info")) < self._rank(notif.get("severity_min", "warning")):
            return [{"transport": "policy", "status": "skipped",
                     "reason": f"below severity_min={notif.get('severity_min')}"}]
        body_lines = [
            f"case_id     : {case['id']}",
            f"threat_class: {case.get('threat_class')}",
            f"severity    : {case.get('severity')}",
            f"confidence  : {case.get('confidence')}",
            f"first_seen  : {case.get('timestamp')}",
            f"hits        : {case.get('hits')}",
        ]
        value = case.get("source_value")
        if value:
            body_lines.append(f"matched     : {value}")
        if case.get("flows"):
            body_lines.append(f"flows       : {case.get('flows')}")
        if case.get("evidence"):
            body_lines.append("evidence    : " + json.dumps(case["evidence"])[:600])
        results = self.dispatch(case.get("severity", "high"),
                                f"[TriNetra] {case.get('threat_class')}",
                                "\n".join(body_lines))
        try:
            conn = self._connect()
            conn.execute("UPDATE cases SET delivery = ? WHERE id = ?",
                         (json.dumps(results), case["id"]))
            conn.commit()
            conn.close()
        except Exception as exc:  # noqa: BLE001
            log.warning("delivery record failed: %s", exc)
        return results

    def dispatch(self, severity: str, title: str, body: str) -> List[Dict[str, Any]]:
        """Fan out through the configured transports, never raising."""
        with self._notify_lock:
            notifier = Notifier(self._transports())
            return notifier.notify(severity, title, body)

    def send_test(self, actor: str = "system") -> Dict[str, Any]:
        results = self.dispatch("info", "[TriNetra] test alert",
                                "Delivery configuration test from TriNetra "
                                f"(sent by {actor} at {_iso_now()}).")
        audit_log(self.settings, actor, "soc.notify.test",
                  f"transports={[r.get('transport') for r in results]}")
        return {"results": results}

    # -------------------------------------------------------------- matching

    @staticmethod
    def _flatten_event(event: Any) -> Dict[str, Any]:
        flat: Dict[str, Any] = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "source_type": event.source_type,
            "client_id": event.client_id,
            "client_ip": event.client_ip or "",
            "category": event.category,
            "severity": event.severity,
            "message": event.message or "",
            "trace_id": event.trace_id or "",
        }
        fields = getattr(event, "fields", None) or {}
        for key, value in fields.items():
            flat[f"fields.{key}"] = value
        return flat

    def _fetch(self, flat: Dict[str, Any], field: str) -> Any:
        if field.startswith("fields."):
            return flat.get(field)
        return flat.get(field)

    def _cond_matches(self, flat: Dict[str, Any], cond: Dict[str, Any]) -> bool:
        value = self._fetch(flat, cond["field"])
        want = cond["value"]
        op = cond["op"]
        if isinstance(want, bool):
            value_bool = str(value).lower() in ("true", "1", "yes")
            return value_bool is want
        if isinstance(want, (int, float)):
            try:
                value_num = float(value)
            except (TypeError, ValueError):
                return False
            if op == "eq":
                return value_num == float(want)
            if op == "neq":
                return value_num != float(want)
            return str(value_num) == str(want)
        value_str = "" if value is None else str(value)
        want_str = str(want)
        if op == "eq":
            return value_str.lower() == want_str.lower()
        if op == "neq":
            return value_str.lower() != want_str.lower()
        if op == "contains":
            return want_str.lower() in value_str.lower()
        if op == "regex":
            try:
                return re.search(want_str, value_str) is not None
            except re.error:
                return False
        return False

    def _entity_values(self, entry: Dict[str, Any], flat: Dict[str, Any]) -> str:
        kind = entry["kind"]
        if kind == "ip":
            return str(flat.get("client_ip") or "")
        if kind == "client":
            return str(flat.get("client_id") or "")
        if kind == "user":
            user = flat.get("fields.user") or flat.get("fields.username") \
                or flat.get("fields.user_name") or ""
            return str(user or "")
        if kind == "domain":
            msg = str(flat.get("message") or "")
            host = str(flat.get("fields.host") or "")
            return msg if entry["value"].lower() in msg.lower() else host
        if kind == "asset":
            return str(flat.get("fields.asset") or flat.get("fields.dst_host") or "")
        return ""

    def _entry_match(self, entry: Dict[str, Any], flat: Dict[str, Any]) -> bool:
        value = self._entity_values(entry, flat)
        return bool(value) and entry["value"].lower() in value.lower()

    def _rule_match(self, rule: Dict[str, Any], flat: Dict[str, Any]) -> bool:
        if rule.get("source_types") and flat.get("source_type") not in rule["source_types"]:
            return False
        if rule.get("categories") and flat.get("category") not in rule["categories"]:
            return False
        if self._rank(flat.get("severity", "info")) < self._rank(rule.get("min_severity", "warning")):
            return False
        return all(self._cond_matches(flat, c) for c in rule["match"])

    # --------------------------------------------------------------- ingest hook

    def evaluate_event(self, event: Any) -> List[Dict[str, Any]]:
        """Run watch/block/rules against one normalized event. Never raises.

        Mutates ``event.fields['blocked']`` on a blocklist hit and returns the
        list of case dicts created (or throttled-hit) so callers can report.
        """
        try:
            flat = self._flatten_event(event)
            created: List[Dict[str, Any]] = []
            blocked = False
            for entry in self._data["blocklist"]:
                if not entry.get("active"):
                    continue
                value = self._entity_values(entry, flat)
                if not value or not self._entry_match(entry, flat):
                    continue
                blocked = True
                case = self._throttled_case(
                    threat_class="blocked_entity",
                    severity="critical",
                    source_kind="block",
                    source_value=value,
                    rule_id="",
                    message=f"Event references blocked {entry['kind']} {entry['value']}",
                    evidence={"list": "blocklist", "kind": entry["kind"],
                              "value": entry["value"], "reason": entry.get("reason", ""),
                              "event_id": event.event_id},
                    key=("block", entry["kind"], entry["value"].lower()),
                    throttle_s=_DEFAULT_THROTTLE_S,
                    ts=event.timestamp or _iso_now(),
                )
                if case:
                    created.append(case)
            if blocked:
                event.fields["blocked"] = "true"

            for entry in self._data["watchlist"]:
                if not entry.get("active"):
                    continue
                value = self._entity_values(entry, flat)
                if not value or not self._entry_match(entry, flat):
                    continue
                case = self._throttled_case(
                    threat_class="watchlist_hit",
                    severity="warning",
                    source_kind="watch",
                    source_value=value,
                    rule_id="",
                    message=f"Watched {entry['kind']} {entry['value']} observed",
                    evidence={"list": "watchlist", "kind": entry["kind"],
                              "value": entry["value"], "reason": entry.get("reason", ""),
                              "event_id": event.event_id},
                    key=("watch", entry["kind"], entry["value"].lower()),
                    throttle_s=_DEFAULT_THROTTLE_S,
                    ts=event.timestamp or _iso_now(),
                )
                if case:
                    created.append(case)

            for rule in self._data["rules"]:
                if not rule.get("enabled"):
                    continue
                if not self._rule_match(rule, flat):
                    continue
                severity = rule.get("min_severity", "warning")
                case = self._throttled_case(
                    threat_class=f"custom::{rule['id']}",
                    severity=severity,
                    source_kind="rule",
                    source_value=flat.get("trace_id") or event.event_id,
                    rule_id=rule["id"],
                    message=rule["name"],
                    evidence={"rule": rule["name"], "description": rule.get("description", ""),
                              "match": rule["match"], "event_id": event.event_id,
                              "message": (event.message or "")[:240]},
                    key=("rule", rule["id"], str(flat.get("trace_id") or event.event_id)),
                    throttle_s=_DEFAULT_THROTTLE_S,
                    ts=event.timestamp or _iso_now(),
                )
                if case:
                    created.append(case)
            return created
        except Exception as exc:  # noqa: BLE001 — policy must never break ingest
            log.warning("soc policy evaluate_event failed: %s", exc)
            return []

    def record_flow_finding(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create/touch a triage case for a Module A/B pipeline finding."""
        try:
            alert = finding.get("alert") or {}
            flows = str(alert.get("flows")
                        or alert.get("flow_id") or finding.get("flow_id") or "")
            severity = str(finding.get("severity") or alert.get("severity") or "high")
            threat_class = str(finding.get("threat_class") or alert.get("threat_class") or "unknown")
            ts = str(alert.get("timestamp") or finding.get("timestamp") or _iso_now())
            evidence = alert.get("evidence") or {}
            client_id = str(finding.get("client_id") or alert.get("client_id") or "")
            involved = self._involved_entities(finding, evidence)
            case = self._throttled_case(
                threat_class=threat_class,
                severity=severity,
                source_kind="flow",
                source_value=flows,
                rule_id="",
                message=f"Module finding {threat_class}",
                evidence=evidence if isinstance(evidence, dict) else {},
                key=("flow", threat_class, flows),
                throttle_s=_FLOW_THROTTLE_S,
                ts=ts,
                extra={"verdict": finding.get("analysis", {}).get("verdict", "n/a"),
                       "store_decision": finding.get("analysis", {}).get("store_decision", "keep"),
                       "confidence": _safe_float(finding.get("confidence", 0)),
                       "flows": flows,
                       "created_by": "system",
                       "client_id": client_id,
                       "involved": involved},
            )
            if case is None:
                return None
            self.notify_case(case)
            return case
        except Exception as exc:  # noqa: BLE001 — never kill the pipeline
            log.warning("record_flow_finding failed: %s", exc)
            return None

    def _involved_entities(self, finding: Dict[str, Any],
                           evidence: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract the parties implicated in a finding (IPs, hosts, users,
        domains, client) so incident drill-down can attribute involvement."""
        seen: Dict[tuple, str] = {}  # (kind, value) -> label
        values: List[Any] = []

        def add(kind: str, value: Any, label: Optional[str] = None) -> None:
            if value is None or str(value) == "":
                return
            text = str(value).strip()
            key = (kind, text)
            if key not in seen:
                seen[key] = label or text

        alert = finding.get("alert") or {}
        for field in ("src_ip", "src", "dst_ip", "dst", "host"):
            add("ip", evidence.get(field) or alert.get(field))
        add("domain", evidence.get("domain") or alert.get("domain")
            or (evidence.get("dns_query") if isinstance(evidence.get("dns_query"), str) else None))
        add("user", evidence.get("user") or alert.get("user")
            or (evidence.get("username") if isinstance(evidence.get("username"), str) else None))
        add("client", finding.get("client_id") or alert.get("client_id"))
        # Fan-out lists carried in evidence (#dst_ips, #unique_sources...).
        for list_field in ("dst_ips", "unique_sources", "srcs", "dsts", "hosts",
                           "suspicious_queries"):
            raw = evidence.get(list_field)
            if isinstance(raw, list):
                for entry in raw[:10]:
                    kind = "domain" if list_field == "suspicious_queries" else "ip"
                    add(kind, entry)
        return [{"kind": k, "value": v, "label": lbl}
                for (k, v), lbl in seen.items()]

    def _throttled_case(self, threat_class: str, severity: str, source_kind: str,
                        source_value: str, rule_id: str, message: str,
                        evidence: Dict[str, Any], key: tuple, throttle_s: int,
                        ts: str, extra: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            # Bound the throttle window (m6: prune stale entries + cap size).
            if len(self._window) > 4096:
                stale = [k for k, t in self._window.items()
                         if now - t > max(3600, float(throttle_s) * 4)]
                for stale_key in stale:
                    self._window.pop(stale_key, None)
                if len(self._window) > 4096:
                    for evicted in list(self._window)[:len(self._window) - 2048]:
                        self._window.pop(evicted, None)
            last = self._window.get(key, 0.0)
            if now - last < float(throttle_s):
                case = self._touch_open(key)
                if case:
                    return case
            self._window[key] = now
            conn = self._connect()
            try:
                case_id = new_uuid()
                timeline = [{"ts": ts, "action": "created", "actor": "system"}]
                conn.execute(
                    "INSERT INTO cases "
                    "(id, threat_class, severity, source_kind, source_value, rule_id,"
                    " message, evidence, verdict, store_decision, confidence, flows,"
                    " timestamp, last_seen, hits, status, assignee, notes, timeline,"
                    " client_id, involved, delivery)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (case_id, threat_class, severity, source_kind, source_value, rule_id,
                     message, json.dumps(evidence),
                     str((extra or {}).get("verdict", "n/a")),
                     str((extra or {}).get("store_decision", "keep")),
                     float((extra or {}).get("confidence", 0)),
                     str((extra or {}).get("flows", "")),
                     ts, ts, 1, "open", str((extra or {}).get("created_by", "system")) or "",
                     "[]", json.dumps(timeline),
                     str((extra or {}).get("client_id", "")),
                     json.dumps((extra or {}).get("involved", [])),
                     "null"))
                conn.commit()
                return self._case_row(conn.execute(
                    "SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone())
            finally:
                conn.close()

    def _touch_open(self, key: tuple) -> Optional[Dict[str, Any]]:
        """Increment hits on the OPEN case matching this throttled key."""
        if key[0] == "rule":
            where, args = ("AND rule_id = ?", [key[1]])
        elif key[0] in ("block", "watch"):
            where, args = ("AND lower(source_value) = lower(?)", [key[2]])
        elif key[0] == "flow":
            where, args = ("AND flows = ?", [key[2]])
        else:
            where, args = ("", [])
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM cases WHERE status != 'closed' "
                "AND source_kind = ? " + where + " ORDER BY timestamp DESC LIMIT 1",
                (key[0], *args)).fetchone()
            if row is None:
                return None
            case = self._case_row(row)
            hits = int(case["hits"]) + 1
            conn.execute(
                "UPDATE cases SET hits = ?, last_seen = ? WHERE id = ?",
                (hits, _iso_now(), case["id"]))
            conn.commit()
            case["hits"] = hits
            case["last_seen"] = _iso_now()
            return case
        finally:
            conn.close()

    # --------------------------------------------------------------- case API

    def list_cases(self, status: Optional[str] = None, limit: int = 100,
                   severity: Optional[str] = None, q: str = "",
                   client_id: str = "") -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        conn = self._connect()
        try:
            where: List[str] = []
            args: List[Any] = []
            if status in _STATUSES:
                where.append("status = ?")
                args.append(status)
            elif status == "unresolved":
                where.append("status != 'closed'")
            if client_id:
                where.append("client_id = ?")
                args.append(client_id)
            if severity in SEVERITY_LEVELS:
                where.append("severity = ?")
                args.append(severity)
            if str(q).strip():
                where.append("(threat_class LIKE ? OR message LIKE ? OR source_value LIKE ?)")
                like = f"%{q.strip()}%"
                args += [like, like, like]
            query = "SELECT * FROM cases"
            if where:
                query += " WHERE " + " AND ".join(where)
            query += " ORDER BY (status = 'closed'), timestamp DESC LIMIT ?"
            args.append(limit)
            rows = conn.execute(query, args).fetchall()
            return [self._case_row(r) for r in rows]
        finally:
            conn.close()

    def case_stats(self) -> Dict[str, Any]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT status, severity, COUNT(*) AS c FROM cases "
                "GROUP BY status, severity").fetchall()
            out = {s: 0 for s in _STATUSES}
            by_sev = {s: 0 for s in SEVERITY_LEVELS}
            open_by_sev = {s: 0 for s in SEVERITY_LEVELS}
            total = 0
            for r in rows:
                count = int(r["c"])
                total += count
                status = r["status"]
                if status in out:
                    out[status] += count
                sev = r["severity"] if r["severity"] in by_sev else "info"
                by_sev[sev] += count
                if status != "closed":
                    open_by_sev[sev] += count
            return {"total": total, "by_status": out, "by_severity": by_sev,
                    "unresolved_by_severity": open_by_sev}
        finally:
            conn.close()

    def case_stats_by_client(self, client_id: str) -> Dict[str, Any]:
        """Case stats scoped to a single client workspace."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS c FROM cases WHERE client_id = ? "
                "GROUP BY status", (client_id,)).fetchall()
            out = {s: 0 for s in _STATUSES}
            total = 0
            for r in rows:
                count = int(r["c"])
                total += count
                if r["status"] in out:
                    out[r["status"]] += count
            return {"total": total, "by_status": out}
        finally:
            conn.close()

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            return self._case_row(conn.execute(
                "SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone())
        finally:
            conn.close()

    def transition(self, case_id: str, action: str, actor: str = "system",
                   assignee: str = "", note: str = "") -> Dict[str, Any]:
        action = _LEGACY_ACTIONS.get(action, action)
        if action not in _ACTIONS:
            raise SocPolicyError(f"action must be one of {_ACTIONS}")
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None:
                raise SocPolicyError("case not found")
            case = self._case_row(row)
            ts = _iso_now()
            timeline = case["timeline"]
            notes = case["notes"]
            now_status = case["status"]
            new_status = now_status
            detail = ""
            if action == "investigate":
                if now_status == "closed":
                    raise SocPolicyError("closed cases must be reopened first")
                new_status = "investigation"
                detail = "opened for investigation"
            elif action == "uninvestigate":
                if now_status != "investigation":
                    raise SocPolicyError("only investigation cases can be un-investigated")
                new_status = "open"
                detail = "back to open"
            elif action == "close":
                if now_status == "closed":
                    raise SocPolicyError("case is already closed")
                new_status = "closed"
                detail = "closed"
            elif action == "reopen":
                if now_status != "closed":
                    raise SocPolicyError("only closed cases can be reopened")
                new_status = "open"
                detail = "reopened"
            elif action == "assign":
                assignee = str(assignee or "").strip()[:64]
                if not assignee:
                    raise SocPolicyError("assignee is required")
                detail = f"assigned to {assignee}"
            elif action == "note":
                note = str(note or "").strip()[:1000]
                if not note:
                    raise SocPolicyError("note is required")
                notes.append({"ts": ts, "actor": str(actor)[:64], "note": note})
                detail = "note added"
            if note and action in ("investigate", "uninvestigate", "close", "reopen", "assign"):
                notes.append({"ts": ts, "actor": str(actor)[:64], "note": note})
            if assignee:
                conn.execute("UPDATE cases SET assignee = ? WHERE id = ?",
                             (assignee, case_id))
            timeline.append({"ts": ts, "action": action, "actor": str(actor)[:64],
                             "detail": detail, "note": note})
            if new_status != now_status:
                conn.execute("UPDATE cases SET status = ? WHERE id = ?",
                             (new_status, case_id))
            conn.execute("UPDATE cases SET timeline = ?, notes = ? WHERE id = ?",
                         (json.dumps(timeline), json.dumps(notes), case_id))
            conn.commit()
            case.update(self._case_row(conn.execute(
                "SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()))
            audit_log(self.settings, actor, f"soc.case.{action}",
                      f"case={case_id} status={new_status} {detail} {note}".strip())
            return case
        finally:
            conn.close()

    # ---------------------------------------------------------------- tasks

    def _task_row(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        """Decode the durable JSON columns of a tasks row."""
        if row is None:
            return None
        task = dict(row)
        for key in ("notes", "timeline"):
            try:
                task[key] = json.loads(task[key]) if task[key] else []
            except (TypeError, ValueError):
                task[key] = []
        try:
            task["timer"] = json.loads(task["timer"]) if task["timer"] else None
        except (TypeError, ValueError):
            task["timer"] = None
        return task

    def _task_query_builder(self, status: str = "", client_id: str = "",
                            q: str = "") -> tuple:
        where: List[str] = []
        args: List[Any] = []
        if status in _TASK_STATUSES:
            where.append("status = ?")
            args.append(status)
        elif status == "open":
            where.append("status != 'done'")
        if client_id:
            where.append("client_id = ?")
            args.append(client_id)
        if str(q).strip():
            where.append("(title LIKE ? OR description LIKE ?)")
            like = f"%{q.strip()}%"
            args += [like, like]
        return where, args

    def create_task(self, title: str, client_id: str = "",
                    description: str = "", priority: str = "P3",
                    due_at: str = "", actor: str = "admin",
                    linked_case_id: str = "") -> Dict[str, Any]:
        """Create a work item for a client workspace (shows on their dashboard)."""
        title = str(title or "").strip()
        if not title or len(title) > 256:
            raise SocPolicyError("title is required (max 256 chars)")
        if priority.upper() not in _TASK_PRIORITIES:
            raise SocPolicyError(f"priority must be one of {_TASK_PRIORITIES}")
        description = str(description or "").strip()[:4000]
        client_id = str(client_id or "").strip()[:128]
        due_at = str(due_at or "").strip()[:40]
        linked_case_id = str(linked_case_id or "").strip()[:128]
        task_id = new_uuid()
        ts = _iso_now()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO tasks (id, title, description, priority, status, due_at,"
                " client_id, created_by, linked_case_id, notes, timeline, timer,"
                " created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (task_id, title, description, priority.upper(), "todo", due_at,
                 client_id, str(actor)[:64], linked_case_id, "[]",
                 json.dumps([{"ts": ts, "action": "created",
                              "actor": str(actor)[:64], "detail": "task created"}]),
                 "null", ts, ts))
            conn.commit()
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            audit_log(self.settings, actor, "soc.task.create",
                      f"task={task_id} client={client_id} title={title}")
            return self._task_row(row)
        finally:
            conn.close()

    def list_tasks(self, status: str = "", client_id: str = "", q: str = "",
                   limit: int = 200) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        conn = self._connect()
        try:
            where, args = self._task_query_builder(status, client_id, q)
            query = "SELECT * FROM tasks"
            if where:
                query += " WHERE " + " AND ".join(where)
            query += " ORDER BY (status = 'done'),"
            query += " (CASE priority WHEN 'P1' THEN 0 WHEN 'P2' THEN 1 WHEN 'P3' THEN 2 ELSE 3 END),"
            query += " due_at IS NOT '' AND due_at ASC, created_at DESC LIMIT ?"
            args.append(limit)
            rows = conn.execute(query, args).fetchall()
            return [self._task_row(r) for r in rows]
        finally:
            conn.close()

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            return self._task_row(conn.execute(
                "SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone())
        finally:
            conn.close()

    def patch_task(self, task_id: str, status: str = "", note: str = "",
                   due_at: str = "", priority: str = "",
                   actor: str = "system") -> Dict[str, Any]:
        """Update status / note / due / priority; every change is time-stamped
        into the timeline so the client can see who did what."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if row is None:
                raise SocPolicyError("task not found")
            task = self._task_row(row)
            ts = _iso_now()
            timeline = task["timeline"]
            sets: List[str] = []
            args: List[Any] = []
            now_status = task["status"]
            if status:
                status = str(status).lower()
                if status not in _TASK_STATUSES:
                    raise SocPolicyError(f"status must be one of {_TASK_STATUSES}")
                if status != now_status:
                    sets.append("status = ?")
                    args.append(status)
                    timeline.append({"ts": ts, "action": "status",
                                     "actor": str(actor)[:64],
                                     "detail": f"{now_status} → {status}"})
                    now_status = status
            if note:
                note = str(note).strip()[:1000]
                if not note:
                    raise SocPolicyError("note is required")
                notes = task["notes"]
                notes.append({"ts": ts, "actor": str(actor)[:64], "note": note})
                sets.append("notes = ?")
                args.append(json.dumps(notes))
                timeline.append({"ts": ts, "action": "note",
                                 "actor": str(actor)[:64], "detail": "note added"})
            if due_at:
                due_at = str(due_at).strip()[:40]
                sets.append("due_at = ?")
                args.append(due_at)
                timeline.append({"ts": ts, "action": "due",
                                 "actor": str(actor)[:64],
                                 "detail": f"due {due_at}"})
            if priority:
                priority = str(priority).upper()
                if priority not in _TASK_PRIORITIES:
                    raise SocPolicyError(f"priority must be one of {_TASK_PRIORITIES}")
                if priority != task["priority"]:
                    sets.append("priority = ?")
                    args.append(priority)
                    timeline.append({"ts": ts, "action": "priority",
                                     "actor": str(actor)[:64],
                                     "detail": f"{task['priority']} → {priority}"})
            if not sets:
                raise SocPolicyError("nothing to update")
            sets.append("updated_at = ?")
            args.append(ts)
            sets.append("timeline = ?")
            args.append(json.dumps(timeline))
            args.append(task_id)
            conn.execute(f"UPDATE tasks SET {', '.join(sets)} WHERE id = ?", args)
            conn.commit()
            task.update(self._task_row(conn.execute(
                "SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()))
            audit_log(self.settings, actor, f"soc.task.update",
                      f"task={task_id} status={now_status} note={note}".strip())
            return task
        finally:
            conn.close()

    def task_stats(self, client_id: str = "") -> Dict[str, Any]:
        """Aggregate task counts; '' client_id counts across all workspaces."""
        conn = self._connect()
        try:
            sql = ("SELECT status, COUNT(*) AS c FROM tasks"
                   f" {'WHERE client_id = ?' if client_id else ''}"
                   " GROUP BY status")
            args = (client_id,) if client_id else ()
            rows = conn.execute(sql, args).fetchall()
            tasks = {s: 0 for s in _TASK_STATUSES}
            total = 0
            for r in rows:
                count = int(r["c"])
                total += count
                if r["status"] in tasks:
                    tasks[r["status"]] += count
            overdue = 0
            if total:
                today = _today()
                if client_id:
                    overdue = int(conn.execute(
                        "SELECT COUNT(*) AS c FROM tasks WHERE client_id = ? "
                        "AND status != 'done' AND due_at != '' "
                        "AND substr(due_at, 1, 10) < ?",
                        (client_id, today)).fetchone()["c"])
                else:
                    overdue = int(conn.execute(
                        "SELECT COUNT(*) AS c FROM tasks "
                        "WHERE status != 'done' AND due_at != '' "
                        "AND substr(due_at, 1, 10) < ?",
                        (today,)).fetchone()["c"])
            return {"total": total, "by_status": tasks, "overdue": overdue}
        finally:
            conn.close()

    # ---------------------------------------------------------------- digest

    def run_digest(self, force: bool = False, actor: str = "system") -> Dict[str, Any]:
        with self._lock:
            notif = self._data["notifications"]
            digest_cfg = notif.get("digest") or {}
            if not force and not digest_cfg.get("enabled"):
                return {"status": "skipped", "reason": "digest disabled"}
            last = str(self._data["state"].get("last_digest") or "")
            today = _today()
            if not force and last == today:
                return {"status": "skipped", "reason": "already delivered today"}
        since = _night_before(24 * 60 * 60)
        cases = [c for c in self.list_cases(status=None, limit=200)
                 if c["timestamp"] >= since or c["status"] != "closed"]
        stats = self.case_stats()
        open_cases = [c for c in cases if c["status"] != "closed"]
        by_sev = {s: 0 for s in SEVERITY_LEVELS}
        for c in cases:
            sev = c["severity"] if c["severity"] in by_sev else "info"
            by_sev[sev] += 1
        lines = [
            "TriNetra security digest",
            "=" * 32,
            f"generated : {_iso_now()}",
            f"window    : last 24h + currently open",
            "",
            f"total alerts  : {stats['total']}",
            f"open          : {stats['by_status']['open']}",
            f"investigation : {stats['by_status']['investigation']}",
            f"closed        : {stats['by_status']['closed']}",
            f"by severity   : " + ", ".join(f"{s}={by_sev[s]}" for s in SEVERITY_LEVELS),
            "",
            "Latest cases",
            "-" * 32,
        ]
        if not open_cases:
            lines.append("No unresolved alerts.")
        for c in open_cases[:20]:
            lines.append(
                f"[{c.get('severity','?')[0].upper()}] {c.get('id','?')[:8]} "
                f"{c.get('threat_class','?')} {c.get('source_value','') or ''} "
                f"hits={c.get('hits',1)} status={c.get('status')}")
        body = "\n".join(lines)
        results = self.dispatch("info", "[TriNetra] daily digest", body)
        with self._lock:
            self._data["state"]["last_digest"] = _today()
            self._save()
        audit_log(self.settings, "system" if not actor else actor,
                  "soc.digest.run", f"delivered={results}")
        return {"status": "sent", "cases_in_window": len(cases),
                "results": results, "generated_at": _iso_now()}

    # --------------------------------------------------------------- digest loop

    def start_digest_loop(self) -> None:
        thread = threading.Thread(target=self._digest_loop, name="soc-digest",
                                  daemon=True)
        thread.start()

    def _digest_loop(self) -> None:
        while True:
            try:
                with self._lock:
                    notif = self._data["notifications"]
                    digest_cfg = notif.get("digest") or {}
                    enabled = digest_cfg.get("enabled", False)
                    hour_utc = int(digest_cfg.get("hour_utc", 8) or 8)
                if enabled:
                    now = datetime.now(timezone.utc)
                    if now.hour == hour_utc:
                        self.run_digest(force=False)
            except Exception as exc:  # noqa: BLE001
                log.warning("digest loop error: %s", exc)
            time.sleep(60)


class _WebhookNotifier:
    """POST a JSON envelope to an HTTP(S) endpoint (optional shared secret)."""

    name = "webhook"

    def __init__(self, url: str, secret: str = "") -> None:
        self.url = url
        self.secret = secret

    def notify(self, severity: str, title: str, body: str) -> Dict[str, Any]:
        payload = json.dumps({
            "type": "trinetra.alert",
            "severity": severity,
            "title": title,
            "body": body,
        }).encode("utf-8")
        req = urllib.request.Request(self.url, data=payload, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "trinetra/0.3"})
        if self.secret:
            req.add_header("X-Trinetra-Secret", self.secret)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = int(resp.status)
            return {"transport": self.name, "status": "sent", "severity": severity,
                    "http_status": status}
        except urllib.error.HTTPError as exc:
            return {"transport": self.name, "status": "error",
                    "http_status": int(exc.code), "error": str(exc)[:200]}
        except Exception as exc:  # noqa: BLE001
            return {"transport": self.name, "status": "error",
                    "error": str(exc)[:200]}