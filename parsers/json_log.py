"""JSON log-line parser — any JSON object per line (cloud audit, app logs)."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from parsers import common
from parsers.registry import register_parser

_TIMESTAMP_KEYS = ("timestamp", "@timestamp", "time", "ts", "datetime", "event_time")
_MESSAGE_KEYS = ("message", "msg", "log", "description", "event")
_SEVERITY_KEYS = ("severity", "level", "loglevel", "priority")
_CATEGORY_KEYS = ("category", "event_type", "type", "kind")


@register_parser("json")
def parse_json_log(raw: str, source: str, client_id: str, host_hint: str = "") -> Optional[Dict[str, Any]]:
    stripped = raw.strip()
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    timestamp = common.parse_syslog_ts(str(common.json_value(
        data, *_TIMESTAMP_KEYS, default="")))
    if not timestamp:
        timestamp = common.now_iso()

    message = str(common.json_value(data, *_MESSAGE_KEYS, default="" or raw))

    fields = {"source_number": len(data)}
    for key, value in data.items():
        if key in _TIMESTAMP_KEYS or key in _MESSAGE_KEYS or key in _SEVERITY_KEYS:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            fields[key] = value

    client_ip = common.find_ip(str(data)) or None
    category = common.json_value(data, *_CATEGORY_KEYS, default="application")
    if category == "authentication":
        category = "auth"
    severity = common._norm_severity(common.json_value(data, *_SEVERITY_KEYS, default="info"))

    if isinstance(data.get("src_ip"), str):
        client_ip = data["src_ip"]

    return {
        "timestamp": timestamp,
        "category": common._norm_category(category),
        "severity": severity,
        "message": message,
        "client_ip": client_ip,
        "fields": fields,
    }