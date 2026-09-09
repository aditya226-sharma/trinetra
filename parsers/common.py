"""Shared parsing helpers: IPs, timestamps, key=value pairs, JSON-safe fields."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
_KV_RE = re.compile(r"([A-Za-z0-9_.-]+)=((?:\"(?:[^\"\\]|\\.)*\"|\S+))")


def find_ip(text: str) -> Optional[str]:
    match = _IP_RE.search(text or "")
    return match.group(0) if match else None


def find_ips(text: str) -> list:
    return _IP_RE.findall(text or "")


def parse_syslog_ts(part: str) -> Optional[str]:
    """Parse 'Sep  9 10:22:11' or '2026-09-09T10:22:11Z' style timestamps to ISO."""
    part = part.strip()
    try:
        dt = datetime.fromisoformat(part.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    tokens = part.split()
    if len(tokens) >= 3 and tokens[0][:3].title() in _MONTHS and tokens[1].isdigit():
        month = _MONTHS[tokens[0][:3].title()]
        day = int(tokens[1])
        clock = tokens[2]
        try:
            now = datetime.now(timezone.utc)
            hour, minute, second = (int(x) for x in clock.split(":"))
            dt = datetime(now.year, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError:
            return None
        if dt > now + timedelta(days=2):  # year rollover guard
            dt = dt.replace(year=now.year - 1)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_key_values(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for match, value in ((m.group(1), m.group(2)) for m in _KV_RE.finditer(text or "")):
        if match not in out:
            out[match] = value.strip('"')
    return out


def json_value(data: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return default