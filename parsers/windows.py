"""Windows Event Log parser — accepts the compact key=value summaries the
Windows collector produces (e.g. via wevtutil) or minimal XML fragments.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from parsers import common
from parsers.registry import register_parser

_EVENT_LEVELS = {0: "info", 1: "critical", 2: "error", 3: "warning", 4: "info", 5: "info"}
_ID_RE = re.compile(r"\(EventID\s*(\d+)\)|EventID[=:]?\s*(\d+)", re.IGNORECASE)


@register_parser("windows")
def parse_windows(raw: str, source: str, client_id: str, host_hint: str = "") -> Optional[Dict[str, Any]]:
    stripped = raw.strip()
    if not stripped:
        return None
    lower = stripped.lower()
    if not (("eventid" in lower or "provider" in lower) or stripped.startswith("<Event")):
        return None

    fields: Dict[str, Any] = {}
    match = _ID_RE.search(stripped)
    if match:
        fields["event_id"] = match.group(1) or match.group(2)

    level_match = re.search(r"Level[=:]?\s*(\d)", stripped, re.IGNORECASE)
    severity = _EVENT_LEVELS.get(int(level_match.group(1)) if level_match else 4, "info")

    provider_match = re.search(r"Provider[=:]?\s*([A-Za-z0-9_.-]+)", stripped, re.IGNORECASE)
    if provider_match:
        fields["provider"] = provider_match.group(1)

    user_match = re.search(r"(?:Account Name|User)[=:]\s*([^\s,]+)", stripped)
    if user_match:
        fields["user"] = user_match.group(1)

    hostname_match = re.search(r"Computer[=:]\s*([^\s,]+)", stripped)
    hostname = hostname_match.group(1) if hostname_match else host_hint

    message = stripped
    category = "auth" if any(k in lower for k in ("logon", "logoff", "credential", "4624", "4625")) \
        else "system"

    return {
        "timestamp": common.now_iso(),
        "category": category,
        "severity": severity,
        "message": message[:2000],
        "client_ip": common.find_ip(stripped) or None,
        "fields": fields | {"hostname": hostname},
    }