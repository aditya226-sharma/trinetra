"""Syslog parser — RFC 3164 (BSD) and RFC 5424 (IETF) styles."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from parsers import common
from parsers.registry import register_parser

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_RFC5424_RE = re.compile(
    r"^<\d{1,3}>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$"
)
_RFC3164_RE = re.compile(
    r"^<\d{1,3}>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
    r"((?:[A-Za-z0-9_.-]+)(?:\[(\d+)\])?):\s?(.*)$"
)
_SIMPLE_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$")

_PRI_SEVERITY = {0: "critical", 1: "critical", 2: "critical", 3: "error",
                 4: "warning", 5: "info", 6: "info", 7: "info"}

_CATEGORY_HINTS = [
    ("sshd|su|sudo|login|passwd|pam|auth", "auth", "error"),
    ("fail2ban|ufw|iptables|firewalld", "network", "warning"),
    ("vpn|strongswan|ike|charon|ipsec|xauth", "vpn", "warning"),
    ("nginx|apache|httpd|tomcat|php-fpm", "application", "info"),
    ("kernel|systemd|rsyslog|cron|dockerd", "system", "info"),
]


def _pri_severity(raw: str) -> Optional[str]:
    match = _PRI_RE.match(raw)
    if not match:
        return None
    return _PRI_SEVERITY.get(int(match.group(1)) >> 3 % 8, "info")


def _categorize(text: str) -> tuple[str, str]:
    lower = (text or "").lower()
    for pattern, category, severity in _CATEGORY_HINTS:
        if re.search(pattern, lower):
            return category, severity
    return "system", "info"


@register_parser("syslog")
def parse_syslog(raw: str, source: str, client_id: str, host_hint: str = "") -> Optional[Dict[str, Any]]:
    raw = raw.rstrip("\n")
    timestamp: Optional[str] = None
    hostname = host_hint or ""
    message = ""
    tag, pid = "", ""

    match = _RFC5424_RE.match(raw)
    if match:
        timestamp, hostname = common.parse_syslog_ts(match.group(1)), match.group(2)
        app = match.group(3)
        pid = match.group(4) or ""
        message = match.group(6)
        tag = app
    else:
        match = _RFC3164_RE.match(raw) or _SIMPLE_RE.match(raw)
        if match:
            timestamp = common.parse_syslog_ts(match.group(1))
            hostname = match.group(2) or host_hint
            if len(match.groups()) >= 4 and match.group(4):
                tag, pid, message = match.group(3), match.group(4), match.group(5) or ""
            elif len(match.groups()) >= 3:
                tag, message = match.group(3), match.group(len(match.groups()))
            message = match.group(len(match.groups()))
        else:
            # No timestamp at all — a bare "host: message" or plain message.
            if ":" in raw and not raw.startswith(("http", "/")):
                hostname, _, message = raw.partition(": ")
                hostname = hostname.strip()
            else:
                message = raw

    if not raw.strip():
        return None

    category, hint_severity = _categorize(f"{tag} {message}")
    severity = _pri_severity(raw) or hint_severity

    fields: Dict[str, Any] = {}
    if tag:
        fields["process"] = tag
    if pid:
        fields["pid"] = pid
    if hostname:
        fields["hostname"] = hostname
    fields.update(common.parse_key_values(message))

    # Key-value tokens (src=, dst=, dpt=, ...) → UES-friendly names so
    # Modules A/C can consume firewall / flow messages uniformly.
    for old, new in (("src", "src_ip"), ("dst", "dst_ip"),
                     ("spt", "sport"), ("dpt", "dport"),
                     ("proto", "proto"), ("act", "action")):
        if old in fields:
            fields[new] = fields.pop(old)

    # Fallbacks for free-text messages: surface the first IPv4 address and
    # the user identity so Modules A/C can consume syslog uniformly.
    if "src_ip" not in fields:
        _ip = common.find_ip(message)
        if _ip:
            fields["src_ip"] = _ip

    # auth-specific detail extraction
    user_match = re.search(r"(?:user|user=|for)\s+(invalid user )?([A-Za-z0-9_.-]+)", message)
    if user_match:
        fields["attempted_user"] = user_match.group(2)
    if "failed password" in message.lower():
        severity = escalate_severity(severity)

    return {
        "timestamp": timestamp or common.now_iso(),
        "category": category,
        "severity": severity,
        "message": message,
        "client_ip": common.find_ip(message) or None,
        "fields": fields,
    }


def escalate_severity(severity: str) -> str:
    if severity in ("info", "warning"):
        return "error"
    return severity