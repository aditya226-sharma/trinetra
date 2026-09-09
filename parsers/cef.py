"""CEF (Common Event Format) parser — the ArcSight standard.

Layout::

    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    CEF:0|Fortinet|FortiGate|v7.0|0001|PolicyViolation|5|src=1.2.3.4 dst=5.6.7.8 spt=123 dpt=80

Severity is 0–10 in CEF; we map 0-2 info, 3-4 warning, 5-7 error, 8-10 critical.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from parsers import common
from parsers.registry import register_parser


def _cef_severity(value: str) -> str:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return "info"
    if number >= 8:
        return "critical"
    if number >= 5:
        return "error"
    if number >= 3:
        return "warning"
    return "info"


# Extension keys → UES-friendly field names (consumed by Modules A/C).
_FIELD_ALIASES = {
    "src": "src_ip", "sourceAddress": "src_ip",
    "dst": "dst_ip", "destinationAddress": "dst_ip",
    "spt": "sport", "sourcePort": "sport",
    "dpt": "dport", "destinationPort": "dport",
    "proto": "proto", "act": "action", "msg": "message",
}


@register_parser("cef")
def parse_cef(raw: str, source: str, client_id: str, host_hint: str = "") -> Optional[Dict[str, Any]]:
    stripped = raw.strip()
    if not stripped.startswith("CEF:"):
        return None
    body = stripped[4:]

    parts = body.split("|")
    if len(parts) < 7:
        return None

    version, vendor, product, _prod_ver, sig, name_text = parts[:6]
    severity_value = parts[6]
    extension = "|".join(parts[7:]) if len(parts) > 7 else ""
    severity = _cef_severity(severity_value)

    fields = common.parse_key_values(extension or "")
    for old, new in _FIELD_ALIASES.items():
        if old in fields:
            fields[new] = fields.pop(old)

    ip = fields.get("src_ip") or fields.get("sourceAddress")
    if not ip:
        ip = common.find_ip(extension or "")

    products = (product or "").lower()
    category = "network" if ("net" in products or "fire" in products or "ids" in products) else "system"

    return {
        "timestamp": common.now_iso(),
        "category": category,
        "severity": severity,
        "message": f"[{vendor}/{product}] {name_text} {extension}".strip(),
        "client_ip": ip,
        "fields": {"cef_version": version, "vendor": vendor, "product": product,
                   "signature_id": sig, "cef_name": name_text, **(fields or {})},
    }