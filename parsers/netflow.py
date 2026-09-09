"""NetFlow / IPFIX flow-record parser.

Flow records may arrive as JSON objects (the typical collector transport) or
as tab/comma separated rows::

    ts <tab> src_ip <tab> dst_ip <tab> proto <tab> src_port <tab> dst_port <tab> pkts <tab> bytes <tab> flags

The parser is deliberately lenient — the raw record is preserved verbatim, and
the *structured* flow features are what Module A consumes downstream.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from parsers import common
from parsers.registry import register_parser

_TSV_COLUMNS = ("ts", "src", "dst", "proto", "sport", "dport", "pkts", "bytes", "flags")


@register_parser("netflow")
def parse_netflow_record(raw: str, source: str, client_id: str, host_hint: str = "") -> Optional[Dict[str, Any]]:
    stripped = raw.strip()
    if not stripped:
        return None

    record: Dict[str, Any]
    if stripped.startswith("{"):
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            return None
    else:
        parts = stripped.split("\t") if "\t" in stripped else stripped.split(",")
        if len(parts) < 5:
            return None
        record = dict(zip(_TSV_COLUMNS[: len(parts)], parts))

    src = record.get("src") or record.get("src_ip") or record.get("source_ip") or ""
    dst = record.get("dst") or record.get("dst_ip") or record.get("destination_ip") or ""
    proto = record.get("proto") or record.get("protocol") or ""
    timestamp = common.parse_syslog_ts(str(record.get("ts", record.get("timestamp", ""))))

    fields: Dict[str, Any] = {}
    for key in ("sport", "dport", "pkts", "bytes", "flags", "protocol", "proto",
                "tcp_flags", "dns_query", "tls_ja3"):
        if key in record:
            fields[key] = _as_int_or_str(record[key])

    return {
        "timestamp": timestamp or common.now_iso(),
        "category": "flow",
        "severity": "info",
        "message": f"flow src={src} dst={dst} proto={proto}",
        "client_ip": src or common.find_ip(stripped),
        "fields": {"src_ip": src, "dst_ip": dst, "proto": proto, **fields},
    }


def _as_int_or_str(value: Any) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError):
        return str(value)