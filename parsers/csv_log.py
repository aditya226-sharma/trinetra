"""CSV log parser — a line with a header row mapping columns to names."""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, Optional

from parsers import common
from parsers.registry import register_parser


class _CsvState:
    """Holds the most recent header row so subsequent lines map onto it."""

    header: Optional[list] = None


_STATE = _CsvState()


@register_parser("csv")
def parse_csv_log(raw: str, source: str, client_id: str, host_hint: str = "") -> Optional[Dict[str, Any]]:
    stripped = raw.rstrip("\n")
    if not stripped.strip():
        return None

    # Parse the single line; if it's not plausibly CSV-shaped, bail out.
    try:
        row = next(csv.reader(io.StringIO(stripped)))
    except StopIteration:
        return None
    if len(stripped.replace(",", "").strip()) == 0 or "," not in stripped:
        return None

    if _STATE.header is not None and len(row) == len(_STATE.header):
        record = dict(zip(_STATE.header, row))
    else:
        # Treat this row as a new header.
        _STATE.header = [c.strip().lower().replace(" ", "_") for c in row]
        return {
            "timestamp": common.now_iso(),
            "category": "system",
            "severity": "info",
            "message": "CSV header row",
            "fields": {"header_row": "true", "columns": _STATE.header},
        }

    if "timestamp" not in record and "ts" not in record:
        return None

    timestamp = common.parse_syslog_ts(record.get("timestamp", record.get("ts", "")))
    message = record.get("message", record.get("msg", "CSV event"))

    fields = {k: v for k, v in record.items()
              if k not in ("timestamp", "ts", "message", "msg", "severity", "level", "category")}

    return {
        "timestamp": timestamp or common.now_iso(),
        "category": common._norm_category(record.get("category", "network")),
        "severity": common._norm_severity(record.get("severity", record.get("level", "info"))),
        "message": message,
        "client_ip": record.get("src_ip", record.get("client_ip")) or common.find_ip(stripped),
        "fields": fields,
    }