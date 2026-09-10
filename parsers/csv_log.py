"""CSV log parser — header-mapped rows with a headerless positional fallback.

A row is interpreted as a *header* when its first cell is neither a plausible
timestamp nor an IP address. Headers are remembered per ``(client_id, source)``
so concurrent ingests from different streams never clobber each other. Header
rows produce no event — the parser signals that with the reserved
``"_skip": True`` key so the caller can preserve the raw line without
materialising a bogus "header row" event.

Data rows without any cached header are mapped positionally using the flow
shape used by TriNetra's CSV collectors::

    timestamp, src_ip, dst_ip, proto, sport, dport, pkts, bytes, flags
"""

from __future__ import annotations

import csv
import io
import threading
from typing import Any, Dict, List, Optional, Tuple

from parsers import common
from parsers.registry import register_parser

_POSITIONAL_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "proto",
    "sport", "dport", "pkts", "bytes", "flags",
]

#: Cached header row per (client_id, source) — as narrow as possible.
_HEADERS: Dict[Tuple[str, str], List[str]] = {}
_LOCK = threading.Lock()


def _looks_like_timestamp(token: str) -> bool:
    """'Sep 12 09:00:00', '2026-09-12T09:00:00Z' and dense numerics."""
    token = token.strip()
    if not token:
        return False
    # ISO-ish (contains digits + '-' or 'T') or pure dense numeric
    if "/" in token or ":" in token or ("-" in token and any(c.isdigit() for c in token)):
        return True
    # syslog style: "Sep <day> <time>"
    parts = token.split()
    return (len(parts) >= 2 and parts[0][:3].title() in
            {"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug",
             "sep", "oct", "nov", "dec"} and parts[1].isdigit())


def _looks_like_ip(token: str) -> bool:
    """True when the whole token is one IP address."""
    return bool(common.find_ip(token)) and common.find_ip(token) == token.strip()


def _parse_csv_line(raw: str) -> Optional[List[str]]:
    row = next(csv.reader(io.StringIO(raw.rstrip("\n"))), None)
    if row is None:
        return None
    if "," not in raw or not raw.replace(",", "").strip():
        return None
    return row


def _emit_data(row: List[str], header: Optional[List[str]]) -> Optional[Dict[str, Any]]:
    """Build a UES dict from a data row using a header or positional names."""
    flat = ",".join(row)
    if header is not None and len(row) == len(header):
        record = dict(zip(header, row))
        timestamp = record.get("timestamp", record.get("ts", ""))
        if not timestamp or not _looks_like_timestamp(timestamp):
            return None
        message = record.get("message", record.get("msg", "CSV event"))
        fields = {k: v for k, v in record.items()
                  if k not in ("timestamp", "ts", "message", "msg",
                               "severity", "level", "category")}
        return {
            "timestamp": common.parse_syslog_ts(timestamp) or common.now_iso(),
            "category": common._norm_category(record.get("category", "network")),
            "severity": common._norm_severity(
                record.get("severity", record.get("level", "info"))),
            "message": message,
            "client_ip": record.get("src_ip", record.get("client_ip"))
                         or common.find_ip(flat),
            "fields": fields,
        }

    # No header: assume the canonical flow-shaped row (timestamp first).
    names = _POSITIONAL_COLUMNS if len(row) == 9 else \
        ["timestamp"] + [f"col_{i}" for i in range(1, len(row))]
    if not _looks_like_timestamp(row[0]):
        return None
    fields = {name: value for name, value in zip(names[1:], row[1:])}
    return {
        "timestamp": common.parse_syslog_ts(row[0]) or common.now_iso(),
        "category": "network",
        "severity": "info",
        "message": pretty_line(row),
        "client_ip": common.find_ip(flat),
        "fields": fields,
    }


def pretty_line(row: List[str]) -> str:
    """Human-readable event message for a positional CSV row."""
    if len(row) >= 3 and (_looks_like_ip(row[1]) or _looks_like_ip(row[2])):
        return f"{row[1]} -> {row[2]}"
    return " ".join(row)


@register_parser("csv")
def parse_csv_log(raw: str, source: str, client_id: str, host_hint: str = "") -> Optional[Dict[str, Any]]:
    try:
        row = _parse_csv_line(raw)
    except StopIteration:
        return None
    if row is None:
        return None

    stream_key = (client_id or "*", source or "*")
    with _LOCK:
        header = _HEADERS.get(stream_key)

        # Header row -> remember it, emit nothing (raw already preserved).
        if not _looks_like_timestamp(row[0]) and not _looks_like_ip(row[0]):
            clean = [c.strip().lower().replace(" ", "_") for c in row]
            _HEADERS[stream_key] = clean
            return {"_skip": True}

        if header is not None and len(row) != len(header):
            # A differently-shaped row — replace the header rather than
            # mis-mapping the old names onto unrelated columns.
            _HEADERS[stream_key] = [c.strip().lower().replace(" ", "_") for c in row]
            return {"_skip": True}

    return _emit_data(row, header)