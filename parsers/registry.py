"""Plug-and-play parser registry (PS26156-e / PS26156-i).

A parser is any callable with signature::

    fn(raw: str, source: str, client_id: str, host_hint: str = "") -> dict | None

Returned dicts are merged into the UES event (timestamp, category, severity,
message, client_ip, fields). Returning ``None`` means "I can't parse this".

``parse_any`` is the fallback that produces a usable generic event from any
orphan line, so the system degrades gracefully instead of dropping data —
the raw event is *always* preserved regardless of parsing outcome.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional

from schema import CATEGORIES, SEVERITY_LEVELS

ParserFn = Callable[[str, str, str, str], Optional[Dict[str, Any]]]

PARSERS: Dict[str, ParserFn] = {}


def register_parser(source_type: str) -> Callable[[ParserFn], ParserFn]:
    """Decorator that registers a parser function under ``source_type``."""

    def decorator(fn: ParserFn) -> ParserFn:
        PARSERS[source_type] = fn
        return fn

    return decorator


def get_parser(source_type: str) -> Optional[ParserFn]:
    return PARSERS.get(source_type)


def parse(raw: str, source: str, client_id: str, host_hint: str = "") -> Optional[Dict[str, Any]]:
    fn = get_parser(source)
    if fn is None:
        return None
    try:
        return fn(raw, source, client_id, host_hint)
    except Exception:  # never let a buggy parser kill the ingestion loop
        return None


def _clean(message: str) -> str:
    return " ".join(str(message).split()).strip()


def _norm_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in SEVERITY_LEVELS:
        return text
    mapping = {
        "emerg": "critical", "alert": "critical", "crit": "critical", "fatal": "critical",
        "err": "error", "error": "error",
        "warn": "warning", "warning": "warning",
        "notice": "info", "info": "info", "informational": "info",
        "debug": "info",
    }
    return mapping.get(text, "info")


def _norm_category(value: Any) -> str:
    text = str(value or "network").strip().lower()
    return text if text in CATEGORIES else "network"


# --------------------------------------------------------------------------
# Generic fallback — used by the normalizer when no specific parser matched.
# --------------------------------------------------------------------------
def parse_any(raw: str, source: str, client_id: str, host_hint: str = "") -> Dict[str, Any]:
    return {
        "category": "system",
        "severity": "info",
        "message": _clean(raw)[:2000],
        "client_ip": None,
        "fields": {"source": source},
    }


def guess_source_type(raw: str, source: str = "") -> str:
    """Try to detect the format of a raw line when the collector didn't tag it."""
    if source:
        return source
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        return "json"
    if "<" in raw[:6] and ">" in raw[:8]:
        return "syslog"
    if "CEF:" in raw:
        return "cef"
    if stripped and "," in stripped:
        return "csv"
    return "generic"