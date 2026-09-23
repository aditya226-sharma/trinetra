"""Normalizer — the only code that touches raw data.

For every incoming raw line:
  1. preserve the raw line losslessly in the RawStore (keyed by ``trace_id``),
  2. run the appropriate registered parser,
  3. emit a fully-formed Universal Event Schema (UES) record.

Nothing downstream of this module ever sees raw input again, which is what
makes the rest of the platform source-agnostic (PS26156-b/c/d).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import parsers  # noqa: F401  (importing registers all parsers)
from parsers import registry
from parsers.registry import guess_source_type, parse_any
from pipeline.raw_store import RawStore
from schema import Event, make_trace_id, new_uuid, utc_now

log = logging.getLogger("trinetra.normalizer")

#: Sentinel returned by :meth:`Normalizer.normalize` when a line was consumed
#: but produced no event (e.g. a CSV header row). Not ``None`` so the
#: orchestrator can tell "skip" apart from "invalid (blank)".
SKIPPED = object()


def _clamp_ts(value: object) -> str:
    """Normalize an ISO timestamp to UTC ``Z`` form, clamping values more than
    10 minutes ahead of the wall clock (a fast client clock otherwise pollutes
    ``last_seen`` and the dashboard sort order with future dates). Mirrors
    ``orchestrator._parse_utc_ts`` without the import cycle."""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt > datetime.now(timezone.utc) + timedelta(minutes=10):
            return utc_now()
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return utc_now()


class Normalizer:
    def __init__(self, raw_store: RawStore, default_client_id: str = "trinetra-core") -> None:
        self.raw_store = raw_store
        self.default_client_id = default_client_id

    def normalize(self, raw: str, source: str = "", client_id: str = "",
                  host_hint: str = "") -> Optional[Event]:
        """Return a UES ``Event``, ``None`` for blank/empty lines, or
        ``SKIPPED`` for lines consumed without producing an event."""
        if not raw or not raw.strip():
            return None

        source_type = guess_source_type(raw, source)
        client_id = client_id or self.default_client_id
        trace_id = make_trace_id(client_id, source_type, raw)

        # 1. Lossless preservation happens BEFORE parsing — always.
        self.raw_store.append(trace_id, client_id, source_type, raw)

        # 2. Parse through the registry (fall back to generic).
        parsed = registry.parse(raw, source_type, client_id, host_hint)
        if parsed is None:
            parsed = parse_any(raw, source_type, client_id, host_hint)
        if parsed.get("_skip"):
            # Consumed (e.g. CSV header row) — preserve raw, emit nothing.
            return SKIPPED

        # 3. Assemble the UES event.
        fields = dict(parsed.get("fields") or {})
        message = parsed.get("message") or raw.strip()
        return Event(
            event_id=new_uuid(),
            timestamp=_clamp_ts(parsed.get("timestamp")),
            source_type=source_type,
            client_id=client_id,
            client_ip=parsed.get("client_ip"),
            category=parsed.get("category") or "system",
            severity=parsed.get("severity") or "info",
            message=message,
            raw_event=raw,
            trace_id=trace_id,
            fields=fields,
        )