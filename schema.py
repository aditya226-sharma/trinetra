"""TriNetra — Universal Event Schema (UES).

Every log / flow / packet-capture event that enters TriNetra is normalized
into this single JSON shape with *zero* information loss:

  * ``raw_event`` keeps the untouched original (forensic / compliance, PS26156-a).
  * ``trace_id`` losslessly links the normalized event back to the raw store (PS26156-d).
  * ``module_findings`` is the shared slot every AI module (A/B/C) writes back
    into, which is what makes cross-module correlation possible.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

SEVERITY_LEVELS = ("info", "warning", "error", "critical")
CATEGORIES = ("auth", "network", "system", "application", "vpn", "flow")

_SOURCE_RE = re.compile(r"[^a-z0-9_]+")


def new_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_trace_id(client_id: str, source_type: str, raw: str) -> str:
    """Deterministic-ish trace key: client + source + sha1 of the raw line.

    Duplicate raw lines arriving from the *same* client + source therefore
    map to the same raw-store record, which the batcher then collapses.
    """
    import hashlib

    digest = hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{_slug(client_id) or 'unknown'}::{_slug(source_type) or 'unknown'}::{digest}"


def _slug(value: str) -> str:
    return _SOURCE_RE.sub("", value.lower())


@dataclass
class Event:
    """Universal Event Schema record."""

    event_id: str
    timestamp: str
    source_type: str
    client_id: str
    client_ip: Optional[str] = None
    category: str = "network"
    severity: str = "info"
    message: str = ""
    raw_event: str = ""
    trace_id: str = ""
    fields: Dict[str, Any] = field(default_factory=dict)
    module_findings: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    def clone(self) -> "Event":
        return Event.from_dict(json.loads(self.to_json()))

    def add_finding(self, module: str, finding: Dict[str, Any]) -> None:
        """Attach a module finding (Module A / B / C output) back to the event."""
        self.module_findings[module] = finding

    def severity_rank(self) -> int:
        try:
            return SEVERITY_LEVELS.index(self.severity)
        except ValueError:
            return 0

    @property
    def is_critical(self) -> bool:
        return self.severity == "critical"


def escalate(severity: str, min_rank: str) -> str:
    """Raise a severity up to at least ``min_rank`` ("info" < ... < "critical")."""
    ranks = list(SEVERITY_LEVELS)
    try:
        current = ranks.index(severity)
    except ValueError:
        current = 0
    target = ranks.index(min_rank)
    return ranks[max(current, target)]