"""Prefilter — the rule-based gate that decides what reaches the LLM layer.

Sends only events worth the analyst's (or the LLM's) attention, which keeps
LLM cost bounded and the summary focused (PS26156-g: "reduced analyst
development effort"). The threshold is configurable per severity.
"""

from __future__ import annotations

from typing import Dict, List

from pipeline.batcher import Event


class Prefilter:
    """Rule-based escalation gate.

    ``rules`` is a list of ``(field_path, matcher, min_severity)`` or simply
    a callable ``(event) -> severity_hint``. Default behaviour: only pass
    events at/above ``min_severity`` unless a rule explicitly catches them.
    """

    def __init__(self, min_severity: str = "error",
                 always_pass_categories: tuple = ("flow", "vpn")) -> None:
        self.min_severity = min_severity
        self.always_pass_categories = always_pass_categories

    def should_pass(self, event: Event) -> bool:
        """Decide whether ``event`` should be sent to the LLM analysis layer."""
        if event.category in self.always_pass_categories:
            # Flow/VPN events carry module findings; the LLM correlates them.
            return bool(event.module_findings)
        return event.severity_rank() >= self._rank(self.min_severity)

    @staticmethod
    def _rank(severity: str) -> int:
        order = ("info", "warning", "error", "critical")
        try:
            return order.index(severity)
        except ValueError:
            return 0

    def filter_batch(self, events: List[Event]) -> List[Event]:
        return [e for e in events if self.should_pass(e)]

    def stats(self, events: List[Event]) -> Dict[str, int]:
        passed = self.filter_batch(events)
        return {
            "in": len(events),
            "passed": len(passed),
            "dropped": len(events) - len(passed),
        }