"""Analyzer backends — pluggable decision engine.

TriNetra keeps the LLM decision surface tiny and typed. A backend receives one
normalized UES event (plus optional module findings that already ran on it) and
returns an :class:`AnalysisResult`. Backends are interchangeable at runtime via
``LLMAnalyzer`` in :mod:`analyzer.llm_analyzer`.

Backends supplied out of the box:

  * :class:`HeuristicBackend`  — offline deterministic rules (default, no deps)
  * :class:`ClaudeBackend`     — Anthropic Messages API (urllib, zero deps)
  * :class:`LocalLLMBackend`   — any OpenAI-compatible local server (GGUF/Ollama)

The heuristic backend guarantees the demo and unit tests run fully offline while
still producing structured, explainable output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol


@dataclass
class AnalysisResult:
    """Structured result of one event's analysis."""

    verdict: str                       # "normal" | "suspicious" | "malicious"
    confidence: float                  # 0..1
    summary: str                       # one-line rationale
    reasoning: List[str] = field(default_factory=list)   # evidence bullets
    actions: List[str] = field(default_factory=list)     # recommended actions
    severity_override: Optional[str] = None               # escalate/de-escalate
    metadata: Dict[str, Any] = field(default_factory=dict)
    store_decision: str = "store"      # "store" | "review" | "quarantine"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "summary": self.summary,
            "reasoning": self.reasoning,
            "actions": self.actions,
            "severity_override": self.severity_override,
            "metadata": self.metadata,
            "store_decision": self.store_decision,
        }


class AnalyzerBackend(Protocol):
    """Contract every backend implements."""

    name: str

    async def analyze_event(self, event: Any, modules: List[Dict[str, Any]],
                            client_id: str = "trinetra-core") -> AnalysisResult:
        """Analyze one event, given any module findings attached to it."""
        ...

    def status(self) -> Dict[str, Any]:
        """Human/machine readable backend status for the dashboard."""
        ...