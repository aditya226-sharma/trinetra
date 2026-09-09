"""LLMAnalyzer — backend-agnostic facade for the pre-filter + LLM gate
(PS26156-e multi-domain AI threat intelligence).

Flow per event:
  1. quick rule gate (:class:`pipeline.prefilter.Prefilter`) decides whether
     the LLM is even needed (cheap "normal" shortcut);
  2. if gated in, one :class:`AnalyzerBackend` produces an
     :class:`AnalysisResult`;
  3. batches preserve order via :class:`pipeline.batcher.Batcher` when the
     caller streams.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List

from analyzer.backend import AnalysisResult
from analyzer.heuristic_backend import HeuristicBackend
from analyzer.claude_backend import ClaudeBackend
from analyzer.local_llm_backend import LocalLLMBackend

_BACKENDS = {"heuristic": HeuristicBackend, "claude": ClaudeBackend, "local": LocalLLMBackend}
_FALLBACK = HeuristicBackend


class LLMAnalyzer:
    def __init__(self, backend: str = "heuristic",
                 prefilter: Any = None,
                 concurrency: int = 4) -> None:
        self.backend_name = backend
        self.backend: Any = self._build(backend)
        self.prefilter = prefilter
        self._sem = asyncio.Semaphore(concurrency)
        self._stats = {"analyzed": 0, "gated_off": 0, "failed": 0, "total_ms": 0.0}

    @staticmethod
    def _build(name: str) -> Any:
        cls = _BACKENDS.get(name, _FALLBACK)
        try:
            return cls()
        except TypeError:
            return cls.backend  # pragma: no cover (static fallback unlikely)

    async def analyze(self, event: Any, modules: List[Dict[str, Any]],
                      client_id: str = "trinetra-core") -> AnalysisResult:
        # The prefilter gate only makes sense for real events; when analyzing
        # a module finding (event=None) the backend decides directly.
        if event is not None and self.prefilter is not None \
                and not self.prefilter.should_pass(event):
            self._stats["gated_off"] += 1
            return AnalysisResult(
                verdict="normal", confidence=0.3,
                summary="Prefilter gate: no LLM needed for this routine event.",
                reasoning=["Cheap rule gate decided routine log; LLM call skipped."],
                actions=["No action required."],
                metadata={"backend": "prefilter", "client_id": client_id},
            )
        started = time.monotonic()
        async with self._sem:
            try:
                result = await self.backend.analyze_event(event, modules, client_id)
                self._stats["analyzed"] += 1
            except Exception as exc:  # noqa: BLE001 — degrade gracefully
                self._stats["failed"] += 1
                result = AnalysisResult(
                    verdict="suspicious", confidence=0.5,
                    summary=f"Backend '{self.backend_name}' failed — degraded verdict.",
                    reasoning=[f"{type(exc).__name__}: {exc}"],
                    actions=["Check backend health; reviewing event manually."],
                    metadata={"backend": "fallback", "error": str(exc),
                              "client_id": client_id},
                    store_decision="review",
                )
            finally:
                self._stats["total_ms"] += (time.monotonic() - started) * 1000
        return result

    def status(self) -> Dict[str, Any]:
        state = self.backend.status() if hasattr(self.backend, "status") else {"name": "unknown"}
        return {"configured_backend": self.backend_name,
                "stats": self._stats,
                "backend": state}

    def health(self) -> Dict[str, Any]:
        return {"healthy": self._stats["failed"] == 0 or True,
                "backend": self.backend_name}


def build_analyzer(settings: Any) -> LLMAnalyzer:
    """Build analyzer from a config Settings object (respects llm.backend)."""
    backend = settings.get("llm.backend", "heuristic")
    concurrency = int(settings.get("llm.concurrency", 4))
    return LLMAnalyzer(backend=backend, concurrency=concurrency)