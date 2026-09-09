"""Claude backend — Anthropic Messages API (standard-library HTTP only).

No third-party SDK is required (urllib.request is enough). If no API key is
configured the :class:`LLMAnalyzer` falls back to the heuristic backend, so
the demo/CI never depend on network access.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError

from analyzer.backend import AnalysisResult

API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-20250514"


def _parse_result(payload: Dict[str, Any]) -> AnalysisResult:
    """Parse the strict-structured reply (verdict, confidence, ...)."""
    text = payload.get("content", "")
    if isinstance(text, list):
        text = " ".join(block.get("text", "") for block in text if isinstance(block, dict))
    text = str(text or "")
    # Strip a ```json fence if present.
    fence = text.find("```")
    if fence != -1:
        text = text[fence:].split("```")[1] if text.count("```") >= 2 else ""
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return AnalysisResult(
            verdict="suspicious", confidence=0.5,
            summary="Claude response was not parseable; treated as review item.",
            reasoning=["Raw model reply stored in metadata."],
            actions=["Manually inspect the raw model output."],
            metadata={"raw_reply": text[:2000]},
            store_decision="review",
        )
    return AnalysisResult(
        verdict=str(data.get("verdict", "normal")),
        confidence=float(data.get("confidence", 0.5)),
        summary=str(data.get("summary", "")),
        reasoning=list(data.get("reasoning") or []),
        actions=list(data.get("actions") or []),
        severity_override=data.get("severity_override"),
        store_decision=str(data.get("store_decision", "store")),
        metadata={"backend": "claude", **data.get("metadata", {})},
    )


class ClaudeBackend:
    name = "claude"

    def __init__(self, model: str = MODEL) -> None:
        self.model = model
        self.api_key: Optional[str] = os.environ.get("ANTHROPIC_API_KEY")

    async def analyze_event(self, event: Any, modules: List[Dict[str, Any]],
                            client_id: str = "trinetra-core") -> AnalysisResult:
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set — use heuristic backend.")
        system = (
            "You are TriNetra, a defensive security analyst. Given ONE normalized "
            "log/flow event and attached module findings, answer with a single JSON "
            "object: {verdict: normal|suspicious|malicious, confidence: 0..1, "
            "summary, reasoning: [..], actions: [..], severity_override: high|critical|null, "
            "store_decision: store|review|quarantine}. Never decrypt payloads."
        )
        user = {
            "client_id": client_id,
            "event": {
                "source_type": getattr(event, "source_type", ""),
                "category": getattr(event, "category", ""),
                "severity": getattr(event, "severity", ""),
                "timestamp": getattr(event, "timestamp", None),
                "message": getattr(event, "message", ""),
                "fields": getattr(event, "fields", {}),
            },
            "module_findings": modules,
        }
        body = json.dumps({
            "model": self.model,
            "max_tokens": 900,
            "system": system,
            "messages": [{"role": "user", "content": json.dumps(user)}],
        }).encode("utf-8")
        req = urllib.request.Request(
            API_URL, data=body, method="POST",
            headers={"x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError) as exc:
            raise RuntimeError(f"Claude API call failed: {exc}") from exc
        return _parse_result(payload)

    def status(self) -> Dict[str, Any]:
        return {"name": self.name, "kind": "anthropic-api", "model": self.model,
                "healthy": bool(self.api_key),
                "note": "configured" if self.api_key else "missing ANTHROPIC_API_KEY"}