"""Local model backend — OpenAI-compatible chat server (GGUF / Ollama / vLLM).

Speaks the common ``/v1/chat/completions`` dialect via standard-library HTTP,
so running a private small model on the GPU node is a drop-in.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError

from analyzer.backend import AnalysisResult

DEFAULT_URL = os.environ.get("TRINETRA_LOCAL_LLM_URL", "http://127.0.0.1:11434/v1/chat/completions")
DEFAULT_MODEL = os.environ.get("TRINETRA_LOCAL_LLM_MODEL", "qwen2.5-coder:7b")

SYSTEM_PROMPT = (
    "You are TriNetra, a defensive SIEM analyst. Reply with a single JSON object: "
    "{verdict: normal|suspicious|malicious, confidence: 0..1, summary, reasoning: [..], "
    "actions: [..], severity_override: high|critical|null, store_decision: store|review|quarantine}. "
    "Never decrypt payloads."
)


class LocalLLMBackend:
    name = "local"

    def __init__(self, url: str = DEFAULT_URL, model: str = DEFAULT_MODEL) -> None:
        self.url = url
        self.model = model

    async def analyze_event(self, event: Any, modules: List[Dict[str, Any]],
                            client_id: str = "trinetra-core") -> AnalysisResult:
        event_payload = {
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
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(event_payload)},
            ],
            "temperature": 0.2,
            "max_tokens": 700,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError) as exc:
            raise RuntimeError(f"Local model unreachable at {self.url}: {exc}") from exc
        message = payload.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        return self._parse(message)

    def _parse(self, text: str) -> AnalysisResult:
        text = str(text or "").strip()
        fence = text.find("```")
        if fence != -1 and text.count("```") >= 2:
            text = text[fence:].split("```")[1]
        try:
            data = json.loads(text)
        except (ValueError, json.JSONDecodeError):
            return AnalysisResult(verdict="suspicious", confidence=0.5,
                                  summary="Local model reply not parseable.",
                                  reasoning=["Raw model reply kept in metadata."],
                                  actions=["Inspect raw model output manually."],
                                  metadata={"raw_reply": text[:2000]},
                                  store_decision="review")
        return AnalysisResult(
            verdict=str(data.get("verdict", "normal")),
            confidence=float(data.get("confidence", 0.5)),
            summary=str(data.get("summary", "")),
            reasoning=list(data.get("reasoning") or []),
            actions=list(data.get("actions") or []),
            severity_override=data.get("severity_override"),
            store_decision=str(data.get("store_decision", "store")),
            metadata={"backend": self.name, "model": self.model, **data.get("metadata", {})},
        )

    def status(self) -> Dict[str, Any]:
        return {"name": self.name, "kind": "local-openai-compatible",
                "model": self.model, "url": self.url, "healthy": True}