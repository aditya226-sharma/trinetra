"""Offline heuristic analyzer — the default backend.

Deterministic, explainable rules over the already-normalized UES event plus
module findings. Produces the same :class:`AnalysisResult` shape as LLM
backends, so the pipeline and UI are backend-agnostic. Used in the live demo
and CI (no API key, no network).
"""

from __future__ import annotations

from typing import Any, Dict, List

from analyzer.backend import AnalysisResult

# Severity ordering for escalation decisions.
_SEVERITY_RANK = {"debug": 0, "info": 1, "notice": 2, "warning": 3,
                  "error": 4, "critical": 5}
_SEVERITIES = list(_SEVERITY_RANK)


def _severity_rank(value: str) -> int:
    return _SEVERITY_RANK.get(str(value).lower(), 1)


class HeuristicBackend:
    name = "heuristic"

    async def analyze_event(self, event: Any, modules: List[Dict[str, Any]],
                            client_id: str = "trinetra-core") -> AnalysisResult:
        reasoning: List[str] = []
        actions: List[str] = []
        verdict = "normal"
        confidence = 0.4
        severity_override = None
        store_decision = "store"

        findings = modules or []
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if str(f.get("severity")).lower() in ("high", "warning")]

        if critical:
            verdict = "malicious"
            confidence = max(confidence, max(float(f.get("confidence", 0.8))
                                             for f in critical))
            store_decision = "quarantine"
            severity_override = "critical"
            for f in critical[:3]:
                reasoning.append(
                    f"Module finding -> {f.get('threat_class', 'tbd')} "
                    f"(conf {float(f.get('confidence', 0)):.2f})")
            actions.append("Block flagged source/destination at the perimeter; open investigation ticket.")
        elif high:
            verdict = "suspicious"
            confidence = max(confidence, max(float(f.get("confidence", 0.6))
                                             for f in high))
            store_decision = "review"
            for f in high[:2]:
                reasoning.append(
                    f"Module finding -> {f.get('threat_class', 'tbd')} "
                    f"(conf {float(f.get('confidence', 0)):.2f})")
            actions.append("Escalate to analyst triage queue; correlate with related flow records.")

        if verdict == "normal":
            event_keywords = {
                "sshd": "ssh", "login": "auth", "failed": "auth",
                "password": "auth", "sudo": "auth", "ufw": "firewall",
                "blocked": "firewall", "DROP": "firewall", "denied": "firewall",
            }
            message = str(getattr(event, "message", "") or "").lower()
            fields = getattr(event, "fields", {}) or {}
            body = " ".join(str(v).lower() for v in fields.values()) + " " + message

            hit_cats = {v for k, v in event_keywords.items() if k in body}
            severity_rank = _severity_rank(getattr(event, "severity", "info"))
            if "auth" in hit_cats:
                reasoning.append("Authentication-related event observed (login/brute-force family).")
                if "failed" in body or "invalid" in body or severity_rank >= 3:
                    verdict = "suspicious"
                    confidence = 0.7
                    store_decision = "review"
                    actions.append("Monitor repeated auth failures from " +
                                   str(fields.get("src_ip") or "unknown source")
                                   + "; enable throttle/rate-limit.")
                else:
                    confidence = max(confidence, 0.55)
            if "firewall" in hit_cats:
                reasoning.append("Firewall decision observed (allow/deny accounting).")
                actions.append("Audit firewall rule-set drift and logging coverage.")
            if severity_rank >= 4:
                severity_override = "critical" if severity_rank >= 5 else "high"
                reasoning.append("Native severity already elevated.")

        return AnalysisResult(
            verdict=verdict,
            confidence=round(min(confidence, 1.0), 2),
            summary=_summary(verdict, reasoning),
            reasoning=reasoning or ["No module signals on this normal event."],
            actions=actions or ["No automated action required."],
            severity_override=severity_override,
            metadata={"backend": self.name, "client_id": client_id},
            store_decision=store_decision,
        )

    def status(self) -> Dict[str, Any]:
        return {"name": self.name, "kind": "offline-rules", "latency_ms": 0,
                "healthy": True, "note": "deterministic, no LLM calls"}


def _summary(verdict: str, reasoning: List[str]) -> str:
    if verdict == "malicious":
        return "Malicious activity confirmed by module evidence — mitigate now."
    if verdict == "suspicious":
        return "Suspicious behaviour detected — analyst review recommended."
    return "No security signals; routine log ingestion."