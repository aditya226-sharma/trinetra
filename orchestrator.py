"""Orchestrator — the pipeline runner shared by the CLI and the FastAPI app.

Wires collectors → raw store → normalizer → dedup → Module A/B/C → analyzer
(prefilter gate + backend) → notifier → event store.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.settings import Settings
from parsers.registry import parse  # noqa: F401  (parser registry warm-up)
from pipeline.raw_store import RawStore
from pipeline.event_store import EventStore
from pipeline.client_store import ClientStore
from pipeline.normalizer import Normalizer, SKIPPED
from pipeline.batcher import Batcher, DedupCounter
from pipeline.prefilter import Prefilter
from modules.network_threat import ThreatDetector
from modules.entity_graph import EntityGraph
from analyzer.llm_analyzer import LLMAnalyzer, build_analyzer
from alerting.notifier import Notifier
from schema import (CATEGORIES, SEVERITY_LEVELS, Event, make_trace_id,
                    new_uuid, utc_now)

log = logging.getLogger("trinetra")

_CATEGORY_BY_SOURCE = {
    "windows_event_log": "system",
    "macos_unified_log": "system",
    "macos_system_log": "system",
    "file_log": "application",
    "syslog": "system",
    "agent": "system",
}


def _parse_utc_ts(value: str) -> str:
    """Normalize an ISO timestamp (offset-aware or Z) to UTC ``Z`` form.

    Also clamps timestamps more than 10 minutes ahead of the wall clock:
    a client whose clock runs fast (or a macOS ``log`` database skewed after
    a clock rollback) otherwise pollutes ``last_seen`` and the dashboard
    sort order with future dates.
    """
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt > datetime.now(timezone.utc) + timedelta(minutes=10):
            return utc_now()
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return utc_now()


def _slug_source(value: str) -> str:
    """UES source_type: lowercase [a-z0-9_], never empty."""
    import re

    return re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_") or "agent"


class Orchestrator:
    """End-to-end pipeline runner; reused by CLI and FastAPI demo route."""

    def __init__(self, settings: Settings, backend_name: Optional[str] = None) -> None:
        self.settings = settings
        self._loop = asyncio.new_event_loop()  # dedicated loop for analyzer calls
        # uvicorn runs sync ingest endpoints on a threadpool: serialize every
        # run_until_complete on the shared loop or concurrent threads raise
        # ``RuntimeError: This event loop is already running``.
        self._loop_lock = threading.Lock()
        self.raw_store = RawStore(settings.path("raw_store"))
        self.event_store = EventStore(settings.path("event_store"))
        self.client_store = ClientStore(settings.path("event_store"))
        self.normalizer = Normalizer(self.raw_store,
                                     default_client_id=settings.get("agent.client_id", "trinetra-core"))
        self.batcher = Batcher(
            window_seconds=float(settings.get("events.batch_window_s", 2.0)),
            max_events=int(settings.get("events.batch_max", 500)),
        )
        self.dedup = DedupCounter()
        self.threats = ThreatDetector()
        self.graph = EntityGraph(client_id=settings.get("agent.client_id", "trinetra-core"))
        self.analyzer: LLMAnalyzer = (
            build_analyzer(settings) if backend_name is None
            else LLMAnalyzer(backend=backend_name,
                             prefilter=Prefilter(min_severity=settings.get("llm.min_severity", "error")))
        )
        self.notifier = Notifier()
        self.vpn_profiles: List[Dict] = []
        self.stats = {"raw_lines": 0, "events": 0, "duplicates": 0, "findings": 0,
                      "alerts_sent": 0, "analyzer_calls": 0}
        self.findings_log: List[Dict] = []
        self.alerts_log: List[Dict] = []

    # ------------------------------------------------------------------ run
    def ingest(self, raw: str, source: str = "", client_id: str = "",
               host_hint: str = "") -> str:
        """Collect→normalize→dedup→modules→analyze→notify for one raw line.

        Returns the outcome so callers can report honest accounting:
        ``"stored"``, ``"duplicate"`` (deduped), ``"invalid"`` (line could
        not be normalized, e.g. blank input), or ``"ignored"`` (consumed but
        not an event, e.g. a CSV header row).
        """
        self.stats["raw_lines"] += 1
        event = self.normalizer.normalize(raw, source, client_id, host_hint)
        if event is None:
            return "invalid"
        if event is SKIPPED:
            return "ignored"
        return self._finalize_event(event)

    def ingest_normalized(self, item: Dict[str, Any],
                          default_client_id: Optional[str] = None) -> str:
        """Ingest a pre-normalized LogEntry-shaped dict (my log-agent on any
        machine). The agent already structured the event, so this skips raw
        parsing and builds the UES Event directly, mapping:

            metadata.host   -> client_id     timestamp (offset-aware) -> UTC Z
            source          -> source_type   level debug/verbose -> severity info
            message         -> message       metadata + channel    -> fields
            raw / message   -> raw_event

        ``default_client_id`` lets a per-machine agent token pin the identity:
        when set it wins over ``item.client_id`` / ``metadata.host`` so a
        token minted for one machine cannot impersonate another.

        Then runs the shared dedup -> store -> modules -> analyzer pipeline.
        Returns "stored" | "duplicate" | "invalid".
        """
        if not isinstance(item, dict) or not str(item.get("message") or "").strip():
            return "invalid"

        metadata = item.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        source = _slug_source(str(item.get("source") or "agent"))
        level = str(item.get("level") or "info").lower()
        severity = {"debug": "info", "verbose": "info"}.get(level, level)
        if severity not in SEVERITY_LEVELS:
            severity = "info"

        category = str(item.get("category") or "").lower()
        if category not in CATEGORIES:
            category = _CATEGORY_BY_SOURCE.get(source, "system")

        # A live vpn event carries the agent's freshly-assessed tunnel/IPsec
        # posture; hold it out of the event fields (nested blob) and apply it
        # to Module B's profile list after the event is finalized.
        vpn_profiles = None
        if category == "vpn":
            vpn_profiles = metadata.get("profiles") or item.get("profiles")
            if isinstance(vpn_profiles, list) and vpn_profiles:
                metadata = {k: v for k, v in metadata.items() if k != "profiles"}

        client_id = str(default_client_id
                        or item.get("client_id")
                        or metadata.get("host")
                        or self.settings.get("agent.client_id", "trinetra-core")).strip()
        client_id = client_id or "trinetra-core"

        raw_event = str(item.get("raw") or item.get("message") or "")
        event = Event(
            event_id=str(item.get("event_id") or new_uuid()),
            timestamp=_parse_utc_ts(str(item.get("timestamp") or "")),
            source_type=source,
            client_id=client_id,
            client_ip=str(metadata.get("client_ip") or ""),
            category=category,
            severity=severity,
            message=str(item.get("message") or ""),
            raw_event=raw_event,
            trace_id=make_trace_id(client_id, source, raw_event),
            fields=dict(metadata),
        )
        if item.get("channel"):
            event.fields.setdefault("channel", str(item["channel"]))
        if item.get("client_id") and "host" not in event.fields:
            event.fields["host"] = item.get("client_id")
        if raw_event:
            try:
                self.raw_store.append(event.trace_id, event.client_id,
                                      event.source_type, raw_event)
            except Exception as exc:  # noqa: BLE001
                log.warning("raw store append failed: %s", exc)
        outcome = self._finalize_event(event)
        if category == "vpn" and vpn_profiles is not None:
            self.set_vpn_profiles(vpn_profiles)
        return outcome

    def _finalize_event(self, event: Event) -> str:
        """Dedup -> annotate stats -> persist -> modules -> analyzer.

        Shared by the raw-line ingest path and the normalized agent path so
        both routes behave identically downstream.
        """
        if not self.dedup.track(event):
            self.stats["duplicates"] += 1
            return "duplicate"
        self.stats["events"] += 1

        # SOC policy gate (watchlist / blocklist / custom rules). Runs before
        # persistence so a blocklist hit can flag the stored event; policy
        # failures never abort ingestion.
        soc = getattr(self, "soc", None)
        if soc is not None:
            try:
                soc.evaluate_event(event)
            except Exception as exc:  # noqa: BLE001
                log.warning("soc policy run failed: %s", exc)

        # Persist the normalized UES event (searchable via API/dashboard).
        try:
            self.event_store.save(event)
        except Exception as exc:  # noqa: BLE001 — store must never kill ingestion
            log.warning("event store save failed: %s", exc)
            return "invalid"

        # Refresh the client registry presence (best-effort; never fatal).
        try:
            self.client_store.touch(
                client_id=event.client_id,
                timestamp=event.timestamp,
                source_type=event.source_type,
                hostname=str(event.fields.get("host") or event.client_id),
                platform=str(event.fields.get("platform") or ""),
                agent_version=str(event.fields.get("agent_version") or ""),
                ip=str(event.client_ip or ""),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("client registry touch failed: %s", exc)

        # Module A — flow threat detection (metadata only)
        if event.category == "flow":
            self.threats.add_event(event)
        # Module C — relationship graph wiring
        self.graph.add_event(event)
        if event.category != "flow":
            self.graph.add_auth(event)

        # Stream live to dashboard SSE subscribers (optional, set by main).
        sink = getattr(self, "stream", None)
        if sink is not None:
            try:
                sink.publish(event.to_dict())
            except Exception as exc:  # noqa: BLE001
                log.warning("stream publish failed: %s", exc)

        # Analyzer gate + backend (flow/vpn pass only when modules found)
        findings: List[Dict] = []
        flow_findings = event.module_findings.get("network_threat")
        if flow_findings:
            findings = flow_findings if isinstance(flow_findings, list) else [flow_findings]
        with self._loop_lock:
            try:
                result = self._loop.run_until_complete(
                    self.analyzer.analyze(event, findings, event.client_id))
            except Exception as exc:  # noqa: BLE001 — fail soft, never 500
                log.warning("analyzer failed on %s: %s", event.event_id, exc)
                result = None
        self.stats["analyzer_calls"] += 1
        if result and result.severity_override:
            event.severity = result.severity_override
        return "stored"

    def flush_batch(self) -> List[str]:
        """Run module windows; analyze + notify findings; return alert lines."""
        alerts: List[str] = []
        window_findings = self.threats.flush()
        for finding in window_findings:
            self.stats["findings"] += 1
            self.findings_log.append(finding)
            self.graph.add_finding(finding)
            # M3: persist the module finding back onto the source flow events
            # so /api/events/search?threat_class= returns correlated events.
            try:
                self.event_store.attach_findings(
                    (finding.get("event_ids") or
                     ([finding.get("flow_id")] if finding.get("flow_id") else [])),
                    "network_threat", finding)
            except Exception as exc:  # noqa: BLE001 — never kill the batch
                log.warning("finding attach failed: %s", exc)
            # AI gate: analyze the module finding itself (event=None).
            with self._loop_lock:
                try:
                    result = self._loop.run_until_complete(
                        self.analyzer.analyze(None, [finding], self.graph.client_id))
                except Exception as exc:  # noqa: BLE001 — fail soft, never 500
                    log.warning("analyzer failed on finding %s: %s",
                                finding.get("threat_class", "?"), exc)
                    result = None
            try:
                confidence = float(finding.get("confidence", 0))
            except (TypeError, ValueError):
                confidence = 0.0
            finding["analysis"] = result.as_dict() if result else {}
            findings_alerts = self.notifier.alert(finding)
            self.stats["alerts_sent"] += sum(
                1 for r in findings_alerts if r.get("status") == "sent")
            self.alerts_log.append({
                "timestamp": finding.get("alert", {}).get("timestamp") or
                             finding.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "threat_class": finding["threat_class"],
                "severity": finding.get("severity", "high"),
                "confidence": round(float(confidence), 3),
                "verdict": result.verdict if result else "error",
                "store_decision": result.store_decision if result else "keep",
                "evidence": finding.get("alert", {}).get("evidence", {}),
                "client_id": finding.get("client_id") or "",
                "flows": (finding.get("alert", {}).get("flows") or
                          finding.get("alert", {}).get("flow_id") or ""),
            })
            # SOC triage case + external delivery fan-out for this finding.
            soc = getattr(self, "soc", None)
            if soc is not None:
                try:
                    soc.record_flow_finding(finding)
                except Exception as exc:  # noqa: BLE001 — never kill the batch
                    log.warning("soc finding record failed: %s", exc)
            verdict = result.verdict if result else "error"
            store_decision = result.store_decision if result else "keep"
            alerts.append(f"[{finding.get('severity', 'high').upper()}] "
                          f"{finding['threat_class']} conf={confidence} "
                          f"verdict={verdict} ({store_decision})")
            if len(self.findings_log) > 2000:
                self.findings_log.pop(0)
            if len(self.alerts_log) > 2000:
                self.alerts_log.pop(0)
        return alerts

    # ----------------------------------------------------------------- pcap
    def run_vpn_module(self, pcap_dir: str) -> Dict:
        """Module B over a directory of .pcap files; stores profiles + alerts."""
        from modules.vpn_assessment import assess_vpn_directory

        results = assess_vpn_directory(pcap_dir)
        self.vpn_profiles = []
        for result in results:
            profile = result.get("profile", {})
            self.vpn_profiles.append({
                "file": Path(result.get("source_path", "capture")).name,
                "ike_version": profile.get("ike_version"),
                "encryption": profile.get("encryption"),
                "key_length": profile.get("key_length"),
                "integrity": profile.get("integrity"),
                "prf": profile.get("prf"),
                "dh_group": profile.get("dh_group"),
                "pfs": profile.get("pfs"),
                "mode": profile.get("mode"),
                "sa_lifetime": profile.get("sa_lifetime"),
                "replay": profile.get("replay"),
                "security_score": result.get("security_score"),
                "risk_level": result.get("risk_level"),
                "confidence": result.get("confidence"),
                "recommendations": result.get("recommendations", [])[:4],
            })
            weak = int(result.get("security_score", 100)) < 50
            severity = result.get("risk_level", "high") if weak else "info"
            self.graph.add_finding({
                "threat_class": "weak_ipsec_config" if weak else "vpn_ok",
                "severity": severity,
                "confidence": result.get("confidence", 0.8),
                "alert": {
                    "flow_id": f"vpn::{profile.get('file', 'capture')}",
                    "threat_class": "weak_ipsec_config" if weak else "vpn_ok",
                    "confidence": result.get("confidence", 0.8),
                    "severity": severity,
                    "evidence": {
                        "gateway": "vpn-gw-01",
                        "peer": profile.get("file", "?"),
                        "score": result.get("security_score"),
                        "risk": result.get("risk_level"),
                        "encryption": profile.get("encryption"),
                        "integrity": profile.get("integrity"),
                    },
                },
            })
        self.stats["vpn_profiles"] = len(self.vpn_profiles)
        return {"profiles_count": len(self.vpn_profiles),
                "profiles": self.vpn_profiles}

    # -------------------------------------------------------------- live vpn
    VPN_PROFILE_KEYS = (
        "file", "interface", "tunnel", "state", "policy",
        "ike_version", "encryption", "key_length", "integrity", "prf",
        "dh_group", "pfs", "mode", "sa_lifetime", "replay",
        "security_score", "risk_level", "confidence", "recommendations",
    )

    def set_vpn_profiles(self, profiles: List[Dict],
                         source_label: str = "live-agent") -> int:
        """Replace Module B's profile list from a live agent vpn event.

        Sanitizes incoming dicts to the superset of keys the demo path and the
        dashboard card understand, records a matching graph finding, and keeps
        ``stats["vpn_profiles"]`` in agreement with the current list.
        """
        clean: List[Dict] = []
        for p in profiles or []:
            if not isinstance(p, dict):
                continue
            entry = {k: p[k] for k in self.VPN_PROFILE_KEYS if k in p}
            score = entry.get("security_score")
            entry.setdefault("source", source_label)
            clean.append(entry)
            if isinstance(score, (int, float)) and score < 50:
                self.graph.add_finding({
                    "threat_class": "weak_ipsec_config",
                    "severity": "high",
                    "confidence": entry.get("confidence", 0.85),
                    "alert": {
                        "flow_id": f"vpn::{entry.get('interface') or entry.get('file', '?')}",
                        "threat_class": "weak_ipsec_config",
                        "confidence": entry.get("confidence", 0.85),
                        "severity": "high",
                        "evidence": dict(entry),
                    },
                })
        if clean:
            self.vpn_profiles = clean
            self.stats["vpn_profiles"] = len(clean)
        return len(clean)

    # ---------------------------------------------------------------- report
    def summary(self) -> Dict:
        return {
            "stats": self.stats,
            "dedup_rate": round(self.dedup.duplicate_rate, 3),
            "threat_detections": self.threats.detection_counts,
            "graph": self.graph.summary(),
            "vpn": {"profiles": self.vpn_profiles},
            "analyzer": self.analyzer.status(),
            "findings": self.findings_log[-20:],
        }

    def rebuild_derived(self) -> None:
        """Rebuild in-memory graph + threat state from persisted events.

        The graph and threat detector are memory-only, so after a container
        restart the dashboard would report events stored but an empty entity
        graph / threat radar. Replaying the store into those modules (without
        re-running dedup, the analyzer, or notifiers) restores them.
        """
        import logging
        log = logging.getLogger("trinetra.orchestrator")
        log.info("rebuilding graph/threats from %d persisted events",
                 self.event_store.count())
        events = 0
        for event in self.event_store.iter_all():
            self.graph.add_event(event)
            if event.category == "flow":
                self.threats.add_event(event)
            elif event.category != "flow":
                self.graph.add_auth(event)
            events += 1
            # The detector buffers every flow in _flows: flush periodically so
            # a large store can't balloon memory or keep one giant window.
            # Mirrors live batches (~500 events) so findings stay comparable.
            if events % 500 == 0:
                self._overlay_threat_findings(log)
        self._overlay_threat_findings(log)
        log.info("replayed %d events into derived state", events)

    def _overlay_threat_findings(self, log: Any = None) -> None:
        """Flush the detector's current window and overlay onto the graph,
        mirroring the stats + alert bookkeeping live flush_batch performs so
        a restart rebuild yields an identical dashboard/alerts surface."""
        for finding in self.threats.flush():
            self.graph.add_finding(finding)
            self.stats["findings"] += 1
            self.findings_log.append(finding)
            if len(self.findings_log) > 2000:
                self.findings_log.pop(0)
            analysis = finding.get("analysis") or {}
            try:
                confidence = float(finding.get("confidence", 0))
            except (TypeError, ValueError):
                confidence = 0.0
            self.alerts_log.append({
                "timestamp": (finding.get("alert", {}).get("timestamp") or
                              finding.get("timestamp") or
                              time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                "threat_class": finding.get("threat_class", "unknown"),
                "severity": finding.get("severity", "high"),
                "confidence": round(confidence, 3),
                "verdict": analysis.get("verdict"),
                "store_decision": analysis.get("store_decision", "keep"),
                "evidence": finding.get("alert", {}).get("evidence", {}),
                "client_id": finding.get("client_id") or "",
                "flows": (finding.get("alert", {}).get("flows") or
                          finding.get("alert", {}).get("flow_id") or ""),
            })
            if len(self.alerts_log) > 2000:
                self.alerts_log.pop(0)


