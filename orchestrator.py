"""Orchestrator — the pipeline runner shared by the CLI and the FastAPI app.

Wires collectors → raw store → normalizer → dedup → Module A/B/C → analyzer
(prefilter gate + backend) → notifier → event store.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

from config.settings import Settings
from parsers.registry import parse  # noqa: F401  (parser registry warm-up)
from pipeline.raw_store import RawStore
from pipeline.event_store import EventStore
from pipeline.normalizer import Normalizer
from pipeline.batcher import Batcher, DedupCounter
from pipeline.prefilter import Prefilter
from modules.network_threat import ThreatDetector
from modules.entity_graph import EntityGraph
from analyzer.llm_analyzer import LLMAnalyzer, build_analyzer
from alerting.notifier import Notifier

log = logging.getLogger("trinetra")


class Orchestrator:
    """End-to-end pipeline runner; reused by CLI and FastAPI demo route."""

    def __init__(self, settings: Settings, backend_name: Optional[str] = None) -> None:
        self.settings = settings
        self._loop = asyncio.new_event_loop()  # dedicated loop for analyzer calls
        self.raw_store = RawStore(settings.path("raw_store"))
        self.event_store = EventStore(settings.path("event_store"))
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

    # ------------------------------------------------------------------ run
    def ingest(self, raw: str, source: str = "", client_id: str = "",
               host_hint: str = "") -> None:
        """Collect→normalize→dedup→modules→analyze→notify for one raw line."""
        self.stats["raw_lines"] += 1
        event = self.normalizer.normalize(raw, source, client_id, host_hint)
        if event is None:
            return
        if not self.dedup.track(event):
            self.stats["duplicates"] += 1
            return
        self.stats["events"] += 1

        # Persist the normalized UES event (searchable via API/dashboard).
        try:
            self.event_store.save(event)
        except Exception as exc:  # noqa: BLE001 — store must never kill ingestion
            log.warning("event store save failed: %s", exc)

        # Module A — flow threat detection (metadata only)
        if event.category == "flow":
            self.threats.add_event(event)
        # Module C — relationship graph wiring
        self.graph.add_event(event)
        if event.category != "flow":
            self.graph.add_auth(event)

        # Analyzer gate + backend (flow/vpn pass only when modules found)
        findings: List[Dict] = []
        flow_findings = event.module_findings.get("network_threat")
        if flow_findings:
            findings = flow_findings if isinstance(flow_findings, list) else [flow_findings]
        result = self._loop.run_until_complete(
            self.analyzer.analyze(event, findings, event.client_id))
        self.stats["analyzer_calls"] += 1
        if result.severity_override:
            event.severity = result.severity_override

    def flush_batch(self) -> List[str]:
        """Run module windows; analyze + notify findings; return alert lines."""
        alerts: List[str] = []
        window_findings = self.threats.flush()
        for finding in window_findings:
            self.stats["findings"] += 1
            self.findings_log.append(finding)
            self.graph.add_finding(finding)
            # AI gate: analyze the module finding itself (event=None).
            result = self._loop.run_until_complete(
                self.analyzer.analyze(None, [finding], self.graph.client_id))
            confidence = float(finding.get("confidence", 0))
            finding["analysis"] = result.as_dict()
            findings_alerts = self.notifier.alert(finding)
            self.stats["alerts_sent"] += sum(
                1 for r in findings_alerts if r.get("status") == "sent")
            alerts.append(f"[{finding.get('severity', 'high').upper()}] "
                          f"{finding['threat_class']} conf={confidence} "
                          f"verdict={result.verdict} ({result.store_decision})")
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


