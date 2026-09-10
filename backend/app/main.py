"""FastAPI service — TriNetra query + ingestion API.

Serves the dashboard data model from the last demo/ingestion run:

    GET  /api/health              backend + storage health
    POST /api/demo/run            run the offline demo storyline (bootstrap)
    GET  /api/dashboard           aggregate: stats + graph + threats + vpn
    GET  /api/graph               relationship graph payload (Module C)
    GET  /api/assets              impacted/internal assets
    GET  /api/assets/{ip}/relations   lateral-movement drill down (Module C)
    GET  /api/compliance/{asset_id}   CIS/NIST/ATT&CK mapping (PS26189)
    GET  /api/network-threats     latest Module A/B findings
    GET  /api/events/search       full-text search over the UES event store
    GET  /api/events/{event_id}   one UES event + raw trace (PS26156-d)
    GET  /api/clients             distinct clients in the store
    POST /api/ingest              ingest raw lines (multi-source)

Run:  uvicorn backend.app.main:app --reload
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make ``trinetra`` importable when the package is run from the repo root.
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analyzer.llm_analyzer import LLMAnalyzer  # noqa: F401  (type surface)
from config.settings import Settings, get_settings
from orchestrator import Orchestrator
from modules.entity_graph import EntityGraph

log = logging.getLogger("trinetra.api")
app = FastAPI(title="TriNetra ULPF API", version="0.1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# One shared orchestrator + graph for the dashboard after a bootstrap run.
_ORCH: Optional[Orchestrator] = None
_GRAPH: Optional[EntityGraph] = None
_settings: Settings = get_settings()

# ------------------------------------------------------------------- models


class IngestLine(BaseModel):
    raw: str
    source: str = ""
    client_id: str = ""
    host_hint: str = ""


class IngestRequest(BaseModel):
    lines: List[IngestLine] = Field(default_factory=list)
    demo: bool = False


# ------------------------------------------------------------- bootstrap


@app.post("/api/demo/run", tags=["bootstrap"])
def run_demo(reset: bool = Query(False)) -> Dict[str, Any]:
    """Run the offline demo storyline once, then serve its data."""
    global _ORCH, _GRAPH
    if reset:
        for path in (_settings.path("raw_store"), _settings.path("event_store")):
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
    _ORCH = Orchestrator(_settings)
    _GRAPH = _ORCH.graph
    from collectors.demo_feed import DemoFeed

    pcap_dir = str(_settings.path("pcap"))
    DemoFeed.generate_pcaps(pcap_dir)
    _ORCH.run_vpn_module(pcap_dir)
    for raw, source, client, host in DemoFeed().iterate():
        _ORCH.ingest(raw, source, client, host)
    _ORCH.flush_batch()
    _ORCH.stats["bootstrapped"] = True
    return {"status": "ok", **dashboard()}


# ------------------------------------------------------------------ queries


@app.get("/api/health", tags=["meta"])
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "events_stored": _ORCH.event_store.count() if _ORCH else 0,
        "analyzer": _ORCH.analyzer.status() if _ORCH else {"configured_backend": "heuristic"},
        "demo_ready": _ORCH is not None,
    }


@app.get("/api/dashboard", tags=["dashboard"])
def dashboard() -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428,
                            detail="Bootstrap first: POST /api/demo/run")
    graph_payload = _GRAPH.to_dashboard() if _GRAPH else {"nodes": [], "edges": []}
    return {
        "stats": _ORCH.stats,
        "dedup_rate": _ORCH.dedup.duplicate_rate,
        "threat_detections": _ORCH.threats.detection_counts,
        "graph": graph_payload,
        "graph_summary": _ORCH.graph.summary(),
        "vpn": {"profiles": _ORCH.vpn_profiles},
        "findings": _ORCH.findings_log[-50:],
    }


@app.get("/api/graph", tags=["module-c"])
def graph() -> Dict[str, Any]:
    if _GRAPH is None:
        raise HTTPException(status_code=428,
                            detail="Bootstrap first: POST /api/demo/run")
    return _GRAPH.to_dashboard()


@app.get("/api/assets", tags=["module-c"])
def assets() -> Dict[str, Any]:
    if _GRAPH is None:
        raise HTTPException(status_code=428,
                            detail="Bootstrap first: POST /api/demo/run")
    payload = _GRAPH.to_dashboard()
    threatened = set(_GRAPH.threatened_ip_ids())
    nodes = [n for n in payload["nodes"] if n["kind"] == "ip"]
    comm_counts: Dict[str, int] = {}
    for edge in payload["edges"]:
        if edge["kind"] == "comm":
            comm_counts[edge["source"]] = comm_counts.get(edge["source"], 0) + 1
    for node in nodes:
        node["threatened"] = node["id"] in threatened
        node["degree"] = comm_counts.get(node["id"], 0)
    return {"assets": sorted(nodes, key=lambda n: (-n["threatened"], -n["degree"]))}


@app.get("/api/assets/{asset_ip}/relations", tags=["module-c"])
def asset_relations(asset_ip: str) -> Dict[str, Any]:
    """Lateral-movement drill down for one internal asset (PS26189 graph)."""
    if _GRAPH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    payload = _GRAPH.to_dashboard()
    node = next((n for n in payload["nodes"] if n.get("id") == asset_ip), None)
    if node is None:
        raise HTTPException(status_code=404, detail=f"Asset {asset_ip} not in graph")
    edges = [e for e in payload["edges"] if asset_ip in (e["source"], e["target"])]
    findings = [f for f in _ORCH.findings_log if
                _touches(f, asset_ip)] if _ORCH else []
    return {
        "asset": node,
        "edges": edges,
        "findings": findings,
        "compliance": compliance_for_asset(asset_ip, findings),
    }


from backend.app.services.compliance import compliance_for_asset, mapping_for


@app.get("/api/compliance/{asset_id}", tags=["compliance"])
def compliance(asset_id: str) -> Dict[str, Any]:
    findings = [f for f in _ORCH.findings_log] if _ORCH else []
    return compliance_for_asset(asset_id, findings)


@app.get("/api/compliance", tags=["compliance"])
def compliance_all() -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    findings = _ORCH.findings_log
    touched = sorted({_touches_targets(f) for f in findings} - {""})
    return {"mappings": [mapping_for(f.get("threat_class")) for f in findings],
            "assets": touched,
            "findings_count": len(findings)}


@app.get("/api/network-threats", tags=["module-a"])
def network_threats(limit: int = Query(50, le=500)) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    return {"findings": _ORCH.findings_log[-limit:][::-1],
            "count": len(_ORCH.findings_log)}


@app.get("/api/clients", tags=["store"])
def clients() -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    return {"clients": _ORCH.event_store.clients()}


@app.get("/api/events/search", tags=["store"])
def search_events(
    query: str = "", source_type: str = "", severity: str = "",
    category: str = "", client_id: str = "",
    limit: int = Query(50, le=500), offset: int = 0,
) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    events = _ORCH.event_store.search(query=query, source_type=source_type,
                                      severity=severity, category=category,
                                      client_id=client_id, limit=limit, offset=offset)
    return {"total": _ORCH.event_store.count(), "limit": limit, "offset": offset,
            "events": [e.to_dict() for e in events]}


@app.get("/api/events/{event_id}", tags=["store"])
def event_detail(event_id: str) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    event = _ORCH.event_store.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    detail = event.to_dict()
    detail["raw"] = _ORCH.raw_store.get(event.trace_id) if event.trace_id else None
    detail["trace_events"] = [e.to_dict()
                              for e in _ORCH.event_store.by_trace(event.trace_id)]
    return detail


# ------------------------------------------------------------------- ingest


@app.post("/api/ingest", tags=["ingest"])
def ingest(body: IngestRequest) -> Dict[str, Any]:
    global _ORCH
    if _ORCH is None:
        _ORCH = Orchestrator(_settings)
        _GRAPH = _ORCH.graph
    accepted, failed = 0, 0
    for line in body.lines:
        try:
            _ORCH.ingest(line.raw, line.source, line.client_id, line.host_hint)
            accepted += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            log.warning("ingest failed: %s", exc)
    alerts = _ORCH.flush_batch()
    return {"accepted": accepted, "failed": failed, "alerts": alerts,
            "total": _ORCH.event_store.count()}


# ------------------------------------------------------------------- utils


def _touches(finding: Dict[str, Any], asset_ip: str) -> bool:
    return compliance_for_asset(asset_ip, [finding]).get("affected_findings") == [finding]


def _touches_targets(finding: Dict[str, Any]) -> str:
    alert = finding.get("alert", finding)
    evidence = alert.get("evidence") or {}
    return str(evidence.get("src") or alert.get("src") or "")
# ------------------------------------------------------- static dashboard
# In a bundled deployment (Docker image) the React build lives in
# frontend/dist and is served directly from the API on "/". Register this
# mount LAST so the explicit API routes above keep precedence.
_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _DIST.is_dir():
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="dashboard")
