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
    GET  /api/events/stream       SSE live tail (requires bearer token)
    GET  /api/clients             distinct clients in the store
    POST /api/ingest              ingest raw lines (multi-source, admin only)
    POST /api/ingest-events       ingest pre-normalized agent LogEntry dicts
                                  (shared X-Agent-Token, rate-limited)
    POST /api/auth/login          dashboard login -> bearer token
    POST /api/auth/register       create users (admin only)

Dashboard data routes require a bearer token; admin-only routes also require
role ``admin``. Run:  uvicorn backend.app.main:app --reload
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make ``trinetra`` importable when the package is run from the repo root.
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from analyzer.llm_analyzer import LLMAnalyzer  # noqa: F401  (type surface)
from backend.app.auth import (ensure_admin, require_admin, require_auth,
                              require_token_query)
from backend.app.auth import router as auth_router
from backend.app.stream import hub
from config.settings import Settings, get_settings
from orchestrator import Orchestrator
from modules.entity_graph import EntityGraph
from pipeline.retention import start_retention_loop

log = logging.getLogger("trinetra.api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Boot the shared orchestrator, seed the first admin account and start
    the retention prune loop.

    The orchestrator is initialized eagerly so reads (dashboard, clients,
    events/search, health counts) reflect already-persisted data without a
    demo/ingest bootstrap first.
    """
    global _ORCH, _GRAPH
    if _ORCH is None:
        _ORCH = Orchestrator(_settings)
        _GRAPH = _ORCH.graph
        _ORCH.stream = hub
    ensure_admin(_settings)
    start_retention_loop(_settings)
    yield


app = FastAPI(title="TriNetra ULPF API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)
app.include_router(auth_router)

# One shared orchestrator + graph for the dashboard after a bootstrap run.
_ORCH: Optional[Orchestrator] = None
_GRAPH: Optional[EntityGraph] = None
_settings: Settings = get_settings()

# In-memory rate buckets for the agent ingest endpoint (per source IP).
_AGENT_WINDOW_SECONDS = 60
_AGENT_LIMIT_PER_WINDOW = 5000
_agent_buckets: Dict[str, List[float]] = {}

# ------------------------------------------------------------------- models


class IngestLine(BaseModel):
    raw: str
    source: str = ""
    client_id: str = ""
    host_hint: str = ""


class IngestRequest(BaseModel):
    lines: List[IngestLine] = Field(default_factory=list)
    demo: bool = False


# ------------------------------------------------------------------ agent auth


def _agent_token_ok(provided: Optional[str]) -> bool:
    import hmac

    expected = str(_settings.get("auth.agent_token") or os.environ.get("AGENT_TOKEN", "")).strip()
    if not expected:
        # No token configured: the endpoint stays disabled (defense in depth).
        return False
    return bool(provided) and hmac.compare_digest(str(provided), expected)


def _rate_limit_ok(key: str) -> bool:
    now = time.monotonic()
    window_start = now - _AGENT_WINDOW_SECONDS
    bucket = _agent_buckets.setdefault(key, [])
    while bucket and bucket[0] < window_start:
        bucket.pop(0)
    if len(bucket) >= _AGENT_LIMIT_PER_WINDOW:
        return False
    bucket.append(now)
    return True


# ------------------------------------------------------------- bootstrap


@app.post("/api/demo/run", tags=["bootstrap"], dependencies=[Depends(require_admin)])
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
    count = _ORCH.event_store.count() if _ORCH else 0
    return {
        "status": "ok",
        "events_stored": count,
        "analyzer": _ORCH.analyzer.status() if _ORCH else {"configured_backend": "heuristic"},
        "demo_ready": count > 0,
    }


@app.get("/api/dashboard", tags=["dashboard"], dependencies=[Depends(require_auth)])
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


@app.get("/api/graph", tags=["module-c"], dependencies=[Depends(require_auth)])
def graph() -> Dict[str, Any]:
    if _GRAPH is None:
        raise HTTPException(status_code=428,
                            detail="Bootstrap first: POST /api/demo/run")
    return _GRAPH.to_dashboard()


@app.get("/api/assets", tags=["module-c"], dependencies=[Depends(require_auth)])
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


@app.get("/api/assets/{asset_ip}/relations", tags=["module-c"],
         dependencies=[Depends(require_auth)])
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


@app.get("/api/compliance/{asset_id}", tags=["compliance"],
         dependencies=[Depends(require_auth)])
def compliance(asset_id: str) -> Dict[str, Any]:
    findings = [f for f in _ORCH.findings_log] if _ORCH else []
    return compliance_for_asset(asset_id, findings)


@app.get("/api/compliance", tags=["compliance"], dependencies=[Depends(require_auth)])
def compliance_all() -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    findings = _ORCH.findings_log
    touched = sorted({_touches_targets(f) for f in findings} - {""})
    return {"mappings": [mapping_for(f.get("threat_class")) for f in findings],
            "assets": touched,
            "findings_count": len(findings)}


@app.get("/api/network-threats", tags=["module-a"],
         dependencies=[Depends(require_auth)])
def network_threats(limit: int = Query(50, le=500)) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    return {"findings": _ORCH.findings_log[-limit:][::-1],
            "count": len(_ORCH.findings_log)}


@app.get("/api/alerts", tags=["alerts"], dependencies=[Depends(require_auth)])
def alerts(limit: int = Query(50, le=500)) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    return {"alerts": _ORCH.alerts_log[-limit:][::-1],
            "count": len(_ORCH.alerts_log),
            "sent": _ORCH.stats.get("alerts_sent", 0)}


@app.get("/api/clients", tags=["store"], dependencies=[Depends(require_auth)])
def clients() -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    return {"clients": _ORCH.event_store.clients()}


@app.get("/api/events/search", tags=["store"], dependencies=[Depends(require_auth)])
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
    total = _ORCH.event_store.count_filtered(
        query=query, source_type=source_type, severity=severity,
        category=category, client_id=client_id)
    return {"total": total, "limit": limit, "offset": offset,
            "events": [e.to_dict() for e in events]}


@app.get("/api/events/stream", tags=["store"])
async def events_stream(payload: Dict[str, Any] = Depends(require_token_query)):
    """SSE live tail: every event the ingest pipeline accepts is pushed to
    connected dashboards. Authenticated with the bearer token (header or
    ``?token=`` — EventSource cannot set headers)."""

    async def generator():
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        hub.subscribe(queue)
        try:
            yield ": connected\n\n"
            while True:
                try:
                    line = await asyncio.wait_for(queue.get(), timeout=15)
                    yield line
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            hub.unsubscribe(queue)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/events/{event_id}", tags=["store"], dependencies=[Depends(require_auth)])
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


@app.post("/api/ingest", tags=["ingest"], dependencies=[Depends(require_admin)])
def ingest(body: IngestRequest) -> Dict[str, Any]:
    global _ORCH, _GRAPH
    if _ORCH is None:
        _ORCH = Orchestrator(_settings)
        _GRAPH = _ORCH.graph
        _ORCH.stream = hub
    accepted, duplicates, ignored, failed = 0, 0, 0, 0
    for line in body.lines:
        try:
            outcome = _ORCH.ingest(line.raw, line.source, line.client_id,
                                   line.host_hint)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            log.warning("ingest failed: %s", exc)
            continue
        if outcome == "stored":
            accepted += 1
        elif outcome == "duplicate":
            duplicates += 1
        elif outcome == "ignored":
            ignored += 1
        else:
            failed += 1
    alerts = _ORCH.flush_batch()
    return {"accepted": accepted, "failed": failed, "duplicates": duplicates,
            "ignored": ignored, "alerts": alerts,
            "total": _ORCH.event_store.count()}


@app.post("/api/ingest-events", tags=["ingest"])
def ingest_events(request: Request,
                  payload: Any = Body(...),
                  x_agent_token: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Accept pre-normalized LogEntry dicts from my log-agent.

    The body may be a bare array of event dicts (what the agent's HTTP
    forwarder posts) or ``{"events": [...]}``. Guarded by the shared
    ``X-Agent-Token`` (constant-time compare) plus a simple per-IP rate limit
    and a body-size cap. Events map to UES and flow through the same
    dedup / modules / analyzer pipeline as raw ingestion.
    """
    if not _agent_token_ok(x_agent_token):
        raise HTTPException(status_code=401, detail="Invalid X-Agent-Token")

    if isinstance(payload, dict):
        events = payload.get("events")
        if not isinstance(events, list):
            raise HTTPException(status_code=422,
                                detail="Expected an array of events or {'events': [...]}")
    elif isinstance(payload, list):
        events = payload
    else:
        raise HTTPException(status_code=422, detail="Body must be a JSON array of events")
    if len(events) > 1000:
        raise HTTPException(status_code=413, detail="Too many events per request")

    key = request.client.host if request.client else "unknown"
    if not _rate_limit_ok(key):
        raise HTTPException(status_code=429, detail="Agent ingest rate limit exceeded")

    global _ORCH, _GRAPH
    if _ORCH is None:
        _ORCH = Orchestrator(_settings)
        _GRAPH = _ORCH.graph
        _ORCH.stream = hub

    accepted, duplicates, failed = 0, 0, 0
    for item in events:
        if not isinstance(item, dict):
            failed += 1
            continue
        try:
            outcome = _ORCH.ingest_normalized(item)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            log.warning("ingest-events failed: %s", exc)
            continue
        if outcome == "stored":
            accepted += 1
        elif outcome == "duplicate":
            duplicates += 1
        else:
            failed += 1
    alerts = _ORCH.flush_batch()
    return {"accepted": accepted, "failed": failed, "duplicates": duplicates,
            "alerts": alerts, "total": _ORCH.event_store.count()}


# ------------------------------------------------------------------- utils


def _touches(finding: Dict[str, Any], asset_ip: str) -> bool:
    return compliance_for_asset(asset_ip, [finding]).get("affected_findings") == [finding]


def _touches_targets(finding: Dict[str, Any]) -> str:
    alert = finding.get("alert", finding)
    evidence = alert.get("evidence") or {}
    return str(evidence.get("src") or alert.get("src") or "")
# ------------------------------------------------------- static dashboard
# In a bundled deployment (Docker image) the React build lives in
# frontend/dist and is served directly from the API. The catch-all below is
# registered LAST so the explicit API routes keep precedence, and it falls
# back to index.html for client-side routes (deep links / refresh / share).
# It is registered unconditionally so a later `npm run build` is picked up
# without an app restart, unknown /api/* paths get a JSON 404 (never the SPA
# HTML), and a missing build yields a clear 503 instead of a 500.
from fastapi.responses import FileResponse, JSONResponse

_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
_DIST_RESOLVED = str(_DIST.resolve())


@app.get("/{full_path:path}", include_in_schema=False)
def spa(full_path: str):
    # Unknown API routes must stay machine-readable (JSON 404), not fall
    # through to the dashboard HTML.
    if full_path.startswith("api/") or full_path == "api":
        return JSONResponse({"detail": "API route not found"}, status_code=404)
    target = (_DIST / full_path).resolve()
    if (str(target).startswith(_DIST_RESOLVED) and target.is_file()
            and target != _DIST / "index.html"):
        return FileResponse(target,
                            headers={"Cache-Control": "public, max-age=31536000, immutable"})
    index = _DIST / "index.html"
    if index.is_file():
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
    return JSONResponse(
        {"detail": "frontend/dist not built yet — run `npm run build` in frontend/"},
        status_code=503,
    )
