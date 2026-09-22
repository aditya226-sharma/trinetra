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
    GET  /api/clients             fleet registry (presence, volume, status)
    GET  /api/agents              agent token inventory
    POST /api/agents              mint a per-machine agent token (admin)
    DELETE /api/agents/{token_id} revoke a per-machine agent token (admin)
    POST /api/ingest              ingest raw lines (multi-source, admin only)
    POST /api/ingest-events       ingest pre-normalized agent LogEntry dicts
                                  (X-Agent-Token, rate-limited)
    POST /api/agent/heartbeat     agent liveness/identity ping (X-Agent-Token)
    POST /api/auth/login          dashboard login -> bearer token
    POST /api/auth/register       create users (admin only)

Dashboard data routes require a bearer token; admin-only routes also require
role ``admin``. Run:  uvicorn backend.app.main:app --reload
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make ``trinetra`` importable when the package is run from the repo root.
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import (Body, Depends, FastAPI, File, Form, Header, HTTPException,
                     Query, Request, Response, UploadFile)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from analyzer.llm_analyzer import LLMAnalyzer  # noqa: F401  (type surface)
from backend.app.auth import (ensure_admin, require_admin, require_analyst,
                              require_auth, require_token_query)
from backend.app.auth import router as auth_router
from backend.app.services.audit import audit_log, audit_recent
from backend.app.stream import hub
from config.settings import Settings, get_settings
from orchestrator import Orchestrator
from modules.entity_graph import EntityGraph
from pipeline.retention import (prune, set_retention, start_retention_loop, storage_snapshot)
from pipeline.collectors_runtime import CollectorsManager
from socpolicy import SocPolicy, SocPolicyError

log = logging.getLogger("trinetra.api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Boot the shared orchestrator, seed the first admin account and start
    the retention prune loop.

    The orchestrator is initialized eagerly so reads (dashboard, clients,
    events/search, health counts) reflect already-persisted data without a
    demo/ingest bootstrap first.
    """
    global _ORCH, _GRAPH, _COLLECTORS, _SOC
    if _ORCH is None:
        _ORCH = Orchestrator(_settings)
        _GRAPH = _ORCH.graph
        _ORCH.stream = hub
        # Rebuild the in-memory counters from persisted data so the dashboard
        # reflects everything previously collected (they reset on restart).
        _ORCH.stats["events"] = _ORCH.event_store.count()
        try:
            _ORCH.stats["raw_lines"] = len(_ORCH.raw_store)
        except Exception:
            pass
        # The graph + threat detector are memory-only: replay persisted events
        # into them so the entity graph isn't empty after a redeploy.
        try:
            _ORCH.rebuild_derived()
        except Exception as exc:  # noqa: BLE001 — derived state must never block boot
            logging.getLogger("trinetra.main").warning(
                "derived-state rebuild failed: %s", exc)
    ensure_admin(_settings)
    start_retention_loop(_settings)
    if _SOC is None:
        _SOC = SocPolicy(_settings)
    _ORCH.soc = _SOC
    _SOC.start_digest_loop()
    if _COLLECTORS is None:
        _COLLECTORS = CollectorsManager(_settings)
    _COLLECTORS.start_all(_ORCH)
    yield
    _COLLECTORS.stop_all()


app = FastAPI(title="TriNetra ULPF API", version="0.1.0", lifespan=lifespan)
_cors_raw = get_settings().get("web.cors_origins")
if isinstance(_cors_raw, str):
    _allow_origins = [o.strip() for o in _cors_raw.split(",") if o.strip()]
else:
    _allow_origins = list(_cors_raw or [])
if not _allow_origins:
    _allow_origins = [
        "http://127.0.0.1:5173", "http://localhost:5173",   # vite dev
        "https://aditya226-sharma.github.io",                # GitHub Pages demo
    ]
app.add_middleware(
    CORSMiddleware, allow_origins=_allow_origins, allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router)

# One shared orchestrator + graph for the dashboard after a bootstrap run.
_ORCH: Optional[Orchestrator] = None
_GRAPH: Optional[EntityGraph] = None
_COLLECTORS: Optional[CollectorsManager] = None
_SOC: Optional[SocPolicy] = None
_settings: Settings = get_settings()

from modules.enricher import build_enricher  # noqa: E402 — after settings load

_ENRICHER = build_enricher(_settings)

# In-memory rate buckets for the agent ingest endpoint (per token / source IP).
_AGENT_WINDOW_SECONDS = 60
_AGENT_LIMIT_PER_WINDOW = 5000
# key -> [(monotonic_ts, event_weight), ...]
_agent_buckets: Dict[str, List[tuple]] = {}

# ------------------------------------------------------------------- models


class IngestLine(BaseModel):
    raw: str
    source: str = ""
    client_id: str = ""
    host_hint: str = ""


class IngestRequest(BaseModel):
    lines: List[IngestLine] = Field(default_factory=list)
    demo: bool = False


class HeartbeatRequest(BaseModel):
    """Liveness + identity ping from a running agent (X-Agent-Token)."""
    client_id: str
    hostname: str = ""
    platform: str = ""
    agent_version: str = ""
    ip: str = ""


class MintAgentRequest(BaseModel):
    """Admin request to mint a per-machine agent token."""
    label: str = ""
    client_id: str = ""


class RetentionRequest(BaseModel):
    """Admin retention change — validated against the allowed policy set."""
    days: int
    prune_now: bool = False


class CollectorsRequest(BaseModel):
    """Admin collector-toggling patch (syslog / file tailers / demo replay)."""
    syslog: Optional[Dict[str, Any]] = None
    tailers: Optional[List[Dict[str, Any]]] = None
    demo: Optional[Dict[str, Any]] = None


class WatchEntryRequest(BaseModel):
    """Add a watchlist / blocklist entry (Phase 3 SOC policy)."""
    list: str = "watchlist"
    kind: str
    value: str
    reason: str = ""


class RuleRequest(BaseModel):
    """Create or update one custom detection rule."""
    name: str
    description: str = ""
    source_types: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    min_severity: str = "warning"
    action: str = "alert"
    match: List[Dict[str, Any]] = Field(default_factory=list)
    enabled: bool = True


class CaseActionRequest(BaseModel):
    """Transition on the case ledger: ack/unack/resolve/reopen/assign/note."""
    action: str
    assignee: str = ""
    note: str = ""


class TaskCreateRequest(BaseModel):
    """Admin assigns a work item to a client workspace."""
    title: str
    description: str = ""
    priority: str = "P3"
    due_at: str = ""
    client_id: str = ""
    linked_case_id: str = ""


class TaskPatchRequest(BaseModel):
    """Client or admin updates a task's status/note/due/priority."""
    status: str = ""
    note: str = ""
    due_at: str = ""
    priority: str = ""


# Bulk upload size caps: guards /api/ingest/bulk against paging the whole
# filesystem into memory or a runaway parse.
_BULK_MAX_BYTES = 8_000_000
_BULK_MAX_RECORDS = 10_000


# ------------------------------------------------------------------ agent auth


def _resolve_agent_token(provided: Optional[str]) -> Optional[Dict[str, Any]]:
    """Resolve an ``X-Agent-Token`` to an identity.

    Priority: an admin-minted per-machine token (bound to a ``client_id``,
    revocable), then the legacy shared ``AGENT_TOKEN``. Returns ``None`` when
    neither matches so the endpoint stays disabled-by-default.
    """
    if not provided:
        return None
    if _ORCH is not None:
        token_hash = hashlib.sha256(str(provided).encode("utf-8")).hexdigest()
        tok = _ORCH.client_store.token_by_hash(token_hash)
        if tok and tok["enabled"]:
            return {"mode": "machine",
                    "token_id": str(tok["token_id"]),
                    "client_id": str(tok["client_id"]) if tok["client_id"] else None}
    expected = str(_settings.get("auth.agent_token") or os.environ.get("AGENT_TOKEN", "")).strip()
    if expected:
        import hmac

        if hmac.compare_digest(str(provided), expected):
            return {"mode": "shared", "token_id": None, "client_id": None}
    return None


def _rate_limit_ok(key: str, weight: int = 1) -> bool:
    """Budget bills **events** per window, not requests: a fleet of agents
    sharing one NATed source IP breaks the old per-request cap the moment each
    agent posts its own small batches. The shared-IP budget is now a softer
    ceiling than the token budget, so one token cannot be starved by another."""
    now = time.monotonic()
    window_start = now - _AGENT_WINDOW_SECONDS
    bucket = _agent_buckets.setdefault(key, [])
    while bucket and bucket[0][0] < window_start:
        bucket.pop(0)
    used = sum(w for _t, w in bucket)
    if used + weight > _AGENT_LIMIT_PER_WINDOW:
        return False
    bucket.append((now, weight))
    # Opportunistic sweep so steady agent fleets don't grow the dict forever.
    if len(_agent_buckets) > 128:
        for stale_key in [k for k, b in _agent_buckets.items()
                          if not b or b[-1][0] < window_start]:
            _agent_buckets.pop(stale_key, None)
    return True


# ------------------------------------------------------------- bootstrap


@app.post("/api/demo/run", tags=["bootstrap"], dependencies=[Depends(require_admin)])
def run_demo(reset: bool = Query(False),
             payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    """Run the offline demo storyline once, then serve its data."""
    global _ORCH, _GRAPH
    if reset:
        for path in (_settings.path("raw_store"), _settings.path("event_store")):
            for suffix in ("", "-wal", "-shm"):  # clear WAL sidecars too
                try:
                    Path(str(path) + suffix).unlink(missing_ok=True)
                except OSError:
                    pass
    _ORCH = Orchestrator(_settings)
    _GRAPH = _ORCH.graph
    _ORCH.stream = hub
    _ORCH.soc = _SOC
    _COLLECTORS.set_orchestrator(_ORCH)
    from collectors.demo_feed import DemoFeed

    pcap_dir = str(_settings.path("pcap"))
    DemoFeed.generate_pcaps(pcap_dir)
    _ORCH.run_vpn_module(pcap_dir)
    for raw, source, client, host in DemoFeed().iterate():
        _ORCH.ingest(raw, source, client, host)
    _ORCH.flush_batch()
    _ORCH.stats["bootstrapped"] = True
    audit_log(_settings, str(payload.get("sub", "admin")), "bootstrap.demo",
              f"ran demo storyline (reset={reset})")
    return {"status": "ok", **dashboard({"sub": "admin", "role": "admin", "scope": ""})}


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


@app.get("/api/dashboard", tags=["dashboard"])
def dashboard(payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428,
                            detail="Bootstrap first: POST /api/demo/run")
    scope = _client_scope(payload)
    if scope:
        return _scoped_dashboard(scope)
    all_cases = _ORCH.soc.list_cases(limit=500) if _ORCH.soc else []
    case_stats = _ORCH.soc.case_stats() if _ORCH.soc else {"total": 0, "by_status": {}}
    return {
        "stats": _ORCH.stats,
        "dedup_rate": _ORCH.dedup.duplicate_rate,
        "threat_detections": _ORCH.threats.detection_counts,
        "graph_summary": _ORCH.graph.summary(),
        "vpn": {"profiles": _ORCH.vpn_profiles},
        "findings": [_finding_card(f) for f in _ORCH.findings_log[-50:]],
        "scope": "",
        "case_stats": case_stats,
        "tasks": _task_dashboard(""),
        "incidents": {
            "open": [c for c in all_cases if c["status"] == "open"],
            "investigation": [c for c in all_cases if c["status"] == "investigation"],
            "closed": [c for c in all_cases if c["status"] == "closed"],
            "stats": case_stats.get("by_status", {}),
        },
    }


@app.get("/api/graph", tags=["module-c"], dependencies=[Depends(require_analyst)])
def graph() -> Dict[str, Any]:
    if _GRAPH is None:
        raise HTTPException(status_code=428,
                            detail="Bootstrap first: POST /api/demo/run")
    return _GRAPH.to_dashboard()


@app.get("/api/assets", tags=["module-c"], dependencies=[Depends(require_analyst)])
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
            if edge.get("target"):
                comm_counts[edge["target"]] = comm_counts.get(edge["target"], 0) + 1
    for node in nodes:
        node["threatened"] = node["id"] in threatened
        node["degree"] = comm_counts.get(node["id"], 0)
    return {"assets": sorted(nodes, key=lambda n: (-n["threatened"], -n["degree"]))}


@app.get("/api/assets/{asset_ip}/relations", tags=["module-c"],
         dependencies=[Depends(require_analyst)])
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
         dependencies=[Depends(require_analyst)])
def compliance(asset_id: str) -> Dict[str, Any]:
    findings = [f for f in _ORCH.findings_log] if _ORCH else []
    return compliance_for_asset(asset_id, findings)


@app.get("/api/compliance", tags=["compliance"], dependencies=[Depends(require_analyst)])
def compliance_all() -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    findings = _ORCH.findings_log
    touched = sorted({_touches_targets(f) for f in findings} - {""})
    return {"mappings": [mapping_for(f.get("threat_class")) for f in findings],
            "assets": touched,
            "findings_count": len(findings)}


@app.get("/api/network-threats", tags=["module-a"])
def network_threats(limit: int = Query(50, le=500),
                    payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    scope = _client_scope(payload)
    findings = [f for f in _ORCH.findings_log
                if not scope or _touches_client(f, scope)]
    return {"findings": findings[-limit:][::-1],
            "count": len(findings)}


@app.get("/api/alerts", tags=["alerts"])
def alerts(limit: int = Query(50, le=500),
           payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    scope = _client_scope(payload)
    log_rows = _ORCH.alerts_log[::-1]
    if scope:
        log_rows = [a for a in log_rows if _alert_for_scope(a, scope)]
    return {"alerts": log_rows[:limit],
            "count": len(log_rows),
            "sent": _ORCH.stats.get("alerts_sent", 0)}


def _alert_for_scope(alert: Dict[str, Any], client_id: str) -> bool:
    cid = str(alert.get("client_id") or "")
    if not cid:
        return True
    return cid == client_id


@app.get("/api/clients", tags=["store"])
def clients(payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    """Fleet registry: per-machine presence + event volume.

    Merges the event-derived summaries (counts, dominant source, last event)
    with the client registry (hostname, platform, agent version, IP, heartbeat)
    and reports ``status`` online/offline from the configured grace window
    plus events in the recent rate window.
    """
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    scope = _client_scope(payload)
    grace_s = int(_settings.get("events.client_online_grace_s", 180))
    window_s = int(_settings.get("events.client_rate_window_s", 300))
    now = datetime.now(timezone.utc)
    grace_cutoff = (now - timedelta(seconds=grace_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    window_cutoff = (now - timedelta(seconds=window_s)).strftime("%Y-%m-%dT%H:%M:%SZ")

    meta = {m["client_id"]: m for m in _ORCH.client_store.list_clients()}
    recent = _ORCH.event_store.client_counts_since(window_cutoff)

    # Union: registered clients (heartbeat-only agents included) + any client
    # that only has events (e.g. shared-token agents not yet heartbeating).
    merged: Dict[str, Dict[str, Any]] = {}
    for entry in _ORCH.event_store.clients():
        merged[entry["client_id"]] = {
            "events": entry["events"], "source_type": entry["source_type"],
            "event_last_seen": entry.get("last_seen") or ""}
    for cid, m in meta.items():
        row = merged.setdefault(cid, {"events": 0, "source_type": "",
                                      "event_last_seen": ""})
        row["meta"] = m

    rows = []
    for cid, entry in merged.items():
        if scope and cid != scope:
            continue
        m = entry.get("meta", {})
        last_seen = str(m.get("last_seen") or entry.get("event_last_seen") or "")
        online = bool(last_seen) and last_seen >= grace_cutoff
        source_type = entry.get("source_type") or (m.get("source_types") or [""])[0]
        rows.append({
            "client_id": cid,
            "hostname": str(m.get("hostname") or cid),
            "platform": str(m.get("platform") or ""),
            "agent_version": str(m.get("agent_version") or ""),
            "ip": str(m.get("ip") or ""),
            "source_types": m.get("source_types") or ([source_type] if source_type else []),
            "events": entry["events"],
            "events_recent": recent.get(cid, 0),
            "first_seen": str(m.get("first_seen") or ""),
            "last_seen": last_seen,
            "heartbeat_at": str(m.get("last_heartbeat") or ""),
            "token_id": str(m.get("token_id") or "") or None,
            "status": "online" if online else "offline",
        })
    rows.sort(key=lambda r: (r["status"] == "offline", -r["events_recent"]))
    totals = {
        "clients": len(rows),
        "online": sum(1 for r in rows if r["status"] == "online"),
        "offline": sum(1 for r in rows if r["status"] == "offline"),
        "events": sum(r["events"] for r in rows),
        "events_recent": sum(r["events_recent"] for r in rows),
    }
    return {"clients": rows, "totals": totals}


def _client_scope(payload: Dict[str, Any]) -> str:
    """The client workspace a non-admin is scoped to ('' = all). Admins and
    analysts always see the whole estate unless an explicit scope is set."""
    if payload.get("role") in ("admin", "analyst"):
        return str(payload.get("scope") or "")
    return str(payload.get("scope") or "")


def _task_dashboard(client_id: str) -> Dict[str, Any]:
    """Task aggregate + visible list for a client workspace (or the whole
    fleet when ``client_id`` is ''). Survives a world without any SOC store."""
    soc = getattr(_ORCH, "soc", None)
    if soc is None:
        return {"total": 0, "by_status": {"todo": 0, "in_progress": 0, "done": 0},
                "overdue": 0, "list": []}
    stats = soc.task_stats(client_id)
    stats["list"] = soc.list_tasks(client_id=client_id, status="open", limit=12)
    return stats


def _scoped_dashboard(client_id: str) -> Dict[str, Any]:
    """Dashboard payload restricted to one client workspace: its events,
    its module findings (via the analytic search), its open incidents and a
    mini incident board — the 'individual dashboard' for a client user."""
    assert _ORCH is not None
    store = _ORCH.event_store
    graph = _ORCH.graph
    events = store.count_filtered(client_id=client_id)
    stats = getattr(_ORCH, "soc", None).case_stats_by_client(client_id) if getattr(_ORCH, "soc", None) else {"total": 0, "by_status": {}}
    threat_counts: Dict[str, int] = {}
    all_cases = _ORCH.soc.list_cases(limit=500, client_id=client_id) if _ORCH.soc else []
    for c in all_cases:
        threat_counts[c["threat_class"]] = threat_counts.get(c["threat_class"], 0) + 1
    findings = [f for f in _ORCH.findings_log
                if _touches_client(f, client_id)][-50:]
    return {
        "client_id": client_id,
        "scope": client_id,
        "stats": {"events": events, "findings": len(findings),
                  "alerts_sent": stats.get("total", 0),
                  "raw_lines": _ORCH.stats.get("raw_lines", 0)},
        "dedup_rate": _ORCH.dedup.duplicate_rate,
        "threat_detections": threat_counts,
        "tasks": _task_dashboard(client_id),
        "incidents": {
            "open": [c for c in all_cases if c["status"] == "open"],
            "investigation": [c for c in all_cases if c["status"] == "investigation"],
            "closed": [c for c in all_cases if c["status"] == "closed"],
            "stats": stats.get("by_status", {}),
        },
        "graph_summary": graph.summary() if graph else {},
        "vpn": {"profiles": _ORCH.vpn_profiles},
        "findings": [_finding_card(f) for f in findings],
    }


def _finding_card(f: Dict[str, Any]) -> Dict[str, Any]:
    """Light projection of a finding for dashboard cards (drops the heavy
    event_ids/evidence arrays — bandwidth & payload friendly for the tunnel)."""
    alert = f.get("alert") or {}
    analysis = f.get("analysis") or {}
    return {
        "threat_class": f.get("threat_class") or alert.get("threat_class"),
        "threat_category": f.get("threat_category") or alert.get("threat_category"),
        "severity": f.get("severity") or alert.get("severity"),
        "confidence": f.get("confidence", alert.get("confidence")),
        "flow_id": f.get("flow_id") or alert.get("flow_id"),
        "client_id": f.get("client_id") or alert.get("client_id"),
        "timestamp": f.get("timestamp") or alert.get("timestamp"),
        "verdict": analysis.get("verdict") or alert.get("verdict"),
        "store_decision": analysis.get("store_decision") or alert.get("store_decision"),
    }


def _touches_client(finding: Dict[str, Any], client_id: str) -> bool:
    """Does a finding implicate a given client workspace? Fall back to true
    when the finding carries no client attribution (single-workspace mode)."""
    cid = str(finding.get("client_id") or (finding.get("alert") or {}).get("client_id") or "")
    if cid:
        return cid == client_id
    return True


@app.get("/api/events/search", tags=["store"])
def search_events(
    query: str = "", source_type: str = "", severity: str = "",
    category: str = "", client_id: str = "", threat_class: str = "",
    ts_from: str = "", ts_to: str = "",
    limit: int = Query(50, le=500), offset: int = 0,
    format: str = "",
    payload: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    scope = _client_scope(payload)
    if scope:
        # Scoped viewers may only ever see their own client's events, no
        # matter what client_id they ask for.
        if client_id and client_id != scope:
            raise HTTPException(status_code=403, detail="not your client's events")
        client_id = scope
    if format == "csv":
        # Exports sweep the full matching set (capped so a runaway corpus
        # can't blow out memory); live triage keeps the paginated fetch below.
        rows = _ORCH.event_store.search(query=query, source_type=source_type,
                                        severity=severity, category=category,
                                        client_id=client_id, threat_class=threat_class,
                                        ts_from=ts_from, ts_to=ts_to,
                                        limit=5000, offset=0)
        return export_events_csv(events_to_rows(rows))
    events = _ORCH.event_store.search(query=query, source_type=source_type,
                                      severity=severity, category=category,
                                      client_id=client_id, threat_class=threat_class,
                                      ts_from=ts_from, ts_to=ts_to,
                                      limit=limit, offset=offset)
    total = _ORCH.event_store.count_filtered(
        query=query, source_type=source_type, severity=severity,
        category=category, client_id=client_id, threat_class=threat_class,
        ts_from=ts_from, ts_to=ts_to)
    return {"total": total, "limit": limit, "offset": offset,
            "events": [e.to_dict() for e in events]}


def events_to_rows(events: List[Any]) -> List[List[str]]:
    """Flatten normalized UES events to CSV-safe rows (header + data)."""
    rows: List[List[str]] = [["event_id", "timestamp", "source_type", "client_id",
                              "client_ip", "category", "severity", "threat_class",
                              "message", "trace_id"]]
    for e in events:
        fields = getattr(e, "fields", None) or {}
        tc = ""
        mf = fields.get("module_findings") or {}
        nt = mf.get("network_threat") or {}
        tc = (nt.get("threat_class") or fields.get("threat_class") or "")
        rows.append([
            str(getattr(e, "event_id", "") or ""),
            str(getattr(e, "timestamp", "") or ""),
            str(getattr(e, "source_type", "") or ""),
            str(getattr(e, "client_id", "") or ""),
            str(getattr(e, "client_ip", "") or ""),
            str(getattr(e, "category", "") or ""),
            str(getattr(e, "severity", "") or ""),
            str(tc),
            (getattr(e, "message", "") or "").replace("\n", " "),
            str(getattr(e, "trace_id", "") or ""),
        ])
    return rows


def _csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula-injection prefixes in exported cells."""
    if value and value[0] in ("=", "+", "-", "@"):
        return "'" + value
    return value


def export_events_csv(rows: List[List[str]]) -> StreamingResponse:
    import csv
    import io as _io
    buf = _io.StringIO()
    writer = csv.writer(buf)
    for row in rows:
        writer.writerow([_csv_safe(c) for c in row])
    return StreamingResponse(
        iter([buf.getvalue().encode("utf-8")]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="trinetra-events.csv"'},
    )


@app.get("/api/events/stream", tags=["store"])
async def events_stream(payload: Dict[str, Any] = Depends(require_token_query)):
    """SSE live tail: every event the ingest pipeline accepts is pushed to
    connected dashboards. Authenticated with the bearer token (header or
    ``?token=`` — EventSource cannot set headers)."""

    async def generator():
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        hub.subscribe(queue, asyncio.get_running_loop())
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


@app.get("/api/events/{event_id}", tags=["store"])
def event_detail(event_id: str,
                 payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    event = _ORCH.event_store.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    scope = _client_scope(payload)
    if scope and getattr(event, "client_id", None) and event.client_id != scope:
        raise HTTPException(status_code=403, detail="not your client's event")
    detail = event.to_dict()
    detail["raw"] = _ORCH.raw_store.get(event.trace_id) if event.trace_id else None
    detail["trace_events"] = [e.to_dict()
                              for e in _ORCH.event_store.by_trace(event.trace_id)]
    return detail


# ------------------------------------------------------------------- ingest


@app.post("/api/ingest", tags=["ingest"], dependencies=[Depends(require_admin)])
def ingest(body: IngestRequest,
           payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    global _ORCH, _GRAPH
    if _ORCH is None:
        _ORCH = Orchestrator(_settings)
        _GRAPH = _ORCH.graph
        _ORCH.stream = hub
    if len(body.lines) > _BULK_MAX_RECORDS:
        raise HTTPException(status_code=413,
                            detail=f"Too many lines: {len(body.lines)} > {_BULK_MAX_RECORDS}")
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
    audit_log(_settings, str(payload.get("sub", "admin")), "ingest.raw",
              f"{len(body.lines)} lines: {accepted} accepted, "
              f"{duplicates} dup, {ignored} ignored, {failed} failed")
    return {"accepted": accepted, "failed": failed, "duplicates": duplicates,
            "ignored": ignored, "alerts": alerts,
            "total": _ORCH.event_store.count()}


@app.post("/api/ingest-events", tags=["ingest"])
def ingest_events(request: Request,
                  payload: Any = Body(...),
                  x_agent_token: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Accept pre-normalized LogEntry dicts from my log-agent.

    The body may be a bare array of event dicts (what the agent's HTTP
    forwarder posts) or ``{"events": [...]}``. Guarded by an agent token
    (per-machine or shared; constant-time compare) plus a simple per-IP rate
    limit and a body-size cap. Events map to UES and flow through the same
    dedup / modules / analyzer pipeline as raw ingestion. A per-machine token
    pins ``client_id`` so one machine cannot impersonate another.
    """
    global _ORCH, _GRAPH
    if _ORCH is None:
        _ORCH = Orchestrator(_settings)
        _GRAPH = _ORCH.graph
        _ORCH.stream = hub

    identity = _resolve_agent_token(x_agent_token)
    if identity is None:
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
    if x_agent_token:
        key = "tok:" + hashlib.sha256(x_agent_token.encode("utf-8")).hexdigest()
    if not _rate_limit_ok(key, len(events)):
        raise HTTPException(status_code=429, detail="Agent ingest rate limit exceeded")

    # An unbound per-machine token gets pinned to the first client it speaks
    # for; once bound, that identity is authoritative for all its events.
    pinned_client = identity["client_id"]
    if identity["mode"] == "machine" and not pinned_client:
        first = next((i for i in events if isinstance(i, dict)
                      and (i.get("client_id") or (i.get("metadata") or {}).get("host"))), None)
        if first is not None:
            metadata = first.get("metadata") or {}
            pinned_client = str(first.get("client_id")
                                or metadata.get("host")
                                or _settings.get("agent.client_id", "trinetra-core")).strip()
            if pinned_client:
                _ORCH.client_store.bind_token(pinned_client, identity["token_id"])

    accepted, duplicates, failed = 0, 0, 0
    for item in events:
        if not isinstance(item, dict):
            failed += 1
            continue
        try:
            outcome = _ORCH.ingest_normalized(item,
                                              default_client_id=pinned_client)
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


@app.post("/api/agent/heartbeat", tags=["ingest"])
def agent_heartbeat(request: Request, body: HeartbeatRequest,
                    x_agent_token: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Agent liveness ping (mint: cURL from the onboarding wizard).

    Authenticated like ingest-events (per-machine or shared token). Updates
    the client registry presence/identity and — for a per-machine token that
    has not yet been bound — binds it to the reported ``client_id`` (a bound
    token's identity is authoritative).
    """
    global _ORCH, _GRAPH
    if _ORCH is None:
        _ORCH = Orchestrator(_settings)
        _GRAPH = _ORCH.graph
        _ORCH.stream = hub

    identity = _resolve_agent_token(x_agent_token)
    if identity is None:
        raise HTTPException(status_code=401, detail="Invalid X-Agent-Token")

    client_id = str(body.client_id or "").strip()
    if identity["mode"] == "machine":
        if identity["client_id"]:
            client_id = identity["client_id"]
        elif client_id:
            _ORCH.client_store.bind_token(client_id, identity["token_id"])
    if not client_id:
        client_id = str(_settings.get("agent.client_id", "trinetra-core"))

    _ORCH.client_store.heartbeat(
        client_id=client_id,
        hostname=str(body.hostname or body.client_id or ""),
        platform=str(body.platform or ""),
        agent_version=str(body.agent_version or ""),
        ip=str(body.ip or (request.client.host if request.client else "")),
    )
    if identity["token_id"]:
        _ORCH.client_store.note_token_used(identity["token_id"])
    return {"status": "ok", "client_id": client_id,
            "server_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


# ------------------------------------------------------------------ agents


@app.post("/api/agents", tags=["agents"], dependencies=[Depends(require_admin)])
def mint_agent(body: MintAgentRequest,
               payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    """Mint a per-machine agent token (admin only). The raw token is returned
    exactly once; only its sha256 is persisted. ``client_id`` may be pre-bound
    or left for the agent's first heartbeat to bind."""
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    token_id, token = _ORCH.client_store.mint_token(
        label=str(body.label or ""), client_id=str(body.client_id or ""))
    audit_log(_settings, str(payload.get("sub", "admin")), "agents.mint",
              f"minted token {token_id} (client={body.client_id or 'unbound'})")
    return {"token_id": token_id, "token": token,
            "client_id": str(body.client_id or "") or None}


@app.get("/api/agents", tags=["agents"], dependencies=[Depends(require_analyst)])
def list_agents() -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    return {"agents": _ORCH.client_store.list_tokens()}


@app.delete("/api/agents/{token_id}", tags=["agents"],
            dependencies=[Depends(require_admin)])
def revoke_agent(token_id: str,
                 payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    if not _ORCH.client_store.revoke_token(token_id):
        raise HTTPException(status_code=404, detail="token not found")
    audit_log(_settings, str(payload.get("sub", "admin")), "agents.revoke",
              f"revoked token {token_id}")
    return {"status": "revoked", "token_id": token_id}


# ------------------------------------------------------------------ admin
# Storage, retention, audit + bulk upload (Phase 2). Admin-gated; every
# mutation is recorded to the audit trail.


@app.get("/api/admin/storage", tags=["admin"], dependencies=[Depends(require_admin)])
def admin_storage() -> Dict[str, Any]:
    """Store volumes, sizes and the effective retention policy."""
    return storage_snapshot(_settings)


@app.put("/api/admin/retention", tags=["admin"],
         dependencies=[Depends(require_admin)])
def admin_retention(body: RetentionRequest,
                    payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    try:
        days = set_retention(_settings, body.days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result: Dict[str, Any] = {"retention_days": days}
    if body.prune_now or days and body.prune_now:
        result.update(prune(_settings, days))
    audit_log(_settings, str(payload.get("sub", "admin")), "admin.retention",
              f"set retention to {days}d"
              + (f"; pruned {result.get('events', 0)} events" if body.prune_now else ""))
    return result


@app.get("/api/admin/audit", tags=["admin"], dependencies=[Depends(require_admin)])
def admin_audit(limit: int = Query(100)) -> Dict[str, Any]:
    """Newest-first audit trail of privileged actions."""
    return {"entries": audit_recent(_settings, limit)}


@app.get("/api/admin/collectors", tags=["admin"], dependencies=[Depends(require_admin)])
def admin_collectors() -> Dict[str, Any]:
    """Current collector config + which live threads are running."""
    if _COLLECTORS is None:
        raise HTTPException(status_code=503, detail="Collectors not initialized")
    return {"config": _COLLECTORS.effective(), "running": _COLLECTORS.status()}


@app.put("/api/admin/collectors", tags=["admin"],
         dependencies=[Depends(require_admin)])
def admin_collectors_put(body: CollectorsRequest,
                         payload: Dict[str, Any] = Depends(require_admin)
                         ) -> Dict[str, Any]:
    """Apply a collector patch (syslog port/on-off, file tailers, demo replay)
    and hot-restart the collector threads."""
    if _COLLECTORS is None:
        raise HTTPException(status_code=503, detail="Collectors not initialized")
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    if not patch:
        raise HTTPException(status_code=400, detail="Nothing to change")
    result = _COLLECTORS.apply(patch)
    audit_log(_settings, str(payload.get("sub", "admin")), "admin.collectors",
              "updated collector config")
    return result


@app.get("/api/analytics", tags=["analytics"], dependencies=[Depends(require_analyst)])
def analytics(hours: int = Query(48, ge=1, le=336),
              format: str = Query("json")) -> Any:
    """Roll-up analytics over the last ``hours``.

    JSON returns a time-series of hourly event counts plus dimension counts
    (source_type / severity / category / client). ``format=csv`` streams the
    same data as flat CSV rows for spreadsheet consumption.
    """
    global _ORCH
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")

    now = datetime.now(timezone.utc).replace(microsecond=0, second=0, minute=0)
    cut = now - timedelta(hours=hours)
    store = _ORCH.event_store

    series: List[Dict[str, Any]] = []
    lo = cut
    # Bucket at the finest granularity that keeps the query count sane.
    step = 1 if hours <= 96 else (hours // 96)
    while lo < now:
        hi = min(lo + timedelta(hours=step), now)
        n = store.count_filtered(ts_from=lo.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 ts_to=hi.strftime("%Y-%m-%dT%H:%M:%SZ"))
        series.append({"bucket": hi.strftime("%Y-%m-%dT%H:%M:%SZ"), "events": n})
        lo = hi

    stats = {k: _ORCH.stats.get(k, 0) for k in
             ("raw_lines", "events", "duplicates", "findings",
              "analyzer_calls", "alerts_sent")}
    totals = {"events_in_window": sum(b["events"] for b in series),
              "events_total": store.count(),
              "duplicates_total": stats["duplicates"],
              "findings_total": stats["findings"],
              "alerts_total": stats["alerts_sent"],
              "analyzer_calls_total": stats["analyzer_calls"],
              "dedup_rate": round(
                  stats["duplicates"] / stats["raw_lines"], 4)
                  if stats.get("raw_lines") else 0.0}
    dims = {
        "by_source_type": store.count_by("source_type"),
        "by_severity": store.count_by("severity"),
        "by_category": store.count_by("category"),
        "by_client": store.count_by("client_id"),
        "detections": getattr(_ORCH.threats, "detection_counts", {}) or {},
    }
    payload: Dict[str, Any] = {
        "generated_at": _iso_now(),
        "window_hours": hours,
        "step_hours": step,
        "totals": totals,
        "time_series": series,
        **dims,
    }
    if format.lower() == "csv":
        import io

        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["bucket_utc", "events"])
        for b in series:
            writer.writerow([b["bucket"], b["events"]])
        writer.writerow([])
        for dim in ("by_source_type", "by_severity", "by_category", "by_client",
                    "detections"):
            writer.writerow([dim])
            for k, v in sorted(payload[dim].items(), key=lambda kv: -kv[1]):
                writer.writerow([k, v])
            writer.writerow([])
        return StreamingResponse(
            iter([out.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition":
                     f'attachment; filename="analytics_{now:%Y%m%dT%H%M}.csv"'},
        )
    return payload


@app.get("/api/compliance/{asset_id}/report", tags=["compliance"],
         dependencies=[Depends(require_analyst)])
def compliance_report(asset_id: str) -> Response:
    """Standalone HTML compliance report (print / save-as-PDF friendly)."""
    if _ORCH is None:
        raise HTTPException(status_code=428, detail="Bootstrap first")
    findings = [f for f in _ORCH.findings_log if _touches(f, asset_id)]
    c = compliance_for_asset(asset_id, findings)
    html = _compliance_report_html(asset_id, c, _iso_now())
    return HTMLResponse(content=html, media_type="text/html")


@app.post("/api/ingest/bulk", tags=["ingest"], dependencies=[Depends(require_admin)])
async def ingest_bulk(file: UploadFile = File(...),
                      source: str = Form(""),
                      client_id: str = Form(""),
                      payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    """Bulk upload: CSV / JSON / JSONL into the pipeline, same normalize →
    dedup → modules → analyzer path as the raw ingester.

    CSV and plain-text files feed each line as raw (source hint + optional
    ``client_id``). JSON accepts either raw-line objects (``{"raw": ...,
    "source": ...}``) or pre-normalized event dicts, mirrored by JSONL.
    """
    global _ORCH
    if _ORCH is None:
        _ORCH = Orchestrator(_settings)
        _ORCH.stream = hub

    raw = await file.read(_BULK_MAX_BYTES + 1)
    if len(raw) > _BULK_MAX_BYTES:
        raise HTTPException(status_code=413,
                            detail=f"File exceeds {_BULK_MAX_BYTES} byte cap")
    text = raw.decode("utf-8", errors="replace")
    name = (file.filename or "").lower()

    default_source = str(source or "file_log")
    default_client = str(client_id or "")

    accepted = duplicates = failed = ignored = raw_accepted = 0
    alerts: List[str] = []

    def _record(rec: Any, fallback_source: str) -> None:
        nonlocal accepted, duplicates, failed, ignored, raw_accepted
        try:
            if isinstance(rec, dict):
                r = rec.get("raw")
                if isinstance(r, str) and r.strip():
                    source_ = str(rec.get("source") or fallback_source) or default_source
                    client_ = str(rec.get("client_id") or default_client)
                    outcome = _ORCH.ingest(r.strip(), source_, client_, "")
                    raw_accepted += 1
                else:
                    outcome = _ORCH.ingest_normalized(rec, default_client_id=default_client)
            else:
                line = str(rec).strip()
                if not line:
                    return
                outcome = _ORCH.ingest(line, fallback_source, default_client, "")
                raw_accepted += 1
            if outcome == "stored":
                accepted += 1
            elif outcome == "duplicate":
                duplicates += 1
            elif outcome == "ignored":
                ignored += 1
            else:
                failed += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            log.warning("bulk ingest record failed: %s", exc)

    if name.endswith(".jsonl"):
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                _record(json.loads(line), default_source)
            except json.JSONDecodeError:
                _record(line, default_source)
    elif name.endswith(".json"):
        try:
            blob = json.loads(text)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc}")
        if isinstance(blob, dict):
            blob = [blob]
        if not isinstance(blob, list):
            raise HTTPException(status_code=422, detail="JSON body must be an array")
        for item in blob:
            _record(item, default_source)
    else:
        for line in text.splitlines():
            _record(line, name.endswith(".csv") and "csv" or default_source)

    alerts = _ORCH.flush_batch()
    summary = {"accepted": accepted, "failed": failed, "duplicates": duplicates,
               "ignored": ignored, "raw_records": raw_accepted, "lines": raw_accepted,
               "alerts": alerts, "total": _ORCH.event_store.count()}
    audit_log(_settings, str(payload.get("sub", "admin")), "ingest.bulk",
              f"uploaded {name or '?'} ({summary['raw_records']} lines): "
              f"{accepted} accepted, {duplicates} dup, {ignored} ignored, {failed} failed")
    return summary


# ------------------------------------------------------------------- utils


def _touches(finding: Dict[str, Any], asset_ip: str) -> bool:
    return compliance_for_asset(asset_ip, [finding]).get("affected_findings") == [finding]


def _touches_targets(finding: Dict[str, Any]) -> str:
    alert = finding.get("alert", finding)
    evidence = alert.get("evidence") or {}
    return str(evidence.get("src") or alert.get("src") or "")


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _esc_html(value: Any) -> str:
    return (str(value)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _compliance_report_html(asset_id: str, compliance: Dict[str, Any],
                            generated_at: str) -> str:
    controls = compliance.get("controls") or []
    rows = "".join(
        f"""
        <div class="ctrl">
          <div class="row"><h3>{_esc_html(c.get('threat_class'))}</h3>
            <span class="sev-{_esc_html(c.get('severity'))}">{_esc_html(c.get('severity'))}</span></div>
          <p class="dim">{_esc_html(c.get('description') or '')}</p>
          <p><span class="k">NIST CSF</span> {_esc_html(c.get('nist_csf') or '—')}</p>
          <p><span class="k">CIS Controls</span> {_esc_html(' · '.join(c.get('cis_controls') or [])) or '—'}</p>
          <p><span class="k">MITRE ATT&amp;CK</span> {_esc_html(', '.join(c.get('mitre_attack') or [])) or '—'}</p>
          <p><span class="k">Status</span> <span class="pill">{_esc_html(c.get('status') or 'pending')}</span></p>
        </div>
        """
        for c in controls)

    findings = compliance.get("findings") or []
    findings_html = "".join(
        f"""
        <tr>
          <td class="mono">{_esc_html(f.get('threat_class'))}</td>
          <td>{_esc_html(f.get('severity'))}</td>
          <td class="mono">{_esc_html(f.get('src') or (f.get('evidence') or {}).get('src') or '—')}</td>
          <td>{_esc_html(f.get('message') or f.get('summary') or '')}</td>
        </tr>
        """
        for f in findings) or (
        "<tr><td colspan=4 class='dim'>No live findings recorded for this asset in "
        "the current session.</td></tr>")

    markdown = _esc_html(compliance.get("summary_markdown") or "")

    now_str = generated_at.replace("T", " ").replace("Z", " UTC")
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compliance report — {_esc_html(asset_id)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, 'Inter', 'Segoe UI', Roboto, sans-serif;
          margin: 0 auto; max-width: 900px; padding: 40px 48px; color: #0f172a;
          background: #fff; line-height: 1.5; }}
  .brand {{ display: flex; justify-content: space-between; align-items: center;
            border-bottom: 3px solid #0f172a; padding-bottom: 14px; }}
  .brand h1 {{ font-size: 17px; letter-spacing: .18em; text-transform: uppercase; margin: 0; }}
  .brand span {{ font-size: 12px; color: #475569; }}
  h2 {{ font-size: 22px; margin: 26px 0 4px; }}
  .sub {{ color: #475569; font-size: 13px; margin-bottom: 8px; }}
  .meta {{ font-size: 12px; color: #64748b; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px 40px;
           margin: 18px 0 30px; font-size: 13px; }}
  .grid b {{ display: inline-block; min-width: 120px; color: #64748b; font-weight: 600; }}
  .ctrl {{ border: 1px solid #e2e8f0; border-left: 4px solid #0ea5e9; border-radius: 8px;
          padding: 14px 16px; margin-bottom: 14px; page-break-inside: avoid; }}
  .row {{ display: flex; justify-content: space-between; align-items: center; }}
  .row h3 {{ margin: 0; font-size: 15px; text-transform: capitalize; }}
  .sev-critical {{ color: #b91c1c; font-weight: 700; font-size: 12px; text-transform: uppercase; }}
  .sev-high {{ color: #c2410c; font-weight: 700; font-size: 12px; text-transform: uppercase; }}
  .sev-medium {{ color: #b45309; font-weight: 700; font-size: 12px; text-transform: uppercase; }}
  .sev-low {{ color: #475569; font-weight: 700; font-size: 12px; text-transform: uppercase; }}
  .k {{ display: inline-block; min-width: 120px; color: #64748b; font-size: 12px;
       font-weight: 600; letter-spacing: .06em; text-transform: uppercase; }}
  .dim {{ color: #64748b; font-size: 12.5px; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
  .pill {{ border: 1px solid #f59e0b; color: #92400e; background:#fef3c7;
          font-size: 11px; font-weight: 700; text-transform: uppercase;
          padding: 2px 8px; border-radius: 999px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; margin: 10px 0 28px; }}
  th, td {{ text-align: left; border-bottom: 1px solid #e2e8f0; padding: 8px 10px; vertical-align: top; }}
  th {{ color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; }}
  pre {{ white-space: pre-wrap; background: #f8fafc; border: 1px solid #e2e8f0;
        border-radius: 8px; padding: 14px 16px; font-size: 12px; }}
  .toolbar {{ position: sticky; top: 12px; display: flex; gap: 10px; justify-content: flex-end;
             margin-bottom: 14px; }}
  .toolbar button {{ border: 1px solid #0f172a; background: #0f172a; color: #fff;
     padding: 8px 16px; border-radius: 7px; font-size: 13px; cursor: pointer; }}
  .toolbar button.alt {{ background: #fff; color: #0f172a; }}
  footer {{ margin-top: 34px; padding-top: 12px; border-top: 1px solid #e2e8f0;
           font-size: 11px; color: #94a3b8; }}
  @page {{ margin: 18mm; }}
  @media print {{ .toolbar {{ display: none; }} }}
</style></head>
<body>
  <div class="toolbar">
    <button onclick="window.print()">Save as PDF</button>
    <button class="alt" onclick="window.close()">Close</button>
  </div>
  <div class="brand"><h1>TriNetra · Compliance brief</h1><span>SECURITY CONTROLS MAPPING</span></div>
  <h2>{_esc_html(asset_id)}</h2>
  <p class="sub">CIS Controls v8 / NIST CSF / MITRE ATT&amp;CK mapping for threat findings
    attributed to this asset.</p>
  <div class="grid">
    <div><b>Generated</b> {_esc_html(now_str)}</div>
    <div><b>Asset id</b> {_esc_html(asset_id)}</div>
    <div><b>Threat → control chains</b> {len(controls)}</div>
    <div><b>Findings in scope</b> {len(findings)}</div>
    <div><b>Severity</b> critical — action required</div>
    <div><b>Status</b> <span class="pill">pending</span></div>
  </div>
  <h2>Control mappings</h2>
  {rows}
  <h2>Attributed findings</h2>
  <table><thead><tr><th>Threat class</th><th>Severity</th><th>Source</th><th>Summary</th></tr></thead>
    <tbody>{findings_html}</tbody></table>
  <h2>Analyst brief</h2>
  <pre>{markdown}</pre>
  <footer>TriNetra Unified Logging &amp; Pipeline Framework — generated {_esc_html(now_str)}. 
    Mapping is advisory; validate against your organisation's current control baseline.</footer>
</body></html>"""


# ------------------------------------------------------- PHASE 3 :: SOC policy
# Watchlist / blocklist, custom detection rules, alert-case lifecycle and
# external delivery. Policy mutations are admin-only; case triage reads and
# Transitions require an SOC analyst (admin or analyst role); plain viewers
# keep a read-only queue.
# -----------------------------------------------------------------------------


def _soc() -> SocPolicy:
    if _SOC is None:
        raise HTTPException(status_code=428, detail="SOC policy not initialized")
    return _SOC


def _soc400(exc: SocPolicyError):
    raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/watchlist", tags=["soc"], dependencies=[Depends(require_analyst)])
def watchlist(list: str = Query("watchlist")) -> Dict[str, Any]:
    if list not in ("watchlist", "blocklist"):
        raise HTTPException(status_code=400, detail="list must be watchlist or blocklist")
    return {"list": list, "entries": _soc().list_entries(list)}


@app.post("/api/watchlist", tags=["soc"], dependencies=[Depends(require_admin)])
def watchlist_add(body: WatchEntryRequest,
                  payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    try:
        entry = _soc().add_entry(body.list, body.kind, body.value, body.reason,
                                 str(payload.get("sub", "admin")))
    except SocPolicyError as exc:
        _soc400(exc)
    return {"entry": entry}


@app.delete("/api/watchlist/{list}/{kind}", tags=["soc"],
            dependencies=[Depends(require_admin)])
def watchlist_remove(list: str, kind: str, value: str = Query(...),
                     payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    removed = _soc().remove_entry(list, kind, value, str(payload.get("sub", "admin")))
    if not removed:
        raise HTTPException(status_code=404, detail="entry not found")
    return {"removed": True}


@app.put("/api/watchlist/{list}/{kind}/active", tags=["soc"],
         dependencies=[Depends(require_admin)])
def watchlist_toggle(list: str, kind: str, value: str = Query(...),
                     active: bool = Query(True),
                     payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    toggled = _soc().set_entry_active(list, kind, value, active,
                                      str(payload.get("sub", "admin")))
    if not toggled:
        raise HTTPException(status_code=404, detail="entry not found")
    return {"active": active}


@app.get("/api/rules", tags=["soc"], dependencies=[Depends(require_analyst)])
def rules_list() -> Dict[str, Any]:
    return {"rules": _soc().list_rules()}


@app.post("/api/rules", tags=["soc"], dependencies=[Depends(require_admin)])
def rules_create(body: RuleRequest,
                 payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    try:
        rule = _soc().upsert_rule(body.model_dump(), str(payload.get("sub", "admin")))
    except SocPolicyError as exc:
        _soc400(exc)
    return {"rule": rule}


@app.put("/api/rules/{rule_id}", tags=["soc"], dependencies=[Depends(require_admin)])
def rules_update(rule_id: str, body: RuleRequest,
                 payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    try:
        rule = _soc().upsert_rule(body.model_dump(), str(payload.get("sub", "admin")),
                                  rule_id=rule_id)
    except SocPolicyError as exc:
        _soc400(exc)
    return {"rule": rule}


@app.delete("/api/rules/{rule_id}", tags=["soc"], dependencies=[Depends(require_admin)])
def rules_delete(rule_id: str,
                 payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    deleted = _soc().delete_rule(rule_id, str(payload.get("sub", "admin")))
    if not deleted:
        raise HTTPException(status_code=404, detail="rule not found")
    return {"deleted": True}


@app.post("/api/rules/{rule_id}/toggle", tags=["soc"],
          dependencies=[Depends(require_admin)])
def rules_toggle(rule_id: str, enabled: bool = Query(True),
                 payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    toggled = _soc().toggle_rule(rule_id, enabled, str(payload.get("sub", "admin")))
    if not toggled:
        raise HTTPException(status_code=404, detail="rule not found")
    return {"enabled": enabled}


@app.get("/api/cases", tags=["soc"])
def cases_list(status: Optional[str] = Query(None), severity: Optional[str] = Query(None),
               q: str = Query(""), limit: int = Query(100, le=500),
               payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    rows = _soc().list_cases(status=status, severity=severity, q=q, limit=limit,
                             client_id=_client_scope(payload))
    return {"cases": rows, "count": len(rows),
            "stats": _soc().case_stats() if not _client_scope(payload)
                     else _soc().case_stats_by_client(_client_scope(payload))}


@app.get("/api/cases/stats", tags=["soc"])
def cases_stats(payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    scope = _client_scope(payload)
    if scope:
        return _soc().case_stats_by_client(scope)
    return _soc().case_stats()


@app.get("/api/cases/{case_id}", tags=["soc"])
def cases_detail(case_id: str,
                 payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    case = _soc().get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    scope = _client_scope(payload)
    if scope and case.get("client_id") and case["client_id"] != scope:
        raise HTTPException(status_code=403, detail="not your client's incident")
    return {"case": case}


@app.get("/api/cases/{case_id}/incident", tags=["soc"])
def incident_detail(case_id: str,
                    payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    """Full incident drill-down: case record + activity timeline (who did what),
    involved parties (who is implicated), the entity graph subgraph around them,
    and enriched context pulled from the event store."""
    case = _soc().get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    scope = _client_scope(payload)
    if scope and case.get("client_id") and case["client_id"] != scope:
        raise HTTPException(status_code=403, detail="not your client's incident")
    involved = case.get("involved") or []
    case_evidence = case.get("evidence") or {}
    if not involved:
        involved = _soc()._involved_entities(case, case_evidence)
    # Enrich each involved party with event-store context.
    enriched = []
    store = _ORCH.event_store if _ORCH else None
    for ent in involved:
        row: Dict[str, Any] = dict(ent)
        if store is not None and ent.get("value"):
            try:
                hits = store.count_filtered(
                    query=str(ent["value"]), client_id=case.get("client_id") or "")
                row["events"] = int(hits)
                row["activity"] = [e.to_dict() for e in store.search(
                    query=str(ent["value"]), client_id=case.get("client_id") or "",
                    limit=3)]
            except Exception as exc:  # noqa: BLE001 — enrichment must never 500
                log.warning("incident enrichment failed: %s", exc)
        if ent.get("kind") == "ip" and ent.get("value"):
            try:
                row["enrichment"] = _ENRICHER.enrich(str(ent["value"]))
            except Exception as exc:  # noqa: BLE001
                log.warning("ip enrichment failed: %s", exc)
        enriched.append(row)
    # Entity graph subgraph restricted to involved parties.
    subgraph = {"nodes": [], "edges": []}
    if _GRAPH is not None:
        full = _GRAPH.to_dashboard()
        wanted = {f"ip:{ent['value']}" if ent.get("kind") == "ip"
                  else f"{ent.get('kind', 'misc')}:{ent['value']}" for ent in involved}
        wanted |= {e["id"] for e in full["nodes"] if e["label"] in {x.get("value") for x in involved}}
        node_ids = {n["id"] for n in full["nodes"] if n["id"] in wanted}
        subgraph["nodes"] = [n for n in full["nodes"] if n["id"] in node_ids]
        edge_ids = node_ids
        subgraph["edges"] = [e for e in full["edges"]
                             if e["source"] in edge_ids or e["target"] in edge_ids]
    if not subgraph["nodes"]:
        subgraph["nodes"] = [{"id": ent["value"], "label": ent["value"],
                              "kind": ent.get("kind", "misc"), "severity": "none"}
                             for ent in involved]
    return {"case": case, "involved": enriched, "graph": subgraph,
            "timeline": case.get("timeline") or [],
            "evidence": case_evidence,
            "client_id": case.get("client_id") or ""}


@app.get("/api/cases/{case_id}/graph", tags=["soc"])
def incident_graph(case_id: str,
                   payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    case = _soc().get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    scope = _client_scope(payload)
    if scope and case.get("client_id") and case["client_id"] != scope:
        raise HTTPException(status_code=403, detail="not your client's incident")
    involved = case.get("involved") or []
    if _GRAPH is None:
        return {"graph": {"nodes": [], "edges": []}, "involved": involved}
    full = _GRAPH.to_dashboard()
    wanted = {f"ip:{ent['value']}" for ent in involved} | \
             {f"{ent.get('kind', 'misc')}:{ent['value']}" for ent in involved}
    node_ids = {n["id"] for n in full["nodes"] if n["id"] in wanted}
    for n in full["nodes"]:
        if n["label"] in {x.get("value") for x in involved} and n["kind"] != "threat":
            node_ids.add(n["id"])
    nodes = [n for n in full["nodes"] if n["id"] in node_ids]
    edge_ids = node_ids
    edges = [e for e in full["edges"]
             if e["source"] in edge_ids or e["target"] in edge_ids]
    return {"graph": {"nodes": nodes, "edges": edges}, "involved": involved}


@app.get("/api/enrich/entity/{kind}/{value}", tags=["enrich"],
         dependencies=[Depends(require_auth)])
def enrich_entity(kind: str, value: str) -> Dict[str, Any]:
    """On-demand enrichment for one entity (geo/ASN for IPs, threat-intel
    verdict when a provider is configured). Fail-soft: always 200 + a dict."""
    if kind != "ip":
        return {"kind": kind, "value": value, "geo": {}, "intel": {}}
    try:
        result = _ENRICHER.enrich(value)
    except Exception as exc:  # noqa: BLE001
        log.warning("enrich endpoint failed for %s: %s", value, exc)
        result = {"geo": {}, "intel": {}}
    return {"kind": kind, "value": value, "geo": result.get("geo", {}),
            "intel": result.get("intel", {})}


@app.patch("/api/cases/{case_id}", tags=["soc"], dependencies=[Depends(require_analyst)])
def cases_action(case_id: str, body: CaseActionRequest,
                 payload: Dict[str, Any] = Depends(require_analyst)) -> Dict[str, Any]:
    try:
        case = _soc().transition(case_id, body.action, str(payload.get("sub", "?")),
                                 assignee=body.assignee, note=body.note)
    except SocPolicyError as exc:
        _soc400(exc)
    if hub is not None:
        try:
            hub.publish({"type": "case", "case": case})
        except Exception as exc:  # noqa: BLE001 — stream must never kill API
            log.warning("case stream publish failed: %s", exc)
    return {"case": case}


# ---------------------------------------------------------------- tasks


def _task_scope(payload: Dict[str, Any]) -> str:
    """The client workspace whose tasks a caller may manage ('' = all)."""
    return _client_scope(payload)


@app.get("/api/tasks", tags=["soc"])
def tasks_list(status: str = Query(""), q: str = Query(""),
               limit: int = Query(100, le=500),
               payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    scope = _task_scope(payload)
    rows = _soc().list_tasks(status=status, q=q, limit=limit, client_id=scope)
    tasks = _soc().task_stats(scope)
    tasks["list"] = rows
    return tasks


@app.post("/api/tasks", tags=["soc"], dependencies=[Depends(require_analyst)])
def tasks_create(body: TaskCreateRequest,
                 payload: Dict[str, Any] = Depends(require_analyst)) -> Dict[str, Any]:
    try:
        task = _soc().create_task(
            title=body.title, client_id=body.client_id, description=body.description,
            priority=body.priority, due_at=body.due_at,
            actor=str(payload.get("sub", "admin")), linked_case_id=body.linked_case_id)
    except SocPolicyError as exc:
        _soc400(exc)
    # Live alert: the client workspace sees the new assignment immediately.
    if hub is not None:
        try:
            hub.publish({"type": "task", "task": task})
        except Exception as exc:  # noqa: BLE001 — stream must never kill API
            log.warning("task stream publish failed: %s", exc)
    return {"task": task}


@app.get("/api/tasks/{task_id}", tags=["soc"])
def tasks_detail(task_id: str,
                 payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    task = _soc().get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    scope = _task_scope(payload)
    if scope and task.get("client_id") and task["client_id"] != scope:
        raise HTTPException(status_code=403, detail="not your client's task")
    return {"task": task}


@app.patch("/api/tasks/{task_id}", tags=["soc"])
def tasks_action(task_id: str, body: TaskPatchRequest,
                 payload: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    task = _soc().get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    actor = str(payload.get("sub", "?"))
    if payload.get("role") not in ("admin", "analyst"):
        scope = _task_scope(payload)
        if task.get("client_id") and task["client_id"] != scope:
            raise HTTPException(status_code=403, detail="not your client's task")
        actor = f"{actor}@{task.get('client_id', '')}"
    try:
        updated = _soc().patch_task(
            task_id, status=body.status, note=body.note, due_at=body.due_at,
            priority=body.priority, actor=actor)
    except SocPolicyError as exc:
        _soc400(exc)
    if hub is not None:
        try:
            hub.publish({"type": "task", "task": updated})
        except Exception as exc:  # noqa: BLE001
            log.warning("task stream publish failed: %s", exc)
    return {"task": updated}


@app.get("/api/admin/notifications", tags=["soc"],
         dependencies=[Depends(require_admin)])
def notifications_get() -> Dict[str, Any]:
    cfg = _soc().notifications()
    email = dict(cfg.get("email") or {})
    webhook = dict(cfg.get("webhook") or {})
    email["has_password"] = bool(email.get("password"))
    email["password"] = ""
    webhook["has_secret"] = bool(webhook.get("secret"))
    webhook["secret"] = ""
    cfg["email"] = email
    cfg["webhook"] = webhook
    return cfg


@app.put("/api/admin/notifications", tags=["soc"],
         dependencies=[Depends(require_admin)])
def notifications_put(body: Dict[str, Any] = Body(...),
                      payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    try:
        notif = _soc().save_notifications(body, str(payload.get("sub", "admin")))
    except SocPolicyError as exc:
        _soc400(exc)
    return notif


@app.post("/api/admin/notifications/test", tags=["soc"],
          dependencies=[Depends(require_admin)])
def notifications_test(payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    return _soc().send_test(str(payload.get("sub", "admin")))


@app.post("/api/admin/notifications/digest", tags=["soc"],
          dependencies=[Depends(require_admin)])
def notifications_digest(force: bool = Query(False),
                         payload: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    return _soc().run_digest(force=force, actor=str(payload.get("sub", "admin")))


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
        return FileResponse(index, headers={"Cache-Control": "no-store"})
    return JSONResponse(
        {"detail": "frontend/dist not built yet — run `npm run build` in frontend/"},
        status_code=503,
    )
