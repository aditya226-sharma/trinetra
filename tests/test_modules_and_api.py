"""Module C + analyzer + endpoint tests."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules.entity_graph import EntityGraph
from schema import Event, new_uuid


def _event(src=None, dst=None, proto="tcp", dns=None, user=None, proc=None):
    fields = {}
    if src:
        fields["src_ip"] = src
    if dst:
        fields["dst_ip"] = dst
    if proto:
        fields["proto"] = proto
    if dns:
        fields["dns_query"] = dns
    if user:
        fields["user"] = user
    if proc:
        fields["proc"] = proc
    return Event(event_id=new_uuid(), client_id="trinetra-core",
                 source_type="netflow", category="flow", severity="info",
                 timestamp="2026-09-10T12:00:00Z", message="m", fields=fields)


def test_graph_builds_entities_and_edges():
    g = EntityGraph()
    for _ in range(4):
        g.add_event(_event(src="10.10.1.50", dst="198.51.100.9", proto="tcp"))
    g.add_event(_event(src="10.10.1.50", dst="8.8.8.8", proto="udp",
                       dns="evil.top"))
    g.add_event(_event(user="root", proc="sshd", src="10.10.1.50"))
    payload = g.to_dashboard()
    kinds = {n["kind"] for n in payload["nodes"]}
    assert {"ip", "domain", "user", "proc"} <= kinds
    edge_kinds = {e["kind"] for e in payload["edges"]}
    assert {"comm", "dns", "auth", "exec"} <= edge_kinds
    assert len(g.communication_pairs()) >= 2


def test_findings_flag_threats_and_impacted_assets():
    g = EntityGraph()
    g.add_event(_event(src="10.10.1.50", dst="198.51.100.9"))
    g.add_finding({
        "threat_class": "c2_beaconing", "severity": "critical",
        "alert": {"src": "10.10.1.50", "dst": "198.51.100.9"},
    })
    assert "10.10.1.50" in g.threatened_ip_ids()
    assert "198.51.100.9" in g.threatened_ip_ids()
    payload = g.to_dashboard()
    assert any(n["kind"] == "threat" for n in payload["nodes"])


def test_analyzer_heuristic_verdicts():
    import asyncio
    from analyzer.llm_analyzer import LLMAnalyzer

    ev = _event(src="10.10.1.50", dst="198.51.100.9")
    analyzer = LLMAnalyzer(backend="heuristic", concurrency=2)

    async def run():
        malicious = await analyzer.analyze(ev, [{
            "threat_class": "c2_beaconing", "severity": "critical",
            "confidence": 0.9}], "c")
        normal = await analyzer.analyze(ev, [], "c")
        return malicious, normal

    malicious, normal = asyncio.run(run())
    assert malicious.verdict == "malicious"
    assert malicious.store_decision == "quarantine"
    assert normal.verdict == "normal"


def test_compliance_mapping_for_asset():
    from backend.app.services.compliance import mapping_for, compliance_for_asset
    ctrl = mapping_for("c2_beaconing")
    assert ctrl["cis"] and ctrl["attack"]
    payload = compliance_for_asset("10.10.1.50", [{
        "threat_class": "c2_beaconing", "severity": "critical", "confidence": 0.9,
        "alert": {"src": "10.10.1.50"},
    }])
    assert payload["asset_id"] == "10.10.1.50"
    assert payload["controls"][0]["status"] == "action_required"
    assert "MITRE" in payload["summary_markdown"]


def test_api_demo_round_trip():
    import backend.app.main as api_module
    from fastapi.testclient import TestClient

    client = TestClient(api_module.app)
    with client:
        resp = client.post("/api/demo/run?reset=true")
        assert resp.status_code == 200
        body = resp.json()
        assert body["stats"]["findings"] >= 5
        assert set(body["threat_detections"]) >= {
            "port_scan", "ddos", "c2_beaconing", "dga_dns", "data_exfiltration"}

        dash = client.get("/api/dashboard")
        assert dash.status_code == 200
        assert dash.json()["graph_summary"]["nodes"] > 0

        assets = client.get("/api/assets").json()["assets"]
        assert any(a["threatened"] for a in assets)

        clients = client.get("/api/clients").json()["clients"]
        assert len(clients) >= 7
        by_id = {c["client_id"]: c for c in clients}
        assert by_id["flow-sensor-1"]["events"] >= by_id["web01"]["events"]
        assert by_id["flow-sensor-1"]["source_type"] == "netflow"
        assert by_id["edge-fw-01"]["source_type"] == "cef"

        alerts = client.get("/api/alerts").json()
        assert alerts["count"] == 5
        assert alerts["sent"] == 5
        verdicts = {a["threat_class"]: a["verdict"] for a in alerts["alerts"]}
        assert verdicts["c2_beaconing"] == "malicious"
        assert verdicts["ddos"] == "malicious"
        assert verdicts["dga_dns"] == "suspicious"

        filtered = client.get("/api/events/search", params={"client_id": "web01"}).json()
        assert filtered["total"] == 20
        assert all(e["client_id"] == "web01" for e in filtered["events"])

        comp = client.get("/api/compliance/10.10.1.50")
        assert comp.status_code == 200
        assert comp.json()["controls"]

        search = client.get("/api/events/search", params={"query": "sshd"})
        assert search.status_code == 200
        assert search.json()["total"] > 0

        threats = client.get("/api/network-threats").json()["findings"]
        assert any(f["threat_class"] == "c2_beaconing" for f in threats)


def test_api_ingest_reports_accepted_duplicates_failed():
    """/api/ingest must not count silently-dropped lines as accepted."""
    import backend.app.main as api_module
    from fastapi.testclient import TestClient

    client = TestClient(api_module.app)
    with client:
        client.post("/api/demo/run?reset=true")
        dup_raw = "Sep 12 09:00:00,192.0.2.5,10.10.1.88,tcp,40000,443,3,1500,S"
        resp = client.post("/api/ingest", json={"lines": [
            {"raw": dup_raw, "source": "csv", "client_id": "ingest-probe"},
            {"raw": dup_raw, "source": "csv", "client_id": "ingest-probe"},
            {"raw": "   ", "source": "csv", "client_id": "ingest-probe"},
        ]})
        body = resp.json()
        assert body["accepted"] == 1
        assert body["duplicates"] == 1
        assert body["failed"] == 1
        probe = client.get("/api/events/search",
                           params={"client_id": "ingest-probe"}).json()
        assert probe["total"] == 1
        # tidy up: leave the demo store exactly as it was
        import sqlite3
        con = sqlite3.connect(str(api_module._settings.path("event_store")))
        con.execute("DELETE FROM events WHERE client_id = 'ingest-probe'")
        con.commit()
        con.close()

def test_api_unknown_routes_return_json_not_spa_html():
    """Unknown /api/* paths must answer 404 JSON — never the dashboard HTML
    (a silent HTML-on-200 response breaks axios callers)."""
    import backend.app.main as api_module
    from fastapi.testclient import TestClient

    client = TestClient(api_module.app)
    with client:
        for path in ("/api/nope", "/api/assets/9.9.9.9", "/api"):
            resp = client.get(path)
            assert resp.status_code == 404, path
            assert resp.json().get("detail") == "API route not found", path
            assert "html" not in resp.headers.get("content-type", ""), path


def test_spa_serves_deep_links_and_static_assets():
    """The catch-all serves real frontend/dist files, falls back to
    index.html for client-side deep links, and keeps explicit API routes."""
    import backend.app.main as api_module
    from fastapi.testclient import TestClient

    client = TestClient(api_module.app)
    with client:
        # explicit API routes keep precedence
        assert client.get("/api/health").status_code == 200
        # deep link -> index.html
        resp = client.get("/events")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")
        # referenced bundle asset is served with the right content type
        index_html = client.get("/").text
        import re
        m = re.search(r'(?:src|href)="(/assets/[^"]+)"', index_html)
        if m:
            asset_path = m.group(1).lstrip("/")
            res = client.get("/" + asset_path)
            assert res.status_code == 200, asset_path
            assert "javascript" in res.headers["content-type"], asset_path


def test_spa_missing_dist_returns_clear_503(monkeypatch):
    """A long-running server whose frontend/dist disappears must answer a
    readable 503 (build hint), not an opaque 500."""
    import backend.app.main as api_module
    from fastapi.testclient import TestClient

    missing = api_module.Path("/nonexistent/trinetra/frontend/dist")
    monkeypatch.setattr(api_module, "_DIST", missing)
    monkeypatch.setattr(api_module, "_DIST_RESOLVED", str(missing.resolve()))
    client = TestClient(api_module.app)
    with client:
        resp = client.get("/deep/link/route")
        assert resp.status_code == 503
        assert "not built" in resp.json().get("detail", "")
        assert "html" not in resp.headers.get("content-type", ""), resp.headers.get("content-type")


def test_ingest_bootstraps_graph_when_first_call():
    """POST /api/ingest must bootstrap BOTH globals (orchestrator + graph) —
    a previous local-variable shadowing left the module `_GRAPH` None, so
    /api/graph answered 428 even though events had been ingested."""
    import backend.app.main as api_module
    from fastapi.testclient import TestClient

    prev_orch, prev_graph = api_module._ORCH, api_module._GRAPH
    api_module._ORCH = None
    api_module._GRAPH = None
    try:
        client = TestClient(api_module.app)
        with client:
            resp = client.post("/api/ingest", json={"lines": [
                {"raw": "Sep 12 09:00:00,192.0.2.9,10.10.1.99,tcp,40000,443,3,1500,S",
                 "source": "csv", "client_id": "ingest-first-call"},
            ]})
            assert resp.status_code == 200, resp.text
            # graph must now be live (was masked by the shadowing bug)
            graph = client.get("/api/graph")
            assert graph.status_code == 200, graph.text
            assert api_module._GRAPH is not None
            # tidy up: leave the demo store exactly as it was
            import sqlite3
            con = sqlite3.connect(str(api_module._settings.path("event_store")))
            con.execute("DELETE FROM events WHERE client_id = 'ingest-first-call'")
            con.commit()
            con.close()
    finally:
        api_module._ORCH, api_module._GRAPH = prev_orch, prev_graph
