"""Agent ingest-events: X-Agent-Token guard, rate limit, UES mapping, dedup."""

import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import backend.app.main as api_module

AGENT_TOKEN = "shared-secret-token"


@pytest.fixture(autouse=True)
def configure_agent_token(monkeypatch):
    # Mutate the in-process settings so the ingest-events guard sees a token.
    api_module._settings._data.setdefault("auth", {})["agent_token"] = AGENT_TOKEN
    yield
    api_module._settings._data["auth"]["agent_token"] = ""


@pytest.fixture()
def client():
    with TestClient(api_module.app) as c:
        yield c


def _agent_entry(**overrides):
    base = {
        "timestamp": "2026-09-11T06:30:00+05:30",
        "source": "macOS Unified Log",
        "level": "info",
        "message": "sshd: Accepted publickey for user from 203.0.113.7",
        "raw": "raw original line",
        "channel": "com.apple.syslog",
        "client_id": "",
        "metadata": {"host": "home-mbp", "pid": 123},
    }
    base.update(overrides)
    return base


def _events_for(client_id):
    orch = api_module._ORCH
    if orch is None:
        pytest.skip("orchestrator not bootstrapped")
    return [e.to_dict() for e in orch.event_store.search(client_id=client_id)]


def test_ingest_events_requires_token(client):
    resp = client.post("/api/ingest-events", json={"events": [_agent_entry()]})
    assert resp.status_code == 401
    resp = client.post("/api/ingest-events", json={"events": [_agent_entry()]},
                       headers={"X-Agent-Token": "wrong"})
    assert resp.status_code == 401


def test_ingest_events_with_token(client):
    resp = client.post("/api/ingest-events",
                       json={"events": [_agent_entry(message="auth ok here")]},
                       headers={"X-Agent-Token": AGENT_TOKEN})
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 1
    assert resp.json()["duplicates"] == 0


def test_mapping_landed_in_ues(client):
    host = f"map-{uuid.uuid4().hex[:6]}"
    entry = _agent_entry(metadata={"host": host, "pid": 123})
    client.post("/api/ingest-events", json={"events": [entry]},
                headers={"X-Agent-Token": AGENT_TOKEN})
    events = _events_for(host)
    # The ingest above had a local timestamp (UTC+05:30) -> stored as UTC Z.
    assert events, "expected at least one stored event"
    ev = events[0]
    assert ev["client_id"] == host
    assert ev["source_type"] == "macos_unified_log"
    assert ev["severity"] == "info"
    assert ev["message"] == "sshd: Accepted publickey for user from 203.0.113.7"
    assert ev["timestamp"].endswith("Z")
    assert ev["fields"]["host"] == host
    assert ev["fields"]["pid"] == 123
    assert ev["fields"]["channel"] == "com.apple.syslog"
    # raw round-trips through the raw store (trace_id aligned), like any event.
    assert api_module._ORCH.raw_store.get(ev["trace_id"]) == "raw original line"


def test_severity_mapping_debug_to_info(client):
    client.post("/api/ingest-events",
                json={"events": [_agent_entry(level="debug", client_id="debug-host")]},
                headers={"X-Agent-Token": AGENT_TOKEN})
    events = _events_for("debug-host")
    assert events and events[0]["severity"] == "info"


def test_duplicate_dedup(client):
    entry = _agent_entry(message="dedup probe", raw="dedup raw")
    first = client.post("/api/ingest-events", json={"events": [entry]},
                        headers={"X-Agent-Token": AGENT_TOKEN}).json()
    second = client.post("/api/ingest-events", json={"events": [entry]},
                         headers={"X-Agent-Token": AGENT_TOKEN}).json()
    assert first["accepted"] == 1
    assert second["duplicates"] == 1 and second["accepted"] == 0


def test_invalid_empty_message_rejected(client):
    resp = client.post("/api/ingest-events",
                       json={"events": [_agent_entry(message="   ")]},
                       headers={"X-Agent-Token": AGENT_TOKEN})
    assert resp.json()["failed"] == 1


def test_size_cap(client):
    many = [_agent_entry(message=f"m{i}", raw=f"r{i}") for i in range(1001)]
    resp = client.post("/api/ingest-events", json={"events": many},
                       headers={"X-Agent-Token": AGENT_TOKEN})
    assert resp.status_code == 413


def test_rate_limit(client, monkeypatch):
    monkeypatch.setattr(api_module, "_AGENT_LIMIT_PER_WINDOW", 3)
    api_module._agent_buckets.clear()
    token_headers = {"X-Agent-Token": AGENT_TOKEN}
    for i in range(3):
        r = client.post("/api/ingest-events",
                        json={"events": [_agent_entry(message=f"rate {i}")]},
                        headers=token_headers)
        assert r.status_code == 200, r.text
    r = client.post("/api/ingest-events",
                    json={"events": [_agent_entry(message="rate 4")]},
                    headers=token_headers)
    assert r.status_code == 429


def test_disabled_when_no_token_configured(client, monkeypatch):
    api_module._settings._data["auth"]["agent_token"] = ""
    resp = client.post("/api/ingest-events", json={"events": [_agent_entry()]},
                       headers={"X-Agent-Token": AGENT_TOKEN})
    assert resp.status_code == 401


def test_vpn_event_updates_vpn_profiles(client):
    """A live vpn-category agent event replaces Module B's profile list."""
    entry = _agent_entry(
        source="live_net",
        message="VPN posture sample",
        category="vpn",
        metadata={
            "host": "vpn-host",
            "profiles": [
                {"file": "live", "interface": "utun3", "mode": "tunnel",
                 "ike_version": 2, "encryption": "AES-GCM-256",
                 "key_length": 256, "pfs": "yes", "security_score": 92,
                 "risk_level": "low", "confidence": 0.95,
                 "recommendations": [], "junk_key": True, "nested": {"a": 1}},
                {"interface": "utun9", "security_score": 30,
                 "risk_level": "high"},
            ],
        },
    )
    resp = client.post("/api/ingest-events", json={"events": [entry]},
                       headers={"X-Agent-Token": AGENT_TOKEN})
    assert resp.status_code == 200, resp.text
    profiles = api_module._ORCH.vpn_profiles
    assert len(profiles) == 2
    assert profiles[0]["interface"] == "utun3"
    assert profiles[0]["security_score"] == 92
    assert "junk_key" not in profiles[0]
    assert "nested" not in profiles[0]
    assert profiles[0]["source"] == "live-agent"
    assert api_module._ORCH.stats["vpn_profiles"] == 2


def test_flow_event_feeds_threat_radar(client):
    """flow-category agent events must reach Module A's detector counts."""
    entries = [
        _agent_entry(
            source="live_flow",
            message=f"tcp 192.168.1.5:5192{i} -> 203.0.113.{i}:443 (1 pkts, 0 bytes)",
            category="flow",
            metadata={"host": "radar-host", "src_ip": "192.168.1.5",
                     "dst_ip": f"203.0.113.{i}", "proto": "tcp",
                     "sport": 51920 + i, "dport": 443, "pkts": 1, "bytes": 0},
        )
        for i in range(1, 9)
    ]
    resp = client.post("/api/ingest-events", json={"events": entries},
                       headers={"X-Agent-Token": AGENT_TOKEN})
    assert resp.status_code == 200, resp.text
    counts = api_module._ORCH.threats.detection_counts
    assert counts, "radar must not be empty"
    assert counts.get("port_scan", 0) >= 1, counts
    assert any(f["threat_class"] == "port_scan"
               and f.get("evidence", {}).get("src") == "192.168.1.5"
               for f in api_module._ORCH.findings_log)


def test_clients_include_last_seen():
    from pipeline.event_store import EventStore
    import tempfile
    from schema import Event, new_uuid

    with tempfile.TemporaryDirectory() as tmp:
        store = EventStore(Path(tmp) / "e.db")
        store.save(Event(event_id=new_uuid(), timestamp="2026-09-10T10:00:00Z",
                         source_type="macos_unified_log", client_id="box-a"))
        store.save(Event(event_id=new_uuid(), timestamp="2026-09-11T08:00:00Z",
                         source_type="windows_event_log", client_id="box-b",
                         severity="error"))
        rows = {r["client_id"]: r for r in store.clients()}
        assert rows["box-a"]["last_seen"] == "2026-09-10T10:00:00Z"
        assert rows["box-b"]["source_type"] == "windows_event_log"


def test_event_store_prune_before():
    from pipeline.event_store import EventStore
    import tempfile
    from schema import Event, new_uuid

    with tempfile.TemporaryDirectory() as tmp:
        store = EventStore(Path(tmp) / "e.db")
        store.save(Event(event_id=new_uuid(), timestamp="2026-01-01T00:00:00Z",
                         source_type="syslog", client_id="c"))
        store.save(Event(event_id=new_uuid(), timestamp="2026-09-10T00:00:00Z",
                         source_type="syslog", client_id="c"))
        assert store.prune_before("2026-06-01T00:00:00Z") == 1
        assert store.count() == 1


def test_retention_prune_skips_when_zero():
    from pipeline.retention import prune
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        api_module._settings._data["paths"]["event_store"] = str(Path(tmp) / "e.db")
        api_module._settings._data["paths"]["raw_store"] = str(Path(tmp) / "r.jsonl")
        api_module._settings._data["events"]["retention_days"] = 0
        result = prune(api_module._settings)
        assert result["events"] == 0
        assert result["raw_records"] == 0


def test_retention_prune_removes_expired(tmp_path, monkeypatch):
    from pipeline.retention import prune
    from pipeline.event_store import EventStore
    from schema import Event, new_uuid

    store_dir = tmp_path
    api_module._settings._data["paths"]["event_store"] = str(store_dir / "e.db")
    api_module._settings._data["paths"]["raw_store"] = str(store_dir / "r.jsonl")
    api_module._settings._data["events"]["retention_days"] = 30
    store = EventStore(store_dir / "e.db")
    store.save(Event(event_id=new_uuid(), timestamp="2026-01-01T00:00:00Z",
                     source_type="syslog", client_id="c"))
    store.save(Event(event_id=new_uuid(), timestamp="2026-09-10T00:00:00Z",
                     source_type="syslog", client_id="c"))
    store.close()
    result = prune(api_module._settings)
    assert result["events"] == 1
    assert EventStore(store_dir / "e.db").count() == 1


def test_stream_hub_publishes_to_subscribers():
    import asyncio

    from backend.app.stream import hub

    async def scenario():
        queue = asyncio.Queue()
        hub.subscribe(queue, asyncio.get_running_loop())
        try:
            hub.publish({"event_id": "evt-1", "message": "hello"})
            item = await asyncio.wait_for(queue.get(), timeout=1)
            assert "evt-1" in item
            assert "hello" in item
        finally:
            hub.unsubscribe(queue)

    asyncio.run(scenario())
