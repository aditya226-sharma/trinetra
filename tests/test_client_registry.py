"""Client registry: per-machine meta, heartbeat, agent tokens, fleet API."""

import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import backend.app.main as api_module
from pipeline.client_store import ClientStore

SHARED_TOKEN = "shared-secret-token"


@pytest.fixture(autouse=True)
def configure_agent_token(monkeypatch):
    api_module._settings._data.setdefault("auth", {})["agent_token"] = SHARED_TOKEN
    yield
    api_module._settings._data["auth"]["agent_token"] = ""


@pytest.fixture()
def client():
    with TestClient(api_module.app) as c:
        yield c


def _admin_headers(client):
    resp = client.post("/api/auth/login",
                       json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


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


def _login(client):
    return _admin_headers(client)


# ------------------------------------------------------------- store (unit)


def test_store_touch_and_heartbeat_and_bind(tmp_path):
    store = ClientStore(tmp_path / "c.db")
    store.touch(client_id="box-a", timestamp="2026-09-11T08:00:00Z",
                source_type="macos_unified_log", hostname="box-a",
                platform="darwin", agent_version="0.7.0", ip="10.0.0.5")
    store.touch(client_id="box-a", timestamp="2026-09-11T09:00:00Z",
                source_type="windows_event_log")
    row = store.get_client("box-a")
    assert row["hostname"] == "box-a"
    assert row["platform"] == "darwin"
    assert row["agent_version"] == "0.7.0"
    assert row["last_seen"] == "2026-09-11T09:00:00Z"
    assert set(row["source_types"]) == {"macos_unified_log", "windows_event_log"}

    store.heartbeat(client_id="box-b", hostname="box-b", platform="linux",
                    agent_version="0.7.0", ip="10.0.0.6")
    row_b = store.get_client("box-b")
    assert row_b["last_heartbeat"]
    assert row_b["last_seen"] == row_b["last_heartbeat"]

    token_id, raw = store.mint_token(label="my mbp", client_id="box-a")
    assert raw.startswith("trn_")
    row_a = store.get_client("box-a")
    assert row_a["token_id"] == token_id

    from pipeline.client_store import _djb2_hash

    tok = store.token_by_hash(_djb2_hash(raw))
    assert tok["token_id"] == token_id
    assert tok["enabled"] == 1
    assert tok["client_id"] == "box-a"
    store.close()


def test_store_revoke_token(tmp_path):
    store = ClientStore(tmp_path / "c.db")
    token_id, raw = store.mint_token()
    assert store.revoke_token(token_id) is True
    assert store.revoke_token("missing") is False
    from pipeline.client_store import _djb2_hash

    assert store.token_by_hash(_djb2_hash(raw))["enabled"] == 0
    store.close()


def test_store_deduplicates_source_types(tmp_path):
    store = ClientStore(tmp_path / "c.db")
    store.touch(client_id="x", timestamp="2026-01-01T00:00:00Z",
                source_type="syslog")
    store.touch(client_id="x", timestamp="2026-01-02T00:00:00Z",
                source_type="syslog")
    assert store.get_client("x")["source_types"] == ["syslog"]
    store.close()


# --------------------------------------------------------------- heartbeat


def test_heartbeat_requires_token(client):
    resp = client.post("/api/agent/heartbeat",
                       json={"client_id": "nobody"})
    assert resp.status_code == 401
    resp = client.post("/api/agent/heartbeat",
                       json={"client_id": "nobody"},
                       headers={"X-Agent-Token": "wrong"})
    assert resp.status_code == 401


def test_heartbeat_shared_token_registers_client(client):
    host = f"hbt-{uuid.uuid4().hex[:6]}"
    resp = client.post("/api/agent/heartbeat",
                       json={"client_id": host, "hostname": host,
                             "platform": "linux", "agent_version": "0.7.0",
                             "ip": "203.0.113.9"},
                       headers={"X-Agent-Token": SHARED_TOKEN})
    assert resp.status_code == 200, resp.text
    assert resp.json()["client_id"] == host
    row = api_module._ORCH.client_store.get_client(host)
    assert row is not None
    assert row["platform"] == "linux"
    assert row["agent_version"] == "0.7.0"
    assert row["last_heartbeat"]


def test_heartbeat_per_machine_token_binds_and_pins(client):
    headers = _login(client)
    minted = client.post("/api/agents", json={"label": "lab-router"},
                         headers=headers).json()
    raw = minted["token"]
    assert raw.startswith("trn_")
    token_headers = {"X-Agent-Token": raw}

    # First heartbeat with an (unbound) token binds it to the reported client.
    resp = client.post("/api/agent/heartbeat",
                       json={"client_id": "lab-router-mac", "platform": "darwin"},
                       headers=token_headers)
    assert resp.status_code == 200
    assert resp.json()["client_id"] == "lab-router-mac"

    # A bound token is authoritative: a bogus client_id is ignored.
    resp = client.post("/api/agent/heartbeat",
                       json={"client_id": "evil-machine"},
                       headers=token_headers)
    assert resp.json()["client_id"] == "lab-router-mac"
    assert api_module._ORCH.client_store.get_client("evil-machine") is None

    # Revoking the token blocks further heartbeats.
    client.delete(f"/api/agents/{minted['token_id']}", headers=headers)
    resp = client.post("/api/agent/heartbeat",
                       json={"client_id": "lab-router-mac"},
                       headers=token_headers)
    assert resp.status_code == 401


# ------------------------------------------------------------------ agents


def test_mint_requires_admin(client):
    resp = client.post("/api/agents", json={"label": "x"})
    assert resp.status_code == 401


def test_agent_tokens_list_and_revoke(client):
    headers = _login(client)
    a = client.post("/api/agents", json={"label": "alpha"}, headers=headers).json()
    b = client.post("/api/agents", json={"label": "beta"}, headers=headers).json()
    assert a["token_id"] != b["token_id"]
    listing = client.get("/api/agents", headers=headers).json()["agents"]
    ids = {t["token_id"] for t in listing}
    assert a["token_id"] in ids and b["token_id"] in ids
    # raw token is never listed back
    assert all(t.get("token") is None and t.get("token_hash") is None
               for t in listing)

    resp = client.delete(f"/api/agents/{a['token_id']}", headers=headers)
    assert resp.status_code == 200
    after = {t["token_id"]: t for t in client.get("/api/agents",
                                                  headers=headers).json()["agents"]}
    assert after[a["token_id"]]["enabled"] == 0


def test_ingest_events_with_per_machine_token_pins_client(client):
    headers = _login(client)
    minted = client.post("/api/agents", json={"label": "pinned"},
                         headers=headers).json()
    token_headers = {"X-Agent-Token": minted["token"]}

    # Token is pre-bound to a client_id at mint time.
    pre = client.post("/api/agents", json={"label": "pre", "client_id": "pre-box"},
                      headers=headers).json()
    pre_headers = {"X-Agent-Token": pre["token"]}
    resp = client.post("/api/ingest-events",
                       json={"events": [_agent_entry(
                           message="impersonation attempt", client_id="attacker")]},
                       headers=pre_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 1
    found = [e.to_dict() for e in api_module._ORCH.event_store.search(client_id="pre-box")]
    assert found and found[0]["message"] == "impersonation attempt"


# ------------------------------------------------------------------ clients


def test_clients_fleet_payload(client):
    host = f"fleet-{uuid.uuid4().hex[:6]}"
    client.post("/api/agent/heartbeat",
                json={"client_id": host, "hostname": host, "platform": "shieldos",
                      "agent_version": "9.9.9"},
                headers={"X-Agent-Token": SHARED_TOKEN})
    payload = client.get("/api/clients", headers=_login(client)).json()
    totals = payload["totals"]
    assert totals["clients"] >= 1
    assert totals["online"] >= 1
    row = next(c for c in payload["clients"] if c["client_id"] == host)
    assert row["platform"] == "shieldos"
    assert row["agent_version"] == "9.9.9"
    assert row["status"] == "online"
    assert "last_seen" in row and "heartbeat_at" in row and "events_recent" in row


def test_clients_require_auth(client):
    assert client.get("/api/clients").status_code == 401