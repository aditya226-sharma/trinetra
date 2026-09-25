"""Analytics roll-up: the current (partial) hour must not be plotted empty.

Regression guard: the bucket loop used the hour-truncated clock as the final
bucket's ``ts_to``. Every event timestamped inside the current hour sorts
after that boundary and was filtered out, so a freshly-ingested event never
appeared in the time series and ``events_in_window`` stayed 0 while
``events_total`` climbed.
"""

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import backend.app.main as api_module

AGENT_TOKEN = "shared-secret-token"


@pytest.fixture(autouse=True)
def configure_agent_token():
    api_module._settings._data.setdefault("auth", {})["agent_token"] = AGENT_TOKEN
    yield
    api_module._settings._data["auth"]["agent_token"] = ""


@pytest.fixture()
def client():
    with TestClient(api_module.app) as c:
        yield c


def _now_event(client_id: str) -> dict:    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "syslog",
        "level": "info",
        "category": "system",
        "message": "current-hour probe event",
        "raw": "current-hour probe event",
        "client_id": client_id,
        "metadata": {"host": client_id},
    }


def _analyst(client) -> dict:
    """Startup seeds admin/admin; analytics requires analyst+."""
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def test_current_hour_event_lands_in_last_bucket(client):
    resp = client.post("/api/ingest-events", json={"events": [_now_event("probe-1")]},
                       headers={"X-Agent-Token": AGENT_TOKEN})
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 1

    body = client.get("/api/analytics?hours=2", headers=_analyst(client)).json()
    series = body["time_series"]
    assert series, "time series must not be empty"
    assert series[-1]["events"] >= 1, (
        f"last bucket must include the just-ingested event, got {series[-1]}")
    assert body["totals"]["events_in_window"] >= 1
    assert body["totals"]["events_total"] >= 1


def test_series_buckets_are_contiguous_and_ordered(client):
    body = client.get("/api/analytics?hours=6", headers=_analyst(client)).json()
    buckets = [b["bucket"] for b in body["time_series"]]
    assert buckets == sorted(buckets), "buckets must be chronological"
    assert len(buckets) == 6, f"hours=6 must yield 6 hourly buckets, got {len(buckets)}"
    assert all(isinstance(b["events"], int) and b["events"] >= 0 for b in body["time_series"])
